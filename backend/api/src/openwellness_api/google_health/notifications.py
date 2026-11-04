"""``POST /api/googleHealth/notifications``: the Google Health webhook subscriber (GHA-02).

Google's contract (https://developers.google.com/health/webhooks, fetched
2026-09-30, page "Last updated 2026-09-24 UTC"; opserver
``docs/google-health.md`` "Notification body"):

- Creating a subscriber runs a two-step handshake with the body
  ``{"type": "verification"}``: once with the configured ``Authorization``
  secret (expects 200/201) and once without it (expects 401/403).
- A notification body is one notification object or a JSON array of them (up
  to 99 per batch). Each carries ``data.healthUserId``, ``data.dataType``,
  ``data.operation`` (``UPSERT`` or ``DELETE``), ``data.intervals`` and, for
  identifiable-data deletes, ``data.recordId``.
- The raw body is signed (``GOOGLE-HEALTH-API-SIGNATURE``); any answer other
  than 204 makes Google store and redeliver the request for up to 7 days.

The route follows Phase 10's enqueue-and-return rule (HOOK-01, D-02): it reads
nothing from Mongo, writes nothing and fetches nothing itself. Order:

1. constant-time ``Authorization`` check (else 401);
2. bounded raw read (64 KiB, else 413), so a 413 proves the sender held the secret;
3. the verification body (200);
4. the signature over the exact raw bytes, in the threadpool (401 invalid,
   503 when the key is unavailable so Google retries);
5. parse: an object or an array of 1..100 items, else 400; an item that
   fails validation is dropped with a WARNING count (redelivery cannot fix
   it) and the rest are processed;
6. one ``googleHealth.handleNotification [healthUserId, dataType,
   operation, dates]`` per distinct (healthUserId, dataType, operation) onto
   ``scheduler_new``, in the threadpool; any publish failure answers 503 so
   Google redelivers the whole request. Groups already published are
   coalesced downstream by ``syncDate``'s ``QueueOnce`` (10.1-18);
7. 204.

Dates per interval: ``civilDateTimeInterval``, else
``civilIso8601TimeInterval``, else ``physicalTimeInterval`` (UTC dates
widened one day on each side). An end of exactly 00:00 excludes that day.
An item may span at most 31 dates.

Log lines have the fixed shape ``googleHealth/notifications <outcome>`` with
counts or an exception class name only: never the body, the secret, the
signature, ``recordId`` or ``healthUserId`` (HIPAA 6-year log retention).
"""

from __future__ import annotations

import hmac
import json
import logging
from datetime import UTC, date, datetime, time, timedelta
from typing import Annotated, Any, Final, Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response

from ..deps.principal import ALLOW_UNAUTHENTICATED
from ..event_handlers.celery_producer import SCHEDULER_NEW_QUEUE
from ..event_handlers.ports import TaskPublisher
from .oauth import get_google_health_deps
from .signature import SignatureVerificationUnavailable

logger = logging.getLogger(__name__)

NOTIFICATIONS_PATH: Final = "/api/googleHealth/notifications"
HANDLE_NOTIFICATION_TASK: Final = "googleHealth.handleNotification"
SIGNATURE_HEADER: Final = "google-health-api-signature"
MAX_BODY_BYTES: Final = 65536
MAX_ITEMS: Final = 100
MAX_DATES_PER_ITEM: Final = 31

_LOG: Final = "googleHealth/notifications"
_MIDNIGHT: Final = time(0, 0)
_ONE_DAY: Final = timedelta(days=1)

GroupKey = tuple[str, str, str]


# --- the notification model ----------------------------------------------------


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)


class _CivilDate(_Model):
    year: int
    month: int
    day: int


class _CivilTime(_Model):
    """``google.type.TimeOfDay``; ``{}`` is midnight, ``24:00`` is the end of the day."""

    hours: int = Field(default=0, ge=0, le=24)
    minutes: int = Field(default=0, ge=0, le=59)
    seconds: int = Field(default=0, ge=0, le=60)
    nanos: int = Field(default=0, ge=0, le=999_999_999)


class _CivilDateTime(_Model):
    civil_date: _CivilDate = Field(alias="date")
    civil_time: _CivilTime = Field(default_factory=_CivilTime, alias="time")

    def value(self) -> datetime:
        d = date(self.civil_date.year, self.civil_date.month, self.civil_date.day)
        t = self.civil_time
        if t.hours == 24:
            if t.minutes or t.seconds or t.nanos:
                raise ValueError("time_out_of_range")
            return datetime.combine(d + _ONE_DAY, _MIDNIGHT)
        return datetime.combine(
            d, time(t.hours, t.minutes, min(t.seconds, 59), t.nanos // 1000)
        )


class _CivilDateTimeInterval(_Model):
    startDateTime: _CivilDateTime
    endDateTime: _CivilDateTime


class _TimeInterval(_Model):
    startTime: str
    endTime: str


class _Interval(_Model):
    civilDateTimeInterval: _CivilDateTimeInterval | None = None
    civilIso8601TimeInterval: _TimeInterval | None = None
    physicalTimeInterval: _TimeInterval | None = None


_HealthUserId = Annotated[
    str, StringConstraints(min_length=1, max_length=256, pattern=r"^[\x21-\x7e]+$")
]
# Opaque Google identifier: any ASCII letters, digits, ``-`` or ``_`` (both
# ``heart-rate`` and ``heart_rate`` forms), bounded so it is safe on the queue.
_DataType = Annotated[
    str, StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
]


class _Data(_Model):
    healthUserId: _HealthUserId
    dataType: _DataType
    operation: Literal["UPSERT", "DELETE"]
    intervals: list[_Interval] = Field(min_length=1)
    # Accepted so an identifiable-data DELETE validates; never used or logged.
    recordId: str | int | None = Field(default=None, repr=False)


class _Notification(_Model):
    data: _Data


# --- dates -----------------------------------------------------------------------


def _date_span(start: datetime, end: datetime) -> tuple[date, date]:
    """First and last civil dates of ``[start, end]``; an end at 00:00 excludes its day."""
    if end < start:
        raise ValueError("interval_reversed")
    last = end.date()
    if end.time() == _MIDNIGHT and end > start:
        last -= _ONE_DAY
    return start.date(), last


def _civil_wall(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed.replace(tzinfo=None)


def _utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed
    return parsed.astimezone(UTC).replace(tzinfo=None)


def _interval_span(interval: _Interval) -> tuple[date, date]:
    if interval.civilDateTimeInterval is not None:
        civil = interval.civilDateTimeInterval
        return _date_span(civil.startDateTime.value(), civil.endDateTime.value())
    if interval.civilIso8601TimeInterval is not None:
        iso = interval.civilIso8601TimeInterval
        return _date_span(_civil_wall(iso.startTime), _civil_wall(iso.endTime))
    if interval.physicalTimeInterval is not None:
        physical = interval.physicalTimeInterval
        first, last = _date_span(_utc(physical.startTime), _utc(physical.endTime))
        return first - _ONE_DAY, last + _ONE_DAY
    raise ValueError("no_usable_interval")


def _item_dates(data: _Data) -> list[str]:
    dates: set[date] = set()
    for interval in data.intervals:
        first, last = _interval_span(interval)
        count = (last - first).days + 1
        if count > MAX_DATES_PER_ITEM:
            raise ValueError("too_many_dates")
        dates.update(first + timedelta(days=offset) for offset in range(count))
        if len(dates) > MAX_DATES_PER_ITEM:
            raise ValueError("too_many_dates")
    return sorted(d.isoformat() for d in dates)


def group_notifications(items: list[Any]) -> tuple[dict[GroupKey, list[str]], int]:
    """Group valid items by (healthUserId, dataType, operation) with the union of their dates.

    Returns the groups in first-seen order and the number of dropped items.
    """
    groups: dict[GroupKey, set[str]] = {}
    dropped = 0
    for item in items:
        try:
            data = _Notification.model_validate(item).data
            dates = _item_dates(data)
        except (ValidationError, ValueError, OverflowError, TypeError):
            dropped += 1
            continue
        key = (data.healthUserId, data.dataType, data.operation)
        groups.setdefault(key, set()).update(dates)
    return {key: sorted(dates) for key, dates in groups.items()}, dropped


# --- body --------------------------------------------------------------------------


def _declared_length(value: str | None) -> int | None:
    if value is None or not value.strip().isdigit():
        return None
    return int(value.strip())


async def _read_bounded(request: Request) -> bytes | None:
    """The raw body, or ``None`` when it exceeds :data:`MAX_BODY_BYTES`.

    A declared length over the cap is refused before any read; otherwise at
    most ``MAX_BODY_BYTES + 1`` bytes are kept (``hapi.read_hapi_payload``).
    """
    declared = _declared_length(request.headers.get("content-length"))
    if declared is not None and declared > MAX_BODY_BYTES:
        return None
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        kept = chunk[: MAX_BODY_BYTES + 1 - size]
        chunks.append(kept)
        size += len(kept)
        if size > MAX_BODY_BYTES:
            return None
    return b"".join(chunks)


_INVALID: Final = object()


def _load_json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return _INVALID


def _is_verification(parsed: Any) -> bool:
    return (
        isinstance(parsed, dict)
        and parsed.get("type") == "verification"
        and "data" not in parsed
    )


def _items(parsed: Any) -> list[Any] | None:
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list) and 1 <= len(parsed) <= MAX_ITEMS:
        return parsed
    return None


def _authorized(header: str | None, secret: str) -> bool:
    return hmac.compare_digest((header or "").encode("utf-8"), secret.encode("utf-8"))


def _publish_groups(publisher: TaskPublisher, groups: dict[GroupKey, list[str]]) -> None:
    for (health_user_id, data_type, operation), dates in groups.items():
        publisher.publish(
            HANDLE_NOTIFICATION_TASK,
            [health_user_id, data_type, operation, dates],
            queue=SCHEDULER_NEW_QUEUE,
        )


# --- the route -------------------------------------------------------------------------


async def receive_notification(request: Request) -> Response:
    deps = get_google_health_deps(request)
    if deps is None or deps.disabled:
        logger.warning("%s unavailable: disabled", _LOG)
        return Response(status_code=503)

    if not _authorized(request.headers.get("authorization"), deps.settings.webhook_secret):
        logger.warning("%s unauthorized", _LOG)
        return Response(status_code=401)

    raw = await _read_bounded(request)
    if raw is None:
        declared = _declared_length(request.headers.get("content-length"))
        logger.warning("%s too_large: %d declared", _LOG, -1 if declared is None else declared)
        return Response(status_code=413)

    parsed = _load_json(raw)
    if _is_verification(parsed):
        logger.info("%s verification", _LOG)
        return Response(status_code=200)

    verifier = deps.signature_verifier
    if verifier is None:
        logger.error("%s unavailable: no_verifier", _LOG)
        return Response(status_code=503)
    signature = request.headers.get(SIGNATURE_HEADER)
    if not signature:
        logger.warning("%s bad_signature: missing", _LOG)
        return Response(status_code=401)
    try:
        valid = await run_in_threadpool(verifier.verify, signature, raw)
    except SignatureVerificationUnavailable:
        logger.warning("%s signature_unavailable", _LOG)
        return Response(status_code=503)
    except Exception as exc:
        logger.error("%s verify failed: %s", _LOG, type(exc).__name__)
        return Response(status_code=503)
    if not valid:
        logger.warning("%s bad_signature", _LOG)
        return Response(status_code=401)

    items = _items(parsed) if parsed is not _INVALID else None
    if items is None:
        logger.warning("%s invalid_body", _LOG)
        return Response(status_code=400)

    groups, dropped = group_notifications(items)
    if dropped:
        logger.warning("%s dropped items: %d", _LOG, dropped)
    try:
        await run_in_threadpool(_publish_groups, deps.publisher, groups)
    except Exception as exc:
        logger.error("%s publish failed: %s", _LOG, type(exc).__name__)
        return Response(status_code=503)
    logger.info(
        "%s published: %d groups from %d items, %d bytes",
        _LOG,
        len(groups),
        len(items) - dropped,
        len(raw),
    )
    return Response(status_code=204)


def build_notifications_router() -> APIRouter:
    """The subscriber endpoint, unauthenticated by marker (the route checks secret and signature)."""
    router = APIRouter()
    router.post(
        NOTIFICATIONS_PATH,
        openapi_extra={ALLOW_UNAUTHENTICATED: True},
        include_in_schema=False,
        name="googleHealth.notifications",
    )(receive_notification)
    return router
