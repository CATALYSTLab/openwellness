"""Google Health notification receiver (10.1-07, GHA-02; HOOK-01 enqueue-and-return).

``POST /api/googleHealth/notifications`` answers Google's subscriber
handshake, checks the shared secret and the signature over the raw body, and
publishes one ``googleHealth.handleNotification`` per distinct
(healthUserId, dataType, operation) onto ``scheduler_new``. It reads, writes
and fetches nothing itself.

The signature check sits behind the ``SignatureVerifier`` port; these tests
drive it with :class:`FakeVerifier`. The bodies under
``fixtures/google_health_notifications/`` are copied from
https://developers.google.com/health/webhooks (fetched 2026-09-30, see the
fixture README). Contract: opserver ``docs/google-health.md`` "Notification
body" and "Celery tasks".
"""

from __future__ import annotations

import asyncio
import json
import logging
import logging.config
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import pytest
import uvicorn.config
from fastapi.dependencies.utils import get_flat_dependant
from fastapi.routing import APIRoute

from openwellness_api.deps.principal import ALLOW_UNAUTHENTICATED, require_write_principal
from openwellness_api.event_handlers.ports import TaskPublishError
from openwellness_api.google_health.notifications import install_notifications_logger
from openwellness_api.google_health.signature import SignatureVerificationUnavailable

from .google_health_harness import Harness, RecordingPublisher, make_settings

PATH = "/api/googleHealth/notifications"
TASK = "googleHealth.handleNotification"
QUEUE = "scheduler_new"
SIGNATURE = "c2lnbmF0dXJlLXNlbnRpbmVsLTRkOWM="
FIXTURES = Path(__file__).parent / "fixtures" / "google_health_notifications"
H = "health-user-id"
LIMIT = 65536


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _in_event_loop() -> bool:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


@dataclass
class FakeVerifier:
    """The port, recording each call and whether it ran on the event loop."""

    result: bool = True
    error: Exception | None = None
    calls: list[tuple[str, bytes]] = field(default_factory=list)
    on_loop: list[bool] = field(default_factory=list)

    def verify(self, signature_b64: str, raw_body: bytes) -> bool:
        self.calls.append((signature_b64, raw_body))
        self.on_loop.append(_in_event_loop())
        if self.error is not None:
            raise self.error
        return self.result


@dataclass
class ScriptedPublisher(RecordingPublisher):
    """Records publishes; raises ``fail_with`` on call number ``fail_on`` (1-based)."""

    fail_on: int | None = None
    fail_with: Exception = field(default_factory=lambda: TaskPublishError("ConnectionError"))
    attempts: int = 0
    on_loop: list[bool] = field(default_factory=list)

    def publish(self, task_name: str, args: list[Any], queue: str = "celery") -> None:
        self.attempts += 1
        self.on_loop.append(_in_event_loop())
        if self.fail_on is not None and self.attempts == self.fail_on:
            raise self.fail_with
        super().publish(task_name, args, queue)


class Rig:
    def __init__(
        self,
        *,
        verifier: FakeVerifier | None = None,
        publisher: ScriptedPublisher | None = None,
        settings: Any = None,
        no_verifier: bool = False,
    ) -> None:
        self.h = Harness(settings)
        self.verifier = verifier if verifier is not None else FakeVerifier()
        self.publisher = publisher if publisher is not None else ScriptedPublisher()
        self.h.app.state.google_health_deps = replace(
            self.h.deps,
            publisher=self.publisher,
            signature_verifier=None if no_verifier else self.verifier,
        )
        self.secret = self.h.settings.webhook_secret
        self.client = self.h.client()

    def post(
        self,
        body: bytes,
        *,
        authorization: str | None = "__secret__",
        signature: str | None = SIGNATURE,
    ) -> Any:
        headers = {"content-type": "application/json"}
        if authorization == "__secret__":
            headers["authorization"] = self.secret
        elif authorization is not None:
            headers["authorization"] = authorization
        if signature is not None:
            headers["google-health-api-signature"] = signature
        return self.client.post(PATH, content=body, headers=headers)

    @property
    def calls(self) -> list[tuple[str, list[Any], str]]:
        return self.publisher.calls


def civil(year: int, month: int, day: int, hours: int | None = None, minutes: int = 0) -> dict:
    time: dict[str, int] = {} if hours is None else {"hours": hours, "minutes": minutes}
    return {"date": {"year": year, "month": month, "day": day}, "time": time}


def civil_interval(start: dict, end: dict) -> dict:
    return {"civilDateTimeInterval": {"startDateTime": start, "endDateTime": end}}


def notification(
    *,
    health_user_id: str = H,
    data_type: str = "steps",
    operation: str = "UPSERT",
    intervals: list[dict] | None = None,
    **extra: Any,
) -> dict:
    data: dict[str, Any] = {
        "version": "1",
        "clientProvidedSubscriptionName": "subscription-name",
        "healthUserId": health_user_id,
        "operation": operation,
        "dataType": data_type,
        "intervals": intervals
        if intervals is not None
        else [civil_interval(civil(2026, 10, 1, 8), civil(2026, 10, 1, 9))],
    }
    data.update(extra)
    return {"data": data}


def dumps(value: Any) -> bytes:
    return json.dumps(value).encode("utf-8")


VERIFICATION = b'{"type": "verification"}'


# --- handshake ---------------------------------------------------------------


def test_missing_authorization_is_401_and_nothing_else_runs() -> None:
    rig = Rig()
    resp = rig.post(fixture("upsert_steps.json"), authorization=None)
    assert resp.status_code == 401
    assert resp.content == b""
    assert rig.verifier.calls == []
    assert rig.calls == []


@pytest.mark.parametrize(
    "value",
    ["wrong", "Bearer wrong", "__prefix__", "__suffix__", "__upper__"],
)
def test_wrong_authorization_is_401(value: str) -> None:
    rig = Rig()
    header = {
        "__prefix__": rig.secret[:-1],
        "__suffix__": rig.secret + "x",
        "__upper__": rig.secret.upper(),
    }.get(value, value)
    resp = rig.post(fixture("upsert_steps.json"), authorization=header)
    assert resp.status_code == 401
    assert resp.content == b""
    assert rig.verifier.calls == []
    assert rig.calls == []


def test_verification_with_the_secret_is_200_and_publishes_nothing() -> None:
    rig = Rig()
    resp = rig.post(VERIFICATION, signature=None)
    assert resp.status_code == 200
    assert rig.calls == []
    assert rig.verifier.calls == []


def test_verification_without_the_secret_is_401() -> None:
    """Google's "unauthorized challenge": the second handshake request carries no credentials."""
    rig = Rig()
    resp = rig.post(VERIFICATION, authorization=None, signature=None)
    assert resp.status_code == 401


# --- signed notifications -----------------------------------------------------


def test_single_notification_publishes_sorted_unique_dates_on_scheduler_new() -> None:
    rig = Rig()
    body = dumps(
        notification(
            intervals=[
                civil_interval(civil(2026, 10, 2, 10), civil(2026, 10, 2, 11)),
                civil_interval(civil(2026, 10, 1, 8), civil(2026, 10, 1, 9)),
                civil_interval(civil(2026, 10, 2, 12), civil(2026, 10, 2, 13)),
            ]
        )
    )
    resp = rig.post(body)
    assert resp.status_code == 204
    assert resp.content == b""
    assert rig.calls == [(TASK, [H, "steps", "UPSERT", ["2026-10-01", "2026-10-02"]], QUEUE)]


def test_verifier_sees_the_exact_raw_bytes_and_header() -> None:
    rig = Rig()
    body = fixture("upsert_steps.json")
    rig.post(body)
    assert rig.verifier.calls == [(SIGNATURE, body)]


def test_upsert_example_prefers_civil_date_time_interval() -> None:
    rig = Rig()
    resp = rig.post(fixture("upsert_steps.json"))
    assert resp.status_code == 204
    assert rig.calls == [(TASK, [H, "steps", "UPSERT", ["2026-03-07"]], QUEUE)]


def test_batch_publishes_one_task_per_group_with_unioned_dates() -> None:
    rig = Rig()
    resp = rig.post(fixture("batch_mixed.json"))
    assert resp.status_code == 204
    assert rig.calls == [
        (TASK, [H, "steps", "UPSERT", ["2026-03-07", "2026-07-14"]], QUEUE),
        (TASK, [H, "sleep", "DELETE", ["2026-08-12", "2026-08-13"]], QUEUE),
    ]


def test_time_series_delete_array_uses_the_civil_iso_interval() -> None:
    rig = Rig()
    resp = rig.post(fixture("delete_steps_timeseries.json"))
    assert resp.status_code == 204
    assert rig.calls == [(TASK, [H, "steps", "DELETE", ["2026-08-12"]], QUEUE)]


def test_sleep_delete_with_record_id_covers_both_civil_dates(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    rig = Rig()
    resp = rig.post(fixture("delete_sleep_record_id.json"))
    assert resp.status_code == 204
    assert rig.calls == [(TASK, [H, "sleep", "DELETE", ["2026-08-12", "2026-08-13"]], QUEUE)]
    assert "9875412" not in caplog.text


def test_full_day_interval_ending_at_midnight_excludes_the_next_day() -> None:
    rig = Rig()
    resp = rig.post(fixture("full_day_steps.json"))
    assert resp.status_code == 204
    assert rig.calls == [(TASK, ["343864966078399341", "steps", "UPSERT", ["2026-07-14"]], QUEUE)]


def test_physical_only_interval_widens_its_utc_date_by_one_day_each_side() -> None:
    rig = Rig()
    resp = rig.post(fixture("physical_only_steps.json"))
    assert resp.status_code == 204
    assert rig.calls == [
        (TASK, [H, "steps", "UPSERT", ["2026-03-07", "2026-03-08", "2026-03-09"]], QUEUE)
    ]


def test_iso_interval_ending_at_midnight_excludes_the_next_day() -> None:
    rig = Rig()
    body = dumps(
        notification(
            intervals=[
                {
                    "civilIso8601TimeInterval": {
                        "startTime": "2026-07-14T00:00:00",
                        "endTime": "2026-07-16T00:00:00",
                    }
                }
            ]
        )
    )
    rig.post(body)
    assert rig.calls == [(TASK, [H, "steps", "UPSERT", ["2026-07-14", "2026-07-15"]], QUEUE)]


def test_items_for_different_users_are_separate_groups() -> None:
    rig = Rig()
    body = dumps(
        [
            notification(health_user_id="user-a"),
            notification(health_user_id="user-b"),
            notification(health_user_id="user-a", operation="DELETE"),
        ]
    )
    resp = rig.post(body)
    assert resp.status_code == 204
    assert [call[1][:3] for call in rig.calls] == [
        ["user-a", "steps", "UPSERT"],
        ["user-b", "steps", "UPSERT"],
        ["user-a", "steps", "DELETE"],
    ]


# --- signature outcomes --------------------------------------------------------


def test_rejected_signature_is_401_and_publishes_nothing() -> None:
    rig = Rig(verifier=FakeVerifier(result=False))
    resp = rig.post(fixture("upsert_steps.json"))
    assert resp.status_code == 401
    assert rig.calls == []


def test_missing_signature_is_401_without_calling_the_verifier() -> None:
    rig = Rig()
    resp = rig.post(fixture("upsert_steps.json"), signature=None)
    assert resp.status_code == 401
    assert rig.verifier.calls == []
    assert rig.calls == []


def test_unavailable_key_is_503_so_google_retries() -> None:
    rig = Rig(verifier=FakeVerifier(error=SignatureVerificationUnavailable("refetch_floor")))
    resp = rig.post(fixture("upsert_steps.json"))
    assert resp.status_code == 503
    assert rig.calls == []


def test_unexpected_verifier_failure_is_503_not_401() -> None:
    rig = Rig(verifier=FakeVerifier(error=RuntimeError("boom")))
    resp = rig.post(fixture("upsert_steps.json"))
    assert resp.status_code == 503
    assert rig.calls == []


def test_verification_and_publishing_run_in_the_threadpool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from openwellness_api.google_health import notifications as module

    ran: list[Any] = []
    real = module.run_in_threadpool

    async def spy(func: Any, *args: Any, **kwargs: Any) -> Any:
        ran.append(func)
        return await real(func, *args, **kwargs)

    monkeypatch.setattr(module, "run_in_threadpool", spy)
    rig = Rig()
    resp = rig.post(fixture("upsert_steps.json"))
    assert resp.status_code == 204
    assert rig.verifier.verify in ran
    assert rig.verifier.on_loop == [False]
    assert rig.publisher.on_loop == [False]


# --- body limits and shape --------------------------------------------------------


def test_body_over_64_kib_is_413_before_verification() -> None:
    rig = Rig()
    body = b'{"data": {"pad": "' + b"x" * LIMIT + b'"}}'
    resp = rig.post(body)
    assert resp.status_code == 413
    assert rig.verifier.calls == []
    assert rig.calls == []


def test_over_cap_without_the_secret_is_401_and_not_read(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    rig = Rig()
    body = b'{"data": {"pad": "' + b"x" * LIMIT + b'"}}'
    resp = rig.post(body, authorization=None)
    assert resp.status_code == 401
    assert rig.verifier.calls == []
    assert rig.calls == []
    assert "unauthorized" in caplog.text
    assert "too_large" not in caplog.text


def test_over_cap_with_a_wrong_secret_is_401() -> None:
    rig = Rig()
    body = b'{"data": {"pad": "' + b"x" * LIMIT + b'"}}'
    resp = rig.post(body, authorization="wrong")
    assert resp.status_code == 401
    assert rig.verifier.calls == []
    assert rig.calls == []


def test_too_large_logs_the_declared_bytes(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    rig = Rig()
    body = b'{"data": {"pad": "' + b"x" * LIMIT + b'"}}'
    assert rig.post(body).status_code == 413
    assert f"too_large: {len(body)} declared" in caplog.text


def test_too_large_logs_minus_one_when_chunked(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    rig = Rig()
    resp = rig.client.post(
        PATH,
        content=iter([b"x" * (LIMIT + 1)]),
        headers={"authorization": rig.secret},
    )
    assert resp.status_code == 413
    assert "too_large: -1 declared" in caplog.text


def test_published_logs_the_body_bytes(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    rig = Rig()
    body = fixture("upsert_steps.json")
    assert rig.post(body).status_code == 204
    assert f"items, {len(body)} bytes" in caplog.text


def test_body_of_exactly_64_kib_is_accepted() -> None:
    rig = Rig()
    base = fixture("upsert_steps.json").rstrip()
    body = base + b" " * (LIMIT - len(base))
    assert len(body) == LIMIT
    resp = rig.post(body)
    assert resp.status_code == 204
    assert len(rig.calls) == 1


@pytest.mark.parametrize(
    "body",
    [b"not json", b"\xff\xfe{", b'"string"', b"42", b"null", b"true", b"[]"],
    ids=["text", "bad-utf8", "string", "number", "null", "bool", "empty-array"],
)
def test_body_that_is_not_an_object_or_non_empty_array_is_400(body: bytes) -> None:
    rig = Rig()
    resp = rig.post(body)
    assert resp.status_code == 400
    assert rig.calls == []


def test_batch_over_100_items_is_400() -> None:
    rig = Rig()
    resp = rig.post(dumps([notification() for _ in range(101)]))
    assert resp.status_code == 400
    assert rig.calls == []


def test_batch_of_99_items_is_accepted() -> None:
    rig = Rig()
    resp = rig.post(dumps([notification(health_user_id=f"u{i}") for i in range(99)]))
    assert resp.status_code == 204
    assert len(rig.calls) == 99


@pytest.mark.parametrize(
    "bad",
    [
        notification(operation="PATCH"),
        notification(intervals=[]),
        notification(intervals=[{"somethingElse": {}}]),
        notification(health_user_id=""),
        notification(data_type=""),
        notification(
            intervals=[civil_interval(civil(2026, 10, 2, 8), civil(2026, 10, 1, 8))]
        ),
        notification(
            intervals=[civil_interval(civil(2026, 2, 30), civil(2026, 3, 1))]
        ),
        {"data": "not-an-object"},
        {"type": "something-else"},
    ],
    ids=[
        "unknown-operation",
        "no-intervals",
        "no-usable-interval",
        "empty-user",
        "empty-type",
        "end-before-start",
        "impossible-date",
        "data-not-object",
        "no-data",
    ],
)
def test_invalid_item_is_dropped_and_the_rest_published(
    bad: dict, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    rig = Rig()
    resp = rig.post(dumps([bad, notification()]))
    assert resp.status_code == 204
    assert rig.calls == [(TASK, [H, "steps", "UPSERT", ["2026-10-01"]], QUEUE)]
    warnings = [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING and "googleHealth/notifications" in r.getMessage()
    ]
    assert warnings == ["googleHealth/notifications dropped items: 1"]


def test_item_spanning_more_than_31_dates_is_dropped() -> None:
    rig = Rig()
    wide = notification(
        data_type="sleep",
        intervals=[civil_interval(civil(2026, 1, 1, 12), civil(2026, 2, 1, 12))],
    )
    edge = notification(
        intervals=[civil_interval(civil(2026, 1, 1, 12), civil(2026, 1, 31, 12))],
    )
    resp = rig.post(dumps([wide, edge]))
    assert resp.status_code == 204
    assert len(rig.calls) == 1
    assert rig.calls[0][1][1] == "steps"
    assert len(rig.calls[0][1][3]) == 31


def test_a_verified_body_whose_every_item_is_invalid_is_acknowledged() -> None:
    """Redelivery cannot fix a structurally unprocessable item, so 204 and a WARNING."""
    rig = Rig()
    resp = rig.post(dumps([notification(operation="PATCH")]))
    assert resp.status_code == 204
    assert rig.calls == []


# --- publish failures ----------------------------------------------------------------


def test_publish_failure_on_the_second_group_is_503_after_publishing_the_first_once() -> None:
    rig = Rig(publisher=ScriptedPublisher(fail_on=2))
    resp = rig.post(fixture("batch_mixed.json"))
    assert resp.status_code == 503
    assert rig.calls == [(TASK, [H, "steps", "UPSERT", ["2026-03-07", "2026-07-14"]], QUEUE)]
    assert rig.publisher.attempts == 2


def test_publish_failure_is_503() -> None:
    rig = Rig(publisher=ScriptedPublisher(fail_on=1))
    resp = rig.post(fixture("upsert_steps.json"))
    assert resp.status_code == 503
    assert rig.calls == []


def test_unexpected_publisher_error_is_503() -> None:
    rig = Rig(publisher=ScriptedPublisher(fail_on=1, fail_with=RuntimeError("x")))
    resp = rig.post(fixture("upsert_steps.json"))
    assert resp.status_code == 503


# --- configuration ---------------------------------------------------------------------


def test_unset_webhook_secret_answers_503_even_to_an_empty_authorization() -> None:
    rig = Rig(settings=make_settings(webhook_secret=""))
    resp = rig.post(fixture("upsert_steps.json"), authorization="")
    assert resp.status_code == 503
    assert rig.verifier.calls == []
    assert rig.calls == []


def test_without_a_verifier_data_notifications_are_503_but_the_handshake_works() -> None:
    rig = Rig(no_verifier=True)
    assert rig.post(VERIFICATION, signature=None).status_code == 200
    assert rig.post(fixture("upsert_steps.json")).status_code == 503
    assert rig.calls == []


def test_route_is_marked_unauthenticated_and_has_no_write_guard() -> None:
    from openwellness_api.main import create_app

    routes = [
        route
        for route in create_app().routes
        if isinstance(route, APIRoute) and route.path == PATH
    ]
    assert len(routes) == 1
    route = routes[0]
    assert route.methods == {"POST"}
    assert (route.openapi_extra or {}).get(ALLOW_UNAUTHENTICATED) is True
    calls = [dep.call for dep in get_flat_dependant(route.dependant).dependencies]
    assert require_write_principal not in calls


# --- logging -----------------------------------------------------------------------------


def test_logs_never_carry_the_body_secret_signature_record_or_user_id(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    user = "HUSER-SENTINEL-7f3a"
    record = "RECORD-SENTINEL-91c2"
    body_marker = "BODY-SENTINEL-55e1"
    signature = "U0lHLVNFTlRJTkVMLWQ0Mg=="
    good = notification(
        health_user_id=user,
        data_type="sleep",
        operation="DELETE",
        recordId=record,
        clientProvidedSubscriptionName=body_marker,
    )
    bad = notification(health_user_id=user, operation="PATCH", recordId=record)
    body = dumps([good, bad])

    rig = Rig()
    assert rig.post(body, signature=signature).status_code == 204
    assert rig.post(body, authorization="wrong " + body_marker).status_code == 401
    assert rig.post(b"not json " + body_marker.encode(), signature=signature).status_code == 400

    Rig(verifier=FakeVerifier(result=False)).post(body, signature=signature)
    Rig(
        verifier=FakeVerifier(error=SignatureVerificationUnavailable("x"))
    ).post(body, signature=signature)
    Rig(publisher=ScriptedPublisher(fail_on=1)).post(body, signature=signature)

    over_cap = b'{"pad": "' + body_marker.encode() + b"x" * LIMIT + b'"}'
    assert rig.post(over_cap, signature=signature).status_code == 413
    assert rig.post(over_cap, authorization=None).status_code == 401

    app_records = [r for r in caplog.records if not r.name.startswith(("httpx", "httpcore"))]
    text = "\n".join(r.getMessage() for r in app_records)
    assert "googleHealth/notifications" in text
    for sentinel in (user, record, body_marker, signature, rig.secret):
        assert sentinel not in text


@pytest.fixture
def uvicorn_logging() -> Iterator[None]:
    """The real server's logging: uvicorn's config, restored after the test."""
    names = (
        "uvicorn",
        "uvicorn.error",
        "uvicorn.access",
        "openwellness_api.google_health.notifications",
    )
    saved = [
        (lg, list(lg.handlers), lg.level, lg.propagate)
        for lg in map(logging.getLogger, names)
    ]
    logging.getLogger(names[-1]).handlers[:] = []
    logging.getLogger(names[-1]).setLevel(logging.NOTSET)
    logging.config.dictConfig(uvicorn.config.LOGGING_CONFIG)
    yield
    for lg, handlers, level, propagate in saved:
        lg.handlers[:] = handlers
        lg.setLevel(level)
        lg.propagate = propagate


def give_root_a_handler_like_production(monkeypatch: pytest.MonkeyPatch) -> None:
    """A module-level ``logging.warning`` on an empty root runs ``basicConfig()``.

    Call from the test body: pytest re-adds its capture handlers to the root at
    each test phase, and ``basicConfig()`` does nothing while they are there.
    ``monkeypatch`` puts the root's own handler list back on teardown.
    """
    monkeypatch.setattr(logging.getLogger(), "handlers", [])
    logging.warning("a module-level logging call")


@pytest.mark.parametrize("root_handler_first", [True, False], ids=["before_install", "after_install"])
def test_notification_lines_reach_stdout_once_under_uvicorn_logging(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    uvicorn_logging: None,
    root_handler_first: bool,
) -> None:
    if root_handler_first:
        give_root_a_handler_like_production(monkeypatch)
    install_notifications_logger()
    install_notifications_logger()
    if not root_handler_first:
        give_root_a_handler_like_production(monkeypatch)

    rig = Rig()
    body = fixture("upsert_steps.json")
    assert rig.post(body).status_code == 204
    assert rig.post(body, authorization="wrong").status_code == 401

    out, err = capsys.readouterr()
    assert "WARNING:root:a module-level logging call" in err  # the root really has a handler
    both = (out + err).splitlines()
    published = [line for line in both if "googleHealth/notifications published:" in line]
    unauthorized = [line for line in both if "googleHealth/notifications unauthorized" in line]
    assert len(published) == 1
    assert f"items, {len(body)} bytes" in published[0]
    assert unauthorized == ["googleHealth/notifications unauthorized"]
    assert "INFO:openwellness_api" not in out + err
    assert "WARNING:openwellness_api" not in out + err
    assert published[0] in out.splitlines()
    assert unauthorized[0] in out.splitlines()


@pytest.mark.parametrize("data_type", ["heart_rate", "total_calories_burned", "heart-rate", "Steps"])
def test_a_google_data_type_with_underscores_or_capitals_is_enqueued(data_type: str) -> None:
    rig = Rig()
    resp = rig.post(dumps([notification(data_type=data_type)]))
    assert resp.status_code == 204
    assert [call[1][1] for call in rig.calls] == [data_type]


@pytest.mark.parametrize("data_type", ["has space", "semi;colon", "x" * 65])
def test_a_data_type_outside_the_safe_charset_is_dropped(data_type: str) -> None:
    rig = Rig()
    resp = rig.post(dumps([notification(data_type=data_type)]))
    assert resp.status_code == 204
    assert rig.calls == []
