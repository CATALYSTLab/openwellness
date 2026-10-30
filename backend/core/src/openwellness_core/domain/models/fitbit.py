"""Connected Fitbit account, and the ``fitbits`` provider contract.

A participant's wearable connection lives in the Mongo ``fitbits``
collection. From opserver Phase 10.1 on, that collection holds two kinds of
record side by side: legacy Fitbit Web API records (no ``provider`` field)
and Google Health API records (``provider: "googleHealth"``). When a
participant migrates, the new Google record supersedes the legacy one
(``supersededAt``/``supersededBy``); the legacy record is kept for audit.

This module is OpenWellness's single statement of that contract, locked in
opserver ``docs/google-health.md`` ("Reference: the contract"). frame and the
scheduler (``schedulernew.common.domain.fitbit_provider``) implement the same
filter documents and selection rule; ``ow_api`` imports them from here.

Why ``None`` rather than ``$exists: false``: a Mongo ``{field: null}`` match
covers both a missing field and an explicit null. A writer that ``$set``s
every field leaves ``supersededAt: null`` on a record rather than no field,
and ``$exists: false`` would hide it. Likewise
``{"provider": {"$ne": "googleHealth"}}`` matches documents with no
``provider`` field, so existing legacy records stay visible to legacy readers.

The filter accessors return a fresh deep copy on every call: the nested
``$ne`` document is mutable, and a caller that edits the returned query must
not change the next caller's filter.

Read scope: ``MongoFitbitRepository.get_by_participant_id`` is the
active-connection lookup and never returns a superseded record.
``get_by_id`` and ``list_all`` (inherited from the base repository) are
audit reads and stay unfiltered by design: they return superseded records.
"""

import copy
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Optional, TypeVar

from .base_entity import BaseEntity

PROVIDER_FITBIT = "fitbit"
"""Legacy Fitbit Web API. Stored records omit ``provider`` (never back-filled)."""

PROVIDER_GOOGLE_HEALTH = "googleHealth"
"""Google Health API."""

_ACTIVE: dict = {"supersededAt": None}
_LEGACY_ACTIVE: dict = {
    "provider": {"$ne": PROVIDER_GOOGLE_HEALTH},
    "supersededAt": None,
}
_GOOGLE_ACTIVE: dict = {"provider": PROVIDER_GOOGLE_HEALTH, "supersededAt": None}

D13_ALIASES: tuple[str, ...] = (
    "provider",
    "expiresAt",
    "scope",
    "healthUserId",
    "legacyUserId",
    "supersededAt",
    "supersededBy",
    "migratedAt",
    "migrationStatus",
    "reconsentRequiredAt",
    "lastSyncAt",
    "devices",
    "devicesFetchedAt",
)
"""The thirteen persisted field names the contract adds to a ``fitbits`` record."""

# Domain attribute name for each persisted name the selection rule reads.
_ATTRIBUTE = {"provider": "provider", "supersededAt": "superseded_at"}

Record = TypeVar("Record")


def active_filter() -> dict:
    """``ACTIVE``: records not superseded, either provider."""
    return copy.deepcopy(_ACTIVE)


def legacy_active_filter() -> dict:
    """``LEGACY_ACTIVE``: active records of the legacy Fitbit provider."""
    return copy.deepcopy(_LEGACY_ACTIVE)


def google_active_filter() -> dict:
    """``GOOGLE_ACTIVE``: active Google Health records."""
    return copy.deepcopy(_GOOGLE_ACTIVE)


def _field(record: Any, name: str) -> Any:
    """Read persisted field ``name`` from a Mongo document or a domain entity.

    A document is keyed by the persisted (camelCase) name, an entity by the
    snake_case attribute. Missing means None.
    """
    if isinstance(record, dict):
        return record.get(name)
    return getattr(record, _ATTRIBUTE[name], None)


def is_google_health(record: Any) -> bool:
    """True only when the record's provider is ``googleHealth``."""
    return _field(record, "provider") == PROVIDER_GOOGLE_HEALTH


def is_active(record: Any) -> bool:
    """True when the record has not been superseded."""
    return _field(record, "supersededAt") is None


def select_active(records: Iterable[Record]) -> Optional[Record]:
    """Pick a participant's record by the contract's selection rule (D-08).

    1. Among the ACTIVE records, if exactly one is a Google Health record, it wins.
    2. Otherwise, if exactly one ACTIVE record exists, it wins.
    3. Otherwise, none.

    Superseded records are dropped here as well as by the query, so the rule
    holds for any input. Accepts domain entities or raw Mongo documents.
    Two active records are a violated invariant (I1), repaired by the
    backfill's reconcile phase; this rule only decides what to use until then.
    """
    active = [r for r in records if is_active(r)]
    google = [r for r in active if is_google_health(r)]
    if len(google) == 1:
        return google[0]
    if len(active) == 1:
        return active[0]
    return None


@dataclass(kw_only=True)
class Fitbit(BaseEntity):
    """A connected Fitbit account (legacy Fitbit Web API or Google Health).

    The fields after ``time_created`` are the contract's D-13 fields; each
    defaults to None so an existing legacy record loads unchanged.
    """

    participant_id: str
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    owner_id: Optional[str] = None
    subscription_id: Optional[str] = None
    time_created: datetime = field(default_factory=datetime.now)
    provider: Optional[str] = None
    expires_at: Optional[int] = None
    scope: Optional[str] = None
    health_user_id: Optional[str] = None
    legacy_user_id: Optional[str] = None
    superseded_at: Optional[int] = None
    superseded_by: Optional[str] = None
    migrated_at: Optional[int] = None
    migration_status: Optional[str] = None
    reconsent_required_at: Optional[int] = None
    last_sync_at: Optional[int] = None
    devices: Optional[list] = None
    devices_fetched_at: Optional[int] = None
