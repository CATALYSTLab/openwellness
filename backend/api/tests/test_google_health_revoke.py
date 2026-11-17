"""The bridge-guarded internal revoke route (opserver Phase 17.3, GHR-02..GHR-05, GHR-08).

frame calls ``POST /internal/googleHealth/revocations`` for a coach with a
bridge JWT whose ``typ`` is ``gh-revoke-bridge`` (D-12). ow asks Google to
revoke each GOOGLE_ACTIVE grant of the participant before any write, then
ends those ``fitbits`` records with ``revokedAt``/``revokedBy`` and keeps
them (D-01..D-03). Every attempt writes one audit line on
``openwellness_api.audit.google_health``.
"""

from __future__ import annotations

from typing import Any

import pytest

from openwellness_api.google_health import bridge
from openwellness_api.google_health.bridge import INTERNAL_LINKS_PATH

from .google_health_harness import Harness, make_settings
from .test_google_health_bridge import (  # noqa: F401  (fixtures register by import)
    ACTOR,
    _Collect,
    audit,
    bearer,
    bridge_token,
    h,
    with_bridge,
)

# The cross-repo contract, pinned as literals (frame and opserver copy them).
REVOKE_PATH = "/internal/googleHealth/revocations"
REVOKE_TYP = "gh-revoke-bridge"


def revoke_token(pid: str, **overrides: Any) -> str:
    """A revoke bridge JWT as frame signs it; ``typ`` is the revoke one unless overridden."""
    overrides.setdefault("typ", REVOKE_TYP)
    return bridge_token(pid, **overrides)


def _revoke(h: Harness, pid: str, headers: dict[str, str] | None = None) -> Any:
    if headers is None:
        headers = bearer(revoke_token(pid))
    return h.client().post(REVOKE_PATH, json={"participantId": pid}, headers=headers)


def _fitbits(h: Harness) -> list[dict[str, Any]]:
    return list(h.db["fitbits"].find().sort("_id", 1))


# --- Task 1: the tracer ---------------------------------------------------------


def test_revoke_ends_the_google_record(h: Harness, audit: _Collect) -> None:
    pid = h.seed_participant()
    record_id = h.seed_google(pid, health_user_id="hu-1", migrated_at=1_790_000_000)
    count = h.db["fitbits"].count_documents({})

    resp = _revoke(h, pid)

    assert resp.status_code == 204, resp.text
    assert resp.content == b""
    assert resp.headers["cache-control"] == "no-store"
    [record] = h.google_records(participantId=pid)
    assert isinstance(record["supersededAt"], int)
    assert record["revokedAt"] == record["supersededAt"]
    assert record["supersededBy"] is None
    assert record["revokedBy"] == ACTOR
    assert record["refreshToken"] == "old-google-refresh"
    assert record["accessToken"] == "old-google-access"
    assert h.google.revokes == ["old-google-refresh"]
    assert h.active_google(participantId=pid) == []
    assert h.db["fitbits"].count_documents({}) == count
    assert audit.lines() == [
        f"googleHealth/internalRevocations outcome=ok actor={ACTOR} participantId={pid} "
        f"recordIds={record_id}"
    ]


def test_revoke_without_bearer_is_401(h: Harness, audit: _Collect) -> None:
    pid = h.seed_participant()
    h.seed_google(pid, health_user_id="hu-1", migrated_at=1_790_000_000)
    before = _fitbits(h)

    resp = _revoke(h, pid, headers={})

    assert resp.status_code == 401
    assert resp.json() == {
        "statusCode": 401,
        "error": "Unauthorized",
        "message": "Invalid bridge credential",
    }
    assert audit.lines() == [
        "googleHealth/internalRevocations outcome=401 actor=- participantId=- recordIds=-"
    ]
    assert _fitbits(h) == before
    assert h.google.revokes == []


def test_mint_token_cannot_revoke(h: Harness, audit: _Collect) -> None:
    pid = h.seed_participant()
    h.seed_google(pid, health_user_id="hu-1", migrated_at=1_790_000_000)
    before = _fitbits(h)

    resp = _revoke(h, pid, headers=bearer(bridge_token(pid)))

    assert resp.status_code == 401
    assert resp.json()["message"] == "Invalid bridge credential"
    assert audit.lines() == [
        f"googleHealth/internalRevocations outcome=401 actor=- participantId={pid} recordIds=-"
    ]
    assert _fitbits(h) == before
    assert h.google.revokes == []


def test_revoke_token_cannot_mint(h: Harness) -> None:
    pid = h.seed_participant()

    resp = h.client().post(
        INTERNAL_LINKS_PATH, json={"participantId": pid}, headers=bearer(revoke_token(pid))
    )

    assert resp.status_code == 401
    assert resp.json()["message"] == "Invalid bridge credential"


# --- Task 2: route outcomes --------------------------------------------------------


def test_revoke_path_is_the_contract_and_outside_api() -> None:
    assert bridge.REVOKE_PATH == REVOKE_PATH
    assert bridge.REVOKE_BRIDGE_TYP == REVOKE_TYP
    assert not bridge.REVOKE_PATH.startswith("/api/")


def test_a_dead_grant_ends_the_record(h: Harness) -> None:
    pid = h.seed_participant()
    h.seed_google(pid, health_user_id="hu-1", migrated_at=1_790_000_000)
    h.google.revoke_errors["old-google-refresh"] = "revoke_token_invalid"

    resp = _revoke(h, pid)

    assert resp.status_code == 204, resp.text
    assert h.google.revokes == ["old-google-refresh"]
    assert h.active_google(participantId=pid) == []


@pytest.mark.parametrize(
    ("kind", "status", "error", "message"),
    [
        ("revoke_failed", 502, "Bad Gateway", "Google did not confirm the revocation."),
        ("revoke_timeout", 504, "Gateway Timeout", "Google did not answer in time."),
    ],
)
def test_a_live_failure_changes_nothing(
    h: Harness, audit: _Collect, kind: str, status: int, error: str, message: str
) -> None:
    pid = h.seed_participant()
    record_id = h.seed_google(pid, health_user_id="hu-1", migrated_at=1_790_000_000)
    h.google.revoke_errors["old-google-refresh"] = kind
    before = _fitbits(h)

    resp = _revoke(h, pid)

    assert resp.status_code == status
    assert resp.json() == {"statusCode": status, "error": error, "message": message}
    assert _fitbits(h) == before
    assert audit.lines() == [
        f"googleHealth/internalRevocations outcome={status} actor={ACTOR} "
        f"participantId={pid} recordIds={record_id}"
    ]


@pytest.mark.parametrize(
    ("tokens", "sent"),
    [
        ({}, ["old-google-refresh"]),
        ({"refresh_token": None}, ["old-google-access"]),
        ({"refresh_token": ""}, ["old-google-access"]),
        ({"refresh_token": None, "access_token": None}, []),
        ({"refresh_token": "", "access_token": ""}, []),
    ],
)
def test_the_refresh_token_is_preferred(
    h: Harness, tokens: dict[str, Any], sent: list[str]
) -> None:
    pid = h.seed_participant()
    h.seed_google(pid, health_user_id="hu-1", migrated_at=1_790_000_000, **tokens)

    resp = _revoke(h, pid)

    assert resp.status_code == 204, resp.text
    assert h.google.revokes == sent
    assert h.active_google(participantId=pid) == []


def _seed_never_linked(h: Harness, pid: str) -> None:
    pass


def _seed_legacy_only(h: Harness, pid: str) -> None:
    h.seed_legacy(pid)


def _seed_already_revoked(h: Harness, pid: str) -> None:
    h.seed_google(pid, health_user_id="hu-1", migrated_at=1_790_000_000)
    assert _revoke(h, pid).status_code == 204
    h.google.revokes.clear()


@pytest.mark.parametrize(
    "seed", [_seed_never_linked, _seed_legacy_only, _seed_already_revoked]
)
def test_nothing_linked_is_409(h: Harness, audit: _Collect, seed: Any) -> None:
    pid = h.seed_participant()
    seed(h, pid)
    audit.records.clear()
    before = _fitbits(h)

    resp = _revoke(h, pid)

    assert resp.status_code == 409
    assert resp.json() == {
        "statusCode": 409,
        "error": "Conflict",
        "message": "No Google Health account is linked for this participant.",
    }
    assert h.google.revokes == []
    assert _fitbits(h) == before
    assert audit.lines() == [
        f"googleHealth/internalRevocations outcome=409 actor={ACTOR} participantId={pid} "
        "recordIds=-"
    ]


def test_a_held_study_still_revokes() -> None:
    held = with_bridge(Harness(make_settings(migration_hold="*")))
    pid = held.seed_participant()
    held.seed_google(pid, health_user_id="hu-1", migrated_at=1_790_000_000)

    assert _revoke(held, pid).status_code == 204
    assert held.active_google(participantId=pid) == []


def test_an_inactive_participant_still_revokes(h: Harness) -> None:
    pid = h.seed_participant(active=False)
    h.seed_google(pid, health_user_id="hu-1", migrated_at=1_790_000_000)

    assert _revoke(h, pid).status_code == 204
    assert h.active_google(participantId=pid) == []


def test_a_write_failure_after_google_is_500(
    h: Harness, audit: _Collect, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid = h.seed_participant()
    record_id = h.seed_google(pid, health_user_id="hu-1", migrated_at=1_790_000_000)

    def fail(*args: Any, **kwargs: Any) -> int:
        raise RuntimeError("write failed")

    monkeypatch.setattr(h.deps.store, "end_revoked", fail)

    resp = _revoke(h, pid)

    assert resp.status_code == 500
    assert resp.json()["message"] == "An internal server error occurred"
    assert h.google.revokes == ["old-google-refresh"]
    assert audit.lines() == [
        f"googleHealth/internalRevocations outcome=500 actor={ACTOR} participantId={pid} "
        f"recordIds={record_id}"
    ]


def test_a_record_without_a_health_user_id_is_500(h: Harness) -> None:
    pid = h.seed_participant()
    record_id = h.seed_google(pid, health_user_id="hu-1", migrated_at=1_790_000_000)
    h.db["fitbits"].update_one({"participantId": pid}, {"$unset": {"healthUserId": ""}})
    before = _fitbits(h)

    resp = _revoke(h, pid)

    assert resp.status_code == 500
    assert h.google.revokes == []
    assert _fitbits(h) == before
    assert record_id


def test_a_revoked_participant_can_link_again(h: Harness) -> None:
    pid = h.seed_participant()
    old_id = h.seed_google(pid, health_user_id="hu-1", migrated_at=1_790_000_000)
    assert _revoke(h, pid).status_code == 204

    h.google.add("c2", access="a2", refresh="r2", health_user_id="hu-1", legacy_user_id=None)
    resp = h.run_flow(pid, "c2")

    assert resp.status_code == 200, resp.text
    [active] = h.active_google(participantId=pid)
    assert str(active["_id"]) != old_id
    assert active["refreshToken"] == "r2"
    [old] = [r for r in h.google_records(participantId=pid) if str(r["_id"]) == old_id]
    assert isinstance(old["revokedAt"], int)
    assert old["supersededBy"] is None
