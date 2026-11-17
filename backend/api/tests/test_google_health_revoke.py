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

from openwellness_api.google_health.bridge import INTERNAL_LINKS_PATH

from .google_health_harness import Harness
from .test_google_health_bridge import (  # noqa: F401  (fixtures register by import)
    ACTOR,
    _Collect,
    audit,
    bearer,
    bridge_token,
    h,
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
