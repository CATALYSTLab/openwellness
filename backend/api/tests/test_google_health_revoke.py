"""The bridge-guarded internal revoke route (opserver Phase 17.3, GHR-02..GHR-05, GHR-08).

frame calls ``POST /internal/googleHealth/revocations`` for a coach with a
bridge JWT whose ``typ`` is ``gh-revoke-bridge`` (D-12). ow asks Google to
revoke each GOOGLE_ACTIVE grant of the participant before any write, then
ends those ``fitbits`` records with ``revokedAt``/``revokedBy`` and keeps
them (D-01..D-03). Every attempt writes one audit line on
``openwellness_api.audit.google_health``.
"""

from __future__ import annotations

import dataclasses
import logging
import re
import time
from collections.abc import Callable
from typing import Any

import pytest
import requests

from openwellness_api.google_health import bridge
from openwellness_api.google_health.bridge import INTERNAL_LINKS_PATH
from openwellness_api.google_health.google_client import (
    GoogleOAuthError,
    RequestsGoogleOAuthClient,
)
from openwellness_api.google_health.tokens import PID_LOCK_KEY, account_lock_key

from .google_health_harness import Harness, make_settings
from .test_google_health_bridge import (  # noqa: F401  (fixtures register by import)
    ACTOR,
    BAD_BODIES,
    NO_BEARER_TOKEN,
    OTHER_PID,
    OTHER_SECRET,
    REFUSALS,
    _Collect,
    _disabled_cases,
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


# --- 17.3-02 Task 1: the real Google client tells a dead grant from a live failure ---


class _StubResponse:
    def __init__(self, status_code: int, body: Any) -> None:
        self.status_code = status_code
        self._body = body

    def json(self) -> Any:
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class _StubSession:
    """A ``requests.Session`` stand-in whose ``post`` answers or raises as set."""

    def __init__(self, status_code: int = 200, body: Any = None, raises: Exception | None = None):
        self.status_code = status_code
        self.body = body
        self.raises = raises
        self.posts: list[tuple[str, dict[str, Any]]] = []

    def post(self, url: str, **kwargs: Any) -> _StubResponse:
        self.posts.append((url, kwargs))
        if self.raises is not None:
            raise self.raises
        return _StubResponse(self.status_code, self.body)


_DESCRIPTION = "the-description-echoes-old-google-refresh"


def _client(session: _StubSession) -> RequestsGoogleOAuthClient:
    return RequestsGoogleOAuthClient(make_settings(), session=session)  # type: ignore[arg-type]


def test_the_real_client_returns_on_200() -> None:
    session = _StubSession(200, {})
    assert _client(session).revoke("old-google-refresh") is None
    [(url, kwargs)] = session.posts
    assert url == make_settings().revoke_endpoint
    assert kwargs["data"] == {"token": "old-google-refresh"}


@pytest.mark.parametrize(
    ("session", "kind"),
    [
        (_StubSession(400, {"error": "invalid_token"}), "revoke_token_invalid"),
        (_StubSession(400, {"error": "invalid_grant"}), "revoke_token_invalid"),
        (
            _StubSession(400, {"error": "invalid_request", "error_description": _DESCRIPTION}),
            "revoke_failed",
        ),
        (_StubSession(400, ValueError("not json")), "revoke_failed"),
        (_StubSession(400, ["invalid_token"]), "revoke_failed"),
        (_StubSession(503, {"error": "invalid_token"}), "revoke_failed"),
        (_StubSession(raises=requests.Timeout("old-google-refresh")), "revoke_timeout"),
        (_StubSession(raises=requests.ConnectionError("old-google-refresh")), "revoke_failed"),
    ],
    ids=[
        "invalid_token",
        "invalid_grant",
        "invalid_request",
        "non_json",
        "non_object",
        "503",
        "timeout",
        "connection_error",
    ],
)
def test_the_real_client_classifies_a_failed_revoke(session: _StubSession, kind: str) -> None:
    with pytest.raises(GoogleOAuthError) as caught:
        _client(session).revoke("old-google-refresh")
    assert caught.value.kind == kind
    assert str(caught.value) == kind
    assert "old-google-refresh" not in str(caught.value)
    assert _DESCRIPTION not in str(caught.value)


def _with_real_client(h: Harness, session: _StubSession) -> None:
    h.app.state.google_health_deps = dataclasses.replace(h.deps, google=_client(session))


def test_a_dead_grant_at_google_ends_the_record_through_the_real_client(h: Harness) -> None:
    pid = h.seed_participant()
    h.seed_google(pid, health_user_id="hu-1", migrated_at=1_790_000_000)
    session = _StubSession(400, {"error": "invalid_token"})
    _with_real_client(h, session)

    resp = _revoke(h, pid)

    assert resp.status_code == 204, resp.text
    assert h.active_google(participantId=pid) == []
    assert [url for url, _ in session.posts] == [make_settings().revoke_endpoint]


@pytest.mark.parametrize(
    ("session", "status"),
    [
        (_StubSession(400, {"error": "invalid_request"}), 502),
        (_StubSession(raises=requests.Timeout()), 504),
    ],
    ids=["invalid_request", "timeout"],
)
def test_a_live_failure_through_the_real_client_changes_nothing(
    h: Harness, session: _StubSession, status: int
) -> None:
    pid = h.seed_participant()
    h.seed_google(pid, health_user_id="hu-1", migrated_at=1_790_000_000)
    _with_real_client(h, session)
    before = _fitbits(h)

    resp = _revoke(h, pid)

    assert resp.status_code == status
    assert _fitbits(h) == before
    assert [url for url, _ in session.posts] == [make_settings().revoke_endpoint]


# --- 17.3-02 Task 2: every GOOGLE_ACTIVE record under every lock (D-14) ----------------


_BUSY = {
    "statusCode": 423,
    "error": "Locked",
    "message": "Another change for this participant is in progress.",
}


def _seed_two(h: Harness, pid: str, second_hu: str = "hu-1") -> tuple[str, str]:
    first = h.seed_google(pid, health_user_id="hu-1", migrated_at=1_790_000_000)
    second = h.seed_google(
        pid,
        health_user_id=second_hu,
        migrated_at=1_790_000_100,
        refresh_token="second-refresh",
        access_token="second-access",
    )
    return first, second


def test_every_active_record_is_revoked_and_ended(h: Harness, audit: _Collect) -> None:
    pid = h.seed_participant()
    first, second = _seed_two(h, pid)

    resp = _revoke(h, pid)

    assert resp.status_code == 204, resp.text
    assert h.google.revokes == ["old-google-refresh", "second-refresh"]
    ended = h.google_records(participantId=pid)
    assert len(ended) == 2
    assert len({record["revokedAt"] for record in ended}) == 1
    assert all(record["revokedBy"] == ACTOR for record in ended)
    assert audit.lines() == [
        f"googleHealth/internalRevocations outcome=ok actor={ACTOR} participantId={pid} "
        f"recordIds={first},{second}"
    ]


def test_every_lock_is_held_during_google_and_released_after(h: Harness) -> None:
    pid = h.seed_participant()
    _seed_two(h, pid, second_hu="hu-2")
    expected = sorted([PID_LOCK_KEY.format(participant_id=pid), account_lock_key("hu-1"),
                       account_lock_key("hu-2")])
    seen: list[list[str]] = []
    revoke = h.google.revoke

    def revoke_seeing_locks(token: str) -> None:
        seen.append(sorted(h.redis.keys("gh:lock:*")))
        revoke(token)

    h.google.revoke = revoke_seeing_locks  # type: ignore[method-assign]

    resp = _revoke(h, pid)

    assert resp.status_code == 204, resp.text
    assert seen == [expected, expected]
    assert h.redis.keys("gh:lock:*") == []


def test_one_live_failure_changes_every_record_back_to_nothing(h: Harness) -> None:
    pid = h.seed_participant()
    _seed_two(h, pid, second_hu="hu-2")
    h.google.revoke_errors["second-refresh"] = "revoke_failed"
    before = _fitbits(h)

    resp = _revoke(h, pid)

    assert resp.status_code == 502
    # The first grant was revoked at Google, yet nothing is written (D-14).
    assert h.google.revokes == ["old-google-refresh", "second-refresh"]
    assert _fitbits(h) == before
    assert h.redis.keys("gh:lock:*") == []


def test_one_dead_and_one_ok_ends_both(h: Harness) -> None:
    pid = h.seed_participant()
    _seed_two(h, pid, second_hu="hu-2")
    h.google.revoke_errors["old-google-refresh"] = "revoke_token_invalid"

    resp = _revoke(h, pid)

    assert resp.status_code == 204, resp.text
    assert h.active_google(participantId=pid) == []


@pytest.mark.parametrize("held", ["pid", "hu-1", "hu-2"])
def test_a_busy_lock_is_423_and_changes_nothing(h: Harness, audit: _Collect, held: str) -> None:
    pid = h.seed_participant()
    first, second = _seed_two(h, pid, second_hu="hu-2")
    key = PID_LOCK_KEY.format(participant_id=pid) if held == "pid" else account_lock_key(held)
    h.redis.set(key, "another-owner", px=60000)
    before = _fitbits(h)

    resp = _revoke(h, pid)

    assert resp.status_code == 423
    assert resp.json() == _BUSY
    assert h.google.revokes == []
    assert _fitbits(h) == before
    assert h.redis.get(key) == "another-owner"
    assert h.redis.keys("gh:lock:*") == [key]
    assert audit.lines() == [
        f"googleHealth/internalRevocations outcome=423 actor={ACTOR} participantId={pid} "
        f"recordIds={first},{second}"
    ]


def test_a_shared_account_is_500_and_never_revoked(h: Harness, audit: _Collect) -> None:
    pid = h.seed_participant()
    record_id = h.seed_google(pid, health_user_id="hu-1", migrated_at=1_790_000_000)
    other = h.seed_participant()
    h.seed_google(
        other, health_user_id="hu-1", migrated_at=1_790_000_000, refresh_token="other-refresh"
    )
    before = _fitbits(h)

    resp = _revoke(h, pid)

    assert resp.status_code == 500
    assert resp.json()["message"] == "An internal server error occurred"
    assert h.google.revokes == []
    assert _fitbits(h) == before
    assert h.redis.keys("gh:lock:*") == []
    assert audit.lines() == [
        f"googleHealth/internalRevocations outcome=500 actor={ACTOR} participantId={pid} "
        f"recordIds={record_id} owner={other}"
    ]


def _change_under_the_locks(h: Harness, change: Any) -> None:
    acquire = h.deps.tokens.acquire_locks

    def acquire_then_change(*args: Any) -> Any:
        locks = acquire(*args)
        change()
        return locks

    h.deps.tokens.acquire_locks = acquire_then_change  # type: ignore[method-assign]


def test_records_gone_under_the_locks_is_409(h: Harness) -> None:
    pid = h.seed_participant()
    h.seed_google(pid, health_user_id="hu-1", migrated_at=1_790_000_000)
    _change_under_the_locks(
        h,
        lambda: h.db["fitbits"].update_many(
            {"participantId": pid}, {"$set": {"supersededAt": 1, "supersededBy": None}}
        ),
    )

    resp = _revoke(h, pid)

    assert resp.status_code == 409
    assert h.google.revokes == []
    assert h.redis.keys("gh:lock:*") == []


def test_a_record_set_changed_under_the_locks_is_423(h: Harness) -> None:
    pid = h.seed_participant()
    h.seed_google(pid, health_user_id="hu-1", migrated_at=1_790_000_000)
    _change_under_the_locks(
        h, lambda: h.seed_google(pid, health_user_id="hu-1", migrated_at=1_790_000_200)
    )
    before_change = h.db["fitbits"].count_documents({})

    resp = _revoke(h, pid)

    assert resp.status_code == 423
    assert resp.json() == _BUSY
    assert h.google.revokes == []
    assert len(h.active_google(participantId=pid)) == 2
    assert h.db["fitbits"].count_documents({}) == before_change + 1
    assert h.redis.keys("gh:lock:*") == []


@pytest.mark.parametrize(
    ("lost_after", "called"),
    [
        # Caught before the next Google call.
        ("old-google-refresh", ["old-google-refresh"]),
        # Caught before the write.
        ("second-refresh", ["old-google-refresh", "second-refresh"]),
    ],
)
def test_a_lease_lost_during_the_revoke_is_423_and_writes_nothing(
    h: Harness, audit: _Collect, lost_after: str, called: list[str]
) -> None:
    pid = h.seed_participant()
    first, second = _seed_two(h, pid, second_hu="hu-2")
    key = account_lock_key("hu-2")
    revoke = h.google.revoke

    def revoke_then_lease_lapses(token: str) -> None:
        revoke(token)
        if token == lost_after:
            # The lease expired during the call and another request took the key.
            h.redis.set(key, "another-owner", px=60000)

    h.google.revoke = revoke_then_lease_lapses  # type: ignore[method-assign]
    before = _fitbits(h)

    resp = _revoke(h, pid)

    assert resp.status_code == 423
    assert resp.json() == _BUSY
    assert h.google.revokes == called
    assert _fitbits(h) == before
    assert h.redis.keys("gh:lock:*") == [key]
    assert h.redis.get(key) == "another-owner"
    assert audit.lines() == [
        f"googleHealth/internalRevocations outcome=423 actor={ACTOR} participantId={pid} "
        f"recordIds={first},{second}"
    ]


# --- 17.3-02 Task 3: refusal, disabled-rule and bad-body matrices; one line per attempt ---

# Each mint refusal re-signed as a revoke token where the case signs one (D-12).
REVOKE_REFUSALS: dict[str, Callable[[Harness, str], dict[str, str]]] = {
    "wrong_secret": lambda h, pid: bearer(revoke_token(pid, secret=OTHER_SECRET)),
    "ow_access_token": REFUSALS["ow_access_token"],
    "link_token": REFUSALS["link_token"],
    "expired": lambda h, pid: bearer(
        revoke_token(pid, iat=int(time.time()) - 120, exp=int(time.time()) - 60)
    ),
    "no_typ": lambda h, pid: bearer(revoke_token(pid, drop=("typ",))),
    "wrong_typ": lambda h, pid: bearer(revoke_token(pid, typ="access")),
    "wrong_aud": lambda h, pid: bearer(revoke_token(pid, aud="openwellness-api")),
    "wrong_iss": lambda h, pid: bearer(revoke_token(pid, iss="openwellness-api")),
    "lifetime_121": lambda h, pid: bearer(revoke_token(pid, lifetime=121)),
    "pid_not_body": lambda h, pid: bearer(revoke_token(OTHER_PID)),
    "sub_not_hex": lambda h, pid: bearer(revoke_token(pid, sub="coach-1")),
    "hs512": lambda h, pid: bearer(revoke_token(pid, algorithm="HS512")),
    "no_jti": lambda h, pid: bearer(revoke_token(pid, drop=("jti",))),
    "basic_scheme": REFUSALS["basic_scheme"],
    "empty_bearer": REFUSALS["empty_bearer"],
    "mint_typ": lambda h, pid: bearer(bridge_token(pid)),
}

REVOKE_AUDIT_LINE = re.compile(
    r"^googleHealth/internalRevocations outcome=(ok|400|401|409|423|500|502|503|504) "
    r"actor=([0-9a-f]{24}|-) participantId=([0-9a-f]{24}|-) "
    r"recordIds=([0-9a-f]{24}(,[0-9a-f]{24})*|-)( owner=[0-9a-f]{24})?$"
)


def test_revoke_refusals_mirror_the_mint_refusals() -> None:
    assert set(REVOKE_REFUSALS) == (set(REFUSALS) - {"revoke_typ_on_links"}) | {"mint_typ"}


@pytest.mark.parametrize("case", sorted(REVOKE_REFUSALS))
def test_revoke_refusals(h: Harness, audit: _Collect, case: str) -> None:
    pid = h.seed_participant()
    h.seed_google(pid, health_user_id="hu-1", migrated_at=1_790_000_000)
    before = _fitbits(h)

    resp = _revoke(h, pid, headers=REVOKE_REFUSALS[case](h, pid))

    assert resp.status_code == 401, resp.text
    assert resp.json() == {
        "statusCode": 401,
        "error": "Unauthorized",
        "message": "Invalid bridge credential",
    }
    logged_pid = "-" if case in NO_BEARER_TOKEN else pid
    assert audit.lines() == [
        f"googleHealth/internalRevocations outcome=401 actor=- participantId={logged_pid} "
        "recordIds=-"
    ]
    assert h.google.revokes == []
    assert _fitbits(h) == before


@pytest.mark.parametrize("rule", sorted(_disabled_cases(make_settings())))
def test_revoke_disabled_answers_503(audit: _Collect, rule: str) -> None:
    harness = Harness()
    secret, rule_name = _disabled_cases(harness.settings)[rule]
    h = with_bridge(harness, secret=secret)
    assert h.app.state.google_health_bridge.disabled == (rule_name,)
    pid = h.seed_participant()
    h.seed_google(pid, health_user_id="hu-1", migrated_at=1_790_000_000)
    before = _fitbits(h)

    resp = _revoke(h, pid)

    assert resp.status_code == 503, resp.text
    assert resp.json() == {
        "statusCode": 503,
        "error": "Service Unavailable",
        "message": "Google Health is not available.",
    }
    assert audit.lines() == [
        "googleHealth/internalRevocations outcome=503 actor=- participantId=- recordIds=-"
    ]
    assert h.google.revokes == []
    assert _fitbits(h) == before


@pytest.mark.parametrize("body", sorted(BAD_BODIES))
def test_revoke_bad_body_is_400(h: Harness, audit: _Collect, body: str) -> None:
    pid = h.seed_participant()
    kwargs = BAD_BODIES[body](pid)
    headers = {**kwargs.pop("headers", {}), **bearer(revoke_token(pid))}

    resp = h.client().post(REVOKE_PATH, headers=headers, **kwargs)

    assert resp.status_code == 400, resp.text
    assert resp.json() == {
        "statusCode": 400,
        "error": "Bad Request",
        "message": "Invalid request payload input",
    }
    assert audit.lines() == [
        "googleHealth/internalRevocations outcome=400 actor=- participantId=- recordIds=-"
    ]


def test_revoke_missing_credential_is_401_before_503(audit: _Collect) -> None:
    h = with_bridge(Harness(), secret="")
    pid = h.seed_participant()

    resp = _revoke(h, pid, headers={})

    assert resp.status_code == 401, resp.text
    assert audit.lines() == [
        "googleHealth/internalRevocations outcome=401 actor=- participantId=- recordIds=-"
    ]


def test_revoke_missing_credential_is_401_before_400(h: Harness, audit: _Collect) -> None:
    resp = h.client().post(REVOKE_PATH, json={"participantId": "not-hex"})

    assert resp.status_code == 401, resp.text
    assert audit.lines() == [
        "googleHealth/internalRevocations outcome=401 actor=- participantId=- recordIds=-"
    ]


def _seeded(h: Harness, n: int) -> str:
    pid = h.seed_participant()
    h.seed_google(
        pid,
        health_user_id=f"hu-{n}",
        migrated_at=1_790_000_000,
        refresh_token=f"refresh-{n}",
        access_token=f"access-{n}",
    )
    return pid


def test_every_revoke_outcome_writes_exactly_one_matching_line(audit: _Collect) -> None:
    h = with_bridge(Harness())
    client = h.client()
    ok, busy, bad_gateway, timeout = (_seeded(h, n) for n in range(1, 5))
    h.redis.set(PID_LOCK_KEY.format(participant_id=busy), "another-owner", px=60000)
    h.google.revoke_errors["refresh-3"] = "revoke_failed"
    h.google.revoke_errors["refresh-4"] = "revoke_timeout"
    shared, owner = h.seed_participant(), h.seed_participant()
    for pid in (shared, owner):
        h.seed_google(pid, health_user_id="hu-shared", migrated_at=1_790_000_000)
    disabled = with_bridge(Harness(), secret="")
    off = disabled.seed_participant()

    def post(pid: str, **kwargs: Any) -> int:
        kwargs.setdefault("json", {"participantId": pid})
        kwargs.setdefault("headers", bearer(revoke_token(pid)))
        return client.post(REVOKE_PATH, **kwargs).status_code

    attempts: list[Callable[[], int]] = [
        lambda: post(ok),
        lambda: post(ok, headers={}),
        lambda: post(ok, json={"participantId": "nope"}),
        lambda: post(ok),
        lambda: post(busy),
        lambda: post(bad_gateway),
        lambda: post(timeout),
        lambda: post(shared),
        lambda: _revoke(disabled, off).status_code,
    ]
    statuses = []
    for n, attempt in enumerate(attempts, start=1):
        statuses.append(attempt())
        assert len(audit.lines()) == n

    assert statuses == [204, 401, 400, 409, 423, 502, 504, 500, 503]
    lines = audit.lines()
    assert all(REVOKE_AUDIT_LINE.match(line) for line in lines), lines
    assert [line for line in lines if " owner=" in line] == [lines[7]]
    assert lines[7].endswith(f" owner={owner}")


def test_no_revoke_log_record_carries_a_token(
    h: Harness, audit: _Collect, caplog: pytest.LogCaptureFixture
) -> None:
    health_user_id = "health-user-id-never-logged"
    done, failing = h.seed_participant(), h.seed_participant()
    for n, pid in enumerate((done, failing), start=1):
        h.seed_google(
            pid,
            health_user_id=f"{health_user_id}-{n}",
            migrated_at=1_790_000_000,
            refresh_token=f"refresh-never-logged-{n}",
            access_token=f"access-never-logged-{n}",
        )
    session = _StubSession(200, {})
    _with_real_client(h, session)
    tokens = [revoke_token(done), revoke_token(failing)]

    with caplog.at_level(logging.DEBUG):
        first = _revoke(h, done, headers=bearer(tokens[0]))
        session.status_code = 400
        session.body = {"error": "invalid_request", "error_description": "refresh-never-logged-2"}
        second = _revoke(h, failing, headers=bearer(tokens[1]))

    assert (first.status_code, second.status_code) == (204, 502)
    assert len(audit.records) == 2
    messages = [r.getMessage() for r in (*caplog.records, *audit.records)]
    secrets = [*tokens, health_user_id, "refresh-never-logged", "access-never-logged"]
    for message in messages:
        for secret in [*secrets, "error_description"]:
            assert secret not in message, message
