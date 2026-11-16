"""Google Health authorization: staff link -> consent -> Google record (10.1-05).

GHA-01 and the supersede half of GHA-06. The flow runs end to end against
fakes (see ``google_health_harness``): a staff member mints a
participant-bound link, the participant's browser follows it to Google with a
signed, browser-bound ``state``, and ``finishAuth`` stores one
``provider: googleHealth`` record, supersedes every other active record of the
participant, and publishes ``googleHealth.completeMigration`` onto
``scheduler_new``. Contract: opserver ``docs/google-health.md``.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import urllib.parse
from datetime import UTC, datetime

import jwt
import pytest
import time_machine
from bson import ObjectId

from openwellness_api.deps.principal import Principal
from openwellness_api.event_handlers.ports import TaskPublishError
from openwellness_api.google_health.google_client import (
    GoogleOAuthError,
    RequestsGoogleOAuthClient,
)
from openwellness_api.google_health.oauth import browser_hash

from .google_health_harness import (
    AUTHORIZE_PATH,
    FINISH_PATH,
    FULL_SCOPE,
    LINKS_PATH,
    PUBLIC_BASE_URL,
    Harness,
    set_cookie_header,
)

FROZEN = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)
FROZEN_TS = int(FROZEN.timestamp())
SCOPES = FULL_SCOPE.split(" ")
# Dropped by opserver 17.2 D-01; grants made before the change still carry it.
OLD_SETTINGS_SCOPE = "https://www.googleapis.com/auth/googlehealth.settings.readonly"


@pytest.fixture
def h() -> Harness:
    return Harness()


def _decode_state(h: Harness, state: str) -> dict:
    return jwt.decode(
        state,
        h.settings.state_secret,
        algorithms=["HS256"],
        audience="googleHealth:state",
        issuer="openwellness-api",
    )


def _b64url_sha256(value: str) -> str:
    digest = hashlib.sha256(value.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# --- Task 1: the happy path ---------------------------------------------------


def test_admin_mints_a_participant_link(h: Harness) -> None:
    pid = h.seed_participant()
    with time_machine.travel(FROZEN, tick=False):
        resp = h.client().post("/api/googleHealth/links", json={"participantId": pid})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body) == {"url", "expiresAt"}
    assert body["url"].startswith(f"{PUBLIC_BASE_URL}{AUTHORIZE_PATH}?t=")
    assert isinstance(body["expiresAt"], int)
    assert body["expiresAt"] == FROZEN_TS + 72 * 3600


def test_authorize_redirects_to_google_with_a_browser_bound_state(h: Harness) -> None:
    pid = h.seed_participant()
    client = h.client()
    with time_machine.travel(FROZEN, tick=False):
        url = h.mint_link(client, pid)
        resp, state, cookie = h.authorize(client, url)
        claims = _decode_state(h, state)
        # Read under the same frozen clock the nonce was stored with.
        ttl = h.redis.ttl(f"gh:state:{claims['jti']}")

    location = urllib.parse.urlsplit(resp.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == (
        "https://accounts.google.com/o/oauth2/v2/auth"
    )
    query = urllib.parse.parse_qs(location.query)
    assert query["response_type"] == ["code"]
    assert query["access_type"] == ["offline"]
    assert query["prompt"] == ["consent"]
    assert query["client_id"] == [h.settings.client_id]
    assert query["redirect_uri"] == [f"{PUBLIC_BASE_URL}/api/googleHealth/finishAuth"]
    assert query["scope"][0].split(" ") == SCOPES
    assert len(SCOPES) == 3

    assert claims["aud"] == "googleHealth:state"
    assert claims["sub"] == pid
    assert claims["exp"] == FROZEN_TS + 900
    assert claims["bh"] == _b64url_sha256(cookie)

    header = set_cookie_header(resp)
    attributes = {part.strip().split("=", 1)[0].lower() for part in header.split(";")[1:]}
    assert {"httponly", "secure", "samesite", "path", "max-age"} <= attributes
    assert "samesite=lax" in header.lower()
    assert "path=/api/googlehealth" in header.lower()
    assert "max-age=900" in header.lower()
    assert len(base64.urlsafe_b64decode(cookie + "=" * (-len(cookie) % 4))) == 32

    assert 0 < ttl <= 900


def test_finish_auth_stores_the_google_record_supersedes_legacy_and_publishes(
    h: Harness,
) -> None:
    pid = h.seed_participant()
    legacy_id = h.seed_legacy(pid)
    h.google.add(
        "code-1",
        access="g-access-1",
        refresh="g-refresh-1",
        health_user_id="HUSER1",
        legacy_user_id="LEGACYOWNER1",
    )

    with time_machine.travel(FROZEN, tick=False):
        resp = h.run_flow(pid, "code-1")

    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("text/html")

    (record,) = h.google_records()
    google_id = str(record["_id"])
    assert set(record) == {
        "_id",
        "participantId",
        "provider",
        "accessToken",
        "refreshToken",
        "expiresAt",
        "scope",
        "healthUserId",
        "legacyUserId",
        "timeCreated",
        "migratedAt",
        "migrationStatus",
    }
    assert record["participantId"] == pid
    assert record["provider"] == "googleHealth"
    assert record["accessToken"] == "g-access-1"
    assert record["refreshToken"] == "g-refresh-1"
    assert record["expiresAt"] == FROZEN_TS + 3599
    assert record["scope"] == FULL_SCOPE
    assert record["healthUserId"] == "HUSER1"
    assert record["legacyUserId"] == "LEGACYOWNER1"
    assert record["timeCreated"] == FROZEN_TS
    assert record["migratedAt"] == FROZEN_TS
    assert record["migrationStatus"] == "pending"

    legacy = h.db["fitbits"].find_one({"_id": ObjectId(legacy_id)})
    assert legacy is not None
    assert legacy["supersededAt"] == FROZEN_TS
    assert legacy["supersededBy"] == google_id
    assert "ownerId" not in record

    assert h.publisher.calls == [
        ("googleHealth.completeMigration", [pid, google_id, [legacy_id]], "scheduler_new")
    ]
    assert h.google.exchanges == ["code-1"]


def test_finish_auth_accepts_a_grant_that_still_holds_the_old_fourth_scope(
    h: Harness,
) -> None:
    pid = h.seed_participant()
    h.google.add(
        "code-1",
        access="g-access-1",
        refresh="g-refresh-1",
        scope=f"{FULL_SCOPE} {OLD_SETTINGS_SCOPE}",
        health_user_id="HUSER1",
        legacy_user_id=None,
    )

    with time_machine.travel(FROZEN, tick=False):
        resp = h.run_flow(pid, "code-1")

    assert resp.status_code == 200, resp.text
    (record,) = h.google_records()
    assert record["scope"] == f"{FULL_SCOPE} {OLD_SETTINGS_SCOPE}"
    assert h.google.revokes == []


def test_reconsent_carries_the_first_migration_date_forward(h: Harness) -> None:
    pid = h.seed_participant()
    first = FROZEN_TS - 30 * 86400
    older_id = h.seed_google(pid, health_user_id="HUSER1", migrated_at=first)
    h.google.add(
        "code-2",
        access="g-access-2",
        refresh="g-refresh-2",
        health_user_id="HUSER1",
        legacy_user_id=None,
    )

    with time_machine.travel(FROZEN, tick=False):
        resp = h.run_flow(pid, "code-2")

    assert resp.status_code == 200, resp.text
    (active,) = h.active_google()
    assert str(active["_id"]) != older_id
    assert active["migratedAt"] == first
    assert active["timeCreated"] == FROZEN_TS
    older = h.db["fitbits"].find_one({"_id": ObjectId(older_id)})
    assert older is not None
    assert older["supersededAt"] == FROZEN_TS
    assert older["supersededBy"] == str(active["_id"])
    assert h.publisher.calls == [
        ("googleHealth.completeMigration", [pid, str(active["_id"]), [older_id]], "scheduler_new")
    ]


# --- Task 2: links refusals -----------------------------------------------------


def test_links_without_a_bearer_is_401(h: Harness) -> None:
    h.principal = Principal(id="anonymous", is_authenticated=False)
    resp = h.client().post(LINKS_PATH, json={"participantId": h.seed_participant()})
    assert resp.status_code == 401


def test_links_with_a_non_admin_bearer_is_403(h: Harness) -> None:
    h.principal = Principal(id="p-1", roles=("participant",), is_authenticated=True)
    resp = h.client().post(LINKS_PATH, json={"participantId": h.seed_participant()})
    assert resp.status_code == 403


@pytest.mark.parametrize("kind", ["unknown", "malformed", "inactive"])
def test_links_for_an_unknown_or_inactive_participant_is_404(h: Harness, kind: str) -> None:
    pid = {
        "unknown": str(ObjectId()),
        "malformed": "not-an-object-id",
        "inactive": h.seed_participant(active=False),
    }[kind]
    resp = h.client().post(LINKS_PATH, json={"participantId": pid})
    assert resp.status_code == 404


@pytest.mark.parametrize(
    "body", [{}, {"participantId": ""}, {"participantId": 7}, [], "text"]
)
def test_links_with_a_bad_body_is_400_never_500(h: Harness, body: object) -> None:
    resp = h.client().post(LINKS_PATH, json=body)
    assert resp.status_code in (400, 422)


def test_links_with_malformed_json_is_400(h: Harness) -> None:
    resp = h.client().post(
        LINKS_PATH, content=b"{bad", headers={"content-type": "application/json"}
    )
    assert resp.status_code == 400


# --- Task 2: authorize refusals -------------------------------------------------


def _no_side_effects_at_authorize(h: Harness, resp: object) -> None:
    assert resp.status_code == 400  # type: ignore[attr-defined]
    assert "set-cookie" not in resp.headers  # type: ignore[attr-defined]
    assert h.redis.keys("gh:state:*") == []
    assert "googleHealth" not in resp.text or "<html" in resp.text  # type: ignore[attr-defined]


def _foreign_token(secret: str, audience: str, pid: str, **extra: object) -> str:
    now = int(datetime.now(UTC).timestamp())
    claims = {
        "iss": "openwellness-api",
        "aud": audience,
        "sub": pid,
        "iat": now,
        "exp": now + 600,
        "jti": "j" * 22,
        **extra,
    }
    return jwt.encode(claims, secret, algorithm="HS256")


@pytest.mark.parametrize("kind", ["missing", "malformed", "empty"])
def test_authorize_refuses_a_missing_or_malformed_link(h: Harness, kind: str) -> None:
    params = {"missing": {}, "malformed": {"t": "abc.def.ghi"}, "empty": {"t": ""}}[kind]
    resp = h.client().get(AUTHORIZE_PATH, params=params)
    _no_side_effects_at_authorize(h, resp)


def test_authorize_refuses_an_expired_link(h: Harness) -> None:
    pid = h.seed_participant()
    client = h.client()
    with time_machine.travel(FROZEN, tick=False):
        url = h.mint_link(client, pid)
    with time_machine.travel(FROZEN.timestamp() + 72 * 3600 + 1, tick=False):
        resp = client.get(AUTHORIZE_PATH, params={"t": h.link_token(url)})
    _no_side_effects_at_authorize(h, resp)


def test_authorize_refuses_a_state_used_as_a_link(h: Harness) -> None:
    pid = h.seed_participant()
    client = h.client()
    _, state, _ = h.authorize(client, h.mint_link(client, pid))
    h.redis.flushall()
    resp = client.get(AUTHORIZE_PATH, params={"t": state})
    _no_side_effects_at_authorize(h, resp)


def test_authorize_refuses_a_link_secret_token_with_the_state_audience(h: Harness) -> None:
    token = _foreign_token(h.settings.link_secret, "googleHealth:state", h.seed_participant())
    resp = h.client().get(AUTHORIZE_PATH, params={"t": token})
    _no_side_effects_at_authorize(h, resp)


def test_authorize_refuses_an_already_claimed_link(h: Harness) -> None:
    pid = h.seed_participant()
    h.google.add("c1", access="a1", refresh="r1", health_user_id="H1", legacy_user_id=None)
    client = h.client()
    url = h.mint_link(client, pid)
    _, state, cookie = h.authorize(client, url)
    assert h.finish(client, code="c1", state=state, cookie=cookie).status_code == 200
    resp = client.get(AUTHORIZE_PATH, params={"t": h.link_token(url)})
    _no_side_effects_at_authorize(h, resp)


# --- Task 2: finishAuth refusals ------------------------------------------------


def _nothing_written(h: Harness) -> None:
    assert h.google_records() == []
    assert h.publisher.calls == []


def test_finish_auth_consent_denied_calls_no_google(h: Harness) -> None:
    pid = h.seed_participant()
    client = h.client()
    _, state, cookie = h.authorize(client, h.mint_link(client, pid))
    resp = client.get(
        FINISH_PATH,
        params={"error": "access_denied", "state": state},
        headers={"cookie": f"gh_oauth={cookie}"},
    )
    assert resp.status_code == 400
    assert h.google.exchanges == []
    _nothing_written(h)


def test_finish_auth_refuses_a_replayed_state(h: Harness) -> None:
    pid = h.seed_participant()
    h.google.add("c1", access="a1", refresh="r1", health_user_id="H1", legacy_user_id=None)
    client = h.client()
    _, state, cookie = h.authorize(client, h.mint_link(client, pid))
    assert h.finish(client, code="c1", state=state, cookie=cookie).status_code == 200
    resp = h.finish(client, code="c1", state=state, cookie=cookie)
    assert resp.status_code == 400
    assert h.google.exchanges == ["c1"]
    assert len(h.google_records()) == 1


def test_finish_auth_refuses_an_expired_state(h: Harness) -> None:
    pid = h.seed_participant()
    h.google.add("c1", access="a1", refresh="r1", health_user_id="H1", legacy_user_id=None)
    client = h.client()
    with time_machine.travel(FROZEN, tick=False):
        _, state, cookie = h.authorize(client, h.mint_link(client, pid))
    with time_machine.travel(FROZEN.timestamp() + 901, tick=False):
        resp = h.finish(client, code="c1", state=state, cookie=cookie)
    assert resp.status_code == 400
    assert h.google.exchanges == []
    _nothing_written(h)


@pytest.mark.parametrize("kind", ["link_secret", "frame_shape", "garbage"])
def test_finish_auth_refuses_a_forged_state(h: Harness, kind: str) -> None:
    pid = h.seed_participant()
    h.google.add("c1", access="a1", refresh="r1", health_user_id="H1", legacy_user_id=None)
    cookie = "c" * 43
    state = {
        "link_secret": _foreign_token(
            h.settings.link_secret,
            "googleHealth:state",
            pid,
            lnk="k" * 22,
            lx=int(datetime.now(UTC).timestamp()) + 3600,
            bh=browser_hash(cookie),
        ),
        "frame_shape": pid,
        "garbage": "x.y.z",
    }[kind]
    resp = h.finish(h.client(), code="c1", state=state, cookie=cookie)
    assert resp.status_code == 400
    assert h.google.exchanges == []
    _nothing_written(h)


@pytest.mark.parametrize("cookie_kind", ["absent", "other_browser"])
def test_finish_auth_refuses_a_state_from_another_browser_without_burning_it(
    h: Harness, cookie_kind: str
) -> None:
    pid = h.seed_participant()
    h.google.add("c1", access="a1", refresh="r1", health_user_id="H1", legacy_user_id=None)
    client = h.client()
    _, state, cookie = h.authorize(client, h.mint_link(client, pid))
    other = None if cookie_kind == "absent" else "o" * 43
    resp = h.finish(client, code="c1", state=state, cookie=other)
    assert resp.status_code == 400
    assert h.google.exchanges == []
    _nothing_written(h)
    # The nonce is intact: the initiating browser can still finish.
    assert len(h.redis.keys("gh:state:*")) == 1
    assert h.finish(client, code="c1", state=state, cookie=cookie).status_code == 200


def _link_claims(h: Harness) -> list[str]:
    return h.redis.keys("gh:link:claim:*")


@pytest.mark.parametrize(
    "grant",
    [
        {"refresh": None, "scope": FULL_SCOPE},
        {"refresh": "r1", "scope": " ".join(SCOPES[:2])},
        {"refresh": "r1", "scope": ""},
    ],
)
def test_finish_auth_rejects_a_partial_grant_and_revokes_an_unshared_one(
    h: Harness, grant: dict
) -> None:
    pid = h.seed_participant()
    h.seed_legacy(pid)
    h.google.add(
        "c1",
        access="a1",
        refresh=grant["refresh"],
        scope=grant["scope"],
        health_user_id="H1",
        legacy_user_id=None,
    )
    resp = h.run_flow(pid, "c1")
    assert resp.status_code == 400
    _nothing_written(h)
    assert h.db["fitbits"].count_documents({"supersededAt": {"$ne": None}}) == 0
    assert _link_claims(h) == []
    assert h.google.revokes == [grant["refresh"] or "a1"]


def test_rejected_reconsent_never_revokes_the_active_grant(
    h: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    pid = h.seed_participant()
    h.seed_google(pid, health_user_id="H1", migrated_at=FROZEN_TS - 86400)
    h.google.add(
        "c1",
        access="a1",
        refresh="r1",
        scope=" ".join(SCOPES[:2]),
        health_user_id="H1",
        legacy_user_id=None,
    )
    with caplog.at_level(logging.WARNING):
        resp = h.run_flow(pid, "c1")
    assert resp.status_code == 400
    assert h.google.revokes == []
    assert len(h.google_records()) == 1
    assert "googleHealth/finishAuth revoke skipped" in caplog.text


def test_rejected_grant_is_not_revoked_when_identity_fails(
    h: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    pid = h.seed_participant()
    h.google.add("c1", access="a1", refresh=None, health_user_id="H1", legacy_user_id=None)
    h.google.fail_identity = True
    with caplog.at_level(logging.WARNING):
        resp = h.run_flow(pid, "c1")
    assert resp.status_code == 400
    assert h.google.revokes == []
    _nothing_written(h)
    assert "googleHealth/finishAuth revoke skipped" in caplog.text


def test_identity_failure_writes_nothing_and_releases_the_link(h: Harness) -> None:
    pid = h.seed_participant()
    h.google.add("c1", access="a1", refresh="r1", health_user_id="H1", legacy_user_id=None)
    h.google.fail_identity = True
    resp = h.run_flow(pid, "c1")
    assert resp.status_code == 400
    _nothing_written(h)
    assert _link_claims(h) == []
    assert h.google.revokes == []


def test_legacy_account_mismatch_succeeds_with_a_warning(
    h: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    pid = h.seed_participant()
    h.seed_legacy(pid, owner_id="LEGACYOWNER1")
    h.google.add(
        "c1", access="a1", refresh="r1", health_user_id="H1", legacy_user_id="SOMEONEELSE"
    )
    with caplog.at_level(logging.WARNING):
        resp = h.run_flow(pid, "c1")
    assert resp.status_code == 200
    mismatches = [
        r for r in caplog.records if "googleHealth/finishAuth legacy account mismatch" in r.getMessage()
    ]
    assert len(mismatches) == 1
    assert "SOMEONEELSE" not in caplog.text
    assert "LEGACYOWNER1" not in caplog.text
    assert pid not in caplog.text


def test_matching_legacy_account_logs_no_mismatch(
    h: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    pid = h.seed_participant()
    h.seed_legacy(pid, owner_id="LEGACYOWNER1")
    h.google.add(
        "c1", access="a1", refresh="r1", health_user_id="H1", legacy_user_id="LEGACYOWNER1"
    )
    with caplog.at_level(logging.WARNING):
        assert h.run_flow(pid, "c1").status_code == 200
    assert "legacy account mismatch" not in caplog.text


def test_publish_failure_still_succeeds_and_leaves_the_record_pending(
    caplog: pytest.LogCaptureFixture,
) -> None:
    h = Harness()
    h.publisher.error = TaskPublishError("ConnectionError")
    pid = h.seed_participant()
    h.google.add("c1", access="a1", refresh="r1", health_user_id="H1", legacy_user_id=None)
    with caplog.at_level(logging.ERROR):
        resp = h.run_flow(pid, "c1")
    assert resp.status_code == 200
    (record,) = h.google_records()
    assert record["migrationStatus"] == "pending"
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert errors == ["googleHealth/finishAuth publish failed: TaskPublishError"]


# --- Task 2: log and page hygiene ---------------------------------------------


def test_no_sensitive_value_reaches_a_log_or_a_page(caplog: pytest.LogCaptureFixture) -> None:
    sentinels = {
        "code": "CODE-SENTINEL-4f1a",
        "access": "ACCESS-SENTINEL-9b2c",
        "refresh": "REFRESH-SENTINEL-7d3e",
        "health": "HEALTHUSER-SENTINEL-1a2b",
        "legacy": "LEGACYUSER-SENTINEL-3c4d",
    }
    bodies: list[str] = []
    secrets_seen: list[str] = []

    with caplog.at_level(logging.DEBUG):
        h = Harness()
        h.publisher.error = TaskPublishError("ConnectionError")
        pid = h.seed_participant()
        h.seed_legacy(pid, owner_id="LEGACYOWNER-SENTINEL")
        h.google.add(
            sentinels["code"],
            access=sentinels["access"],
            refresh=sentinels["refresh"],
            health_user_id=sentinels["health"],
            legacy_user_id=sentinels["legacy"],
        )
        client = h.client()
        url = h.mint_link(client, pid)
        link = h.link_token(url)
        resp, state, cookie = h.authorize(client, url)
        bodies.append(resp.text)
        secrets_seen += [link, state, cookie]
        bodies.append(h.finish(client, code=sentinels["code"], state=state, cookie=cookie).text)
        # A refused replay and a rejected partial grant log too.
        bodies.append(h.finish(client, code=sentinels["code"], state=state, cookie=cookie).text)
        h.google.add(
            "PARTIAL-CODE-SENTINEL",
            access="PARTIAL-ACCESS-SENTINEL",
            refresh=None,
            health_user_id="PARTIAL-HEALTH-SENTINEL",
            legacy_user_id=None,
        )
        pid2 = h.seed_participant()
        url2 = h.mint_link(client, pid2)
        _, state2, cookie2 = h.authorize(client, url2)
        secrets_seen += [h.link_token(url2), state2, cookie2]
        bodies.append(
            h.finish(client, code="PARTIAL-CODE-SENTINEL", state=state2, cookie=cookie2).text
        )

    # Every server-side record. httpx/httpcore are the test client's own
    # request logs (they print the URL it sent), not the app's.
    server_log = "\n".join(
        f"{r.name} {r.getMessage()} {r.exc_text or ''}"
        for r in caplog.records
        if not r.name.startswith(("httpx", "httpcore"))
    )
    assert "googleHealth/finishAuth" in server_log
    haystacks = [server_log, *bodies]
    needles = [
        *sentinels.values(),
        "LEGACYOWNER-SENTINEL",
        "PARTIAL-CODE-SENTINEL",
        "PARTIAL-ACCESS-SENTINEL",
        "PARTIAL-HEALTH-SENTINEL",
        pid,
        pid2,
        *secrets_seen,
    ]
    for needle in needles:
        for haystack in haystacks:
            assert needle not in haystack


def test_access_log_filter_strips_google_health_queries() -> None:
    from openwellness_api.main import GoogleHealthAccessLogFilter

    f = GoogleHealthAccessLogFilter()

    def record(path: str) -> logging.LogRecord:
        return logging.LogRecord(
            "uvicorn.access",
            logging.INFO,
            __file__,
            0,
            '%s - "%s %s HTTP/%s" %d',
            ("127.0.0.1:5000", "GET", path, "1.1", 302),
            None,
        )

    finish = record("/api/googleHealth/finishAuth?code=X&state=Y")
    assert f.filter(finish) is True
    assert finish.args[2] == "/api/googleHealth/finishAuth"  # type: ignore[index]
    assert "code=X" not in finish.getMessage()

    link = record("/api/googleHealth/authorize?t=SECRET")
    assert f.filter(link) is True
    assert "SECRET" not in link.getMessage()

    other = record("/v1/participants?pageSize=5")
    assert f.filter(other) is True
    assert other.args[2] == "/v1/participants?pageSize=5"  # type: ignore[index]

    odd = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 0, "plain", None, None)
    assert f.filter(odd) is True


def test_access_log_filter_is_installed_once() -> None:
    from openwellness_api.main import (
        GoogleHealthAccessLogFilter,
        install_google_health_access_log_filter,
    )

    install_google_health_access_log_filter()
    install_google_health_access_log_filter()
    access = logging.getLogger("uvicorn.access")
    assert sum(isinstance(x, GoogleHealthAccessLogFilter) for x in access.filters) == 1


def _hu_lock(health_user_id: str) -> str:
    return "gh:lock:hu:" + hashlib.sha256(health_user_id.encode()).hexdigest()[:32]


def test_a_rejected_grant_is_revoked_under_the_locks_and_they_are_released(h: Harness) -> None:
    pid = h.seed_participant()
    h.google.add("c1", access="a1", refresh=None, health_user_id="H1", legacy_user_id=None)
    seen: list[list[str]] = []
    revoke = h.google.revoke

    def revoke_seeing_locks(token: str) -> None:
        seen.append(sorted(h.redis.keys("gh:lock:*")))
        revoke(token)

    h.google.revoke = revoke_seeing_locks  # type: ignore[method-assign]
    resp = h.run_flow(pid, "c1")
    assert resp.status_code == 400
    assert h.google.revokes == ["a1"]
    assert seen == [sorted([f"gh:lock:pid:{pid}", _hu_lock("H1")])]
    assert h.redis.keys("gh:lock:*") == []


def test_a_rejected_grant_is_not_revoked_while_the_account_is_locked_elsewhere(
    h: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    pid = h.seed_participant()
    h.google.add("c1", access="a1", refresh=None, health_user_id="H1", legacy_user_id=None)
    # A concurrent finishAuth for the same account is mid-insert.
    h.redis.set(_hu_lock("H1"), "another-owner", px=60000)
    with caplog.at_level(logging.WARNING):
        resp = h.run_flow(pid, "c1")
    assert resp.status_code == 400
    assert h.google.revokes == []
    assert "googleHealth/finishAuth revoke skipped" in caplog.text
    assert h.redis.get(_hu_lock("H1")) == "another-owner"
    assert h.redis.get(f"gh:lock:pid:{pid}") is None


class _RedirectSession:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def _answer(self, **kwargs: object) -> object:
        self.calls.append(kwargs)

        class Response:
            status_code = 302

            def json(self) -> dict:
                return {"access_token": "a", "expires_in": 1, "scope": FULL_SCOPE}

        return Response()

    def request(self, method: str, url: str, **kwargs: object) -> object:
        return self._answer(**kwargs)

    def post(self, url: str, **kwargs: object) -> object:
        return self._answer(**kwargs)


@pytest.mark.parametrize("call", ["exchange_code", "get_identity", "revoke"])
def test_the_google_client_never_follows_a_redirect(h: Harness, call: str) -> None:
    session = _RedirectSession()
    client = RequestsGoogleOAuthClient(h.settings, session=session)  # type: ignore[arg-type]
    with pytest.raises(GoogleOAuthError):
        getattr(client, call)("x")
    assert [kwargs.get("allow_redirects") for kwargs in session.calls] == [False]
