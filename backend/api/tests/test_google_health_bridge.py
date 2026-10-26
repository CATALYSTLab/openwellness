"""The bridge-guarded internal links route (opserver Phase 16, GHB-02, GHB-03, GHB-05).

frame (the legacy hapi ``api`` service) mints a Google Health consent link
for a coach by calling ``POST /internal/googleHealth/links`` over the Compose
network with a short-lived HS256 bridge JWT signed with
``GOOGLE_HEALTH_BRIDGE_SECRET``. The route shares ``_mint_link`` with the
public ``POST /api/googleHealth/links`` and writes one audit line per attempt
on ``openwellness_api.audit.google_health``. Contract: OpenWellness spec 009.
"""

from __future__ import annotations

import logging
import re
import sys
import time
import urllib.parse
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import jwt
import pytest
from bson import ObjectId

from openwellness_api.google_health.bridge import (
    AUDIT_LOGGER_NAME,
    INTERNAL_LINKS_PATH,
    BridgeSettings,
    build_bridge_deps,
    install_google_health_audit_logger,
)
from openwellness_api.google_health.settings import GoogleHealthSettings

from .google_health_harness import API_JWT_SECRET, LINKS_PATH, Harness, make_settings

BRIDGE_SECRET = "bridge-shared-secret-for-tests-000000000000000000000000000000001"
AUTH_PEPPER = "auth-code-pepper-for-tests-0000000000001"
ACTOR = "5f0c0ffee0c0ffee0c0ffee0"

assert len(BRIDGE_SECRET) == 64
assert len(AUTH_PEPPER) == 40


def bridge_token(
    pid: str,
    *,
    sub: str = ACTOR,
    secret: str = BRIDGE_SECRET,
    lifetime: int = 60,
    algorithm: str = "HS256",
    drop: tuple[str, ...] = (),
    **claim_overrides: Any,
) -> str:
    """A bridge JWT exactly as frame signs it, with optional overrides."""
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": "frame",
        "aud": "ow-bridge",
        "typ": "gh-link-bridge",
        "sub": sub,
        "pid": pid,
        "iat": now,
        "exp": now + lifetime,
        "jti": str(uuid.uuid4()),
    }
    claims.update(claim_overrides)
    for name in drop:
        claims.pop(name, None)
    return jwt.encode(claims, secret, algorithm=algorithm)


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class _Collect(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.INFO)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def lines(self) -> list[str]:
        return [record.getMessage() for record in self.records]


@pytest.fixture
def audit() -> Iterator[_Collect]:
    """Records on the audit logger. ``caplog`` cannot see a ``propagate=False`` logger."""
    logger = logging.getLogger(AUDIT_LOGGER_NAME)
    handler = _Collect()
    previous = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    yield handler
    logger.removeHandler(handler)
    logger.setLevel(previous)


def with_bridge(harness: Harness, secret: str = BRIDGE_SECRET) -> Harness:
    harness.app.state.google_health_bridge = build_bridge_deps(
        google_health=harness.settings,
        auth_jwt_secret=API_JWT_SECRET,
        auth_code_pepper=AUTH_PEPPER,
        settings=BridgeSettings(secret=secret),
    )
    return harness


@pytest.fixture
def h() -> Harness:
    return with_bridge(Harness())


# --- Task 1: the tracer ---------------------------------------------------------


def test_valid_bridge_token_mints_a_link(h: Harness, audit: _Collect) -> None:
    pid = h.seed_participant()
    resp = h.client().post(
        INTERNAL_LINKS_PATH, json={"participantId": pid}, headers=bearer(bridge_token(pid))
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body) == {"url", "expiresAt"}
    assert resp.headers["cache-control"] == "no-store"
    assert body["url"].startswith(make_settings().authorize_url())
    assert isinstance(body["expiresAt"], int)
    assert audit.lines() == [
        f"googleHealth/internalLinks outcome=ok actor={ACTOR} participantId={pid} "
        f"expiresAt={body['expiresAt']}"
    ]
    # ``expiresAt=`` itself contains "t=", so look for the query form and
    # the link token value instead.
    link_token = urllib.parse.parse_qs(urllib.parse.urlsplit(body["url"]).query)["t"][0]
    assert body["url"] not in audit.lines()[0]
    assert "?t=" not in audit.lines()[0]
    assert link_token not in audit.lines()[0]


def test_missing_bridge_credential_is_401(h: Harness, audit: _Collect) -> None:
    pid = h.seed_participant()
    resp = h.client().post(INTERNAL_LINKS_PATH, json={"participantId": pid})

    assert resp.status_code == 401, resp.text
    assert resp.json() == {
        "statusCode": 401,
        "error": "Unauthorized",
        "message": "Invalid bridge credential",
    }
    assert audit.lines() == [
        f"googleHealth/internalLinks outcome=401 actor=- participantId={pid} expiresAt=-"
    ]


# --- Task 2: refusals, disable rules, audit lines, logger, path ----------------

AUDIT_LINE = re.compile(
    r"^googleHealth/internalLinks outcome=(ok|400|401|404|409|500|503) "
    r"actor=([0-9a-f]{24}|-) participantId=([0-9a-f]{24}|-) expiresAt=([0-9]+|-)$"
)
OTHER_SECRET = "a-different-bridge-secret-for-tests-0000000000000000000000000001"
OTHER_PID = "0123456789abcdef01234567"

assert len(OTHER_SECRET) == 64


def _ow_access_token(pid: str) -> str:
    now = int(time.time())
    claims = {
        "iss": "openwellness-api",
        "aud": "openwellness-api",
        "typ": "access",
        "sub": ACTOR,
        "pid": pid,
        "roles": ["admin"],
        "iat": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(claims, API_JWT_SECRET, algorithm="HS256")


def _expired(pid: str) -> str:
    now = int(time.time())
    return bridge_token(pid, iat=now - 120, exp=now - 60)


REFUSALS: dict[str, Callable[[Harness, str], dict[str, str]]] = {
    "wrong_secret": lambda h, pid: bearer(bridge_token(pid, secret=OTHER_SECRET)),
    "ow_access_token": lambda h, pid: bearer(_ow_access_token(pid)),
    "link_token": lambda h, pid: bearer(h.deps.tokens.mint_link(pid)[0]),
    "expired": lambda h, pid: bearer(_expired(pid)),
    "no_typ": lambda h, pid: bearer(bridge_token(pid, drop=("typ",))),
    "wrong_typ": lambda h, pid: bearer(bridge_token(pid, typ="access")),
    "wrong_aud": lambda h, pid: bearer(bridge_token(pid, aud="openwellness-api")),
    "wrong_iss": lambda h, pid: bearer(bridge_token(pid, iss="openwellness-api")),
    "lifetime_121": lambda h, pid: bearer(bridge_token(pid, lifetime=121)),
    "pid_not_body": lambda h, pid: bearer(bridge_token(OTHER_PID)),
    "sub_not_hex": lambda h, pid: bearer(bridge_token(pid, sub="coach-1")),
    "hs512": lambda h, pid: bearer(bridge_token(pid, algorithm="HS512")),
    "no_jti": lambda h, pid: bearer(bridge_token(pid, drop=("jti",))),
    "basic_scheme": lambda h, pid: {"Authorization": "Basic c2Vzc2lvbjprZXk="},
    "empty_bearer": lambda h, pid: {"Authorization": "Bearer "},
}


@pytest.mark.parametrize("case", sorted(REFUSALS))
def test_bridge_token_refusals(h: Harness, audit: _Collect, case: str) -> None:
    pid = h.seed_participant()
    resp = h.client().post(
        INTERNAL_LINKS_PATH, json={"participantId": pid}, headers=REFUSALS[case](h, pid)
    )

    assert resp.status_code == 401, resp.text
    assert resp.json() == {
        "statusCode": 401,
        "error": "Unauthorized",
        "message": "Invalid bridge credential",
    }
    assert audit.lines() == [
        f"googleHealth/internalLinks outcome=401 actor=- participantId={pid} expiresAt=-"
    ]


def test_bearer_scheme_is_case_insensitive(h: Harness, audit: _Collect) -> None:
    pid = h.seed_participant()
    resp = h.client().post(
        INTERNAL_LINKS_PATH,
        json={"participantId": pid},
        headers={"Authorization": f"bearer {bridge_token(pid)}"},
    )
    assert resp.status_code == 200, resp.text


def _disabled_cases(settings: GoogleHealthSettings) -> dict[str, tuple[str, str]]:
    """rule case -> (bridge secret, the rule name it must trip)."""
    return {
        "unset": ("", "bridge_secret_unset"),
        "short": ("s" * 31, "bridge_secret_short"),
        "api_jwt_secret": (API_JWT_SECRET, "bridge_secret_reuses_api_auth_secret"),
        "auth_code_pepper": (AUTH_PEPPER, "bridge_secret_reuses_api_auth_secret"),
        "link_secret": (settings.link_secret, "bridge_secret_reuses_google_health_secret"),
        "state_secret": (settings.state_secret, "bridge_secret_reuses_google_health_secret"),
        "webhook_secret": (
            settings.webhook_secret,
            "bridge_secret_reuses_google_health_secret",
        ),
        "client_secret": (
            settings.client_secret,
            "bridge_secret_reuses_google_health_secret",
        ),
    }


@pytest.mark.parametrize("rule", sorted(_disabled_cases(make_settings())))
def test_bridge_disabled_answers_503(audit: _Collect, rule: str) -> None:
    harness = Harness()
    secret, rule_name = _disabled_cases(harness.settings)[rule]
    h = with_bridge(harness, secret=secret)
    assert h.app.state.google_health_bridge.disabled == (rule_name,)
    pid = h.seed_participant()
    client = h.client()

    resp = client.post(
        INTERNAL_LINKS_PATH, json={"participantId": pid}, headers=bearer(bridge_token(pid))
    )

    assert resp.status_code == 503, resp.text
    assert resp.json() == {
        "statusCode": 503,
        "error": "Service Unavailable",
        "message": "Google Health is not available.",
    }
    assert audit.lines() == [
        "googleHealth/internalLinks outcome=503 actor=- participantId=- expiresAt=-"
    ]
    # Only the internal route is off: the public route still mints.
    assert client.post(LINKS_PATH, json={"participantId": pid}).status_code == 200


def test_internal_route_is_503_while_google_health_is_disabled(audit: _Collect) -> None:
    h = with_bridge(Harness(settings=make_settings(client_id="")))
    assert h.deps.disabled
    pid = h.seed_participant()

    resp = h.client().post(
        INTERNAL_LINKS_PATH, json={"participantId": pid}, headers=bearer(bridge_token(pid))
    )

    assert resp.status_code == 503, resp.text
    assert resp.json()["error"] == "Service Unavailable"
    assert audit.lines() == [
        "googleHealth/internalLinks outcome=503 actor=- participantId=- expiresAt=-"
    ]


def test_bridge_warning_names_rules_only(caplog: pytest.LogCaptureFixture) -> None:
    settings = make_settings()
    with caplog.at_level(logging.WARNING, logger="openwellness_api.google_health.bridge"):
        deps = build_bridge_deps(
            google_health=settings,
            auth_jwt_secret=API_JWT_SECRET,
            auth_code_pepper=AUTH_PEPPER,
            settings=BridgeSettings(secret=settings.link_secret),
        )

    assert deps.verifier is None
    records = [
        r
        for r in caplog.records
        if r.name == "openwellness_api.google_health.bridge" and r.levelno == logging.WARNING
    ]
    assert len(records) == 1
    message = records[0].getMessage()
    assert message == (
        "googleHealth internal links disabled until fixed: "
        "bridge_secret_reuses_google_health_secret"
    )
    assert settings.link_secret not in message
    assert settings.link_secret not in caplog.text


def test_valid_secret_logs_no_warning(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="openwellness_api.google_health.bridge"):
        deps = build_bridge_deps(
            google_health=make_settings(),
            auth_jwt_secret=API_JWT_SECRET,
            auth_code_pepper=AUTH_PEPPER,
            settings=BridgeSettings(secret=BRIDGE_SECRET),
        )
    assert deps.verifier is not None and deps.disabled == ()
    assert caplog.records == []


BAD_BODIES: dict[str, Callable[[str], dict[str, Any]]] = {
    "non_json": lambda pid: {"content": b"{bad", "headers": {"content-type": "application/json"}},
    "json_list": lambda pid: {"json": [pid]},
    "missing_participant_id": lambda pid: {"json": {}},
    "uppercase_hex": lambda pid: {"json": {"participantId": pid.upper()}},
    "hex_25": lambda pid: {"json": {"participantId": pid + "a"}},
    "non_str_id": lambda pid: {"json": {"participantId": 7}},
}


@pytest.mark.parametrize("body", sorted(BAD_BODIES))
def test_bad_body_is_400(h: Harness, audit: _Collect, body: str) -> None:
    pid = h.seed_participant()
    kwargs = BAD_BODIES[body](pid)
    headers = {**kwargs.pop("headers", {}), **bearer(bridge_token(pid))}

    resp = h.client().post(INTERNAL_LINKS_PATH, headers=headers, **kwargs)

    assert resp.status_code == 400, resp.text
    assert resp.json() == {
        "statusCode": 400,
        "error": "Bad Request",
        "message": "Invalid request payload input",
    }
    assert audit.lines() == [
        "googleHealth/internalLinks outcome=400 actor=- participantId=- expiresAt=-"
    ]


def _failing_mint(participant_id: str) -> tuple[str, int]:
    raise RuntimeError("redis down")


@pytest.mark.parametrize(
    ("case", "status", "message"),
    [
        ("unknown", 404, "Participant not found."),
        ("inactive", 404, "Participant not found."),
        ("held", 409, "The participant's study is on hold for Google Health migration."),
        ("mint_failure", 500, "An internal server error occurred"),
    ],
)
def test_mint_outcomes_are_audited(
    audit: _Collect, monkeypatch: pytest.MonkeyPatch, case: str, status: int, message: str
) -> None:
    settings = make_settings(migration_hold="*") if case == "held" else None
    h = with_bridge(Harness(settings=settings))
    if case == "unknown":
        pid = str(ObjectId())
    elif case == "inactive":
        pid = h.seed_participant(active=False)
    else:
        pid = h.seed_participant()
    if case == "mint_failure":
        monkeypatch.setattr(h.deps.tokens, "mint_link", _failing_mint)

    resp = h.client().post(
        INTERNAL_LINKS_PATH, json={"participantId": pid}, headers=bearer(bridge_token(pid))
    )

    assert resp.status_code == status, resp.text
    assert resp.json()["message"] == message
    lines = audit.lines()
    assert lines == [
        f"googleHealth/internalLinks outcome={status} actor={ACTOR} participantId={pid} "
        "expiresAt=-"
    ]
    assert all(AUDIT_LINE.match(line) for line in lines)


def test_every_outcome_writes_exactly_one_matching_line(h: Harness, audit: _Collect) -> None:
    pid = h.seed_participant()
    client = h.client()
    attempts = [
        {"json": {"participantId": pid}, "headers": bearer(bridge_token(pid))},
        {"json": {"participantId": pid}},
        {"json": {"participantId": "nope"}, "headers": bearer(bridge_token(pid))},
        {"json": {"participantId": OTHER_PID}, "headers": bearer(bridge_token(OTHER_PID))},
    ]
    statuses = []
    for n, attempt in enumerate(attempts, start=1):
        statuses.append(client.post(INTERNAL_LINKS_PATH, **attempt).status_code)
        assert len(audit.lines()) == n

    assert statuses == [200, 401, 400, 404]
    assert all(AUDIT_LINE.match(line) for line in audit.lines()), audit.lines()


def test_no_log_record_carries_the_url_or_token(
    h: Harness, audit: _Collect, caplog: pytest.LogCaptureFixture
) -> None:
    pid = h.seed_participant()
    token = bridge_token(pid)
    with caplog.at_level(logging.DEBUG):
        resp = h.client().post(
            INTERNAL_LINKS_PATH, json={"participantId": pid}, headers=bearer(token)
        )

    assert resp.status_code == 200, resp.text
    url = resp.json()["url"]
    link_token = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["t"][0]
    messages = [r.getMessage() for r in (*caplog.records, *audit.records)]
    assert len(audit.records) == 1
    for message in messages:
        assert url not in message
        assert "?t=" not in message
        assert link_token not in message
        assert token not in message


@pytest.fixture
def restore_audit_logger() -> Iterator[logging.Logger]:
    logger = logging.getLogger(AUDIT_LOGGER_NAME)
    handlers, level, propagate = list(logger.handlers), logger.level, logger.propagate
    yield logger
    logger.handlers[:] = handlers
    logger.setLevel(level)
    logger.propagate = propagate


def test_audit_logger_installed_once(restore_audit_logger: logging.Logger) -> None:
    logger = restore_audit_logger
    install_google_health_audit_logger()
    install_google_health_audit_logger()

    stdout_handlers = [
        handler
        for handler in logger.handlers
        if isinstance(handler, logging.StreamHandler) and handler.stream is sys.stdout
    ]
    assert len(stdout_handlers) == 1
    assert logger.propagate is False
    assert logger.level == logging.INFO
    assert stdout_handlers[0].formatter is not None
    assert stdout_handlers[0].formatter._fmt == "%(message)s"


def test_internal_path_is_outside_api() -> None:
    assert INTERNAL_LINKS_PATH == "/internal/googleHealth/links"
    assert not INTERNAL_LINKS_PATH.startswith("/api/")
