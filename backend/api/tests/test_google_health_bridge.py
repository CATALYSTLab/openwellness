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
import time
import uuid
from collections.abc import Iterator
from typing import Any

import jwt
import pytest

from openwellness_api.google_health.bridge import (
    AUDIT_LOGGER_NAME,
    INTERNAL_LINKS_PATH,
    BridgeSettings,
    build_bridge_deps,
)

from .google_health_harness import API_JWT_SECRET, Harness, make_settings

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


@pytest.fixture
def h() -> Harness:
    harness = Harness()
    harness.app.state.google_health_bridge = build_bridge_deps(
        google_health=harness.settings,
        auth_jwt_secret=API_JWT_SECRET,
        auth_code_pepper=AUTH_PEPPER,
        settings=BridgeSettings(secret=BRIDGE_SECRET),
    )
    return harness


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
    assert body["url"] not in audit.lines()[0]
    assert "t=" not in audit.lines()[0]


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
