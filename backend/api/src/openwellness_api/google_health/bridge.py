"""``POST /internal/googleHealth/links``: the bridge-guarded internal mint (opserver Phase 16).

frame (the legacy hapi ``api`` service) authorizes a coach, then calls this
route over the Compose network with a short-lived HS256 bridge JWT signed
with ``GOOGLE_HEALTH_BRIDGE_SECRET`` (Phase 16 D-01..D-03). The route mints
through the same :func:`~.oauth._mint_link_result` code as the public
``POST /api/googleHealth/links``, which stays unchanged.

- The path sits outside ``/api/``: edge routes only ``/api/*`` groups to ow
  and its catch-all is never ow, so the route is unreachable from outside the
  Compose network (T-09-16 containment).
- The bridge JWT is not an ow access token: its own secret, ``iss=frame``,
  ``aud=ow-bridge``, ``typ=gh-link-bridge``, HS256 only, at most
  :data:`MAX_LIFETIME_SECONDS` of life, a 24-hex ``sub`` (the coach's
  ``users._id``) and a 24-hex ``pid`` equal to the body ``participantId``.
- Every attempt writes one audit line on :data:`AUDIT_LOGGER_NAME`:
  ``googleHealth/internalLinks outcome=<ok|400|401|404|409|500|503>
  actor=<24hex|-> participantId=<24hex|-> expiresAt=<int|->`` (D-10). It
  carries record ids only, never the URL, a token, a participantNumber, a
  name or an email (HIPAA 6-year log retention).
"""

from __future__ import annotations

import hmac
import logging
import re
import sys
from dataclasses import dataclass
from typing import Annotated, Any, Final

import jwt
from fastapi import Depends, Request
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response

from ..event_handlers.hapi import boom
from .oauth import _mint_link_result, get_google_health_deps
from .settings import _MIN_SECRET_LENGTH, GoogleHealthSettings

INTERNAL_LINKS_PATH: Final = "/internal/googleHealth/links"
BRIDGE_ISSUER: Final = "frame"
BRIDGE_AUDIENCE: Final = "ow-bridge"
BRIDGE_TYP: Final = "gh-link-bridge"
MAX_LIFETIME_SECONDS: Final = 120
LEEWAY_SECONDS: Final = 5
AUDIT_LOGGER_NAME: Final = "openwellness_api.audit.google_health"

_HEX24: Final = re.compile(r"[0-9a-f]{24}")
_REQUIRED_CLAIMS: Final = ["exp", "iat", "iss", "aud", "sub", "jti"]
_GOOGLE_HEALTH_SECRETS: Final = ("link_secret", "state_secret", "webhook_secret", "client_secret")
_AUDIT_HANDLER_MARK: Final = "_openwellness_google_health_audit"

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger(AUDIT_LOGGER_NAME)


def _is_hex24(value: object) -> bool:
    """A lowercase 24-hex record id. ``fullmatch``, so a trailing newline fails."""
    return isinstance(value, str) and _HEX24.fullmatch(value) is not None


class BridgeSettings(BaseSettings):
    """``GOOGLE_HEALTH_BRIDGE_SECRET``, shared by frame and ow_api (D-01)."""

    model_config = SettingsConfigDict(env_prefix="GOOGLE_HEALTH_BRIDGE_", extra="ignore")

    secret: str = Field(default="", repr=False)

    def problems(
        self,
        *,
        auth_jwt_secret: str,
        auth_code_pepper: str,
        google_health: GoogleHealthSettings,
    ) -> list[str]:
        """Names of the violated rules, never a value (D-04).

        The bridge secret must be set, at least 32 characters (the floor of
        every other ow secret), and distinct from ``API_AUTH_JWT_SECRET``,
        ``API_AUTH_CODE_PEPPER`` and every Google Health secret, so a leak of
        one can never mint as the other.
        """
        if not self.secret:
            return ["bridge_secret_unset"]
        rules: list[str] = []
        if len(self.secret) < _MIN_SECRET_LENGTH:
            rules.append("bridge_secret_short")
        if any(_same(self.secret, other) for other in (auth_jwt_secret, auth_code_pepper)):
            rules.append("bridge_secret_reuses_api_auth_secret")
        if any(
            _same(self.secret, getattr(google_health, name))
            for name in _GOOGLE_HEALTH_SECRETS
        ):
            rules.append("bridge_secret_reuses_google_health_secret")
        return rules


def _same(secret: str, other: str) -> bool:
    """Constant-time equality against a non-empty secret."""
    return bool(other) and hmac.compare_digest(secret.encode("utf-8"), other.encode("utf-8"))


@dataclass(frozen=True)
class BridgeClaims:
    actor: str
    participant_id: str


class BridgeTokenError(Exception):
    """Any bridge credential failure. The message is fixed, never the library's."""

    def __init__(self) -> None:
        super().__init__("bridge token rejected")


class BridgeVerifier:
    """Verifies a bridge JWT under the bridge secret (D-03)."""

    def __init__(self, secret: str) -> None:
        self._secret = secret

    def verify(self, token: str | None, *, participant_id: str) -> BridgeClaims:
        if not token:
            raise BridgeTokenError()
        try:
            claims = jwt.decode(
                token,
                self._secret,
                algorithms=["HS256"],
                audience=BRIDGE_AUDIENCE,
                issuer=BRIDGE_ISSUER,
                leeway=LEEWAY_SECONDS,
                options={"require": _REQUIRED_CLAIMS},
            )
        except Exception as exc:
            raise BridgeTokenError() from exc
        exp, iat = claims.get("exp"), claims.get("iat")
        sub, pid = claims.get("sub"), claims.get("pid")
        if (
            claims.get("typ") != BRIDGE_TYP
            or not isinstance(exp, int)
            or isinstance(exp, bool)
            or not isinstance(iat, int)
            or isinstance(iat, bool)
            or not 0 < exp - iat <= MAX_LIFETIME_SECONDS
            or not _is_hex24(sub)
            or not _is_hex24(pid)
            or pid != participant_id
        ):
            raise BridgeTokenError()
        assert isinstance(sub, str) and isinstance(pid, str)
        return BridgeClaims(actor=sub, participant_id=pid)


@dataclass(frozen=True)
class BridgeDeps:
    verifier: BridgeVerifier | None
    disabled: tuple[str, ...]


def build_bridge_deps(
    *,
    google_health: GoogleHealthSettings,
    auth_jwt_secret: str,
    auth_code_pepper: str,
    settings: BridgeSettings | None = None,
) -> BridgeDeps:
    """The internal route's verifier, or the rules that keep it disabled (D-04).

    Any violated rule logs one WARNING listing rule names only, never a
    value, and makes only the internal route answer 503; the public Google
    Health routes are unaffected. Mirrors :func:`build_google_health_deps`.
    """
    bridge = settings if settings is not None else BridgeSettings()
    rules = tuple(
        bridge.problems(
            auth_jwt_secret=auth_jwt_secret,
            auth_code_pepper=auth_code_pepper,
            google_health=google_health,
        )
    )
    if rules:
        logger.warning(
            "googleHealth internal links disabled until fixed: %s", ", ".join(rules)
        )
        return BridgeDeps(verifier=None, disabled=rules)
    return BridgeDeps(verifier=BridgeVerifier(bridge.secret), disabled=())


def get_bridge_deps(request: Request) -> BridgeDeps | None:
    deps = getattr(request.app.state, "google_health_bridge", None)
    return deps if isinstance(deps, BridgeDeps) else None


def require_bridge_credential(request: Request) -> str | None:
    """The token after a case-insensitive ``Bearer`` scheme, else ``None``.

    Never raises, so :func:`create_link_internal` can audit every outcome.
    The route-walking test identifies bridge-guarded routes by this dependency.
    """
    header = request.headers.get("authorization")
    if not header:
        return None
    scheme, _, token = header.partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        return None
    return token


def install_google_health_audit_logger() -> None:
    """Give the audit logger its own stdout handler (idempotent).

    uvicorn configures only its own loggers, and the root logger stays at
    WARNING, so an ``openwellness_api.*`` INFO line never reaches stdout.
    The audit line needs its own handler to reach Promtail and Loki (D-10).
    ``propagate=False`` keeps it from being written twice.
    """
    if not any(getattr(h, _AUDIT_HANDLER_MARK, False) for h in audit_logger.handlers):
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        setattr(handler, _AUDIT_HANDLER_MARK, True)
        audit_logger.addHandler(handler)
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False


def _audit(
    outcome: str, actor: str | None, participant_id: str | None, expires_at: int | None
) -> None:
    audit_logger.info(
        "googleHealth/internalLinks outcome=%s actor=%s participantId=%s expiresAt=%s",
        outcome,
        actor or "-",
        participant_id or "-",
        "-" if expires_at is None else expires_at,
    )


@dataclass
class _Attempt:
    """What the audit line may say: only verified or regex-checked values."""

    actor: str | None = None
    participant_id: str | None = None
    expires_at: int | None = None


async def create_link_internal(
    request: Request,
    token: Annotated[str | None, Depends(require_bridge_credential)],
) -> Response:
    attempt = _Attempt()
    try:
        response = await _create_link_internal(request, token, attempt)
    except Exception as exc:
        logger.error("googleHealth/internalLinks failed: %s", type(exc).__name__)
        response = boom(500, "An internal server error occurred")
    status = response.status_code
    _audit(
        "ok" if status == 200 else str(status),
        attempt.actor,
        attempt.participant_id,
        attempt.expires_at if status == 200 else None,
    )
    return response


async def _create_link_internal(
    request: Request, token: str | None, attempt: _Attempt
) -> Response:
    # No bearer token at all: refuse before the 503 and the body checks, so
    # a caller without one learns nothing about configuration and cannot put
    # a participantId into the audit line.
    if token is None:
        return boom(401, "Invalid bridge credential")
    deps = get_google_health_deps(request)
    bridge = get_bridge_deps(request)
    if (
        deps is None
        or deps.disabled
        or bridge is None
        or bridge.disabled
        or bridge.verifier is None
    ):
        return boom(503, "Google Health is not available.")
    try:
        body: Any = await request.json()
    except Exception:
        return boom(400, "Invalid request payload input")
    participant_id = body.get("participantId") if isinstance(body, dict) else None
    if not _is_hex24(participant_id):
        return boom(400, "Invalid request payload input")
    assert isinstance(participant_id, str)
    attempt.participant_id = participant_id
    try:
        claims = bridge.verifier.verify(token, participant_id=participant_id)
    except BridgeTokenError:
        return boom(401, "Invalid bridge credential")
    attempt.actor = claims.actor
    response, expires_at = await run_in_threadpool(_mint_link_result, deps, participant_id)
    attempt.expires_at = expires_at
    return response
