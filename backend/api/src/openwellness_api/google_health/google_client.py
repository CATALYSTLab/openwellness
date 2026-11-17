"""The three Google calls finishAuth makes inline (D-17).

Only the code exchange, the identity lookup and the revoke of a rejected
grant run inside the request. Health data is never fetched here (D-06); the
scheduler does that from ``googleHealth.completeMigration`` on. ``revoke``
also serves the coach revoke route (opserver Phase 17.3), which needs to tell
a grant that is already dead from a live failure (D-05).

Every failure raises :class:`GoogleOAuthError` carrying a fixed kind string,
never Google's response body, a token or a code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final, Protocol

import requests

from .settings import GoogleHealthSettings

_TIMEOUT_SECONDS: Final = 10
# Revoke-endpoint codes proving the grant is already dead (scheduler DEAD_TOKEN_CODES).
_DEAD_TOKEN_CODES: Final = frozenset({"invalid_token", "invalid_grant"})


class GoogleOAuthError(Exception):
    """A Google call failed. ``kind`` is one of a fixed set of strings."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


@dataclass(frozen=True)
class TokenGrant:
    access_token: str = field(repr=False)
    refresh_token: str | None = field(repr=False)
    expires_in: int
    scope: str


@dataclass(frozen=True)
class Identity:
    health_user_id: str = field(repr=False)
    legacy_user_id: str | None = field(repr=False)


class GoogleOAuthClient(Protocol):
    def exchange_code(self, code: str) -> TokenGrant: ...

    def get_identity(self, access_token: str) -> Identity: ...

    def revoke(self, token: str) -> None: ...


class RequestsGoogleOAuthClient:
    """:class:`GoogleOAuthClient` over ``requests`` with 10 s timeouts."""

    def __init__(
        self, settings: GoogleHealthSettings, session: requests.Session | None = None
    ) -> None:
        self._settings = settings
        self._session = session if session is not None else requests.Session()

    def exchange_code(self, code: str) -> TokenGrant:
        body = self._json(
            "token_exchange_failed",
            "POST",
            self._settings.token_endpoint,
            data={
                "code": code,
                "client_id": self._settings.client_id,
                "client_secret": self._settings.client_secret,
                "redirect_uri": self._settings.redirect_uri(),
                "grant_type": "authorization_code",
            },
        )
        access = body.get("access_token")
        refresh = body.get("refresh_token")
        expires_in = body.get("expires_in")
        scope = body.get("scope")
        if (
            not isinstance(access, str)
            or not access
            or not isinstance(expires_in, int)
            or not isinstance(scope, str)
        ):
            raise GoogleOAuthError("token_response_invalid")
        return TokenGrant(
            access_token=access,
            refresh_token=refresh if isinstance(refresh, str) and refresh else None,
            expires_in=expires_in,
            scope=scope,
        )

    def get_identity(self, access_token: str) -> Identity:
        body = self._json(
            "identity_failed",
            "GET",
            self._settings.identity_url,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        health_user_id = body.get("healthUserId")
        legacy_user_id = body.get("legacyUserId")
        if not isinstance(health_user_id, str) or not health_user_id:
            raise GoogleOAuthError("identity_invalid")
        return Identity(
            health_user_id=health_user_id,
            legacy_user_id=legacy_user_id if isinstance(legacy_user_id, str) else None,
        )

    def revoke(self, token: str) -> None:
        try:
            response = self._session.post(
                self._settings.revoke_endpoint,
                data={"token": token},
                timeout=_TIMEOUT_SECONDS,
                allow_redirects=False,
            )
        except requests.Timeout as exc:
            raise GoogleOAuthError("revoke_timeout") from exc
        except Exception as exc:
            raise GoogleOAuthError("revoke_failed") from exc
        if _ok(response.status_code):
            return
        if response.status_code == 400 and _oauth_error(response) in _DEAD_TOKEN_CODES:
            raise GoogleOAuthError("revoke_token_invalid")
        raise GoogleOAuthError("revoke_failed")

    def _json(self, kind: str, method: str, url: str, **kwargs: Any) -> dict[str, Any]:
        try:
            # A redirect is never followed: it could carry the code, the client
            # secret or the bearer token off Google's HTTPS endpoints.
            response = self._session.request(
                method, url, timeout=_TIMEOUT_SECONDS, allow_redirects=False, **kwargs
            )
        except Exception as exc:
            raise GoogleOAuthError(kind) from exc
        if not _ok(response.status_code):
            raise GoogleOAuthError(kind)
        try:
            body = response.json()
        except Exception as exc:
            raise GoogleOAuthError(kind) from exc
        if not isinstance(body, dict):
            raise GoogleOAuthError(kind)
        return body


def _ok(status: int) -> bool:
    """2xx only: a redirect is a failure, not something to follow."""
    return 200 <= status < 300


def _oauth_error(response: Any) -> str | None:
    """Google's RFC 6749 ``error`` code only; the free-text description can echo request values."""
    try:
        body = response.json()
    except Exception:
        return None
    error = body.get("error") if isinstance(body, dict) else None
    return error if isinstance(error, str) else None
