"""Google Health authorization settings (opserver ``docs/google-health.md``, "Env keys").

Inside the ``ow_api`` container every key carries the ``GOOGLE_HEALTH_``
prefix: the client id and secret are the shared, unprefixed host keys passed
by name, and opserver maps the ``OW_GOOGLE_HEALTH_*`` host keys onto the rest.

The secrets are declared ``repr=False`` so a settings object that reaches a
log or a traceback never prints one.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Final, Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_SCOPES: Final[tuple[str, ...]] = (
    "https://www.googleapis.com/auth/googlehealth.activity_and_fitness.readonly",
    "https://www.googleapis.com/auth/googlehealth.health_metrics_and_measurements.readonly",
    "https://www.googleapis.com/auth/googlehealth.sleep.readonly",
)
"""The three locked read-only scopes (contract "Scopes", 10.1 D-18 as amended by opserver 17.2 D-01)."""

AUTHORIZE_ENDPOINT: Final = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT: Final = "https://oauth2.googleapis.com/token"
REVOKE_ENDPOINT: Final = "https://oauth2.googleapis.com/revoke"
IDENTITY_URL: Final = "https://health.googleapis.com/v4/users/me/identity"
"""Google's OAuth and identity endpoints. Constants, not settings: the code,
client secret and bearer token they receive must never go elsewhere."""

LINK_TTL_SECONDS: Final = 259200
STATE_TTL_SECONDS: Final = 900
LOCK_TTL_MS: Final = 60000
"""The 72 h link, 15 min state and 60 s migration-lock lifetimes. Constants,
not settings: no environment value can zero, negate or stretch them."""

FINISH_AUTH_PATH: Final = "/api/googleHealth/finishAuth"
AUTHORIZE_PATH: Final = "/api/googleHealth/authorize"

_REQUIRED: Final[tuple[str, ...]] = (
    "client_id",
    "client_secret",
    "link_secret",
    "state_secret",
    "webhook_secret",
    "public_base_url",
)

_STUDY_ID = re.compile(r"^[0-9a-fA-F]{24}$")
_CLIENT_ID_SUFFIX: Final = ".apps.googleusercontent.com"
_MIN_SECRET_LENGTH: Final = 32
_SECRETS: Final[tuple[str, ...]] = ("link_secret", "state_secret", "webhook_secret")


class GoogleHealthSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GOOGLE_HEALTH_", extra="ignore")

    client_id: str = ""
    client_secret: str = Field(default="", repr=False)
    link_secret: str = Field(default="", repr=False)
    state_secret: str = Field(default="", repr=False)
    webhook_secret: str = Field(default="", repr=False)
    public_base_url: str = ""
    migration_hold: str = ""


    keyset_url: str = (
        "https://www.gstatic.com/googlehealthapi/webhooks/webhooks_public_keyset.json"
    )
    """Google's webhook signing keyset (``GOOGLE_HEALTH_KEYSET_URL``); public keys only."""

    @property
    def scopes(self) -> tuple[str, ...]:
        """The locked scopes. Not a field, so no ``GOOGLE_HEALTH_SCOPES`` can widen them."""
        return DEFAULT_SCOPES

    @property
    def link_ttl_seconds(self) -> int:
        return LINK_TTL_SECONDS

    @property
    def state_ttl_seconds(self) -> int:
        return STATE_TTL_SECONDS

    @property
    def lock_ttl_ms(self) -> int:
        return LOCK_TTL_MS

    @property
    def store_write_budget_seconds(self) -> float:
        """Upper bound on the insert and supersede, well inside one lock lease."""
        return LOCK_TTL_MS / 2000

    @property
    def authorize_endpoint(self) -> str:
        return AUTHORIZE_ENDPOINT

    @property
    def token_endpoint(self) -> str:
        return TOKEN_ENDPOINT

    @property
    def revoke_endpoint(self) -> str:
        return REVOKE_ENDPOINT

    @property
    def identity_url(self) -> str:
        return IDENTITY_URL

    def redirect_uri(self) -> str:
        """The registered OAuth redirect URI (contract "Origins")."""
        return self.public_base_url.rstrip("/") + FINISH_AUTH_PATH

    def authorize_url(self) -> str:
        """Base of the staff link: ``<origin>/api/googleHealth/authorize``."""
        return self.public_base_url.rstrip("/") + AUTHORIZE_PATH

    @staticmethod
    def required_keys() -> tuple[str, ...]:
        return _REQUIRED

    def missing_keys(self) -> list[str]:
        """Environment names of the unset required keys. Names only, never values."""
        return [
            f"GOOGLE_HEALTH_{name.upper()}" for name in _REQUIRED if not getattr(self, name)
        ]

    def problems(self, auth_signing_secret: str) -> list[str]:
        """Names of the violated rules (T-10.1-75). Never a value.

        ``auth_signing_secret`` is ``ow_api``'s own access-token signing
        secret, compared only to reject its reuse.
        """
        found: list[str] = []
        values = [getattr(self, name) for name in _SECRETS]
        for name, value in zip(_SECRETS, values, strict=True):
            if len(value) < _MIN_SECRET_LENGTH:
                found.append(f"{name}_short")
        present = [value for value in values if value]
        if len(set(present)) != len(present):
            found.append("secrets_not_distinct")
        if auth_signing_secret and auth_signing_secret in present:
            found.append("secret_reuses_api_jwt")
        if not _is_https_origin(self.public_base_url):
            found.append("public_base_url_not_https_origin")
        if (
            not self.client_id.endswith(_CLIENT_ID_SUFFIX)
            or len(self.client_id) == len(_CLIENT_ID_SUFFIX)
        ):
            found.append("client_id_format")
        hold = self.migration_hold.strip()
        if hold and _hold_malformed(hold):
            found.append("migration_hold_malformed")
        if not _is_https_url(self.keyset_url):
            found.append("keyset_url_not_https")
        return found

    def held_study_ids(self) -> frozenset[str] | Literal["*"]:
        """The migration hold: ``"*"`` for every study, else the held study ids.

        A malformed value holds every study (fail closed); ``problems`` names
        it, and the routes answer 503 until it is fixed.
        """
        raw = self.migration_hold.strip()
        if not raw:
            return frozenset()
        if _hold_malformed(raw):
            return "*"
        if raw == "*":
            return "*"
        return frozenset(item.strip().lower() for item in raw.split(","))


def _hold_malformed(raw: str) -> bool:
    if raw == "*":
        return False
    items = [item.strip() for item in raw.split(",")]
    return any(not _STUDY_ID.match(item) for item in items)


def _is_https_url(value: str) -> bool:
    try:
        parts = urllib.parse.urlsplit(value)
    except ValueError:
        return False
    return parts.scheme == "https" and bool(parts.hostname) and parts.username is None


def _is_https_origin(value: str) -> bool:
    try:
        parts = urllib.parse.urlsplit(value)
        port_ok = parts.port is None or parts.port > 0
    except ValueError:
        return False
    return (
        parts.scheme == "https"
        and bool(parts.hostname)
        and parts.username is None
        and parts.password is None
        and port_ok
        and parts.path in ("", "/")
        and not parts.query
        and not parts.fragment
        and "?" not in value
        and "#" not in value
    )
