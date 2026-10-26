"""Interface skeleton for the bridge-guarded internal links route (opserver Phase 16).

Declares only the names the tests import; the route itself lands with the
implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

INTERNAL_LINKS_PATH: Final = "/internal/googleHealth/links"
AUDIT_LOGGER_NAME: Final = "openwellness_api.audit.google_health"


class BridgeSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GOOGLE_HEALTH_BRIDGE_", extra="ignore")

    secret: str = Field(default="", repr=False)


@dataclass(frozen=True)
class BridgeDeps:
    verifier: Any
    disabled: tuple[str, ...]


def build_bridge_deps(
    *,
    google_health: Any,
    auth_jwt_secret: str,
    auth_code_pepper: str,
    settings: BridgeSettings | None = None,
) -> BridgeDeps:
    return BridgeDeps(verifier=None, disabled=())
