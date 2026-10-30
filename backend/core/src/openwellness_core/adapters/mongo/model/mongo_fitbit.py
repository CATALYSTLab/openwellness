"""Mongo persistence for Fitbit."""

from typing import Any, ClassVar

from pydantic import ConfigDict, Field

from .mongo_base_entity import MongoBaseEntity


class MongoFitbit(MongoBaseEntity):
    """Persistence for Fitbit."""

    model_config = ConfigDict(
        populate_by_name=True, extra="ignore", arbitrary_types_allowed=True
    )

    collection: ClassVar[str] = "fitbits"

    participant_id: Any = Field(alias="participantId", default=None)
    access_token: Any = Field(alias="accessToken", default=None)
    refresh_token: Any = Field(alias="refreshToken", default=None)
    owner_id: Any = Field(alias="ownerId", default=None)
    subscription_id: Any = Field(alias="subscriptionId", default=None)
    time_created: Any = Field(alias="timeCreated", default=None)
    # The contract's D-13 fields (opserver docs/google-health.md). Each
    # defaults to None so an existing legacy document loads unchanged; the
    # repository drops them from writes while None (MongoFitbitRepository._to_doc).
    # devices / devicesFetchedAt are the paired-device snapshot schedulernew's
    # activity sync writes on Google records.
    provider: Any = Field(alias="provider", default=None)
    expires_at: Any = Field(alias="expiresAt", default=None)
    scope: Any = Field(alias="scope", default=None)
    health_user_id: Any = Field(alias="healthUserId", default=None)
    legacy_user_id: Any = Field(alias="legacyUserId", default=None)
    superseded_at: Any = Field(alias="supersededAt", default=None)
    superseded_by: Any = Field(alias="supersededBy", default=None)
    migrated_at: Any = Field(alias="migratedAt", default=None)
    migration_status: Any = Field(alias="migrationStatus", default=None)
    reconsent_required_at: Any = Field(alias="reconsentRequiredAt", default=None)
    last_sync_at: Any = Field(alias="lastSyncAt", default=None)
    devices: Any = Field(alias="devices", default=None)
    devices_fetched_at: Any = Field(alias="devicesFetchedAt", default=None)
