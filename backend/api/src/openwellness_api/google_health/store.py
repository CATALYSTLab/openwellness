"""The ``fitbits`` writes and reads finishAuth and the revoke route need.

Every filter comes from :mod:`openwellness_core.domain.models.fitbit` (10.1-17),
so ``ow_api``, OpenWellness core, frame and the scheduler agree on which
record is active. This module defines no filter literal of its own.
"""

from __future__ import annotations

from typing import Any, Final

from bson import ObjectId

from openwellness_core.domain.models.fitbit import (
    active_filter,
    google_active_filter,
    legacy_active_filter,
)

FITBITS: Final = "fitbits"


class GoogleHealthStore:
    """Over the raw Mongo handle (indexable by collection name)."""

    def __init__(self, db: Any) -> None:
        self._db = db

    @property
    def _fitbits(self) -> Any:
        return self._db[FITBITS]

    def insert_google_record(self, doc: dict[str, Any]) -> str:
        return str(self._fitbits.insert_one(dict(doc)).inserted_id)

    def supersede_active(self, participant_id: str, by_id: str, at: int) -> list[str]:
        """Mark every other ACTIVE record of the participant superseded by ``by_id``.

        The update repeats the ACTIVE filter, so a record another writer has
        already superseded is left alone. Returns the hex ids read inside the
        same filter.
        """
        query = {"participantId": participant_id, **active_filter()}
        query["_id"] = {"$ne": ObjectId(by_id)}
        ids = [doc["_id"] for doc in self._fitbits.find(query, {"_id": 1})]
        if not ids:
            return []
        update_query = {"participantId": participant_id, **active_filter(), "_id": {"$in": ids}}
        self._fitbits.update_many(
            update_query, {"$set": {"supersededAt": at, "supersededBy": by_id}}
        )
        return [str(oid) for oid in ids]

    def active_google_owner_of(
        self, health_user_id: str, *, other_than: str | None = None
    ) -> str | None:
        """A participant whose GOOGLE_ACTIVE record holds ``health_user_id`` (I2).

        With ``other_than``, only a different participant counts, so a
        dual-active state left by a past race (I6) cannot hide another
        owner behind this participant's own record.
        """
        query: dict[str, Any] = {"healthUserId": health_user_id, **google_active_filter()}
        if other_than is not None:
            query["participantId"] = {"$ne": other_than}
        doc = self._fitbits.find_one(query, {"participantId": 1})
        if doc is None:
            return None
        return str(doc.get("participantId"))

    def carried_migrated_at(self, participant_id: str) -> int | None:
        """The earliest ``migratedAt`` among the participant's GOOGLE_ACTIVE records."""
        values = [
            doc.get("migratedAt")
            for doc in self._fitbits.find(
                {"participantId": participant_id, **google_active_filter()},
                {"migratedAt": 1},
            )
        ]
        stamps = [v for v in values if isinstance(v, int) and not isinstance(v, bool)]
        return min(stamps) if stamps else None

    def legacy_owner_ids(self, participant_id: str) -> list[str]:
        """``ownerId`` of the participant's LEGACY_ACTIVE records (mismatch check)."""
        return [
            str(doc["ownerId"])
            for doc in self._fitbits.find(
                {"participantId": participant_id, **legacy_active_filter()},
                {"ownerId": 1},
            )
            if doc.get("ownerId") is not None
        ]

    def active_google_records(self, participant_id: str) -> list[dict[str, Any]]:
        """The participant's GOOGLE_ACTIVE records, oldest ``_id`` first (revoke, Phase 17.3).

        Each is ``{"id", "healthUserId", "refreshToken", "accessToken"}``. The
        result carries tokens and must never be logged.
        """
        return [
            {
                "id": str(doc["_id"]),
                "healthUserId": doc.get("healthUserId"),
                "refreshToken": doc.get("refreshToken"),
                "accessToken": doc.get("accessToken"),
            }
            for doc in self._fitbits.find(
                {"participantId": participant_id, **google_active_filter()},
                {"_id": 1, "healthUserId": 1, "refreshToken": 1, "accessToken": 1},
            ).sort("_id", 1)
        ]

    def end_revoked(
        self, participant_id: str, record_ids: list[str], actor: str, at: int
    ) -> int:
        """End revoked GOOGLE_ACTIVE records; the documents and tokens stay (D-01..D-03).

        Returns the matched count. Fewer than ``len(record_ids)`` means another
        writer ended a record first; the grant is dead either way.
        """
        query = {
            "participantId": participant_id,
            **google_active_filter(),
            "_id": {"$in": [ObjectId(i) for i in record_ids]},
        }
        ended = {"supersededAt": at, "supersededBy": None, "revokedAt": at, "revokedBy": actor}
        result = self._fitbits.update_many(query, {"$set": ended})
        return int(result.matched_count)
