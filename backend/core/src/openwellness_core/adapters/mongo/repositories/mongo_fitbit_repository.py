"""Mongo repository for Fitbit."""

from typing import Generic, Type

from ....application.repositories.fitbit_repository import (
    FitbitRepository,
    SomeFitbit,
)
from ....domain.models.fitbit import (
    D13_ALIASES,
    Fitbit,
    active_filter,
    select_active,
)
from ...interfaces.collection_repository import CollectionRepository
from ..model.mongo_fitbit import MongoFitbit
from .mongo_base_repository import MongoBaseRepository

# schedulernew alone writes these, under a devicesFetchedAt guard; OpenWellness
# reads them but never writes them, so a save can't overwrite a newer snapshot.
_SCHEDULER_OWNED: tuple[str, ...] = ("devices", "devicesFetchedAt")


class MongoFitbitRepository(
    MongoBaseRepository[SomeFitbit, MongoFitbit],
    FitbitRepository[SomeFitbit],
    Generic[SomeFitbit],
):
    """Mongo repository for the Fitbit entity."""

    def __init__(
        self,
        mongo_repo: CollectionRepository,
        entity_type: Type[SomeFitbit] = Fitbit,
        persistence_type: type[MongoFitbit] = MongoFitbit,
    ) -> None:
        super().__init__(mongo_repo, entity_type, persistence_type)
        self.entity_type: Type[SomeFitbit] = entity_type

    def _to_doc(self, entity: SomeFitbit) -> dict:
        """Serialize ``entity``, leaving out every D-13 key whose value is None
        and the scheduler-owned device snapshot keys.

        Used by both ``create`` and ``save``. A legacy record loaded and saved
        through OpenWellness keeps its stored shape: no ``provider: null`` or
        ``supersededAt: null`` keys appear in a document frame and the
        scheduler also read.
        """
        doc = super()._to_doc(entity)
        for alias in D13_ALIASES:
            if doc.get(alias, 0) is None:
                del doc[alias]
        for alias in _SCHEDULER_OWNED:
            doc.pop(alias, None)
        return doc

    def get_by_participant_id(self, participant_id: str) -> SomeFitbit | None:
        """The participant's active connection, by the contract's selection rule.

        Queries only ACTIVE records, so a superseded record is never returned;
        with a superseded legacy record and a Google record, the Google record
        wins (D-08, D-09). ``get_by_id`` and ``list_all`` stay unfiltered audit
        reads.
        """
        result = self.get_by_query({"participantId": participant_id, **active_filter()})
        return select_active(result)
