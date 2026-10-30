"""The ``fitbits`` provider contract in OpenWellness core (opserver 10.1-17).

The contract is locked in opserver ``docs/google-health.md``, "Reference: the
contract". frame (10.1-03) and the scheduler (10.1-04) implement the same
filter documents and selection rule; these tests pin OpenWellness to them.

``mongomock`` is imported directly: a missing install fails the run rather
than skipping it.
"""

from datetime import datetime
from typing import Any

import mongomock

from openwellness_core.adapters.interfaces.collection_repository import (
    CollectionRepository,
)
from openwellness_core.adapters.mongo.model.mongo_fitbit import MongoFitbit
from openwellness_core.adapters.mongo.repositories.mongo_fitbit_repository import (
    MongoFitbitRepository,
)
from openwellness_core.domain.models.fitbit import (
    D13_ALIASES,
    PROVIDER_FITBIT,
    PROVIDER_GOOGLE_HEALTH,
    Fitbit,
    active_filter,
    google_active_filter,
    is_google_health,
    legacy_active_filter,
    select_active,
)

P = "5f0c1e2d3a4b5c6d7e8f9a0b"

D13_SNAKE = (
    "provider",
    "expires_at",
    "scope",
    "health_user_id",
    "legacy_user_id",
    "superseded_at",
    "superseded_by",
    "migrated_at",
    "migration_status",
    "reconsent_required_at",
    "last_sync_at",
    "devices",
    "devices_fetched_at",
)


class RecordingCollection:
    """Wraps a mongomock collection and records every ``find`` query."""

    def __init__(self, inner: Any, queries: list[dict]) -> None:
        self._inner = inner
        self._queries = queries

    def find(self, query: dict, *args: Any, **kwargs: Any) -> Any:
        self._queries.append(query)
        return self._inner.find(query, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class FakeCollectionRepository(CollectionRepository):
    """A ``CollectionRepository`` backed by an in-memory mongomock database."""

    def __init__(self) -> None:
        self.db = mongomock.MongoClient().db
        self.queries: list[dict] = []

    def __getattr__(self, name: str) -> Any:
        return self[name]

    def __getitem__(self, name: str) -> Any:
        return RecordingCollection(self.db[name], self.queries)

    def list_collection_names(self, *args: Any, **kwargs: Any) -> Any:
        return self.db.list_collection_names(*args, **kwargs)

    def create_collection(self, name: str, *args: Any, **kwargs: Any) -> Any:
        return self.db.create_collection(name, *args, **kwargs)

    def drop_collection(self, name_or_collection: Any, *args: Any, **kwargs: Any) -> Any:
        return self.db.drop_collection(name_or_collection, *args, **kwargs)

    def command(self, command: Any, *args: Any, **kwargs: Any) -> Any:
        return self.db.command(command, *args, **kwargs)


def legacy_doc(participant_id: str = P, **extra: Any) -> dict:
    """A legacy record as frame writes it: no provider, none of the D-13 fields."""
    doc = {
        "participantId": participant_id,
        "accessToken": "legacy-access",
        "refreshToken": "legacy-refresh",
        "ownerId": "LEGACY1",
        "subscriptionId": "sub-1",
        "timeCreated": 1_700_000_000,
    }
    doc.update(extra)
    return doc


def google_doc(participant_id: str = P, **extra: Any) -> dict:
    """A Google Health record as ``ow_api`` finishAuth writes it (D-13)."""
    doc = {
        "participantId": participant_id,
        "provider": PROVIDER_GOOGLE_HEALTH,
        "accessToken": "google-access",
        "refreshToken": "google-refresh",
        "expiresAt": 1_800_000_000,
        "scope": "https://www.googleapis.com/auth/googlehealth.sleep.readonly",
        "healthUserId": "health-user-1",
        "legacyUserId": "LEGACY1",
        "timeCreated": 1_790_000_000,
        "migratedAt": 1_790_000_000,
        "migrationStatus": "pending",
        "reconsentRequiredAt": None,
        "lastSyncAt": None,
    }
    doc.update(extra)
    return doc


def make_repo() -> tuple[FakeCollectionRepository, MongoFitbitRepository]:
    fake = FakeCollectionRepository()
    return fake, MongoFitbitRepository(fake)


# --- Task 1 tracer: a migrated participant resolves to the Google record ---


def test_migrated_participant_resolves_to_google_record():
    fake, repo = make_repo()
    google_id = fake.db.fitbits.insert_one(google_doc()).inserted_id
    fake.db.fitbits.insert_one(
        legacy_doc(supersededAt=1_790_000_001, supersededBy=str(google_id))
    )

    record = repo.get_by_participant_id(P)

    assert record is not None
    assert str(record.id) == str(google_id)
    assert record.provider == "googleHealth"
    assert record.health_user_id == "health-user-1"
    assert record.expires_at == 1_800_000_000
    assert record.scope is not None


def test_get_by_participant_id_sends_the_active_query():
    fake, repo = make_repo()

    repo.get_by_participant_id(P)

    assert fake.queries == [{"participantId": P, "supersededAt": None}]


def test_legacy_document_loads_with_all_d13_attributes_none():
    fake, repo = make_repo()
    legacy_id = fake.db.fitbits.insert_one(legacy_doc()).inserted_id

    record = repo.get_by_participant_id(P)

    assert isinstance(record, Fitbit)
    assert str(record.id) == str(legacy_id)
    assert record.owner_id == "LEGACY1"
    for name in D13_SNAKE:
        assert getattr(record, name) is None, name


def test_single_legacy_record_is_still_returned():
    fake, repo = make_repo()
    legacy_id = fake.db.fitbits.insert_one(legacy_doc()).inserted_id
    fake.db.fitbits.insert_one(legacy_doc(participant_id="other-participant"))

    record = repo.get_by_participant_id(P)

    assert record is not None
    assert str(record.id) == str(legacy_id)
    assert record.access_token == "legacy-access"


# --- Task 2: selection table, matching the scheduler's (10.1-04) case for case ---


def _entity(**kwargs: Any) -> Fitbit:
    return Fitbit(participant_id=P, time_created=datetime(2023, 11, 14), **kwargs)


def test_select_active_superseded_legacy_and_google_gives_google():
    legacy = _entity(id="legacy", superseded_at=1_790_000_001, superseded_by="google")
    google = _entity(id="google", provider=PROVIDER_GOOGLE_HEALTH)
    assert select_active([legacy, google]) is google
    assert select_active([google, legacy]) is google


def test_select_active_single_active_legacy_gives_it():
    legacy = _entity(id="legacy")
    assert select_active([legacy]) is legacy


def test_select_active_active_legacy_and_active_google_gives_google():
    legacy = _entity(id="legacy")
    google = _entity(id="google", provider=PROVIDER_GOOGLE_HEALTH)
    assert select_active([legacy, google]) is google


def test_select_active_two_active_legacy_gives_none():
    assert select_active([_entity(id="a"), _entity(id="b")]) is None


def test_select_active_empty_gives_none():
    assert select_active([]) is None


def test_select_active_superseded_google_and_active_google_gives_active():
    old = _entity(
        id="old",
        provider=PROVIDER_GOOGLE_HEALTH,
        superseded_at=1_790_000_500,
        superseded_by="new",
    )
    new = _entity(id="new", provider=PROVIDER_GOOGLE_HEALTH)
    assert select_active([old, new]) is new


def test_select_active_accepts_raw_documents():
    legacy = legacy_doc(supersededAt=1_790_000_001, supersededBy="google")
    google = google_doc()
    assert select_active([legacy, google]) is google
    assert select_active([legacy_doc(), legacy_doc()]) is None


def test_is_google_health_only_for_google_provider():
    assert is_google_health(_entity(provider=None)) is False
    assert is_google_health(_entity(provider=PROVIDER_FITBIT)) is False
    assert is_google_health(_entity(provider=PROVIDER_GOOGLE_HEALTH)) is True
    assert is_google_health(legacy_doc()) is False  # no provider key at all
    assert is_google_health({"provider": None}) is False
    assert is_google_health({"provider": "fitbit"}) is False
    assert is_google_health({"provider": "googleHealth"}) is True
    assert PROVIDER_FITBIT == "fitbit"
    assert PROVIDER_GOOGLE_HEALTH == "googleHealth"


# --- Task 2: contract equality and fresh copies ---

# Copied from opserver docs/google-health.md, "Reference: the contract",
# "Filters" (JSON null written as Python None).
CONTRACT_ACTIVE = {"supersededAt": None}
CONTRACT_LEGACY_ACTIVE = {"provider": {"$ne": "googleHealth"}, "supersededAt": None}
CONTRACT_GOOGLE_ACTIVE = {"provider": "googleHealth", "supersededAt": None}
CONTRACT_D13 = (
    "provider",
    "expiresAt",
    "scope",
    "healthUserId",
    "legacyUserId",
    "supersededAt",
    "supersededBy",
    "migratedAt",
    "migrationStatus",
    "reconsentRequiredAt",
    "lastSyncAt",
    "devices",
    "devicesFetchedAt",
)


def test_filters_equal_the_contract_documents():
    assert active_filter() == CONTRACT_ACTIVE
    assert legacy_active_filter() == CONTRACT_LEGACY_ACTIVE
    assert google_active_filter() == CONTRACT_GOOGLE_ACTIVE
    assert D13_ALIASES == CONTRACT_D13


def test_filter_accessors_return_fresh_deep_copies():
    legacy = legacy_active_filter()
    legacy["provider"]["$ne"] = "tampered"
    legacy["supersededAt"] = 1
    active = active_filter()
    active["extra"] = True
    google = google_active_filter()
    google["provider"] = "tampered"

    assert legacy_active_filter() == CONTRACT_LEGACY_ACTIVE
    assert active_filter() == CONTRACT_ACTIVE
    assert google_active_filter() == CONTRACT_GOOGLE_ACTIVE
    assert legacy_active_filter()["provider"] is not legacy_active_filter()["provider"]


# --- Task 2: three-record fixture visibility (the one 10.1-03 and 10.1-04 seed) ---


def seed_three_records(collection: Any) -> dict[str, Any]:
    """Active legacy, superseded legacy and Google, all for participant P."""
    google_id = collection.insert_one(google_doc()).inserted_id
    active_legacy_id = collection.insert_one(legacy_doc(ownerId="ACTIVE")).inserted_id
    superseded_id = collection.insert_one(
        legacy_doc(
            ownerId="SUPERSEDED",
            supersededAt=1_790_000_001,
            supersededBy=str(google_id),
        )
    ).inserted_id
    return {
        "google": google_id,
        "active_legacy": active_legacy_id,
        "superseded_legacy": superseded_id,
    }


def _ids(cursor: Any) -> set[Any]:
    return {doc["_id"] for doc in cursor}


def test_three_record_fixture_visibility_mongomock():
    collection = mongomock.MongoClient().db.fitbits
    ids = seed_three_records(collection)

    assert _ids(collection.find(legacy_active_filter())) == {ids["active_legacy"]}
    assert _ids(collection.find(google_active_filter())) == {ids["google"]}
    assert _ids(collection.find(active_filter())) == {
        ids["active_legacy"],
        ids["google"],
    }


def test_missing_provider_and_explicit_null_superseded_match_legacy_active_mongomock():
    collection = mongomock.MongoClient().db.fitbits
    no_provider = collection.insert_one(legacy_doc()).inserted_id
    explicit_null = collection.insert_one(
        legacy_doc(provider=None, supersededAt=None)
    ).inserted_id

    assert _ids(collection.find(legacy_active_filter())) == {no_provider, explicit_null}
    assert _ids(collection.find(google_active_filter())) == set()


# --- Task 2: write shape ---


def test_saving_a_loaded_legacy_record_keeps_its_key_set():
    fake, repo = make_repo()
    legacy_id = fake.db.fitbits.insert_one(legacy_doc()).inserted_id
    stored = fake.db.fitbits.find_one({"_id": legacy_id})
    assert stored is not None
    before = set(stored)

    record = repo.get_by_participant_id(P)
    assert record is not None
    record.access_token = "refreshed-access"
    repo.save(record, actor="test")

    after = fake.db.fitbits.find_one({"_id": legacy_id})
    assert after is not None
    assert set(after) == before
    assert after["accessToken"] == "refreshed-access"
    for alias in CONTRACT_D13:
        assert alias not in after


def test_creating_a_legacy_entity_writes_no_d13_keys():
    fake, repo = make_repo()

    repo.create(_entity(access_token="a", refresh_token="r"), actor="test")

    stored = fake.db.fitbits.find_one({"participantId": P})
    assert stored is not None
    for alias in CONTRACT_D13:
        assert alias not in stored, alias


# One paired device in the five-key legacy shape schedulernew stores.
DEVICE: dict[str, Any] = {
    "deviceVersion": "Charge 6",
    "type": "TRACKER",
    "lastSyncTime": "2026-10-06T13:01:40.000",
    "battery": "High",
    "batteryLevel": 80,
}

GOOGLE_VALUES: dict[str, Any] = {
    "provider": PROVIDER_GOOGLE_HEALTH,
    "expires_at": 1_800_000_000,
    "scope": "https://www.googleapis.com/auth/googlehealth.sleep.readonly",
    "health_user_id": "health-user-1",
    "legacy_user_id": "LEGACY1",
    "superseded_at": 1_795_000_000,
    "superseded_by": "6abd7bda37af6d279584adfc",
    "migrated_at": 1_790_000_000,
    "migration_status": "complete",
    "reconsent_required_at": 1_792_000_000,
    "last_sync_at": 1_791_000_000,
    "devices": [DEVICE],
    "devices_fetched_at": 1_791_000_100,
}
ALIAS_OF: dict[str, str] = dict(zip(D13_SNAKE, CONTRACT_D13))


def test_google_entity_round_trips_every_d13_field_by_alias():
    fake, repo = make_repo()

    created = repo.create(
        _entity(access_token="a", refresh_token="r", **GOOGLE_VALUES), actor="test"
    )

    stored = fake.db.fitbits.find_one({"participantId": P})
    assert stored is not None
    for name, value in GOOGLE_VALUES.items():
        if ALIAS_OF[name] in ("devices", "devicesFetchedAt"):
            assert ALIAS_OF[name] not in stored, name  # schedulernew-owned
        else:
            assert stored[ALIAS_OF[name]] == value, name
            assert getattr(created, name) == value, name
    loaded = repo.get_by_id(str(created.id))
    assert loaded is not None
    for name, value in GOOGLE_VALUES.items():
        if ALIAS_OF[name] not in ("devices", "devicesFetchedAt"):
            assert getattr(loaded, name) == value, name


def test_mongo_fitbit_round_trips_d13_fields_by_alias():
    doc = legacy_doc(**{ALIAS_OF[n]: v for n, v in GOOGLE_VALUES.items()})

    model = MongoFitbit.model_validate(doc)
    for name, value in GOOGLE_VALUES.items():
        assert getattr(model, name) == value, name

    dumped = model.model_dump(by_alias=True)
    for name, value in GOOGLE_VALUES.items():
        assert dumped[ALIAS_OF[name]] == value, name

    entity = model.to_domain(Fitbit)
    for name, value in GOOGLE_VALUES.items():
        assert getattr(entity, name) == value, name


def test_saving_a_loaded_google_record_keeps_a_newer_scheduler_snapshot():
    fake, repo = make_repo()
    google_id = fake.db.fitbits.insert_one(
        google_doc(devices=[DEVICE], devicesFetchedAt=1_791_000_100)
    ).inserted_id

    record = repo.get_by_participant_id(P)
    assert record is not None
    assert record.devices == [DEVICE]
    # schedulernew stores a newer snapshot between OpenWellness's load and save.
    newer = {**DEVICE, "battery": "Low"}
    fake.db.fitbits.update_one(
        {"_id": google_id},
        {"$set": {"devices": [newer], "devicesFetchedAt": 1_791_000_200}},
    )
    record.access_token = "refreshed-access"
    repo.save(record, actor="test")

    after = fake.db.fitbits.find_one({"_id": google_id})
    assert after is not None
    assert after["accessToken"] == "refreshed-access"
    assert after["devices"] == [newer]
    assert after["devicesFetchedAt"] == 1_791_000_200


def test_superseded_record_stays_visible_to_audit_reads():
    fake, repo = make_repo()
    ids = seed_three_records(fake.db.fitbits)

    assert repo.get_by_id(str(ids["superseded_legacy"])) is not None
    assert len(repo.list_all()) == 3
