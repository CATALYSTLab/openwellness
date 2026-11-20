"""Shared fakes for the Google Health authorization tests (10.1-05).

Nothing here talks to Google, Mongo, Redis or a broker: mongomock stands in
for the ``participants`` and ``fitbits`` collections, fakeredis for the state
nonces, link claims and locks, :class:`FakeGoogleOAuthClient` for the token,
identity and revoke calls, and :class:`RecordingPublisher` for Celery.

The app is a local ``FastAPI()`` with only the Google Health router, the
exception handlers and a ``get_principal`` override, like the event-handler
suites build theirs.
"""

from __future__ import annotations

import threading
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import fakeredis
import mongomock
from bson import ObjectId
from fastapi import FastAPI
from fastapi.testclient import TestClient

from openwellness_api.deps.principal import Principal, get_principal
from openwellness_api.errors.handlers import register_exception_handlers
from openwellness_api.event_handlers.celery_producer import ProducerSettings
from openwellness_api.event_handlers.ports import TaskPublishError
from openwellness_api.google_health import (
    GoogleHealthDeps,
    build_google_health_deps,
    build_google_health_router,
)
from openwellness_api.google_health.google_client import (
    GoogleOAuthError,
    Identity,
    TokenGrant,
)
from openwellness_api.google_health.settings import DEFAULT_SCOPES, GoogleHealthSettings

PUBLIC_BASE_URL = "https://example.test"
LINKS_PATH = "/api/googleHealth/links"
AUTHORIZE_PATH = "/api/googleHealth/authorize"
FINISH_PATH = "/api/googleHealth/finishAuth"
COOKIE_NAME = "gh_oauth"
API_JWT_SECRET = "api-access-token-signing-secret-for-tests-0001"

FULL_SCOPE = " ".join(DEFAULT_SCOPES)


def make_settings(**overrides: Any) -> GoogleHealthSettings:
    values: dict[str, Any] = {
        "client_id": "123456789012-testclient.apps.googleusercontent.com",
        "client_secret": "client-secret-for-tests-000000000001",
        "link_secret": "link-signing-secret-for-tests-00000000001",
        "state_secret": "state-signing-secret-for-tests-0000000001",
        "webhook_secret": "webhook-shared-secret-for-tests-00000001",
        "public_base_url": PUBLIC_BASE_URL,
        "migration_hold": "",
    }
    values.update(overrides)
    return GoogleHealthSettings(**values)


@dataclass
class FakeGoogleOAuthClient:
    """Recorded Google responses keyed by code and by access token.

    ``identity_gate`` maps an access token to an event ``get_identity`` waits
    on, so a threaded test can hold a request inside the identity call.
    ``revoke_errors`` maps a token to the ``GoogleOAuthError`` kind ``revoke``
    raises after recording it.
    """

    grants: dict[str, TokenGrant] = field(default_factory=dict)
    identities: dict[str, Identity] = field(default_factory=dict)
    exchanges: list[str] = field(default_factory=list)
    identity_calls: list[str] = field(default_factory=list)
    revokes: list[str] = field(default_factory=list)
    revoke_errors: dict[str, str] = field(default_factory=dict)
    identity_gate: dict[str, threading.Event] = field(default_factory=dict)
    identity_entered: dict[str, threading.Event] = field(default_factory=dict)
    fail_identity: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def add(
        self,
        code: str,
        *,
        access: str,
        refresh: str | None,
        health_user_id: str,
        legacy_user_id: str | None,
        scope: str = FULL_SCOPE,
        expires_in: int = 3599,
    ) -> None:
        self.grants[code] = TokenGrant(
            access_token=access, refresh_token=refresh, expires_in=expires_in, scope=scope
        )
        self.identities[access] = Identity(
            health_user_id=health_user_id, legacy_user_id=legacy_user_id
        )

    def exchange_code(self, code: str) -> TokenGrant:
        with self._lock:
            self.exchanges.append(code)
        grant = self.grants.get(code)
        if grant is None:
            raise GoogleOAuthError("token_exchange_failed")
        return grant

    def get_identity(self, access_token: str) -> Identity:
        with self._lock:
            self.identity_calls.append(access_token)
        entered = self.identity_entered.get(access_token)
        if entered is not None:
            entered.set()
        gate = self.identity_gate.get(access_token)
        if gate is not None:
            assert gate.wait(timeout=10), "identity gate never released"
        if self.fail_identity:
            raise GoogleOAuthError("identity_failed")
        identity = self.identities.get(access_token)
        if identity is None:
            raise GoogleOAuthError("identity_failed")
        return identity

    def revoke(self, token: str) -> None:
        with self._lock:
            self.revokes.append(token)
        kind = self.revoke_errors.get(token)
        if kind is not None:
            raise GoogleOAuthError(kind)


@dataclass
class RecordingPublisher:
    calls: list[tuple[str, list[Any], str]] = field(default_factory=list)
    error: Exception | None = None

    def publish(self, task_name: str, args: list[Any], queue: str = "celery") -> None:
        if self.error is not None:
            raise self.error
        self.calls.append((task_name, list(args), queue))


class Harness:
    """One isolated set of fakes, the deps built from them, and an app."""

    def __init__(self, settings: GoogleHealthSettings | None = None) -> None:
        self.db = mongomock.MongoClient()["frame"]
        self.redis = fakeredis.FakeRedis(decode_responses=True)
        self.google = FakeGoogleOAuthClient()
        self.publisher = RecordingPublisher()
        self.settings = settings if settings is not None else make_settings()
        self.principal = Principal(id="staff-1", roles=("admin",), is_authenticated=True)
        self.deps: GoogleHealthDeps = build_google_health_deps(
            db=self.db,
            redis=self.redis,
            producer_settings=ProducerSettings(),
            settings=self.settings,
            auth_signing_secret=API_JWT_SECRET,
            google=self.google,
            publisher=self.publisher,
        )
        self.app = FastAPI()
        register_exception_handlers(self.app)
        self.app.include_router(build_google_health_router())
        self.app.state.google_health_deps = self.deps
        self.app.dependency_overrides[get_principal] = lambda: self.principal

    def client(self) -> TestClient:
        return TestClient(self.app, follow_redirects=False)

    # --- seeding ------------------------------------------------------------

    def seed_participant(
        self, *, active: bool | None = True, study_id: ObjectId | None = None
    ) -> str:
        oid = ObjectId()
        doc: dict[str, Any] = {
            "_id": oid,
            "couchId": str(oid),
            "studyId": study_id if study_id is not None else ObjectId(),
        }
        if active is not None:
            doc["isActive"] = active
        self.db["participants"].insert_one(doc)
        return str(oid)

    def seed_legacy(self, participant_id: str, owner_id: str = "LEGACYOWNER1") -> str:
        result = self.db["fitbits"].insert_one(
            {
                "participantId": participant_id,
                "accessToken": "legacy-access-token",
                "refreshToken": "legacy-refresh-token",
                "ownerId": owner_id,
                "timeCreated": 1_700_000_000,
            }
        )
        return str(result.inserted_id)

    def seed_google(
        self,
        participant_id: str,
        *,
        health_user_id: str,
        migrated_at: int,
        refresh_token: str | None = "old-google-refresh",
        access_token: str | None = "old-google-access",
    ) -> str:
        """A GOOGLE_ACTIVE record; a ``None`` token leaves that field out."""
        doc: dict[str, Any] = {
            "participantId": participant_id,
            "provider": "googleHealth",
            "accessToken": access_token,
            "refreshToken": refresh_token,
            "expiresAt": migrated_at + 3600,
            "scope": FULL_SCOPE,
            "healthUserId": health_user_id,
            "legacyUserId": None,
            "timeCreated": migrated_at,
            "migratedAt": migrated_at,
            "migrationStatus": "complete",
        }
        for name in ("accessToken", "refreshToken"):
            if doc[name] is None:
                del doc[name]
        result = self.db["fitbits"].insert_one(doc)
        return str(result.inserted_id)

    # --- the three steps ------------------------------------------------------

    def mint_link(self, client: TestClient, participant_id: str) -> str:
        resp = client.post(LINKS_PATH, json={"participantId": participant_id})
        assert resp.status_code == 200, resp.text
        return resp.json()["url"]

    def link_token(self, url: str) -> str:
        query = urllib.parse.urlsplit(url).query
        return urllib.parse.parse_qs(query)["t"][0]

    def authorize(self, client: TestClient, url_or_token: str) -> tuple[Any, str, str]:
        """Follow the link; return (response, state, cookie value)."""
        token = (
            self.link_token(url_or_token) if url_or_token.startswith("http") else url_or_token
        )
        resp = client.get(AUTHORIZE_PATH, params={"t": token})
        assert resp.status_code == 302, resp.text
        location = resp.headers["location"]
        state = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)["state"][0]
        return resp, state, cookie_value(resp)

    def finish(
        self, client: TestClient, *, code: str, state: str, cookie: str | None
    ) -> Any:
        headers = {"cookie": f"{COOKIE_NAME}={cookie}"} if cookie is not None else {}
        return client.get(FINISH_PATH, params={"code": code, "state": state}, headers=headers)

    def run_flow(self, participant_id: str, code: str) -> Any:
        client = self.client()
        url = self.mint_link(client, participant_id)
        _, state, cookie = self.authorize(client, url)
        return self.finish(client, code=code, state=state, cookie=cookie)

    # --- inspection -----------------------------------------------------------

    def google_records(self, **query: Any) -> list[dict[str, Any]]:
        return list(self.db["fitbits"].find({"provider": "googleHealth", **query}))

    def active_google(self, **query: Any) -> list[dict[str, Any]]:
        return self.google_records(supersededAt=None, **query)


def cookie_value(resp: Any) -> str:
    for header in resp.headers.get_list("set-cookie"):
        name, _, rest = header.partition("=")
        if name.strip() == COOKIE_NAME:
            return rest.split(";", 1)[0]
    raise AssertionError("no gh_oauth cookie set")


def set_cookie_header(resp: Any) -> str:
    for header in resp.headers.get_list("set-cookie"):
        if header.strip().startswith(f"{COOKIE_NAME}="):
            return header
    raise AssertionError("no gh_oauth cookie set")


class FailingPublisher(RecordingPublisher):
    def __init__(self) -> None:
        super().__init__(error=TaskPublishError("ConnectionError"))
