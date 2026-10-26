"""FastAPI app factory and entrypoint.

The lifespan builds an :class:`ApplicationContainer`, binds the concrete
``AppConfig`` to the ``app_config`` provider, opens the Couchbase
connection, and wires the resource modules so ``@inject`` markers
resolve. Routes pull repositories through container providers — no
hand-rolled ``app.state.repos`` map.

The exceptions are the event-handler routes, which read
``app.state.event_handler_deps`` (see :mod:`openwellness_api.event_handlers`),
and frame's ``POST /api/participants``, which reads
``app.state.frame_participant_deps`` (see
:mod:`openwellness_api.frame_participants`).
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from dependency_injector import providers
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import APISettings, AppConfig
from .container import ApplicationContainer
from .deps.auth_container import AuthContainer
from .errors.handlers import register_exception_handlers
from .event_handlers import build_event_handler_deps, build_event_handlers_router
from .event_handlers.celery_producer import ProducerSettings
from .frame_participants import build_frame_participant_deps, build_frame_participants_router
from .google_health import (
    build_bridge_deps,
    build_google_health_deps,
    build_google_health_router,
)
from .google_health.bridge import install_google_health_audit_logger
from .resources import RESOURCE_MODULES
from .v1 import build_v1_router

logger = logging.getLogger(__name__)

_WIRED_MODULES = [mod.__name__ for mod in RESOURCE_MODULES]

LIVENESS_PATH = "/healthz"


class LivenessAccessLogFilter(logging.Filter):
    """Drop uvicorn access records for the liveness path (D-16).

    uvicorn's access logger formats ``(client_addr, method, full_path,
    http_version, status_code)``; ``full_path`` may carry a query string, so
    it is split before comparing. Anything that does not look like an access
    record passes through untouched.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str):
            return args[2].split("?", 1)[0] != LIVENESS_PATH
        return True


_LIVENESS_FILTER = LivenessAccessLogFilter()

GOOGLE_HEALTH_PREFIX = "/api/googlehealth"


class GoogleHealthAccessLogFilter(logging.Filter):
    """Drop the query string from uvicorn access records under ``/api/googleHealth``.

    ``authorize?t=`` carries the link token and ``finishAuth?code=&state=``
    the OAuth code and state (research Pitfall 7, T-10.1-17). The record is
    kept, with the path only; every other record passes untouched. The
    prefix is compared case-insensitively, so an odd-cased probe of the same
    group cannot log its query either.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str):
            path, sep, _query = args[2].partition("?")
            if sep and path.lower().startswith(GOOGLE_HEALTH_PREFIX):
                record.args = (*args[:2], path, *args[3:])
        return True


_GOOGLE_HEALTH_FILTER = GoogleHealthAccessLogFilter()


def install_google_health_access_log_filter() -> None:
    """Attach the Google Health query filter to uvicorn's access logger (idempotent)."""
    logging.getLogger("uvicorn.access").addFilter(_GOOGLE_HEALTH_FILTER)


def install_liveness_access_log_filter() -> None:
    """Attach the liveness filter to uvicorn's access logger (idempotent)."""
    logging.getLogger("uvicorn.access").addFilter(_LIVENESS_FILTER)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # D-16: the liveness probe is the same noise class the api submodule's
    # log-noise cleanup removed for `frame`. Every prober (Compose healthcheck,
    # edge, `make smokeEdge`, cutover checks) would otherwise write an access
    # line every ~10 s into a log store held under six-year retention,
    # drowning the real requests the channels-guard alert queries. Filtering
    # at the access logger silences all probers at the source; widening the
    # healthcheck interval would silence one and degrade readiness. Installed
    # here because the access logger only matters under a real server (the
    # test fixture never runs the lifespan).
    install_liveness_access_log_filter()
    # T-10.1-17: the Google Health authorize and finishAuth URLs carry a link
    # token, an OAuth code and a state in their query strings.
    install_google_health_access_log_filter()
    # Phase 16 D-10: the internal links audit line is INFO on its own
    # logger, which needs its own stdout handler to reach Loki.
    install_google_health_audit_logger()

    # --- Auth feature wiring (settings + boot guard) -------------------- #
    auth_container = AuthContainer()

    # Boot guard (fail fast): refuse to start with weak/unset secrets, BEFORE
    # any expensive setup (no Couchbase/Redis is opened yet), so a misconfigured
    # secret fails instantly. The 32-char minimum also keeps PyJWT's HS256 keys
    # above its weak-key warning threshold. This runs only at real server
    # startup (the test app fixture does not invoke the lifespan), so it can be
    # unconditional.
    s = auth_container.auth_settings()
    if len(s.jwt_secret) < 32 or len(s.code_pepper) < 32:
        raise RuntimeError(
            "API_AUTH_JWT_SECRET and API_AUTH_CODE_PEPPER must each be set to "
            "at least 32 characters."
        )

    # Boot guard passed — now open the expensive resources. The Couchbase
    # cluster opens here (entity_repository().initialize()); from this point on
    # all further setup runs INSIDE the try/ so the finally: always cleans up.
    container = ApplicationContainer()
    container.app_config.override(providers.Object(AppConfig()))
    container.repositories.entity_repository().initialize()
    app.state.container = container
    container.wire(modules=_WIRED_MODULES)

    try:
        # The Mongo refresh-session collection handle is owned by the MAIN
        # container; hand it to the auth container so its session store can use
        # it. If this (or ensure_indexes / redis construction) raises, the
        # finally: below still cleans up the already-open Couchbase cluster.
        collection_repository = container.repositories.collection_repository()
        coll = collection_repository[s.refresh_collection]
        auth_container.refresh_collection.override(providers.Object(coll))
        auth_container.session_store().ensure_indexes()

        # Construct/open the Redis client now (lazy provider). Do NOT hard-fail
        # startup if Redis is down — it may come up later, and the per-request
        # 503 handler covers runtime outages. A best-effort ping just surfaces
        # a warning.
        redis_client = auth_container.redis_client()
        try:
            redis_client.ping()
        except Exception:  # pragma: no cover - startup resilience
            logger.warning("Redis not reachable at startup; continuing anyway")

        app.state.auth_container = auth_container

        # Event-handler deps (HOOK-01): frame's own Couchbase views on the
        # bucket the entity repository already opened (no second cluster
        # connection), frame's ``studies`` collection on the same Mongo
        # handle, and the Celery producer for the queue ``router`` consumes.
        # The SMART weight readers (D-04) share both handles: ``conditions``
        # (CouchbaseViewConditionReader) and ``participants``
        # (MongoParticipantReader) are assigned into EventHandlerDeps by
        # build_event_handler_deps, as is the ActiGraph ``devices`` reader
        # (MongoDeviceReader) on the same Mongo handle (HOOK-02).
        # ``STUDY_SPECIFIC`` is read on first use.
        # The producer connects lazily, so an unset CELERY_BROKER_URL does
        # not stop boot; it logs one warning and every publish answers 500.
        entity_repository = container.repositories.entity_repository()
        app.state.event_handler_deps = build_event_handler_deps(
            bucket=entity_repository.cluster.bucket(entity_repository.bucket_name),
            db=collection_repository,
            producer_settings=ProducerSettings(),
        )

        # Frame's participant creation (HOOK-03): the same Mongo handle, and
        # the SG admin repository built on first use from
        # SYNC_GATEWAY_ADMIN_URL/SYNC_GATEWAY_DB. Unset keys log one WARNING
        # naming them and make only this route answer 500 (T-10-39).
        app.state.frame_participant_deps = build_frame_participant_deps(db=collection_repository)

        # Google Health authorization (Phase 10.1, GHA-01): the same Mongo
        # handle for ``participants``/``fitbits``, the auth Redis for the
        # state nonces, link claims and migration locks (shared by both
        # uvicorn workers), and a producer for ``scheduler_new``. Unset or
        # invalid GOOGLE_HEALTH_* keys log one WARNING naming them (never a
        # value) and make only the Google Health routes answer 503.
        app.state.google_health_deps = build_google_health_deps(
            db=collection_repository,
            redis=redis_client,
            producer_settings=ProducerSettings(),
            auth_signing_secret=s.jwt_secret,
        )
        # Phase 16 D-01/D-04/D-10: the frame -> ow bridge for the internal
        # links route. An unset, short or reused GOOGLE_HEALTH_BRIDGE_SECRET
        # logs one WARNING naming the rules (never a value) and makes only
        # POST /internal/googleHealth/links answer 503.
        app.state.google_health_bridge = build_bridge_deps(
            google_health=app.state.google_health_deps.settings,
            auth_jwt_secret=s.jwt_secret,
            auth_code_pepper=s.code_pepper,
        )

        yield
    finally:
        try:
            container.repositories.entity_repository().cleanup()
        except Exception:  # pragma: no cover - shutdown best-effort
            pass
        try:
            # The redis client may not have been constructed if startup failed
            # before redis_client() was first resolved; guard accordingly.
            auth_container.redis_client().close()
        except Exception:  # pragma: no cover - shutdown best-effort
            pass
        container.unwire()


def create_app() -> FastAPI:
    settings = APISettings()
    app = FastAPI(title=settings.title, lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        # Browsers hide non-safelisted response headers from JS unless exposed;
        # the dashboard reads Retry-After for the 429 resend-cooldown fallback.
        expose_headers=["Retry-After"],
    )
    register_exception_handlers(app)
    app.include_router(build_v1_router())
    # Externally registered vendor and Sync Gateway contracts (HOOK-01/02),
    # outside /v1 so require_write_principal never applies. Unauthenticated by
    # design, matching frame's ``auth: false``, with a per-route marker the
    # route-walking test pins. The router ends in a hapi-404 catch-all for
    # every other URI under /api/eventHandlers.
    app.include_router(build_event_handlers_router())
    # Frame's participant creation at frame's path (D-11), outside /v1 but
    # behind the same require_write_principal guard at the router level; the
    # handler then applies frame's admin scope and root group. Built, not
    # flipped: the edge's /api/participants group stays on frame (D-13).
    app.include_router(build_frame_participants_router())
    # Google Health authorization (Phase 10.1): the staff link route behind
    # require_write_principal, and the participant's authorize/finishAuth
    # routes carrying the unauthenticated marker (D-11).
    app.include_router(build_google_health_router())

    # Liveness: its access-log line is filtered at startup (D-16, see lifespan).
    @app.get(LIVENESS_PATH, tags=["meta"])
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    _ = healthz
    return app


app = create_app()
