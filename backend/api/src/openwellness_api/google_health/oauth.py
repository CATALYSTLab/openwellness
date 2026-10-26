"""``/api/googleHealth/links``, ``/authorize`` and ``/finishAuth`` (GHA-01, D-09..D-11, D-17).

1. Staff mint a participant-bound link (admin bearer).
2. The participant's browser follows it: ``authorize`` verifies the link, sets
   the ``gh_oauth`` cookie, mints a browser-bound single-use ``state`` and
   redirects to Google consent.
3. Google redirects to ``finishAuth``, which exchanges the code inline,
   stores one ``provider: googleHealth`` record with
   ``migrationStatus: "pending"``, supersedes every other active record of
   the participant and publishes ``googleHealth.completeMigration`` onto
   ``scheduler_new``.

Pages are fixed HTML strings that echo no request data. Log lines have the
fixed shape ``googleHealth/<route> <outcome>[: <ExceptionClassName>]`` and
never carry a token, code, state, link, cookie, participant id or Google
user id (HIPAA 6-year log retention).
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Annotated, Any, Final

import pymongo
from bson.errors import InvalidId
from pymongo.errors import WriteError
from fastapi import Depends, Query, Request
from starlette.concurrency import run_in_threadpool
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from ..deps.principal import Principal, get_principal
from ..event_handlers.celery_producer import SCHEDULER_NEW_QUEUE
from ..event_handlers.hapi import boom
from ..event_handlers.ports import ParticipantReader, TaskPublisher
from .google_client import GoogleOAuthClient, GoogleOAuthError, TokenGrant
from .settings import GoogleHealthSettings
from .signature import SignatureVerifier
from .store import GoogleHealthStore
from .tokens import GoogleHealthTokenError, GoogleHealthTokens, LinkClaim, TokenStoreError

logger = logging.getLogger(__name__)

COOKIE_NAME: Final = "gh_oauth"
COOKIE_PATH: Final = "/api/googleHealth"
COMPLETE_MIGRATION_TASK: Final = "googleHealth.completeMigration"
PROVIDER_GOOGLE_HEALTH: Final = "googleHealth"

_PAGE_HEADERS: Final = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


def _html(title: str, message: str) -> str:
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{title}</title></head><body><h1>{title}</h1><p>{message}</p></body></html>"
    )


SUCCESS_PAGE: Final = _html(
    "Google Health connected",
    "Your Google account is connected to the study. You can close this window.",
)
ERROR_PAGE: Final = _html(
    "We could not connect your Google account",
    "This link did not work. Please contact the study team for a new link.",
)
BUSY_PAGE: Final = _html(
    "Please try again",
    "Your account is being connected in another window. Please wait a minute, "
    "then open your link again.",
)
UNAVAILABLE_PAGE: Final = _html(
    "Google Health is not available",
    "Connecting Google accounts is not available right now. Please contact the study team.",
)


@dataclass(frozen=True)
class GoogleHealthDeps:
    """Everything the Google Health routes touch.

    ``disabled`` lists setting names or rule names that are unset or
    invalid; while it is non-empty every route answers 503.
    ``signature_verifier`` checks notification signatures (10.1-07); while it
    is ``None`` the notification receiver answers data notifications 503.
    """

    settings: GoogleHealthSettings
    tokens: GoogleHealthTokens
    store: GoogleHealthStore
    participants: ParticipantReader
    google: GoogleOAuthClient
    publisher: TaskPublisher
    clock: Callable[[], float] = time.time
    disabled: tuple[str, ...] = field(default=())
    signature_verifier: SignatureVerifier | None = None


def get_google_health_deps(request: Request) -> GoogleHealthDeps | None:
    deps = getattr(request.app.state, "google_health_deps", None)
    return deps if isinstance(deps, GoogleHealthDeps) else None


def _page(body: str, status: int) -> HTMLResponse:
    return HTMLResponse(body, status_code=status, headers=dict(_PAGE_HEADERS))


def _unavailable() -> HTMLResponse:
    return _page(UNAVAILABLE_PAGE, 503)


def _error(status: int = 400) -> HTMLResponse:
    return _page(ERROR_PAGE, status)


def _busy() -> HTMLResponse:
    return _page(BUSY_PAGE, 409)


def browser_hash(cookie: str) -> str:
    """SHA-256 of the cookie value, base64url without padding (the ``bh`` claim)."""
    digest = hashlib.sha256(cookie.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _new_cookie() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def _participant(deps: GoogleHealthDeps, participant_id: str) -> dict[str, Any] | None:
    """The participant document, or ``None`` when unknown, malformed or inactive.

    ``fitbits.participantId`` is the hex ``_id`` of the ``participants``
    document (contract "fitbits Google record"; frame wraps the same id in
    ``ObjectID``), so the lookup is by ``_id``. A malformed id is "unknown";
    a Mongo failure propagates.
    """
    try:
        doc = deps.participants.find_by_id(participant_id)
    except (InvalidId, TypeError):
        return None
    if doc is None or doc.get("isActive") is False:
        return None
    return doc


def _held(deps: GoogleHealthDeps, participant: dict[str, Any]) -> bool:
    """Whether the participant's study is on the migration hold (contract "Migration hold")."""
    held = deps.settings.held_study_ids()
    if held == "*":
        return True
    study_id = participant.get("studyId")
    return bool(held) and study_id is not None and str(study_id).lower() in held


# --- POST /api/googleHealth/links ---------------------------------------------


async def create_link(
    request: Request,
    principal: Annotated[Principal, Depends(get_principal)],
) -> Response:
    deps = get_google_health_deps(request)
    if deps is None or deps.disabled:
        return _unavailable()
    if "admin" not in principal.roles:
        return boom(403, "Insufficient scope")
    try:
        body = await request.json()
    except Exception:
        return boom(400, "Invalid request payload input")
    participant_id = body.get("participantId") if isinstance(body, dict) else None
    if not isinstance(participant_id, str) or not participant_id:
        return boom(400, "Invalid request payload input")
    return await run_in_threadpool(_mint_link, deps, participant_id)


def _mint_link(deps: GoogleHealthDeps, participant_id: str) -> Response:
    return _mint_link_result(deps, participant_id)[0]


def _mint_link_result(deps: GoogleHealthDeps, participant_id: str) -> tuple[Response, int | None]:
    """The link response and its ``expiresAt``, or ``None`` on any refusal.

    The single minting implementation, shared by the public route and the
    bridge-guarded internal route (:mod:`.bridge`), which audits the expiry
    without reading the URL.
    """
    try:
        participant = _participant(deps, participant_id)
        if participant is None:
            return boom(404, "Participant not found."), None
        if _held(deps, participant):
            logger.warning("googleHealth/links held")
            return (
                boom(409, "The participant's study is on hold for Google Health migration."),
                None,
            )
        token, exp = deps.tokens.mint_link(participant_id)
    except Exception as exc:
        logger.error("googleHealth/links failed: %s", type(exc).__name__)
        return boom(500, "An internal server error occurred"), None
    url = deps.settings.authorize_url() + "?" + urllib.parse.urlencode({"t": token})
    response = JSONResponse(
        {"url": url, "expiresAt": exp}, headers={"Cache-Control": "no-store"}
    )
    return response, exp


# --- GET /api/googleHealth/authorize ------------------------------------------


def authorize(request: Request, t: Annotated[str | None, Query()] = None) -> Response:
    deps = get_google_health_deps(request)
    if deps is None or deps.disabled:
        return _unavailable()
    try:
        link = deps.tokens.verify_link(t)
        if deps.tokens.is_link_claimed(link.jti):
            logger.warning("googleHealth/authorize refused: link already used")
            return _error()
        participant = _participant(deps, link.participant_id)
        if participant is None:
            logger.warning("googleHealth/authorize refused: participant not active")
            return _error()
        if _held(deps, participant):
            logger.warning("googleHealth/authorize held")
            return _error()
        cookie = _new_cookie()
        state = deps.tokens.mint_state(
            link.participant_id, link.jti, link.exp, browser_hash(cookie)
        )
    except TokenStoreError as exc:
        # Redis is down, not the link: an infrastructure failure.
        logger.error("googleHealth/authorize failed: %s", type(exc).__name__)
        return _error(500)
    except GoogleHealthTokenError as exc:
        logger.warning("googleHealth/authorize refused: %s", type(exc).__name__)
        return _error()
    except Exception as exc:
        logger.error("googleHealth/authorize failed: %s", type(exc).__name__)
        return _error(500)

    settings = deps.settings
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": settings.client_id,
            "redirect_uri": settings.redirect_uri(),
            "scope": " ".join(settings.scopes),
            "access_type": "offline",
            "prompt": "consent",
            "state": state,
        },
        quote_via=urllib.parse.quote,
    )
    response = RedirectResponse(
        f"{settings.authorize_endpoint}?{query}", status_code=302, headers=dict(_PAGE_HEADERS)
    )
    response.set_cookie(
        COOKIE_NAME,
        cookie,
        max_age=settings.state_ttl_seconds,
        path=COOKIE_PATH,
        secure=True,
        httponly=True,
        samesite="lax",
    )
    return response


# --- GET /api/googleHealth/finishAuth -----------------------------------------


def finish_auth(
    request: Request,
    code: Annotated[str | None, Query()] = None,
    state: Annotated[str | None, Query()] = None,
    error: Annotated[str | None, Query()] = None,
) -> Response:
    deps = get_google_health_deps(request)
    if deps is None or deps.disabled:
        return _unavailable()
    if error is not None:
        # The participant declined (or Google refused) consent. Nothing is
        # claimed yet, and Google is not called.
        logger.warning("googleHealth/finishAuth consent not granted")
        return _error()
    if not code or not state:
        logger.warning("googleHealth/finishAuth refused: incomplete callback")
        return _error()

    # The cookie is checked against ``bh`` before the nonce is consumed, so a
    # state replayed from another browser cannot burn the real one (T-10.1-73).
    cookie = request.cookies.get(COOKIE_NAME) or ""
    try:
        claims = deps.tokens.consume_state(state, browser_hash(cookie))
    except TokenStoreError as exc:
        logger.error("googleHealth/finishAuth state store failed: %s", type(exc).__name__)
        return _error(500)
    except GoogleHealthTokenError as exc:
        logger.warning("googleHealth/finishAuth refused: %s", type(exc).__name__)
        return _error()

    pid = claims.participant_id
    try:
        participant = _participant(deps, pid)
    except Exception as exc:
        logger.error("googleHealth/finishAuth participant read failed: %s", type(exc).__name__)
        return _error(500)
    if participant is None:
        logger.warning("googleHealth/finishAuth refused: participant not active")
        return _error()
    if _held(deps, participant):
        logger.warning("googleHealth/finishAuth held")
        return _error()

    # I3: the link is claimed before the code is exchanged, so a second state
    # minted from the same link can never exchange a code.
    try:
        link_claim = deps.tokens.claim_link(claims.link_jti, claims.link_exp)
    except GoogleHealthTokenError as exc:
        logger.error("googleHealth/finishAuth link claim failed: %s", type(exc).__name__)
        return _error(500)
    if link_claim is None:
        logger.warning("googleHealth/finishAuth refused: link already used or expired")
        return _error()

    try:
        grant = deps.google.exchange_code(code)
    except GoogleOAuthError as exc:
        logger.warning("googleHealth/finishAuth google failed: %s", exc.kind)
        _release_link(deps, link_claim)
        return _error()

    missing_scope = set(deps.settings.scopes) - set(grant.scope.split())
    if grant.refresh_token is None or missing_scope:
        # Pitfall 5: granular consent or a missing refresh token. Nothing is
        # stored; the link can be used again once the participant re-consents
        # with every permission.
        logger.warning("googleHealth/finishAuth rejected grant: incomplete")
        _revoke_rejected_grant(deps, pid, grant)
        _release_link(deps, link_claim)
        return _error()

    try:
        identity = deps.google.get_identity(grant.access_token)
    except GoogleOAuthError as exc:
        logger.warning("googleHealth/finishAuth google failed: %s", exc.kind)
        _release_link(deps, link_claim)
        return _error()

    locks = deps.tokens.acquire_locks(pid, identity.health_user_id)
    if locks is None:
        logger.warning("googleHealth/finishAuth busy")
        _release_link(deps, link_claim)
        return _busy()

    superseded: list[str] = []
    try:
        try:
            # I2: under the account lock, no other participant may hold this
            # Google account. The grant is not revoked: the other
            # participant's active record shares it.
            owner = deps.store.active_google_owner_of(identity.health_user_id, other_than=pid)
            if owner is not None:
                logger.warning("googleHealth/finishAuth refused: account connected elsewhere")
                _release_link(deps, link_claim)
                return _error()
            legacy_owners = deps.store.legacy_owner_ids(pid)
            now = int(deps.clock())
            migrated_at = deps.store.carried_migrated_at(pid) or now
        except Exception as exc:
            # Nothing was written: the link can be retried.
            logger.error("googleHealth/finishAuth store failed: %s", type(exc).__name__)
            _release_link(deps, link_claim)
            return _error(500)

        # The locks are leases: the reads above may have outlived them. Renew
        # both (owner-checked) while the link claim is still pending, so a
        # failure here leaves only a short-lived claim behind.
        if not deps.tokens.renew_locks(locks):
            logger.warning("googleHealth/finishAuth busy: lock lease lost")
            _release_link(deps, link_claim)
            return _busy()

        # Last step before writing: keep the claim for the link's lifetime
        # (at least one lease); a pending claim lost to another request
        # writes nothing.
        try:
            committed = deps.tokens.commit_link(link_claim, claims.link_exp)
        except GoogleHealthTokenError as exc:
            logger.error("googleHealth/finishAuth link commit failed: %s", type(exc).__name__)
            _release_link(deps, link_claim)
            return _error(500)
        if not committed:
            logger.warning("googleHealth/finishAuth refused: link claim lost")
            return _error()

        # One deadline covers the insert and the supersede together, so both
        # finish, or fail, well before the renewed leases lapse.
        with pymongo.timeout(deps.settings.store_write_budget_seconds):
            written = _write_google_record(
                deps,
                link_claim,
                {
                    "participantId": pid,
                    "provider": PROVIDER_GOOGLE_HEALTH,
                    "accessToken": grant.access_token,
                    "refreshToken": grant.refresh_token,
                    "expiresAt": now + grant.expires_in,
                    "scope": grant.scope,
                    "healthUserId": identity.health_user_id,
                    "legacyUserId": identity.legacy_user_id,
                    "timeCreated": now,
                    "migratedAt": migrated_at,
                    "migrationStatus": "pending",
                },
            )
        if isinstance(written, Response):
            return written
        google_id, superseded = written
        if not deps.tokens.holds_locks(locks):
            # A lease is not a fence: a stall past it lets another finishAuth
            # write too. The dual-active state this can leave is never used
            # (contract I6, selection rule) and reconcile repairs it; say so now.
            logger.error("googleHealth/finishAuth lock lease lost during write")
    finally:
        deps.tokens.release_locks(locks)

    if legacy_owners and identity.legacy_user_id not in legacy_owners:
        # T-10.1-15: possibly the wrong Google account for this participant.
        logger.warning("googleHealth/finishAuth legacy account mismatch")

    _publish_complete_migration(deps, pid, google_id, superseded)
    logger.info("googleHealth/finishAuth connected")
    return _success()


def _write_google_record(
    deps: GoogleHealthDeps, claim: LinkClaim, doc: dict[str, Any]
) -> tuple[str, list[str]] | Response:
    """Insert the record, then supersede the participant's others.

    Runs under the caller's single ``pymongo.timeout`` deadline. Returns the
    new id and the superseded ids, or the error page when the insert failed.
    """
    try:
        google_id = deps.store.insert_google_record(doc)
    except WriteError as exc:
        # The server refused the insert: nothing was written, so the link
        # can be retried. The claim is already committed to the link's
        # lifetime; if Redis also fails to release it, only a new link helps.
        logger.error("googleHealth/finishAuth store failed: %s", type(exc).__name__)
        if not deps.tokens.release_link(claim):
            logger.error(
                "googleHealth/finishAuth link release failed after a refused insert: "
                "mint a new link"
            )
        return _error(500)
    except Exception as exc:
        # A timeout or dropped connection may follow a committed insert.
        # The link stays consumed so a retry cannot write a second record;
        # staff mint a new link if none was written.
        logger.error("googleHealth/finishAuth store outcome unknown: %s", type(exc).__name__)
        return _error(500)

    # From here the record exists and stays ``pending`` until the
    # scheduler's completeMigration runs (I5); the link stays consumed.
    try:
        superseded = deps.store.supersede_active(doc["participantId"], google_id, doc["timeCreated"])
    except Exception as exc:
        logger.error("googleHealth/finishAuth supersede failed: %s", type(exc).__name__)
        superseded = []
    return google_id, superseded


def _release_link(deps: GoogleHealthDeps, claim: LinkClaim) -> None:
    if not deps.tokens.release_link(claim):
        # The pending claim expires within ``lock_ttl_ms``; the link is
        # usable again after that.
        logger.warning("googleHealth/finishAuth link release failed")


def _success() -> Response:
    response = _page(SUCCESS_PAGE, 200)
    response.delete_cookie(
        COOKIE_NAME, path=COOKIE_PATH, secure=True, httponly=True, samesite="lax"
    )
    return response


def _publish_complete_migration(
    deps: GoogleHealthDeps, pid: str, google_id: str, superseded: list[str]
) -> None:
    """Hand the migration to the scheduler. Ids only, never a token (T-10.1-19).

    A failure is logged and swallowed: the record stays ``pending`` and the
    backfill's reconcile phase re-publishes it (contract I5, T-10.1-20).
    """
    try:
        deps.publisher.publish(
            COMPLETE_MIGRATION_TASK, [pid, google_id, superseded], queue=SCHEDULER_NEW_QUEUE
        )
    except Exception as exc:
        logger.error("googleHealth/finishAuth publish failed: %s", type(exc).__name__)


def _revoke_rejected_grant(deps: GoogleHealthDeps, pid: str, grant: TokenGrant) -> None:
    """Revoke a rejected grant only when no active record can share it.

    Contract revocation rule: revoke only when the identity lookup succeeds
    and no GOOGLE_ACTIVE record holds the same ``healthUserId``. A re-consent
    that unticked a scope shares the current connection's grant, and
    revoking it could disconnect the participant.

    The check and the revoke run under the participant and account locks, so
    a concurrent finishAuth cannot insert an active record for the same
    account between them. A lock held elsewhere skips the revoke.
    """
    try:
        identity = deps.google.get_identity(grant.access_token)
    except Exception:
        logger.warning("googleHealth/finishAuth revoke skipped")
        return
    locks = deps.tokens.acquire_locks(pid, identity.health_user_id)
    if locks is None:
        logger.warning("googleHealth/finishAuth revoke skipped")
        return
    try:
        try:
            revocable = deps.store.active_google_owner_of(identity.health_user_id) is None
        except Exception:
            revocable = False
        if not revocable:
            logger.warning("googleHealth/finishAuth revoke skipped")
            return
        try:
            deps.google.revoke(grant.refresh_token or grant.access_token)
        except Exception as exc:
            logger.warning("googleHealth/finishAuth revoke failed: %s", type(exc).__name__)
    finally:
        deps.tokens.release_locks(locks)
