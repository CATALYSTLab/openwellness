"""``POST /internal/googleHealth/revocations``: the bridge-guarded revoke (opserver Phase 17.3).

frame authorizes a coach, then calls this route over the Compose network with
a bridge JWT whose ``typ`` is ``gh-revoke-bridge`` (D-12); the checks are
those of the internal links route (:func:`.bridge._bridge_request`).

- Google first: ow asks Google to revoke each GOOGLE_ACTIVE grant of the
  participant before any write (D-05, D-14).
- Then the records end with ``supersededAt``/``revokedAt`` (one unix second),
  ``supersededBy: null`` and ``revokedBy`` = the coach id. Tokens and every
  other field stay; the document is never deleted (D-01..D-03).
- Nothing linked answers 409 (D-06). The migration hold and the
  participant's ``isActive`` do not block (D-07, D-13): ow reads only
  ``fitbits`` here.
- Every attempt writes one audit line on :data:`.bridge.AUDIT_LOGGER_NAME`:
  ``googleHealth/internalRevocations outcome=<ok|400|401|409|423|500|502|503|504>
  actor=<24hex|-> participantId=<24hex|-> recordIds=<24hex[,24hex...]|->``.
  Record ids only, never a token or ``healthUserId``.
"""

from __future__ import annotations

import logging
from typing import Annotated

import pymongo
from fastapi import Depends, Request
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response

from ..event_handlers.hapi import HAPI_HEADERS, boom
from .bridge import (
    REVOKE_BRIDGE_TYP,
    _Attempt,
    _bridge_request,
    audit_logger,
    require_bridge_credential,
)
from .oauth import GoogleHealthDeps

logger = logging.getLogger(__name__)


def _audit_revoke(
    outcome: str, actor: str | None, participant_id: str | None, record_ids: tuple[str, ...]
) -> None:
    audit_logger.info(
        "googleHealth/internalRevocations outcome=%s actor=%s participantId=%s recordIds=%s",
        outcome,
        actor or "-",
        participant_id or "-",
        ",".join(record_ids) or "-",
    )


async def revoke_internal(
    request: Request,
    token: Annotated[str | None, Depends(require_bridge_credential)],
) -> Response:
    attempt = _Attempt()
    try:
        response = await _revoke_internal(request, token, attempt)
    except Exception as exc:
        logger.error("googleHealth/internalRevocations failed: %s", type(exc).__name__)
        response = boom(500, "An internal server error occurred")
    status = response.status_code
    _audit_revoke(
        "ok" if status == 204 else str(status),
        attempt.actor,
        attempt.participant_id,
        attempt.record_ids,
    )
    return response


async def _revoke_internal(request: Request, token: str | None, attempt: _Attempt) -> Response:
    checked = await _bridge_request(request, token, attempt, typ=REVOKE_BRIDGE_TYP)
    if isinstance(checked, Response):
        return checked
    deps, claims = checked
    return await run_in_threadpool(
        _revoke_result, deps, claims.participant_id, claims.actor, attempt
    )


def _revoke_result(
    deps: GoogleHealthDeps, participant_id: str, actor: str, attempt: _Attempt
) -> Response:
    records = deps.store.active_google_records(participant_id)
    attempt.record_ids = tuple(record["id"] for record in records)
    if not records:
        return boom(409, "No Google Health account is linked for this participant.")
    locks = deps.tokens.acquire_locks(participant_id, records[0]["healthUserId"])
    if locks is None:
        return boom(423, "Another change for this participant is in progress.")
    try:
        for record in records:
            deps.google.revoke(record["refreshToken"] or record["accessToken"])
        with pymongo.timeout(deps.settings.store_write_budget_seconds):
            deps.store.end_revoked(
                participant_id, list(attempt.record_ids), actor, int(deps.clock())
            )
    finally:
        deps.tokens.release_locks(locks)
    # Lowercase key, so it replaces HAPI_HEADERS' no-cache rather than adding a second header.
    return Response(status_code=204, headers={**HAPI_HEADERS, "cache-control": "no-store"})
