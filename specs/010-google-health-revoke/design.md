# Design: Google Health revoke

## Overview

frame authorizes a coach, then calls one new `ow_api` route over the Compose network:

| Method and path | Caller | Credential |
|---|---|---|
| `POST /internal/googleHealth/revocations` | frame, on the Compose network only | a per-request bridge JWT under `GOOGLE_HEALTH_BRIDGE_SECRET` with `typ` `gh-revoke-bridge`; dependency `require_bridge_credential` |

frame decides who may revoke: the same rule as minting, narrowed to the study check (D-11, D-13). `ow_api` trusts the actor named in a verified bridge JWT and does no second role check, as for the mint (spec 009). The route asks Google to revoke each active grant first and writes only when every grant is dead. It ends the records and keeps them.

Alternatives rejected:

- **Delete the `fitbits` record.** The record is the audit trail of a grant, and retention keeps superseded legacy records the same way (D-01).
- **End the record, then call Google.** A Google failure would leave the dashboard saying "revoked" while the grant still syncs (D-05).
- **A second bridge secret.** A separate `typ` on the same secret already keeps each token to one route, and nothing new is provisioned (D-12).
- **`healthUserId` in the audit line.** One revoke can end more than one record (D-14), and the operator joins the line to Mongo by record id, so the line names record ids only.

## Cross-repo contract

Pinned verbatim from opserver plan 17.3-01; api spec 008 pins the same contract. Both sides must change together.

- ow route `POST /internal/googleHealth/revocations`; header `Authorization: Bearer <bridge JWT>`; body `{"participantId": "<24 lowercase hex>"}`.
- JWT: HS256 over `GOOGLE_HEALTH_BRIDGE_SECRET`; `iss=frame`, `aud=ow-bridge`, `typ=gh-revoke-bridge`, `sub` = coach `users._id`, `pid` = `participants._id`, `iat`, `exp=iat+60`, `jti`. ow verifies exactly as for mint, except `typ == "gh-revoke-bridge"`. The mint route keeps accepting only `gh-link-bridge` (D-12).
- ow answers: 204 empty body with `cache-control: no-store`; Boom JSON 400 `Invalid request payload input`, 401 `Invalid bridge credential`, 409 `No Google Health account is linked for this participant.`, 423 `Another change for this participant is in progress.`, 500 `An internal server error occurred`, 502 `Google did not confirm the revocation.`, 503 `Google Health is not available.`, 504 `Google did not answer in time.`.
- ow audit line: `googleHealth/internalRevocations outcome=<ok|400|401|409|423|500|502|503|504> actor=<24hex|-> participantId=<24hex|-> recordIds=<24hex[,24hex...]|->`; 17.3-02 appends ` owner=<24hex>` only on the shared-account 500.
- Record end: `$set {supersededAt: now, supersededBy: null, revokedAt: now, revokedBy: sub}` on each GOOGLE_ACTIVE record of the participant.
- frame (17.3-04): `POST /api/participants/{id}/googleHealthRevoke`, client `revokeGoogleHealth`, `REVOKE_PATH`, `REVOKE_TYP`, `REVOKE_TIMEOUT_MS = 20000`.

The route is outside `/api/` for the reasons in spec 009, "Why the route is outside `/api/`".

## Affected components

| Layer | Module(s) | Change |
|---|---|---|
| domain | `backend/core/.../domain/models/fitbit.py` | `D13_ALIASES` gains `"revokedAt", "revokedBy"` (fifteen names); `Fitbit.revoked_at`, `Fitbit.revoked_by`, default None |
| adapters | `backend/core/.../adapters/mongo/model/mongo_fitbit.py` | `MongoFitbit.revoked_at` (alias `revokedAt`), `revoked_by` (alias `revokedBy`), default None |
| infrastructure | `backend/api/.../google_health/revoke.py` | new: `revoke_internal`, the audit line, `_RevokeAttempt` (carries `owner`) |
| infrastructure | `backend/api/.../google_health/bridge.py` | `REVOKE_PATH`, `REVOKE_BRIDGE_TYP`; `_bridge_request(..., typ=...)` holds the checks both internal routes share; the verifier takes the expected `typ` |
| infrastructure | `backend/api/.../google_health/store.py` | `active_google_records`, `end_revoked` |
| infrastructure | `backend/api/.../google_health/tokens.py` | `acquire_locks(participant_id, health_user_id, *more_health_user_ids)` |
| infrastructure | `backend/api/.../google_health/google_client.py` | `revoke` classifies Google's answer (`_DEAD_TOKEN_CODES`) |
| infrastructure | `backend/api/.../google_health/oauth.py` | finishAuth's connected-elsewhere refusal logs the owner on the audit logger |
| infrastructure | `backend/api/.../google_health/__init__.py` | mounts the revoke route beside the internal links route |
| infrastructure | `backend/api/.../event_handlers/hapi.py` | `_REASON` gains `423 "Locked"`, `502 "Bad Gateway"`, `504 "Gateway Timeout"` (Boom's phrases) |

No package is added.

## Google's revoke answer (D-05)

`RequestsGoogleOAuthClient.revoke(token)` posts the token to Google's revoke endpoint and reads only the status and Google's `error` key, never `error_description`, which can echo request values. The scheduler uses the same classification.

| Google's answer | `GoogleOAuthError` kind | The grant | Route outcome |
|---|---|---|---|
| 2xx | none (returns) | revoked | continue |
| 400 `invalid_token` or `invalid_grant` | `revoke_token_invalid` | already dead | continue |
| timeout | `revoke_timeout` | unknown | 504, nothing written |
| any other 4xx, 5xx, a non-JSON body or a connection error | `revoke_failed` | unknown | 502, nothing written |

Google documents the revoke as grant-wide: "Revocation removes all OAuth 2.0 scopes previously granted to a project", and revoking an access token also revokes its refresh token (developers.google.com/identity/protocols/oauth2/web-server, fetched 2026-11-17). A live probe with a garbage token returned `400 {"error": "invalid_token"}`. A corrupted stored token also answers `invalid_token`, so its record ends; such a record could never sync anyway.

The route sends the refresh token, or the access token when there is no refresh token. A record with neither has no grant to revoke and is ended without a Google call.

## The revoke flow and lock order (D-14)

`_bridge_request` runs the spec 009 checks in the spec 009 order (bearer present, deps enabled, body, JWT with `typ=gh-revoke-bridge`). Then, in the threadpool:

1. Read every GOOGLE_ACTIVE record of the participant. None: 409. A record without a `healthUserId`: 500, because the locks and the I2 check need it (a contract breach for the operator to repair).
2. Take the locks with `SET NX PX` and no waiting: `gh:lock:pid:<P>` first, then one `gh:lock:hu:<hash>` per distinct account, in sorted key order. finishAuth and the migration take the same keys in the same order, so no two of them deadlock. Any key busy, or Redis failing: 423, and every key already taken is given back.
3. Re-read under the locks. No records: 409. A different set of record ids: 423, because finishAuth or the migration moved first.
4. The I2 refusal: for each account, if another participant holds it GOOGLE_ACTIVE, answer 500 with ` owner=<24hex>` on the audit line and call Google for none of them.
5. Call Google for each record. Any live failure (504 or 502) stops the loop and nothing is written, even for grants Google already revoked in this request. The locks are leases of `lock_ttl_ms` (60 s) and several Google calls can outlive them, so each call is preceded by an owner-checked `renew_locks`, as in finishAuth; a lost lease answers 423 and writes nothing.
6. Every grant is dead: renew the leases once more (lost: 423, nothing written), then one `end_revoked` writes all records, with `pymongo.timeout(store_write_budget_seconds)`, half a lease.
7. Release the locks (in `finally`) and answer 204.

All or nothing means a coach's retry meets the same records. A retry after a partial Google success finds the already revoked grants dead (`invalid_token`) and ends them.

## The I2 refusal

I2 allows one GOOGLE_ACTIVE owner per `healthUserId`. A breach is possible only after a past race. Because the revoke is grant-wide, revoking the shared account would also disconnect the other participant, so the route refuses with 500, calls Google for nothing and names the other participant in ` owner=` for the operator. finishAuth's own refusal of a connected-elsewhere account now logs `googleHealth/finishAuth outcome=connected_elsewhere participantId=<24hex> owner=<24hex>` on the same audit logger.

## Why the migration hold and `isActive` do not block (D-07, D-13)

The migration hold (`OW_GOOGLE_HEALTH_MIGRATION_HOLD`) gates new consents, so it gates the mint and finishAuth. A revoke creates no consent. The participant's `isActive` is not read either: a withdrawn participant is a likely reason to revoke, and frame's study check still runs first. The route reads only `fitbits`.

## The record end and the two contract fields (D-01..D-04)

`GoogleHealthStore.end_revoked(participant_id, record_ids, actor, at)` runs one `update_many` on `{participantId, provider: "googleHealth", supersededAt: null, _id: {$in: record_ids}}` with `$set {supersededAt: at, supersededBy: null, revokedAt: at, revokedBy: actor}`. `at` is one unix second for all records. The documents, their tokens and the participant's synced data stay.

`revokedAt` (unix seconds) and `revokedBy` (the coach's `users._id`) join the contract, so ow core's `D13_ALIASES` grows from thirteen to fifteen names, pinned by `CONTRACT_D13` in `backend/core/tests/test_mongo_fitbit_provider.py`. The `Fitbit` entity and `MongoFitbit` carry them with default None, so a record without them loads unchanged, and `MongoFitbitRepository._to_doc` drops them from writes while None, as it does for every D-13 field. The fields are rated costly to remove: ow, frame, the scheduler and the consuming project's `docs/google-health.md` share these names.

Readers need no change: every ACTIVE and GOOGLE_ACTIVE filter keys on `supersededAt`, so a revoked record is invisible to `get_by_participant_id`, `select_active`, finishAuth's I2 check and the scheduler. Re-link works through the normal flow: a fresh link and finishAuth insert a new GOOGLE_ACTIVE record. Its `migratedAt` restarts at "now", because the revoked record no longer counts as the participant's first Google authorization.

## The audit line

```
googleHealth/internalRevocations outcome=<ok|400|401|409|423|500|502|503|504> actor=<24hex|-> participantId=<24hex|-> recordIds=<24hex[,24hex...]|-> [owner=<24hex>]
```

- One line on every exit, including an unexpected exception, on `openwellness_api.audit.google_health` (stdout, as in spec 009).
- `actor` and `participantId` follow spec 009's rules. `recordIds` is set once the GOOGLE_ACTIVE records are read, so a 409 for nothing linked carries `-`, and a 502 names the records that stayed active.
- `owner` appears only on the shared-account 500.
- No token, `healthUserId`, participantNumber, name or email.

## Status table

| Outcome | Status | Audit `outcome` | Records changed |
|---|---|---|---|
| every grant dead, records ended | 204 | `ok` | all |
| bad body | 400 | `400` | none |
| bad credential, including a mint token | 401 | `401` | none |
| nothing linked, before or under the locks | 409 | `409` | none |
| a lock busy, Redis failing, a lease lost before a Google call or the write, or the record set changed under the locks | 423 | `423` | none |
| shared account, missing `healthUserId`, Mongo write failure or handler failure | 500 | `500` | none |
| Google failed other than a timeout | 502 | `502` | none |
| route disabled | 503 | `503` | none |
| Google timed out | 504 | `504` | none |

## The trust model (D-12)

Spec 009 promised that a leaked bridge secret can mint consent links, nothing else. This spec restates it: a leaked bridge secret can mint consent links or revoke Google Health grants, nothing else. Each internal route verifies its own `typ`, so a token minted for one cannot be used on the other, and both stay off the edge.

## Error handling

- A live Google failure changes nothing and answers 502 or 504, so the coach retries.
- A busy lock answers 423; the coach retries.
- Misconfiguration disables the route with 503, as for the mint.
- `GoogleOAuthError` carries a kind only; Google's message is never logged.

## Test strategy

All with the spec 008 harness (`google_health_harness.Harness`: mongomock, fakeredis, a fake Google client):

- `backend/api/tests/test_google_health_revoke.py`: the tracer revoke, the typ in both directions, the path pin, dead and live Google outcomes through the fake and the real client, the refresh-token preference, 409, the hold and inactive participants, the write failure, re-link, every record and every lock (D-14), the busy lock, the shared account, records gone or changed under the locks, the refusal, disable and bad-body matrices, one audit line per outcome, and no token in any log record.
- `backend/api/tests/test_google_health_bridge.py`: `revoke_typ_on_links`, so a revoke token cannot mint.
- `backend/api/tests/test_google_health_oauth.py`: the connected-elsewhere owner line.
- `backend/api/tests/test_write_routes_require_auth.py`: `EXPECTED_BRIDGE_GUARDED` lists both internal routes.
- `backend/core/tests/test_mongo_fitbit_provider.py`: the fifteen-name contract, both round trips by alias, and `test_a_revoked_google_record_is_not_active`.

## Deferred / accepted

- **The scheduler's `save()` could resurrect a revoked record.** Every scheduler write to a Google record is an `update_one` conditional on GOOGLE_ACTIVE, so an in-flight sync cannot resurrect or relabel a revoked record (`mark_reconsent_required` matches 0). The scheduler drops unknown fields on load, so `revokedAt`/`revokedBy` need no scheduler change, and its `D13_FIELDS` stays at thirteen (the fields it reads). Its repository's `save()` would `$set` every field, None included, on `{"_id": ...}` and so clear `supersededAt`, but nothing calls `save()` on the fitbit repository (verified at scheduler `ce76e244`). The same hazard already exists for re-consent supersedes. Accepted and monitored: any future caller must use a GOOGLE_ACTIVE-conditional update.
- **JWT replay within 60 s.** As in spec 009, there is no `jti` store. A replayed revoke of a completed revoke finds nothing linked and gets 409, so a replay adds no harm.
- **frame times out after a completed revoke.** frame gives up after 20 s, and the coach sees a bridge fault while `ow_api` may have finished. The coach's retry then gets the true 409, and the dashboard shows nothing linked on reload.
- **Mongo fails after Google revoked.** The grant is dead but the record is still active, and the route answers 500. The next scheduler refresh sets `reconsentRequiredAt`, and the coach's retry gets Google's 400 `invalid_token`, which counts as dead and ends the record.
- **A consent that finishes during a revoke.** finishAuth swaps the code for tokens before it takes the participant and account locks. So a participant who completes consent while a coach's revoke is running can store tokens the revoke has already killed, and sees the success page. D-04 rules out a new check in finishAuth. The stored tokens sync nothing: the scheduler's first refresh gets `invalid_grant` and sets `reconsentRequiredAt`, the same recovery as above, and the participant links again through a new link.
- **Per-coach rate limiting** of revokes is not in scope.
