# Design: Google Health authorization and notifications

## Overview

`ow_api` serves four routes under `/api/googleHealth`, all outside `/v1`:

| Method and path | Caller | Credential |
|---|---|---|
| `POST /api/googleHealth/links` | staff | admin bearer: `require_write_principal`, then `"admin"` in roles |
| `GET /api/googleHealth/authorize?t=<link>` | participant's browser | the link token; `x-allow-unauthenticated` marker |
| `GET /api/googleHealth/finishAuth` | participant's browser, redirected by Google | the OAuth `state` and the `gh_oauth` cookie; marker |
| `POST /api/googleHealth/notifications` | Google | the `Authorization` secret and `GOOGLE-HEALTH-API-SIGNATURE`; marker |

Google records live in the existing Mongo `fitbits` collection beside legacy Fitbit records, told apart by `provider: "googleHealth"`. Frame, the scheduler and OpenWellness all read that collection, so they share one contract, kept in the consuming project's `docs/google-health.md` ("Reference: the contract"): the record fields, three filters, the active-record selection rule and six invariants (I1 to I6). This design cites those names.

Alternatives rejected:

- **Port frame's `/fitbits/authorize` flow.** Frame's `state` is the bare participant id, so anyone who knows an id can complete a consent for that participant.
- **Enqueue the code exchange.** The authorization code expires in minutes and the participant is waiting on the page. finishAuth does its credential work inline; see "finishAuth order".
- **A new collection for Google records.** Every reader of `fitbits` would need a second query path, and the same participant would have two sources of truth during migration.

## Affected components

| Layer | Module(s) | Change |
|---|---|---|
| domain | `backend/core/.../domain/models/fitbit.py` | provider constants, D-13 fields, the three filters, `select_active` |
| adapters | `backend/core/.../adapters/mongo/model/mongo_fitbit.py`, `.../repositories/mongo_fitbit_repository.py` | camelCase D-13 fields; `get_by_participant_id` applies `ACTIVE` and `select_active`; `_to_doc` drops None-valued D-13 keys |
| infrastructure | `backend/api/.../google_health/` | new package: the four routes, settings, tokens, Google client, store, signature verifier, selfcheck |
| infrastructure | `backend/api/.../event_handlers/ports.py`, `celery_producer.py` | `publish(..., queue="celery")` and `SCHEDULER_NEW_QUEUE` |
| infrastructure | `backend/api/.../main.py` | mounts the router; lifespan builds the deps; access-log query filter |
| infrastructure | `backend/api/pyproject.toml`, `backend/uv.lock` | `tink>=1.16,<2` (locked 1.16.1) |

### Package layout

```
backend/api/src/openwellness_api/google_health/
  __init__.py        router assembly (staff, browser, notifications); build_google_health_deps
  settings.py        GoogleHealthSettings (GOOGLE_HEALTH_*), required keys, problems()
  tokens.py          link and state JWTs, Redis nonce, link claim, migration locks
  oauth.py           links, authorize, finishAuth; pages; completeMigration publish
  google_client.py   GoogleOAuthClient port; requests client (exchange, identity, revoke; 10 s timeouts)
  store.py           fitbits writes and ownership reads
  notifications.py   the webhook receiver
  signature.py       SignatureVerifier port; TinkSignatureVerifier
  selfcheck.py       python -m entry point, six checks
  data/              selfcheck vector and keyset snapshot (the image excludes tests/)
```

## Link and state tokens

Two HS256 JWTs with separate secrets. Neither secret may equal `API_AUTH_JWT_SECRET`, and the `aud` values stop one token being accepted as the other.

| Token | Secret | Claims | Lifetime |
|---|---|---|---|
| Link (`t`) | `GOOGLE_HEALTH_LINK_SECRET` | `aud=googleHealth:link`, `sub=<participantId>`, `jti` | 72 h |
| OAuth `state` | `GOOGLE_HEALTH_STATE_SECRET` | `aud=googleHealth:state`, `sub`, `jti`, `bh`, `lnk` (link `jti`), `lx` (link `exp`) | 15 min |

Both carry `iss=openwellness-api`, and verification requires `exp`, `iat`, `jti`, `sub`, `aud` and `iss`.

`lnk` and `lx` let finishAuth claim the link without the link token itself.

### Browser binding and Redis keys

`authorize` sets `gh_oauth`: 32 random bytes, `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/api/googleHealth`, `Max-Age=900`. The state's `bh` claim is the SHA-256 (base64url) of that value. finishAuth checks the cookie against `bh` **before** it consumes the nonce, so a state replayed from another browser cannot burn the real one.

| Key | Set | Purpose |
|---|---|---|
| `gh:state:<jti>` | `SET NX EX 900` at authorize | single-use state; finishAuth consumes it with `DEL` |
| `gh:link:claim:<jti>` | `SET NX PX min(remaining link lifetime, 60000)` with an owner token; committed (owner-checked) to `max(remaining link lifetime, 60000)` just before the insert | the only consumed-link marker (I3) |
| `gh:lock:pid:<participantId>` | `SET NX PX 60000` | serializes migration per participant (I3) |
| `gh:lock:hu:<first 32 hex of sha256(healthUserId)>` | `SET NX PX 60000` | serializes migration per Google account (I3) |

`ow_api` runs two uvicorn workers, so none of this state lives in process memory. The link claim and the locks carry a random owner token and are renewed, committed and released by compare-and-set or compare-and-delete under `WATCH`, so a request never touches a key another request re-took after expiry. A pending claim lives one lock lease, so a claim whose release failed before the commit frees the link within 60 s.

The lifetimes, scopes and Google endpoints are constants, not settings: no `GOOGLE_HEALTH_*` value can change the link (72 h), state (15 min) or lock (60 s) lifetime, the four scopes, or the OAuth and identity URLs. The OAuth client and the keyset fetch never follow a redirect.

## finishAuth order

finishAuth is the one route that does credential work inline (the consuming project's decision D-17). Everything after the credential work is enqueued: legacy revoke and unsubscribe, and the first sync, run in the scheduler's `completeMigration`. The notification receiver stays enqueue-only.

1. `error` present (consent declined): refuse; nothing claimed, Google not called.
2. Verify the state and the cookie, then consume the nonce.
3. Read the participant (active, not held).
4. Claim the link (`gh:link:claim`, pending). An expired link cannot be claimed. A second state minted from the same link can never exchange a code.
5. Exchange the code.
6. Validate the grant: all four scopes and a refresh token, else refuse and release the claim.
7. Look up the identity (`healthUserId`, `legacyUserId`).
8. Take the participant lock, then the account lock; busy answers 409.
9. Recheck ownership under the account lock: another participant's GOOGLE_ACTIVE record on the same `healthUserId` refuses (I2).
10. Carry the earliest `migratedAt` of the participant's Google records forward, else now.
11. Renew both lock leases (owner-checked); a lease lost during the reads answers 409 and writes nothing.
12. Commit the link claim (owner-checked); a claim lost to another request writes nothing.
13. Under one `pymongo.timeout` deadline of half a lease (30 s): insert the record with `migrationStatus: "pending"`, then supersede the participant's other ACTIVE records (`supersededAt`, `supersededBy`) in one `update_many` that repeats the ACTIVE filter (I1).
14. Check both leases are still held; if not, log an ERROR (see below). Release the locks.
15. Publish `googleHealth.completeMigration [participantId, googleRecordId, supersededRecordIds]` onto `scheduler_new`.

Any failure before step 13 releases the link claim and writes nothing, so the participant can reuse the link. An insert the server refuses (`WriteError`) also releases it; if that release fails, the committed claim blocks this link and an ERROR says to mint a new one. Any other insert failure (timeout, dropped connection) may follow a committed write, so the link stays consumed. Once the record exists the link stays consumed. A supersede failure publishes an empty `supersededRecordIds`, and a publish failure is logged and swallowed: the record stays `pending`.

The locks are leases, not fences: a worker paused longer than a lease between step 11 and the write can still write after another request took the locks. Mongo has no uniqueness constraint for I1 or I2 in this phase, because the insert-then-supersede order briefly holds two ACTIVE records by design. The resulting dual-active state is never used (the selection rule picks none of two Google records), is counted by status and repaired by reconcile (I6), and step 14 logs it as it happens.

### `migrationStatus` and reconcile

The scheduler's `completeMigration` is idempotent, re-supersedes any ACTIVE record the insert left behind, revokes superseded grants under the revocation rule, and sets `migrationStatus: "complete"`. Its daily backfill reconciles: it re-publishes `completeMigration` for every `pending` record older than 10 minutes and for every participant with more than one ACTIVE record (I5, I6). A lost publish therefore delays legacy revocation by at most a day instead of losing it. Both halves live in the consuming project's scheduler, not here.

### Supersede and revocation rule

- A superseded legacy grant is revoked, best effort, by the scheduler.
- A superseded Google record is revoked only when its `healthUserId` differs from the new record's. See "Deferred".
- A partial grant rejected at step 6 is revoked in finishAuth only when the identity lookup succeeds and no GOOGLE_ACTIVE record holds the same `healthUserId`: a re-consent that unticked a scope shares the live connection's grant.

### Migration hold

`GOOGLE_HEALTH_MIGRATION_HOLD` is empty, `*`, or a comma-separated list of 24-hex study ids. For a held study, `links` answers 409 and `authorize` and finishAuth refuse. A malformed value holds every study and disables the routes until fixed.

## Notification receiver

The receiver follows the enqueue-and-return rule of spec 007: no Mongo read, no write. Order:

1. `hmac.compare_digest` on `Authorization` against `GOOGLE_HEALTH_WEBHOOK_SECRET`, else 401. An oversized request without the secret is 401 and not read.
2. Bounded raw read, 64 KiB, else 413. The secret check runs first, so a 413 proves the sender held the secret.
3. `{"type": "verification"}` answers 200 with an empty body (Google's subscriber handshake accepts 200 or 201 and reads no body; the secret is never echoed).
4. The signature over the exact raw bytes, in the threadpool: invalid is 401, unavailable key is 503.
5. Parse: one object or an array of 1..100 items, else 400. An item that fails validation is dropped with a WARNING count; redelivery cannot fix it, so a signed body whose every item is invalid still answers 204.
6. Group by (healthUserId, dataType, operation), union the dates, publish one `googleHealth.handleNotification [healthUserId, dataType, operation, dates]` per group onto `scheduler_new`, in the threadpool. Any publish failure answers 503 so Google redelivers the whole request; groups already published are coalesced downstream by the scheduler's `QueueOnce` on `syncDate`.
7. 204.

### Batched and interval contract

Source: <https://developers.google.com/health/webhooks>, fetched 2026-09-30 (page "Last updated 2026-09-24 UTC"). The page allows up to 99 items per batch; the receiver accepts 100.

- Dates per interval, first form present wins: `civilDateTimeInterval`, else `civilIso8601TimeInterval` (the only civil form in Google's DELETE examples), else `physicalTimeInterval` as UTC dates widened by one day on each side (the participant's zone is unknown here).
- An interval end of exactly 00:00 excludes that day.
- A present but malformed `civilDateTimeInterval` drops the item, with no fallback to the other forms.
- An item spanning more than 31 dates is dropped, not truncated.
- `recordId` is accepted and never logged or published.

### Signature verification and the 401-versus-503 rule

Google signs the raw body with Tink `PublicKeySign` (ECDSA P-256, SHA-256) and publishes a public keyset at a gstatic URL, rotated every 30 days. The receiver depends only on the `SignatureVerifier` port, which has two failure outcomes the route must keep apart:

| Outcome | Answer | Why |
|---|---|---|
| `verify` returns `False` | 401 | a bad signature; Google does not redeliver |
| `verify` raises `SignatureVerificationUnavailable` | 503 | the key needed to judge it is missing right now; Google redelivers, so a genuine notification signed under a newly rotated key is not lost |

`TinkSignatureVerifier` reads the key id from the Tink prefix (`0x01`, then a 4-byte big-endian key id) and keeps the parsed keyset in process:

- A known key id that fails verification is `False`, with no refetch.
- An unknown key id refetches the keyset, at most once per 60 seconds (a failed attempt counts). One lock serializes fetches, so a flood of unknown ids causes one fetch.
- If a keyset fetched during the same call still lacks the key id, the answer is `False`.
- An unknown key id when the floor forbids a refetch, a failed fetch (5 s timeout), or an unparseable keyset raises `SignatureVerificationUnavailable`.
- Construction fetches nothing; the first `verify` does, in the threadpool.

`GOOGLE_HEALTH_KEYSET_URL` defaults to Google's URL and must be https, so a misconfigured key source disables the routes instead of fetching keys over plain HTTP.

## Settings validation

`GoogleHealthSettings` reads `GOOGLE_HEALTH_*`. Required: `CLIENT_ID`, `CLIENT_SECRET`, `LINK_SECRET`, `STATE_SECRET`, `WEBHOOK_SECRET`, `PUBLIC_BASE_URL`. Optional: `MIGRATION_HOLD`, `KEYSET_URL`. Once any required key is set, `problems()` checks these rules:

| Rule | Violated when |
|---|---|
| `<secret>_short` | a link, state or webhook secret is under 32 characters |
| `secrets_not_distinct` | two of the three secrets are equal |
| `secret_reuses_api_jwt` | a secret equals `API_AUTH_JWT_SECRET` |
| `public_base_url_not_https_origin` | the base URL is not an https origin with no path, query or userinfo |
| `client_id_format` | the client id does not end in `.apps.googleusercontent.com` |
| `migration_hold_malformed` | the hold is not empty, `*` or a list of 24-hex ids |
| `keyset_url_not_https` | the keyset URL is not https |

An unset key or a violated rule makes all four routes answer 503 and logs one WARNING, `googleHealth routes disabled until fixed: unset <names>; invalid <rules>`. The rest of `ow_api` boots and serves; it never refuses to start on these keys. Secrets are `repr=False`, so a settings object in a traceback prints none.

## Selfcheck

`python -m openwellness_api.google_health.selfcheck` builds the real objects from the environment, as the lifespan does, and prints one line per check: `PASS <name>` or `FAIL <name>: <setting, rule or exception class names>`, never a value. It exits 0 only when all six pass.

| Check | Proves |
|---|---|
| `settings` | every required key set and every rule satisfied |
| `signature_vector` | the real Tink verifier accepts the bundled openssl-signed vector and rejects it over a tampered body |
| `keyset_snapshot` | the bundled snapshot of Google's keyset parses into P-256 keys |
| `token_roundtrip` | a link and a state mint and verify against the real Redis client |
| `redis_ping` | Redis answers |
| `publisher_config` | `CELERY_BROKER_URL` is set and the producer app builds; nothing is published |

It uses no network for the keyset. The bundled files live under `google_health/data/` because the Docker build context excludes `tests/`; a test pins them to the fixtures.

## Producer queue

`TaskPublisher.publish(task_name, args, queue="celery")` gains a `queue` parameter. The default keeps every spec 007 handler on `celery`, the queue frame's `router` consumes. Google Health tasks name `SCHEDULER_NEW_QUEUE = "scheduler_new"` directly, which must equal the scheduler's `SCHEDULER_NEW`: a typo publishes successfully to a queue no worker reads.

## Core schema mirror

`openwellness_core.domain.models.fitbit` holds the contract once for OpenWellness:

- `PROVIDER_FITBIT`, `PROVIDER_GOOGLE_HEALTH`, `D13_ALIASES`.
- `active_filter()`, `legacy_active_filter()`, `google_active_filter()`: fresh deep copies of `{"supersededAt": null}`, `{"provider": {"$ne": "googleHealth"}, "supersededAt": null}` and `{"provider": "googleHealth", "supersededAt": null}`. The filters match `null` instead of using `$exists: false` because the scheduler's `save` writes explicit nulls; `$ne` keeps records with no `provider` visible to legacy readers.
- `select_active`: among ACTIVE records, the single Google record wins; else the single record; else none. It takes entities (snake_case attributes) or raw documents (camelCase keys).

`Fitbit` and `MongoFitbit` carry the eleven D-13 fields, each defaulting to None. `get_by_participant_id` queries ACTIVE and applies `select_active`; `get_by_id` and `list_all` stay unfiltered audit reads. The repository's `_to_doc` drops None-valued D-13 keys, so saving a legacy record keeps its stored key set. The REST wire schema `schemas/fitbit.py` does not change.

## Log hygiene

Logs are kept six years under HIPAA retention, so no line carries a token, code, state, link, cookie, secret, signature, participant id, `healthUserId` or `recordId`.

- Route lines have the fixed shape `googleHealth/<route> <outcome>[: <ExceptionClassName>]`, with counts for notifications.
- Token errors carry fixed messages, never the underlying library's.
- `GoogleHealthAccessLogFilter` strips the query string from uvicorn access records under `/api/googleHealth` (case-insensitive), because `authorize?t=` and `finishAuth?code=&state=` carry credentials.
- Pages are fixed HTML that echo no request data and send `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY`.
- Tokens, codes and notification bodies are never task arguments.

## Error handling

| Route | Refusal | Infrastructure failure | Busy | Disabled |
|---|---|---|---|---|
| `links` | 400, 403, 404, 409 (hapi Boom JSON); 401 from the write guard | 500 | n/a | 503 |
| `authorize`, `finishAuth` | 400 generic page | 500 generic page | 409 page | 503 page |
| `notifications` | 400, 401, 413 | 503 (verifier or publisher) | n/a | 503 |

The refusal page is the same for every cause, so a caller learns nothing about why a link failed.

## Deferred

These are known and accepted, and not fixed here.

1. **Tokens stored in plaintext.** `accessToken` and `refreshToken` sit in `fitbits` unencrypted, as legacy Fitbit tokens do. Google's CASA security assessment, if required for this client, may demand encryption at rest; that change touches every reader of `fitbits` (frame, the scheduler and OpenWellness) and needs its own specification.
2. **Google revocation limited to a different Google account.** A superseded Google record is revoked only when its `healthUserId` differs from the superseding record's. A same-account re-consent shares the Google grant for this client, and whether Google's revoke endpoint is grant-wide is unconfirmed (the 2026-09-30 documentation fetch could not settle it). Revoking could disconnect the new record. A superseded same-account record keeps a live grant until Google expires it.

## Data models

No new collections. Google records in `fitbits`:

| Field | Type | Meaning |
|---|---|---|
| `participantId` | str | hex `_id` of the `participants` document |
| `provider` | str | `"googleHealth"`; absent means legacy |
| `accessToken`, `refreshToken` | str | Google tokens |
| `expiresAt` | int | access-token expiry, unix seconds |
| `scope` | str | space-delimited, as granted |
| `healthUserId` | str | Google Health user id; notifications arrive under it |
| `legacyUserId` | str or null | legacy Fitbit user id from the identity lookup |
| `timeCreated`, `migratedAt` | int | unix seconds; `migratedAt` is the participant's first Google authorization |
| `migrationStatus` | str | `"pending"` on insert, `"complete"` after `completeMigration` |
| `reconsentRequiredAt`, `lastSyncAt` | int or null | written by the scheduler |

Google records never carry `ownerId` or `subscriptionId`: frame's legacy `finishAuth` matches on `ownerId` and would overwrite one. Superseded records gain `supersededAt` (int) and `supersededBy` (hex id) and are kept for audit.

## Test strategy

`backend/api/tests/google_health_harness.py` builds a local app with mongomock, fakeredis, a fake Google client and a recording publisher; each test asserts Mongo documents, Redis keys and publisher calls. Google is never called. Signature tests use vectors signed by `openssl` and framed by stdlib Python (`tests/fixtures/google_health_signature/gen_vectors.sh`), never by Tink, so the verifier is checked against an independent signer. Notification fixtures are copied from Google's webhooks page. `backend/core/tests/test_mongo_fitbit_provider_real_mongo.py` repeats the visibility tests against a real `mongo:4.0.6` when `GH_REAL_MONGO_URL` is set, skips when it is unset, and fails when it is set but unreachable. `test_write_routes_require_auth.py` walks every write route: `EXPECTED_EXEMPTIONS` gains `/api/googleHealth/notifications`, and `links` must keep the write guard. `authorize` and `finishAuth` are GETs, outside the walk, and carry the marker as the contract requires.
