# Design: Google Health link bridge

## Overview

frame (the legacy hapi `api` service of the consuming project) authorizes a coach, then calls one new `ow_api` route over the Compose network:

| Method and path | Caller | Credential |
|---|---|---|
| `POST /internal/googleHealth/links` | frame, on the Compose network only | a per-request bridge JWT under `GOOGLE_HEALTH_BRIDGE_SECRET`; dependency `require_bridge_credential` |

frame decides who may mint (session, admin scope, study membership). `ow_api` trusts the actor named in a verified bridge JWT and does no second role check. The route mints through the code that serves `POST /api/googleHealth/links` (spec 008), so both routes produce the same link with the same lifetime and refusals.

Alternatives rejected:

- **Give frame an `ow_api` access token.** frame would hold `API_AUTH_JWT_SECRET`, or a long-lived admin token, either of which mints far more than consent links.
- **A second route under `/api/googleHealth`.** The edge group `/api/googleHealth` is a prefix match that sends to `ow_api`, so the route would be public.
- **A shared static header secret.** A captured header replays forever and names no actor; a JWT expires in 60 s and carries the coach's id and the participant it is bound to.

## Cross-repo contract

The same table is pinned in api spec 006. Both sides must change together.

| Item | Value |
|---|---|
| Route | `POST /internal/googleHealth/links` (never under `/api/`) |
| Request header | `Authorization: Bearer <bridge JWT>` |
| Request body | `{"participantId": "<participants._id, 24 lowercase hex>"}` |
| JWT algorithm | `HS256` |
| JWT secret | host key `GOOGLE_HEALTH_BRIDGE_SECRET`, shared and unprefixed, the same name in both containers |
| `iss` | `frame` |
| `aud` | `ow-bridge` |
| `typ` (a claim, like `ow_api`'s `"typ": "access"`) | `gh-link-bridge` |
| `sub` | the coach's `users._id` (24 hex) |
| `pid` | the target `participants._id` (24 hex); must equal the body `participantId` |
| `iat`, `exp`, `jti` | `exp = iat + 60`; `jti` a random UUID |
| `ow_api` verifies | signature, `aud`, `iss`, required `exp iat iss aud sub jti`, `leeway=5`, `typ == "gh-link-bridge"`, `exp - iat <= 120`, `sub` and `pid` 24-hex, `pid == body.participantId` |
| `ow_api` answers | 200 `{"url", "expiresAt"}` with `Cache-Control: no-store`; 400, 401, 404, 409, 500 and 503 as Boom JSON |

Boom JSON is hapi's error body, `{"statusCode", "error", "message"}`, produced by `event_handlers/hapi.boom`.

## Why the route is outside `/api/`

The consuming project's edge proxy routes only `/api/*` location groups, and only an allowlist of them (`/api/eventHandlers`, `= /api/eventHandlers/actigraph`, `/api/googleHealth`) to `ow_api`. Its catch-all goes to frame, never to `ow_api` (its T-09-16 containment, kept because two read-only POST methods on `ow_api` are unauthenticated). A path under `/internal/` therefore matches no edge location that reaches `ow_api`. frame reaches it directly at `http://${OW_API_HOST}:${OW_API_PORT}` on the Compose network. The consuming project's `checkEdgeRoutes` gate fails if any edge location ever matches the path.

## Affected components

| Layer | Module(s) | Change |
|---|---|---|
| infrastructure | `backend/api/.../google_health/bridge.py` | new: `BridgeSettings`, `BridgeVerifier`, `BridgeTokenError`, `BridgeClaims`, `BridgeDeps`, `build_bridge_deps`, `require_bridge_credential`, `create_link_internal`, `install_google_health_audit_logger`, `INTERNAL_LINKS_PATH`, `AUDIT_LOGGER_NAME` |
| infrastructure | `backend/api/.../google_health/oauth.py` | `_mint_link` split into `_mint_link_result`; `_mint_link` delegates |
| infrastructure | `backend/api/.../google_health/__init__.py` | mounts the internal route on its own `APIRouter` with no router-level dependency; exports `INTERNAL_LINKS_PATH`, `build_bridge_deps` |
| infrastructure | `backend/api/.../event_handlers/hapi.py` | `_REASON` gains `401 "Unauthorized"` and `503 "Service Unavailable"` (Boom's phrases) |
| infrastructure | `backend/api/.../main.py` | the lifespan installs the audit logger and sets `app.state.google_health_bridge` |

No domain, application or adapter code changes. No package is added; PyJWT and pydantic-settings are already locked.

## The verifier

`BridgeVerifier(secret).verify(token, participant_id=...)` mirrors `JwtTokenService.verify_access` under its own secret and audience:

1. A missing token fails.
2. `jwt.decode` with `algorithms=["HS256"]`, `audience="ow-bridge"`, `issuer="frame"`, `leeway=5` and `options={"require": ["exp", "iat", "iss", "aud", "sub", "jti"]}`. An `alg` of `none`, `HS512` or anything else fails here.
3. `typ == "gh-link-bridge"`; `exp` and `iat` are integers (not booleans) with `0 < exp - iat <= 120`.
4. `sub` and `pid` fully match `[0-9a-f]{24}` (`re.fullmatch`, so a trailing newline fails) and `pid == participant_id`.

Every failure raises `BridgeTokenError` with a fixed message; the library's message is never surfaced or logged. The distinct secret, `aud`, `iss` and `typ` mean an `ow_api` access token (`aud=openwellness-api`, `typ=access`, signed with `API_AUTH_JWT_SECRET`) and a Google Health link token (`aud=googleHealth:link`, signed with the link secret) are both refused.

`require_bridge_credential(request)` returns the token after a case-insensitive `Bearer ` scheme, or `None`. It never raises, so the handler can audit every outcome; it is also the marker the route-walking test uses to classify the route as bridge-guarded.

## Disable rules

`BridgeSettings` reads `GOOGLE_HEALTH_BRIDGE_SECRET` (`env_prefix="GOOGLE_HEALTH_BRIDGE_"`, field `secret`, `repr=False`). `BridgeSettings.problems(...)` returns rule names only:

| Rule | Fires when |
|---|---|
| `bridge_secret_unset` | the secret is empty (no other rule is checked) |
| `bridge_secret_short` | fewer than 32 characters, the floor of every other `ow_api` secret |
| `bridge_secret_reuses_api_auth_secret` | equal to `API_AUTH_JWT_SECRET` or `API_AUTH_CODE_PEPPER` |
| `bridge_secret_reuses_google_health_secret` | equal to a non-empty `GOOGLE_HEALTH_LINK_SECRET`, `GOOGLE_HEALTH_STATE_SECRET`, `GOOGLE_HEALTH_WEBHOOK_SECRET` or `GOOGLE_HEALTH_CLIENT_SECRET` |

Equality uses `hmac.compare_digest`. `build_bridge_deps` logs one WARNING, `googleHealth internal links disabled until fixed: <comma-joined rules>`, and returns `BridgeDeps(verifier=None, disabled=rules)`. The handler answers 503 while `disabled` is non-empty, while the Google Health deps are missing or disabled, or while `app.state.google_health_bridge` is unset. This mirrors `build_google_health_deps`. The public route reads only the Google Health deps, so it is unaffected.

## The `_mint_link_result` split

The audit line needs the link's `expiresAt` without parsing the URL. `_mint_link_result(deps, participant_id)` returns `(response, exp)` on success and `(response, None)` on every refusal; `_mint_link` returns `_mint_link_result(...)[0]`. The public `create_link` still calls `_mint_link`, so its responses, its log lines and every test in `test_google_health_oauth.py` are unchanged (that file is not edited).

## Handler order

`create_link_internal` checks, in order, and answers Boom JSON:

| Step | Failure | Answer |
|---|---|---|
| Google Health deps present and enabled; bridge deps present, enabled, with a verifier | any is not | 503 `Google Health is not available.` |
| Body is a JSON object whose `participantId` is 24 lowercase hex | not | 400 `Invalid request payload input` |
| `BridgeVerifier.verify(token, participant_id=...)` | `BridgeTokenError` | 401 `Invalid bridge credential` |
| `_mint_link_result(deps, pid)` in the threadpool | unknown or inactive / held / mint failure | 404 `Participant not found.` / 409 / 500 |
| (success) | — | 200 `{"url", "expiresAt"}`, `Cache-Control: no-store` |
| any unexpected exception | — | 500 `An internal server error occurred` |

The checks are inline rather than router dependencies because a dependency that raises cannot write the audit line, and `require_google_health_enabled` raises an AIP-193 envelope (Google's API error format) instead of Boom JSON.

## The audit line

```
googleHealth/internalLinks outcome=<ok|400|401|404|409|500|503> actor=<24hex|-> participantId=<24hex|-> expiresAt=<int|->
```

- One line on every exit, including an unexpected exception.
- `actor` is set only from a verified JWT. `participantId` is set only after the body id matched the regex, so a crafted id cannot inject log content. `expiresAt` is set only for `ok`.
- Fixed keys in logfmt, so a LogQL `| logfmt` stage parses it.
- Logger `openwellness_api.audit.google_health`. uvicorn configures only its own loggers and the root logger stays at WARNING, so an `openwellness_api.*` INFO line would never reach stdout. `install_google_health_audit_logger()` gives this logger its own `StreamHandler(sys.stdout)` with formatter `%(message)s`, level INFO and `propagate=False`, marked so a second call adds nothing. The lifespan calls it; stdout reaches the consuming project's Promtail and Loki under six-year retention.
- The handler never logs the request body, the response body, the URL or a token. The startup WARNING names rules, never a value.

## Status table

| Outcome | Status | Body | Audit `outcome` | `actor` |
|---|---|---|---|---|
| minted | 200 | `{"url", "expiresAt"}` | `ok` | `sub` |
| bad body | 400 | Boom | `400` | `-` |
| bad credential | 401 | Boom | `401` | `-` |
| unknown or inactive participant | 404 | Boom | `404` | `sub` |
| study on hold | 409 | Boom | `409` | `sub` |
| mint or handler failure | 500 | Boom | `500` | `sub` once verified, else `-` |
| route disabled | 503 | Boom | `503` | `-` |

## Error handling

- Misconfiguration never stops `ow_api`: a bad bridge secret disables one route and logs one WARNING at startup.
- Token failures are 401 with a fixed message. frame treats a 401 from this route as a bridge fault (a 502 to the coach), never as the coach's sign-in failing.
- Mongo and Redis failures inside minting become 500 through `_mint_link_result`, as on the public route.

## Test strategy

All under `backend/api/tests`, with the spec 008 fakes (`google_health_harness.Harness`: mongomock, fakeredis, a fake Google client):

- `test_google_health_bridge.py`: the tracer mint and the missing-credential 401; 15 refusal cases; eight disable rules, each with the public route still answering 200; Google Health disabled; the name-only WARNING; six bad bodies; 404, 409 and 500 audited with the actor; one audit line per request; no record on root or the audit logger carrying the URL, `?t=`, the link token or the bridge token; the logger installer's idempotence; the path outside `/api/`.
- `test_write_routes_require_auth.py`: `EXPECTED_BRIDGE_GUARDED == {"/internal/googleHealth/links"}`, and that route carries neither the unauthenticated marker nor `require_write_principal`.
- pytest's `caplog` hangs off the root logger and cannot see a `propagate=False` logger, so the audit tests attach their own handler to `openwellness_api.audit.google_health`.

## Deferred / accepted

- **No `jti` replay store.** A bridge JWT captured on the Compose network can be replayed until it expires (60 s, at most 120 s by the lifetime check) and only for the participant it names. The token never leaves the Compose network, and a store would add a Redis failure mode to an otherwise Redis-light mint. Accepted.
- **The `ow_api` signing secret reaches other containers.** In the consuming project every `env_file: .env` service receives the root `.env`, which includes `OW_API_AUTH_JWT_SECRET` (`ow_api`'s `API_AUTH_JWT_SECRET`) and will include `GOOGLE_HEALTH_BRIDGE_SECRET`. That exposure predates this spec; the bridge's isolation is in code (only frame and `ow_api` read the key). Out of scope.
- **Per-coach rate limiting** of mints is not in scope.
