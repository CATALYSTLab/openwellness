# Requirements: Google Health link bridge

Status: approved
Created: 2026-10-26

## Summary

Coaches work in the consuming project's dashboard (coachapp), which signs in to frame (the legacy hapi `api` service), not to `ow_api`. A coach therefore holds no `ow_api` bearer and cannot call `POST /api/googleHealth/links` (spec 008, Story 1) to mint a participant's Google Health consent link. Today only an operator can mint one, from inside the container. This specification adds one internal route, `POST /internal/googleHealth/links`, that frame calls over the Compose network after it has authorized the coach. frame proves the call with a short-lived JWT (JSON Web Token) signed with a secret only frame and `ow_api` hold. `ow_api` mints through the same code as the public route and writes one audit line per attempt. The public route and the operator path do not change. Traceability: opserver GHB-02 (the internal route), the `ow_api` half of GHB-03 (the bridge secret and its disable rules) and the `ow_api` half of GHB-05 (the audit line). GHB is the consuming project's Google Health Bridge requirement group.

## User stories

### Story 1: frame mints a link for an authorized coach

As frame, having checked a coach's session, admin scope and study access, I want to mint a participant's consent link without holding an `ow_api` user token or `ow_api`'s signing key, so that a coach can send the link from the dashboard.

**Acceptance criteria**

- WHEN a request to `POST /internal/googleHealth/links` carries `Authorization: Bearer <bridge JWT>` and `{"participantId": "<24 lowercase hex>"}`, and the JWT is HS256 over `GOOGLE_HEALTH_BRIDGE_SECRET` with `iss=frame`, `aud=ow-bridge`, `typ=gh-link-bridge`, a 24-hex `sub` (the coach's `users._id`), a 24-hex `pid` equal to the body `participantId`, `exp`, `iat` and `jti`, THE system SHALL answer 200 `{"url", "expiresAt"}` with `Cache-Control: no-store`, minted by the same code as `POST /api/googleHealth/links`.
- WHEN the participant is unknown or inactive THE system SHALL answer 404 Boom JSON `Participant not found.`; WHEN the participant's study is on the migration hold THE system SHALL answer 409; WHEN minting fails THE system SHALL answer 500.
- WHEN the body is not JSON, not an object, lacks `participantId`, or the id is not 24 lowercase hex THE system SHALL answer 400 Boom JSON `Invalid request payload input`.
- The route SHALL live outside `/api/`, so the consuming project's edge proxy never routes it.

### Story 2: Only a bridge JWT mints

As an operator, I want every other credential refused, so that a leaked user token, link token or webhook secret cannot mint through this route.

**Acceptance criteria**

- WHEN the `Authorization` header is missing, not a `Bearer` scheme, or empty THE system SHALL answer 401 Boom JSON `Invalid bridge credential`.
- WHEN the token is signed with another secret, is an `ow_api` access token, is a Google Health link token, is expired beyond 5 s of leeway, lacks `typ` or `jti`, has the wrong `typ`, `aud` or `iss`, lives longer than 120 s (`exp - iat`), has a non-hex `sub` or `pid`, names a `pid` other than the body's, or uses any algorithm other than HS256 THE system SHALL answer the same 401.
- The route SHALL NOT accept the `x-allow-unauthenticated` marker or `require_write_principal`; the route-walking test SHALL list it as bridge-guarded.

### Story 3: A weak or reused secret disables only this route

As an operator, I want a misconfigured bridge secret to switch off only the internal route and say why, so that the rest of `ow_api` keeps serving.

**Acceptance criteria**

- WHEN `GOOGLE_HEALTH_BRIDGE_SECRET` is unset, shorter than 32 characters, or equal to `API_AUTH_JWT_SECRET`, `API_AUTH_CODE_PEPPER`, `GOOGLE_HEALTH_LINK_SECRET`, `GOOGLE_HEALTH_STATE_SECRET`, `GOOGLE_HEALTH_WEBHOOK_SECRET` or `GOOGLE_HEALTH_CLIENT_SECRET` THE system SHALL answer 503 Boom JSON `Google Health is not available.` on the internal route only, and log one WARNING at startup naming the broken rules, never a value.
- WHEN the Google Health routes themselves are disabled (spec 008, Story 4) THE system SHALL answer the same 503 on the internal route.
- WHILE the internal route is disabled THE system SHALL keep `POST /api/googleHealth/links` answering exactly as before.

### Story 4: Every attempt is audited without identifying anyone

As a compliance reviewer, I want one log line per mint attempt with record ids only, so that I can tell who minted for whom from the six-year log store without it holding personal data or a usable link.

**Acceptance criteria**

- WHEN a request reaches the internal route THE system SHALL write exactly one line to stdout: `googleHealth/internalLinks outcome=<ok|400|401|404|409|500|503> actor=<24hex|-> participantId=<24hex|-> expiresAt=<int|->`, including when the handler fails unexpectedly.
- `actor` SHALL be `-` unless the bridge JWT verified; `participantId` SHALL be `-` unless the body id is 24 lowercase hex; `expiresAt` SHALL be `-` unless the outcome is `ok`.
- No log line from this route SHALL carry the URL, the link token, the bridge token, a participantNumber, a name or an email.

## Out of scope

- frame's side: the coach-facing `POST /api/participants/{id}/googleHealthLink`, its session, scope and study checks, and its status mapping (api spec 006).
- Provisioning `GOOGLE_HEALTH_BRIDGE_SECRET` in the consuming project's environment files and compose mappings. Until that lands the internal route answers 503 and nothing else changes.
- Edge routing. No edge location names the path; the consuming project's `checkEdgeRoutes` gate proves it.
- A `jti` replay store, per-coach rate limiting, and the pre-existing exposure of `API_AUTH_JWT_SECRET` to other containers. See "Deferred / accepted" in `design.md`.
