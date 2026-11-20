# Requirements: Google Health revoke

Status: approved
Created: 2026-11-17

## Summary

A coach in the consuming project's dashboard (coachapp) can send a participant a Google Health consent link (spec 009) but cannot undo it. Ending a grant today needs an operator in the container, or the participant acting at Google. This specification adds one internal route, `POST /internal/googleHealth/revocations`, that frame (the legacy hapi `api` service) calls over the Compose network after it has authorized the coach, as it does for the mint. `ow_api` asks Google to revoke each of the participant's active grants, then ends the participant's active Google records and keeps them. Synced data stays, and the participant can link again through a fresh link. The route uses the bridge secret of spec 009 with its own JWT `typ`, so a mint token cannot revoke and a revoke token cannot mint. Traceability: opserver GHR-02 (the internal route), GHR-03 (Google first, all or nothing), GHR-04 (the record end), GHR-05 (nothing linked), the `ow_api` half of GHR-06 (the two contract fields) and the `ow_api` half of GHR-08 (the audit line). GHR is the consuming project's Google Health Revoke requirement group; the decisions cited (D-01..D-14) are its Phase 17.3 decisions.

## User stories

### Story 1: frame revokes for an authorized coach

As frame, having checked a coach's session, admin scope and study access, I want to revoke a participant's Google Health grant without holding an `ow_api` user token, so that a coach can stop syncing from the dashboard.

**Acceptance criteria**

- WHEN a request to `POST /internal/googleHealth/revocations` carries `Authorization: Bearer <bridge JWT>` and `{"participantId": "<24 lowercase hex>"}`, and the JWT verifies exactly as for the mint (spec 009, Story 1) except that `typ` is `gh-revoke-bridge`, THE system SHALL answer 204 with an empty body and `cache-control: no-store` once every active grant is revoked and every active record ended. (GHR-02, D-12)
- WHEN the participant has no GOOGLE_ACTIVE record (never linked, already revoked, or legacy only) THE system SHALL answer 409 Boom JSON `No Google Health account is linked for this participant.` (GHR-05, D-06)
- WHILE the participant's study is on the migration hold, or the participant is inactive, THE system SHALL still revoke: the route reads only `fitbits`. (GHR-05, D-07, D-13)
- The route SHALL live outside `/api/`, so the consuming project's edge proxy never routes it, and the route-walking test SHALL list it as bridge-guarded. (GHR-02)

### Story 2: Each bridge route accepts only its own token

As an operator, I want a mint token refused by the revoke route and a revoke token refused by the mint route, so that each token does exactly one thing.

**Acceptance criteria**

- WHEN the revoke route receives a token with `typ` `gh-link-bridge`, or any token the mint route would refuse (spec 009, Story 2), THE system SHALL answer 401 Boom JSON `Invalid bridge credential`. (GHR-02, D-12)
- WHEN `POST /internal/googleHealth/links` receives a token with `typ` `gh-revoke-bridge` THE system SHALL answer the same 401.
- WHEN the bridge secret breaks a disable rule, or Google Health is disabled (spec 009, Story 3), THE system SHALL answer 503 Boom JSON `Google Health is not available.` on the revoke route too.

### Story 3: Google first, all or nothing

As a coach, I want the dashboard to say "revoked" only when Google has stopped the grant, so that I never believe syncing stopped while it did not.

**Acceptance criteria**

- THE system SHALL ask Google to revoke the grant of every GOOGLE_ACTIVE record of the participant before ending any of them, preferring the refresh token. (GHR-03, D-05, D-14)
- WHEN Google answers 200, or 400 with `invalid_token` or `invalid_grant` (the grant is already dead), THE system SHALL count that grant as revoked.
- WHEN Google times out THE system SHALL answer 504 `Google did not answer in time.`; WHEN Google fails in any other way THE system SHALL answer 502 `Google did not confirm the revocation.`; in both cases THE system SHALL change no record, including records whose grant Google already revoked in this request.
- THE system SHALL hold the participant lock and the lock of every account involved while it calls Google and writes. WHEN any lock is busy, a lock lease is lost before a Google call or the write, or the records change between the first read and the read under the locks, THE system SHALL answer 423 `Another change for this participant is in progress.` and change nothing.
- WHEN another participant holds one of the accounts GOOGLE_ACTIVE (an I2 breach), THE system SHALL answer 500 without calling Google, because the revoke is grant-wide and would cut that participant off too.

### Story 4: The record ends and is kept

As a compliance reviewer, I want a revoked record kept and labelled, so that Mongo shows when and by whom it ended.

**Acceptance criteria**

- WHEN the revoke succeeds THE system SHALL `$set {supersededAt: now, supersededBy: null, revokedAt: now, revokedBy: <JWT sub>}` on each GOOGLE_ACTIVE record of the participant, under a GOOGLE_ACTIVE-conditional update, and SHALL keep the document, its tokens and the participant's synced data. (GHR-04, D-01, D-03)
- `revokedAt` and `revokedBy` SHALL be contract fields: ow core's `D13_ALIASES` lists fifteen names ending `"revokedAt", "revokedBy"`, and the `Fitbit` entity and `MongoFitbit` model carry them, default None. (GHR-06, D-02)
- No reader SHALL change: every ACTIVE and GOOGLE_ACTIVE filter keys on `supersededAt`, so ow core's `get_by_participant_id` returns None for a participant whose only Google record is revoked. (GHR-04, D-02)
- WHEN the participant completes a fresh consent link THE system SHALL insert a new GOOGLE_ACTIVE record through the normal finishAuth. (GHR-04, D-04)

### Story 5: Every attempt is audited without identifying anyone

As a compliance reviewer, I want one log line per revoke attempt with record ids only, so that I can tell who revoked whose grant from the six-year log store.

**Acceptance criteria**

- WHEN a request reaches the revoke route THE system SHALL write exactly one line to stdout on the spec 009 audit logger: `googleHealth/internalRevocations outcome=<ok|400|401|409|423|500|502|503|504> actor=<24hex|-> participantId=<24hex|-> recordIds=<24hex[,24hex...]|->`, plus ` owner=<24hex>` only on the shared-account 500. (GHR-08)
- No log line from this route SHALL carry a token, a `healthUserId`, a participantNumber, a name or an email.
- WHEN finishAuth refuses an account connected to another participant THE system SHALL log `googleHealth/finishAuth outcome=connected_elsewhere participantId=<24hex> owner=<24hex>` on the same logger, so the operator can find the owner a coach may need to revoke first.

## Out of scope

- frame's side: the coach-facing `POST /api/participants/{id}/googleHealthRevoke`, its session, scope and study checks, and its status mapping (api spec 008).
- coachapp's button, confirmation and messages.
- Deleting synced data, blocking re-link, or notifying the participant.
- Edge routing. No edge location names the path; the consuming project's `checkEdgeRoutes` gate proves it.
- The scheduler: it needs no change (see "Deferred / accepted" in `design.md`).
