# Requirements: Google Health authorization and notifications

Status: approved
Created: 2026-09-30

## Summary

Google turns off the Fitbit Web API on 2026-10-30. Participants whose Fitbit accounts moved to Google must re-consent through the Google Health API, or their device data stops arriving. The consuming project (opserver) runs the legacy Fitbit flow on frame and cannot move it. This specification adds four `ow_api` routes under `/api/googleHealth`: staff mint a participant-bound link, the participant completes Google OAuth, `ow_api` stores a `provider: googleHealth` record in the shared `fitbits` collection, and Google's data-change notifications are verified and handed to the scheduler. Legacy Fitbit participants keep working unchanged until they migrate. Traceability: opserver GHA-01 (link, OAuth and the stored record) and GHA-02 (notification receiver).

## User stories

### Story 1: Staff mint a participant link

As a study coordinator with the `admin` role, I want to mint a signed link for one participant, so that I can send it to the participant without handing out any credential of mine.

**Acceptance criteria**

- WHEN an authenticated caller with `admin` in its roles posts `{"participantId": <hex id>}` to `/api/googleHealth/links` THE system SHALL answer 200 `{"url", "expiresAt"}`, where `url` is `<public origin>/api/googleHealth/authorize?t=<link token>` and the token expires 72 hours after minting.
- WHEN the caller is anonymous THE system SHALL answer 401; WHEN the caller lacks the `admin` role THE system SHALL answer 403.
- WHEN the participant is unknown, malformed or inactive THE system SHALL answer 404; WHEN the participant's study is on the migration hold THE system SHALL answer 409.

### Story 2: The participant connects a Google account

As a participant, I want to open my link, consent on Google's page and see a confirmation, so that my data keeps reaching the study after the Fitbit Web API is gone.

**Acceptance criteria**

- WHEN a valid, unclaimed link is opened THE system SHALL set a browser-binding cookie, mint a single-use OAuth state bound to that cookie, and redirect to Google consent with `access_type=offline`, `prompt=consent`, the three read-only Google Health scopes and the registered redirect URI.
- WHEN Google redirects back with a code THE system SHALL exchange it, look up the Google identity, and store one `fitbits` record with `provider: "googleHealth"` and `migrationStatus: "pending"`, in the shape of opserver's `docs/google-health.md` contract.
- WHEN that record is stored THE system SHALL mark every other active record of the participant superseded by it, keep a first `migratedAt` across re-consents, and publish `googleHealth.completeMigration [participantId, googleRecordId, supersededRecordIds]` onto queue `scheduler_new`.
- WHEN the grant lacks any of the three scopes or a refresh token THE system SHALL store nothing and let the participant use the same link again.
- WHEN the state is forged, expired, replayed, from another browser, or signed for another audience THE system SHALL refuse without calling Google and without a write.
- WHEN the Google account is already connected to another participant THE system SHALL refuse without a write.
- WHEN two finishAuth requests race for the same link, participant or Google account THE system SHALL let at most one of them store a record.

### Story 3: Google notifications reach the scheduler

As an operator, I want `ow_api` to accept Google's data-change notifications, so that the scheduler syncs a participant's changed dates without polling.

**Acceptance criteria**

- WHEN Google sends the subscriber handshake `{"type": "verification"}` with the configured `Authorization` header THE system SHALL answer 200 with an empty body (Google accepts 200 or 201 and reads no body), and WHEN the header is missing or wrong THE system SHALL answer 401. The secret is never echoed in a response.
- WHEN a notification arrives THE system SHALL verify `GOOGLE-HEALTH-API-SIGNATURE` over the raw body, and answer 401 for an invalid signature and 503 when the signing key cannot be obtained, so that Google redelivers.
- WHEN a signed body holds one notification or an array of them THE system SHALL publish one `googleHealth.handleNotification [healthUserId, dataType, operation, dates]` per distinct (healthUserId, dataType, operation) onto `scheduler_new` and answer 204.
- WHEN an interval is given as `civilDateTimeInterval`, `civilIso8601TimeInterval` or `physicalTimeInterval` THE system SHALL derive the civil dates it covers.
- WHEN a publish fails THE system SHALL answer 503.
- WHEN the handler runs THE system SHALL NOT read Mongo, write any datastore, or call Google except to fetch the public signing keyset.

### Story 4: Misconfiguration is safe and visible

As an operator, I want an unset or weak Google Health setting to disable only these routes, so that the rest of `ow_api` keeps serving and the cause is in the log.

**Acceptance criteria**

- WHEN a required `GOOGLE_HEALTH_*` key is unset, or a setting breaks a rule (secret length, distinct secrets, reuse of `API_AUTH_JWT_SECRET`, https origin, client id shape, hold format, https keyset URL) THE system SHALL answer 503 on all four routes and log one WARNING naming the keys or rules, never a value.
- WHEN an operator runs `python -m openwellness_api.google_health.selfcheck` in the built image THE system SHALL print one PASS or FAIL line for each of six checks and exit 0 only when all pass.

## Out of scope

- Routing. Merging this change sends no traffic to `ow_api`; the consuming project adds the `/api/googleHealth` edge group when it is ready.
- The scheduler side: `completeMigration`, legacy revoke and unsubscribe, data sync, the daily backfill and its reconcile phase. They live in the consuming project's scheduler.
- The `/api/fitbit` and `/api/fitbits` routes, which stay on frame.
- Encrypting stored tokens and grant-wide Google revocation. See "Deferred" in `design.md`.
