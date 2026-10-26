# Tasks: Google Health link bridge

Rules:

- Tasks are ordered; each left the affected package green (`cd backend/api && uv run --python 3.14 pytest --deselect tests/test_session_store.py::test_unique_token_hash_is_enforced`, and `cd backend && uv run --python 3.14 pyright` adding no error to the branch-point set of 3, all in `core/tests/test_smoke.py`). `--python 3.14` because uv otherwise picks CPython 3.15, for which `psycopg-binary` has no wheel.
- Each code task was test-first: a commit with failing tests, then the commit that makes them pass.

## Checklist

- [x] 1. Mint end to end through the internal route: a valid bridge JWT gets 200 `{url, expiresAt}` with `no-store` and one `outcome=ok` audit line; no credential gets 401 Boom and one `outcome=401` line. Split `_mint_link` into `_mint_link_result`; mount `INTERNAL_LINKS_PATH` on its own router; add `401` and `503` to `_REASON`. _(Stories 1, 2, 4)_
  - `google_health/{bridge,oauth,__init__}.py`, `event_handlers/hapi.py`; tests `test_google_health_bridge.py::test_valid_bridge_token_mints_a_link`, `::test_missing_bridge_credential_is_401`; `test_google_health_oauth.py` unchanged (`2a59ca9`, `1c8a526`).
- [x] 2. Refuse every confused or forged credential, disable only the internal route on a weak or reused secret, audit every outcome, install the stdout audit logger, wire the lifespan, and classify the route as bridge-guarded. _(Stories 2, 3, 4)_
  - `google_health/bridge.py`, `main.py`; tests `test_google_health_bridge.py::test_bridge_token_refusals[*]` (15 cases), `::test_bridge_disabled_answers_503[*]` (8 rules), `::test_internal_route_is_503_while_google_health_is_disabled`, `::test_bridge_warning_names_rules_only`, `::test_valid_secret_logs_no_warning`, `::test_bad_body_is_400[*]` (6 bodies), `::test_mint_outcomes_are_audited[*]` (404, 404, 409, 500), `::test_every_outcome_writes_exactly_one_matching_line`, `::test_no_log_record_carries_the_url_or_token`, `::test_audit_logger_installed_once`, `::test_internal_path_is_outside_api`; `test_write_routes_require_auth.py` (`EXPECTED_BRIDGE_GUARDED`, `::test_bridge_guarded_route_is_neither_unauthenticated_nor_write_principal`) (`0e208b8`, `163ed12`).
- [x] 3. Write this specification. _(all stories)_
- [ ] 4. Merge, then have the consuming project provision `GOOGLE_HEALTH_BRIDGE_SECRET` for `api` and `ow_api`, point its `openwellness` submodule at the merge commit, rebuild `ow_api`, and confirm in-network: a frame-signed bridge JWT for a synthetic id gets Boom 404, a JWT under a wrong secret gets 401, and both leave an audit line on `ow_api`'s stdout.
