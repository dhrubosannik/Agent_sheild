# AgentShield `policies` Collection Implementation Report

Date: 2026-11-28 · Status: **Implemented and Verified Locally (Not Deployed)**

## 1. Overview

Implemented and configured the Cloud Firestore `policies` collection for AgentShield using the existing Firebase project configuration, with strict schema/engine compatibility validation, monotonic policy versioning, immutable per-version audit history, ADMIN-only FastAPI management endpoints, and seamless integration into the deterministic security engine without breaking existing policy evaluation behavior.

---

## 2. Firestore `policies` Schema

- **Collection:** `policies`
- **Document ID:** Stable unique `policy_id` (1–128 chars, alphanumeric start, e.g. `POLICY_001`)
- **Audit History Subcollection:** `policies/{policy_id}/history/{version:06d}`

| # | Field | Type | Constraints / Behavior |
|---|---|---|---|
| 1 | `policy_id` | String | Stable unique identifier; matches document ID |
| 2 | `name` | String | Non-empty policy display name (`<= 200` chars) |
| 3 | `description` | String | Non-empty policy description (`<= 1000` chars) |
| 4 | `enabled` | Boolean | Strict boolean; only enabled policies are active in evaluation |
| 5 | `priority` | Integer | Integer `1..10000` (lower value = higher priority order) |
| 6 | `action` | String | `ALLOW`, `BLOCK`, `REDACT`, or `REQUIRE_APPROVAL` (`SecurityDecision`) |
| 7 | `rules` | Map | Engine-compatible `PolicyRuleSpec` map (no invented/unknown keys) |
| 8 | `created_by` | String | Authenticated ADMIN UID from verified backend token |
| 9 | `created_at` | Timestamp | Server timestamp (`firestore.SERVER_TIMESTAMP`) set once at creation |
| 10 | `updated_at` | Timestamp | Server timestamp (`firestore.SERVER_TIMESTAMP`) updated on every mutation |
| 11 | `version` | Integer | Starts at `1`; incremented atomically (`+1`) on update/enable/disable |

### Engine-Compatible `rules` Map Structure
`PolicyRuleSpec` (`ConfigDict(extra="forbid")`) permits only fields recognized by `SecurityRule` and `PolicyConfiguration` in [policy_models.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/core/policy_models.py):
- `tools`: `list[str]` (optional)
- `data_labels`: `list[str]` (optional)
- `destination_classes`: `list[DestinationClass]` (`APPROVED`, `UNAPPROVED`, `INTERNAL`, `UNKNOWN`, optional)
- `approved_domains`: `list[str]` (optional, validated via `ApprovedDomain`)
- `allowed_internal_destinations`: `list[str]` (optional, validated via `PolicyConfiguration.validate_internal_allowlist`)
- `protected_values`: `list[ProtectedValue]` (optional)
- `defaults`: `DefaultPolicyBehavior` (optional)

Unknown/incompatible keys (such as invented flags) and empty `{}` rule maps are rejected with validation errors (`422`).

---

## 3. Files Changed

- [backend/app/models/policy.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/models/policy.py) — Created `PolicyRuleSpec`, `StoredPolicy`, `PolicyCreateRequest`, `PolicyUpdateRequest`, `PolicyHistoryEntry`, `PolicyListResponse`, and `merge_policies_into_configuration()`.
- [backend/app/storage/firestore_policy_repository.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/storage/firestore_policy_repository.py) — Created `FirestorePolicyRepository` with transactional `create_policy()` (non-overwriting), `get_by_id()`, `list_policies_page()`, `list_enabled_policies()`, `update_policy()`, `set_enabled()`, and `list_history()`.
- [backend/app/storage/__init__.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/storage/__init__.py) — Exported `FirestorePolicyRepository` and policy repository exceptions.
- [backend/app/core/policy_loader.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/core/policy_loader.py) — Added `load_active_policy()` merging base YAML `default_policy.yaml` with enabled Firestore policies sorted by `(priority ASC, policy_id ASC)`.
- [backend/app/services/security_engine.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/services/security_engine.py) — Updated `evaluate_tool_call()` to call `load_active_policy()` when no explicit `policy` argument is supplied.
- [backend/app/api/evaluation.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/api/evaluation.py) — Wired `get_optional_policy_repository` so `POST /api/v1/evaluate` evaluates against active stored policies when Firestore mode is enabled.
- [backend/app/api/policies.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/app/api/policies.py) — Added `GET /api/v1/policies`, `GET /api/v1/policies/{policy_id}`, `GET /api/v1/policies/{policy_id}/history`, `POST /api/v1/policies`, `POST /api/v1/policies/{policy_id}/update`, `POST /api/v1/policies/{policy_id}/enable`, and `POST /api/v1/policies/{policy_id}/disable`, while preserving `GET /api/v1/policies/current`.
- [firestore.rules](file:///Users/sayantanisinha/Desktop/agent%20shield/firestore.rules) — Hardened `match /policies/{policyId}` to `allow read: if signedIn(); allow write: if false;` and added `match /history/{versionId}` (`allow read: if isAdmin(); allow write: if false;`).
- [firestore.indexes.json](file:///Users/sayantanisinha/Desktop/agent%20shield/firestore.indexes.json) — Added composite index `(enabled ASC, priority ASC)` on `policies`.
- [backend/tests/test_policies_firestore.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/tests/test_policies_firestore.py) — Added unit and API tests covering validation, non-overwriting creation, versioning, enable/disable, RBAC, audit history, and security engine integration.
- [backend/tests/emulator/test_emulator_policies.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/tests/emulator/test_emulator_policies.py) — Added Auth + Firestore emulator end-to-end policy tests.
- [backend/tests/emulator/test_emulator_firestore_rules.py](file:///Users/sayantanisinha/Desktop/agent%20shield/backend/tests/emulator/test_emulator_firestore_rules.py) — Added `test_policies_collection_rules_deny_all_client_writes`.

---

## 4. Security Controls Implemented

- **Browser Write Prohibition:** `firestore.rules` sets `allow write: if false;` on both `policies/{policyId}` and `policies/{policyId}/history/{versionId}` so no client SDK—even an admin—can bypass backend validation or write directly.
- **ADMIN-Only Mutations:** Creating, updating, enabling, disabling, and reading change history require `require_roles(UserRole.ADMIN)`. `VIEWER`, `REVIEWER` (`403`), unverified (`403`), and unauthenticated (`401`) callers are blocked.
- **Strict Rule & Schema Validation:** Unknown keys in `rules` and invalid `action`, `priority`, `enabled`, or `policy_id` values fail with `422 Unprocessable Entity`.
- **Immutable Audit History & Non-Overwrite:** `create_policy` uses `transaction.create()` (`409` on duplicate `policy_id`). Every create, update, enable, and disable writes an immutable snapshot (`CREATE`, `UPDATE`, `ENABLE`, `DISABLE`) to `policies/{policy_id}/history/{version:06d}` in the same Firestore transaction.

---

## 5. Tests Executed

| Suite | Command | Result |
|---|---|---|
| Backend & SDK unit/API tests | `.venv/bin/python -m pytest -q` | **326 passed** |
| Firebase Emulator Suite (Auth + Firestore + `firestore.rules`) | `npx -y firebase-tools emulators:exec --only auth,firestore --project demo-agentshield "unset GOOGLE_APPLICATION_CREDENTIALS FIREBASE_CLOUD_PROJECT_CONFIRM && AGENTSHIELD_EMULATOR_TESTS=1 .venv/bin/python -m pytest backend/tests/emulator -q"` | **36 passed** |
| Frontend unit tests | `cd frontend && npm test` | **24 passed**, 1 skipped (`auth.emulator.test.ts` requires running emulator) |

---

## 6. Remaining Issues & Notes

1. **Not Deployed:** Updated `firestore.rules` and `firestore.indexes.json` are verified locally and against the Firebase Emulator Suite only; nothing was deployed in this task (`Do not deploy.`).
2. **Engine Precedence:** `evaluate_policy()` enforces deterministic decision-tier precedence (`BLOCK > INTERNAL > PROTECTED_VALUE BLOCK > REDACT > REQUIRE_APPROVAL > ALLOW`), so `priority` determines rule ordering within each decision tier while preserving AgentShield's fail-closed deny-overrides-allow security invariant.
3. **Read Path Performance:** `load_active_policy()` queries enabled policies from Firestore on each evaluation in Firestore mode; for high-throughput deployments, a short-TTL cache or snapshot listener could be added later.
