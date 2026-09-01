# Permissions UX — Vault + Per-Key Map + Select-Revoke

**Branch:** `feature/enforcement-point` (continue here)
**Goal:** Make permissions inclusive + legible — an owner manages their secrets (key:value, encrypted at rest), an agent's grants are shown as a per-secret permission map (granted highlighted, un-granted greyed), and revoking is select-and-revoke.

## Decisions (confirmed)
- **Per-key scopes**: `read:secrets:alice/db-url` (not owner-scoped `read:secrets:alice`). Enables per-secret granularity in the map.
- **Vault as a tab** in the right Policy Console (agent/owner level — scoped to the selected agent's owner).
- **Encryption at rest** for secret values (AES-256-GCM, key derived from `REAL_UPSTREAM_SECRET`).

## 1. Encryption utility + config
- `secret-cipher.ts`: `encrypt(value, key)` / `decrypt(ciphertext, key)` (AES-256-GCM; format `v1:<iv>:<tag>:<ct>` base64).
- Config: derive a 32-byte key from `REAL_UPSTREAM_SECRET` (SHA-256) — no new env var. The `redactedView` stays plaintext (it's a label).

## 2. Vault backend (`MockResourceService`)
- `addSecret(owner, key, value, redactedView?)` — encrypts `value`, stores `{owner, key, value: ct, redactedView: redactedView ?? autoRedact(value)}`.
- `listSecrets(owner)` → `[{owner, key, redactedView}]` — **never** the `value`.
- `deleteSecret(owner, key)`.
- Migrate the seed resources to encrypted `value`s; `handleUpstream` decrypts on read (so the Tier-2 upstream path returns the raw value; the relay path still returns `redactedView`).

## 3. Per-key scope format
- `deriveScope` → `read:secrets:alice/db-url` (include the key) for `secrets/alice/db-url`.
- `classifyScope` parses `<owner>/<key>`: own-key read = baseline; cross-user / any write / `act:deploy:prod` = elevated; else unknown.
- Taxonomy becomes **dynamic**: `taxonomyFor(ownerId, secretKeys)` lists per-key read/write for each of the owner's secrets + the deploy scopes.
- `IntentPlanner.plan(intent, ownerId, secretKeys)` — the LLM prompt (and the fallback keyword matcher) propose **specific** per-key scopes from the owner's actual secrets.

## 4. Routes
- `POST /api/secrets {key, value, redactedView?}` → addSecret.
- `GET /api/secrets` → listSecrets (redacted, owner = principal).
- `DELETE /api/secrets/:key` → deleteSecret.
- `POST /api/agents/plan` now passes the owner's secret keys to the planner.

## 5. Web — tabbed Policy Console
The right pane becomes **tabs** (scoped to the selected agent's owner):
- **Permissions**: the permission map — a grid of the owner's secrets × {read, write} + `act:deploy:{dev,prod}`. Granted scopes highlighted; un-granted **greyed**. Checkboxes on granted scopes + **Revoke selected** (bulk `removeScope`). Per-scope × stays for single.
- **Vault**: the owner's key:value secrets — add row (key + value + optional label), list (shows `redactedView` only), delete. Stored privately.
- **Decisions**: the audit timeline (filter + expand + live) — unchanged.
- Policy reference: a collapsible at the bottom of the Permissions tab.

## 6. Tests + check
- Vault: addSecret encrypts + listSecrets never returns the value; deleteSecret removes.
- Per-key: classifyScope for own/cross-user/per-key; deriveScope emits per-key; IntentPlanner proposes per-key from the secret list.
- Relay: a per-key grant allows, a non-granted per-key scope 403s.
- `npm run check` green.

## Invariants (kept)
- Secret `value` never returned over the API (only `redactedView`); encrypted at rest.
- Relay still redacts before responding (agent never sees the raw value).
- Enforcement stays decoupled (capability match on action/resource/scope — `scope` is now `<owner>/<key>`).
