# Bouncer — Centralized Permissions + Admin Panel (Full Flow)

This document outlines the updates that make the Bouncer (identity/authz) full flow work end-to-end: centralized secrets, admin-managed per-user permissions, intent-bound agent scopes, and the relay that enforces them.

Branch: `feat/bouncer-admin-centralized` (on top of `6d9d24a`).

## 1. Overview

The control plane distinguishes three permission layers, each with a clear owner and surface:

| Layer | What it is | Who manages it | Where it's enforced |
|---|---|---|---|
| **Centralized secrets** | Key:value pairs (encrypted at rest, redacted views only) | Admin (Vault tab) | The relay reads them; the raw `value` never leaves the server |
| **Inherent user permissions** | A user's inherent scopes (`User.scopes`) — what a user can exercise or delegate | Admin (Admin panel + add-user wizard) | Surfaced in the admin matrix; the baseline authority a user holds |
| **Agent credential scopes** | The per-run Tier-1 credential's scopes — what a specific agent can do | The owner at create time (intent → plan → approve) | **The relay (boundary 3) enforces these** |

Secrets are **centralized** (no per-user ownership); the relationship is "which users have access to each secret" (the admin matrix). The relay authorizes the **agent's** credential, not the user — so an agent run is bounded by the scopes its owner approved at create time.

## 2. What's new (the updates)

### Centralized secrets (no owner)
- `MockResource` / `Secret` dropped `owner`. Secrets are global admin-managed resources: `{ key, value, redactedView }`.
- Scope format: `read:secrets:<key>` / `write:secrets:<key>` (no owner axis).
- `deriveScope` / `handleUpstream` treat the full path after `secrets/` as the key, so legacy composite keys (`alice/db-url`) keep working.
- `classifyScope` / `taxonomyFor` / `IntentPlanner.plan` dropped the `ownerId` dimension: any read is baseline, any write is elevated, `act:deploy:dev` baseline, `act:deploy:prod` elevated.
- Seed: `dev-db-url`, `prod-db-url`, `api-token` (generic, not user-named).
- Store migration folds any legacy owner-based resource into a composite key (`owner/key`) so old DBs keep working.

### Inherent user permissions (`User.scopes`)
- `User.scopes: string[]` — a user's inherent (human-principal) permissions, distinct from agent credential scopes.
- `MockResourceService.grantUserScope` / `revokeUserScope` (idempotent, return the user or null).
- `AgentService.grantUserScope` / `revokeUserScope` are **admin-only + audited**; 404 on unknown user.
- `addUser` accepts an optional `scopes` array (the wizard's "inherit" step).
- Routes: `POST /api/users` accepts `scopes`; `POST /api/users/:userId/scopes/grant` + `/revoke` (admin-only; `:userId` is URL-safe, not a UUID — own zod schema).

### Admin panel (admin-only)
- Sidebar ⚙ button (admin only) opens a two-column overlay:
  - **Left** — the permission catalog (flat: `Secrets` group = per-key read/write for every secret; `Deploy` group = dev/prod). Each row shows a user-count badge + **breadcrumb chips** (first 3 users who hold it, then `+N more` when too many, or `no one`).
  - **Right** — click a permission → detail panel: the scope + risk badge + a row per user with a toggle. Status is computed with `userPermissionStatus`, mirroring the relay's covering rule:
    - `admin` → disabled, "admin" badge (bypass)
    - inherited via a broader granted scope → disabled, "via `<scope>`" note
    - granted (exact) → toggle off calls `revoke`
    - none → toggle on calls `grant`

### Add-user wizard (2 steps)
- Step 1: user ID + role.
- Step 2: **permissions the user inherits** — checkboxes drawn from the same catalog. Back / Next / Add user. `POST /api/users` carries the selected scopes.

### Owner panel → agents accordion
- The Owner tab is now an **accordion of the current user's agents** (the list is already owner-filtered), collapsed except the **selected** agent (expanded).
- The expanded card shows id/session/created + **that agent's scopes**, each with a per-scope **× (revoke)**, **bulk-revoke checkboxes + "Revoke selected"**, and a **Revoke credential** button.
- Header "Agents owned by {currentUser}" makes the owner-based framing explicit.

## 3. Backend

### Data model
- `User { id, userId, role, scopes, createdAt }`
- `MockResource { key, value, redactedView }` / `Secret { key, redactedView }` (value encrypted AES-256-GCM; redacted view is the only thing ever returned)
- `Agent { ..., ownerId, scopes, plan }` — `scopes` are the live enforcement scopes; `plan` is the intent-bound plan that produced them
- `AgentCredential { tokenHash, agentId, runId, ownerId, role, scopes, issuedAt, expiresAt, revokedAt }` — Tier-1 credential minted per run; only the SHA-256 hash is persisted

### Routes (new / changed)
- `GET /api/secrets` → all secrets (redacted views only)
- `POST /api/secrets` `{ key, value, redactedView? }` (admin-only) → add/update
- `POST /api/secrets/revoke` `{ key }` (admin-only) → delete
- `GET /api/users` → all users (with `scopes`)
- `POST /api/users` `{ userId, role, scopes? }` (admin-only) → add user with inherited scopes
- `POST /api/users/:userId/scopes/grant` `{ scope }` (admin-only)
- `POST /api/users/:userId/scopes/revoke` `{ scope }` (admin-only)
- `POST /api/agents/plan` `{ intent }` → intent-bound plan (per-key taxonomy from the vault)
- `POST /api/agents` `{ name, intent?, scopes?, plan? }` → create with approved scopes + stored plan
- `POST /api/agents/:id/scopes/revoke` `{ scope }` → per-scope revoke (affects future runs)
- `POST /api/agents/:id/revoke-credential` → revoke the active Tier-1 credential

### Enforcement (boundary 3 — the relay)
The relay is the policy-enforcing reverse proxy. Flow:
1. Validate the Tier-1 credential (injected by the egress proxy).
2. Derive the required scope from `(method, path)` — `read:secrets:<key>` for GET, `write:secrets:<key>` for mutating, `act:deploy:<env>` for deploy.
3. Normalize the credential into an `AuthorizationContext` (`credentialToContext`).
4. `authorize(context, requestedCapability)`:
   - **admin role → bypass** (allow regardless of capabilities)
   - else: a granted capability matches when `action` + `resource` match AND (`scope` equal OR `requested.scope.startsWith(capability.scope + "/")`) — so an owner-scoped grant covers per-key cells.
5. On allow → reach the protected resource via `handleUpstream` (decrypt for the Tier-2 upstream gate only), redact the response, audit `allow`.
6. On deny → 403 + audit `deny` ("capability not granted").

Raw secret `value` never leaves the server: reads return `redactedView`; the relay redacts before responding; `handleUpstream` is the only decrypt path and is reachable directly only with the Tier-2 secret.

## 4. Web

### `api.ts` (contract)
- `addSecret(key, value, redactedView?)`, `revokeSecret(key)` — owner-less
- `addUser(userId, role, scopes?)`, `grantUserScope(userId, scope)`, `revokeUserScope(userId, scope)`
- Centralized `request<T>()` sets `Authorization` (shared operator token) + `X-Mock-User` (mock identity) headers.

### `App.tsx`
- **Permissions tab** — a permission map (all secrets × {read, write} + deploy). Granted highlighting uses `scopeCovers` (mirrors the relay). Per-cell × (single revoke) + checkboxes + "Revoke selected" (bulk).
- **Vault tab** — centralized secret store (admin add/delete; non-admin read-only).
- **Decisions tab** — the audit timeline (filter + expand + live via `pollRun` 900ms `/api/audit` refetch).
- **Owner tab** — agents accordion (above).
- **Admin panel overlay** + **add-user wizard** (above).
- `classifyScopeClient(scope)` (no ownerId): any read baseline, any write elevated.

## 5. Demo flow

1. Switch to `admin` → ⚙ Admin → the matrix shows `read:secrets:dev-db-url` → alice, `read:secrets:prod-db-url` → bob, `act:deploy:dev` → alice.
2. Grant/revoke per user per permission in the detail panel.
3. Add user `carol` → wizard step 2 picks inherited permissions → carol appears in the switcher.
4. Switch to `alice` → Create Agent → intent "build a todo app that reads my DB url and deploys to dev" → Plan → approve elevated → create. The agent's scopes (e.g. `read:secrets:dev-db-url`, `act:deploy:dev`) are the live enforcement scopes.
5. Owner tab → the accordion lists alice's agents; the selected one is expanded showing its scopes + revoke.
6. (Playground run needs Ark configured with a valid model; the admin/vault/permissions/owner surfaces work without Ark.)

## 6. Invariants
- Secret `value` never returned over the API (only `redactedView`); encrypted at rest (AES-256-GCM).
- The relay still redacts before responding — the agent never sees the raw value.
- Enforcement is decoupled from `AgentCredential` via `credentialToContext → scopeToCapability → authorize` (so plan-bound capabilities can be introduced later without touching the credential model).
- Admin role bypasses the capability check at the relay (boundary 3) and at agent ownership is **not** bypassed — admins still can't read agents they don't own (boundary 2).
- The user `scopes` model is a policy/visibility surface today; it is **not yet wired into relay enforcement** (the relay still authorizes the agent credential). Wiring "a user can only delegate scopes they themselves have" into agent create/plan is a clean follow-up.

## 7. Verification
- `npm run check` green: 50/50 tests; web `tsc` + `vite` build; server `tsc` build.
- Dev: `http://localhost:5173/` (server :3000, mock-resource :3001).
- Reseed fresh: delete `apps/server/.data` (the server CWD is `apps/server`, so `APP_DATA_DIR` resolves there, not the project root).
