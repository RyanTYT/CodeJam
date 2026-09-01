# Bouncer UI — Policy Console Plan

**Branch:** `feat/intent-bound-permissions`
**Goal:** Make the Bouncer story (scopes + decisions) always visible alongside the agent's work, with flawless navigation/control of policy.

## 1. Layout — 3-pane

```
Sidebar (left)  |  Center: header + playground  |  Policy Console (right, NEW)
```

- **Left sidebar** (existing): brand, user switcher (default/alice/bob), Create Agent, agent list, runtime card.
- **Center**: agent header (name, status, Start/Stop/Revoke/Delete) + settings panel (kept) + playground (messages, composer). The audit panel currently *below* the playground is **removed from here** and moves to the right pane.
- **Right pane** (new): the Policy Console.

Responsive: ≥1200px → 3-pane; 768–1200 → sidebar + center, pane as a header-toggle drawer; <768 → single column, pane as a full overlay.

## 2. The Policy Console (right pane) — single scroll

One scrollable column (not tabs — tabs hide decisions during a run):

### a. Permissions card (sticky top)
- The agent's current `scopes`, color-coded by risk: 🟢 baseline · 🟠 elevated · 🔴 unknown.
- One-line **Intent** + a **plan source** badge (`llm` / `fallback`).
- **Per-scope revoke**: each scope chip has an `×` → removes it from the agent's scopes (tighten after the fact); next run's credential won't include it.
- **"View plan"** expander → the stored `IntentPlan`: requested / baseline / elevated / unknown + justification + source + which elevated the user approved vs denied. The "how did this agent get these permissions?" trail.

### b. Decisions timeline (scrolling below)
- The audit rows, newest first, **live during a run**.
- Each row: a dot (🟢 allow / 🔴 deny) + `METHOD resource` + scope + reason + time.
- Filter chips: **All / Allow / Deny**. Click a row → expand (full reason + runId).
- `pollRun` refetches `/api/audit` on every poll (not just completion) so rows stream as the agent acts.

### c. Policy reference (collapsible bottom)
- The scope taxonomy: baseline (`read:secrets:<owner>`, `act:deploy:dev`), elevated (`write:secrets:<owner>`, `act:deploy:prod`, cross-user), unknown (rejected). The "what's the policy?" reference.

## 3. Create flow (modal, kept)
- Name + Intent → **Plan permissions** → plan card (baseline/elevated/unknown + approve toggles) → **Approve & create**.
- The create call now **sends the plan** so it's stored on the agent (`agent.plan`) → the Permissions card can render the trail.
- After create → the right pane's Permissions card populates; the plan is also a `plan` row in the Decisions timeline.

## 4. Settings panel (kept)
- The header's Settings collapsible (name/description/instructions) stays. The Permissions card (right pane) is the scopes surface; Settings is the agent-config surface. They don't overlap.

## 5. Backend changes
- **`Agent.plan: IntentPlan | null`** (new field) — store the plan that produced the scopes. `store.ts` migration defaults `null`.
- **`CreateAgentInput.plan?: IntentPlan`** + zod `intentPlanSchema` in `app.ts` — the create call carries the plan.
- **`AgentService.removeScope(agentId, scope, principal)`** — ownership check + remove the scope from `agent.scopes` + audit `revoke-scope`. Affects future runs (the active run's credential was minted at start).
- **`POST /api/agents/:id/scopes/revoke` `{ scope }`** — the route.

## 6. Visual language
- Scope risk: baseline = green (`mini-ready`), elevated = amber (`mini-warning` — add), unknown = red (`mini-error`).
- Decision dots: allow = green, deny = red.
- Plan source badge: `llm` / `fallback` pill.
- Empty states: "Select an agent…", "No decisions yet — send a prompt", spinner while planning.

## 7. Implementation order
1. Backend: `Agent.plan` + `intentPlanSchema` + `createAgent` stores plan + `removeScope` + route.
2. Frontend: 3-pane shell (move audit to the right pane).
3. Frontend: Permissions card (scopes + plan trail + per-scope revoke ×).
4. Frontend: Decisions timeline (filter + expand + live poll during runs).
5. Frontend: Policy reference (taxonomy collapsible) + the Create modal sends the plan.
6. Tests + `npm run check`.
