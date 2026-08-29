# Bouncer — Identity & Authorization Middleware Plan

**Status:** DRAFT for team review (no implementation yet).
**Track:** Bouncer — identity & authorization (per `docs/HACKATHON_EXTENSION_GUIDE.md`).
**Goal:** Separate the human principal from the agent principal; enforce authorization at trusted backend boundaries, not the UI; prove it with allow + deny + revocation cases.

---

## 0. Track & objective

The starter kit has one shared operator bearer token and no notion of *which human* or *which agent* is acting. Bouncer adds:

- A **human principal** (mock, from a header) identifying who owns/creates/drives an agent.
- An **agent principal** — a distinct, scoped, revocable credential the agent presents to access protected resources on its owner's behalf.
- **Policy enforcement** at trusted boundaries, with **audit** recording human + agent + method + resource + decision.
- A **mock resource service** the agent reaches over the network, gated by the agent credential — the concrete protected asset for the demo.

Real-world analogue: Vault workload identities / AWS STS / GitHub App tokens / SigV4 signing proxies — a non-human workload gets a scoped, short-lived, revocable credential separate from the human's identity.

### Decisions (confirmed)

- **D1 — Credential delivery:** per-run **egress HTTP proxy** (MVP, primary). `.netrc` mount kept only as an emergency fallback if the proxy lifecycle proves too fragile on Day 2.
- **D2 — Relay shape:** a **generic method+path reverse proxy** (`ANY /mock/proxy/*`). The HTTP method is a dimension of the scope (read vs write vs act). Reads and writes are both demoed under the same endpoint.
- **D3 — Redaction:** the relay returns a **redacted view** to the agent on every path (reads → redacted value; writes → confirmation). The raw value never reaches the container, even on ALLOW.

---

## 1. Architecture at a glance

```
┌────────────────────── one host process (Node) ──────────────────────────┐
│                                                                          │
│  Main Fastify app — 127.0.0.1:3000 (operator + browser)                 │
│    /api/*  (bearer-hooked, existing)                                     │
│      • onRequest attaches Principal{human} from X-Mock-User            │
│      • AgentService: ownership check (boundary 2) → 403 + audit         │
│      • executeRun: mint Tier 1 + start/stop per-run egress proxy        │
│      • POST /api/agents/:id/revoke-credential  ·  GET /api/audit         │
│                                                                          │
│  Mock Fastify app — 0.0.0.0:3001 (agent-facing, NO bearer hook)          │
│    /mock/ping            ← Day-1 reachability probe                     │
│    /mock/proxy/* (ANY)   ← boundary 3: validate Tier 1 + scope(method,  │
│                            path) → forward to upstream with Tier 2     │
│    /mock/upstream/* (ANY)← Tier 2 gate (REAL_UPSTREAM_SECRET)            │
│                                                                          │
│  Shared JsonStore (single process ✓): agents, messages, runs,           │
│    credentials, mockResources, deployState, audit (unified audit)      │
└──────────────────────────────────────────────────────────────────────────┘
                            │  HTTP_PROXY routes container traffic
                            │  through the per-run egress proxy
                            ▼
┌── per-run egress proxy (host, ephemeral port, source-IP-bound) ─┐
│  injects Authorization: Bearer <Tier1> for allowlisted targets   │
│  (host.docker.internal:3001/mock/proxy/*); blocks others         │
└────────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌── disposable container (bridge net, own fs/net namespace) ────┐
│  codex exec …  →  bash:                                       │
│   curl -X GET  http://host.docker.internal:3001/mock/proxy/    │
│        secrets/alice/db-url                                    │
│   curl -X POST http://host.docker.internal:3001/mock/proxy/    │
│        deploy/prod -d '{}'                                     │
│   (no auth flag in the command — the egress proxy adds it;    │
│    the agent never holds Tier 1 or Tier 2)                     │
└────────────────────────────────────────────────────────────────┘
```

One process, one store, two listeners on different addresses — the main API stays on loopback as the starter kit intended; only the mock app is exposed to the container bridge. **Two distinct proxy roles** (don't conflate): the **egress proxy** (forward proxy, injects Tier 1) and the **relay** (`/mock/proxy/*`, reverse proxy, validates Tier 1 + scope + injects Tier 2).

---

## 2. Data model (`apps/server/src/types.ts`)

```ts
type PrincipalKind = "human" | "agent";
interface Principal {
  kind: PrincipalKind;
  id: string;                 // "user:alice" | "agent:<agentId>"
  userId?: string;            // owning human (for agent principals)
  runId?: string;
  scopes: string[];
  expiresAt?: string;
}

interface Agent { /* existing fields… */ ownerId: string }     // NEW

interface AgentCredential {        // Tier 1
  tokenHash: string;              // SHA-256; never store the raw token
  agentId: string; runId: string; ownerId: string;
  scopes: string[];               // multi-verb: ["read:secrets:alice", "act:deploy:dev"]
  issuedAt: string; expiresAt: string; revokedAt: string | null;
}

interface MockResource {           // Tier 2 data, lives only in the store
  owner: string; key: string;
  value: string;                  // full, never sent to the container
  redactedView: string;           // what the agent sees on ALLOW (D3)
}

interface DeployState {           // protected "state" asset for the write demo
  env: string;                   // "dev" | "prod"
  deployed: boolean;              // flips to true on an allowed POST /deploy
}

interface Audit {
  id: string; timestamp: string;
  humanPrincipalId: string; agentId: string | null;
  agentPrincipalId: string | null; runId: string | null;
  method: string;                 // GET | POST | PUT | … (NEW — method is part of the decision)
  action: string;                 // "read" | "write" | "act" | "create" | "send" | "revoke"
  resource: string;               // "secrets:alice/db-url" | "deploy:prod" | "agent:<id>"
  scope: string;                  // the required scope, e.g. "read:secrets:alice"
  decision: "allow" | "deny";
  reason: string;                 // "owner" | "scope mismatch" | "revoked" | "expired" | "bypass"
}

interface Database {
  version: 2;                     // bumped from 1
  agents: Agent[]; messages: Message[]; runs: AgentRun[];
  credentials: AgentCredential[]; mockResources: MockResource[];
  deployStates: DeployState[]; audit: Audit[];
}
```

`store.ts` migrates v1→v2 on load: add the new arrays, default existing `agents[].ownerId = "default"`, seed `mockResources` (e.g. `alice/db-url`, `bob/db-url`, `prod/db-url`) and `deployStates` (`dev`, `prod`).

---

## 3. Three enforcement boundaries

| # | Boundary | Code location | Protects | Decision | On deny |
|---|---|---|---|---|---|
| 1 | HTTP request | `app.ts` `onRequest` | Human principal is established | Attach `Principal` from `X-Mock-User` (operator bearer token stays separate) | `401` if missing |
| 2 | Service / orchestration | `AgentService.*` | A human may drive only an agent they own | `principal.userId === agent.ownerId` | `403` + audit `"not owner"` |
| 3 | Relay (reverse proxy) | `ANY /mock/proxy/*` | An agent may access only resources (and methods) its scopes permit | token valid & not revoked/expired & `scopes ⊇ required(method,path)` | `403`/`401` + audit; **upstream never called** |

Checks are centralized in `AgentService` (boundary 2) and the relay (boundary 3) so every path crosses them — not just the ones the UI happens to call.

---

## 4. Two-tier credential model

| Tier | Lives in | What it is | Leak blast radius |
|---|---|---|---|
| **Tier 1** — agent identity | the per-run egress proxy (never in the container) | scoped, revocable, per-run, ~1h, hashed in DB | its scopes only; dies on revoke/expiry |
| **Tier 2** — real upstream secret | mock-resource server only (`REAL_UPSTREAM_SECRET`) | the credential the upstream demands | the upstream — but it never leaves the server |

The agent holds **no credential at all**: its outbound HTTP is routed (via `HTTP_PROXY`) through the per-run egress proxy, which injects Tier 1; the relay validates Tier 1, then uses Tier 2 *on the agent's behalf* and returns only a **redacted** response. Even on ALLOW, neither Tier 1, Tier 2, nor the raw `value` ever enters the container.

---

## 5. Credential delivery & trust model

### 5.1 The principle

**Identity is bound to the container (the sandbox), not to the LLM.** The credential is anchored to an unforgeable property of the execution environment; the LLM is trapped inside that environment and cannot forge the anchor, so it cannot claim another agent's identity. The credential is attached by a **trusted** component (the server-controlled egress proxy), never by the LLM — the LLM cannot drop, modify, or forget what it is never asked to provide (there is no auth header in its curl command at all).

### 5.2 Delivery path (primary: per-run egress proxy)

```
executeRun:
  1. mint Tier 1 token (scoped, multi-verb, revocable, hashed in DB)
  2. start egress proxy on host ephemeral port P, configured with
     {token, allowlist:["host.docker.internal:3001/mock/proxy/*"]}
  3. buildContainerRunArgs sets:
       --env HTTP_PROXY=http://host.docker.internal:P
       --env HTTPS_PROXY=http://host.docker.internal:P
       --env NO_PROXY=ark.cn-beijing.volces.com   (Ark goes direct)
       --add-host=host.docker.internal:host-gateway
       --add-host=host.containers.internal:host-gateway
     (no LAUNCHPAD_AGENT_TOKEN env — token lives only in the proxy)
  4. after container start: docker inspect → learn container bridge IP →
     tighten proxy to "accept only this source IP"
  5. on run end (try/finally): stop proxy (closeAllConnections) + revoke token
```

The egress proxy (a ~60-line `http.createServer` in `egress-proxy.ts`): for requests to allowlisted targets, inject `Authorization: Bearer <Tier1>` and forward; for non-allowlisted targets (e.g. `webhook.site`), return `403` (egress denied — bonus Kill-Switch-flavored control, in-scope per the brief's "outbound allowlists").

### 5.3 Binding anchor (why the LLM can't claim another agent's identity)

| Design | Bound to | Why the LLM can't forge it |
|---|---|---|
| **Egress proxy (primary)** | the container's **source IP** on the bridge | B's proxy accepts only B's container's bridge IP. A's packets arrive from A's IP → rejected. A can't spoof B's IP because `--cap-drop ALL` drops `CAP_NET_RAW` → no raw sockets → no IP spoofing. |
| `.netrc` (emergency fallback only) | container's filesystem namespace | B's `.netrc` not mounted into A; `--cap-drop ALL` drops `CAP_SYS_ADMIN` so A can't mount it. |

**Linchpin:** the starter kit's existing `--cap-drop ALL` + `--security-opt no-new-privileges` in `buildContainerRunArgs` is the *foundation* that makes the binding unforgeable. This is **not** the new control (the brief says default caps don't count as the new control) — the new control is the credential + policy; the cap-drop is what prevents the LLM from forging the binding.

### 5.4 "If they were able to communicate" — still fails

Two agents' containers sharing the bridge network does **not** grant inter-agent identity, because network reach ≠ source-IP reach:

- A can probe `host.docker.internal` ports and *find* B's egress proxy, but B's proxy checks the **source IP** of the incoming connection and rejects A. A would need raw sockets to spoof B's IP — forbidden by the cap-drop.
- A can `curl` B's container IP, but B's container runs Codex, not a file server; there's nothing to serve. And there's no `.netrc` in the primary path to read.

Agents share a network; they do not share credentials. Each run mints its own.

### 5.5 Residual spoof vectors — all fail closed

| Attack | Why it fails |
|---|---|
| A's own token is injected by A's proxy; A tries to reach B's resource | A's token scoped `read:secrets:alice` → relay 403 for `bob` (scope mismatch). |
| A sniffs B's bridge traffic to steal B's token | Sniffing needs promiscuous/packet-capture → raw sockets → `CAP_NET_RAW` → dropped. (Also: B's token is in B's proxy on the host, not in B's container.) |
| A reaches B's egress proxy and spoofs B's source IP | Needs raw sockets → `CAP_NET_RAW` → dropped. |
| A & B share a "session" (multi-agent coordination) | Shared conversation memory, not shared identity. Each run mints its own credential. |
| Agent bypasses the proxy (`curl --noproxy`) and hits the relay directly | No Tier 1 in the request → relay 401. |
| Agent bypasses the proxy and hits `/mock/upstream/*` directly | No `X-Upstream-Secret` (Tier 2) → 401. |

### 5.6 Caveats & limitations (document in README)

- The guarantee is **conditional on the capability profile.** If anyone relaxes `--cap-drop ALL` (e.g. adds `CAP_NET_RAW`), the source-IP / no-sniff protections weaken. Document: "identity binding is unforgeable given the cap-dropped, no-new-privileges container; relaxing capabilities voids this guarantee."
- Production path (out of scope): **per-container network namespace** — each agent's container and its egress proxy on an isolated docker network with no route to other agents' proxies. The source-IP check is the POC approximation, non-bypassable because of the cap-drop.
- `HTTP_PROXY` covers curl/wget/node/python/Go but not raw sockets; `curl --noproxy` can opt out — but the direct path still 401s (no Tier 1 / Tier 2). Document.
- **Proxy bootstrapping window:** the proxy starts permissive (before the container's IP is known via `docker inspect`), then tightens to "only accept this container's source IP" once the IP is known. Brief window, mitigated by the ephemeral port being hard to discover.
- **Proxy lifecycle hazards:** port leaks (→ `listen(0)` ephemeral + `try/finally` + `closeAllConnections()`), concurrent proxies (N for N concurrent runs, low for POC), local LAN exposure of the proxy (bind 0.0.0.0; document; real fix = bind to the bridge gateway IP only). `.netrc` fallback available if these prove fragile on Day 2.

---

## 6. Mock-resource server (`apps/server/src/mock-resource-server.ts`, new)

A second Fastify instance created in `index.ts`, listening on `0.0.0.0:MOCK_RESOURCE_PORT` (default 3001), sharing the same `JsonStore` (single-process ✓). **No bearer hook** — gated solely by Tier 1 / Tier 2.

### 6.1 The relay: one generic reverse-proxy endpoint (D2)

```
ANY /mock/proxy/*   (one wildcard route, all HTTP methods)
  1. validate Tier 1 token (Authorization: Bearer, injected by the egress proxy)
       → revoked? expired? → identify agent + scopes
  2. derive (kind, owner/target, verb) from method + path:
       GET    /mock/proxy/secrets/alice/db-url  → kind=secrets, owner=alice, verb=read
       PUT    /mock/proxy/secrets/alice/db-url  → verb=write
       POST   /mock/proxy/deploy/prod           → kind=deploy, target=prod, verb=act
  3. compute required scope:
       GET/HEAD → read:<kind>:<owner>
       PUT/POST/PATCH/DELETE on data → write:<kind>:<owner>
       POST on an action → act:<kind>:<target>
  4. check agent.scopes ⊇ required → allow/deny
       + Audit{method, action, resource, scope, decision, reason}
  5. on deny → 403 + STOP (upstream never called)
     on allow → forward (method + path + body) to /mock/upstream/* with
                 X-Upstream-Secret: REAL_UPSTREAM_SECRET (Tier 2)
               → return a REDACTED envelope (D3)
```

The **method is a dimension of the scope** (read vs write vs act). One endpoint, one policy engine, one audit shape — adding a resource kind is a new path prefix, not new relay code.

### 6.2 The upstream (Tier 2 gate)

`ANY /mock/upstream/*` gated by `X-Upstream-Secret == REAL_UPSTREAM_SECRET` (timingSafeEqual). A tiny method+path router over the shared store:

- `GET /mock/upstream/secrets/:owner/:key` → returns `MockResource.value`
- `PUT /mock/upstream/secrets/:owner/:key` → sets it (write demo)
- `POST /mock/upstream/deploy/:env` → flips `DeployState.deployed = true` (the protected state)

### 6.3 Redaction envelope (D3)

The relay always returns a redacted envelope to the agent, regardless of method — the raw `value` and Tier 2 never reach the container:

- reads → `{owner, key, value: redactedView}`
- writes → `{ok: true, action, target}` (a confirmation, never raw data)

### 6.4 Concrete paths under the **same** endpoint

```
GET  /mock/proxy/secrets/alice/db-url   (alice ⊇ read:secrets:alice)   → 200 {value: redactedView}   + Audit allow
GET  /mock/proxy/secrets/bob/db-url     (alice)                        → 403 scope mismatch          + Audit deny (upstream not called)
POST /mock/proxy/deploy/dev             (alice ⊇ act:deploy:dev)      → 202 {ok:true, env:"dev"}   + Audit allow; deployState.dev=true
POST /mock/proxy/deploy/prod            (alice, scoped to dev only)    → 403 scope mismatch          + Audit deny; prod untouched
PUT  /mock/proxy/secrets/alice/db-url   (alice ⊇ write:secrets:alice)   → 204 {ok:true, written:true} + Audit allow
direct /mock/upstream/secrets/bob/db-url (no Tier 2)                    → 401 (bypass)
```

| Route | Gated by | Returns |
|---|---|---|
| `GET /mock/ping` | nothing | `{ok:true}` (Day-1 probe) |
| `ANY /mock/proxy/*` | Tier 1 (egress-proxy-injected) + scope(method,path) | redacted envelope, or 403/401 + audit |
| `ANY /mock/upstream/*` | `X-Upstream-Secret == REAL_UPSTREAM_SECRET` | the raw data / state mutation, else 401 |

---

## 7. Control-plane integration (per file)

| File | Change |
|---|---|
| `types.ts` | §2 types; `Agent.ownerId`; `Database` v2; add `proxyPort?: number` to `RunnerRequest` |
| `config.ts` | Add `MOCK_RESOURCE_HOST` (0.0.0.0), `MOCK_RESOURCE_PORT` (3001), `REAL_UPSTREAM_SECRET` (required, ≥24 chars, never logged) |
| `store.ts` | v1→v2 migration; seed mock resources + deploy states |
| `egress-proxy.ts` (new) | ~60-line `http.createServer`: inject `Authorization: Bearer <Tier1>` for allowlisted targets, 403 others; source-IP allowlist (set after `docker inspect`); `listen(0)`; `closeAllConnections()` on stop |
| `agent-service.ts` | Thread `Principal` through every method; ownership 403 + audit; in `executeRun`: mint Tier 1 + start egress proxy (get port) + pass `proxyPort` to runner + on `finally` stop proxy + revoke token; `revokeCredential(agentId)` |
| `app.ts` | `onRequest` attaches `Principal` from `X-Mock-User` (bearer token stays); thread principal to service calls; add `POST /api/agents/:id/revoke-credential`, `GET /api/audit?agentId=` |
| `mock-resource-server.ts` (new) | `createMockApp()` → Fastify on 0.0.0.0:3001 with `GET /mock/ping`, `ANY /mock/proxy/*`, `ANY /mock/upstream/*` |
| `mock-resource-service.ts` (new) | `mintCredential`, `validateToken`, `revokeCredential`, `deriveScope(method,path)`, `relay(method, path, body)`, scope check, redaction; holds `REAL_UPSTREAM_SECRET`; writes audit |
| `container-codex-runner.ts` | `buildContainerRunArgs`: add `--add-host=host.docker.internal:host-gateway` + `--add-host=host.containers.internal:host-gateway`; set `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` from `RunnerRequest.proxyPort` (no `LAUNCHPAD_AGENT_TOKEN` env) |
| `codex-runner.ts` | symmetry: host-provider path (less used in poc) — set the same proxy env if `proxyPort` present |
| `index.ts` | Instantiate `MockResourceService` + `createMockApp`; `app.listen` main (127.0.0.1:3000) and mock (0.0.0.0:3001) |
| `apps/web/src/api.ts` | `setMockUser(u)` adds `X-Mock-User`; add `revokeCredential(id)`, `audit()` |
| `apps/web/src/App.tsx` | User switcher (sidebar), audit panel, revoke button |

---

## 8. Minimal web UI

- **User switcher** (sidebar header): Alice / Bob → sets `X-Mock-User` on all requests via `api.ts`.
- **Audit panel** (per agent, below messages): rows of `{timestamp, method, action, resource, scope, decision, reason}` — allow/deny color-coded.
- **Revoke button** (agent header actions): calls `POST /api/agents/:id/revoke-credential`; shows degraded next run.
- Optional: show active credential `{scopes, expiresAt, revokedAt}` and deploy-state (`dev`/`prod` deployed?) on the agent.

No more UI — behavior is backend.

---

## 9. Audit (unified)

One `Audit` store, written from two places: `AgentService` (boundary-2 denies + lifecycle actions) and `MockResourceService.relay` (boundary-3 allow/deny). `GET /api/audit?agentId=` returns both. **Redaction rule:** never write `REAL_UPSTREAM_SECRET` or a raw Tier 1 token or a raw `value` into `Audit`; record `method`, `action`, `resource`, `scope`, `decision`, `reason` only.

---

## 10. Test matrix

**`agent-service.test.ts` (extend — boundary 2):**
- A owns agent → A get/send/update/delete/start/stop ✓
- B → get A's agent → 403 + audit deny `"not owner"`
- B → send/delete A's agent → 403
- missing `X-Mock-User` → 401

**`mock-resource.test.ts` (new — boundary 3 + Tier 2, generic relay):**
- `GET /mock/proxy/secrets/alice/db-url` + alice token → 200, returns **redactedView** (not raw value), audit allow, upstream called
- `GET /mock/proxy/secrets/bob/db-url` + alice token → 403, audit deny `"scope mismatch"`, **upstream NOT called**
- `POST /mock/proxy/deploy/dev` + alice token (`act:deploy:dev`) → 202, deployState.dev=true, audit allow
- `POST /mock/proxy/deploy/prod` + alice token (scoped to dev) → 403, audit deny, **prod untouched**
- `PUT /mock/proxy/secrets/alice/db-url` + alice token (`write:secrets:alice`) → 204, audit allow
- revoked token → 401, audit deny `"revoked"`
- expired token → 401, audit deny `"expired"`
- missing/bogus token → 401
- direct `GET /mock/upstream/secrets/bob/db-url` without `X-Upstream-Secret` → 401 (bypass)

**Egress-proxy tests (new):**
- request to allowlisted target → forwarded with `Authorization: Bearer <Tier1>` injected
- request to non-allowlisted host → 403 (egress denied)
- request from a source IP not in the allowlist → rejected (spoof resistance)

**Redaction test:**
- no `Audit` row contains `REAL_UPSTREAM_SECRET`, a raw token, or a raw `value`; server logs don't print any of them; the relay response never contains the raw `value`.

**Trust-model test (optional, Day 3):**
- run A's egress proxy rejects requests from run B's container source IP.

---

## 11. Demo script (~3 min)

1. **(15s)** Alice → create "Alice's Coder" (owned by alice). Audit: `allow create`.
2. **(30s)** Alice → prompt: `curl -X GET http://host.docker.internal:3001/mock/proxy/secrets/alice/db-url` and summarize. Agent's curl (no auth flag — egress proxy injects Tier 1) → relay validates → 200 `{value: redactedView}` → agent summarizes. Audit: `allow GET read:secrets:alice/db-url`.
3. **(30s)** Switch to Bob → can't open Alice's agent (403). Audit: `deny "not owner"`.
4. **(30s)** Alice → `curl -X GET .../mock/proxy/secrets/bob/db-url`. Relay → 403. Audit: `deny "scope mismatch"`. Upstream not called; bob's secret unchanged.
5. **(30s)** Alice → `curl -X POST .../mock/proxy/deploy/prod`. Relay → 403 (scoped to `act:deploy:dev` only). Audit: `deny`. **prod deployState untouched** — the denied *write*.
6. **(20s)** Alice → bypass attempt: `curl --noproxy '*' http://host.docker.internal:3001/mock/upstream/secrets/bob/db-url`. → 401 (no Tier 2). Real secret never left the server.
7. **(25s)** Click Revoke → re-run the GET → 401. Audit: `deny "revoked"`. Later execution changed after revocation.

---

## 12. Day-by-day schedule

| Day | Goal | Exit |
|---|---|---|
| **1** | Types + config + store v2; `app.ts` principal hook; `AgentService` ownership 403 + audit; mock app skeleton (`/mock/ping` + `ANY /mock/proxy/*` stub + `ANY /mock/upstream/*` stub); `egress-proxy.ts`; `HTTP_PROXY`/`--add-host` in `buildContainerRunArgs`; **reachability probe** (agent curls `/mock/ping` through the proxy); ownership tests | One real middleware behavior (ownership 403) + proxy plumbing proven from a test ✅ Phase 1 |
| **2** | `MockResourceService` (mint/validate/revoke/deriveScope/relay/redact); wire `executeRun` → mint → start egress proxy → relay validates → upstream; source-IP tightening after `docker inspect`; minimal UI (switcher, audit, revoke); full positive+negative flow (read allow/deny + write deny) from browser | End-to-end scenario browser→backend→egress proxy→relay→upstream ✅ Phase 2 |
| **3** | Full test matrix; redaction pass; bypass test; egress-proxy spoof test; (stretch) per-container network-namespace hardening; architecture diagram; README section (track, demo steps, limitations, trust model); `npm run check`; rehearse 3-min demo | `npm run check` passes; demo ≤3 min ✅ Phase 3 |

---

## 13. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Backend binds 127.0.0.1 (poc default) → container can't reach | Mock app on its own 0.0.0.0:3001 listener; main API untouched |
| `host.docker.internal` not resolvable (Linux/Podman) | `--add-host` for both `host.docker.internal` and `host.containers.internal`; standardize curl on the former |
| Tier 1 token leaks from DB | Store `tokenHash` (SHA-256), never raw; compare hashes |
| `REAL_UPSTREAM_SECRET` leaks | Never in any API response, log, or audit; `timingSafeEqual` check; `.env`-only |
| Raw `value` leaks into agent output / traces | Relay returns `redactedView` only (D3); audit records decision not value; agent never sees raw `value` |
| v1 DB migration breaks existing agents | Default `ownerId="default"` on load; documented in README |
| Operator bearer token vs agent credential conflation | Mock app is a separate Fastify instance with no bearer hook; `/mock/*` gated only by Tier 1/2 |
| Egress proxy port leak | `listen(0)` ephemeral + `try/finally` + `closeAllConnections()` + revoke token in `finally` |
| Egress proxy bootstrapping window (permissive until IP known) | Ephemeral port hard to discover; tighten immediately after `docker inspect`; document |
| Egress proxy local LAN exposure | Bind 0.0.0.0 for POC, document; real fix = bind to bridge gateway IP only |
| Identity spoofing across agents | Bound to container source IP; non-forgeable due to `--cap-drop ALL` (§5) |
| Proxy lifecycle proves fragile on Day 2 | `.netrc` mount available as emergency fallback (keeps the demo working); swap-in is localized to `executeRun` + `buildContainerRunArgs` |

---

## 14. Evaluation-criteria mapping

| Criterion (weight) | How this design earns it |
|---|---|
| End-to-end middleware (40%) | Browser → ownership check → token mint → egress-proxy start → `HTTP_PROXY` routing → relay scope(method,path) check → upstream Tier 2 → redacted response → audit. Allow AND deny paths (read + write) real and tested. |
| Design & integration (25%) | Two-tier credential model; three explicit boundaries; generic method+path reverse-proxy relay (method as scope dimension); trust model bound to container sandbox not LLM; relayer pattern mapped to Vault/SigV4/IRSA/API-Gateway-ext-authz; operator token separate from agent identity; focused, extensible contracts. |
| Verification & robustness (20%) | Boundary-2 + boundary-3 (read+write) + revocation + bypass + egress-allowlist + spoof + redaction tests; hashed tokens; bypass-resistant by construction (agent lacks Tier 1 and Tier 2; cap-drop prevents forging the binding). |
| Demo & reproducibility (15%) | One-command `npm run poc`; README (track, demo steps, limitations, trust model); one-page diagram; ≤3-min demo hitting create/invoke/real-action/audit + 5 failure cases (cross-user, denied read, denied write, bypass, revocation). |

---

## 15. Decisions summary

| # | Decision | Status |
|---|---|---|
| D1 | Per-run egress HTTP proxy as the primary credential delivery (MVP) | ✅ confirmed |
| D2 | Generic method+path reverse-proxy relay (`ANY /mock/proxy/*`); method is a scope dimension; demo both reads and writes | ✅ confirmed |
| D3 | Relay returns a redacted view; raw `value` never reaches the container | ✅ confirmed |
| D4 | `.netrc` mount kept as emergency fallback only | ✅ confirmed |
| — | Day-3 stretch (still open): per-container network-namespace hardening, or redaction/test polish | ⏳ pick on Day 3 |

All design decisions are locked. Implementation begins Day 1 with: types + config + store v2 + `app.ts` principal hook + `AgentService` ownership 403 + `egress-proxy.ts` + `/mock/ping` + `ANY /mock/proxy/*` skeleton + reachability probe + ownership tests.
