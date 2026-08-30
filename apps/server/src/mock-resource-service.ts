import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type { AppConfig } from "./config.js";
import type { JsonStore } from "./store.js";
import { encrypt, decrypt } from "./secret-cipher.js";
import type {
  AgentCredential,
  Audit,
  AuthorizationContext,
  AuthorizationDecision,
  Capability,
  DeployState,
  MockResource,
  RequestedCapability,
  Secret,
  User,
} from "./types.js";
import { calculateAgentRiskProfile, assessOperationRisk } from "./risk-engine.js";

const now = () => new Date().toISOString();
const TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour

export interface DerivedScope {
  kind: string;
  owner: string;
  verb: "read" | "write" | "act";
  scope: string;
  resource: string;
}

export interface RelayResult {
  status: number;
  body: unknown;
}

export interface UpstreamResult {
  status: number;
  body: unknown;
}

const SEED_RESOURCES: MockResource[] = [
  {
    key: "dev-db-url",
    value: "postgres://dev:s3cret@db.dev.local/agentdb",
    redactedView: "postgres://***:***@db.dev.local/agentdb",
  },
  {
    key: "prod-db-url",
    value: "postgres://prod:pr0d-secret@db.prod.local/agentdb",
    redactedView: "postgres://***:***@db.prod.local/agentdb",
  },
  {
    key: "api-token",
    value: "sk-dev-9f3e2a8c4b1d7e0f6a5c3b2d1e0f9a8b",
    redactedView: "sk-dev-************************",
  },
];

const SEED_DEPLOYS: DeployState[] = [
  { env: "dev", deployed: false },
  { env: "prod", deployed: false },
];

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/**
 * Owns the Bouncer data: Tier 1 credentials, Tier 2 mock resources, deploy
 * state, and the unified audit trail. All state lives in the shared JsonStore
 * (single process). Raw Tier 1 tokens are never persisted — only their SHA-256
 * hashes — so a store leak does not expose live credentials.
 *
 * The relay is the policy-enforcing reverse proxy (boundary 3): it validates
 * the Tier 1 token, derives the required scope from (method, path), checks the
 * agent's scopes, then reaches the protected data via `handleUpstream` and
 * returns a redacted envelope. `handleUpstream` is also reachable directly
 * through `/mock/upstream/*`, but only with the Tier 2 secret — so the agent
 * cannot bypass the relay to read raw data it lacks a scope for.
 */
export class MockResourceService {
  constructor(
    private readonly config: AppConfig,
    private readonly store: JsonStore,
  ) {}

  async initialize(): Promise<void> {
    await this.store.mutate((db) => {
      if (db.mockResources.length === 0) {
        db.mockResources.push(
          ...SEED_RESOURCES.map((resource) => ({
            ...resource,
            value: encrypt(resource.value, this.config.secretsKey),
          })),
        );
      }
      if (db.deployStates.length === 0) {
        db.deployStates.push(...SEED_DEPLOYS.map((state) => ({ ...state })));
      }
      if (db.users.length === 0) {
        const timestamp = now();
        // Seed each user with a baseline inherent scope so the admin panel
        // shows a non-empty permission->user matrix out of the box. Admins
        // bypass the capability check regardless of their scopes field.
        db.users.push(
          { id: randomUUID(), userId: "admin", role: "admin", scopes: [], createdAt: timestamp },
          { id: randomUUID(), userId: "default", role: "user", scopes: [], createdAt: timestamp },
          {
            id: randomUUID(),
            userId: "alice",
            role: "user",
            scopes: ["read:secrets:dev-db-url", "act:deploy:dev"],
            createdAt: timestamp,
          },
          {
            id: randomUUID(),
            userId: "bob",
            role: "user",
            scopes: ["read:secrets:prod-db-url"],
            createdAt: timestamp,
          },
        );
      }
    });
  }

  async mintCredential(
    agentId: string,
    runId: string,
    ownerId: string,
    scopes: string[],
  ): Promise<{ token: string; credential: AgentCredential }> {
    const token = randomBytes(32).toString("base64url");
    const issuedAt = now();
    const expiresAt = new Date(Date.now() + TOKEN_TTL_MS).toISOString();
    const user = this.store.snapshot().users.find((u) => u.userId === ownerId);
    const role = user?.role ?? "user";
    // A user can only delegate scopes they themselves hold (admin bypasses).
    // This is the seam that makes an admin's user-permission grant actually
    // gate agent access: if the owner lacks `read:secrets:flag`, their agent's
    // credential is minted WITHOUT it, so the relay 403s it.
    const userScopes = user?.scopes ?? [];
    const effectiveScopes =
      role === "admin"
        ? scopes
        : scopes.filter(
            (scope) =>
              userScopes.some((granted) => scope === granted || scope.startsWith(granted + "/")),
          );
    const credential: AgentCredential = {
      tokenHash: hashToken(token),
      agentId,
      runId,
      ownerId,
      role,
      scopes: effectiveScopes,
      issuedAt,
      expiresAt,
      revokedAt: null,
    };
    await this.store.mutate((db) => {
      db.credentials.push(credential);
    });
    return { token, credential };
  }

  validateToken(token: string): AgentCredential | null {
    const tokenHash = hashToken(token);
    const credential = this.store
      .snapshot()
      .credentials.find((entry) => entry.tokenHash === tokenHash);
    if (!credential) return null;
    if (credential.revokedAt !== null) return null;
    if (Date.parse(credential.expiresAt) < Date.now()) return null;
    return credential;
  }

  async revokeCredential(agentId: string): Promise<boolean> {
    let revoked = false;
    await this.store.mutate((db) => {
      for (const credential of db.credentials) {
        if (credential.agentId === agentId && credential.revokedAt === null) {
          credential.revokedAt = now();
          revoked = true;
        }
      }
    });
    return revoked;
  }

  /**
   * Vault — owner-managed key:value secrets. The value is encrypted at rest
   * (AES-256-GCM) and is never returned by any of these methods; only the
   * redacted view is exposed. The relay's `handleUpstream` is the only path
   * that decrypts (for the Tier-2 upstream gate).
   */
  async addSecret(
    key: string,
    value: string,
    redactedView: string | undefined,
  ): Promise<Secret> {
    const view = redactedView?.trim() || "•••••••• (redacted)";
    const encrypted = encrypt(value, this.config.secretsKey);
    await this.store.mutate((db) => {
      const existing = db.mockResources.find((resource) => resource.key === key);
      if (existing) {
        existing.value = encrypted;
        existing.redactedView = view;
      } else {
        db.mockResources.push({ key, value: encrypted, redactedView: view });
      }
    });
    return { key, redactedView: view };
  }

  /** List all centralized secrets — redacted views only, never the values. */
  listSecrets(): Secret[] {
    return this.store.snapshot().mockResources.map((resource) => ({
      key: resource.key,
      redactedView: resource.redactedView,
    }));
  }

  /** Just the secret keys — for the IntentPlanner's per-key taxonomy. */
  listSecretKeys(): string[] {
    return this.store.snapshot().mockResources.map((resource) => resource.key);
  }

  async deleteSecret(key: string): Promise<boolean> {
    let removed = false;
    await this.store.mutate((db) => {
      const before = db.mockResources.length;
      db.mockResources = db.mockResources.filter((resource) => resource.key !== key);
      removed = db.mockResources.length < before;
    });
    return removed;
  }

  /** Resolve a mock-user userId to a User from the central users store. */
  resolveUser(userId: string): User | null {
    return this.store.snapshot().users.find((u) => u.userId === userId) ?? null;
  }

  listUsers(): User[] {
    return [...this.store.snapshot().users].sort((a, b) =>
      a.userId.localeCompare(b.userId),
    );
  }

  async addUser(
    userId: string,
    role: "admin" | "user",
    scopes: readonly string[] = [],
  ): Promise<User> {
    const user: User = {
      id: randomUUID(),
      userId,
      role,
      scopes: [...new Set(scopes)],
      createdAt: now(),
    };
    await this.store.mutate((db) => {
      db.users.push(user);
    });
    return user;
  }

  /** Grant an inherent scope to a user (admin-managed). Returns the updated
   *  user, or null if the user does not exist. Idempotent. */
  async grantUserScope(userId: string, scope: string): Promise<User | null> {
    return this.store.mutate((db) => {
      const user = db.users.find((entry) => entry.userId === userId);
      if (!user) return null;
      if (!user.scopes.includes(scope)) user.scopes.push(scope);
      return structuredClone(user);
    });
  }

  /** Revoke an inherent scope from a user (admin-managed). Returns the updated
   *  user, or null if the user does not exist. Idempotent. */
  async revokeUserScope(userId: string, scope: string): Promise<User | null> {
    return this.store.mutate((db) => {
      const user = db.users.find((entry) => entry.userId === userId);
      if (!user) return null;
      user.scopes = user.scopes.filter((entry) => entry !== scope);
      return structuredClone(user);
    });
  }

  /** All secrets across all owners (admin view) — redacted views only. */
  listAllSecrets(): Secret[] {
    return this.store.snapshot().mockResources.map((resource) => ({
      key: resource.key,
      redactedView: resource.redactedView,
    }));
  }

  /**
   * Derive the authorization scope required for a (method, path) pair. The HTTP
   * method is a dimension of the scope: reads need `read:`, mutating data needs
   * `write:`, and action endpoints (deploy) need `act:`.
   */
  deriveScope(method: string, path: string): DerivedScope | null {
    const parts = path.split("/").filter(Boolean);
    const kind = parts[0];
    if (!kind) return null;
    if (kind === "secrets") {
      // Centralized: the entire path after `secrets/` is the key (may itself
      // contain `/` for legacy composite keys like `alice/db-url`).
      const key = parts.slice(1).join("/");
      if (!key) return null;
      const verb: DerivedScope["verb"] =
        method === "GET" || method === "HEAD" ? "read" : "write";
      return {
        kind,
        owner: key,
        verb,
        scope: `${verb}:secrets:${key}`,
        resource: `secrets:${key}`,
      };
    }
    if (kind === "deploy") {
      const env = parts.slice(1).join("/");
      if (!env) return null;
      return {
        kind,
        owner: env,
        verb: "act",
        scope: `act:deploy:${env}`,
        resource: `deploy:${env}`,
      };
    }
    return null;
  }

  /**
   * Boundary 3 — the policy-enforcing relay.
   *
   * Flow:
   * 1. Validate Tier 1 credential (injected by the egress proxy)
   * 2. Derive resource scope for response handling
   * 3. Normalize credential into AuthorizationContext
   * 4. Derive requested capability
   * 5. Authorize capability
   * 6. Only then reach the protected resource
   * 7. Redact response
   * 8. Audit the decision
   */
  async relay(
    method: string,
    path: string,
    body: unknown,
    token: string | undefined,
  ): Promise<RelayResult> {

    // 1. Validate Tier 1 credential
    if (!token) {
      await this.auditDeny(method, path, null, "missing token", null);
      return { status: 401, body: { error: "missing token" } };
    }

    // 2. Authentication / Credential validation
    const credential = this.validateToken(token);

    if (!credential) {
      await this.auditDeny(method, path, null, "invalid or revoked token", null);
      return { status: 401, body: { error: "invalid or revoked token" } };
    }

    // Handle Reources and redaction
    const scope = this.deriveScope(method, path);
    if (!scope) {
      await this.auditDeny(method, path, credential, "unknown resource", null);
      return { status: 404, body: { error: "unknown resource" } };
    }
    // if (!credential.scopes.includes(scope.scope)) {
    //   await this.auditDeny(method, path, credential, "scope mismatch", scope.scope);
    //   return { status: 403, body: { error: "scope mismatch", scope: scope.scope } };
    // }

    // 3. Normalize credential into AuthorizationContext
    const context = this.credentialToContext(credential);

    // 4. Derive requested capability
    const requestedCapability = this.scopeToRequestedCapability(scope);

    if (!requestedCapability){
      await this.auditDeny(
        method,
        path,
        credential,
        "unknown capability",
        null,
      )

      return {
        status: 404,
        body: { error: "unknown resource" },
      }
    }

    // 5. Authorize capability
    const decision = this.authorize(context, requestedCapability);

    if (!decision.allowed){
      await this.auditDeny(
        method,
        path,
        credential,
        "capability not granted",
        requestedCapability.scope,
      )

      return {
        status: 403,
        body: {
          error: "capability not granted",
          capability: requestedCapability.scope,
        }
      }
    }

    // 6. Protected resource
    const upstream = await this.handleUpstream(method, path, body);
    const redacted = this.redactEnvelope(scope, upstream);

    // Phase 2: Calculate risk scores before audit
    const db = this.store.snapshot();
    const agent = db.agents.find((a) => a.id === credential.agentId);
    const recentAudit = db.audit.filter((a) => a.agentId === credential.agentId).slice(-20); // Last 20 operations
    
    const auditEntry: Omit<Audit, "id" | "timestamp"> = {
      humanPrincipalId: "user:" + credential.ownerId,
      agentId: credential.agentId,
      agentPrincipalId: "agent:" + credential.agentId,
      planId: "", // TODO: Add planId to audit
      planHash: "", // TODO: Add planHash to audit
      capability: "", // TODO: Add capability to audit
      runId: credential.runId,
      method,
      action: scope.verb,
      resource: scope.resource,
      scope: scope.scope,
      decision: "allow",
      reason: "scope match",
    };

    if (agent) {
      // Calculate agent risk profile
      const agentProfile = calculateAgentRiskProfile(agent, recentAudit);
      
      // Assess operation risk
      const operationAssessment = assessOperationRisk(
        agent,
        agentProfile,
        scope.resource,
        method,
        recentAudit,
      );

      if (operationAssessment.operationRiskLevel !== undefined) {
        auditEntry.operationRiskLevel = operationAssessment.operationRiskLevel;
      }
      if (operationAssessment.operationRiskScore !== undefined) {
        auditEntry.operationRiskScore = operationAssessment.operationRiskScore;
      }
      if (operationAssessment.operationRiskFactors) {
        auditEntry.operationRiskFactors = operationAssessment.operationRiskFactors;
      }
    }

    await this.writeAudit(auditEntry);

    return { status: upstream.status, body: redacted };
  }

  /**
   * The protected data handler. Reads/writes secrets and flips deploy state.
   * Reachable two ways: internally from `relay` (trusted — the relay already
   * validated Tier 1 + scope), and from `/mock/upstream/*` (which additionally
   * requires the Tier 2 secret). The raw `value` returned here is redacted by
   * the relay before it ever reaches the agent.
   */
  async handleUpstream(
    method: string,
    path: string,
    body: unknown,
  ): Promise<UpstreamResult> {
    const parts = path.split("/").filter(Boolean);
    const kind = parts[0];
    const target = parts.slice(1).join("/");
    if (!kind || !target) {
      return { status: 404, body: { error: "unknown resource" } };
    }

    if (kind === "secrets") {
      const key = target;
      if (method === "GET" || method === "HEAD") {
        const resource = this.store
          .snapshot()
          .mockResources.find((entry) => entry.key === key);
        if (!resource) return { status: 404, body: { error: "not found" } };
        return {
          status: 200,
          body: {
            ...structuredClone(resource),
            value: decrypt(resource.value, this.config.secretsKey),
          },
        };
      }
      if (method === "PUT") {
        let updated = false;
        await this.store.mutate((db) => {
          const entry = db.mockResources.find(
            (resource) => resource.key === key,
          );
          if (entry) {
            entry.value = encrypt(
              typeof body === "string" ? body : JSON.stringify(body),
              this.config.secretsKey,
            );
            entry.redactedView = "*** redacted ***";
            updated = true;
          }
        });
        if (!updated) return { status: 404, body: { error: "not found" } };
        return { status: 204, body: { ok: true, written: true } };
      }
      return { status: 405, body: { error: "method not allowed" } };
    }

    if (kind === "deploy") {
      if (method === "POST") {
        let deployed = false;
        await this.store.mutate((db) => {
          const entry = db.deployStates.find((state) => state.env === target);
          if (entry) {
            entry.deployed = true;
            deployed = true;
          }
        });
        if (!deployed) return { status: 404, body: { error: "unknown env" } };
        return { status: 202, body: { ok: true, env: target, deployed: true } };
      }
      return { status: 405, body: { error: "method not allowed" } };
    }

    return { status: 404, body: { error: "unknown resource" } };
  }

  /** Reads return the redacted view; writes/actions return a confirmation. */
  private redactEnvelope(scope: DerivedScope, upstream: UpstreamResult): unknown {
    if (upstream.status >= 400) return upstream.body;
    if (scope.kind === "secrets" && scope.verb === "read" && upstream.status === 200) {
      const resource = upstream.body as MockResource;
      return { key: resource.key, value: resource.redactedView };
    }
    return upstream.body;
  }

  /** True when the presented Tier 2 secret matches the configured one. */
  isUpstreamAuthorized(secret: string): boolean {
    if (this.config.realUpstreamSecret.length === 0) return false;
    return constantTimeEqual(secret, this.config.realUpstreamSecret);
  }

  async writeAudit(entry: Omit<Audit, "id" | "timestamp">): Promise<Audit> {
    const audit: Audit = { ...entry, id: randomUUID(), timestamp: now() };
    await this.store.mutate((db) => {
      db.audit.push(audit);
    });
    return audit;
  }

  private async auditDeny(
    method: string,
    path: string,
    credential: AgentCredential | null,
    reason: string,
    scope: string | null,
  ): Promise<void> {
    const derived = this.deriveScope(method, path);
    await this.writeAudit({
      humanPrincipalId: credential ? "user:" + credential.ownerId : "unknown",
      agentId: credential?.agentId ?? null,
      agentPrincipalId: credential ? "agent:" + credential.agentId : null,
      planId: "", // TODO: add planId to audit
      planHash: "", // TODO: add planHash to audit
      capability: "", // TODO: add capability
      runId: credential?.runId ?? null,
      method,
      action: derived?.verb ?? "unknown",
      resource: derived?.resource ?? path,
      scope: scope ?? derived?.scope ?? null,
      decision: "deny",
      reason,
    });
  }

  /* Normalizes the current AgentCredential representation into the
  representation consumed by the enforcement point

  The enforcement logic should NOT depend directly on AgentCredential.scopes
  This adapter is the seam that allows plan-bound capabilities to be introduced
  later
  */
  credentialToContext(
    credential: AgentCredential
  ): AuthorizationContext {
    return {
      agentId: credential.agentId,
      runId: credential.runId,
      ownerId: credential.ownerId,
      isAdmin: credential.role === "admin",
      capabilities: credential.scopes?.map(
        (scope) => this.scopeToCapability(scope)) ?? [],
      expiresAt: credential.expiresAt,
    };
  }

  /* Convert string-based scope into the normalized
  capability representation.
  */
  private scopeToCapability(scope: string): Capability {
    const parts = scope.split(":");

    if (parts.length !== 3) {
      throw new Error(`Invalid capability scope: ${scope}`);
    }

    const [action, resource, target] = parts;

    if (
      action !== "read" &&
      action !== "write" &&
      action !== "act"
    ) {
      throw new Error(`Invalid capability action: ${action}`);
    }

    if (!resource){
      throw new Error(`Invalid capability resource: ${resource}`);
    }

    if (!target){
      throw new Error(`Invalid capability scope: ${target}`);
    }

      return {
        action,
        resource,
        scope: target,
      };
  }

  private scopeToRequestedCapability(
    scope: DerivedScope,
  ): RequestedCapability {
    const [action, resource, target] = scope.scope.split(":");

    if (
      action !== "read" &&
      action !== "write" &&
      action !== "act"
    ) {
      throw new Error(`Invalid derived scope: ${scope.scope}`);
    }

    if(!resource || !target) {
      throw new Error(`Invalid derived scope: ${scope.scope}`);
    }

    return {
      action,
      resource,
      scope: target,
    }
  }

  /* Enforcement decision

  This function intentionally knows nothing about AgentCredential,
  tokens, JWTs, plan compilers, or how capabilities were created

  It only answers: "Does this authorization context contain the
  capability required by this request?"
   */
  authorize(
    context: AuthorizationContext,
    requested: RequestedCapability,
  ): AuthorizationDecision {
    if (context.isAdmin) {
      return {
        allowed: true,
        reason: "capability_granted",
        requiredCapability: requested,
        matchedCapability: {
          action: requested.action,
          resource: requested.resource,
          scope: requested.scope,
        },
      };
    }
    const matchedCapability = context.capabilities.find(
      (capability) =>
        capability.action === requested.action &&
        capability.resource === requested.resource &&
        (capability.scope === requested.scope ||
          requested.scope.startsWith(capability.scope + "/")),
    );

    if (!matchedCapability){
      return {
        allowed: false,
        reason: "capability_not_granted",
        requiredCapability: requested,
      };
    }

    return {
      allowed: true,
      reason: "capability_granted",
      requiredCapability: requested,
      matchedCapability,
    };
  }

  listAudit(agentId?: string): Audit[] {
    const all = this.store.snapshot().audit;
    const filtered = agentId ? all.filter((entry) => entry.agentId === agentId) : all;
    return [...filtered].sort((left, right) => right.timestamp.localeCompare(left.timestamp));
  }

}
