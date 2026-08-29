import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type { AppConfig } from "./config.js";
import type { JsonStore } from "./store.js";
import type { AgentCredential, Audit, DeployState, MockResource } from "./types.js";

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
    owner: "alice",
    key: "db-url",
    value: "postgres://alice:s3cret@db.alice.local/agentdb",
    redactedView: "postgres://***:***@db.alice.local/agentdb",
  },
  {
    owner: "bob",
    key: "db-url",
    value: "postgres://bob:p4ssw0rd@db.bob.local/agentdb",
    redactedView: "postgres://***:***@db.bob.local/agentdb",
  },
  {
    owner: "prod",
    key: "db-url",
    value: "postgres://prod:pr0d-secret@db.prod.local/agentdb",
    redactedView: "postgres://***:***@db.prod.local/agentdb",
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
        db.mockResources.push(...SEED_RESOURCES.map((resource) => ({ ...resource })));
      }
      if (db.deployStates.length === 0) {
        db.deployStates.push(...SEED_DEPLOYS.map((state) => ({ ...state })));
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
    const credential: AgentCredential = {
      tokenHash: hashToken(token),
      agentId,
      runId,
      ownerId,
      scopes,
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
   * Derive the authorization scope required for a (method, path) pair. The HTTP
   * method is a dimension of the scope: reads need `read:`, mutating data needs
   * `write:`, and action endpoints (deploy) need `act:`.
   */
  deriveScope(method: string, path: string): DerivedScope | null {
    const parts = path.split("/").filter(Boolean);
    const kind = parts[0];
    const owner = parts[1];
    if (!kind || !owner) return null;
    if (kind === "secrets") {
      const verb: DerivedScope["verb"] =
        method === "GET" || method === "HEAD" ? "read" : "write";
      const key = parts.slice(2).join("/");
      return {
        kind,
        owner,
        verb,
        scope: `${verb}:secrets:${owner}`,
        resource: key ? `secrets:${owner}/${key}` : `secrets:${owner}`,
      };
    }
    if (kind === "deploy") {
      return {
        kind,
        owner,
        verb: "act",
        scope: `act:deploy:${owner}`,
        resource: `deploy:${owner}`,
      };
    }
    return null;
  }

  /**
   * Boundary 3 — the policy-enforcing relay. Validates the Tier 1 token (injected
   * by the egress proxy), derives the required scope, checks the agent's scopes,
   * reaches the protected data, and returns a redacted envelope. Every path
   * writes an Audit row; on a deny the upstream is never contacted.
   */
  async relay(
    method: string,
    path: string,
    body: unknown,
    token: string | undefined,
  ): Promise<RelayResult> {
    if (!token) {
      await this.auditDeny(method, path, null, "missing token", null);
      return { status: 401, body: { error: "missing token" } };
    }
    const credential = this.validateToken(token);
    if (!credential) {
      await this.auditDeny(method, path, null, "invalid or revoked token", null);
      return { status: 401, body: { error: "invalid or revoked token" } };
    }
    const scope = this.deriveScope(method, path);
    if (!scope) {
      await this.auditDeny(method, path, credential, "unknown resource", null);
      return { status: 404, body: { error: "unknown resource" } };
    }
    if (!credential.scopes.includes(scope.scope)) {
      await this.auditDeny(method, path, credential, "scope mismatch", scope.scope);
      return { status: 403, body: { error: "scope mismatch", scope: scope.scope } };
    }

    const upstream = await this.handleUpstream(method, path, body);
    const redacted = this.redactEnvelope(scope, upstream);

    await this.writeAudit({
      humanPrincipalId: "user:" + credential.ownerId,
      agentId: credential.agentId,
      agentPrincipalId: "agent:" + credential.agentId,
      runId: credential.runId,
      method,
      action: scope.verb,
      resource: scope.resource,
      scope: scope.scope,
      decision: "allow",
      reason: "scope match",
    });

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
    const target = parts[1];
    if (!kind || !target) {
      return { status: 404, body: { error: "unknown resource" } };
    }

    if (kind === "secrets") {
      const key = parts.slice(2).join("/");
      if (!key) return { status: 400, body: { error: "missing key" } };
      if (method === "GET" || method === "HEAD") {
        const resource = this.store
          .snapshot()
          .mockResources.find((entry) => entry.owner === target && entry.key === key);
        if (!resource) return { status: 404, body: { error: "not found" } };
        return { status: 200, body: structuredClone(resource) };
      }
      if (method === "PUT") {
        let updated = false;
        await this.store.mutate((db) => {
          const entry = db.mockResources.find(
            (resource) => resource.owner === target && resource.key === key,
          );
          if (entry) {
            entry.value = typeof body === "string" ? body : JSON.stringify(body);
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
      return { owner: resource.owner, key: resource.key, value: resource.redactedView };
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
      runId: credential?.runId ?? null,
      method,
      action: derived?.verb ?? "unknown",
      resource: derived?.resource ?? path,
      scope: scope ?? derived?.scope ?? null,
      decision: "deny",
      reason,
    });
  }

  listAudit(agentId?: string): Audit[] {
    const all = this.store.snapshot().audit;
    const filtered = agentId ? all.filter((entry) => entry.agentId === agentId) : all;
    return [...filtered].sort((left, right) => right.timestamp.localeCompare(left.timestamp));
  }
}
