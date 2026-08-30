import { mkdtemp } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "../config.js";
import { AuthorizationContext } from "../types.js";
import { createMockApp } from "../mock-resource-server.js";
import { MockResourceService } from "../mock-resource-service.js";
import { JsonStore } from "../store.js";

const temporaryDirectories: string[] = [];
const TIER2 = "real-upstream-secret-min-24-chars";

afterEach(async () => {
  const { rm } = await import("node:fs/promises");
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

async function makeService(): Promise<{
  service: MockResourceService;
  store: JsonStore;
}> {
  const root = await mkdtemp(path.join(tmpdir(), "launchpad-mock-"));
  temporaryDirectories.push(root);
  const config = loadConfig({
    NODE_ENV: "test",
    APP_DATA_DIR: path.join(root, "data"),
    REAL_UPSTREAM_SECRET: TIER2,
  });
  const store = new JsonStore(path.join(root, "data", "db.json"));
  const service = new MockResourceService(config, store);
  await store.initialize();
  await service.initialize();
  return { service, store };
}

const bodyValue = (body: unknown): string =>
  typeof body === "object" && body !== null && "value" in body
    ? String((body as { value: unknown }).value)
    : "";

describe("boundary 3 — relay policy", () => {
  it("allows a scoped read, returns the redacted view, and audits allow", async () => {
    const { service, store } = await makeService();
    const { token } = await service.mintCredential("agent-1", "run-1", "alice", [
      "read:secrets:alice",
    ]);

    const result = await service.relay("GET", "secrets/alice/db-url", undefined, token);

    expect(result.status).toBe(200);
    const resource = store
      .snapshot()
      .mockResources.find((entry) => entry.owner === "alice");
    expect(bodyValue(result.body)).toBe(resource?.redactedView);
    expect(bodyValue(result.body)).not.toBe(resource?.value);
    expect(JSON.stringify(result.body)).not.toContain(resource?.value ?? "no-raw");

    const allow = service
      .listAudit("agent-1")
      .find((row) => row.decision === "allow" && row.action === "read");
    expect(allow).toBeTruthy();
  });

  it("denies a scope mismatch with 403, never reaches upstream, and audits deny", async () => {
    const { service, store } = await makeService();
    const { token } = await service.mintCredential("agent-1", "run-1", "alice", [
      "read:secrets:alice",
    ]);
    const before = store.snapshot().mockResources.find((entry) => entry.owner === "bob")?.value;

    const result = await service.relay("GET", "secrets/bob/db-url", undefined, token);

    expect(result.status).toBe(403);
    expect(store.snapshot().mockResources.find((entry) => entry.owner === "bob")?.value).toBe(
      before,
    );
    const deny = service
      .listAudit("agent-1")
      .find((row) => row.decision === "deny" && row.reason === "capability not granted");
      expect(deny).toBeTruthy();
  });

  it("denies a revoked credential with 401 and audits the denial", async () => {
    const { service } = await makeService();
    const { token } = await service.mintCredential("agent-1", "run-1", "alice", [
      "read:secrets:alice",
    ]);
    await service.revokeCredential("agent-1");

    const result = await service.relay("GET", "secrets/alice/db-url", undefined, token);

    expect(result.status).toBe(401);
    expect(
      service
        .listAudit()
        .some((row) => row.decision === "deny" && row.reason === "invalid or revoked token"),
    ).toBe(true);
  });

  it("denies a missing or bogus token with 401", async () => {
    const { service } = await makeService();
    expect(
      (await service.relay("GET", "secrets/alice/db-url", undefined, undefined)).status,
    ).toBe(401);
    expect(
      (await service.relay("GET", "secrets/alice/db-url", undefined, "bogus")).status,
    ).toBe(401);
  });

  it("allows a scoped deploy (dev) and denies prod, leaving prod untouched", async () => {
    const { service, store } = await makeService();
    const { token } = await service.mintCredential("agent-1", "run-1", "alice", [
      "act:deploy:dev",
    ]);

    const ok = await service.relay("POST", "deploy/dev", {}, token);
    expect(ok.status).toBe(202);
    expect(store.snapshot().deployStates.find((entry) => entry.env === "dev")?.deployed).toBe(
      true,
    );

    const denied = await service.relay("POST", "deploy/prod", {}, token);
    expect(denied.status).toBe(403);
    expect(store.snapshot().deployStates.find((entry) => entry.env === "prod")?.deployed).toBe(
      false,
    );
  });
});

describe("boundary 3 — HTTP routes", () => {
  it("routes /mock/proxy/* through the relay with the proxy-injected token", async () => {
    const { service } = await makeService();
    const { token } = await service.mintCredential("agent-1", "run-1", "alice", [
      "read:secrets:alice",
    ]);
    const app = await createMockApp(service);
    try {
      const res = await app.inject({
        method: "GET",
        url: "/mock/proxy/secrets/alice/db-url",
        headers: { authorization: "Bearer " + token },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().value).toContain("***");
    } finally {
      await app.close();
    }
  });

  it("refuses a bypass attempt on /mock/upstream without the Tier 2 secret", async () => {
    const { service } = await makeService();
    const app = await createMockApp(service);
    try {
      const denied = await app.inject({
        method: "GET",
        url: "/mock/upstream/secrets/alice/db-url",
      });
      expect(denied.statusCode).toBe(401);

      const allowed = await app.inject({
        method: "GET",
        url: "/mock/upstream/secrets/alice/db-url",
        headers: { "x-upstream-secret": TIER2 },
      });
      expect(allowed.statusCode).toBe(200);
    } finally {
      await app.close();
    }
  });

  it("never exposes the raw secret via the relay, even on an allowed read", async () => {
    const { service, store } = await makeService();
    const { token } = await service.mintCredential("agent-1", "run-1", "alice", [
      "read:secrets:alice",
    ]);
    const app = await createMockApp(service);
    try {
      const res = await app.inject({
        method: "GET",
        url: "/mock/proxy/secrets/alice/db-url",
        headers: { authorization: "Bearer " + token },
      });
      const raw = store.snapshot().mockResources.find((entry) => entry.owner === "alice")?.value;
      expect(res.rawPayload).not.toContain(raw ?? "no-raw-value");
    } finally {
      await app.close();
    }
  });

  // Enforcement Point Test Cases
  it("converts credential scopes into capabilities", async() => {
    const credential = {
      tokenHash: "test",
      agentId: "agent-1",
      runId: "run-1",
      ownerId: "alice",
      scopes: [
        "read:secrets:alice",
        "act:deploy:dev",
      ],
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      revokedAt: null,
    };
    const { service } = await makeService();

    const context =
      service.credentialToContext(credential);

    expect(context.capabilities).toEqual([
      {
        action: "read",
        resource: "secrets",
        scope: "alice",
      },
      {
        action: "act",
        resource: "deploy",
        scope: "dev",
      },
    ]);
  });

  it("denies a capability that is not granted", async() => {
    const { service } = await makeService();
    const context: AuthorizationContext = {
      agentId: "agent-1",
      runId: "run-1",
      ownerId: "alice",
      capabilities: [
        {
          action: "act",
          resource: "deploy",
          scope: "dev",
        },
      ],
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    };

    const decision = service.authorize(context, {
      action: "act",
      resource: "deploy",
      scope: "prod",
    });

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe("capability_not_granted");
  });

  it("does not treat read capability as write capability", async() => {
    const { service } = await makeService();
    const context: AuthorizationContext = {
      agentId: "agent-1",
      runId: "run-1",
      ownerId: "alice",
      capabilities: [
        {
          action: "read",
          resource: "secrets",
          scope: "alice",
        },
      ],
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    };

    const decision = service.authorize(context, {
      action: "write",
      resource: "secrets",
      scope: "alice",
    });

    expect(decision.allowed).toBe(false);
  });

  it("does not allow a dev deployment capability to deploy to prod", async() => { 
    const { service } = await makeService(); 
    const context: AuthorizationContext = { 
      agentId: "agent-1", 
      runId: "run-1", 
      ownerId: "alice", 
      capabilities: [ 
        { action: "act", resource: "deploy", scope: "dev", }, 
      ], 
      expiresAt: new Date(Date.now() + 60_000).toISOString(), 
    }; 
    const decision = service.authorize(context, 
      { action: "act", resource: "deploy", scope: "prod", }
    ); 
    expect(decision.allowed).toBe(false); 
  }); 
  
  it("evaluates capabilities independently", async() => { 
    const { service } = await makeService();  
    const context: AuthorizationContext = {
      agentId: "agent-1", 
      runId: "run-1", 
      ownerId: "alice", 
      capabilities: [ 
        { action: "read", resource: "secrets", scope: "alice", },
        { action: "act", resource: "deploy", scope: "dev", }, 
      ], 
      expiresAt: new Date(Date.now() + 60_000).toISOString(), 
    }; 
    expect( service.authorize(context, 
      { action: "read", resource: "secrets", scope: "alice", }).allowed, 
    ).toBe(true); 
    expect( service.authorize(context, 
      { action: "act", resource: "deploy", scope: "prod", }).allowed, 
    ).toBe(false); 
    expect( service.authorize(context, 
      { action: "write", resource: "secrets", scope: "alice", }).allowed,
     ).toBe(false); });

});
