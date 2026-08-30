import { mkdtemp } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { AgentService, defaultPrincipal } from "./agent-service.js";
import { loadConfig } from "./config.js";
import { HttpError } from "./errors.js";
import { MockResourceService } from "./mock-resource-service.js";
import { IntentPlanner } from "./intent-planner.js";
import { JsonStore } from "./store.js";
import type { AgentRunner, Principal, RunnerRequest, RunnerResult } from "./types.js";
import { WorkspaceManager } from "./workspace.js";

class FakeRunner implements AgentRunner {
  async run(request: RunnerRequest): Promise<RunnerResult> {
    return {
      output: "Completed: " + request.prompt,
      threadId: request.threadId ?? "fake-thread",
      usage: { inputTokens: 12, outputTokens: 5 },
    };
  }
  async cancel(): Promise<boolean> {
    return false;
  }
  async isAvailable(): Promise<boolean> {
    return true;
  }
}

const temporaryDirectories: string[] = [];

afterEach(async () => {
  const { rm } = await import("node:fs/promises");
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

async function makeService(runner: AgentRunner = new FakeRunner()): Promise<AgentService> {
  const root = await mkdtemp(path.join(tmpdir(), "launchpad-test-"));
  temporaryDirectories.push(root);
  const config = loadConfig({
    NODE_ENV: "test",
    APP_DATA_DIR: path.join(root, "data"),
    AGENT_WORKSPACE_ROOT: path.join(root, "workspaces"),
    CODEX_HOME: path.join(root, "codex"),
    ARK_API_KEY: "test-key",
    ARK_MODEL: "ep-test",
  });
  const store = new JsonStore(path.join(root, "data", "db.json"));
  const mockResourceService = new MockResourceService(config, store);
  const intentPlanner = new IntentPlanner(config);
  const service = new AgentService(
    config,
    store,
    new WorkspaceManager(path.join(root, "workspaces")),
    runner,
    mockResourceService,
    intentPlanner,
  );
  await service.initialize();
  return service;
}

const principal = (userId: string): Principal => ({
  kind: "human",
  id: "user:" + userId,
  userId,
  runId: undefined,
  scopes: [],
  expiresAt: undefined,
});

describe("Agent lifecycle", () => {
  it("creates, updates, stops, starts and deletes an Agent", async () => {
    const service = await makeService();
    const agent = await service.createAgent({ name: "Builder" });
    expect(service.listAgents()).toHaveLength(1);
    expect((await service.updateAgent(agent.id, { description: "Builds apps" })).description)
      .toBe("Builds apps");
    expect((await service.stopAgent(agent.id)).status).toBe("stopped");
    expect((await service.startAgent(agent.id)).status).toBe("ready");
    await service.deleteAgent(agent.id);
    expect(service.listAgents()).toHaveLength(0);
  });

  it("persists a playground conversation", async () => {
    const service = await makeService();
    const agent = await service.createAgent({ name: "Coder" });
    const { run } = await service.sendMessage(agent.id, "write hello world");
    await expect.poll(() => service.getRun(run.id).status).toBe("completed");
    const messages = service.getMessages(agent.id);
    expect(messages.map((message) => message.role)).toEqual(["user", "assistant"]);
    expect(messages[1]?.content).toContain("write hello world");
    expect(service.getAgent(agent.id).codexThreadId).toBe("fake-thread");
  });

  it("atomically accepts only one concurrent run per Agent", async () => {
    let finish!: (result: RunnerResult) => void;
    const pending = new Promise<RunnerResult>((resolve) => {
      finish = resolve;
    });
    const runner: AgentRunner = {
      run: () => pending,
      cancel: async () => false,
      isAvailable: async () => true,
    };
    const service = await makeService(runner);
    const agent = await service.createAgent({ name: "Concurrent" });
    const attempts = await Promise.allSettled([
      service.sendMessage(agent.id, "first"),
      service.sendMessage(agent.id, "second"),
    ]);

    expect(attempts.filter((attempt) => attempt.status === "fulfilled")).toHaveLength(1);
    const rejected = attempts.find((attempt) => attempt.status === "rejected");
    expect(rejected).toMatchObject({ reason: { statusCode: 409 } });
    expect(service.getMessages(agent.id)).toHaveLength(1);

    finish({ output: "done", threadId: "thread", usage: null });
    const accepted = attempts.find((attempt) => attempt.status === "fulfilled");
    if (accepted?.status === "fulfilled") {
      await expect.poll(() => service.getRun(accepted.value.run.id).status).toBe("completed");
    }
  });

  it("does not let start reset a busy Agent and admit a second run", async () => {
    let finish!: (result: RunnerResult) => void;
    const pending = new Promise<RunnerResult>((resolve) => {
      finish = resolve;
    });
    const service = await makeService({
      run: () => pending,
      cancel: async () => false,
      isAvailable: async () => true,
    });
    const agent = await service.createAgent({ name: "Busy" });
    const { run } = await service.sendMessage(agent.id, "first");

    await expect(service.startAgent(agent.id)).rejects.toMatchObject({ statusCode: 409 });
    await expect(service.sendMessage(agent.id, "second")).rejects.toMatchObject({
      statusCode: 409,
    });

    finish({ output: "done", threadId: "thread", usage: null });
    await expect.poll(() => service.getRun(run.id).status).toBe("completed");
  });
});

describe("Bouncer ownership boundary (boundary 2)", () => {
  it("attributes an Agent to its creating principal and lists only owned Agents", async () => {
    const service = await makeService();
    const alice = principal("alice");
    const bob = principal("bob");

    const aliceAgent = await service.createAgent({ name: "Alice's Coder" }, alice);
    expect(aliceAgent.ownerId).toBe("alice");

    const bobAgent = await service.createAgent({ name: "Bob's Coder" }, bob);
    expect(bobAgent.ownerId).toBe("bob");

    expect(service.listAgents(alice).map((a) => a.id)).toEqual([aliceAgent.id]);
    expect(service.listAgents(bob).map((a) => a.id)).toEqual([bobAgent.id]);
    expect(service.listAgents().map((a) => a.id)).toEqual([]);
  });

  it("denies a non-owner read/send/delete with 403 and audits the denial", async () => {
    const service = await makeService();
    const alice = principal("alice");
    const bob = principal("bob");

    const agent = await service.createAgent({ name: "Alice's Coder" }, alice);

    expect(() => service.getAgent(agent.id, bob)).toThrow(HttpError);
    expect(() => service.getAgent(agent.id, bob)).toThrow("Not authorized to access this Agent");
    expect(() => service.getMessages(agent.id, bob)).toThrow(HttpError);
    expect(() => service.getRuns(agent.id, bob)).toThrow(HttpError);
    expect(() => service.getAgent(agent.id, principal("default"))).toThrow(HttpError);
    await expect(service.sendMessage(agent.id, "hi", bob)).rejects.toMatchObject({
      statusCode: 403,
    });
    await expect(service.deleteAgent(agent.id, bob)).rejects.toMatchObject({
      statusCode: 403,
    });
    await expect(service.revokeCredential(agent.id, bob)).rejects.toMatchObject({
      statusCode: 403,
    });

    // Deny audits are fire-and-forget from the sync read path; poll for them.
    await expect
      .poll(() =>
        service
          .listAudit(agent.id, alice)
          .filter((row) => row.decision === "deny" && row.reason === "not owner").length,
      )
      .toBeGreaterThan(0);

    // The protected asset (the Agent) is unchanged: still owned by Alice and intact.
    const intact = service.getAgent(agent.id, alice);
    expect(intact.id).toBe(agent.id);
    expect(intact.ownerId).toBe("alice");
  });

  it("uses the synthetic default principal when no X-Mock-User is present", async () => {
    const service = await makeService();
    const agent = await service.createAgent({ name: "Default" });
    expect(agent.ownerId).toBe("default");
    expect(service.getAgent(agent.id, defaultPrincipal()).id).toBe(agent.id);

    const { run } = await service.sendMessage(agent.id, "hello");
    await expect.poll(() => service.getRun(run.id).status).toBe("completed");
  });

  it("plans intent-bound scopes from a stated intent (fallback planner)", async () => {
    const service = await makeService();
    const alice = principal("alice");
    const plan = await service.planIntent(
      "build a todo app that reads my DB url and deploys to dev",
      alice,
    );
    expect(plan.source).toBe("fallback");
    expect(plan.baselineScopes).toContain("read:secrets:alice");
    expect(plan.baselineScopes).toContain("act:deploy:dev");
    expect(plan.elevatedScopes).toEqual([]);
    expect(service.listAudit().some((row) => row.action === "plan")).toBe(true);
  });

  it("stores the approved scopes on the Agent (reduced when an elevated scope is denied)", async () => {
    const service = await makeService();
    const alice = principal("alice");
    const agent = await service.createAgent(
      {
        name: "Scoped Coder",
        intent: "read my DB and deploy to dev",
        scopes: ["read:secrets:alice"],
      },
      alice,
    );
    expect(agent.scopes).toEqual(["read:secrets:alice"]);
  });

  it("removes a single scope per-scope and audits the change", async () => {
    const service = await makeService();
    const alice = principal("alice");
    const agent = await service.createAgent(
      {
        name: "Scoped",
        intent: "read + write + deploy",
        scopes: ["read:secrets:alice", "write:secrets:alice", "act:deploy:dev"],
      },
      alice,
    );
    expect(agent.scopes).toHaveLength(3);
    const updated = await service.removeScope(agent.id, "write:secrets:alice", alice);
    expect(updated.scopes).toEqual(["read:secrets:alice", "act:deploy:dev"]);
    expect(
      service.listAudit(agent.id, alice).some((row) => row.action === "revoke-scope"),
    ).toBe(true);
  });
});
