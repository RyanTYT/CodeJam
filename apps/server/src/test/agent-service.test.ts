import { mkdtemp } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { AgentService, defaultPrincipal } from "../agent-service.js";
import { loadConfig } from "../config.js";
import { HttpError } from "../errors.js";
import { MockResourceService } from "../mock-resource-service.js";
import { IntentPlanner } from "../intent-planner.js";
import { JsonStore } from "../store.js";
import type { AgentRunner, Principal, RunnerRequest, RunnerResult } from "./types.js";
import { WorkspaceManager } from "../workspace.js";

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

async function makeService(
  runner: AgentRunner = new FakeRunner(),
  opts: { arklessPlanner?: boolean } = {},
): Promise<AgentService> {
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
  // The fallback-planner test must NOT take the live LLM path (it would fetch
  // Ark with bogus creds and hang past the test timeout on networked hosts).
  // An arkless planner config forces plan() onto the deterministic fallback.
  const plannerConfig = opts.arklessPlanner
    ? { ...config, arkApiKey: "", arkModel: "" }
    : config;
  const intentPlanner = new IntentPlanner(plannerConfig);
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

  it("stores each Codex progress event once and records when the response is ready", async () => {
    const event = {
      id: "progress-1",
      type: "command_execution",
      label: "Command",
      summary: "Ran command",
      detail: "Command: npm test",
      timestamp: new Date().toISOString(),
    };
    const runner: AgentRunner = {
      run: async (request) => {
        await request.onProgress?.(event);
        return {
          output: "Done.",
          threadId: "progress-thread",
          usage: null,
          progress: [event],
        };
      },
      cancel: async () => false,
      isAvailable: async () => true,
    };
    const service = await makeService(runner);
    const agent = await service.createAgent({ name: "Progress" });
    const { run } = await service.sendMessage(agent.id, "run tests");

    await expect.poll(() => service.getRun(run.id).status).toBe("completed");
    const progress = service.getRun(run.id).progress;
    expect(progress.filter((item) => item.id === event.id)).toHaveLength(1);
    expect(progress).toContainEqual(expect.objectContaining({
      id: `response-${run.id}`,
      type: "response_ready",
      label: "Response ready",
    }));
  });

  it("keeps progress and response events correlated to their own user messages", async () => {
    let invocation = 0;
    const runner: AgentRunner = {
      run: async (request) => {
        invocation += 1;
        const event = {
          id: `command-${invocation}`,
          type: "command_execution",
          label: "Command",
          summary: "Ran command",
          detail: `Command: echo run-${invocation}`,
          timestamp: new Date().toISOString(),
        };
        await request.onProgress?.(event);
        return {
          output: `Completed run ${invocation}`,
          threadId: `thread-${invocation}`,
          usage: null,
          progress: [event],
        };
      },
      cancel: async () => false,
      isAvailable: async () => true,
    };
    const service = await makeService(runner);
    const agent = await service.createAgent({ name: "Timeline" });
    const first = await service.sendMessage(agent.id, "first request");
    await expect.poll(() => service.getRun(first.run.id).status).toBe("completed");
    const second = await service.sendMessage(agent.id, "second request");
    await expect.poll(() => service.getRun(second.run.id).status).toBe("completed");

    for (const run of [first.run, second.run]) {
      const stored = service.getRun(run.id);
      expect(stored.progress.filter((event) => event.type === "command_execution")).toHaveLength(1);
      expect(stored.progress).toContainEqual(expect.objectContaining({
        id: `response-${run.id}`,
        type: "response_ready",
      }));
    }
    const messages = service.getMessages(agent.id);
    expect(messages.filter((message) => message.runId === first.run.id)).toHaveLength(2);
    expect(messages.filter((message) => message.runId === second.run.id)).toHaveLength(2);
  });

  it("preserves progress and marks workflow evidence failed when the Agent run fails", async () => {
    const failureEvent = {
      id: "command-failed",
      type: "command_execution",
      label: "Command",
      summary: "Ran command",
      detail: "Command: exit 1",
      timestamp: new Date().toISOString(),
    };
    const runner: AgentRunner = {
      run: async (request) => {
        await request.onProgress?.(failureEvent);
        throw new Error("command exited with code 1");
      },
      cancel: async () => false,
      isAvailable: async () => true,
    };
    const service = await makeService(runner);
    const agent = await service.createAgent({ name: "Failed timeline" });
    const { run } = await service.sendMessage(agent.id, "fail this request");

    await expect.poll(() => service.getRun(run.id).status).toBe("failed");
    const stored = service.getRun(run.id);
    expect(stored.progress).toContainEqual(failureEvent);
    expect(stored.progress.some((event) => event.type === "response_ready")).toBe(false);
    expect(service.getWorkflow(run.id).every((node) => node.status === "failed" && node.completedAt)).toBe(true);
    expect(service.getMessages(agent.id).filter((message) => message.runId === run.id)).toHaveLength(1);
  });

  it("tracks workflow hierarchy and risk snapshots for a run", async () => {
    const service = await makeService();
    const agent = await service.createAgent({ name: "Workflow" });
    const { run } = await service.sendMessage(agent.id, "run workflow");
    await expect.poll(() => service.getRun(run.id).status).toBe("completed");

    const workflow = service.getWorkflow(run.id);
    expect(workflow.some((node) => node.type === "orchestrator")).toBe(true);
    expect(workflow.some((node) => node.type === "task" && node.agentId === agent.id)).toBe(true);
    expect(workflow.every((node) => node.status === "completed" && node.completedAt)).toBe(true);
    expect(workflow.every((node) => node.riskLevel === "low" || node.riskLevel === "medium" || node.riskLevel === "high")).toBe(true);
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

  it("deduplicates repeated progress events and adds one response-ready event", async () => {
    const event = {
      id: "progress-1",
      type: "command_execution",
      label: "Command",
      summary: "ran tests",
      timestamp: new Date().toISOString(),
    };
    const runner: AgentRunner = {
      run: async (request) => {
        await request.onProgress?.(event);
        await request.onProgress?.(event);
        return { output: "done", threadId: "thread", usage: null, progress: [event] };
      },
      cancel: async () => false,
      isAvailable: async () => true,
    };
    const service = await makeService(runner);
    const agent = await service.createAgent({ name: "Progress" });

    const { run } = await service.sendMessage(agent.id, "run tests");
    await expect.poll(() => service.getRun(run.id).status).toBe("completed");

    const progress = service.getRun(run.id).progress;
    expect(progress.filter((item) => item.id === event.id)).toHaveLength(1);
    expect(progress.filter((item) => item.type === "response_ready")).toHaveLength(1);
  });

  it("keeps user progress visible and fails the workflow when the runner errors", async () => {
    const event = {
      id: "progress-before-failure",
      type: "file_search_call",
      label: "File search",
      summary: "inspected the workspace",
      timestamp: new Date().toISOString(),
    };
    const service = await makeService({
      run: async (request) => {
        await request.onProgress?.(event);
        throw new Error("runner failed");
      },
      cancel: async () => false,
      isAvailable: async () => true,
    });
    const agent = await service.createAgent({ name: "Failure" });

    const { run } = await service.sendMessage(agent.id, "inspect files");
    await expect.poll(() => service.getRun(run.id).status).toBe("failed");

    expect(service.getMessages(agent.id)).toHaveLength(1);
    expect(service.getRun(run.id).progress).toEqual(expect.arrayContaining([event]));
    expect(service.getWorkflow(run.id).every((node) => node.status === "failed")).toBe(true);
    expect(service.getRun(run.id).progress.some((item) => item.type === "response_ready")).toBe(false);
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

  it("limits unfiltered audit history to owned agents and the caller's own control-plane events", async () => {
    const service = await makeService();
    const alice = principal("alice");
    const bob = principal("bob");
    const aliceAgent = await service.createAgent({ name: "Alice audit agent" }, alice);
    const bobAgent = await service.createAgent({ name: "Bob audit agent" }, bob);
    await service.planIntent("read my database", alice);

    const aliceAudit = service.listAudit(undefined, alice);
    expect(aliceAudit.some((entry) => entry.agentId === aliceAgent.id)).toBe(true);
    expect(aliceAudit.some((entry) => entry.agentId === bobAgent.id)).toBe(false);
    expect(aliceAudit.some((entry) => entry.action === "plan")).toBe(true);

    const admin = service.resolvePrincipal("admin");
    if (!admin) throw new Error("seed admin missing");
    const globalAudit = service.listAudit(undefined, admin);
    expect(globalAudit.some((entry) => entry.agentId === aliceAgent.id)).toBe(true);
    expect(globalAudit.some((entry) => entry.agentId === bobAgent.id)).toBe(true);
  });

  it("plans intent-bound scopes from a stated intent (fallback planner)", async () => {
    const service = await makeService(new FakeRunner(), { arklessPlanner: true });
    const alice = principal("alice");
    const plan = await service.planIntent(
      "build a todo app that reads my DB url and deploys to dev",
      alice,
    );
    expect(plan.source).toBe("fallback");
    expect(plan.baselineScopes).toContain("read:secrets:dev-db-url");
    expect(plan.baselineScopes).toContain("act:deploy:dev");
    expect(plan.elevatedScopes).toEqual([]);
    expect(service.listAudit(undefined, alice).some((row) => row.action === "plan")).toBe(true);
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

describe("User permission management (inherent scopes)", () => {
  it("adds a user with inherited scopes (admin)", async () => {
    const service = await makeService();
    const admin = service.resolvePrincipal("admin");
    if (!admin) throw new Error("seed admin missing");
    const user = await service.addUser(
      "carol",
      "user",
      ["act:deploy:dev", "read:secrets:dev-db-url"],
      admin,
    );
    expect(user.userId).toBe("carol");
    expect(user.scopes).toEqual(["act:deploy:dev", "read:secrets:dev-db-url"]);
    expect(
      service.listUsers().find((u) => u.userId === "carol")?.scopes,
    ).toContain("act:deploy:dev");
  });

  it("grants a scope to a user and audits the grant (admin)", async () => {
    const service = await makeService();
    const admin = service.resolvePrincipal("admin");
    if (!admin) throw new Error("seed admin missing");
    const user = await service.grantUserScope("alice", "act:deploy:prod", admin);
    expect(user.scopes).toContain("act:deploy:prod");
    expect(
      service.listUsers().find((u) => u.userId === "alice")?.scopes,
    ).toContain("act:deploy:prod");
    expect(service.listAudit(undefined, admin).some((row) => row.action === "grant-scope")).toBe(true);
  });

  it("revokes a scope from a user and audits the revoke (admin)", async () => {
    const service = await makeService();
    const admin = service.resolvePrincipal("admin");
    if (!admin) throw new Error("seed admin missing");
    const user = await service.revokeUserScope("alice", "act:deploy:dev", admin);
    expect(user.scopes).not.toContain("act:deploy:dev");
    expect(
      service.listUsers().find((u) => u.userId === "alice")?.scopes,
    ).not.toContain("act:deploy:dev");
    expect(
      service.listAudit(undefined, admin).some((row) => row.action === "revoke-user-scope"),
    ).toBe(true);
  });

  it("denies grant/revoke/add for a non-admin principal (403)", async () => {
    const service = await makeService();
    const alice = principal("alice");
    await expect(
      service.grantUserScope("bob", "act:deploy:dev", alice),
    ).rejects.toThrow(/Only admins/);
    await expect(
      service.revokeUserScope("bob", "act:deploy:dev", alice),
    ).rejects.toThrow(/Only admins/);
    await expect(service.addUser("eve", "user", [], alice)).rejects.toThrow(/Only admins/);
  });

  it("returns 404 when granting to an unknown user (admin)", async () => {
    const service = await makeService();
    const admin = service.resolvePrincipal("admin");
    if (!admin) throw new Error("seed admin missing");
    await expect(
      service.grantUserScope("nobody", "act:deploy:dev", admin),
    ).rejects.toThrow(/User not found/);
  });
});
