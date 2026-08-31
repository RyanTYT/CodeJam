import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AgentService } from "../agent-service.js";
import { createApp } from "../app.js";
import { loadConfig } from "../config.js";
import { IntentPlanner } from "../intent-planner.js";
import { createMockApp } from "../mock-resource-server.js";
import { MockResourceService } from "../mock-resource-service.js";
import { JsonStore } from "../store.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "../types.js";
import { WorkspaceManager } from "../workspace.js";

const temporaryDirectories: string[] = [];

class FunctionalTestRunner implements AgentRunner {
  async run(request: RunnerRequest): Promise<RunnerResult> {
    return {
      output: `Completed: ${request.prompt}`,
      threadId: "functional-test-thread",
      usage: null,
      progress: [],
    };
  }

  async cancel(): Promise<boolean> {
    return false;
  }

  async isAvailable(): Promise<boolean> {
    return true;
  }
}

afterEach(async () => {
  const { rm } = await import("node:fs/promises");
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

describe("functional IAM flow", () => {
  it("creates an Agent, completes a run, allows its approved read, and blocks production deployment", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "launchpad-functional-"));
    temporaryDirectories.push(root);
    const config = loadConfig({
      NODE_ENV: "test",
      APP_DATA_DIR: path.join(root, "data"),
      AGENT_WORKSPACE_ROOT: path.join(root, "workspaces"),
      CODEX_HOME: path.join(root, "codex-home"),
      ARK_API_KEY: "functional-test-key",
      ARK_MODEL: "ep-functional-test",
      REAL_UPSTREAM_SECRET: "functional-test-upstream-secret",
    });
    const store = new JsonStore(path.join(root, "data", "launchpad.json"));
    const resources = new MockResourceService(config, store);
    const service = new AgentService(
      config,
      store,
      new WorkspaceManager(path.join(root, "workspaces")),
      new FunctionalTestRunner(),
      resources,
      new IntentPlanner(config),
    );
    await service.initialize();
    const app = await createApp(config, service);
    const mockApp = await createMockApp(resources);

    try {
      const created = await app.inject({
        method: "POST",
        url: "/api/agents",
        headers: { "x-mock-user": "alice" },
        payload: {
          name: "Functional IAM Agent",
          scopes: ["read:secrets:dev-db-url"],
        },
      });
      expect(created.statusCode).toBe(201);
      const agentId = (created.json() as { agent: { id: string } }).agent.id;

      const sent = await app.inject({
        method: "POST",
        url: `/api/agents/${agentId}/messages`,
        headers: { "x-mock-user": "alice" },
        payload: { content: "Read the approved development configuration." },
      });
      expect(sent.statusCode).toBe(202);
      const runId = (sent.json() as { run: { id: string } }).run.id;
      let completedRun: { status: string; progress: Array<{ type: string }> } | undefined;
      await expect.poll(async () => {
        const response = await app.inject({
          method: "GET",
          url: `/api/runs/${runId}`,
          headers: { "x-mock-user": "alice" },
        });
        completedRun = (response.json() as { run: typeof completedRun }).run;
        return completedRun?.status;
      }).toBe("completed");
      expect(completedRun?.progress).toEqual(expect.arrayContaining([
        expect.objectContaining({ type: "response_ready" }),
      ]));

      const messages = await app.inject({
        method: "GET",
        url: `/api/agents/${agentId}/messages`,
        headers: { "x-mock-user": "alice" },
      });
      expect(messages.statusCode).toBe(200);
      expect((messages.json() as { messages: Array<{ runId: string }> }).messages)
        .toEqual(expect.arrayContaining([
          expect.objectContaining({ runId }),
        ]));

      const workflow = await app.inject({
        method: "GET",
        url: `/api/runs/${runId}/workflow`,
        headers: { "x-mock-user": "alice" },
      });
      expect(workflow.statusCode).toBe(200);
      expect((workflow.json() as { workflow: Array<{ runId: string; status: string }> }).workflow)
        .toEqual(expect.arrayContaining([
          expect.objectContaining({ runId, status: "completed" }),
        ]));

      // This token represents the credential injected by the trusted egress proxy.
      const { token } = await resources.mintCredential(
        agentId,
        runId,
        "alice",
        ["read:secrets:dev-db-url"],
      );
      const allowed = await mockApp.inject({
        method: "GET",
        url: "/mock/proxy/secrets/dev-db-url",
        headers: { authorization: `Bearer ${token}` },
      });
      expect(allowed.statusCode).toBe(200);
      expect(allowed.json()).toMatchObject({
        key: "dev-db-url",
        value: expect.stringContaining("***"),
      });

      const blocked = await mockApp.inject({
        method: "POST",
        url: "/mock/proxy/deploy/prod",
        headers: { authorization: `Bearer ${token}` },
        payload: {},
      });
      expect(blocked.statusCode).toBe(403);
      expect(blocked.json()).toMatchObject({ error: "capability not granted" });

      const auditResponse = await app.inject({
        method: "GET",
        url: `/api/audit?agentId=${agentId}`,
        headers: { "x-mock-user": "alice" },
      });
      expect(auditResponse.statusCode).toBe(200);
      const audit = (auditResponse.json() as { audit: Array<Record<string, unknown>> }).audit;
      expect(audit).toEqual(expect.arrayContaining([
        expect.objectContaining({
          action: "read",
          resource: "secrets:dev-db-url",
          scope: "read:secrets:dev-db-url",
          decision: "allow",
          agentName: "Functional IAM Agent",
          runId,
        }),
        expect.objectContaining({
          action: "act",
          resource: "deploy:prod",
          scope: "act:deploy:prod",
          decision: "deny",
          operationRiskLevel: "high",
          runId,
        }),
      ]));
    } finally {
      await Promise.all([app.close(), mockApp.close()]);
    }
  });
});
