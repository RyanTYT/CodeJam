import { randomUUID } from "node:crypto";
import type { AppConfig } from "./config.js";
import { isArkConfigured } from "./config.js";
import { startEgressProxy, type EgressProxy } from "./egress-proxy.js";
import { HttpError, RunCancelledError } from "./errors.js";
import type { MockResourceService } from "./mock-resource-service.js";
import type { IntentPlanner } from "./intent-planner.js";
import { JsonStore } from "./store.js";
import type {
  Agent,
  AgentCredential,
  AgentRun,
  AgentRunner,
  Audit,
  CreateAgentInput,
  IntentPlan,
  Message,
  Principal,
  RunnerRequest,
  Secret,
  UpdateAgentInput,
  WorkflowNode,
  User,
} from "./types.js";
import { WorkspaceManager } from "./workspace.js";
import { calculateAgentRiskProfile } from "./risk-engine.js";
import { calculateAgentRiskProfile } from "./risk-engine.js";

const now = () => new Date().toISOString();

/** The synthetic principal used when X-Mock-User is absent (baseline operator). */
export const defaultPrincipal = (): Principal => ({
  kind: "human",
  id: "user:default",
  userId: "default",
  role: "user",
  runId: undefined,
  scopes: [],
  expiresAt: undefined,
});

/**
 * AgentService coordinates lifecycle, persistence, workspaces, and Runs. Every
 * operation crosses the ownership boundary (boundary 2): a human principal may
 * only drive an Agent they own, else 403 + an Audit row. In container mode,
 * `executeRun` mints a Tier 1 credential and starts a per-run egress proxy so
 * the disposable container can reach the mock resource service without ever
 * holding the credential itself.
 */
export class AgentService {
  private readonly activeExecutions = new Map<string, Promise<void>>();
  private readonly cancellationRequests = new Set<string>();

  constructor(
    private readonly config: AppConfig,
    private readonly store: JsonStore,
    private readonly workspaces: WorkspaceManager,
    private readonly runner: AgentRunner,
    private readonly mockResourceService: MockResourceService,
    private readonly intentPlanner: IntentPlanner,
  ) {}

  async initialize(): Promise<void> {
    await this.store.initialize();
    await this.workspaces.initialize();
    await this.mockResourceService.initialize();
    await this.store.mutate((database) => {
      for (const run of database.runs) {
        if (run.status === "queued" || run.status === "running") {
          run.status = "cancelled";
          run.error = "Server restarted while this run was active";
          run.completedAt = now();
        }
      }
      for (const agent of database.agents) {
        if (agent.status === "busy") {
          agent.status = "ready";
          agent.updatedAt = now();
        }
      }
    });
  }

  listAgents(principal: Principal = defaultPrincipal()): Agent[] {
    return this.store
      .snapshot()
      .agents.filter((agent) => agent.ownerId === principal.userId)
      .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
  }

  getAgent(id: string, principal: Principal = defaultPrincipal()): Agent {
    const agent = this.store.snapshot().agents.find((item) => item.id === id);
    if (!agent) {
      throw new HttpError(404, "Agent not found");
    }
    this.assertOwner(agent, principal, "read");
    return agent;
  }

  async createAgent(
    input: CreateAgentInput,
    principal: Principal = defaultPrincipal(),
  ): Promise<Agent> {
    const timestamp = now();
    const id = randomUUID();
    const ownerId = principal.userId ?? "default";
    const scopes =
      input.scopes && input.scopes.length > 0
        ? [...new Set(input.scopes)]
        : [`read:secrets:${ownerId}`, "act:deploy:dev"];
    const agent: Agent = {
      id,
      name: input.name.trim(),
      description: input.description?.trim() || input.intent?.trim() || "",
      instructions: input.instructions?.trim() ?? "",
      status: "ready",
      ownerId,
      scopes,
      plan: input.plan ?? null,
      workspacePath: this.workspaces.workspacePath(id),
      codexThreadId: null,
      lastError: null,
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    await this.workspaces.create(agent);
    await this.store.mutate((database) => {
      database.agents.push(agent);
      
      // Phase 2: Calculate and store initial risk profile
      const riskProfile = calculateAgentRiskProfile(agent, []);
      database.agentRiskProfiles.push(riskProfile);
    });
    await this.audit(
      principal,
      agent.id,
      "create",
      `agent:${agent.id}`,
      "allow",
      `owner; scopes: ${scopes.join(", ")}`,
    );
    return agent;
  }

  /**
   * Intent-bound permissions planning: ask the planner for the minimum scopes
   * the stated intent needs, classify them (baseline/elevated/unknown), and
   * audit the proposal. The UI then asks the user to approve the elevated
   * subset before createAgent stores the approved scopes on the Agent.
   */
  async planIntent(
    intent: string,
    principal: Principal = defaultPrincipal(),
  ): Promise<IntentPlan> {
    const ownerId = principal.userId ?? "default";
    const secretKeys = this.mockResourceService.listSecretKeys();
    const plan = await this.intentPlanner.plan(intent, secretKeys);
    await this.audit(
      principal,
      null,
      "plan",
      `intent:${intent.slice(0, 80)}`,
      "allow",
      `requested [${plan.requestedScopes.join(", ")}] baseline ${plan.baselineScopes.length} elevated ${plan.elevatedScopes.length} unknown ${plan.unknownScopes.length}; source ${plan.source}`,
    );
    return plan;
  }

  async updateAgent(
    id: string,
    input: UpdateAgentInput,
    principal: Principal = defaultPrincipal(),
  ): Promise<Agent> {
    const current = this.getAgent(id, principal);
    if (current.status === "busy") {
      throw new HttpError(409, "Stop the active run before editing this Agent");
    }
    const updated = await this.store.mutate((database) => {
      const agent = database.agents.find((item) => item.id === id);
      if (!agent) {
        throw new HttpError(404, "Agent not found");
      }
      if (agent.status === "busy") {
        throw new HttpError(409, "Stop the active run before editing this Agent");
      }
      if (input.name !== undefined) agent.name = input.name.trim();
      if (input.description !== undefined) agent.description = input.description.trim();
      if (input.instructions !== undefined) agent.instructions = input.instructions.trim();
      agent.lastError = null;
      agent.updatedAt = now();
      return structuredClone(agent);
    });
    await this.workspaces.writeInstructions(updated);
    await this.audit(principal, updated.id, "update", `agent:${updated.id}`, "allow", "owner");
    return updated;
  }

  async deleteAgent(
    id: string,
    principal: Principal = defaultPrincipal(),
  ): Promise<{ archivedWorkspace: string }> {
    const agent = this.getAgent(id, principal);
    await this.cancelExecution(id);
    const archivedWorkspace = await this.workspaces.archive(agent);
    await this.store.mutate((database) => {
      database.agents = database.agents.filter((item) => item.id !== id);
      database.messages = database.messages.filter((item) => item.agentId !== id);
      database.runs = database.runs.filter((item) => item.agentId !== id);
    });
    await this.audit(principal, agent.id, "delete", `agent:${agent.id}`, "allow", "owner");
    return { archivedWorkspace };
  }

  async startAgent(id: string, principal: Principal = defaultPrincipal()): Promise<Agent> {
    this.getAgent(id, principal);
    const agent = await this.setStatus(id, "ready");
    await this.audit(principal, id, "start", `agent:${id}`, "allow", "owner");
    return agent;
  }

  async stopAgent(id: string, principal: Principal = defaultPrincipal()): Promise<Agent> {
    this.getAgent(id, principal);
    await this.cancelExecution(id);
    const agent = await this.setStatus(id, "stopped");
    await this.audit(principal, id, "stop", `agent:${id}`, "allow", "owner");
    return agent;
  }

  getMessages(agentId: string, principal: Principal = defaultPrincipal()): Message[] {
    this.getAgent(agentId, principal);
    return this.store
      .snapshot()
      .messages.filter((message) => message.agentId === agentId)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  getRun(runId: string, principal: Principal = defaultPrincipal()): AgentRun {
    const run = this.store.snapshot().runs.find((item) => item.id === runId);
    if (!run) {
      throw new HttpError(404, "Run not found");
    }
    this.getAgent(run.agentId, principal);
    return run;
  }

  getRuns(agentId: string, principal: Principal = defaultPrincipal()): AgentRun[] {
    this.getAgent(agentId, principal);
    return this.store
      .snapshot()
      .runs.filter((run) => run.agentId === agentId)
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
  }

  async sendMessage(
    agentId: string,
    prompt: string,
    principal: Principal = defaultPrincipal(),
  ): Promise<{ run: AgentRun; message: Message }> {
    this.getAgent(agentId, principal);
    if (!isArkConfigured(this.config)) {
      throw new HttpError(
        503,
        "Ark is not configured. Set ARK_API_KEY and ARK_MODEL, then restart.",
      );
    }
    const timestamp = now();
    const runId = randomUUID();
    const run: AgentRun = {
      id: runId,
      agentId,
      status: "queued",
      prompt,
      output: null,
      error: null,
      usage: null,
      progress: [],
      startedAt: null,
      completedAt: null,
      createdAt: timestamp,
    };
    const message: Message = {
      id: randomUUID(),
      agentId,
      runId,
      role: "user",
      content: prompt,
      createdAt: timestamp,
    };
    const agentAtStart = await this.store.mutate((database) => {
      const storedAgent = database.agents.find((item) => item.id === agentId);
      if (!storedAgent) {
        throw new HttpError(404, "Agent not found");
      }
      if (storedAgent.status === "stopped") {
        throw new HttpError(409, "Start the Agent before sending a message");
      }
      if (storedAgent.status === "busy") {
        throw new HttpError(409, "This Agent is already running");
      }
      const riskProfile = database.agentRiskProfiles.find((profile) => profile.agentId === agentId);
      const orchestratorNode: WorkflowNode = {
        id: randomUUID(),
        type: "orchestrator",
        runId: run.id,
        status: "running",
        riskLevel: riskProfile?.agentRiskLevel ?? "low",
        createdAt: timestamp,
      };
      const taskNode: WorkflowNode = {
        id: randomUUID(),
        type: "task",
        parentId: orchestratorNode.id,
        runId: run.id,
        agentId: agentId,
        status: "running",
        riskLevel: riskProfile?.agentRiskLevel ?? "low",
        createdAt: timestamp,
      };
      database.runs.push(run);
      database.messages.push(message);
      database.workflowNodes.push(orchestratorNode, taskNode);
      const snapshot = structuredClone(storedAgent);
      storedAgent.status = "busy";
      storedAgent.lastError = null;
      storedAgent.updatedAt = timestamp;
      return snapshot;
    });
    await this.audit(principal, agentId, "send", `agent:${agentId}`, "allow", "owner", { runId });
    const execution = this.executeRun(agentAtStart, run, principal);
    this.activeExecutions.set(agentId, execution);
    void execution
      .finally(() => {
        if (this.activeExecutions.get(agentId) === execution) {
          this.activeExecutions.delete(agentId);
        }
      })
      .catch(() => undefined);
    return { run, message };
  }

  async revokeCredential(
    agentId: string,
    principal: Principal = defaultPrincipal(),
  ): Promise<{ revoked: boolean }> {
    this.getAgent(agentId, principal);
    const revoked = await this.mockResourceService.revokeCredential(agentId);
    await this.audit(principal, agentId, "revoke", `credential:${agentId}`, "allow", "owner");
    return { revoked };
  }

  /**
   * Per-scope revocation: remove a single scope from the agent's stored set.
   * Affects future runs (the active run's credential was minted at start);
   * the next run's credential won't include the removed scope → the relay 403s it.
   */
  async removeScope(
    agentId: string,
    scope: string,
    principal: Principal = defaultPrincipal(),
  ): Promise<Agent> {
    this.getAgent(agentId, principal);
    const updated = await this.store.mutate((database) => {
      const agent = database.agents.find((item) => item.id === agentId);
      if (!agent) {
        throw new HttpError(404, "Agent not found");
      }
      agent.scopes = agent.scopes.filter((entry) => entry !== scope);
      agent.updatedAt = now();
      return structuredClone(agent);
    });
    await this.audit(
      principal,
      agentId,
      "revoke-scope",
      `scope:${scope}`,
      "allow",
      `owner; removed ${scope}`,
    );
    return updated;
  }

  getWorkflow(runId: string, principal: Principal = defaultPrincipal()): WorkflowNode[] {
    const run = this.getRun(runId, principal);
    return this.store
      .snapshot()
      .workflowNodes.filter((node) => node.runId === run.id)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  listAudit(
    agentId: string | undefined,
    principal: Principal = defaultPrincipal(),
  ): Audit[] {
    if (agentId) this.getAgent(agentId, principal);
    return this.mockResourceService.listAudit(agentId);
  }

  /** Vault — centralized secrets (encrypted at rest, redacted views only).
   *  Everyone sees the redacted catalog; only admins may add/delete. */
  listSecrets(principal: Principal = defaultPrincipal()): Secret[] {
    void principal;
    return this.mockResourceService.listSecrets();
  }

  async addSecret(
    key: string,
    value: string,
    redactedView: string | undefined,
    principal: Principal = defaultPrincipal(),
  ): Promise<Secret> {
    if (principal.role !== "admin") {
      throw new HttpError(403, "Only admins may manage secrets");
    }
    const secret = await this.mockResourceService.addSecret(key, value, redactedView);
    await this.audit(principal, null, "add-secret", `secret:${key}`, "allow", "admin");
    return secret;
  }

  async deleteSecret(
    key: string,
    principal: Principal = defaultPrincipal(),
  ): Promise<{ deleted: boolean }> {
    if (principal.role !== "admin") {
      throw new HttpError(403, "Only admins may manage secrets");
    }
    const deleted = await this.mockResourceService.deleteSecret(key);
    await this.audit(
      principal,
      null,
      "revoke-secret",
      `secret:${key}`,
      deleted ? "allow" : "deny",
      deleted ? "admin" : "not found",
    );
    return { deleted };
  }

  /** Resolve a mock-user userId to a Principal (with role) from the users store, or null. */
  resolvePrincipal(userId: string): Principal | null {
    const user = this.mockResourceService.resolveUser(userId);
    if (!user) return null;
    return {
      kind: "human",
      id: "user:" + user.userId,
      userId: user.userId,
      role: user.role,
      runId: undefined,
      scopes: [],
      expiresAt: undefined,
    };
  }

  listUsers(): User[] {
    return this.mockResourceService.listUsers();
  }

  async addUser(
    userId: string,
    role: "admin" | "user",
    scopes: readonly string[] = [],
    principal: Principal = defaultPrincipal(),
  ): Promise<User> {
    if (principal.role !== "admin") {
      throw new HttpError(403, "Only admins may add users");
    }
    if (this.mockResourceService.resolveUser(userId)) {
      throw new HttpError(409, `User ${userId} already exists`);
    }
    const user = await this.mockResourceService.addUser(userId, role, scopes);
    await this.audit(
      principal,
      null,
      "add-user",
      `user:${userId}`,
      "allow",
      `admin; role ${role}; scopes ${scopes.length}`,
    );
    return user;
  }

  /** Grant an inherent permission to a user (admin-managed + audited). */
  async grantUserScope(
    userId: string,
    scope: string,
    principal: Principal = defaultPrincipal(),
  ): Promise<User> {
    if (principal.role !== "admin") {
      throw new HttpError(403, "Only admins may manage user permissions");
    }
    const user = await this.mockResourceService.grantUserScope(userId, scope);
    if (!user) {
      throw new HttpError(404, "User not found");
    }
    await this.audit(
      principal,
      null,
      "grant-scope",
      `user:${userId};scope:${scope}`,
      "allow",
      `admin; granted ${scope}`,
    );
    return user;
  }

  /** Revoke an inherent permission from a user (admin-managed + audited). */
  async revokeUserScope(
    userId: string,
    scope: string,
    principal: Principal = defaultPrincipal(),
  ): Promise<User> {
    if (principal.role !== "admin") {
      throw new HttpError(403, "Only admins may manage user permissions");
    }
    const user = await this.mockResourceService.revokeUserScope(userId, scope);
    if (!user) {
      throw new HttpError(404, "User not found");
    }
    await this.audit(
      principal,
      null,
      "revoke-user-scope",
      `user:${userId};scope:${scope}`,
      "allow",
      `admin; revoked ${scope}`,
    );
    return user;
  }

  /**
   * Debug: mint a Tier-1 credential for a user (admin-only). Lets you test the
   * relay enforcement (boundary 3) live — curl /mock/proxy/secrets/<key> with
   * the returned token — without running an agent (which needs Ark/Codex).
   * The credential's scopes are filtered by the owner's inherent User.scopes
   * (admin bypasses), exactly like a real agent run.
   */
  async mintDebugCredential(
    userId: string,
    scopes: string[],
    principal: Principal = defaultPrincipal(),
  ): Promise<{ token: string; credential: AgentCredential }> {
    if (principal.role !== "admin") {
      throw new HttpError(403, "Only admins may mint debug credentials");
    }
    return this.mockResourceService.mintCredential(
      "debug-agent",
      "debug-run",
      userId,
      scopes,
    );
  }

  async systemInfo(): Promise<Record<string, unknown>> {
    return {
      arkConfigured: isArkConfigured(this.config),
      arkBaseUrl: this.config.arkBaseUrl,
      arkModel: this.config.arkModel || null,
      codexAvailable: await this.runner.isAvailable(),
      codexSandboxMode: this.config.codexSandboxMode,
      runtimeProvider: this.config.runtimeProvider,
      containerEngine:
        this.config.runtimeProvider === "container" ? this.config.containerEngine : null,
      runtime:
        this.config.runtimeProvider === "container"
          ? "Codex CLI in " + this.config.containerEngine + " Runtime"
          : "Codex CLI in application container",
      mockResourcePort: this.config.mockResourcePort,
    };
  }

  private async executeRun(
    agentAtStart: Agent,
    run: AgentRun,
    principal: Principal,
  ): Promise<void> {
    await this.store.mutate((database) => {
      const storedRun = database.runs.find((item) => item.id === run.id);
      if (storedRun) {
        storedRun.status = "running";
        storedRun.startedAt = now();
      }
    });

    const containerMode = this.config.runtimeProvider === "container";
    let proxy: EgressProxy | null = null;
    if (containerMode) {
      try {
        const minted = await this.mockResourceService.mintCredential(
          agentAtStart.id,
          run.id,
          agentAtStart.ownerId,
          agentAtStart.scopes,
        );
        proxy = await startEgressProxy({
          token: minted.token,
          allowHosts: [`host.docker.internal:${this.config.mockResourcePort}`],
          allowPathPrefixes: ["/mock/proxy/", "/mock/ping"],
        });
        // Source-IP tightening (post docker-inspect) is wired in Day 2 alongside
        // the runner's container-IP discovery; permissive until then.
      } catch (error) {
        proxy = null;
        console.warn(
          "[bouncer] egress proxy start failed; run proceeding without proxy:",
          error instanceof Error ? error.message : String(error),
        );
      }
    }

    try {
      if (this.cancellationRequests.has(agentAtStart.id)) {
        throw new RunCancelledError();
      }
      const request: RunnerRequest = {
        agentId: agentAtStart.id,
        workspacePath: agentAtStart.workspacePath,
        prompt: run.prompt,
        threadId: agentAtStart.codexThreadId,
        onProgress: async (event) => {
          await this.store.mutate((database) => {
            const storedRun = database.runs.find((item) => item.id === run.id);
            if (!storedRun) return;
            storedRun.progress ??= [];
            const exists = storedRun.progress.some((entry) => entry.id === event.id);
            if (!exists) {
              storedRun.progress.push(event);
            }
          });
        },
      };
      if (proxy) {
        request.proxyPort = proxy.port;
        const proxyHandle = proxy;
        request.tightenEgressProxy = (sourceIp: string) =>
          proxyHandle.setExpectedSourceIp(sourceIp);
      }
      const result = await this.runner.run(request);
      const completedAt = now();
      await this.store.mutate((database) => {
        const storedRun = database.runs.find((item) => item.id === run.id);
        const agent = database.agents.find((item) => item.id === agentAtStart.id);
        if (!storedRun || !agent) return;
        storedRun.status = "completed";
        storedRun.output = result.output;
        storedRun.usage = result.usage;
        storedRun.progress = [...(storedRun.progress ?? []), ...result.progress];
        storedRun.completedAt = completedAt;
        database.messages.push({
          id: randomUUID(),
          agentId: agent.id,
          runId: run.id,
          role: "assistant",
          content: result.output,
          createdAt: completedAt,
        });
        agent.status = "ready";
        agent.codexThreadId = result.threadId;
        agent.lastError = null;
        agent.updatedAt = completedAt;
      });
    } catch (error) {
      const completedAt = now();
      const cancelled = error instanceof RunCancelledError;
      const message = error instanceof Error ? error.message : String(error);
      await this.store.mutate((database) => {
        const storedRun = database.runs.find((item) => item.id === run.id);
        const agent = database.agents.find((item) => item.id === agentAtStart.id);
        if (storedRun) {
          storedRun.status = cancelled ? "cancelled" : "failed";
          storedRun.error = message;
          storedRun.completedAt = completedAt;
        }
        if (agent) {
          if (agent.status !== "stopped") {
            agent.status = cancelled ? "ready" : "error";
          }
          agent.lastError = cancelled ? null : message;
          agent.updatedAt = completedAt;
        }
      });
    } finally {
      if (proxy) {
        await proxy.stop().catch(() => undefined);
      }
      if (containerMode) {
        await this.mockResourceService.revokeCredential(agentAtStart.id).catch(() => undefined);
      }
    }
    void principal;
  }

  private assertOwner(agent: Agent, principal: Principal, action: string): void {
    if (principal.userId !== agent.ownerId) {
      void this.audit(principal, agent.id, action, `agent:${agent.id}`, "deny", "not owner");
      throw new HttpError(403, "Not authorized to access this Agent");
    }
  }

  private async audit(
    principal: Principal,
    agentId: string | null,
    action: string,
    resource: string,
    decision: "allow" | "deny",
    reason: string,
    options: { runId?: string; method?: string; scope?: string; agentPrincipalId?: string } = {},
  ): Promise<void> {
    await this.mockResourceService.writeAudit({
      humanPrincipalId: principal.id,
      agentId,
      agentPrincipalId: options.agentPrincipalId ?? null,
      runId: options.runId ?? null,
      method: options.method ?? null,
      action,
      resource,
      scope: options.scope ?? null,
      decision,
      reason,
    });
  }

  private async setStatus(id: string, status: Agent["status"]): Promise<Agent> {
    return this.store.mutate((database) => {
      const agent = database.agents.find((item) => item.id === id);
      if (!agent) {
        throw new HttpError(404, "Agent not found");
      }
      if (status === "ready" && agent.status === "busy") {
        throw new HttpError(409, "Stop the active run before starting this Agent");
      }
      agent.status = status;
      if (status === "ready") agent.lastError = null;
      agent.updatedAt = now();
      return structuredClone(agent);
    });
  }

  private async cancelExecution(agentId: string): Promise<void> {
    this.cancellationRequests.add(agentId);
    try {
      await this.runner.cancel(agentId);
      const execution = this.activeExecutions.get(agentId);
      if (execution) {
        await execution;
      }
    } finally {
      this.cancellationRequests.delete(agentId);
    }
  }
}
