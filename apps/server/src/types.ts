export type AgentStatus = "ready" | "busy" | "stopped" | "error";
export type RunStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type MessageRole = "user" | "assistant";

export interface Agent {
  id: string;
  name: string;
  description: string;
  instructions: string;
  status: AgentStatus;
  ownerId: string;
  workspacePath: string;
  codexThreadId: string | null;
  lastError: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface Message {
  id: string;
  agentId: string;
  runId: string;
  role: MessageRole;
  content: string;
  createdAt: string;
}

export interface RunUsage {
  inputTokens?: number;
  cachedInputTokens?: number;
  outputTokens?: number;
}

export interface AgentRun {
  id: string;
  agentId: string;
  status: RunStatus;
  prompt: string;
  output: string | null;
  error: string | null;
  usage: RunUsage | null;
  startedAt: string | null;
  completedAt: string | null;
  createdAt: string;
}

/*
 * Bouncer middleware — identity & authorization.
 *
 * The control plane distinguishes a human principal (who owns/drives an Agent)
 * from an agent principal (the credential an Agent presents to access protected
 * resources). See docs/BOUNCER_PLAN.md for the trust model.
 */

export type PrincipalKind = "human" | "agent";

export interface Principal {
  kind: PrincipalKind;
  id: string;
  userId: string | undefined;
  runId: string | undefined;
  scopes: string[];
  expiresAt: string | undefined;
}

/** Tier 1 — a scoped, revocable, per-run credential an Agent presents. */
export interface AgentCredential {
  tokenHash: string;
  agentId: string;
  runId: string;
  ownerId: string;
  scopes: string[];
  issuedAt: string;
  expiresAt: string;
  revokedAt: string | null;
}

/** Tier 2 data — the protected resource. `value` never leaves the server. */
export interface MockResource {
  owner: string;
  key: string;
  value: string;
  redactedView: string;
}

/** Protected state asset for the denied-write demo. */
export interface DeployState {
  env: string;
  deployed: boolean;
}

export interface Audit {
  id: string;
  timestamp: string;
  humanPrincipalId: string;
  agentId: string | null;
  agentPrincipalId: string | null;
  runId: string | null;
  method: string | null;
  action: string;
  resource: string;
  scope: string | null;
  decision: "allow" | "deny";
  reason: string;
}

export interface Database {
  version: 2;
  agents: Agent[];
  messages: Message[];
  runs: AgentRun[];
  credentials: AgentCredential[];
  mockResources: MockResource[];
  deployStates: DeployState[];
  audit: Audit[];
}

export interface CreateAgentInput {
  name: string;
  description?: string | undefined;
  instructions?: string | undefined;
}

export interface UpdateAgentInput {
  name?: string | undefined;
  description?: string | undefined;
  instructions?: string | undefined;
}

export interface RunnerResult {
  output: string;
  threadId: string | null;
  usage: RunUsage | null;
}

export interface RunnerRequest {
  agentId: string;
  workspacePath: string;
  prompt: string;
  threadId: string | null;
  proxyPort?: number;
  tightenEgressProxy?: (sourceIp: string) => void;
}

export interface AgentRunner {
  run(request: RunnerRequest): Promise<RunnerResult>;
  cancel(agentId: string): Promise<boolean>;
  isAvailable(): Promise<boolean>;
}
