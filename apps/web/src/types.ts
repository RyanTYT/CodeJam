export type AgentStatus = "ready" | "busy" | "stopped" | "error";
export type RunStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export interface Agent {
  id: string;
  name: string;
  description: string;
  instructions: string;
  status: AgentStatus;
  ownerId?: string;
  scopes?: string[];
  plan?: IntentPlan | null;
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
  role: "user" | "assistant";
  content: string;
  createdAt: string;
}

export interface AgentRun {
  id: string;
  agentId: string;
  status: RunStatus;
  prompt: string;
  output: string | null;
  error: string | null;
  usage: {
    inputTokens?: number;
    cachedInputTokens?: number;
    outputTokens?: number;
  } | null;
  createdAt: string;
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

export interface SystemInfo {
  arkConfigured: boolean;
  arkBaseUrl: string;
  arkModel: string | null;
  codexAvailable: boolean;
  codexSandboxMode: string;
  runtimeProvider: "local-process" | "container";
  containerEngine: string | null;
  runtime: string;
  mockResourcePort?: number;
}

export interface IntentPlan {
  intent: string;
  requestedScopes: string[];
  baselineScopes: string[];
  elevatedScopes: string[];
  unknownScopes: string[];
  justification: string;
  source: "llm" | "fallback";
}

export interface Secret {
  owner: string;
  key: string;
  redactedView: string;
}

export interface User {
  id: string;
  userId: string;
  role: "admin" | "user";
  createdAt: string;
}
