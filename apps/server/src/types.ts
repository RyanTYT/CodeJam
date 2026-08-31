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
  /** Intent-bound, approved scopes minted into the agent's Tier 1 credential. */
  scopes: string[];
  /** The plan that produced the scopes (requested/baseline/elevated/unknown + justification). Null for legacy agents. */
  plan: IntentPlan | null;
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

export interface AgentProgressEvent {
  id: string;
  type: string;
  label: string;
  summary: string;
  detail?: string;
  timestamp: string;
}

export interface AgentRun {
  id: string;
  agentId: string;
  status: RunStatus;
  prompt: string;
  output: string | null;
  error: string | null;
  usage: RunUsage | null;
  progress: AgentProgressEvent[];
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
  role: "admin" | "user";
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
  role: "admin" | "user";
  scopes: string[];
  issuedAt: string;
  expiresAt: string;
  revokedAt: string | null;
}

/** Tier 2 data — a centralized protected secret. `value` never leaves the
 *  server. Secrets are global resources (not user-owned); per-user access is
 *  governed by each user's inherent scopes + each agent's credential scopes. */
export interface MockResource {
  key: string;
  value: string;
  redactedView: string;
}

/** A redacted view of a centralized stored secret — the value never leaves
 *  the server. */
export interface Secret {
  key: string;
  redactedView: string;
}

/** A registered principal in the central users store. Admins can access all secrets.
 *  `scopes` are the user's INHERENT (human-principal) permissions — the baseline
 *  authority a user can exercise or delegate to their agents, managed by admins. */
export interface User {
  id: string;
  userId: string;
  role: "admin" | "user";
  scopes: string[];
  createdAt: string;
}

/** Protected state asset for the denied-write demo. */
export interface DeployState {
  env: string;
  deployed: boolean;
}

// Normalized authorization capability
// Independent of how capability was produced and comes
// from AgentCredential.scopes and later can come from
// A plan/compiler-generated capability grant
export interface Capability {
  action: "read" | "write" | "act";
  resource: string;
  scope: string;
}

// Normalized authorization context consumed by
// enforcement point
export interface AuthorizationContext {
  agentId: string;
  runId: string;
  ownerId: string;
  isAdmin: boolean;
  capabilities: Capability[];

  // Temporarily Optional since the current
  // credential model does not have plan
  // binding yet
  planId?: string;
  planHash?: string;

  credentialId?: string;
  expiresAt: string;
}

// Capability required by an incoming
// resource request
export interface RequestedCapability {
  action: "read" | "write" | "act";
  resource: string;
  scope: string;
}

// Result returned by the authorization check
export interface AuthorizationDecision {
  allowed: boolean;
  reason: | "capability_granted" | "capability_not_granted";

  requiredCapability: RequestedCapability;

  // Present when a granted capability matched the request
  matchedCapability?: Capability;
}

export interface Audit {
  id: string;
  timestamp: string;
  humanPrincipalId: string;
  agentId: string | null;
  agentPrincipalId: string | null;
  runId: string | null;
  planId?: string | null;
  planHash?: string | null;
  capability?: string | null;
  method: string | null;
  action: string;
  resource: string;
  scope: string | null;
  decision: "allow" | "deny";
  reason: string;
  /** Operation-level risk assessment (Phase 1 enhancement). */
  operationRiskLevel?: "low" | "medium" | "high";
  operationRiskScore?: number; // 0-100
  operationRiskFactors?: string[];
  /** Workflow hierarchy tracking (Phase 1 enhancement). */
  nodeId?: string;
  parentNodeId?: string;
}

/** Risk level classification (Phase 1 enhancement). */
export type RiskLevel = "low" | "medium" | "high";

/**
 * Agent-level risk profile: computed from scope capabilities and audit history.
 * Captures the overall risk an agent poses based on its declared scopes and
 * behavioral patterns.
 */
export interface AgentRiskProfile {
  agentId: string;
  agentRiskLevel: RiskLevel;
  riskScore: number; // 0-100
  riskFactors: string[]; // e.g., ["elevated_scope_present", "secrets_access", "wildcard_scopes"]
  lastAssessedAt: string;
  assessmentMethod: "scope_based" | "behavior_based" | "hybrid";
}

/**
 * Operation-level risk assessment: computed per authorization request.
 * Evaluates the specific request (not the agent's overall capability) to
 * determine if this operation should be approved/flagged/denied.
 */
export interface OperationRiskAssessment {
  operationRiskLevel: RiskLevel;
  operationRiskScore: number; // 0-100
  scopeIntersectionRisk: number; // What is being requested (0-100)
  auditContextRisk: number; // Historical pattern match (0-100)
  operationRiskFactors: string[];
  requiresApproval: boolean;
}

/**
 * Workflow hierarchy node: tracks agent/task relationships and status.
 * Allows audit trail to show which agent/task in the workflow tree
 * triggered each audit event.
 */
export interface WorkflowNode {
  id: string; // nodeId, unique per run
  type: "orchestrator" | "agent" | "task";
  parentId?: string; // parent node (for hierarchy)
  runId: string; // which run/execution
  agentId?: string; // associated agent (if type === "agent")
  status: "queued" | "running" | "completed" | "failed" | "pending_approval";
  riskLevel: RiskLevel; // snapshot of agent's risk at node creation
  createdAt: string;
  completedAt?: string;
  /** Operation-level risk assessment (Phase 1 enhancement). */
  operationRiskLevel?: "low" | "medium" | "high";
  operationRiskScore?: number; // 0-100
  operationRiskFactors?: string[];
  /** Workflow hierarchy tracking (Phase 1 enhancement). */
  nodeId?: string;
  parentNodeId?: string;
}

/**
 * Agent-level risk profile: computed from scope capabilities and audit history.
 * Captures the overall risk an agent poses based on its declared scopes and
 * behavioral patterns.
 */
export interface AgentRiskProfile {
  agentId: string;
  agentRiskLevel: RiskLevel;
  riskScore: number; // 0-100
  riskFactors: string[]; // e.g., ["elevated_scope_present", "secrets_access", "wildcard_scopes"]
  lastAssessedAt: string;
  assessmentMethod: "scope_based" | "behavior_based" | "hybrid";
}

/**
 * Operation-level risk assessment: computed per authorization request.
 * Evaluates the specific request (not the agent's overall capability) to
 * determine if this operation should be approved/flagged/denied.
 */
export interface OperationRiskAssessment {
  operationRiskLevel: RiskLevel;
  operationRiskScore: number; // 0-100
  scopeIntersectionRisk: number; // What is being requested (0-100)
  auditContextRisk: number; // Historical pattern match (0-100)
  operationRiskFactors: string[];
  requiresApproval: boolean;
}

/**
 * Workflow hierarchy node: tracks agent/task relationships and status.
 * Allows audit trail to show which agent/task in the workflow tree
 * triggered each audit event.
 */
export interface WorkflowNode {
  id: string; // nodeId, unique per run
  type: "orchestrator" | "agent" | "task";
  parentId?: string; // parent node (for hierarchy)
  runId: string; // which run/execution
  agentId?: string; // associated agent (if type === "agent")
  status: "queued" | "running" | "completed" | "failed" | "pending_approval";
  riskLevel: RiskLevel; // snapshot of agent's risk at node creation
  createdAt: string;
  completedAt?: string;
}

/** Risk classification for a scope, used to decide auto-grant vs approval. */
export type ScopeRisk = "baseline" | "elevated" | "unknown";

/**
 * Intent-bound permissions plan: the IntentPlanner proposes the minimum scopes
 * for a stated intent; each scope is classified (baseline auto-grant, elevated
 * needs approval, unknown rejected). The user approves a subset; the approved
 * scopes are stored on the Agent.
 */
export interface IntentPlan {
  intent: string;
  requestedScopes: string[];
  baselineScopes: string[];
  elevatedScopes: string[];
  unknownScopes: string[];
  justification: string;
  /** "llm" when the model produced the plan, "fallback" when the deterministic planner was used. */
  source: "llm" | "fallback";
}

export interface Database {
  version: 3;
  agents: Agent[];
  messages: Message[];
  runs: AgentRun[];
  credentials: AgentCredential[];
  mockResources: MockResource[];
  deployStates: DeployState[];
  audit: Audit[];
  workflowNodes: WorkflowNode[]; // NEW in v3
  agentRiskProfiles: AgentRiskProfile[]; // NEW in v3
  users: User[];
}

export interface CreateAgentInput {
  name: string;
  description?: string | undefined;
  instructions?: string | undefined;
  /** The task that drove the scope plan (stored as part of the agent's context). */
  intent?: string | undefined;
  /** Approved scopes (intent-bound). Defaults to read:secrets:<owner> + act:deploy:dev. */
  scopes?: string[] | undefined;
  /** The plan that produced the scopes (stored on the agent for the Permissions card). */
  plan?: IntentPlan | undefined;
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
  progress: AgentProgressEvent[];
}

export interface RunnerRequest {
  agentId: string;
  workspacePath: string;
  prompt: string;
  threadId: string | null;
  proxyPort?: number;
  tightenEgressProxy?: (sourceIp: string) => void;
  onProgress?: (event: AgentProgressEvent) => void | Promise<void>;
}

export interface AgentRunner {
  run(request: RunnerRequest): Promise<RunnerResult>;
  cancel(agentId: string): Promise<boolean>;
  isAvailable(): Promise<boolean>;
}
