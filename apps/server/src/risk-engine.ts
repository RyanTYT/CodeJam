import { Agent, Audit, AgentRiskProfile, OperationRiskAssessment, RiskLevel } from "./types.js";

/**
 * Risk Classification Engine - Phase 2 of Audit Trail Feature
 *
 * Provides dual-layer risk assessment:
 * 1. Agent-level: 40% scope risk + 30% resource sensitivity + 20% scope breadth + 10% audit history
 * 2. Operation-level: 40% scope intersection + 40% audit context + 20% authority check
 */

/**
 * Determines the risk level of agent scopes
 * Factors: number of scopes, scope generality (wildcards), permission breadth
 */
function determineScopeRisk(agent: Agent): number {
  let risk = 0;

  // More scopes = higher risk
  if (agent.scopes && agent.scopes.length > 0) {
    risk += Math.min(agent.scopes.length * 5, 30); // max 30 points from scope count
  }

  // Wildcard scopes are higher risk
  if (agent.scopes) {
    const wildcardCount = agent.scopes.filter((s: string) => s.includes("*")).length;
    risk += wildcardCount * 10; // 10 points per wildcard
  }

  return Math.min(risk, 100);
}

/**
 * Determines resource sensitivity risk
 * Factors: access to credentials, secrets, user data, infrastructure
 */
function determineResourceSensitivity(agent: Agent): number {
  let risk = 0;
  const scopesStr = (agent.scopes || []).join(" ").toLowerCase();

  // Credential/secret access
  if (scopesStr.includes("credential") || scopesStr.includes("secret") || scopesStr.includes("token")) {
    risk += 35;
  }

  // User/personal data access
  if (scopesStr.includes("user") || scopesStr.includes("profile") || scopesStr.includes("email")) {
    risk += 25;
  }

  // Infrastructure/system access
  if (scopesStr.includes("infrastructure") || scopesStr.includes("system") || scopesStr.includes("cluster")) {
    risk += 20;
  }

  // Write permissions are riskier than read
  if (scopesStr.includes("write") || scopesStr.includes("delete") || scopesStr.includes("update")) {
    risk += 20;
  }

  return Math.min(risk, 100);
}

/**
 * Determines scope breadth risk
 * Factors: number of distinct resource types, API version generality
 */
function determineScopeBreadth(agent: Agent): number {
  let risk = 0;

  if (!agent.scopes || agent.scopes.length === 0) {
    return 0; // No scopes = minimal breadth risk
  }

  // Count distinct resource types (split by "/")
  const resourceTypes = new Set<string>();
  agent.scopes.forEach((scope: string) => {
    const parts = scope.split("/");
    if (parts.length > 0 && parts[0]) {
      resourceTypes.add(parts[0]);
    }
  });

  // More resource types = higher breadth risk
  risk += Math.min(resourceTypes.size * 15, 50);

  return Math.min(risk, 100);
}

/**
 * Determines audit history signal
 * Factors: past deny decisions, suspicious patterns, frequency of operations
 */
function determineAuditHistorySignal(recentAudit: Audit[]): number {
  if (!recentAudit || recentAudit.length === 0) {
    return 0; // No history = neutral signal
  }

  let risk = 0;

  // Denied operations suggest risky behavior
  const deniedCount = recentAudit.filter((a) => a.decision === "deny").length;
  risk += deniedCount * 15; // 15 points per denial

  // High frequency of operations in short time = suspicious
  const recentWindow = 1000 * 60 * 60; // 1 hour
  const now = Date.now();
  const recentOps = recentAudit.filter((a) => now - new Date(a.timestamp).getTime() < recentWindow);
  if (recentOps.length > 10) {
    risk += 20; // Unusually high frequency
  }

  // Repeated failed attempts on same resource = concerning pattern
  const resourceDenials = new Map<string, number>();
  recentAudit.filter((a) => a.decision === "deny").forEach((a) => {
    const key = `${a.resource}-${a.method}`;
    resourceDenials.set(key, (resourceDenials.get(key) || 0) + 1);
  });
  const repeatedFailures = Array.from(resourceDenials.values()).filter((count) => count > 2).length;
  risk += repeatedFailures * 10;

  return Math.min(risk, 100);
}

/**
 * Converts numerical risk score (0-100) to risk level
 */
function scoreToLevel(score: number): RiskLevel {
  if (score < 35) return "low";
  if (score < 65) return "medium";
  return "high";
}

/**
 * Calculates agent-level risk profile
 * Used at agent creation and when agent scopes change
 */
export function calculateAgentRiskProfile(agent: Agent, recentAudit: Audit[]): AgentRiskProfile {
  // 40% scope risk + 30% resource sensitivity + 20% scope breadth + 10% audit history
  const scopeRisk = determineScopeRisk(agent);
  const resourceSensitivity = determineResourceSensitivity(agent);
  const scopeBreadth = determineScopeBreadth(agent);
  const auditSignal = determineAuditHistorySignal(recentAudit);

  const riskScore = Math.round(scopeRisk * 0.4 + resourceSensitivity * 0.3 + scopeBreadth * 0.2 + auditSignal * 0.1);

  const riskFactors: string[] = [];
  if (scopeRisk > 40) riskFactors.push("broad scope access");
  if (resourceSensitivity > 40) riskFactors.push("sensitive resource access");
  if (scopeBreadth > 40) riskFactors.push("wide resource coverage");
  if (auditSignal > 40) riskFactors.push("concerning audit history");

  return {
    agentId: agent.id,
    agentRiskLevel: scoreToLevel(riskScore),
    riskScore,
    riskFactors,
    lastAssessedAt: new Date().toISOString(),
    assessmentMethod: "hybrid",
  };
}

/**
 * Assesses operation-level risk for a single request
 * 40% scope intersection + 40% audit context + 20% authority check
 */
export function assessOperationRisk(
  agent: Agent,
  agentProfile: AgentRiskProfile,
  requestedResource: string,
  requestedMethod: string,
  recentAudit: Audit[]
): OperationRiskAssessment {
  // 1. Scope intersection risk (40%)
  // How much does the requested resource overlap with agent's authorized scopes?
  let scopeIntersectionRisk = 0;

  if (agent.scopes && agent.scopes.length > 0) {
    const matchesScope = agent.scopes.some((scope) => {
      // Simple matching: exact match or wildcard match
      if (scope === "*") return true;
      if (scope === requestedResource) return true;

      // Wildcard matching (e.g., "users/*" matches "users/123")
      const scopePattern = scope.replace(/\*/g, ".*");
      const regex = new RegExp(`^${scopePattern}$`);
      return regex.test(requestedResource);
    });

    if (!matchesScope) {
      scopeIntersectionRisk = 95; // Requested resource outside scopes = very high risk
    } else {
      // Resource is in scope but we still evaluate breadth
      // Wide scopes (wildcards) are higher risk for any single operation
      const hasWildcard = agent.scopes.some((s) => s.includes("*"));
      scopeIntersectionRisk = hasWildcard ? 35 : 15;
    }
  } else {
    scopeIntersectionRisk = 100; // No scopes at all = maximum risk
  }

  // 2. Audit context risk (40%)
  // Is there suspicious pattern in this agent's recent audit trail?
  let auditContextRisk = 0;

  const agentAudit = recentAudit.filter((a) => a.agentId === agent.id);
  if (agentAudit.length === 0) {
    auditContextRisk = 20; // New agent, neutral risk
  } else {
    const recentWindow = 1000 * 60 * 15; // 15 minutes
    const now = Date.now();
    const recentOps = agentAudit.filter((a) => now - new Date(a.timestamp).getTime() < recentWindow);

    const deniedCount = agentAudit.filter((a) => a.decision === "deny").length;
    const deniedRatio = agentAudit.length > 0 ? deniedCount / agentAudit.length : 0;

    if (deniedRatio > 0.3) {
      auditContextRisk += 40; // >30% denial rate is suspicious
    }

    if (recentOps.length > 5) {
      auditContextRisk += 25; // High frequency in short window
    }

    // Check for repeated failures on similar resources
    const sameResourceDenials = agentAudit
      .filter((a: Audit) => a.decision === "deny" && a.resource === requestedResource)
      .slice(-5); // Last 5 attempts on this resource
    if (sameResourceDenials.length > 2) {
      auditContextRisk += 30; // Multiple failures on same resource
    }
  }

  auditContextRisk = Math.min(auditContextRisk, 100);

  // 3. Authority check risk (20%)
  // Does the agent have proper authority for this operation?
  let authorityCheckRisk = 0;

  // Check if operation type (GET/POST/DELETE) matches scope permissions
  const scopesStr = (agent.scopes || []).join(" ").toLowerCase();
  const isWriteOp = ["post", "put", "patch", "delete"].includes(requestedMethod.toLowerCase());
  const hasWritePermission = scopesStr.includes("write") || scopesStr.includes("update") || scopesStr.includes("delete");

  if (isWriteOp && !hasWritePermission && scopesStr.includes("read")) {
    authorityCheckRisk = 85; // Read-only agent attempting write = high risk
  } else if (isWriteOp && hasWritePermission) {
    authorityCheckRisk = 15; // Write operation with write permission = low risk
  } else if (!isWriteOp) {
    authorityCheckRisk = 10; // Read operation = low risk generally
  }

  // Combined operation risk score: 40% scope + 40% audit context + 20% authority
  const operationRiskScore = Math.round(
    scopeIntersectionRisk * 0.4 + auditContextRisk * 0.4 + authorityCheckRisk * 0.2
  );

  const operationRiskFactors: string[] = [];
  if (scopeIntersectionRisk > 50) operationRiskFactors.push("resource outside authorized scopes");
  if (auditContextRisk > 50) operationRiskFactors.push("suspicious audit pattern");
  if (authorityCheckRisk > 50) operationRiskFactors.push("operation type not authorized");

  const operationRiskLevel = scoreToLevel(operationRiskScore);
  const requiresApproval = operationRiskLevel === "high" || operationRiskScore > 75;

  return {
    operationRiskLevel,
    operationRiskScore,
    scopeIntersectionRisk,
    auditContextRisk,
    operationRiskFactors: operationRiskFactors.length > 0 ? operationRiskFactors : ["no specific risk factors"],
    requiresApproval,
  };
}
