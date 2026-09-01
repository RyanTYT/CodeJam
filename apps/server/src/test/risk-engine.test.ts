import { describe, expect, it } from "vitest";
import { assessOperationRisk, calculateAgentRiskProfile } from "../risk-engine.js";
import type { Agent } from "../types.js";

function agentWithScopes(scopes: string[]): Agent {
  return {
    id: "agent-1",
    name: "Risk test Agent",
    description: "",
    instructions: "",
    status: "ready",
    ownerId: "alice",
    scopes,
    plan: null,
    workspacePath: "/tmp/workspace",
    codexThreadId: null,
    lastError: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
}

describe("operation risk assessment", () => {
  it("keeps a scoped secret read low risk", () => {
    const agent = agentWithScopes(["read:secrets:dev-db-url"]);
    const assessment = assessOperationRisk(
      agent,
      calculateAgentRiskProfile(agent, []),
      "secrets:dev-db-url",
      "read:secrets:dev-db-url",
      [],
    );

    expect(assessment.operationRiskLevel).toBe("low");
    expect(assessment.operationRiskScore).toBeLessThan(35);
  });

  it("flags a permitted production deployment as high risk", () => {
    const agent = agentWithScopes(["act:deploy:prod"]);
    const assessment = assessOperationRisk(
      agent,
      calculateAgentRiskProfile(agent, []),
      "deploy:prod",
      "act:deploy:prod",
      [],
    );

    expect(assessment.operationRiskLevel).toBe("high");
    expect(assessment.operationRiskFactors).toContain("production deployment");
    expect(assessment.requiresApproval).toBe(true);
  });
});
