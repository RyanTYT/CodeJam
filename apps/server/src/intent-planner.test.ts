import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
import { classifyScope, IntentPlanner } from "./intent-planner.js";

describe("classifyScope", () => {
  it("treats any read of a centralized secret as baseline", () => {
    expect(classifyScope("read:secrets:dev-db-url")).toBe("baseline");
    expect(classifyScope("read:secrets:prod-db-url")).toBe("baseline");
  });

  it("treats any write as elevated", () => {
    expect(classifyScope("write:secrets:dev-db-url")).toBe("elevated");
    expect(classifyScope("write:secrets:prod-db-url")).toBe("elevated");
  });

  it("treats deploy:dev as baseline and deploy:prod as elevated", () => {
    expect(classifyScope("act:deploy:dev")).toBe("baseline");
    expect(classifyScope("act:deploy:prod")).toBe("elevated");
  });

  it("rejects unknown scopes", () => {
    expect(classifyScope("admin:system")).toBe("unknown");
    expect(classifyScope("read:secrets")).toBe("unknown");
    expect(classifyScope("act:deploy:staging")).toBe("unknown");
  });
});

describe("IntentPlanner (fallback — Ark is not configured in tests)", () => {
  const planner = new IntentPlanner(loadConfig({ NODE_ENV: "test" }));

  it("derives read + deploy:dev (both baseline) for a benign build intent", async () => {
    const plan = await planner.plan(
      "build a todo app that reads my DB url and deploys to dev",
      ["dev-db-url", "prod-db-url", "api-token"],
    );
    expect(plan.source).toBe("fallback");
    expect(plan.baselineScopes).toContain("read:secrets:dev-db-url");
    expect(plan.baselineScopes).toContain("act:deploy:dev");
    expect(plan.elevatedScopes).toEqual([]);
    expect(plan.unknownScopes).toEqual([]);
  });

  it("flags write + deploy:prod as elevated for a prod intent", async () => {
    const plan = await planner.plan(
      "migrate the prod DB and deploy to prod",
      ["dev-db-url", "prod-db-url", "api-token"],
    );
    expect(plan.elevatedScopes).toContain("write:secrets:prod-db-url");
    expect(plan.elevatedScopes).toContain("act:deploy:prod");
  });

  it("defaults to reading the first secret when no keyword matches", async () => {
    const plan = await planner.plan("hello world", ["dev-db-url", "prod-db-url"]);
    expect(plan.requestedScopes).toContain("read:secrets:dev-db-url");
  });

  it("never grants a scope the taxonomy doesn't know", async () => {
    const plan = await planner.plan("do something benign", ["dev-db-url"]);
    expect(plan.unknownScopes).toEqual([]);
    for (const scope of plan.requestedScopes) {
      expect(classifyScope(scope)).not.toBe("unknown");
    }
  });
});
