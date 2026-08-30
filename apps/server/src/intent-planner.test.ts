import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
import { classifyScope, IntentPlanner } from "./intent-planner.js";

describe("classifyScope", () => {
  it("treats own read as baseline and cross-user read as elevated", () => {
    expect(classifyScope("read:secrets:alice", "alice")).toBe("baseline");
    expect(classifyScope("read:secrets:bob", "alice")).toBe("elevated");
  });

  it("treats any write as elevated", () => {
    expect(classifyScope("write:secrets:alice", "alice")).toBe("elevated");
    expect(classifyScope("write:secrets:bob", "alice")).toBe("elevated");
  });

  it("treats deploy:dev as baseline and deploy:prod as elevated", () => {
    expect(classifyScope("act:deploy:dev", "alice")).toBe("baseline");
    expect(classifyScope("act:deploy:prod", "alice")).toBe("elevated");
  });

  it("rejects unknown scopes", () => {
    expect(classifyScope("admin:system", "alice")).toBe("unknown");
    expect(classifyScope("read:secrets", "alice")).toBe("unknown");
    expect(classifyScope("act:deploy:staging", "alice")).toBe("unknown");
  });
});

describe("IntentPlanner (fallback — Ark is not configured in tests)", () => {
  const planner = new IntentPlanner(loadConfig({ NODE_ENV: "test" }));

  it("derives read + deploy:dev (both baseline) for a benign build intent", async () => {
    const plan = await planner.plan(
      "build a todo app that reads my DB url and deploys to dev",
      "alice",
      ["db-url"],
    );
    expect(plan.source).toBe("fallback");
    expect(plan.baselineScopes).toContain("read:secrets:alice/db-url");
    expect(plan.baselineScopes).toContain("act:deploy:dev");
    expect(plan.elevatedScopes).toEqual([]);
    expect(plan.unknownScopes).toEqual([]);
  });

  it("flags write + deploy:prod as elevated for a prod intent", async () => {
    const plan = await planner.plan(
      "migrate the prod DB and deploy to prod",
      "alice",
      ["db-url"],
    );
    expect(plan.elevatedScopes).toContain("write:secrets:alice/db-url");
    expect(plan.elevatedScopes).toContain("act:deploy:prod");
  });

  it("defaults to read own secrets when no keyword matches", async () => {
    const plan = await planner.plan("hello world", "alice");
    expect(plan.requestedScopes).toContain("read:secrets:alice");
  });

  it("never grants a scope the taxonomy doesn't know", async () => {
    const plan = await planner.plan("do something benign", "alice");
    expect(plan.unknownScopes).toEqual([]);
    for (const scope of plan.requestedScopes) {
      expect(classifyScope(scope, "alice")).not.toBe("unknown");
    }
  });
});
