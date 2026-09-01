import { expect, test, type Page } from "@playwright/test";

const operatorToken = "playwright-test-token-1234567890";
const apiBase = "http://127.0.0.1:3100";

async function apiRequest(
  path: string,
  user: string,
  options: RequestInit = {},
): Promise<Response> {
  return fetch(apiBase + path, {
    ...options,
    headers: {
      authorization: `Bearer ${operatorToken}`,
      "content-type": "application/json",
      "x-mock-user": user,
      ...options.headers,
    },
  });
}

async function createAgent(user: string, name: string): Promise<string> {
  const response = await apiRequest("/api/agents", user, {
    method: "POST",
    body: JSON.stringify({ name, scopes: ["read:secrets:dev-db-url"] }),
  });
  expect(response.ok).toBe(true);
  const body = (await response.json()) as { agent: { id: string } };
  return body.agent.id;
}

async function unlock(page: Page): Promise<void> {
  await page.getByLabel("Access token").fill(operatorToken);
  await page.getByRole("button", { name: "Open Launchpad" }).click();
  await expect(page.getByText("Mock user")).toBeVisible();
}

test.describe("IAM audit log UI", () => {
  let aliceAgentName = "";
  let bobAgentName = "";

  test.beforeEach(async ({ page }) => {
    const suffix = Date.now().toString();
    aliceAgentName = "Alice Audit Agent " + suffix;
    bobAgentName = "Bob Audit Agent " + suffix;
    await createAgent("alice", aliceAgentName);
    await createAgent("bob", bobAgentName);
    await page.goto("/");
    await unlock(page);
  });

  test("shows a user's own agent logs and selected IAM detail", async ({ page }) => {
    await page.getByRole("button", { name: "alice", exact: true }).click();
    await page.locator(".agent-card").filter({ hasText: aliceAgentName }).click();
    await page.getByRole("button", { name: "Logs", exact: true }).click();

    await expect(page.getByText("Agent log stream")).toBeVisible();
    await page.getByRole("button", { name: /Expand/ }).click();
    const rows = page.locator(".log-list-item");
    await expect(rows.first()).toBeVisible();
    await expect(rows.first()).toContainText("alice");
    await expect(rows.first()).toContainText(aliceAgentName);
    await rows.first().click();

    const detail = page.locator(".policy-console");
    await expect(detail.getByText("Activity Detail")).toBeVisible();
    await expect(detail.getByText("User", { exact: true })).toBeVisible();
    await expect(detail.getByText("Agent", { exact: true })).toBeVisible();
    await expect(detail.getByText("Capability", { exact: true })).toBeVisible();
    await expect(detail.getByText("Risk factors", { exact: true })).toBeVisible();
  });

  test("admin Logs shows activity across all users and agents", async ({ page }) => {
    await page.getByRole("button", { name: "admin", exact: true }).click();
    await page.getByRole("button", { name: "Logs", exact: true }).click();

    await expect(page.getByRole("heading", { name: "All agent activity", level: 2 })).toBeVisible();
    const rows = page.locator(".admin-log-list .log-list-item");
    await expect(rows.filter({ hasText: aliceAgentName }).first()).toBeVisible();
    await expect(rows.filter({ hasText: bobAgentName }).first()).toBeVisible();
    await rows.filter({ hasText: aliceAgentName }).first().click();

    await expect(page.getByText("Activity Detail")).toBeVisible();
    await expect(page.locator(".focused-log-detail").getByText("alice", { exact: true })).toBeVisible();
  });

  test("admin Secrets hides the audit side panel", async ({ page }) => {
    await page.getByRole("button", { name: "admin", exact: true }).click();
    await page.getByRole("button", { name: "Secrets", exact: true }).click();

    await expect(page.getByRole("heading", { name: "Centralized secrets" })).toBeVisible();
    await expect(page.locator(".policy-console")).toHaveCount(0);
  });
});
