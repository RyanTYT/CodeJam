import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  retries: process.env.CI ? 2 : 0,
  reporter: "list",
  use: {
    baseURL: "http://127.0.0.1:5174",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: [
    {
      command: "npm run dev -w @launchpad/server",
      url: "http://127.0.0.1:3100/api/health",
      timeout: 120_000,
      reuseExistingServer: false,
      env: {
        HOST: "127.0.0.1",
        PORT: "3100",
        APP_DATA_DIR: ".playwright/data",
        AGENT_WORKSPACE_ROOT: ".playwright/workspaces",
        CODEX_HOME: ".playwright/codex-home",
        RUNTIME_PROVIDER: "local-process",
        NODE_ENV: "test",
        APP_AUTH_TOKEN: "playwright-test-token-1234567890",
      },
    },
    {
      command: "npm run dev -w @launchpad/web -- --host 127.0.0.1 --port 5174",
      url: "http://127.0.0.1:5174",
      timeout: 120_000,
      reuseExistingServer: false,
      env: {
        VITE_API_TARGET: "http://127.0.0.1:3100",
      },
    },
  ],
});
