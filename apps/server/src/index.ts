import path from "node:path";
import { AgentService } from "./agent-service.js";
import { createApp } from "./app.js";
import { loadConfig, writeCodexConfig } from "./config.js";
import { createRunner } from "./runner-factory.js";
import { JsonStore } from "./store.js";
import { WorkspaceManager } from "./workspace.js";
import { MockResourceService } from "./mock-resource-service.js";
import { createMockApp } from "./mock-resource-server.js";
import { IntentPlanner } from "./intent-planner.js";

const config = loadConfig();
await writeCodexConfig(config);

const store = new JsonStore(path.join(config.dataDirectory, "launchpad.json"));
const workspaces = new WorkspaceManager(config.workspaceRoot);
const runner = createRunner(config);
const mockResourceService = new MockResourceService(config, store);
const intentPlanner = new IntentPlanner(config);
const service = new AgentService(config, store, workspaces, runner, mockResourceService, intentPlanner);
await service.initialize();

const app = await createApp(config, service);
const mockApp = await createMockApp(mockResourceService);

const shutdown = async (signal: string) => {
  app.log.info({ signal }, "Shutting down");
  await Promise.allSettled([mockApp.close(), app.close()]);
  process.exit(0);
};

process.on("SIGTERM", () => void shutdown("SIGTERM"));
process.on("SIGINT", () => void shutdown("SIGINT"));

await app.listen({ host: config.host, port: config.port });
await mockApp.listen({ host: config.mockResourceHost, port: config.mockResourcePort });
app.log.info(
  { host: config.mockResourceHost, port: config.mockResourcePort },
  "Mock resource service listening (agent-facing, no bearer hook)",
);
