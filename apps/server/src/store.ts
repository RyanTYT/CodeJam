import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import type { Database } from "./types.js";

const CURRENT_VERSION = 3;
const CURRENT_VERSION = 3;

const emptyDatabase = (): Database => ({
  version: CURRENT_VERSION,
  agents: [],
  messages: [],
  runs: [],
  credentials: [],
  mockResources: [],
  deployStates: [],
  audit: [],
  users: [],
  workflowNodes: [],
  agentRiskProfiles: [],
});

/**
 * Migrate a parsed DB document to the current schema. v1 stores have no Bouncer
 * collections and no `ownerId` on agents; existing agents are attributed to the
 * synthetic "default" human principal so the baseline single-user experience
 * keeps working when X-Mock-User is absent. v2→v3 adds risk profiling and
 * workflow hierarchy tracking for the audit trail feature.
 */
function migrate(parsed: Partial<Database>): Database {
  const version = parsed.version as number | undefined;
  if (version !== 1 && version !== 2 && version !== CURRENT_VERSION) {
  if (version !== 1 && version !== 2 && version !== CURRENT_VERSION) {
    throw new Error("Unsupported database format");
  }
  if (
    !Array.isArray(parsed.agents) ||
    !Array.isArray(parsed.messages) ||
    !Array.isArray(parsed.runs)
  ) {
    throw new Error("Unsupported database format");
  }
  const agents = parsed.agents.map((agent) => {
    const ownerId = agent.ownerId ?? "default";
    const baseScopes = agent.scopes ?? [`read:secrets:${ownerId}`, "act:deploy:dev"];
    return {
      ...agent,
      ownerId,
      scopes: [...new Set(baseScopes)],
      plan: agent.plan ?? null,
    };
  });
  if (version === CURRENT_VERSION) {
    return {
      version: CURRENT_VERSION,
      agents,
      messages: parsed.messages ?? [],
      runs: parsed.runs ?? [],
      credentials: parsed.credentials ?? [],
      mockResources: (parsed.mockResources ?? []).map((resource) => {
        const legacy = resource as { owner?: unknown; key?: unknown };
        const owner = typeof legacy.owner === "string" ? legacy.owner : "";
        const key = typeof legacy.key === "string" ? legacy.key : "";
        return {
          key: owner.length > 0 ? `${owner}/${key}` : key,
          value: resource.value,
          redactedView: resource.redactedView,
        };
      }),
      deployStates: parsed.deployStates ?? [],
      audit: parsed.audit ?? [],
      // Normalize legacy users that predate the per-user `scopes` field so the
      // User type (scopes: string[]) always holds an array at runtime.
      users: (parsed.users ?? []).map((user) => ({
        ...user,
        scopes: Array.isArray(user.scopes) ? user.scopes : [],
      })),
      workflowNodes: parsed.workflowNodes ?? [],
      agentRiskProfiles: parsed.agentRiskProfiles ?? [],
    };
  }
  // v1 or v2 → v3 migration
  const baseDatabase: Database = {
    version: 3,
    agents,
    messages: parsed.messages ?? [],
    runs: parsed.runs ?? [],
    credentials: parsed.credentials ?? [],
    mockResources: parsed.mockResources ?? [],
    deployStates: parsed.deployStates ?? [],
    audit: parsed.audit ?? [],
    workflowNodes: [],
    agentRiskProfiles: [],
    users: [],
  };

  return baseDatabase;

  return baseDatabase;
}

export class JsonStore {
  private data: Database = emptyDatabase();
  private queue: Promise<void> = Promise.resolve();

  constructor(private readonly filePath: string) {}

  async initialize(): Promise<void> {
    await mkdir(path.dirname(this.filePath), { recursive: true });
    try {
      const raw = await readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw) as Partial<Database>;
      const migrated = migrate(parsed);
      const wasUpgraded = (parsed.version as number | undefined) === 1;
      this.data = migrated;
      if (wasUpgraded) {
        await this.persist();
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw error;
      }
      await this.persist();
    }
  }

  snapshot(): Database {
    return structuredClone(this.data);
  }

  async mutate<T>(mutation: (database: Database) => T | Promise<T>): Promise<T> {
    let result!: T;
    const operation = this.queue.then(async () => {
      const next = structuredClone(this.data);
      result = await mutation(next);
      await this.persist(next);
      this.data = next;
    });
    this.queue = operation.catch(() => undefined);
    await operation;
    return result;
  }

  private async persist(data: Database = this.data): Promise<void> {
    const temporaryPath = this.filePath + ".tmp";
    await writeFile(temporaryPath, JSON.stringify(data, null, 2) + "\n", {
      encoding: "utf-8",
      mode: 0o600,
    });
    await rename(temporaryPath, this.filePath);
  }
}
