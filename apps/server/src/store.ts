import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import type { Database } from "./types.js";

const CURRENT_VERSION = 2;

const emptyDatabase = (): Database => ({
  version: CURRENT_VERSION,
  agents: [],
  messages: [],
  runs: [],
  credentials: [],
  mockResources: [],
  deployStates: [],
  audit: [],
});

/**
 * Migrate a parsed DB document to the current schema. v1 stores have no Bouncer
 * collections and no `ownerId` on agents; existing agents are attributed to the
 * synthetic "default" human principal so the baseline single-user experience
 * keeps working when X-Mock-User is absent. `version` is widened to number so
 * the v1->v2 branch is type-checkable even though the current Database type
 * pins version to the literal `2`.
 */
function migrate(parsed: Partial<Database>): Database {
  const version = parsed.version as number | undefined;
  if (version !== 1 && version !== CURRENT_VERSION) {
    throw new Error("Unsupported database format");
  }
  if (
    !Array.isArray(parsed.agents) ||
    !Array.isArray(parsed.messages) ||
    !Array.isArray(parsed.runs)
  ) {
    throw new Error("Unsupported database format");
  }
  const agents = parsed.agents.map((agent) => ({
    ...agent,
    ownerId: agent.ownerId ?? "default",
  }));
  if (version === CURRENT_VERSION) {
    return {
      version: CURRENT_VERSION,
      agents,
      messages: parsed.messages ?? [],
      runs: parsed.runs ?? [],
      credentials: parsed.credentials ?? [],
      mockResources: parsed.mockResources ?? [],
      deployStates: parsed.deployStates ?? [],
      audit: parsed.audit ?? [],
    };
  }
  return {
    version: CURRENT_VERSION,
    agents,
    messages: parsed.messages ?? [],
    runs: parsed.runs ?? [],
    credentials: [],
    mockResources: [],
    deployStates: [],
    audit: [],
  };
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
