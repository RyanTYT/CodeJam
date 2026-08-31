import type { AppConfig } from "./config.js";
import { isArkConfigured } from "./config.js";
import type { IntentPlan, ScopeRisk } from "./types.js";

export type { ScopeRisk };

export interface TaxonomyEntry {
  scope: string;
  risk: "baseline" | "elevated";
  description: string;
}

/**
 * The per-key taxonomy for the centralized secret store: for each secret, a
 * baseline `read:` and an elevated `write:`; plus the deploy scopes. Dynamic
 * because it depends on the vault's actual contents. Secrets are global (not
 * user-owned), so there is no own/cross-user distinction.
 */
export function taxonomyFor(
  secretKeys: readonly string[] = [],
): TaxonomyEntry[] {
  const entries: TaxonomyEntry[] = [];
  for (const key of secretKeys) {
    entries.push({
      scope: `read:secrets:${key}`,
      risk: "baseline",
      description: `read the centralized secret "${key}"`,
    });
    entries.push({
      scope: `write:secrets:${key}`,
      risk: "elevated",
      description: `write the centralized secret "${key}"`,
    });
  }
  entries.push({ scope: "act:deploy:dev", risk: "baseline", description: "deploy to the dev environment" });
  entries.push({ scope: "act:deploy:prod", risk: "elevated", description: "deploy to prod" });
  return entries;
}

/**
 * Classify a concrete scope. With centralized secrets there is no
 * own/cross-user axis: any `read:secrets:<key>` is baseline; any write is
 * elevated; deploy dev is baseline, prod elevated; anything else is unknown
 * (rejected, never granted).
 */
export function classifyScope(scope: string): ScopeRisk {
  if (/^read:secrets:.+/.test(scope)) return "baseline";
  if (/^write:secrets:.+/.test(scope)) return "elevated";
  if (scope === "act:deploy:dev") return "baseline";
  if (scope === "act:deploy:prod") return "elevated";
  return "unknown";
}

interface ProposedPlan {
  scopes: string[];
  justification: string;
  source: "llm" | "fallback";
}

/**
 * Intent-bound permissions planner. Given a free-text intent + the vault's
 * secret keys, proposes the MINIMUM per-key scopes an agent needs. Calls the
 * configured Ark model; on any failure falls back to a deterministic
 * keyword→per-key-scope planner. Every proposed scope is then classified —
 * baseline auto-grants, elevated need approval, unknown is rejected — so the
 * LLM cannot grant a scope the taxonomy doesn't know.
 */
export class IntentPlanner {
  constructor(private readonly config: AppConfig) {}

  async plan(
    intent: string,
    secretKeys: readonly string[] = [],
  ): Promise<IntentPlan> {
    let proposed: ProposedPlan;
    if (isArkConfigured(this.config)) {
      proposed = await this.planWithLlm(intent, secretKeys).catch(() =>
        this.planFallback(intent, secretKeys),
      );
      if (proposed.scopes.length === 0) proposed = this.planFallback(intent, secretKeys);
    } else {
      proposed = this.planFallback(intent, secretKeys);
    }
    return this.classify(intent, proposed);
  }

  private async planWithLlm(
    intent: string,
    secretKeys: readonly string[],
  ): Promise<ProposedPlan> {
    const taxonomy = taxonomyFor(secretKeys)
      .map((entry) => `- ${entry.scope} (${entry.risk}): ${entry.description}`)
      .join("\n");
    const prompt = [
      "You are a least-privilege permissions planner for an AI coding agent.",
      `The user wants the agent to: "${intent}".`,
      "",
      "Available scopes:",
      taxonomy,
      "",
      "Pick the MINIMUM set of scopes the agent needs. Return ONLY JSON, no prose:",
      '{"scopes": ["..."], "justification": "one sentence"}',
    ].join("\n");

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);
    timeout.unref();
    try {
      const res = await fetch(`${this.config.arkBaseUrl}/responses`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer " + this.config.arkApiKey,
        },
        body: JSON.stringify({ model: this.config.arkModel, input: prompt }),
        signal: controller.signal,
      });
      if (!res.ok) throw new Error(`Ark responded ${res.status}`);
      const data = (await res.json()) as unknown;
      const text = extractOutputText(data);
      const parsed = parseScopesJson(text);
      if (parsed.scopes.length === 0) throw new Error("model returned no parseable scopes");
      return { scopes: parsed.scopes, justification: parsed.justification, source: "llm" };
    } finally {
      clearTimeout(timeout);
    }
  }

  /** Deterministic per-key fallback: match the intent's keywords to vault secrets. */
  private planFallback(
    intent: string,
    secretKeys: readonly string[],
  ): ProposedPlan {
    const lower = intent.toLowerCase();
    const scopes = new Set<string>();
    const wantsRead = /\b(read|fetch|get|db|database|secret|url|connection|retrieve)/.test(lower);
    const wantsWrite = /\b(write|update|delete|rotate|replace|change|migrate|insert|seed|modify)/.test(lower);
    for (const key of secretKeys) {
      const klower = key.toLowerCase();
      const parts = klower
        .split(/[^a-z0-9]+/)
        .filter((part) => part.length >= 3 && !["api", "db", "key", "token", "url"].includes(part));
      const mentioned = lower.includes(klower) || parts.some((part) => new RegExp(`\\b${part}\\b`).test(lower));
      if (mentioned && wantsRead) scopes.add(`read:secrets:${key}`);
      if (mentioned && wantsWrite) scopes.add(`write:secrets:${key}`);
    }
    // Never grant an arbitrary secret just to make a plan non-empty. The user
    // must name a resource, or explicitly select one in the permissions plan.
    const declinesDeploy = /\b(?:do not|don't|never|without|no)\s+(?:\w+\s+){0,3}(?:deploy(?:ing|ed|s)?|ship(?:ping|ped|s)?|release(?:d|s)?)\b/.test(lower);
    const declinesProd = /\b(?:do not|don't|never|without|no)\s+(?:\w+\s+){0,5}(?:prod|production)\b/.test(lower);
    const requestsDeploy = /\b(deploy(?:ing|ed|s)?|ship(?:ping|ped|s)?|release(?:d|s)?)\b/.test(lower) && !declinesDeploy;
    const requestsProd = /\b(prod|production)\b/.test(lower) && !declinesProd;
    if (requestsDeploy) {
      scopes.add(requestsProd ? "act:deploy:prod" : "act:deploy:dev");
    }
    return {
      scopes: [...scopes],
      justification:
        "Fallback planner: derived the minimum per-key scopes from keywords in the intent (the model was unavailable or its output was unparseable).",
      source: "fallback",
    };
  }

  private classify(intent: string, proposed: ProposedPlan): IntentPlan {
    const baseline: string[] = [];
    const elevated: string[] = [];
    const unknown: string[] = [];
    const seen = new Set<string>();
    for (const scope of proposed.scopes) {
      if (seen.has(scope)) continue;
      seen.add(scope);
      const risk = classifyScope(scope);
      if (risk === "baseline") baseline.push(scope);
      else if (risk === "elevated") elevated.push(scope);
      else unknown.push(scope);
    }
    return {
      intent,
      requestedScopes: [...baseline, ...elevated, ...unknown],
      baselineScopes: baseline,
      elevatedScopes: elevated,
      unknownScopes: unknown,
      justification: proposed.justification,
      source: proposed.source,
    };
  }
}

/** Tolerantly extract the model's text from an OpenAI/Ark Responses-API body. */
function extractOutputText(data: unknown): string {
  if (typeof data !== "object" || data === null) return "";
  const root = data as Record<string, unknown>;
  if (typeof root.output_text === "string") return root.output_text;
  const output = root.output;
  if (Array.isArray(output)) {
    for (const item of output) {
      if (typeof item !== "object" || item === null) continue;
      const entry = item as Record<string, unknown>;
      const content = entry.content;
      if (Array.isArray(content)) {
        for (const part of content) {
          if (typeof part === "object" && part !== null) {
            const text = (part as Record<string, unknown>).text;
            if (typeof text === "string") return text;
          }
        }
      }
      if (typeof entry.text === "string") return entry.text;
    }
  }
  return "";
}

/** Pull the first {...} object out of the model's text and parse {scopes, justification}. */
function parseScopesJson(text: string): { scopes: string[]; justification: string } {
  const match = text.match(/\{[\s\S]*\}/);
  const json = match ? (match[0] ?? "") : "";
  if (!json) return { scopes: [], justification: "" };
  try {
    const parsed = JSON.parse(json) as { scopes?: unknown; justification?: unknown };
    const scopes = Array.isArray(parsed.scopes)
      ? parsed.scopes.filter((scope): scope is string => typeof scope === "string")
      : [];
    const justification = typeof parsed.justification === "string" ? parsed.justification : "";
    return { scopes, justification };
  } catch {
    return { scopes: [], justification: "" };
  }
}
