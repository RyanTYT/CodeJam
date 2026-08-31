import type { Agent, AgentRun, Audit, IntentPlan, Message, Secret, SystemInfo, User } from "./types";

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
  }
}

let authToken = "";
let mockUser = "";

export function setAuthToken(token: string): void {
  authToken = token.trim();
}

export function setMockUser(user: string): void {
  mockUser = user.trim();
}

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const headers = {
    ...(options?.body ? { "Content-Type": "application/json" } : {}),
    ...(authToken ? { Authorization: "Bearer " + authToken } : {}),
    ...(mockUser ? { "X-Mock-User": mockUser } : {}),
    ...options?.headers,
  };
  const response = await fetch(url, {
    ...options,
    headers,
  });
  const data = (await response.json().catch(() => ({}))) as T & { error?: string };
  if (!response.ok) {
    throw new ApiError(data.error ?? "Request failed", response.status);
  }
  return data;
}

export const api = {
  auth: () => request<{ required: boolean }>("/api/auth"),
  system: () => request<SystemInfo>("/api/system"),
  listAgents: () => request<{ agents: Agent[] }>("/api/agents"),
  createAgent: (body: {
    name: string;
    description?: string;
    instructions?: string;
    intent?: string;
    scopes?: string[];
    plan?: IntentPlan;
  }) =>
    request<{ agent: Agent }>("/api/agents", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  removeScope: (id: string, scope: string) =>
    request<{ agent: Agent }>("/api/agents/" + id + "/scopes/revoke", {
      method: "POST",
      body: JSON.stringify({ scope }),
    }),
  listSecrets: () => request<{ secrets: Secret[] }>("/api/secrets"),
  addSecret: (key: string, value: string, redactedView: string | undefined) =>
    request<{ secret: Secret }>("/api/secrets", {
      method: "POST",
      body: JSON.stringify({ key, value, redactedView }),
    }),
  revokeSecret: (key: string) =>
    request<{ deleted: boolean }>("/api/secrets/revoke", {
      method: "POST",
      body: JSON.stringify({ key }),
    }),
  listUsers: () => request<{ users: User[] }>("/api/users"),
  addUser: (userId: string, role: "admin" | "user", scopes?: string[]) =>
    request<{ user: User }>("/api/users", {
      method: "POST",
      body: JSON.stringify({ userId, role, scopes }),
    }),
  grantUserScope: (userId: string, scope: string) =>
    request<{ user: User }>("/api/users/" + userId + "/scopes/grant", {
      method: "POST",
      body: JSON.stringify({ scope }),
    }),
  revokeUserScope: (userId: string, scope: string) =>
    request<{ user: User }>("/api/users/" + userId + "/scopes/revoke", {
      method: "POST",
      body: JSON.stringify({ scope }),
    }),
  me: () => request<{ user: { userId: string; role: "admin" | "user" } }>("/api/me"),
  planAgent: (intent: string) =>
    request<{ plan: IntentPlan }>("/api/agents/plan", {
      method: "POST",
      body: JSON.stringify({ intent }),
    }),
  updateAgent: (
    id: string,
    body: { name: string; description: string; instructions: string },
  ) =>
    request<{ agent: Agent }>("/api/agents/" + id, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deleteAgent: (id: string) =>
    request<{ archivedWorkspace: string }>("/api/agents/" + id, {
      method: "DELETE",
    }),
  startAgent: (id: string) =>
    request<{ agent: Agent }>("/api/agents/" + id + "/start", {
      method: "POST",
    }),
  stopAgent: (id: string) =>
    request<{ agent: Agent }>("/api/agents/" + id + "/stop", {
      method: "POST",
    }),
  revokeCredential: (id: string) =>
    request<{ revoked: boolean }>("/api/agents/" + id + "/revoke-credential", {
      method: "POST",
    }),
  messages: (id: string) =>
    request<{ messages: Message[] }>("/api/agents/" + id + "/messages"),
  runs: (id: string) =>
    request<{ runs: AgentRun[] }>("/api/agents/" + id + "/runs"),
  sendMessage: (id: string, content: string) =>
    request<{ run: AgentRun; message: Message }>(
      "/api/agents/" + id + "/messages",
      {
        method: "POST",
        body: JSON.stringify({ content }),
      },
    ),
  run: (id: string) => request<{ run: AgentRun }>("/api/runs/" + id),
  audit: (agentId?: string) =>
    request<{ audit: Audit[] }>(
      "/api/audit" + (agentId ? "?agentId=" + encodeURIComponent(agentId) : ""),
    ),
};
