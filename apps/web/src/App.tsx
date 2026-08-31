import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError, setAuthToken, setMockUser } from "./api";
import type { Agent, AgentRun, Audit, IntentPlan, Message, Secret, SystemInfo, User, WorkflowNode } from "./types";

const starterPrompts = [
  "Create a small TypeScript CLI that prints a weather summary from sample JSON.",
  "Inspect this workspace and explain what you would improve first.",
  "Build a responsive single-page todo app with tests.",
];

const SHOW_DEMO_LOGS = true;

const emptyForm = {
  name: "",
  description: "",
  instructions:
    "Help me build and test software in this workspace. Keep changes small and explain the result.",
};

const POLICY_TABS = ["permissions", "vault", "owner"] as const;
type PolicyTab = (typeof POLICY_TABS)[number];

function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

function formatDateTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

/**
 * Client-side mirror of the server's scope taxonomy for centralized secrets:
 * any `read:secrets:<key>` is baseline, any write is elevated, deploy dev is
 * baseline, prod elevated. No own/cross-user axis (secrets are global).
 */
function classifyScopeClient(scope: string): "baseline" | "elevated" | "unknown" {
  if (/^read:secrets:.+/.test(scope)) return "baseline";
  if (/^write:secrets:.+/.test(scope)) return "elevated";
  if (scope === "act:deploy:dev") return "baseline";
  if (scope === "act:deploy:prod") return "elevated";
  return "unknown";
}

/**
 * Mirror of the relay's capability check: a granted scope `granted` covers a
 * cell scope `cell` when they are equal, OR `cell` starts with `granted + "/"`
 * (so an owner-scoped grant covers every per-key cell under that owner).
 */
function scopeCovers(granted: string, cell: string): boolean {
  return cell === granted || cell.startsWith(granted + "/");
}

function isGranted(scopes: string[], cell: string): boolean {
  return scopes.some((granted) => scopeCovers(granted, cell));
}

/** Does a user have access to a permission? Admins bypass; otherwise any
 *  granted scope that covers the permission (exact or a coarser owner scope)
 *  counts. */
function userHasPermission(user: User, scope: string): boolean {
  if (user.role === "admin") return true;
  return user.scopes.some((granted) => scopeCovers(granted, scope));
}

type UserPermissionStatus =
  | { kind: "admin" }
  | { kind: "granted" }
  | { kind: "via"; via: string }
  | { kind: "none" };

/** How a user holds a permission: admin bypass, exact grant, inherited via a
 *  broader granted scope, or not at all. Drives the admin detail toggles. */
function userPermissionStatus(user: User, scope: string): UserPermissionStatus {
  if (user.role === "admin") return { kind: "admin" };
  if (user.scopes.includes(scope)) return { kind: "granted" };
  const broader = user.scopes.find((granted) => granted !== scope && scopeCovers(granted, scope));
  if (broader) return { kind: "via", via: broader };
  return { kind: "none" };
}

function StatusPill({ status }: { status: Agent["status"] }) {
  return (
    <span className={"status status-" + status}>
      <span className="status-dot" />
      {status}
    </span>
  );
}

function Spinner() {
  return <span className="spinner" aria-label="Loading" />;
}

export default function App() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [system, setSystem] = useState<SystemInfo | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [form, setForm] = useState(emptyForm);
  const [prompt, setPrompt] = useState("");
  const [activeRun, setActiveRun] = useState<AgentRun | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [authRequired, setAuthRequired] = useState<boolean | null>(null);
  const [authInput, setAuthInput] = useState("");
  const [currentUser, setCurrentUser] = useState("default");
  const [audit, setAudit] = useState<Audit[]>([]);
  const [workflow, setWorkflow] = useState<WorkflowNode[]>([]);
  const [activeTab, setActiveTab] = useState<"chat" | "logs">("chat");
  const [intent, setIntent] = useState("");
  const [plan, setPlan] = useState<IntentPlan | null>(null);
  /** Scopes the owner has picked for the new agent. Pre-filled by the plan
   *  (its baseline + elevated), but the owner can toggle ANY catalog scope. */
  const [createScopes, setCreateScopes] = useState<Set<string>>(new Set());
  const [auditFilter, setAuditFilter] = useState<"all" | "allow" | "deny">("all");
  const [expandedAuditId, setExpandedAuditId] = useState<string | null>(null);
  const [policyTab, setPolicyTab] = useState<PolicyTab>("permissions");
  const [secrets, setSecrets] = useState<Secret[]>([]);
  const [selectedForRevoke, setSelectedForRevoke] = useState<Set<string>>(new Set());
  const [vaultForm, setVaultForm] = useState({
    key: "",
    value: "",
    redactedView: "",
  });
  const [showVaultForm, setShowVaultForm] = useState(false);
  const [editingSecretKey, setEditingSecretKey] = useState<string | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [showAddUser, setShowAddUser] = useState(false);
  const [newUserForm, setNewUserForm] = useState<{ userId: string; role: "user" | "admin" }>({
    userId: "",
    role: "user",
  });
  const [addUserStep, setAddUserStep] = useState<1 | 2>(1);
  const [newUserScopes, setNewUserScopes] = useState<Set<string>>(new Set());
  const [showAdmin, setShowAdmin] = useState(false);
  const [adminPerm, setAdminPerm] = useState<string | null>(null);
  const [selectedWorkflowNodeId, setSelectedWorkflowNodeId] = useState<string | null>(null);
  const [selectedLogId, setSelectedLogId] = useState<string | null>(null);
  const messageEnd = useRef<HTMLDivElement>(null);
  const selectedIdRef = useRef<string | null>(null);
  const mountedRef = useRef(true);
  const pollingRunIds = useRef(new Set<string>());
  selectedIdRef.current = selectedId;
  const currentRole: "admin" | "user" =
    users.find((u) => u.userId === currentUser)?.role ?? "user";

  const myScopes: string[] =
    users.find((u) => u.userId === currentUser)?.scopes ?? [];

  const selected = useMemo(
    () => agents.find((agent) => agent.id === selectedId) ?? null,
    [agents, selectedId],
  );

  const workflowByParent = useMemo(() => {
    const next = new Map<string | undefined, WorkflowNode[]>();
    for (const node of workflow) {
      const key = node.parentId ?? "root";
      const existing = next.get(key) ?? [];
      existing.push(node);
      next.set(key, existing);
    }
    return next;
  }, [workflow]);

  const ownerRole: "admin" | "user" = selected
    ? (users.find((u) => u.userId === selected.ownerId)?.role ?? "user")
    : "user";

  /** The full permission catalog for the admin panel + add-user wizard: every
   *  per-key read/write for each centralized secret, plus the deploy scopes.
   *  `riskMap` looks up a scope's inherent risk (read = baseline, write/prod =
   *  elevated) for the detail view. */
  const catalog = useMemo(() => {
    const secretEntries: { scope: string; risk: "baseline" | "elevated" }[] = [];
    const riskMap = new Map<string, "baseline" | "elevated">();
    for (const s of secrets) {
      const readScope = "read:secrets:" + s.key;
      const writeScope = "write:secrets:" + s.key;
      secretEntries.push({ scope: readScope, risk: "baseline" });
      secretEntries.push({ scope: writeScope, risk: "elevated" });
      riskMap.set(readScope, "baseline");
      riskMap.set(writeScope, "elevated");
    }
    const deployEntries = [
      { scope: "act:deploy:dev", risk: "baseline" as const },
      { scope: "act:deploy:prod", risk: "elevated" as const },
    ];
    for (const e of deployEntries) riskMap.set(e.scope, e.risk);
    const groups: {
      label: string;
      entries: { scope: string; risk: "baseline" | "elevated" }[];
    }[] = [
      { label: "Secrets", entries: secretEntries },
      { label: "Deploy", entries: deployEntries },
    ];
    return { groups, riskMap };
  }, [secrets]);

  const runProgress = useMemo(
    () => activeRun?.progress ?? [],
    [activeRun],
  );

  const agentLogs = useMemo(() => {
    const items: Array<{
      id: string;
      timestamp: string;
      agentId: string | null;
      agentName: string;
      runId: string | null;
      userId: string;
      summary: string;
      action: string;
      capability: string;
      resource: string;
      scope: string | null;
      riskLevel: "low" | "medium" | "high";
      decision: "allow" | "deny" | "info";
      detail: string;
      status?: string;
    }> = [];

    const auditRows =
      audit.length > 0 || !selected || !SHOW_DEMO_LOGS
        ? audit
        : [
            {
              id: "demo-low",
              timestamp: new Date(Date.now() - 2 * 60_000).toISOString(),
              humanPrincipalId: "user:" + (selected.ownerId ?? "demo-user"),
              agentId: selected.id,
              agentPrincipalId: null,
              runId: null,
              method: "GET",
              action: "Read resource",
              resource: "secrets:dev-db-url",
              scope: "read:secrets:dev-db-url",
              decision: "allow" as const,
              reason: "capability granted",
              operationRiskLevel: "low" as const,
            },
            {
              id: "demo-medium",
              timestamp: new Date(Date.now() - 90_000).toISOString(),
              humanPrincipalId: "user:" + (selected.ownerId ?? "demo-user"),
              agentId: selected.id,
              agentPrincipalId: null,
              runId: null,
              method: "POST",
              action: "Deploy change",
              resource: "deploy:dev",
              scope: "act:deploy:dev",
              decision: "allow" as const,
              reason: "elevated action approved",
              operationRiskLevel: "medium" as const,
            },
            {
              id: "demo-high",
              timestamp: new Date(Date.now() - 30_000).toISOString(),
              humanPrincipalId: "user:" + (selected.ownerId ?? "demo-user"),
              agentId: selected.id,
              agentPrincipalId: null,
              runId: null,
              method: "POST",
              action: "Deploy change",
              resource: "deploy:prod",
              scope: "act:deploy:prod",
              decision: "deny" as const,
              reason: "capability not granted",
              operationRiskLevel: "high" as const,
            },
          ];

    for (const row of auditRows) {
      items.push({
        id: row.id,
        timestamp: row.timestamp,
        agentId: row.agentId ?? selected?.id ?? null,
        agentName: agents.find((agent) => agent.id === row.agentId)?.name ?? "Agent",
        runId: row.runId,
        userId: row.humanPrincipalId.replace(/^user:/, ""),
        summary: `${row.action} on ${row.resource}`,
        action: row.action,
        capability: row.method ?? row.resource,
        resource: row.resource,
        scope: row.scope,
        riskLevel: row.operationRiskLevel ?? (row.decision === "deny" ? "high" : "low"),
        decision: row.decision,
        detail: row.reason || row.resource,
      });
    }

    for (const node of workflow) {
      items.push({
        id: node.id,
        timestamp: node.createdAt,
        agentId: node.agentId ?? selected?.id ?? null,
        agentName: agents.find((agent) => agent.id === node.agentId)?.name ?? selected?.name ?? "Agent",
        runId: node.runId,
        userId: "—",
        summary: `${node.status} · ${node.type}`,
        action: node.type === "agent" ? "Agent node" : node.type === "task" ? "Task execution" : "Workflow orchestration",
        capability: node.type,
        resource: node.type,
        scope: null,
        riskLevel: node.riskLevel,
        decision: "info",
        detail: `${node.status} · ${node.type}`,
        status: node.status,
      });
    }

    for (const item of runProgress) {
      items.push({
        id: item.id,
        timestamp: item.timestamp,
        agentId: selected?.id ?? null,
        agentName: selected?.name ?? "Agent",
        runId: activeRun?.id ?? null,
        userId: "—",
        summary: item.summary || "Progress event",
        action: item.label,
        capability: item.type,
        resource: item.type,
        scope: null,
        riskLevel: item.type.includes("validation") ? "medium" : item.type.includes("command") ? "high" : "low",
        decision: "info",
        detail: item.summary || item.detail || "Progress event",
      });
    }

    return items.sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
    );
  }, [activeRun, agents, audit, runProgress, selected, workflow]);

  const selectedWorkflowNode = useMemo(
    () => workflow.find((node) => node.id === selectedWorkflowNodeId) ?? workflow[0] ?? null,
    [selectedWorkflowNodeId, workflow],
  );

  const selectedLog = useMemo(
    () => agentLogs.find((log) => log.id === selectedLogId) ?? agentLogs[0] ?? null,
    [agentLogs, selectedLogId],
  );

  const refreshAgents = useCallback(async () => {
    const { agents: next } = await api.listAgents();
    setAgents(next);
    setSelectedId((current) =>
      current && next.some((agent) => agent.id === current)
        ? current
        : (next[0]?.id ?? null),
    );
  }, []);

  const refreshMessages = useCallback(async (agentId: string) => {
    const result = await api.messages(agentId);
    if (mountedRef.current && selectedIdRef.current === agentId) {
      setMessages(result.messages);
    }
  }, []);

  const refreshSecrets = useCallback(async () => {
    const { secrets: next } = await api.listSecrets();
    if (mountedRef.current) setSecrets(next);
  }, []);

  const refreshUsers = useCallback(async () => {
    const { users: next } = await api.listUsers();
    if (mountedRef.current) setUsers(next);
  }, []);

  const bootstrap = useCallback(async () => {
    await Promise.all([
      refreshAgents(),
      api.system().then(setSystem),
      refreshUsers(),
      refreshSecrets(),
    ]);
  }, [refreshAgents, refreshUsers, refreshSecrets]);

  useEffect(() => {
    mountedRef.current = true;
    void api
      .auth()
      .then(async ({ required }) => {
        if (!mountedRef.current) return;
        setAuthRequired(required);
        if (!required) await bootstrap();
      })
      .catch((reason) => setError(reason instanceof Error ? reason.message : String(reason)));
    return () => {
      mountedRef.current = false;
    };
  }, [bootstrap]);

  useEffect(() => {
    setMockUser(currentUser);
    void Promise.all([refreshAgents(), refreshUsers(), refreshSecrets()]).catch((reason) =>
      setError(reason instanceof Error ? reason.message : String(reason)),
    );
  }, [currentUser, refreshAgents, refreshUsers, refreshSecrets]);

  useEffect(() => {
    setActiveRun(null);
    setShowSettings(false);
    setShowVaultForm(false);
    setAudit([]);
    setWorkflow([]);
    setSelectedForRevoke(new Set());
    if (!selectedId) {
      setMessages([]);
      return;
    }
    void Promise.all([
      refreshMessages(selectedId),
      api.runs(selectedId),
      api.audit(selectedId),
      refreshSecrets(),
    ])
      .then(async ([, runsResult, auditResult]) => {
        if (selectedIdRef.current !== selectedId) return;
        setAudit(auditResult.audit);
        const latest = runsResult.runs[0] ?? null;
        setActiveRun(latest);
        if (latest) {
          try {
            const workflowResult = await api.workflow(latest.id);
            if (selectedIdRef.current === selectedId) {
              setWorkflow(workflowResult.workflow);
            }
          } catch (reason) {
            setError(reason instanceof Error ? reason.message : String(reason));
          }
        }
        if (latest && ["queued", "running"].includes(latest.status)) {
          void pollRun(latest.id, selectedId).catch((reason) =>
            setError(reason instanceof Error ? reason.message : String(reason)),
          );
        }
      })
      .catch((reason) =>
        setError(reason instanceof Error ? reason.message : String(reason)),
      );
  }, [refreshMessages, selectedId, refreshSecrets]);

  useEffect(() => {
    if (currentRole !== "admin") return;
    setAudit([]);
    const refreshAudit = () => api.audit()
      .then((result) => {
        if (mountedRef.current && currentRole === "admin") setAudit(result.audit);
      })
      .catch((reason) => setError(reason instanceof Error ? reason.message : String(reason)));
    void refreshAudit();
    const interval = window.setInterval(() => void refreshAudit(), 900);
    return () => window.clearInterval(interval);
  }, [currentRole]);

  useEffect(() => {
    if (selected) {
      setForm({
        name: selected.name,
        description: selected.description,
        instructions: selected.instructions,
      });
    }
  }, [selected]);

  useEffect(() => {
    if (agentLogs.length === 0) {
      setSelectedLogId(null);
      return;
    }

    if (!selectedLogId || !agentLogs.some((log) => log.id === selectedLogId)) {
      setSelectedLogId(agentLogs[0].id);
    }
  }, [agentLogs, selectedLogId]);

  useEffect(() => {
    messageEnd.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, activeRun]);

  const createAgent = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { agent } = await api.createAgent(form);
      await refreshAgents();
      setSelectedId(agent.id);
      setShowCreate(false);
      setForm(emptyForm);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const planIntent = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!intent.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const { plan: next } = await api.planAgent(intent.trim());
      setPlan(next);
      // Pre-fill the pickable set with the plan's suggested scopes (baseline +
      // elevated). The owner can then toggle any catalog scope.
      setCreateScopes(new Set([...next.baselineScopes, ...next.elevatedScopes]));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const toggleCreateScope = (scope: string) => {
    setCreateScopes((prev) => {
      const next = new Set(prev);
      if (next.has(scope)) next.delete(scope);
      else next.add(scope);
      return next;
    });
  };

  const approveAndCreate = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!plan || !form.name.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const scopes = [...createScopes];
      const { agent } = await api.createAgent({
        name: form.name.trim(),
        intent: intent.trim(),
        scopes,
        plan,
      });
      await refreshAgents();
      setSelectedId(agent.id);
      setShowCreate(false);
      setForm(emptyForm);
      setIntent("");
      setPlan(null);
      setCreateScopes(new Set());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const saveAgent = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      await api.updateAgent(selected.id, form);
      await refreshAgents();
      setShowSettings(false);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const toggleAgent = async () => {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      if (selected.status === "stopped") {
        await api.startAgent(selected.id);
      } else {
        await api.stopAgent(selected.id);
      }
      await refreshAgents();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const deleteAgent = async () => {
    if (!selected) return;
    if (!window.confirm("Delete " + selected.name + "? Its workspace will be archived.")) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.deleteAgent(selected.id);
      await refreshAgents();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const revokeCredential = async () => {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      await api.revokeCredential(selected.id);
      const result = await api.audit(selected.id);
      if (selectedIdRef.current === selected.id) setAudit(result.audit);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const revokeScope = async (scope: string) => {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      await api.removeScope(selected.id, scope);
      await refreshAgents();
      const result = await api.audit(selected.id);
      if (selectedIdRef.current === selected.id) setAudit(result.audit);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const toggleRevokeSelect = (scope: string) => {
    setSelectedForRevoke((prev) => {
      const next = new Set(prev);
      if (next.has(scope)) next.delete(scope);
      else next.add(scope);
      return next;
    });
  };

  const revokeSelected = async () => {
    if (!selected || selectedForRevoke.size === 0) return;
    setBusy(true);
    setError(null);
    try {
      for (const scope of selectedForRevoke) {
        await api.removeScope(selected.id, scope);
      }
      await refreshAgents();
      const result = await api.audit(selected.id);
      if (selectedIdRef.current === selected.id) setAudit(result.audit);
      setSelectedForRevoke(new Set());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const addSecret = async (event: React.FormEvent) => {
    event.preventDefault();
    if (currentRole !== "admin") {
      setError("Only admins may manage secrets.");
      return;
    }
    const { key, value, redactedView } = vaultForm;
    if (!key.trim() || !value) return;
    setBusy(true);
    setError(null);
    try {
      await api.addSecret(key.trim(), value, redactedView.trim() || undefined);
      await refreshSecrets();
      setVaultForm({ key: "", value: "", redactedView: "" });
      setEditingSecretKey(null);
      setShowVaultForm(false);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const editSecret = (key: string) => {
    setEditingSecretKey(key);
    setVaultForm({ key, value: "", redactedView: "" });
    setShowVaultForm(false);
  };

  const cancelEditSecret = () => {
    setEditingSecretKey(null);
    setVaultForm({ key: "", value: "", redactedView: "" });
  };

  const revokeSecret = async (key: string) => {
    if (currentRole !== "admin") {
      setError("Only admins may manage secrets.");
      return;
    }
    if (!window.confirm("Revoke secret " + key + "?")) return;
    setBusy(true);
    setError(null);
    try {
      await api.revokeSecret(key);
      await refreshSecrets();
      if (selected) {
        const result = await api.audit(selected.id);
        if (selectedIdRef.current === selected.id) setAudit(result.audit);
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const toggleNewUserScope = (scope: string) => {
    setNewUserScopes((prev) => {
      const next = new Set(prev);
      if (next.has(scope)) next.delete(scope);
      else next.add(scope);
      return next;
    });
  };

  const submitAddUser = async () => {
    if (currentRole !== "admin") {
      setError("Only admins may add users.");
      return;
    }
    if (!newUserForm.userId.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const userId = newUserForm.userId.trim();
      await api.addUser(userId, newUserForm.role, [...newUserScopes]);
      await refreshUsers();
      setCurrentUser(userId);
      setShowAddUser(false);
      setAddUserStep(1);
      setNewUserForm({ userId: "", role: "user" });
      setNewUserScopes(new Set());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const grantScopeToUser = async (userId: string, scope: string) => {
    setBusy(true);
    setError(null);
    try {
      await api.grantUserScope(userId, scope);
      await refreshUsers();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const revokeScopeFromUser = async (userId: string, scope: string) => {
    setBusy(true);
    setError(null);
    try {
      await api.revokeUserScope(userId, scope);
      await refreshUsers();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const pollRun = async (runId: string, agentId: string) => {
    if (pollingRunIds.current.has(runId)) return;
    pollingRunIds.current.add(runId);
    try {
      while (mountedRef.current) {
        await new Promise((resolve) => window.setTimeout(resolve, 900));
        if (!mountedRef.current) return;
        const result = await api.run(runId);
        const auditResult = await api.audit(agentId);
        const workflowResult = await api.workflow(runId);
        if (selectedIdRef.current === agentId) {
          setActiveRun(result.run);
          setAudit(auditResult.audit);
          setWorkflow(workflowResult.workflow);
        }
        if (!["queued", "running"].includes(result.run.status)) {
          await Promise.all([refreshMessages(agentId), refreshAgents()]);
          return;
        }
      }
    } finally {
      pollingRunIds.current.delete(runId);
    }
  };

  const sendMessage = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!selected || !prompt.trim()) return;
    const content = prompt.trim();
    setPrompt("");
    setError(null);
    try {
      const result = await api.sendMessage(selected.id, content);
      if (selectedIdRef.current === selected.id) {
        setMessages((current) => [...current, result.message]);
        setActiveRun(result.run);
      }
      setAgents((current) =>
        current.map((agent) =>
          agent.id === selected.id ? { ...agent, status: "busy" } : agent,
        ),
      );
      await pollRun(result.run.id, selected.id);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
      setActiveRun(null);
      await refreshAgents();
    }
  };

  const unlock = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setAuthToken(authInput);
    try {
      await bootstrap();
      setAuthRequired(false);
      setAuthInput("");
    } catch (reason) {
      if (reason instanceof ApiError && reason.status === 401) {
        setError("The access token is not valid.");
      } else {
        setError(reason instanceof Error ? reason.message : String(reason));
      }
    } finally {
      setBusy(false);
    }
  };

  /** A single permission-map cell: risk dot + verb label + (if granted) a
   *  bulk-revoke checkbox and a single-scope revoke ×. Greyed when un-granted. */
  const renderPermCell = (scope: string, label: string) => {
    if (!selected) return null;
    const granted = isGranted(selected.scopes ?? [], scope);
    const risk = classifyScopeClient(scope);
    const checked = selectedForRevoke.has(scope);
    return (
      <div key={scope} className={"perm-cell" + (granted ? " perm-granted" : "")}>
        <span
          className={"mini-dot mini-" + (risk === "baseline" ? "ready" : risk === "elevated" ? "warning" : "error")}
        />
        <code>{label}</code>
        {granted ? (
          <label className="perm-check">
            <input
              type="checkbox"
              checked={checked}
              onChange={() => toggleRevokeSelect(scope)}
              disabled={busy}
              title="Select for bulk revoke"
            />
          </label>
        ) : (
          <span className="perm-dash">—</span>
        )}
        {granted && (
          <button
            className="perm-x"
            onClick={() => revokeScope(scope)}
            disabled={busy}
            title="Revoke this scope"
          >
            ×
          </button>
        )}
      </div>
    );
  };

  if (authRequired === null) {
    return (
      <main className="auth-screen">
        <section className="auth-card" aria-live="polite">
          <div className="brand-mark">A</div>
          <span className="eyebrow">Agent Launchpad</span>
          <h1>Connecting to the control plane</h1>
          {error ? <div className="error-banner" role="alert">{error}</div> : <Spinner />}
        </section>
      </main>
    );
  }

  if (authRequired) {
    return (
      <main className="auth-screen">
        <form className="auth-card" onSubmit={unlock}>
          <div className="brand-mark">A</div>
          <span className="eyebrow">Agent Launchpad</span>
          <h1>Enter the access token</h1>
          <p>This shared demo token is configured by the platform operator.</p>
          {error && <div className="error-banner" role="alert">{error}</div>}
          <label>
            Access token
            <input
              autoFocus
              type="password"
              value={authInput}
              onChange={(event) => setAuthInput(event.target.value)}
              autoComplete="current-password"
              required
            />
          </label>
          <button className="button button-primary" disabled={busy || !authInput.trim()}>
            {busy ? <Spinner /> : "Open Launchpad"}
          </button>
        </form>
      </main>
    );
  }

  const switcherUsers = users.length > 0 ? users.map((u) => u.userId) : ["default"];

  return (
    <div className={"app-shell" + (currentRole === "admin" && activeTab === "logs" ? " app-shell-wide" : "")}>
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">A</div>
          <div>
            <strong>Agent Launchpad</strong>
            <span>
              {system?.runtimeProvider === "container"
                ? "Local container · Codex CLI"
                : "ECS / Docker · Codex CLI"}
            </span>
          </div>
        </div>

        <div className="user-switcher">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
            <span className="eyebrow">Mock user</span>
            <span className="eyebrow" style={{ color: currentRole === "admin" ? "#b9a4ff" : undefined }}>
              {currentRole}
            </span>
          </div>
          <div className="segmented">
            {switcherUsers.map((user) => (
              <button
                key={user}
                type="button"
                className={"segment" + (currentUser === user ? " segment-active" : "")}
                onClick={() => {
                  setCurrentUser(user);
                  setSelectedId(null);
                }}
              >
                {user}
              </button>
            ))}
          </div>
          {currentRole === "admin" ? (
            <div style={{ display: "flex", gap: 6 }}>
              <button
                style={{
                  flex: 1,
                  minHeight: 32,
                  fontSize: 11,
                  border: "1px solid #3d3d38",
                  background: "#292925",
                  color: "#c9c8c1",
                  borderRadius: 9,
                  cursor: "pointer",
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: 6,
                }}
                onClick={() => {
                  setAddUserStep(1);
                  setNewUserScopes(new Set());
                  setShowAddUser(true);
                }}
              >
                <span>＋</span> Add user
              </button>
              <button
                style={{
                  flex: 1,
                  minHeight: 32,
                  fontSize: 11,
                  border: "1px solid #3d3d38",
                  background: "#292925",
                  color: "#c9c8c1",
                  borderRadius: 9,
                  cursor: "pointer",
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: 6,
                }}
                onClick={() => {
                  setAdminPerm(null);
                  void refreshSecrets();
                  void refreshUsers();
                  setShowAdmin(true);
                }}
              >
                <span>⚙</span> Permissions
              </button>
            </div>
          ) : (
            <button
              style={{
                width: "100%",
                minHeight: 32,
                fontSize: 11,
                border: "1px solid #3d3d38",
                background: "#292925",
                color: "#c9c8c1",
                borderRadius: 9,
                cursor: "pointer",
                display: "inline-flex",
                alignItems: "center",
                justifyContent: "center",
                gap: 6,
              }}
              onClick={() => {
                void refreshUsers();
                setShowAdmin(true);
              }}
            >
              <span>⚙</span> My permissions
            </button>
          )}
        </div>

        {currentRole !== "admin" && (
          <>
        <button
          className="button button-primary create-button"
          onClick={() => {
            setForm(emptyForm);
            setIntent("");
            setPlan(null);
            setCreateScopes(new Set());
            setShowCreate(true);
          }}
        >
          <span>＋</span> Create Agent
        </button>

        <div className="sidebar-label">
          <span>Your Agents</span>
          <span>{agents.length}</span>
        </div>
        <nav className="agent-list">
          {agents.map((agent) => (
            <button
              className={"agent-card " + (agent.id === selectedId ? "selected" : "")}
              key={agent.id}
              onClick={() => setSelectedId(agent.id)}
            >
              <div className="agent-avatar">{agent.name.slice(0, 1).toUpperCase()}</div>
              <div className="agent-card-copy">
                <strong>{agent.name}</strong>
                <span>{agent.description || "Coding Agent"}</span>
              </div>
              <span className={"mini-dot mini-" + agent.status} />
            </button>
          ))}
          {agents.length === 0 && (
            <div className="empty-sidebar">
              <span>◇</span>
              Create your first coding Agent.
            </div>
          )}
        </nav>
          </>
        )}

        <div className="runtime-card">
          <span className="eyebrow">Runtime</span>
          <strong>{system?.runtime ?? "Checking…"}</strong>
          <span>
            {system?.arkModel ?? "Ark model not configured"}
            {system?.containerEngine ? " · " + system.containerEngine : ""}
          </span>
        </div>
      </aside>

      <main className="main">
        {currentRole !== "admin" && (!system?.arkConfigured || !system?.codexAvailable) ? (
          <div className="config-banner">
            <span>!</span>
            <div>
              <strong>Runtime configuration needed</strong>
              <p>
                {!system?.arkConfigured
                  ? "Set ARK_API_KEY and ARK_MODEL in .env before using the Playground."
                  : system.runtimeProvider === "container"
                    ? "The local container engine or Agent Runtime image is unavailable. Rerun npm run poc."
                    : "Codex CLI was not found. Use the Docker image or install @openai/codex."}
              </p>
            </div>
          </div>
        ) : null}

        {error && (
          <div className="error-banner" role="alert">
            <span>{error}</span>
            <button onClick={() => setError(null)}>×</button>
          </div>
        )}

        {currentRole === "admin" && (
          <div className="agent-view-toggle admin-view-toggle" role="tablist" aria-label="Agent views">
            <button
              type="button"
              className={"tab-button " + (activeTab === "chat" ? "tab-active" : "")}
              onClick={() => setActiveTab("chat")}
            >
              Secrets
            </button>
            <button
              type="button"
              className={"tab-button " + (activeTab === "logs" ? "tab-active" : "")}
              onClick={() => setActiveTab("logs")}
            >
              Logs
            </button>
          </div>
        )}

        {currentRole === "admin" && activeTab === "chat" ? (
          <section className="secrets-panel">
            <div className="secrets-head">
              <div>
                <span className="eyebrow">Secrets management</span>
                <h1>Centralized secrets</h1>
              </div>
              <span className="eyebrow">{secrets.length}</span>
            </div>
            <p className="owner-note" style={{ margin: "0 0 14px" }}>
              Add, update, or delete the centralized secrets that users and agents access.
              Values are encrypted at rest; only the redacted label is ever returned.
            </p>
            <form className="vault-form" onSubmit={addSecret}>
              <div className="secrets-form-row">
                <label>
                  Key
                  <input
                    value={vaultForm.key}
                    onChange={(event) => setVaultForm({ ...vaultForm, key: event.target.value })}
                    readOnly={!!editingSecretKey}
                    required
                    maxLength={120}
                    placeholder="dev-db-url"
                  />
                </label>
                <label>
                  Redacted label (optional)
                  <input
                    value={vaultForm.redactedView}
                    onChange={(event) =>
                      setVaultForm({ ...vaultForm, redactedView: event.target.value })
                    }
                    maxLength={200}
                    placeholder="postgres://***:***@db/agentdb"
                  />
                </label>
              </div>
              <label>
                Value
                <textarea
                  value={vaultForm.value}
                  onChange={(event) => setVaultForm({ ...vaultForm, value: event.target.value })}
                  rows={2}
                  required
                  placeholder={
                    editingSecretKey
                      ? "Enter a new value to update this secret"
                      : "the raw secret value — encrypted at rest"
                  }
                />
              </label>
              <div className="modal-footer" style={{ marginTop: 4 }}>
                {editingSecretKey && (
                  <button type="button" className="button button-ghost" onClick={cancelEditSecret}>
                    Cancel
                  </button>
                )}
                <button
                  className="button button-primary"
                  disabled={busy || !vaultForm.key.trim() || !vaultForm.value}
                >
                  {busy ? <Spinner /> : editingSecretKey ? "Update secret" : "Add secret"}
                </button>
              </div>
            </form>
            <div className="vault-grid">
              {secrets.map((s) => (
                <div className="vault-card" key={s.key}>
                  <div className="vault-card-head">
                    <code className="vault-key">{s.key}</code>
                    <div className="secrets-card-actions">
                      <button
                        className="button button-ghost"
                        style={{ minHeight: 28, fontSize: 10, padding: "0 8px" }}
                        onClick={() => editSecret(s.key)}
                        disabled={busy}
                      >
                        Edit
                      </button>
                      <button
                        className="perm-x"
                        onClick={() => revokeSecret(s.key)}
                        disabled={busy}
                        title="Delete secret"
                      >
                        ×
                      </button>
                    </div>
                  </div>
                  <div className="vault-redacted">{s.redactedView}</div>
                </div>
              ))}
              {secrets.length === 0 && <div className="perm-empty">No secrets yet.</div>}
            </div>
          </section>
        ) : currentRole === "admin" && activeTab === "logs" ? (
          <section className="admin-log-stream playground-logs">
            <div className="logs-header-row">
              <div>
                <span className="eyebrow">Agent log stream</span>
                <h2>All agent activity</h2>
              </div>
              <span className="logs-count">{agentLogs.length} events</span>
            </div>
            <div className="audit-filter-row">
              {(["all", "allow", "deny"] as const).map((filter) => (
                <button
                  key={filter}
                  type="button"
                  className={"audit-filter" + (auditFilter === filter ? " audit-filter-active" : "")}
                  onClick={() => setAuditFilter(filter)}
                >
                  {filter}
                </button>
              ))}
            </div>
            <div className="admin-log-list">
              {agentLogs
                .filter((log) => auditFilter === "all" || log.decision === auditFilter)
                .map((log) => (
                  <button
                    key={log.id}
                    type="button"
                    className={"log-list-item risk-row-" + log.riskLevel + (selectedLog?.id === log.id ? " log-list-item-selected" : "")}
                    onClick={() => setSelectedLogId(log.id)}
                  >
                    <div className="log-list-top">
                      <span className={"risk-badge risk-" + log.riskLevel}>{log.riskLevel}</span>
                      <span className="log-list-time">{formatTime(log.timestamp)}</span>
                    </div>
                    <strong>{log.action}</strong>
                    <span>{log.userId} · {log.agentName} · {log.resource}</span>
                    <small>{log.detail}</small>
                  </button>
                ))}
              {agentLogs.filter((log) => auditFilter === "all" || log.decision === auditFilter).length === 0 && (
                <div className="empty-log-state">No matching logs.</div>
              )}
            </div>
          </section>
        ) : selected ? (
          <>
            <header className="agent-header">
              <div>
                <div className="header-title-row">
                  <h1>{selected.name}</h1>
                  <StatusPill status={selected.status} />
                </div>
                <p>{selected.description || "A Codex coding Agent in an isolated workspace."}</p>
              </div>
              <div className="header-actions">
                <button
                  className="button button-ghost"
                  onClick={() => setShowSettings((value) => !value)}
                  disabled={busy || selected.status === "busy"}
                >
                  Settings
                </button>
                <button
                  className="button button-ghost"
                  onClick={toggleAgent}
                  disabled={busy}
                >
                  {selected.status === "stopped" ? "Start" : "Stop"}
                </button>
                <button
                  className="button button-ghost"
                  onClick={revokeCredential}
                  disabled={busy || selected.status === "busy"}
                >
                  Revoke
                </button>
                <button
                  className="button button-danger"
                  onClick={deleteAgent}
                  disabled={busy || selected.status === "busy"}
                >
                  Delete
                </button>
              </div>
            </header>

            <div className="agent-view-toggle" role="tablist" aria-label="Agent views">
              <button
                type="button"
                className={"tab-button " + (activeTab === "chat" ? "tab-active" : "")}
                onClick={() => setActiveTab("chat")}
              >
                Chat
              </button>
              <button
                type="button"
                className={"tab-button " + (activeTab === "logs" ? "tab-active" : "")}
                onClick={() => setActiveTab("logs")}
              >
                Logs
              </button>
            </div>

            {showSettings && (
              <form className="settings-panel" onSubmit={saveAgent}>
                <div className="settings-title">
                  <div>
                    <span className="eyebrow">Agent configuration</span>
                    <h2>Instructions and identity</h2>
                  </div>
                  <button type="button" onClick={() => setShowSettings(false)}>×</button>
                </div>
                <div className="form-grid">
                  <label>
                    Name
                    <input
                      value={form.name}
                      onChange={(event) => setForm({ ...form, name: event.target.value })}
                      required
                      maxLength={80}
                    />
                  </label>
                  <label>
                    Description
                    <input
                      value={form.description}
                      onChange={(event) =>
                        setForm({ ...form, description: event.target.value })
                      }
                      maxLength={500}
                    />
                  </label>
                </div>
                <label>
                  System instructions
                  <textarea
                    value={form.instructions}
                    onChange={(event) =>
                      setForm({ ...form, instructions: event.target.value })
                    }
                    rows={5}
                    maxLength={10_000}
                  />
                </label>
                <div className="panel-footer">
                  <code>{selected.workspacePath}</code>
                  <button className="button button-primary" disabled={busy}>
                    {busy ? <Spinner /> : "Save changes"}
                  </button>
                </div>
              </form>
            )}

            <section className={"playground " + (activeTab === "logs" ? "playground-logs user-log-container" : "")}>
              <div className={"playground-topbar " + (activeTab === "logs" ? "logs-topbar-hidden" : "")}>
                <div>
                  <span className="eyebrow">Playground</span>
                  <h2>Build something with your Agent</h2>
                </div>
                <div className="playground-actions">
                  <div className="session-info">
                    <span className="pulse" />
                    {selected.codexThreadId ? "Session connected" : "New session"}
                  </div>
                </div>
              </div>

              <div className="messages">
                {activeTab === "chat" ? (
                  <>
                    {messages.length === 0 && !activeRun ? (
                      <div className="welcome">
                        <div className="welcome-orbit">
                          <div>⌁</div>
                        </div>
                        <h3>What should {selected.name} build?</h3>
                        <p>
                          The Agent can inspect files, write code, run commands, and continue the
                          same Codex session across messages.
                        </p>
                        <div className="prompt-grid">
                          {starterPrompts.map((item) => (
                            <button key={item} onClick={() => setPrompt(item)}>
                              <span>↗</span>
                              {item}
                            </button>
                          ))}
                        </div>
                      </div>
                    ) : (
                      messages.map((message) => (
                        <article className={"message message-" + message.role} key={message.id}>
                          <div className="message-meta">
                            <strong>{message.role === "user" ? "You" : selected.name}</strong>
                            <span>{formatTime(message.createdAt)}</span>
                          </div>
                          <div className="message-body">{message.content}</div>
                        </article>
                      ))
                    )}
                    {activeRun && ["queued", "running"].includes(activeRun.status) && (
                      <article className="message message-assistant thinking">
                        <div className="message-meta">
                          <strong>{selected.name}</strong>
                          <span>working in the Agent workspace</span>
                        </div>
                        <div className="thinking-row">
                          <Spinner />
                          Codex is reading, editing, or running commands…
                        </div>
                      </article>
                    )}
                    {runProgress.length > 0 && (
                      <article className="message message-assistant" style={{ marginTop: 8 }}>
                        <div className="message-meta">
                          <strong>Progress</strong>
                          <span>{runProgress.length} updates</span>
                        </div>
                        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                          {runProgress.map((item: { id: string; type: string; label: string; summary: string; detail?: string; timestamp: string }) => (
                            <div
                              key={item.id}
                              style={{
                                display: "grid",
                                gridTemplateColumns: "12px minmax(0,1fr)",
                                gap: 10,
                                alignItems: "start",
                                paddingLeft: 4,
                              }}
                            >
                              <div
                                style={{
                                  width: 10,
                                  height: 10,
                                  borderRadius: "50%",
                                  background: item.type.includes("command") || item.type.includes("validation")
                                    ? "#a7d8ff"
                                    : item.type.includes("file")
                                      ? "#7fe3a5"
                                      : "#ffd166",
                                  marginTop: 5,
                                  boxShadow: "0 0 0 3px rgba(255,255,255,.08)",
                                }}
                              />
                              <div style={{ minWidth: 0 }}>
                                <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                                  <strong style={{ fontSize: 12 }}>{item.label}</strong>
                                  <span style={{ fontSize: 10, opacity: 0.6 }}>{formatTime(item.timestamp)}</span>
                                </div>
                                <div style={{ fontSize: 12, opacity: 0.9, marginTop: 2 }}>{item.summary}</div>
                                {item.detail && (
                                  <div style={{ fontSize: 10, opacity: 0.7, marginTop: 3, wordBreak: "break-word" }}>
                                    {item.detail}
                                  </div>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </article>
                    )}
                    {activeRun?.status === "failed" && (
                      <article className="run-error">
                        <strong>Run failed</strong>
                        <span>{activeRun.error}</span>
                      </article>
                    )}
                    <div ref={messageEnd} />
                  </>
                ) : (
                  <div className="logs-panel">
                    <div className="logs-header-row">
                      <div>
                        <span className="eyebrow">Agent log stream</span>
                        <h3>{selected.name}</h3>
                      </div>
                      <span className="logs-count">{agentLogs.length} events</span>
                    </div>
                    <div className="logs-layout">
                      <div className="logs-list-pane">
                        {agentLogs.length === 0 ? (
                          <div className="empty-log-state">No logs yet — start a run to populate the activity stream.</div>
                        ) : (
                          agentLogs.map((log) => (
                            <button
                              key={log.id}
                              type="button"
                              className={"log-list-item risk-row-" + log.riskLevel + (selectedLog?.id === log.id ? " log-list-item-selected" : "")}
                              onClick={() => setSelectedLogId(log.id)}
                            >
                              <div className="log-list-top">
                                <span className={"risk-badge risk-" + log.riskLevel}>{log.riskLevel}</span>
                                <span className="log-list-time">{formatTime(log.timestamp)}</span>
                              </div>
                              <strong>{log.action}</strong>
                              <span>{log.capability}</span>
                              <small>{log.userId} · {log.resource} · {log.detail}</small>
                            </button>
                          ))
                        )}
                      </div>

                      <aside className="log-detail-pane">
                        {selectedLog ? (
                          <>
                            <div className="log-detail-header">
                              <div>
                                <span className="eyebrow">Activity Detail</span>
                                <h4>{selectedLog.action}</h4>
                              </div>
                              <span className={"risk-badge risk-" + selectedLog.riskLevel}>{selectedLog.riskLevel}</span>
                            </div>

                            <div className="log-detail-card">
                              <div className="log-detail-block">
                                <label>Summary</label>
                                <p>{selectedLog.summary}</p>
                              </div>
                              <div className="log-detail-grid">
                                <div><label>User</label><strong>{selectedLog.userId}</strong></div>
                                <div><label>Agent</label><strong>{selectedLog.agentName}</strong></div>
                                <div><label>Resource</label><strong>{selectedLog.resource}</strong></div>
                                <div><label>Scope</label><strong>{selectedLog.scope ?? "—"}</strong></div>
                                <div><label>Time</label><strong>{formatDateTime(selectedLog.timestamp)}</strong></div>
                                <div><label>Result</label><strong>{selectedLog.decision}</strong></div>
                                <div><label>Capability</label><strong>{selectedLog.capability}</strong></div>
                              </div>

                              <div className="log-detail-block">
                                <label>Details</label>
                                <p>{selectedLog.detail}</p>
                              </div>

                              <div className="log-footer">
                                {selectedLog.runId && <span>Run {selectedLog.runId.slice(0, 8)}</span>}
                                {selectedLog.agentId && <span>Agent {selectedLog.agentId.slice(0, 8)}</span>}
                                <span>{selectedLog.decision === "info" ? selectedLog.status?.toUpperCase() ?? "INFO" : selectedLog.decision.toUpperCase()}</span>
                              </div>
                            </div>
                          </>
                        ) : (
                          <div className="empty-log-state">Select a log item to inspect the details.</div>
                        )}
                      </aside>
                    </div>
                  </div>
                )}
              </div>

              {activeTab === "chat" && (
                <form className="composer" onSubmit={sendMessage}>
                <textarea
                  value={prompt}
                  onChange={(event) => setPrompt(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" && !event.shiftKey) {
                      event.preventDefault();
                      event.currentTarget.form?.requestSubmit();
                    }
                  }}
                  placeholder={
                    selected.status === "stopped"
                      ? "Start this Agent to continue…"
                      : "Describe what you want the Agent to do…"
                  }
                  disabled={
                    selected.status === "stopped" ||
                    selected.status === "busy" ||
                    (activeRun != null && ["queued", "running"].includes(activeRun.status))
                  }
                  rows={3}
                />
                  <div className="composer-footer">
                    <span>
                      Enter to send · Shift + Enter for newline · {system?.codexSandboxMode ?? "checking sandbox"}
                    </span>
                    <button
                      className="send-button"
                      disabled={
                        !prompt.trim() ||
                        selected.status === "stopped" ||
                        selected.status === "busy" ||
                        (activeRun != null && ["queued", "running"].includes(activeRun.status))
                      }
                      aria-label="Send message"
                    >
                      ↑
                    </button>
                  </div>
                </form>
              )}
            </section>
          </>
        ) : (
          <div className="no-agent">
            <div className="no-agent-art">A</div>
            <span className="eyebrow">Agent Launchpad</span>
            <h1>Your runtime is ready for an Agent.</h1>
            <p>Create a workspace, give Codex a job, and continue the conversation here.</p>
            <button
              className="button button-primary"
              onClick={() => {
                setForm(emptyForm);
                setIntent("");
                setPlan(null);
                setCreateScopes(new Set());
                setShowCreate(true);
              }}
            >
              Create your first Agent
            </button>
          </div>
        )}
      </main>

      {(activeTab === "logs" || currentRole !== "admin") && (
      <aside className="policy-console">
        {activeTab === "logs" ? (
          <div className="focused-logs">
            <div className="logs-header-row">
              <div>
                <span className="eyebrow">Log stream</span>
                <h3>{currentRole === "admin" ? "All agent activity" : selected?.name ?? "Agent activity"}</h3>
              </div>
              <span className="logs-count">{agentLogs.length} events</span>
            </div>
            <div className="audit-filter-row">
              {(["all", "allow", "deny"] as const).map((filter) => (
                <button
                  key={filter}
                  type="button"
                  className={"audit-filter" + (auditFilter === filter ? " audit-filter-active" : "")}
                  onClick={() => setAuditFilter(filter)}
                >
                  {filter}
                </button>
              ))}
            </div>
            <div className="focused-log-list">
              {agentLogs
                .filter((log) => auditFilter === "all" || log.decision === auditFilter)
                .map((log) => (
                  <button
                    key={log.id}
                    type="button"
                    className={"focused-log risk-row-" + log.riskLevel + (selectedLog?.id === log.id ? " focused-log-selected" : "")}
                    onClick={() => setSelectedLogId(log.id)}
                  >
                    <span className="focused-log-status">{log.decision}</span>
                    <strong>{log.action}</strong>
                    <span>{log.userId} · {log.agentName} · {log.resource}</span>
                    <small>{log.detail}</small>
                    <time>{formatTime(log.timestamp)}</time>
                  </button>
                ))}
              {agentLogs.filter((log) => auditFilter === "all" || log.decision === auditFilter).length === 0 && (
                <div className="empty-log-state">No matching logs.</div>
              )}
            </div>
            {selectedLog && (
              <div className="focused-log-detail">
                <div className="log-detail-header">
                  <div>
                    <span className="eyebrow">Activity Detail</span>
                    <h4>{selectedLog.action}</h4>
                  </div>
                  <span className={"risk-badge risk-" + selectedLog.riskLevel}>{selectedLog.riskLevel}</span>
                </div>
                <div className="log-detail-block">
                  <label>Summary</label>
                  <p>{selectedLog.summary}</p>
                </div>
                <div className="log-detail-grid">
                  <div><label>User</label><strong>{selectedLog.userId}</strong></div>
                  <div><label>Agent</label><strong>{selectedLog.agentName}</strong></div>
                  <div><label>Resource</label><strong>{selectedLog.resource}</strong></div>
                  <div><label>Scope</label><strong>{selectedLog.scope ?? "—"}</strong></div>
                  <div><label>Time</label><strong>{formatDateTime(selectedLog.timestamp)}</strong></div>
                  <div><label>Result</label><strong>{selectedLog.decision}</strong></div>
                  <div><label>Capability</label><strong>{selectedLog.capability}</strong></div>
                </div>
                <div className="log-detail-block">
                  <label>Details</label>
                  <p>{selectedLog.detail}</p>
                </div>
              </div>
            )}
          </div>
        ) : currentRole !== "admin" && selected ? (
          <>
            <div className="policy-tabs">
              {POLICY_TABS.map((tab) => (
                <button
                  key={tab}
                  type="button"
                  className={"policy-tab" + (policyTab === tab ? " policy-tab-active" : "")}
                  onClick={() => setPolicyTab(tab)}
                >
                  {tab}
                </button>
              ))}
            </div>

            {policyTab === "permissions" && (
              <div className="policy-section">
                <div className="playground-topbar" style={{ marginBottom: 4 }}>
                  <div>
                    <span className="eyebrow">Permissions</span>
                    {selected.plan && (
                      <span style={{ fontSize: 11, opacity: 0.6, marginLeft: 6 }}>
                        plan: {selected.plan.source}
                      </span>
                    )}
                  </div>
                  <button
                    className="button button-danger"
                    style={{ minHeight: 30, fontSize: 11, padding: "0 10px" }}
                    disabled={busy || selectedForRevoke.size === 0}
                    onClick={revokeSelected}
                  >
                    Revoke selected ({selectedForRevoke.size})
                  </button>
                </div>

                {ownerRole === "admin" && (
                  <div className="perm-bypass">
                    Owner is an admin — the relay grants all requests (capability check bypassed).
                  </div>
                )}

                {selected.plan?.intent && (
                  <p className="perm-intent">Intent: {selected.plan.intent}</p>
                )}

                <div className="owner-scope-list">
                  {(selected.scopes ?? []).length === 0 ? (
                    <div className="perm-empty">No permissions granted to this agent.</div>
                  ) : (
                    (selected.scopes ?? []).map((scope) => {
                      const risk = classifyScopeClient(scope);
                      return (
                        <div className="owner-scope" key={scope}>
                          <span
                            className={"mini-dot mini-" + (risk === "baseline" ? "ready" : "warning")}
                          />
                          <code>{scope}</code>
                          <label className="perm-check">
                            <input
                              type="checkbox"
                              checked={selectedForRevoke.has(scope)}
                              onChange={() => toggleRevokeSelect(scope)}
                              disabled={busy}
                            />
                          </label>
                          <button
                            className="perm-x"
                            onClick={() => revokeScope(scope)}
                            disabled={busy}
                            title="Revoke scope"
                          >
                            ×
                          </button>
                        </div>
                      );
                    })
                  )}
                </div>

                {selected.plan && (
                  <details className="perm-plan" style={{ marginTop: 4 }}>
                    <summary>View plan</summary>
                    <div className="perm-plan-body">
                      <p>{selected.plan.justification}</p>
                      <p>requested: {selected.plan.requestedScopes.join(", ") || "—"}</p>
                      <p>baseline: {selected.plan.baselineScopes.join(", ") || "—"}</p>
                      <p>elevated: {selected.plan.elevatedScopes.join(", ") || "—"}</p>
                      <p>unknown: {selected.plan.unknownScopes.join(", ") || "—"}</p>
                    </div>
                  </details>
                )}

                <details style={{ marginTop: 4 }}>
                  <summary className="perm-ref-summary">Policy reference</summary>
                  <div className="perm-ref">
                    <p>🟢 baseline: read:secrets:&lt;own&gt;, act:deploy:dev</p>
                    <p>🟠 elevated: write:*, read cross-user, act:deploy:prod</p>
                    <p>🔴 unknown: rejected</p>
                  </div>
                </details>
              </div>
            )}

            {policyTab === "vault" && (
              <div className="policy-section">
                <div className="playground-topbar" style={{ marginBottom: 4 }}>
                  <div>
                    <span className="eyebrow">Vault</span>
                  </div>
                </div>

                <div className="perm-empty">
                  Secrets are centralized and admin-managed. This is the read-only catalog
                  (redacted views only — the raw value never leaves the server).
                </div>

                <div className="vault-grid">
                  {secrets.map((s) => (
                    <div className="vault-card" key={s.key}>
                      <div className="vault-card-head">
                        <code className="vault-key">{s.key}</code>
                      </div>
                      <div className="vault-redacted">{s.redactedView}</div>
                    </div>
                  ))}
                  {secrets.length === 0 && (
                    <div className="perm-empty">No secrets registered yet.</div>
                  )}
                </div>
              </div>
            )}

            {policyTab === "owner" && (
              <div className="policy-section">
                <div className="owner-ownerbar">
                  <div>
                    <span className="eyebrow">Owner view</span>
                    <h2>Agents owned by {currentUser}</h2>
                    <p className="owner-note" style={{ margin: "2px 0 0" }}>
                      These are your agents and the permissions each was granted. Owner-based:
                      only agents you own appear here — the selected one is expanded.
                    </p>
                  </div>
                  <span className="eyebrow">{agents.length}</span>
                </div>

                <div className="owner-card">
                  <div className="owner-scopes-head">
                    <span className="eyebrow">Your permissions</span>
                    <span className="eyebrow">{myScopes.length}</span>
                  </div>
                  <p className="owner-note" style={{ margin: "0 0 6px" }}>
                    The permissions you inherit as {currentUser} (granted by an admin).
                  </p>
                  <div className="owner-scope-list">
                    {myScopes.length === 0 ? (
                      <div className="perm-empty">You have no inherent permissions.</div>
                    ) : (
                      myScopes.map((scope) => {
                        const risk = classifyScopeClient(scope);
                        return (
                          <div className="owner-scope" key={scope}>
                            <span
                              className={"mini-dot mini-" + (risk === "baseline" ? "ready" : "warning")}
                            />
                            <code>{scope}</code>
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>

                {agents.length === 0 ? (
                  <div className="perm-empty">You own no agents yet.</div>
                ) : (
                  <div className="owner-accordion">
                    {agents.map((agent) => {
                      const expanded = agent.id === selectedId;
                      return (
                        <div
                          key={agent.id}
                          className={"owner-agent" + (expanded ? " owner-agent-open" : "")}
                        >
                          <button
                            type="button"
                            className="owner-agent-head"
                            onClick={() => setSelectedId(agent.id)}
                          >
                            <span className={"mini-dot mini-" + agent.status} />
                            <strong>{agent.name}</strong>
                            <span className="owner-agent-meta">
                              {agent.scopes?.length ?? 0} scopes · {agent.status}
                            </span>
                            {agent.plan && (
                              <span className="admin-chip">{agent.plan.source}</span>
                            )}
                            <span className="owner-chevron">{expanded ? "▾" : "▸"}</span>
                          </button>

                          {expanded && (
                            <div className="owner-agent-body">
                              <div className="owner-kv-grid">
                                <div className="owner-kv">
                                  <span>id</span>
                                  <code>{agent.id.slice(0, 8)}</code>
                                </div>
                                <div className="owner-kv">
                                  <span>session</span>
                                  <code>
                                    {agent.codexThreadId
                                      ? agent.codexThreadId.slice(0, 8)
                                      : "none"}
                                  </code>
                                </div>
                                <div className="owner-kv">
                                  <span>created</span>
                                  <code>{formatTime(agent.createdAt)}</code>
                                </div>
                              </div>

                              <div className="owner-scopes">
                                <div className="owner-scopes-head">
                                  <span className="eyebrow">
                                    Permissions · {agent.scopes?.length ?? 0}
                                  </span>
                                  <button
                                    className="button button-danger"
                                    style={{ minHeight: 28, fontSize: 10, padding: "0 8px" }}
                                    disabled={busy || selectedForRevoke.size === 0}
                                    onClick={revokeSelected}
                                  >
                                    Revoke selected ({selectedForRevoke.size})
                                  </button>
                                </div>
                                {(agent.scopes ?? []).length === 0 ? (
                                  <div className="perm-empty">No scopes granted.</div>
                                ) : (
                                  <div className="owner-scope-list">
                                    {(agent.scopes ?? []).map((scope) => {
                                      const risk = classifyScopeClient(scope);
                                      return (
                                        <div key={scope} className="owner-scope">
                                          <span
                                            className={
                                              "mini-dot mini-" +
                                              (risk === "baseline" ? "ready" : "warning")
                                            }
                                          />
                                          <code>{scope}</code>
                                          <label className="perm-check">
                                            <input
                                              type="checkbox"
                                              checked={selectedForRevoke.has(scope)}
                                              onChange={() => toggleRevokeSelect(scope)}
                                              disabled={busy}
                                            />
                                          </label>
                                          <button
                                            className="perm-x"
                                            onClick={() => revokeScope(scope)}
                                            disabled={busy}
                                            title="Revoke scope"
                                          >
                                            ×
                                          </button>
                                        </div>
                                      );
                                    })}
                                  </div>
                                )}
                              </div>

                              <button
                                className="button button-ghost"
                                style={{ minHeight: 30, fontSize: 11, alignSelf: "flex-start" }}
                                onClick={revokeCredential}
                                disabled={busy || agent.status === "busy"}
                              >
                                Revoke credential
                              </button>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}
          </>
        ) : (
          <div className="perm-empty">Select an agent to see its permissions + decisions.</div>
        )}
      </aside>
      )}

      {showCreate && (
        <div className="modal-backdrop" onMouseDown={() => setShowCreate(false)}>
          <form
            className="modal"
            onSubmit={plan ? approveAndCreate : planIntent}
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="modal-heading">
              <div>
                <span className="eyebrow">Intent-bound permissions</span>
                <h2>Create an Agent</h2>
                <p>
                  State what you want the agent to do — the planner derives the minimum
                  permissions; you approve the risky ones.
                </p>
              </div>
              <button type="button" onClick={() => setShowCreate(false)}>
                ×
              </button>
            </div>
            <label>
              Name
              <input
                autoFocus
                placeholder="Frontend Builder"
                value={form.name}
                onChange={(event) => setForm({ ...form, name: event.target.value })}
                required
                maxLength={80}
              />
            </label>
            <label>
              Intent
              <textarea
                placeholder="e.g. build a todo app that reads my DB url and deploys to dev"
                value={intent}
                onChange={(event) => {
                  setIntent(event.target.value);
                  setPlan(null);
                }}
                rows={3}
                maxLength={10_000}
              />
            </label>
            {plan && (
              <div
                style={{
                  marginTop: 8,
                  padding: "12px 14px",
                  border: "1px solid rgba(255,255,255,.1)",
                  borderRadius: 12,
                  display: "flex",
                  flexDirection: "column",
                  gap: 8,
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                  }}
                >
                  <span className="eyebrow">Permissions plan · {plan.source}</span>
                  <span style={{ fontSize: 12, opacity: 0.6 }}>
                    {plan.baselineScopes.length} baseline · {plan.elevatedScopes.length}{" "}
                    elevated · {plan.unknownScopes.length} unknown
                  </span>
                </div>
                <p style={{ fontSize: 13, opacity: 0.85, margin: 0 }}>{plan.justification}</p>
                <p className="owner-note" style={{ margin: "0 0 4px" }}>
                  Pick the permissions for this agent. The plan suggested the checked ones — adjust as needed.
                </p>
                <div className="admin-wizard-catalog">
                  {catalog.groups.map((group) => (
                    <div key={group.label} className="admin-group">
                      <div className="admin-group-title">{group.label}</div>
                      {group.entries.map((entry) => (
                        <label
                          key={entry.scope}
                          className={
                            "admin-perm admin-perm-toggle" +
                            (createScopes.has(entry.scope) ? " admin-perm-active" : "")
                          }
                        >
                          <span
                            className={
                              "mini-dot mini-" + (entry.risk === "baseline" ? "ready" : "warning")
                            }
                          />
                          <code>{entry.scope}</code>
                          <input
                            type="checkbox"
                            checked={createScopes.has(entry.scope)}
                            onChange={() => toggleCreateScope(entry.scope)}
                          />
                        </label>
                      ))}
                    </div>
                  ))}
                </div>
                {plan.unknownScopes.length > 0 && (
                  <div className="perm-empty" style={{ marginTop: 4 }}>
                    Rejected (not in taxonomy): {plan.unknownScopes.join(", ")}
                  </div>
                )}
              </div>
            )}
            <div className="modal-footer">
              <button
                type="button"
                className="button button-ghost"
                onClick={() => setShowCreate(false)}
              >
                Cancel
              </button>
              <button
                className="button button-primary"
                disabled={
                  busy ||
                  !intent.trim() ||
                  (plan ? !form.name.trim() : false)
                }
              >
                {busy ? <Spinner /> : plan ? "Approve & create" : "Plan permissions"}
              </button>
            </div>
          </form>
        </div>
      )}

      {showAddUser && (
        <div
          className="modal-backdrop"
          onMouseDown={() => {
            setShowAddUser(false);
            setAddUserStep(1);
            setNewUserScopes(new Set());
          }}
        >
          <form
            className="modal"
            style={{ width: "min(560px, 100%)" }}
            onSubmit={(event) => {
              event.preventDefault();
              if (addUserStep === 1) {
                if (newUserForm.userId.trim()) setAddUserStep(2);
              } else {
                void submitAddUser();
              }
            }}
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="modal-heading">
              <div>
                <span className="eyebrow">Users &amp; roles</span>
                <h2>Add user{addUserStep === 2 ? " · permissions" : ""}</h2>
                <p>
                  {addUserStep === 1
                    ? "Register a mock principal. Non-admin users see only their own secrets and agents."
                    : "Pick the permissions " +
                      (newUserForm.userId || "the user") +
                      " inherits. Adjust later in the Admin panel."}
                </p>
              </div>
              <button
                type="button"
                onClick={() => {
                  setShowAddUser(false);
                  setAddUserStep(1);
                  setNewUserScopes(new Set());
                }}
              >
                ×
              </button>
            </div>

            {addUserStep === 1 ? (
              <>
                <label>
                  User ID
                  <input
                    autoFocus
                    value={newUserForm.userId}
                    onChange={(event) =>
                      setNewUserForm({ ...newUserForm, userId: event.target.value })
                    }
                    required
                    maxLength={60}
                    placeholder="e.g. carol"
                  />
                </label>
                <label>
                  Role
                  <div style={{ display: "flex", gap: 6, marginTop: 6 }}>
                    {(["user", "admin"] as const).map((r) => (
                      <button
                        key={r}
                        type="button"
                        onClick={() => setNewUserForm({ ...newUserForm, role: r })}
                        style={{
                          flex: 1,
                          minHeight: 36,
                          borderRadius: 9,
                          border: "1px solid",
                          borderColor: newUserForm.role === r ? "#6954d9" : "#d9d7cf",
                          background: newUserForm.role === r ? "#efecff" : "#fff",
                          color: newUserForm.role === r ? "#513db9" : "#575851",
                          fontWeight: 600,
                          fontSize: 12,
                          cursor: "pointer",
                          textTransform: "capitalize",
                        }}
                      >
                        {r}
                      </button>
                    ))}
                  </div>
                </label>
              </>
            ) : (
              <div className="admin-wizard-catalog">
                {catalog.groups.map((group) => (
                  <div key={group.label} className="admin-group">
                    <div className="admin-group-title">{group.label}</div>
                    {group.entries.map((entry) => (
                      <label
                        key={entry.scope}
                        className={
                          "admin-perm admin-perm-toggle" +
                          (newUserScopes.has(entry.scope) ? " admin-perm-active" : "")
                        }
                      >
                        <span
                          className={
                            "mini-dot mini-" +
                            (entry.risk === "baseline" ? "ready" : "warning")
                          }
                        />
                        <code>{entry.scope}</code>
                        <input
                          type="checkbox"
                          checked={newUserScopes.has(entry.scope)}
                          onChange={() => toggleNewUserScope(entry.scope)}
                        />
                      </label>
                    ))}
                  </div>
                ))}
              </div>
            )}

            {error && (
              <div className="error-banner" role="alert">
                <span>{error}</span>
              </div>
            )}

            <div className="modal-footer">
              <button
                type="button"
                className="button button-ghost"
                onClick={() => {
                  setShowAddUser(false);
                  setAddUserStep(1);
                  setNewUserScopes(new Set());
                }}
              >
                Cancel
              </button>
              {addUserStep === 1 ? (
                <button
                  type="button"
                  className="button button-primary"
                  disabled={!newUserForm.userId.trim()}
                  onClick={() => setAddUserStep(2)}
                >
                  Next
                </button>
              ) : (
                <>
                  <button
                    type="button"
                    className="button button-ghost"
                    onClick={() => setAddUserStep(1)}
                  >
                    Back
                  </button>
                  <button type="submit" className="button button-primary" disabled={busy}>
                    {busy ? <Spinner /> : "Add user"}
                  </button>
                </>
              )}
            </div>
          </form>
        </div>
      )}

      {showAdmin && currentRole === "admin" && (
        <div className="modal-backdrop admin-backdrop" onMouseDown={() => setShowAdmin(false)}>
          <div className="admin-panel" onMouseDown={(event) => event.stopPropagation()}>
            <header className="admin-header">
              <div>
                <span className="eyebrow">Admin</span>
                <h2>User permissions</h2>
              </div>
              <button type="button" onClick={() => setShowAdmin(false)}>
                ×
              </button>
            </header>
            <div className="admin-body">
              <aside className="admin-catalog">
                {catalog.groups.map((group) => (
                  <div key={group.label} className="admin-group">
                    <div className="admin-group-title">{group.label}</div>
                    {group.entries.map((entry) => {
                      const usersWith = users.filter((u) =>
                        userHasPermission(u, entry.scope),
                      );
                      return (
                        <button
                          key={entry.scope}
                          type="button"
                          className={
                            "admin-perm" +
                            (adminPerm === entry.scope ? " admin-perm-active" : "")
                          }
                          onClick={() => setAdminPerm(entry.scope)}
                        >
                          <span
                            className={
                              "mini-dot mini-" +
                              (entry.risk === "baseline" ? "ready" : "warning")
                            }
                          />
                          <code>{entry.scope}</code>
                          <span className="admin-perm-count">{usersWith.length}</span>
                          <span className="admin-breadcrumbs">
                            {usersWith.slice(0, 3).map((u) => (
                              <span key={u.userId} className="admin-chip">
                                {u.userId}
                              </span>
                            ))}
                            {usersWith.length > 3 && (
                              <span className="admin-chip admin-chip-more">
                                +{usersWith.length - 3}
                              </span>
                            )}
                            {usersWith.length === 0 && (
                              <span className="admin-chip admin-chip-none">no one</span>
                            )}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                ))}
              </aside>
              <section className="admin-detail">
                {adminPerm ? (
                  <>
                    <div className="admin-detail-head">
                      <div>
                        <span className="eyebrow">Permission</span>
                        <code className="admin-detail-scope">{adminPerm}</code>
                      </div>
                      <span
                        className={
                          "role-badge role-" +
                          (catalog.riskMap.get(adminPerm) === "elevated" ? "admin" : "user")
                        }
                      >
                        {catalog.riskMap.get(adminPerm) ?? "unknown"}
                      </span>
                    </div>
                    <div className="admin-user-list">
                      {users.map((u) => {
                        const status = userPermissionStatus(u, adminPerm);
                        const checked = status.kind !== "none";
                        const disabled =
                          busy || status.kind === "admin" || status.kind === "via";
                        return (
                          <label
                            key={u.id}
                            className={"admin-user" + (checked ? " admin-user-granted" : "")}
                          >
                            <div className="admin-user-id">
                              <strong>{u.userId}</strong>
                              {u.role === "admin" && (
                                <span className="role-badge role-admin">admin</span>
                              )}
                              {status.kind === "via" && (
                                <span className="admin-via">via {status.via}</span>
                              )}
                            </div>
                            <input
                              type="checkbox"
                              checked={checked}
                              disabled={disabled}
                              onChange={() => {
                                if (status.kind === "granted") {
                                  void revokeScopeFromUser(u.userId, adminPerm);
                                } else if (status.kind === "none") {
                                  void grantScopeToUser(u.userId, adminPerm);
                                }
                              }}
                            />
                          </label>
                        );
                      })}
                    </div>
                  </>
                ) : (
                  <div className="perm-empty">
                    Select a permission to see which users have access and toggle it per user.
                  </div>
                )}
              </section>
            </div>
          </div>
        </div>
      )}

      {showAdmin && currentRole !== "admin" && (
        <div className="modal-backdrop" onMouseDown={() => setShowAdmin(false)}>
          <div
            className="modal"
            style={{ width: "min(520px, 100%)" }}
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="modal-heading">
              <div>
                <span className="eyebrow">My permissions</span>
                <h2>{currentUser}</h2>
                <p>The permissions you inherit. Ask an admin to grant more.</p>
              </div>
              <button type="button" onClick={() => setShowAdmin(false)}>
                ×
              </button>
            </div>
            <div className="owner-scope-list">
              {myScopes.length === 0 ? (
                <div className="perm-empty">
                  You have no inherent permissions. An admin can grant them.
                </div>
              ) : (
                myScopes.map((scope) => {
                  const risk = classifyScopeClient(scope);
                  return (
                    <div className="owner-scope" key={scope}>
                      <span
                        className={"mini-dot mini-" + (risk === "baseline" ? "ready" : "warning")}
                      />
                      <code>{scope}</code>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
