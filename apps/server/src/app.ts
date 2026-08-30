import cors from "@fastify/cors";
import fastifyStatic from "@fastify/static";
import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import { timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import type { AppConfig } from "./config.js";
import { HttpError } from "./errors.js";
import type { AgentService } from "./agent-service.js";
import { defaultPrincipal } from "./agent-service.js";
import type { Principal } from "./types.js";

declare module "fastify" {
  interface FastifyRequest {
    principal: Principal;
  }
}

const agentIdParams = z.object({ id: z.string().uuid() });
const runIdParams = z.object({ id: z.string().uuid() });
const intentPlanSchema = z.object({
  intent: z.string(),
  requestedScopes: z.array(z.string()),
  baselineScopes: z.array(z.string()),
  elevatedScopes: z.array(z.string()),
  unknownScopes: z.array(z.string()),
  justification: z.string(),
  source: z.enum(["llm", "fallback"]),
});
const createAgentBody = z.object({
  name: z.string().trim().min(1).max(80),
  description: z.string().max(500).optional(),
  instructions: z.string().max(10_000).optional(),
  intent: z.string().max(10_000).optional(),
  scopes: z.array(z.string().max(200)).max(32).optional(),
  plan: intentPlanSchema.optional(),
});
const planAgentBody = z.object({
  intent: z.string().trim().min(1).max(10_000),
});
const revokeScopeBody = z.object({
  scope: z.string().trim().min(1).max(200),
});
const updateAgentBody = createAgentBody.partial().refine(
  (value) => Object.keys(value).length > 0,
  "At least one field is required",
);
const messageBody = z.object({
  content: z.string().trim().min(1).max(50_000),
});
const auditQuery = z.object({
  agentId: z.string().uuid().optional(),
});

export async function createApp(
  config: AppConfig,
  service: AgentService,
): Promise<FastifyInstance> {
  const app = Fastify({
    logger: {
      level: config.logLevel,
      redact: [
        "req.headers.authorization",
        "req.headers.cookie",
        "req.headers.x-mock-user",
      ],
    },
    bodyLimit: 1_048_576,
  });

  await app.register(cors, {
    origin:
      config.nodeEnv === "development"
        ? ["http://localhost:5173", "http://127.0.0.1:5173"]
        : false,
  });

  app.addHook("onRequest", async (request: FastifyRequest, reply) => {
    // Attach the human principal for /api/ routes. X-Mock-User is the mock
    // identity (the brief permits a small mock identity model); when absent the
    // synthetic "default" principal preserves the baseline single-user flow.
    if (request.url.startsWith("/api/")) {
      const header = request.headers["x-mock-user"];
      const raw = Array.isArray(header) ? header[0] : header;
      const userId =
        typeof raw === "string" && raw.trim().length > 0 ? raw.trim() : "default";
      request.principal = {
        kind: "human",
        id: "user:" + userId,
        userId,
        runId: undefined,
        scopes: [],
        expiresAt: undefined,
      };
    }

    // Shared operator bearer token (NOT identity). Kept separate from the
    // human principal above.
    if (
      !config.authToken ||
      !request.url.startsWith("/api/") ||
      request.url === "/api/health" ||
      request.url === "/api/auth"
    ) {
      return;
    }
    const header = request.headers.authorization ?? "";
    const candidate = header.startsWith("Bearer ") ? header.slice(7) : "";
    const expectedBuffer = Buffer.from(config.authToken);
    const candidateBuffer = Buffer.from(candidate);
    const valid =
      candidateBuffer.length === expectedBuffer.length &&
      timingSafeEqual(candidateBuffer, expectedBuffer);
    if (!valid) {
      return reply.code(401).send({ error: "Authentication required" });
    }
  });

  app.get("/api/health", async () => ({
    ok: true,
    service: "volc-agent-launchpad",
  }));

  app.get("/api/auth", async () => ({ required: config.authToken.length > 0 }));

  app.get("/api/system", async () => service.systemInfo());

  app.get("/api/agents", async (request) => ({
    agents: service.listAgents(request.principal ?? defaultPrincipal()),
  }));

  app.post("/api/agents", async (request, reply) => {
    const body = createAgentBody.parse(request.body);
    const agent = await service.createAgent(body, request.principal);
    return reply.code(201).send({ agent });
  });

  app.post("/api/agents/plan", async (request, reply) => {
    const body = planAgentBody.parse(request.body);
    const plan = await service.planIntent(body.intent, request.principal);
    return reply.code(200).send({ plan });
  });

  app.get("/api/agents/:id", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return { agent: service.getAgent(id, request.principal) };
  });

  app.patch("/api/agents/:id", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    const body = updateAgentBody.parse(request.body);
    return { agent: await service.updateAgent(id, body, request.principal) };
  });

  app.delete("/api/agents/:id", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return service.deleteAgent(id, request.principal);
  });

  app.post("/api/agents/:id/start", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return { agent: await service.startAgent(id, request.principal) };
  });

  app.post("/api/agents/:id/stop", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return { agent: await service.stopAgent(id, request.principal) };
  });

  app.post("/api/agents/:id/revoke-credential", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return service.revokeCredential(id, request.principal);
  });

  app.post("/api/agents/:id/scopes/revoke", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    const body = revokeScopeBody.parse(request.body);
    return { agent: await service.removeScope(id, body.scope, request.principal) };
  });

  app.get("/api/agents/:id/messages", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return { messages: service.getMessages(id, request.principal) };
  });

  app.get("/api/agents/:id/runs", async (request) => {
    const { id } = agentIdParams.parse(request.params);
    return { runs: service.getRuns(id, request.principal) };
  });

  app.post("/api/agents/:id/messages", async (request, reply) => {
    const { id } = agentIdParams.parse(request.params);
    const body = messageBody.parse(request.body);
    const result = await service.sendMessage(id, body.content, request.principal);
    return reply.code(202).send(result);
  });

  app.get("/api/runs/:id", async (request) => {
    const { id } = runIdParams.parse(request.params);
    return { run: service.getRun(id, request.principal) };
  });

  app.get("/api/runs/:id/workflow", async (request) => {
    const { id } = runIdParams.parse(request.params);
    return { workflow: service.getWorkflow(id, request.principal) };
  });

  app.get("/api/audit", async (request) => {
    const query = auditQuery.parse(request.query);
    return { audit: service.listAudit(query.agentId, request.principal) };
  });

  if (config.nodeEnv === "production") {
    const webRoot = fileURLToPath(new URL("../../web/dist", import.meta.url));
    await app.register(fastifyStatic, {
      root: webRoot,
      prefix: "/",
    });
    app.setNotFoundHandler((request, reply) => {
      if (request.url.startsWith("/api/")) {
        return reply.code(404).send({ error: "API route not found" });
      }
      return reply.sendFile("index.html");
    });
  }

  app.setErrorHandler((error, request, reply) => {
    const appError = error instanceof Error ? error : new Error(String(error));
    const validationError = error instanceof z.ZodError;
    const frameworkStatus =
      typeof (error as { statusCode?: unknown }).statusCode === "number"
        ? (error as { statusCode: number }).statusCode
        : null;
    const statusCode =
      error instanceof HttpError
        ? error.statusCode
        : validationError
          ? 400
          : frameworkStatus && frameworkStatus >= 400 && frameworkStatus <= 599
            ? frameworkStatus
            : 500;
    if (statusCode >= 500) {
      request.log.error(appError);
    }
    return reply.code(statusCode).send({
      error: appError.message,
      ...(validationError ? { details: error.issues } : {}),
    });
  });

  return app;
}
