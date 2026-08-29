import Fastify, { type FastifyInstance } from "fastify";
import type { MockResourceService } from "./mock-resource-service.js";

/**
 * The agent-facing mock Fastify app. Listens on 0.0.0.0:MOCK_RESOURCE_PORT so
 * the disposable container can reach it over the bridge network. It has NO
 * bearer hook — `/mock/*` is gated solely by Tier 1 (agent credential, via the
 * relay) and Tier 2 (REAL_UPSTREAM_SECRET, via the upstream gate), keeping the
 * operator token and agent identity cleanly separated.
 */
export async function createMockApp(service: MockResourceService): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });

  app.get("/mock/ping", async () => ({ ok: true }));

  // Boundary 3 — the relay. The Authorization header is injected by the
  // per-run egress proxy; the agent never touches it. The wildcard captures
  // the resource path, e.g. /mock/proxy/secrets/alice/db-url -> "secrets/alice/db-url".
  app.all("/mock/proxy/*", async (request, reply) => {
    const auth = request.headers.authorization;
    const authHeader = Array.isArray(auth) ? auth[0] : auth;
    const token =
      typeof authHeader === "string" && authHeader.startsWith("Bearer ")
        ? authHeader.slice(7)
        : undefined;
    const pathParam = (request.params as Record<string, string>)["*"];
    const path = typeof pathParam === "string" ? pathParam : "";
    const result = await service.relay(request.method, path, request.body, token);
    return reply.code(result.status).send(result.body);
  });

  // Tier 2 gate — direct/bypass attempts must present REAL_UPSTREAM_SECRET.
  // The agent never holds this secret, so a bypass that skips the egress proxy
  // and hits this route directly is refused with 401.
  app.all("/mock/upstream/*", async (request, reply) => {
    const secret = request.headers["x-upstream-secret"];
    const secretHeader = Array.isArray(secret) ? secret[0] : secret;
    if (!service.isUpstreamAuthorized(typeof secretHeader === "string" ? secretHeader : "")) {
      return reply.code(401).send({ error: "upstream unauthorized" });
    }
    const pathParam = (request.params as Record<string, string>)["*"];
    const path = typeof pathParam === "string" ? pathParam : "";
    const result = await service.handleUpstream(request.method, path, request.body);
    return reply.code(result.status).send(result.body);
  });

  return app;
}
