import * as http from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { startEgressProxy, type EgressProxy } from "../egress-proxy.js";

const proxies: EgressProxy[] = [];
const upstreams: { close: () => Promise<void> }[] = [];

afterEach(async () => {
  await Promise.all(proxies.splice(0).map((proxy) => proxy.stop()));
  await Promise.all(upstreams.splice(0).map((upstream) => upstream.close()));
});

async function startUpstream(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<{ port: number; close: () => Promise<void> }> {
  const server = http.createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  const close = () => new Promise<void>((resolve) => server.close(() => resolve()));
  upstreams.push({ close });
  return { port, close };
}

function proxyGet(proxyPort: number, target: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const request = http.request(
      { method: "GET", host: "127.0.0.1", port: proxyPort, path: target },
      (response) => {
        let body = "";
        response.on("data", (chunk: Buffer) => {
          body += chunk.toString();
        });
        response.on("end", () => resolve({ status: response.statusCode ?? 0, body }));
      },
    );
    request.on("error", reject);
    request.end();
  });
}

describe("egress proxy", () => {
  it("injects the Tier 1 token and forwards allowlisted requests", async () => {
    let seenAuthorization: string | undefined;
    const upstream = await startUpstream((req, res) => {
      seenAuthorization = req.headers.authorization;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
    const proxy = await startEgressProxy({
      token: "tier1-secret",
      allowHosts: ["127.0.0.1:" + upstream.port],
      allowPathPrefixes: ["/mock/"],
      host: "127.0.0.1",
    });
    proxies.push(proxy);

    const result = await proxyGet(proxy.port, `http://127.0.0.1:${upstream.port}/mock/ping`);

    expect(result.status).toBe(200);
    expect(result.body).toContain("true");
    expect(seenAuthorization).toBe("Bearer tier1-secret");
  });

  it("denies requests to non-allowlisted paths with 403 and never calls upstream", async () => {
    let upstreamCalled = false;
    const upstream = await startUpstream((_req, res) => {
      upstreamCalled = true;
      res.writeHead(200);
      res.end("ok");
    });
    const proxy = await startEgressProxy({
      token: "tier1-secret",
      allowHosts: ["127.0.0.1:" + upstream.port],
      allowPathPrefixes: ["/mock/"],
      host: "127.0.0.1",
    });
    proxies.push(proxy);

    const result = await proxyGet(proxy.port, `http://127.0.0.1:${upstream.port}/secret`);

    expect(result.status).toBe(403);
    expect(result.body).toContain("egress denied");
    expect(upstreamCalled).toBe(false);
  });

  it("denies requests to non-allowlisted hosts without resolving or contacting them", async () => {
    const proxy = await startEgressProxy({
      token: "tier1-secret",
      allowHosts: ["127.0.0.1:1"],
      allowPathPrefixes: ["/mock/"],
      host: "127.0.0.1",
    });
    proxies.push(proxy);

    const result = await proxyGet(proxy.port, "http://evil.example.invalid/mock/ping");

    expect(result.status).toBe(403);
    expect(result.body).toContain("egress denied");
  });

  it("rejects requests whose source IP is not the expected container IP", async () => {
    const proxy = await startEgressProxy({
      token: "tier1-secret",
      allowHosts: ["127.0.0.1:1"],
      allowPathPrefixes: ["/mock/"],
      host: "127.0.0.1",
    });
    proxies.push(proxy);
    // Tighten to an IP that is not the test runner's loopback.
    proxy.setExpectedSourceIp("10.99.99.99");

    const result = await proxyGet(proxy.port, "http://127.0.0.1:1/mock/ping");

    expect(result.status).toBe(403);
    expect(result.body).toContain("source IP not authorized");
  });
});
