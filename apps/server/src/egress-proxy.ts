import * as http from "node:http";
import { URL } from "node:url";

/**
 * Per-run egress proxy (forward proxy).
 *
 * The agent container's `HTTP_PROXY`/`HTTPS_PROXY` env points here. The proxy
 * injects the agent's Tier 1 credential (`Authorization: Bearer <token>`) on
 * allowlisted targets and refuses everything else, so the LLM never touches the
 * credential and cannot exfiltrate via an unapproved host. After `docker inspect`
 * reveals the container's bridge IP, `setExpectedSourceIp` tightens the proxy so
 * a different container cannot route through this run's proxy (spoof resistance
 * rests on the cap-dropped container having no CAP_NET_RAW to forge source IPs).
 */
export interface EgressProxy {
  port: number;
  setExpectedSourceIp: (ip: string | undefined) => void;
  stop: () => Promise<void>;
}

export interface EgressProxyOptions {
  /** Tier 1 token injected as `Authorization: Bearer` on forwarded requests. */
  token: string;
  /** Allowed upstream hosts, e.g. ["host.docker.internal:3001"]. */
  allowHosts: string[];
  /** Allowed path prefixes, e.g. ["/mock/proxy/", "/mock/ping"]. */
  allowPathPrefixes: string[];
  /** Bind address (default 0.0.0.0 — reachable from the container bridge). */
  host?: string;
}

export async function startEgressProxy(opts: EgressProxyOptions): Promise<EgressProxy> {
  let expectedSourceIp: string | undefined;

  const server = http.createServer((req, res) =>
    handleHttp(req, res, opts, () => expectedSourceIp),
  );

  // Reject HTTPS tunneling. Ark is excluded via NO_PROXY and goes direct; any
  // other HTTPS egress (e.g. an exfil target) is denied at the network edge.
  server.on("connect", (_req, socket) => {
    socket.write("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
    socket.end();
  });

  await new Promise<void>((resolve, reject) => {
    const onError = (err: NodeJS.ErrnoException) => reject(err);
    server.once("error", onError);
    server.listen(0, opts.host ?? "0.0.0.0", () => {
      server.off("error", onError);
      resolve();
    });
  });

  const address = server.address();
  const port = typeof address === "object" && address ? address.port : -1;
  if (port < 0) {
    await stopServer(server);
    throw new Error("egress proxy failed to bind");
  }

  return {
    port,
    setExpectedSourceIp: (ip) => {
      expectedSourceIp = ip;
    },
    stop: () => stopServer(server),
  };
}

function handleHttp(
  req: http.IncomingMessage,
  res: http.ServerResponse<http.IncomingMessage>,
  opts: EgressProxyOptions,
  getExpectedIp: () => string | undefined,
): void {
  const expectedIp = getExpectedIp();
  const remote = req.socket.remoteAddress;
  if (expectedIp && remote && remote !== expectedIp && remote !== "::ffff:" + expectedIp) {
    writeJson(res, 403, { error: "source IP not authorized" });
    return;
  }

  const target = req.url ?? "";
  if (!target.startsWith("http://")) {
    writeJson(res, 400, { error: "proxy requires an absolute http:// URL" });
    return;
  }
  let url: URL;
  try {
    url = new URL(target);
  } catch {
    writeJson(res, 400, { error: "invalid target URL" });
    return;
  }

  const host = url.host;
  const path = url.pathname + (url.search || "");
  if (
    !opts.allowHosts.includes(host) ||
    !opts.allowPathPrefixes.some((prefix) => path.startsWith(prefix))
  ) {
    writeJson(res, 403, { error: "egress denied", host, path });
    return;
  }

  const upstream = http.request(
    {
      method: req.method ?? "GET",
      host: url.hostname,
      port: url.port ? Number(url.port) : 80,
      path,
      headers: {
        ...stripHopByHopHeaders(req.headers),
        host,
        authorization: "Bearer " + opts.token,
      },
    },
    (upstreamRes) => {
      res.writeHead(upstreamRes.statusCode ?? 502, stripHopByHopHeaders(upstreamRes.headers));
      upstreamRes.pipe(res);
    },
  );
  upstream.on("error", () => {
    if (!res.headersSent) writeJson(res, 502, { error: "upstream error" });
    else res.end();
  });
  req.pipe(upstream);
}

function writeJson(res: http.ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

function stripHopByHopHeaders(
  headers: http.IncomingMessage["headers"],
): Record<string, string | string[]> {
  const next: Record<string, string | string[]> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    const lower = key.toLowerCase();
    if (
      lower === "connection" ||
      lower === "keep-alive" ||
      lower === "proxy-connection" ||
      lower === "transfer-encoding" ||
      lower === "te" ||
      lower === "trailer" ||
      lower === "upgrade"
    ) {
      continue;
    }
    next[key] = value;
  }
  return next;
}

async function stopServer(server: http.Server): Promise<void> {
  const closeAll = (
    server as http.Server & { closeAllConnections?: () => void }
  ).closeAllConnections;
  if (typeof closeAll === "function") closeAll.call(server);
  await new Promise<void>((resolve) => server.close(() => resolve()));
}
