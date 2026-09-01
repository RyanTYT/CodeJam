// scripts/mini-resource.mjs
//
// A miniature "checks-for-a-key" server — a standalone, dependency-free
// reference for the Bouncer enforcement concept. It holds a secret and only
// returns it when the request presents the right Bearer key.
//
// Run:   node scripts/mini-resource.mjs            (default port 4000)
//        PORT=4444 node scripts/mini-resource.mjs
//
// Manual check:
//   curl -H "Authorization: Bearer ACCESS_GRANTED_42" http://localhost:4000/flag   # 200
//   curl http://localhost:4000/flag                                                 # 403
//
// ──────────────────────────────────────────────────────────────────────────
// NOTE: This standalone server is a VISUAL REFERENCE for the "checks for a
// key" idea. In the LIVE Launchpad flow the mock-resource RELAY (boundary 3)
// IS that server: it validates the agent's per-run Tier-1 credential (the key)
// AND checks the agent's scopes. The agent curls the RELAY, not this script,
// because the per-run egress proxy only injects the Tier-1 key for
//   http://host.docker.internal:<MOCK_RESOURCE_PORT>/mock/proxy/...
// So the live enforcement test (Alice allow / Bob deny) is done by prompting
// the agent to curl the relay. See the prompts in the chat.
// ──────────────────────────────────────────────────────────────────────────

import { createServer } from "node:http";

const PORT = Number(process.env.PORT ?? 4000);
const FLAG_KEY = process.env.FLAG_KEY ?? "ACCESS_GRANTED_42"; // the key this server checks for
const FLAG_VALUE = "ACCESS_GRANTED_42"; // the protected data it guards

const server = createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url !== "/flag" && req.url !== "/") {
    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not found" }));
    return;
  }
  const auth = req.headers.authorization ?? "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (token !== FLAG_KEY) {
    res.statusCode = 403;
    res.end(JSON.stringify({ error: "missing or wrong key", decision: "deny" }));
    return;
  }
  res.statusCode = 200;
  res.end(JSON.stringify({ flag: FLAG_VALUE, decision: "allow" }));
});

server.listen(PORT, () => {
  console.log(`mini-resource server listening on http://localhost:${PORT}`);
  console.log(`  GET /flag  (needs Authorization: Bearer ${FLAG_KEY})`);
});
