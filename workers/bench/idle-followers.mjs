// Followers long-polling a namespace nobody writes to, for a while: to read
// from Cloudflare's analytics what idle followers cost (requests, duration).
//   node bench/idle-followers.mjs https://patchlog.example.workers.dev 100 240
import { EnvHttpProxyAgent, Agent, setGlobalDispatcher } from "undici";
setGlobalDispatcher(process.env.HTTPS_PROXY ? new EnvHttpProxyAgent({ connections: 4096 }) : new Agent({ connections: 4096 }));
const [base, n = "100", secs = "240"] = process.argv.slice(2);
const H = { "X-Author": "idle", "Content-Type": "application/json-patch+json" };
const ns = "idle-" + Date.now().toString(36);
await fetch(`${base}/ns/${ns}`, { method: "PATCH", headers: { ...H, "If-None-Match": "*" }, body: JSON.stringify([{ op: "add", path: "", value: { read: "public" } }]) });
const first = await fetch(`${base}/ns/${ns}/log?since=&live=long-poll`);
const since = first.headers.get("x-namespace-revision");
const end = Date.now() + Number(secs) * 1000;
const stats = { polls: 0, s200: 0, s204: 0, other: 0 };
console.log(JSON.stringify({ ns, start: new Date().toISOString() }));
await Promise.all(Array.from({ length: Number(n) }, async () => {
  let cursor = first.headers.get("x-cursor");
  while (Date.now() < end) {
    try {
      const r = await fetch(`${base}/ns/${ns}/log?since=${since}&live=long-poll&cursor=${cursor}`);
      await r.arrayBuffer();
      stats.polls++;
      if (r.status === 204) stats.s204++; else if (r.status === 200) stats.s200++; else stats.other++;
      cursor = r.headers.get("x-cursor") ?? cursor;
    } catch { stats.other++; }
  }
}));
console.log(JSON.stringify({ end: new Date().toISOString(), followers: Number(n), ...stats }));
