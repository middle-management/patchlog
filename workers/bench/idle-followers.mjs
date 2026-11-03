// Followers long-polling a namespace nobody writes to, for a while: to read
// from Cloudflare's analytics what idle followers cost (requests, duration),
// and, behind a CDN, how many of their polls reach the origin.
//   node bench/idle-followers.mjs https://patchlog.example.com 100 240
import { EnvHttpProxyAgent, Agent, setGlobalDispatcher } from "undici";
setGlobalDispatcher(process.env.HTTPS_PROXY ? new EnvHttpProxyAgent({ connections: 4096 }) : new Agent({ connections: 4096 }));
const [base, n = "100", secs = "240"] = process.argv.slice(2);
const H = { "X-Author": "idle", "Content-Type": "application/json-patch+json" };
const ns = "idle-" + Date.now().toString(36);
await fetch(`${base}/ns/${ns}`, { method: "PATCH", headers: { ...H, "If-None-Match": "*" }, body: JSON.stringify([{ op: "add", path: "", value: { read: "public" } }]) }).then((r) => r.arrayBuffer());
const first = await fetch(`${base}/ns/${ns}/log?since=&live=long-poll`);
await first.arrayBuffer();
const since = first.headers.get("x-namespace-revision");
const end = Date.now() + Number(secs) * 1000;
// Answers by status and by each cache's verdict: Fastly's x-cache (its last
// word) when a Fastly service is in front, Cloudflare's cf-cache-status.
const stats = {};
let polls = 0, toOrigin = 0, failed = 0;
console.log(JSON.stringify({ ns, start: new Date().toISOString() }));
await Promise.all(Array.from({ length: Number(n) }, async () => {
  let cursor = first.headers.get("x-cursor");
  while (Date.now() < end) {
    let r;
    try {
      r = await fetch(`${base}/ns/${ns}/log?since=${since}&live=long-poll&cursor=${cursor}`);
      await r.arrayBuffer();
    } catch {
      failed++; // a dropped connection (the client's proxy, under load)
      continue;
    }
    polls++;
    const fastly = (r.headers.get("x-cache") ?? "").split(",").pop().trim();
    const k = `${r.status}${fastly ? " fastly=" + fastly : ""} cf=${r.headers.get("cf-cache-status") ?? "-"}`;
    stats[k] = (stats[k] ?? 0) + 1;
    if (fastly && fastly !== "HIT") toOrigin++;
    cursor = r.headers.get("x-cursor") ?? cursor;
  }
}));
console.log(JSON.stringify({ end: new Date().toISOString(), followers: Number(n), polls, failed, ...(toOrigin ? { past_fastly: toOrigin } : {}), stats }));
