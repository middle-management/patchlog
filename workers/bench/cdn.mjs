// What Cloudflare's cache in front of the Worker (Workers Cache) does for
// patchlog's cacheable responses (§9), by `cf-cache-status`.
//   node bench/cdn.mjs https://patchlog.example.com [followers...]
import { Agent, EnvHttpProxyAgent, setGlobalDispatcher } from "undici";

const pool = { connections: 4096, keepAliveTimeout: 60_000 };
setGlobalDispatcher(process.env.HTTPS_PROXY ? new EnvHttpProxyAgent(pool) : new Agent(pool));
const writer = process.env.HTTPS_PROXY ? new EnvHttpProxyAgent() : new Agent();
const [base = "http://127.0.0.1:8788", ...rest] = process.argv.slice(2);
const counts = rest.length ? rest.map(Number) : [100, 500];
const H = { "X-Author": "cdn", "Content-Type": "application/json-patch+json" };
const tag = Date.now().toString(36);
const out = (o) => console.log(JSON.stringify(o));
const pct = (xs, p) => (xs.length ? Math.round([...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.floor(p * xs.length))]) : null);

async function write(path, body, headers) {
  const r = await fetch(base + path, { dispatcher: writer, method: "PATCH", headers: { ...H, ...headers }, body: JSON.stringify(body) });
  await r.arrayBuffer();
  return r;
}

// 1. Immutable revision reads: the first misses, the rest should hit.
{
  const ns = `cdn-r-${tag}`;
  await write(`/ns/${ns}`, [{ op: "add", path: "", value: { read: "public" } }], { "If-None-Match": "*" });
  const r = await write(`/r/${ns}/doc`, [{ op: "add", path: "", value: { n: 1 } }], { "If-None-Match": "*" });
  const id = r.headers.get("etag").slice(1, -1);
  const seen = {};
  const ms = { HIT: [], other: [] };
  for (let i = 0; i < 30; i++) {
    const t = performance.now();
    const g = await fetch(`${base}/r/${ns}/doc/rev/${id}`);
    await g.arrayBuffer();
    const st = g.headers.get("cf-cache-status") ?? "none";
    seen[st] = (seen[st] ?? 0) + 1;
    (st === "HIT" ? ms.HIT : ms.other).push(performance.now() - t);
  }
  out({ test: "revision read, 30 in a row", cache: seen, hit_p50_ms: pct(ms.HIT, 0.5), miss_p50_ms: pct(ms.other, 0.5) });
}

// 2. Long-poll followers on one URL: does the cache collapse them (§7.7)?
for (const n of counts) {
  const ns = `cdn-f-${tag}-${n}`;
  await write(`/ns/${ns}`, [{ op: "add", path: "", value: { read: "public" } }], { "If-None-Match": "*" });
  const probe = async () => {
    const r = await fetch(`${base}/ns/${ns}/log?since=&live=long-poll`);
    await r.arrayBuffer();
    return { since: r.headers.get("x-namespace-revision"), cur: r.headers.get("x-cursor"), ms: Date.parse(r.headers.get("date") ?? "") || Date.now() };
  };
  let p = await probe();
  const left = 20_000 - (p.ms % 20_000);
  if (left < 9_000) { await new Promise((r) => setTimeout(r, left + 1_500)); p = await probe(); }
  const cache = {}, status = {}, got = [];
  let tw = 0;
  const t0 = new Date().toISOString();
  const polls = Array.from({ length: n }, () =>
    fetch(`${base}/ns/${ns}/log?since=${p.since}&live=long-poll&cursor=${p.cur}`)
      .then(async (r) => {
        await r.arrayBuffer();
        const st = r.headers.get("cf-cache-status") ?? "none";
        cache[st] = (cache[st] ?? 0) + 1;
        status[r.status] = (status[r.status] ?? 0) + 1;
        if (r.status === 200 && tw) got.push(performance.now() - tw);
      })
      .catch((e) => { status["client " + (e.cause?.code ?? e.message)] = (status["client " + (e.cause?.code ?? e.message)] ?? 0) + 1; }),
  );
  await new Promise((r) => setTimeout(r, 3_000));
  tw = performance.now();
  await write(`/r/${ns}/wake`, [{ op: "add", path: "", value: { x: 1 } }], { "If-None-Match": "*" });
  await Promise.all(polls);
  out({ test: "long-poll followers, one write", followers: n, from: t0, status, cache, delivered_p50_ms: pct(got, 0.5), delivered_max_ms: pct(got, 1) });
}
