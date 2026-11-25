// Load against a running deployment (default: wrangler dev on this machine).
//   node bench/load.mjs [base-url] [--only writes,many,large,reads,followers] [--secs 8]
// Prints one JSON object per scenario. Locally, workerd runs every Durable
// Object in one process on local disk, with no replication: these numbers
// are what the code costs, not what Cloudflare's network adds.

import { readFileSync } from "node:fs";
import { Agent, EnvHttpProxyAgent, setGlobalDispatcher } from "undici";

// Through HTTPS_PROXY where one is set (it isn't used for 127.0.0.1).
const pool = { connections: 4096, pipelining: 1, keepAliveTimeout: 60_000 };
setGlobalDispatcher(process.env.HTTPS_PROXY ? new EnvHttpProxyAgent(pool) : new Agent(pool));

const args = process.argv.slice(2);
const base = args.find((a) => a.startsWith("http")) ?? "http://127.0.0.1:8787";
const only = (args[args.indexOf("--only") + 1] ?? "").split(",").filter((x) => args.includes("--only") && x);
const secs = Number(args.includes("--secs") ? args[args.indexOf("--secs") + 1] : 8);
// With --pid, each result adds the server's CPU time per operation, from /proc.
const pid = args.includes("--pid") ? args[args.indexOf("--pid") + 1] : null;
const cpuSeconds = () => {
  if (!pid) return 0;
  const f = readFileSync(`/proc/${pid}/stat`, "utf8").split(") ")[1].split(" ");
  return (Number(f[11]) + Number(f[12])) / 100; // utime + stime, in clock ticks of 10 ms
};
const run = (name) => only.length === 0 || only.includes(name);
const tag = Date.now().toString(36);

async function call(method, path, body, headers = {}) {
  const h = { "X-Author": "bench", ...headers };
  if (body !== undefined) h["Content-Type"] = "application/json-patch+json";
  const init = { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), redirect: "manual" };
  let r;
  try {
    r = await fetch(base + path, init);
  } catch {
    r = await fetch(base + path, init); // a keep-alive connection the server had closed
  }
  const text = await r.text();
  return { status: r.status, h: r.headers, text };
}

async function mkns(ns) {
  const r = await call("PATCH", `/ns/${ns}`, [{ op: "add", path: "", value: { read: "public", limits: { documentSize: 1572864 } } }], { "If-None-Match": "*" });
  if (r.status !== 201) throw new Error(`namespace ${ns}: ${r.status} ${r.text}`);
}

async function create(ns, name, value) {
  const r = await call("PATCH", `/r/${ns}/${name}`, [{ op: "add", path: "", value }], { "If-None-Match": "*" });
  if (r.status !== 201) throw new Error(`create ${ns}/${name}: ${r.status} ${r.text.slice(0, 200)}`);
  return r.h.get("etag").slice(1, -1);
}

function pct(xs, p) {
  const s = [...xs].sort((a, b) => a - b);
  return +s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))].toFixed(2);
}

// Runs `worker(i)` in `concurrency` loops for `seconds`; each call returns ok or not.
async function load(concurrency, seconds, worker) {
  const lat = [];
  let errors = 0;
  const cpu0 = cpuSeconds();
  const end = performance.now() + seconds * 1000;
  await Promise.all(
    Array.from({ length: concurrency }, async (_, i) => {
      while (performance.now() < end) {
        const t = performance.now();
        const ok = await worker(i);
        if (ok) lat.push(performance.now() - t);
        else errors++;
      }
    }),
  );
  const res = { ops: lat.length, per_s: Math.round(lat.length / seconds), p50_ms: pct(lat, 50), p99_ms: pct(lat, 99), errors };
  if (pid) res.server_cpu_ms_per_op = +(((cpuSeconds() - cpu0) * 1000) / Math.max(1, lat.length)).toFixed(3);
  return res;
}

function doc(bytes) {
  const items = [];
  let n = 0;
  while (JSON.stringify(items).length + 80 < bytes) items.push({ id: `b${n}`, kind: "para", text: `lorem ipsum dolor ${n}`, n: n++ });
  return { title: "bench", items };
}

// Each writer appends to its own resource, so writes contend only for the namespace.
async function appenders(nsOf, concurrency, seconds, size = 500) {
  const heads = [];
  for (let i = 0; i < concurrency; i++) heads.push({ ns: nsOf(i), name: `w${i}`, head: await create(nsOf(i), `w${i}`, doc(size)) });
  let k = 0;
  return load(concurrency, seconds, async (i) => {
    const w = heads[i];
    const r = await call("PATCH", `/r/${w.ns}/${w.name}`, [{ op: "replace", path: "/items/0/n", value: k++ }], { "If-Match": `"${w.head}"` });
    if (r.status !== 201) return false;
    w.head = r.h.get("etag").slice(1, -1);
    return true;
  });
}

const out = (name, o) => console.log(JSON.stringify({ scenario: name, ...o }));

if (run("writes")) {
  const writers = args.includes("--writers") ? args[args.indexOf("--writers") + 1].split(",").map(Number) : [1, 8, 32];
  for (const c of writers) {
    const ns = `bw-${tag}-${c}`;
    await mkns(ns);
    out("writes, one namespace", { writers: c, ...(await appenders(() => ns, c, secs)) });
  }
}

if (run("many")) {
  const N = 100;
  for (let i = 0; i < N; i++) await mkns(`bm-${tag}-${i}`);
  const w = args.includes("--many-writers") ? Number(args[args.indexOf("--many-writers") + 1]) : 32;
  out("writes, 100 namespaces", { writers: w, ...(await appenders((i) => `bm-${tag}-${i % N}`, w, secs)) });
}

if (run("large")) {
  for (const size of [16 << 10, 256 << 10, 1 << 20]) {
    const ns = `bl-${tag}-${size}`;
    await mkns(ns);
    out("appends to a large document", { doc_bytes: size, writers: 1, ...(await appenders(() => ns, 1, Math.min(secs, 5), size)) });
  }
}

if (run("reads")) {
  const ns = `br-${tag}`;
  await mkns(ns);
  const revs = [];
  for (let i = 0; i < 200; i++) revs.push({ name: `d${i}`, id: await create(ns, `d${i}`, doc(500)) });
  let k = 0;
  out("head pointer reads (302, Durable Object)", { readers: 8, ...(await load(8, secs, async () => (await call("GET", `/r/${ns}/d${k++ % 200}`)).status === 302)) });
  // Misses: each revision once, served by the Durable Object, then by the Cache API.
  k = 0;
  const miss = await load(8, 2, async () => {
    const r = revs[k++ % revs.length];
    return (await call("GET", `/r/${ns}/${r.name}/rev/${r.id}`)).status === 200;
  });
  out("revision reads, first pass (Durable Object, then cached)", { readers: 8, ...miss });
  out("revision reads, second pass (Cache API where the runtime has one)", { readers: 8, ...(await load(8, secs, async () => {
    const r = revs[k++ % revs.length];
    return (await call("GET", `/r/${ns}/${r.name}/rev/${r.id}`)).status === 200;
  })) });
}

if (run("followers")) {
  const counts = args.includes("--followers") ? args[args.indexOf("--followers") + 1].split(",").map(Number) : [100, 1000, 3000];
  for (const [i, n] of counts.entries()) {
    const ns = `bf-${tag}-${i}-${n}`;
    await mkns(ns);
    const first = await call("GET", `/ns/${ns}/log?since=&live=long-poll`);
    const since = first.h.get("x-namespace-revision"), cursor = first.h.get("x-cursor");
    // Take the cursor from the server (§7.7), whose clock may differ from
    // ours, and start well before the interval ends, which would answer the polls.
    const probe = async () => { const r = await call("GET", `/ns/${ns}/log?since=&live=long-poll`); const d = r.h.get("date"); return { cur: r.h.get("x-cursor"), ms: d ? Date.parse(d) : Date.now() }; };
    let p = await probe();
    const left = 20_000 - (p.ms % 20_000);
    if (left < 8_000) { await new Promise((r) => setTimeout(r, left + 1_500)); p = await probe(); }
    const cur = p.cur;
    let done = 0;
    const t = { write: 0, all: 0 };
    const polls = Array.from({ length: n }, () =>
      call("GET", `/ns/${ns}/log?since=${since}&live=long-poll&cursor=${cur}`).then((r) => {
        if (r.status === 200) done++;
        t.all = performance.now();
      }),
    );
    await new Promise((r) => setTimeout(r, 2000)); // let every poll arrive and wait
    t.write = performance.now();
    const cpu0 = cpuSeconds();
    await create(ns, "wake", { x: 1 });
    await Promise.all(polls);
    const o = { followers: n, delivered: done, all_delivered_ms: Math.round(t.all - t.write) };
    if (pid) o.server_cpu_ms_per_follower = +(((cpuSeconds() - cpu0) * 1000) / n).toFixed(3);
    out("long-poll followers of one namespace, one write", o);
  }
}
