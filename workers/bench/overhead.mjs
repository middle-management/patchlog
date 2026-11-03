// Server CPU per request for requests that do less and less work, to split a
// request's cost into runtime, Durable Object dispatch, SQLite and our code.
//   node bench/overhead.mjs http://127.0.0.1:8788 <workerd pid>
import { readFileSync } from "node:fs";
const [base = "http://127.0.0.1:8788", pid] = process.argv.slice(2);
const cpu = () => { const f = readFileSync(`/proc/${pid}/stat`, "utf8").split(") ")[1].split(" "); return (Number(f[11]) + Number(f[12])) * 10; };
const H = { "X-Author": "o", "Content-Type": "application/json-patch+json" };
const ns = "oh-" + Date.now().toString(36);
await fetch(`${base}/ns/${ns}`, { method: "PATCH", headers: { ...H, "If-None-Match": "*" }, body: JSON.stringify([{ op: "add", path: "", value: { read: "public" } }]) });
let r = await fetch(`${base}/r/${ns}/d`, { method: "PATCH", headers: { ...H, "If-None-Match": "*" }, body: JSON.stringify([{ op: "add", path: "", value: { n: 0 } }]) });
let head = r.headers.get("etag");
async function measure(label, n, conc, f) {
  const c0 = cpu(), t0 = performance.now();
  let k = 0;
  await Promise.all(Array.from({ length: conc }, async () => { while (k < n) await f(k++); }));
  console.log(JSON.stringify({ request: label, n, per_s: Math.round(n / ((performance.now() - t0) / 1000)), server_cpu_ms_per_op: +((cpu() - c0) / n).toFixed(3) }));
}
await measure("GET / (front Worker only)", 4000, 8, () => fetch(base + "/").then((r) => r.arrayBuffer()));
await measure("GET /ns/{ns} (Durable Object, head in memory, no SQL)", 4000, 8, () => fetch(`${base}/ns/${ns}`, { redirect: "manual" }).then((r) => r.arrayBuffer()));
await measure("GET /r/{ns}/{name} (Durable Object, 2 SQL reads)", 4000, 8, () => fetch(`${base}/r/${ns}/d`, { redirect: "manual" }).then((r) => r.arrayBuffer()));
await measure("PATCH append (Durable Object, 4 SQL reads, 3 writes)", 1500, 1, async (i) => {
  const r = await fetch(`${base}/r/${ns}/d`, { method: "PATCH", headers: { ...H, "If-Match": head }, body: JSON.stringify([{ op: "replace", path: "/n", value: i + 1 }]) });
  await r.arrayBuffer();
  head = r.headers.get("etag");
});
