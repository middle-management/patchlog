// Sequential latency of the request kinds, one at a time, against a deployment.
//   node bench/latency.mjs https://patchlog.example.workers.dev
import { EnvHttpProxyAgent, setGlobalDispatcher } from "undici";
if (process.env.HTTPS_PROXY) setGlobalDispatcher(new EnvHttpProxyAgent());
const base = process.argv[2] ?? "http://127.0.0.1:8788";
const H = { "X-Author": "lat", "Content-Type": "application/json-patch+json" };
const pct = (xs, p) => +[...xs].sort((a, b) => a - b)[Math.floor((p / 100) * xs.length)].toFixed(1);
async function t(label, n, f) {
  const xs = [];
  for (let i = 0; i < n; i++) { const s = performance.now(); await f(i); xs.push(performance.now() - s); }
  console.log(JSON.stringify({ request: label, n, p50_ms: pct(xs, 50), p90_ms: pct(xs, 90), min_ms: +Math.min(...xs).toFixed(1) }));
}
const ns = "lat-" + Date.now().toString(36);
let r = await fetch(base + "/");
console.log(JSON.stringify({ edge: r.headers.get("cf-ray") }));
await fetch(`${base}/ns/${ns}`, { method: "PATCH", headers: { ...H, "If-None-Match": "*" }, body: JSON.stringify([{ op: "add", path: "", value: { read: "public" } }]) });
r = await fetch(`${base}/r/${ns}/d`, { method: "PATCH", headers: { ...H, "If-None-Match": "*" }, body: JSON.stringify([{ op: "add", path: "", value: { n: 0 } }]) });
let head = r.headers.get("etag");
await t("GET / (edge Worker only)", 50, () => fetch(base + "/").then((r) => r.arrayBuffer()));
await t("GET /r/{ns}/{name} (Durable Object, from memory)", 50, () => fetch(`${base}/r/${ns}/d`, { redirect: "manual" }).then((r) => r.arrayBuffer()));
await t("PATCH append (Durable Object, durable commit)", 50, async (i) => {
  const r = await fetch(`${base}/r/${ns}/d`, { method: "PATCH", headers: { ...H, "If-Match": head }, body: JSON.stringify([{ op: "replace", path: "/n", value: i + 1 }]) });
  await r.arrayBuffer();
  head = r.headers.get("etag");
});
const id = head.slice(1, -1);
await t("GET /rev/{id} (Cache API after the first)", 50, () => fetch(`${base}/r/${ns}/d/rev/${id}`).then((r) => r.arrayBuffer()));
