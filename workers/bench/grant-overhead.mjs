// What grants add to the server's CPU per request: the same reads and
// appends, on plain workerd, with authentication off and with grants on.
//   npm run build && cargo build -p patchlog-grant
//   node bench/grant-overhead.mjs        # starts workerd twice, prints both
// Uses the development keys of bench/auth-smoke.mjs.

import { execFileSync, spawn } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync, rmSync, mkdirSync } from "node:fs";
import { join } from "node:path";

const here = new URL(".", import.meta.url).pathname;
const CLI = join(here, "../target/debug/patchlog-grant");
const cli = (...a) => execFileSync(CLI, a, { encoding: "utf8" }).trim();
const seed = (b) => b.toString(16).padStart(2, "0").repeat(32);
const pub = (b) => JSON.parse(cli("keygen", "--seed", seed(b))).pub;
const jwks = { keys: [{ kty: "OKP", crv: "Ed25519", x: pub(1), kid: "dev-operator", use: "sig", patchlog: { from: "2026-01-01T00:00:00Z" } }] };
const exp = new Date(Date.now() + 3600_000).toISOString().replace(/\.\d+Z$/, "Z");
const mint = (b, root) => cli("mint", "--seed", seed(b), "--root", JSON.stringify(root));

function config(grants, port) {
  // workerd embeds files by paths relative to the config, which sits here.
  const build = "../crates/worker/build";
  mkdirSync(join(here, "../.workerd-data"), { recursive: true });
  const vars = grants
    ? `(name = "AUTH", text = "grants"), (name = "OPERATOR_JWKS", text = ${JSON.stringify(JSON.stringify(jwks))}),`
    : `(name = "AUTH", text = "disabled"),`;
  return `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [(name = "main", worker = .w), (name = "disk", disk = (path = "${mkdtempSync(join(here, "../.workerd-data/go-"))}", writable = true))],
  sockets = [(name = "http", address = "127.0.0.1:${port}", http = (), service = "main")],
);
const w :Workerd.Worker = (
  modules = [(name = "index.js", esModule = embed "${build}/index.js"), (name = "index_bg.wasm", wasm = embed "${build}/index_bg.wasm")],
  compatibilityDate = "2025-10-01",
  bindings = [(name = "NAMESPACE", durableObjectNamespace = "Namespace"), ${vars}],
  durableObjectNamespaces = [(className = "Namespace", uniqueKey = "pl", enableSql = true)],
  durableObjectStorage = (localDisk = "disk"),
);`;
}

async function run(grants) {
  const port = grants ? 8791 : 8790;
  const file = join(here, `.grant-overhead-${port}.capnp`);
  writeFileSync(file, config(grants, port));
  const p = spawn(join(here, "../node_modules/.bin/workerd"), ["serve", file], { stdio: "ignore" });
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 100; i++) { try { await fetch(base + "/"); break; } catch { await new Promise((r) => setTimeout(r, 100)); } }
  const cpu = () => { const f = readFileSync(`/proc/${p.pid}/stat`, "utf8").split(") ")[1].split(" "); return (Number(f[11]) + Number(f[12])) * 10; };
  const ns = "go-" + Date.now().toString(36);
  const H = { "Content-Type": "application/json-patch+json" };
  const keyed = { read: grants ? "grant" : "public", keys: [{ kid: "ed", alg: "Ed25519", pub: pub(3), can: ["read", "create", "append"] }] };
  let auth = { "X-Author": "o" };
  if (grants) auth = { Authorization: `Bearer ${mint(1, { kid: "dev-operator", sub: "ops:x", ns: [ns], can: ["config"], exp })}` };
  let r = await fetch(`${base}/ns/${ns}`, { method: "PATCH", headers: { ...H, ...auth, "If-None-Match": "*" }, body: JSON.stringify([{ op: "add", path: "", value: grants ? keyed : { read: "public" } }]) });
  if (r.status !== 201) throw new Error(`create ${r.status} ${await r.text()}`);
  if (grants) auth = { Authorization: `Bearer ${mint(3, { kid: "ed", sub: "user:x", ns: [ns], can: ["read", "create", "append"], exp })}` };
  r = await fetch(`${base}/r/${ns}/d`, { method: "PATCH", headers: { ...H, ...auth, "If-None-Match": "*" }, body: JSON.stringify([{ op: "add", path: "", value: { n: 0 } }]) });
  let head = r.headers.get("etag");
  const out = {};
  async function measure(label, n, conc, f) {
    for (let i = 0; i < 200; i++) await f(i); // warm up
    const c0 = cpu();
    let k = 0;
    await Promise.all(Array.from({ length: conc }, async () => { while (k < n) await f(k++); }));
    out[label] = +((cpu() - c0) / n).toFixed(3);
  }
  await measure("GET /ns/{ns}", 3000, 8, () => fetch(`${base}/ns/${ns}`, { headers: auth, redirect: "manual" }).then((r) => r.arrayBuffer()));
  await measure("GET /r/{ns}/{name}", 3000, 8, () => fetch(`${base}/r/${ns}/d`, { headers: auth, redirect: "manual" }).then((r) => r.arrayBuffer()));
  await measure("PATCH append", 1500, 1, async (i) => {
    const r = await fetch(`${base}/r/${ns}/d`, { method: "PATCH", headers: { ...H, ...auth, "If-Match": head }, body: JSON.stringify([{ op: "replace", path: "/n", value: i + 1 }]) });
    await r.arrayBuffer();
    if (r.status !== 201) throw new Error(`append ${r.status}`);
    head = r.headers.get("etag");
  });
  p.kill();
  rmSync(file);
  return out;
}

const off = await run(false);
const on = await run(true);
console.log("server CPU ms per request (workerd, this machine)");
for (const k of Object.keys(off)) console.log(`${k.padEnd(20)} auth off ${off[k].toFixed(3)}  grant ${on[k].toFixed(3)}  +${(on[k] - off[k]).toFixed(3)}`);
