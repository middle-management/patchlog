// End-to-end checks of grants (Addendum C) and edge grants (§C.5) against a
// deployment running with AUTH=grants and the development keys below:
//
//   cargo build -p patchlog-grant
//   node bench/auth-smoke.mjs --serve        # wrangler dev on :8788 with them
//   node bench/auth-smoke.mjs [base-url]
//
// Every seed here is a fixed, public, development-only key: never configure
// these keys in a deployment that holds anything.

import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { EnvHttpProxyAgent, setGlobalDispatcher } from "undici";

if (process.env.HTTPS_PROXY) setGlobalDispatcher(new EnvHttpProxyAgent());

const CLI = new URL("../target/debug/patchlog-grant", import.meta.url).pathname;
const cli = (...args) => execFileSync(CLI, args, { encoding: "utf8" }).trim();
const seed = (b) => b.toString(16).padStart(2, "0").repeat(32);
const key = (b) => ({ seed: seed(b), pub: JSON.parse(cli("keygen", "--seed", seed(b))).pub });

const OP = key(1);
const jwks = { keys: [{ kty: "OKP", crv: "Ed25519", x: OP.pub, kid: "dev-operator", use: "sig", patchlog: { from: "2026-01-01T00:00:00Z" } }] };
// Development-only HMAC key for edge-grant cookies, and the page origin
// allowed to send them.
const EDGE_KEYS = [{ kid: "dev-edge", key: "11".repeat(32) }];
const STUDIO = "https://studio.example";
// Development-only secret a verifying edge shares with the origin (§9).
export const EDGE_SECRET = "dev-edge-verify-secret";
if (process.argv[2] === "--serve") {
  const vars = { AUTH: "grants", OPERATOR_JWKS: JSON.stringify(jwks), EDGE_KEYS: JSON.stringify(EDGE_KEYS), CREDENTIALED_ORIGINS: JSON.stringify([STUDIO]), EDGE_VERIFY_SECRET: EDGE_SECRET };
  const args = ["wrangler", "dev", "--port", "8788", ...Object.entries(vars).flatMap(([k, v]) => ["--var", `${k}:${v}`])];
  spawn("npx", args, { stdio: "inherit" }).on("exit", (c) => process.exit(c ?? 0));
} else {

const base = process.argv[2] ?? "http://127.0.0.1:8787";
const ns = `auth-${Date.now().toString(36)}`;
let failed = 0;
const check = (name, cond, detail) => {
  if (cond) console.log(`ok   ${name}`);
  else { failed++; console.log(`FAIL ${name}`, detail ?? ""); }
};
const iso = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");
const exp = iso(Date.now() + 3600_000);
const mint = (k, root, ...blocks) => cli("mint", "--seed", k.seed, "--root", JSON.stringify(root), ...blocks.flatMap((b) => ["--block", JSON.stringify(b)]));
const attenuate = (t, b) => cli("attenuate", "--token", t, "--block", JSON.stringify(b));
const inspect = (t) => JSON.parse(cli("inspect", "--token", t));

async function req(method, path, { grant, body, headers = {}, raw } = {}) {
  const h = { ...headers };
  if (grant) h.Authorization = `Bearer ${grant}`;
  if (body !== undefined) h["Content-Type"] ??= "application/json-patch+json";
  const r = await fetch(base + path, { method, headers: h, body: raw ?? (body === undefined ? undefined : JSON.stringify(body)), redirect: "manual" });
  const text = await r.text();
  let json;
  try { json = text ? JSON.parse(text) : undefined; } catch { json = text; }
  return { status: r.status, h: r.headers, json };
}
const etag = (r) => r.h.get("etag")?.slice(1, -1);

let r = await req("GET", "/");
check("GET / says grants, with jwks_uri", r.json?.auth === "grants" && r.json.jwks_uri === "/.well-known/patchlog-keys", r.json);
r = await req("GET", "/.well-known/patchlog-keys");
check("operator key history", r.status === 200 && r.h.get("content-type") === "application/jwk-set+json" && r.json?.keys?.[0]?.kid === "dev-operator", r.json);

// Keys: a * key, an editor key, a key that may only grant config.
const STAR = key(2), ED = key(3), CFG = key(4);
const doc = {
  read: "grant",
  keys: [
    { kid: "star", alg: "Ed25519", pub: STAR.pub, can: ["*"] },
    { kid: "editors", alg: "Ed25519", pub: ED.pub, can: ["read", "create", "append", "restore", "delete"], sub: "user:.*" },
    { kid: "config", alg: "Ed25519", pub: CFG.pub, can: ["config", "read"] },
  ],
  roles: {
    editor: { can: ["read", "create", "append", "restore", "delete"] },
    translator: { can: ["read", "append"], rules: [{ op: "writes", within: ["/i18n"] }] },
  },
};
const create = (grant) => req("PATCH", `/ns/${ns}`, { grant, body: [{ op: "add", path: "", value: doc }], headers: { "If-None-Match": "*" } });

r = await create();
check("creating a namespace without a grant 401", r.status === 401, r.json);
const notOp = mint(ED, { kid: "editors", sub: "user:mallory", ns: [ns], can: ["config"], exp });
r = await create(notOp);
check("creating with a key the namespace doesn't have 401", r.status === 401, r.json);
const opGrant = mint(OP, { kid: "dev-operator", sub: "ops:bootstrap", ns: [ns], can: ["config"], exp });
r = await create(opGrant);
const cfg0 = r.h.get("x-config-revision");
check("an operator grant creates it", r.status === 201 && !!cfg0, r.json);
r = await req("PATCH", `/r/${ns}/x`, { grant: opGrant, body: [{ op: "add", path: "", value: {} }], headers: { "If-None-Match": "*" } });
check("an operator grant writes nothing else 401", r.status === 401, r.json);

// Reads of a private namespace.
r = await req("GET", `/ns/${ns}`);
check("private namespace without a grant 401", r.status === 401, r.status);
r = await req("GET", `/r/${ns}/doc`);
check("private resource without a grant 401", r.status === 401, r.status);
r = await req("GET", `/ns/${ns}-nope`);
check("missing namespace without a grant 401, like a private one", r.status === 401, r.status);

const alice = mint(ED, { kid: "editors", sub: "user:alice", ns: [ns], can: ["read", "create", "append", "restore", "delete"], exp });
r = await req("GET", `/ns/${ns}`, { grant: alice });
check("unrestricted read of the namespace", r.status === 302, r.status);
r = await req("PATCH", `/r/${ns}/doc`, { grant: alice, body: [{ op: "add", path: "", value: { title: "Hi", i18n: {} } }], headers: { "If-None-Match": "*" } });
const d1 = etag(r);
const aliceId = inspect(alice).id;
check("an editor creates", r.status === 201, r.json);
r = await req("GET", `/r/${ns}/doc/rev/${d1}`, { grant: alice });
check("private reads are private and not for the CDN", r.status === 200 && /private/.test(r.h.get("cache-control")) && r.h.get("cdn-cache-control") === "no-store", [r.status, r.h.get("cache-control")]);
r = await req("GET", `/ns/${ns}/rev/${r.h.get("x-revision") ? "" : ""}`, { grant: alice });
r = await req("GET", `/ns/${ns}`, { grant: alice });
const nsRev = etag(r);
r = await req("GET", `/ns/${ns}/rev/${nsRev}/log`, { grant: alice });
const head = r.json?.find?.((e) => e.kind === "head");
check("the log records the grant and author", head?.grant?.id === aliceId && head.grant.sub === "user:alice" && head.grant.kid === "editors" && head.author === "user:alice", head);
const genesis = r.json?.[0];
check("the genesis records the operator grant", genesis?.grant?.kid === "dev-operator", genesis);
r = await req("GET", `/ns/${ns}/grants/${aliceId}`, { grant: alice });
check("grants/{gid}", r.status === 200 && r.json?.root?.sub === "user:alice" && r.json.stored === inspect(alice).stored, r.json);

// The ns check, then verification.
const other = mint(ED, { kid: "editors", sub: "user:alice", ns: [`${ns}-other`], can: ["read"], exp });
r = await req("GET", `/ns/${ns}`, { grant: other });
check("a grant for another namespace 403 (ns check)", r.status === 403, r.status);
r = await req("GET", `/ns/${ns}`, { grant: "not-a-token" });
check("a malformed grant 401", r.status === 401, r.status);
const expired = mint(ED, { kid: "editors", sub: "user:alice", ns: [ns], can: ["read"], exp: iso(Date.now() - 60_000) });
r = await req("GET", `/ns/${ns}`, { grant: expired });
check("an expired grant 401", r.status === 401, r.json);
const wrongSub = mint(ED, { kid: "editors", sub: "bot:x", ns: [ns], can: ["read"], exp });
r = await req("GET", `/ns/${ns}`, { grant: wrongSub });
check("a sub the key's scope doesn't allow 403", r.status === 403, r.json);
const tooMuch = mint(ED, { kid: "editors", sub: "user:alice", ns: [ns], can: ["config"], exp });
r = await req("GET", `/ns/${ns}`, { grant: tooMuch });
check("a verb the key can't grant 403", r.status === 403, r.json);

// Verbs and narrowing.
const reader = mint(ED, { kid: "editors", sub: "user:rita", ns: [ns], can: ["read"], exp });
r = await req("PATCH", `/r/${ns}/doc`, { grant: reader, body: [{ op: "replace", path: "/title", value: "x" }], headers: { "If-Match": `"${d1}"` } });
check("a reader can't append 403", r.status === 403, r.json);
const narrowed = attenuate(alice, { can: ["read"], via: "svc:preview" });
r = await req("PATCH", `/r/${ns}/doc`, { grant: narrowed, body: [{ op: "replace", path: "/title", value: "x" }], headers: { "If-Match": `"${d1}"` } });
check("a narrowing block takes append away 403", r.status === 403, r.json);
r = await req("GET", `/r/${ns}/doc`, { grant: narrowed });
check("and keeps read", r.status === 302, r.status);

// Roles: alternatives, with their own rules; a grant without can.
const translator = mint(ED, { kid: "editors", sub: "user:tom", ns: [ns], roles: ["translator"], exp });
r = await req("PATCH", `/r/${ns}/doc`, { grant: translator, body: [{ op: "add", path: "/i18n/sv", value: "Hej" }], headers: { "If-Match": `"${d1}"` } });
const d2 = etag(r);
check("a translator appends within /i18n", r.status === 201, r.json);
r = await req("PATCH", `/r/${ns}/doc`, { grant: translator, body: [{ op: "replace", path: "/title", value: "x" }], headers: { "If-Match": `"${d2}"` } });
check("but not outside it 403", r.status === 403, r.json);
r = await req("PATCH", `/r/${ns}/new`, { grant: translator, body: [{ op: "add", path: "", value: {} }], headers: { "If-None-Match": "*" } });
check("nor create 403", r.status === 403, r.json);
r = await req("GET", `/ns/${ns}/principal`, { grant: translator });
check("principal", r.status === 200 && r.json?.principal?.id === "user:tom" && JSON.stringify(r.json.roles) === '["translator"]' && JSON.stringify(r.json.can) === '["append","read"]' && r.json.kid === "editors" && r.json.operator === false && r.json.writer?.limits?.documentSize && r.h.get("x-config-revision"), r.json);
const unknownRole = mint(ED, { kid: "editors", sub: "user:tom", ns: [ns], roles: ["nobody"], exp });
r = await req("GET", `/r/${ns}/doc`, { grant: unknownRole });
check("an unknown role grants nothing (404 for a resource)", r.status === 404, r.status);

// A grant fixed to one resource.
const one = mint(ED, { kid: "editors", sub: "user:ann", ns: [ns], can: ["read"], exp, rules: [{ op: "test", path: "/resource", value: "doc" }] });
r = await req("GET", `/r/${ns}/doc`, { grant: one });
check("a grant fixed to a resource reads it", r.status === 302, r.status);
r = await req("GET", `/r/${ns}/other`, { grant: one });
check("and nothing else (404)", r.status === 404, r.status);
r = await req("GET", `/ns/${ns}`, { grant: one });
check("nor the namespace, which needs unrestricted read 403", r.status === 403, r.status);

// Retries are by the same principal: the same sub and kid.
const body = [{ op: "replace", path: "/title", value: "Hello" }];
r = await req("PATCH", `/r/${ns}/doc`, { grant: alice, body, headers: { "If-Match": `"${d2}"` } });
const d3 = etag(r);
r = await req("PATCH", `/r/${ns}/doc`, { grant: alice, body, headers: { "If-Match": `"${d2}"` } });
check("a retry by the same principal 200", r.status === 200 && etag(r) === d3, r.status);
const aliceStar = mint(STAR, { kid: "star", sub: "user:alice", ns: [ns], can: ["read", "append"], exp });
r = await req("PATCH", `/r/${ns}/doc`, { grant: aliceStar, body, headers: { "If-Match": `"${d2}"` } });
check("the same sub under another key isn't the same principal 412", r.status === 412, r.status);

// Config writes: the *-key guard, then rules.
const cfgGrant = mint(CFG, { kid: "config", sub: "ops:cfg", ns: [ns], can: ["config", "read"], exp });
r = await req("GET", `/ns/${ns}`, { grant: cfgGrant });
let cfg = r.h.get("x-config-revision");
r = await req("PATCH", `/ns/${ns}`, { grant: cfgGrant, body: [{ op: "add", path: "/x-note", value: "hi" }], headers: { "If-Match": `"${cfg}"` } });
check("a config key writes plain members", r.status === 201, r.json);
cfg = r.h.get("x-config-revision");
r = await req("PATCH", `/ns/${ns}`, { grant: cfgGrant, body: [{ op: "add", path: "/revoked", value: [aliceId] }], headers: { "If-Match": `"${cfg}"` } });
check("but revocations need a * key 403", r.status === 403, r.json);
r = await req("PATCH", `/ns/${ns}`, { grant: cfgGrant, body: [{ op: "replace", path: "/read", value: "public" }], headers: { "If-Match": `"${cfg}"` } });
check("and so does going public 403", r.status === 403, r.json);
const star = mint(STAR, { kid: "star", sub: "ops:root", ns: [ns], can: ["config", "read"], exp });
r = await req("PATCH", `/ns/${ns}`, { grant: star, body: [{ op: "add", path: "/revoked", value: [aliceId] }], headers: { "If-Match": `"${cfg}"` } });
check("a * key revokes", r.status === 201, r.json);
r = await req("GET", `/r/${ns}/doc`, { grant: alice });
check("a revoked grant 401", r.status === 401, r.json);
r = await req("GET", `/r/${ns}/doc`, { grant: narrowed });
check("so are its narrowings 401", r.status === 401, r.json);

// Batches: per-item verbs.
const bob = mint(ED, { kid: "editors", sub: "user:bob", ns: [ns], can: ["read", "create"], exp });
const batch = (grant, items) => req("POST", `/ns/${ns}/batch`, { grant, headers: { "Content-Type": "application/json" }, raw: JSON.stringify({ items }) });
r = await batch(bob, [{ resource: "b1", ifNoneMatch: "*", steps: [[{ op: "add", path: "", value: {} }]] }]);
check("a batch item the grant allows", r.status === 201, r.json);
r = await batch(bob, [{ resource: "doc", ifMatch: d3, steps: [[{ op: "add", path: "/x", value: 1 }]] }]);
check("a batch item it doesn't 403", r.status === 403 || (r.status === 422 && r.json?.items?.[0]?.status === 403), r.json);

// A public namespace ignores grants on reads.
const pub = `${ns}-pub`;
r = await req("PATCH", `/ns/${pub}`, { grant: mint(OP, { kid: "dev-operator", sub: "ops:bootstrap", ns: [pub], can: ["config"], exp }), body: [{ op: "add", path: "", value: { read: "public" } }], headers: { "If-None-Match": "*" } });
r = await req("GET", `/ns/${pub}`, { grant: "garbage" });
check("a public namespace's reads ignore the grant", r.status === 302 && /public/.test(r.h.get("cache-control")), [r.status, r.h.get("cache-control")]);
r = await req("PATCH", `/r/${pub}/x`, { body: [{ op: "add", path: "", value: {} }], headers: { "If-None-Match": "*", "X-Author": "me" } });
check("but writes still need one 401", r.status === 401, r.status);

// Blobs: uploads check create/append/restore; pending blobs are the uploader's.
function blobId(type, bytes) {
  const d = createHash("sha256").update(`patchlog-blob-v1\n${type}\n\n`).update(bytes).digest().subarray(0, 20);
  const A = "abcdefghijklmnopqrstuvwxyz234567";
  let s = "1", acc = 0n, bits = 0;
  for (const b of d) { acc = (acc << 8n) | BigInt(b); bits += 8; while (bits >= 5) { bits -= 5; s += A[Number((acc >> BigInt(bits)) & 31n)]; } }
  return s;
}
{
  const bytes = Buffer.from("logo bytes"), bid = blobId("image/png", bytes);
  const carol = mint(ED, { kid: "editors", sub: "user:carol", ns: [ns], can: ["read", "create", "append"], exp });
  r = await req("PUT", `/r/${ns}/logo/blob/${bid}`, { grant: reader, raw: bytes, headers: { "Content-Type": "image/png" } });
  check("a reader can't upload 403", r.status === 403, r.json);
  r = await req("PUT", `/r/${ns}/logo/blob/${bid}`, { grant: carol, raw: bytes, headers: { "Content-Type": "image/png" } });
  check("an editor uploads", r.status === 201, r.json);
  const ref = { $blob: bid, type: "image/png", size: bytes.length };
  r = await req("PATCH", `/r/${ns}/logo`, { grant: bob, body: [{ op: "add", path: "", value: ref }], headers: { "If-None-Match": "*" } });
  check("someone else's pending blob isn't available 422", r.status === 422 && r.json?.code === "blob", r.json);
  r = await req("PATCH", `/r/${ns}/logo`, { grant: carol, body: [{ op: "add", path: "", value: ref }], headers: { "If-None-Match": "*" } });
  check("the uploader references it", r.status === 201, r.json);
  r = await req("GET", `/r/${ns}/logo/blob/${bid}`, { grant: one });
  check("a grant fixed to another resource can't read its blob 404", r.status === 404, r.status);
  r = await req("GET", `/r/${ns}/logo/blob/${bid}`, { grant: carol });
  check("a reader of the resource can", r.status === 200 && /private/.test(r.h.get("cache-control")), [r.status, r.h.get("cache-control")]);
}

// Branches: branch with unrestricted read of the base; the branch keeps the
// base's keys (copied at creation), reads through, and records the creator.
{
  const br = `${ns}-br`;
  const brq = (grant) => req("POST", `/ns/${ns}/branches`, { grant, headers: { "Content-Type": "application/json", "If-None-Match": "*" }, raw: JSON.stringify({ name: br }) });
  r = await brq(bob);
  check("branching without branch 403", r.status === 403, r.json);
  const brancher = mint(STAR, { kid: "star", sub: "ops:release", ns: [ns, br], can: ["branch", "read"], exp });
  r = await brq(brancher);
  check("a branch grant with unrestricted read branches", r.status === 201, r.json);
  const edBr = mint(ED, { kid: "editors", sub: "user:erin", ns: [br], can: ["read", "append"], exp });
  r = await req("GET", `/r/${br}/doc`, { grant: edBr });
  check("the base's key works in the branch; reads through", r.status === 302 && etag(r) === d3, [r.status, etag(r)]);
  r = await req("GET", `/r/${br}/doc/rev/${d3}`, { grant: edBr });
  check("a base revision under the branch", r.status === 200 && r.json?.title === "Hello", r.json);
  r = await req("PATCH", `/r/${br}/doc`, { grant: edBr, body: [{ op: "replace", path: "/title", value: "Branch" }], headers: { "If-Match": `"${d3}"` } });
  check("a first write in the private branch", r.status === 201, r.json);
  r = await req("GET", `/ns/${br}`, { grant: brancher });
  r = await req("GET", `/ns/${br}/rev/${etag(r)}/log`, { grant: brancher });
  check("the branch's genesis records its creator", r.json?.[0]?.grant?.sub === "ops:release", r.json?.[0]);
  r = await req("GET", `/r/${br}/doc`);
  check("the branch is private too 401", r.status === 401, r.status);
}


// Long-polls carry the grant to the namespace's object (§7.7).
{
  r = await req("GET", `/ns/${ns}/log?since=&live=long-poll`);
  check("a long-poll without a grant 401", r.status === 401, r.status);
  r = await req("GET", `/ns/${ns}/log?since=&live=long-poll`, { grant: star });
  check("a long-poll with a grant answers", r.status === 200 && Array.isArray(r.json) && r.h.get("x-cursor"), [r.status, r.json]);
  const since = r.h.get("x-namespace-revision"), cursor = r.h.get("x-cursor");
  const poll = (async () => {
    let c = cursor, p;
    for (let i = 0; i < 3; i++) {
      p = await req("GET", `/ns/${ns}/log?since=${since}&live=long-poll&cursor=${c}`, { grant: star });
      if (p.status !== 204) return p;
      c = p.h.get("x-cursor");
    }
    return p;
  })();
  await new Promise((res) => setTimeout(res, 300));
  await req("PATCH", `/r/${ns}/woken`, { grant: bob, body: [{ op: "add", path: "", value: {} }], headers: { "If-None-Match": "*" } });
  r = await poll;
  check("a write wakes a long-poll with a grant", r.status === 200 && r.json?.[0]?.resource === "woken" && /private/.test(r.h.get("cache-control")), [r.status, r.json]);
  r = await req("GET", `/r/${ns}/doc/log?since=&live=long-poll`, { grant: one });
  check("a resource long-poll with a grant fixed to it", r.status === 200, r.status);
}

// Edge grants (§C.5.2–§C.5.4) and credentialed CORS.
{
  const eg = (grant, extra = {}) => req("POST", "/edge-grants", { grant, headers: { Origin: STUDIO, ...extra.headers }, raw: extra.raw });
  const cookies = (r) => r.h.getSetCookie().map((c) => c.split(";")[0]).join("; ");
  r = await fetch(`${base}/edge-grants`, { method: "OPTIONS", headers: { Origin: STUDIO, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization" } });
  check("preflight from the credentialed origin", r.status === 204 && r.headers.get("access-control-allow-origin") === STUDIO && r.headers.get("access-control-allow-credentials") === "true" && /Origin/.test(r.headers.get("vary") ?? ""), [...r.headers]);
  r = await fetch(`${base}/edge-grants`, { method: "OPTIONS", headers: { Origin: "https://evil.example", "Access-Control-Request-Method": "POST" } });
  check("preflight for /edge-grants from another origin isn't allowed", !r.headers.get("access-control-allow-origin"), [...r.headers]);
  r = await req("GET", "/", { headers: { Origin: "https://elsewhere.example" } });
  check("other origins get *", r.h.get("access-control-allow-origin") === "*" && !r.h.get("access-control-allow-credentials"), [...r.h]);

  r = await eg();
  check("edge grants without a grant 401", r.status === 401, r.json);
  r = await eg(one, { headers: { "Content-Type": "application/json" }, raw: "{}" });
  check("Authorization together with a body 400", r.status === 400, r.json);
  r = await eg(undefined, { headers: { "Content-Type": "text/plain" }, raw: "x" });
  check("a body that isn't JSON 415", r.status === 415, r.json);
  const timed = mint(ED, { kid: "editors", sub: "user:tim", ns: [ns], can: ["read"], exp, rules: [{ op: "compare", path: "/now", lt: { value: exp } }] });
  r = await eg(timed);
  check("rules on /now can't go to an edge 403", r.status === 403, r.json);

  r = await eg(one);
  const docCookies = cookies(r);
  check("a grant fixed to a resource gets one cookie", r.status === 200 && JSON.stringify(r.json?.prefixes) === JSON.stringify([`/r/${ns}/doc`]) && r.h.getSetCookie().length === 1 && /^__Secure-pl-eg-[0-9a-f]{16}=/.test(docCookies) && /Path=\/r\//.test(r.h.getSetCookie()[0]) && /HttpOnly/.test(r.h.getSetCookie()[0]) && /SameSite=None; Partitioned/.test(r.h.getSetCookie()[0]) && r.h.get("access-control-allow-origin") === STUDIO, [r.status, r.json, r.h.getSetCookie()]);
  r = await req("GET", `/r/${ns}/doc`, { headers: { Cookie: docCookies } });
  check("the cookie reads its resource", r.status === 302, r.status);
  r = await req("GET", `/r/${ns}/logo`, { headers: { Cookie: docCookies } });
  check("but nothing outside its prefix 401", r.status === 401, r.status);
  r = await req("PATCH", `/r/${ns}/doc`, { headers: { Cookie: docCookies }, body: [], });
  check("and never writes", r.status === 401 || r.status === 428, r.status);

  r = await eg(undefined, { headers: { "Content-Type": "application/json" }, raw: JSON.stringify({ grants: [star, one] }) });
  const nsCookies = cookies(r);
  check("several grants in the body", r.status === 200 && r.json?.prefixes?.length === 3 && r.json.prefixes.includes(`/ns/${ns}`) && r.json.prefixes.includes(`/r/${ns}`), r.json);
  r = await req("GET", `/ns/${ns}/log?since=&live=long-poll`, { headers: { Cookie: nsCookies } });
  check("a namespace cookie follows by long-poll", r.status === 200, r.status);
  const tampered = nsCookies.replace(/=([^.;]+)\./, (_, b) => `=${b.slice(0, -2)}AA.`);
  r = await req("GET", `/ns/${ns}`, { headers: { Cookie: tampered } });
  check("a tampered cookie counts for nothing 401", r.status === 401, r.status);
  r = await req("DELETE", `/edge-grants?prefix=/r/${ns}/doc&prefix=/r/${ns}/doc`, { headers: { Origin: STUDIO } });
  check("withdrawing", r.status === 204 && r.h.getSetCookie().length === 1 && /Max-Age=0/.test(r.h.getSetCookie()[0]), [r.status, r.h.getSetCookie()]);
  r = await req("DELETE", `/edge-grants?prefix=/elsewhere`);
  check("withdrawing a non-prefix 400", r.status === 400, r.status);
}

console.log(failed ? `\n${failed} failed` : "\nall passed");
process.exit(failed ? 1 : 0);
}
