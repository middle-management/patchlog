// Tests of the Bunny middleware: its cookie checks against Addendum I.5,
// then its hooks around a local origin with a simulated Bunny cache.
//   node bench/auth-smoke.mjs --serve      # the origin, on :8788
//   node edge/bunny/test.mjs [origin]
// Uses the development keys of bench/auth-smoke.mjs.

import { execFileSync } from "node:child_process";
globalThis.__PATCHLOG_TEST__ = true;
const { hooks, keysFrom, verify, cookieName, MARK } = await import("./middleware.ts");

let failed = 0;
const check = (name, cond, detail) => {
  if (cond) console.log(`ok   ${name}`);
  else { failed++; console.log(`FAIL ${name}`, detail ?? ""); }
};

// Addendum I.5.
{
  const keys = keysFrom(JSON.stringify([{ kid: "origin", key: "3dba7ab1a5240f2d1e3f4922b87f24be07b3e95885e0f515c57d6ac5c13dd708" }]));
  const value = "eyJleHAiOjE3OTAwMDA5MDAsImtpZCI6Im9yaWdpbiIsInAiOiIvci9kZW1vL2RlcmJ5In0.qn5oOZCcn6Au_LourbFpV2VbJ3u-XeiQlwNKAj43Lhw";
  const name = await cookieName("/r/demo/derby");
  check("I.5 cookie name", name === "__Secure-pl-eg-4390e78526d94754", name);
  const before = 1790000900 * 1000 - 1;
  const r = (path, h = {}) => new Request(`https://cdn.example${path}`, { headers: { Cookie: `${name}=${value}`, ...h } });
  check("I.5 verifies", (await verify(r("/r/demo/derby/rev/x"), keys, before)) === "/r/demo/derby");
  check("expired", (await verify(r("/r/demo/derby"), keys, 1790000900 * 1000)) === null);
  check("a path the prefix covers only as a string", (await verify(r("/r/demo/derbyx"), keys, before)) === null);
  check("with Authorization", (await verify(r("/r/demo/derby", { Authorization: "Bearer x" }), keys, before)) === null);
  check("another key", (await verify(r("/r/demo/derby"), keysFrom('[{"kid":"origin","key":"00"}]'), before)) === null);
  const reordered = Buffer.from('{"kid":"origin","exp":1790000900,"p":"/r/demo/derby"}').toString("base64url");
  check("claims not canonical", (await verify(new Request("https://cdn.example/r/demo/derby", { headers: { Cookie: `${name}=${reordered}.${value.split(".")[1]}` } }), keys, before)) === null);
}

// Around a local origin.
const origin = process.argv[2] ?? "http://127.0.0.1:8788";
const here = new URL(".", import.meta.url).pathname;
const CLI = `${here}../../target/debug/patchlog-grant`;
const cli = (...a) => execFileSync(CLI, a, { encoding: "utf8" }).trim();
const seed = (b) => b.toString(16).padStart(2, "0").repeat(32);
const pub = (b) => JSON.parse(cli("keygen", "--seed", seed(b))).pub;
const exp = new Date(Date.now() + 3600_000).toISOString().replace(/\.\d+Z$/, "Z");
const mint = (b, root) => cli("mint", "--seed", seed(b), "--root", JSON.stringify(root));
const keys = keysFrom(JSON.stringify([{ kid: "dev-edge", key: "11".repeat(32) }]));
const h = hooks(keys, "dev-edge-verify-secret", origin);

// The simulated pull zone: Bunny's cache keyed by the URL the client sent,
// query included, as measured (not by the URL onClientRequest returns).
const cache = new Map();
let originCalls = 0;
async function viaBunny(url, headers = {}) {
  const client = new Request(url.replace(origin, "https://cdn.example"), { headers });
  const r1 = await h.onClientRequest({ request: client });
  if (r1 instanceof Response) return r1;
  const key = client.url;
  let res;
  const hit = cache.get(key);
  if (hit && hit.until > Date.now()) {
    res = new Response(hit.body, { status: hit.status, headers: hit.headers });
    res.hit = true;
  } else {
    const r2 = await h.onOriginRequest({ request: r1 });
    originCalls++;
    const upstream = await fetch(r2.url.replace("https://cdn.example", origin), { headers: r2.headers, redirect: "manual" });
    res = await h.onOriginResponse({ request: r2, response: upstream });
    const cc = res.headers.get("Cache-Control") ?? "";
    const age = /max-age=(\d+)/.exec(cc);
    if (/public/.test(cc) && age && +age[1] > 0) {
      const body = await res.clone().arrayBuffer();
      cache.set(key, { body, status: res.status, headers: [...res.headers], until: Date.now() + age[1] * 1000 });
    }
  }
  const out = await h.onClientResponse({ request: r1, response: res });
  out.hit = res.hit;
  out.key = key;
  return out;
}

const OP_SEED = 1, ED = 3;
const ns = `edge-${Date.now().toString(36)}`;
let r = await fetch(`${origin}/ns/${ns}`, {
  method: "PATCH",
  headers: { Authorization: `Bearer ${mint(OP_SEED, { kid: "dev-operator", sub: "ops:x", ns: [ns], can: ["config"], exp })}`, "Content-Type": "application/json-patch+json", "If-None-Match": "*" },
  body: JSON.stringify([{ op: "add", path: "", value: { read: "grant", keys: [{ kid: "ed", alg: "Ed25519", pub: pub(ED), can: ["read", "create", "append"] }] } }]),
});
check("private namespace created", r.status === 201, await r.text());
const grant = mint(ED, { kid: "ed", sub: "user:x", ns: [ns], can: ["read", "create", "append"], exp });
r = await fetch(`${origin}/r/${ns}/doc`, { method: "PATCH", headers: { Authorization: `Bearer ${grant}`, "Content-Type": "application/json-patch+json", "If-None-Match": "*" }, body: JSON.stringify([{ op: "add", path: "", value: { a: 1 } }]) });
const id = r.headers.get("etag").slice(1, -1);
r = await fetch(`${origin}/edge-grants`, { method: "POST", headers: { Authorization: `Bearer ${grant}` } });
const cookie = r.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
check("cookies issued", r.status === 200 && cookie.includes("__Secure-pl-eg-"), r.status);

const rev = `${origin}/r/${ns}/doc/rev/${id}`;
r = await viaBunny(rev, { Cookie: cookie });
check("a verified read reaches the origin once", r.status === 200 && !r.hit, [r.status, r.key]);
check("the client sees private, with no edge headers", /^private/.test(r.headers.get("Cache-Control")) && !r.headers.get("CDN-Cache-Control") && !r.headers.get("X-Patchlog-Edge"), [...r.headers]);
const calls = originCalls;
r = await viaBunny(rev, { Cookie: cookie });
check("the next verified read is a hit", r.status === 200 && r.hit && originCalls === calls && /^private/.test(r.headers.get("Cache-Control")), [r.status, r.hit]);
r = await viaBunny(rev);
check("without a cookie, on the same cache entry: fetched from the origin, which refuses", r.status === 401 && r.hit, [r.status, r.hit]);
r = await viaBunny(rev, { "X-Edge-Verified": "dev-edge-verify-secret", "X-Edge-Prefix": `/r/${ns}` });
check("forged edge headers are stripped", r.status === 401, r.status);
r = await viaBunny(rev, { Cookie: cookie, Authorization: `Bearer ${grant}` });
check("with Authorization, on the same entry: fetched from the origin, as for no cache", r.status === 200 && r.hit && /no-store/.test(r.headers.get("CDN-Cache-Control") ?? ""), [r.status, r.hit, r.headers.get("CDN-Cache-Control")]);
const other = `${origin}/r/${ns}/elsewhere`;
r = await viaBunny(other, { Cookie: cookie });
check("a cookie for the namespace reads another resource", r.status === 404 || r.status === 302, r.status);

// The origin's side alone.
r = await fetch(rev, { headers: { Cookie: cookie, "X-Edge-Verified": "dev-edge-verify-secret", "X-Edge-Prefix": `/r/${ns}` } });
check("origin: a verified read gets edge lifetimes", r.status === 200 && r.headers.get("CDN-Cache-Control") === "max-age=31536000, immutable" && r.headers.get("Cloudflare-CDN-Cache-Control") === "no-store" && /^private/.test(r.headers.get("Cache-Control")) && !r.headers.get("X-Patchlog-Class"), [...r.headers]);
for (const [what, hd] of [
  ["a wrong secret", { "X-Edge-Verified": "nope", "X-Edge-Prefix": `/r/${ns}` }],
  ["a prefix that doesn't cover the path", { "X-Edge-Verified": "dev-edge-verify-secret", "X-Edge-Prefix": `/r/${ns}/other` }],
  ["a comma", { "X-Edge-Verified": "dev-edge-verify-secret, x", "X-Edge-Prefix": `/r/${ns}` }],
  ["no cookie", { "X-Edge-Verified": "dev-edge-verify-secret", "X-Edge-Prefix": `/r/${ns}`, Cookie: "" }],
]) {
  r = await fetch(rev, { headers: { Cookie: cookie, ...hd } });
  check(`origin: ${what} gets no edge lifetime`, r.headers.get("CDN-Cache-Control") === "no-store" || r.status === 401, [r.status, r.headers.get("CDN-Cache-Control")]);
}
r = await fetch(`${origin}/ns/${ns}/log?since=&live=long-poll`, { headers: { Cookie: cookie, "X-Edge-Verified": "dev-edge-verify-secret", "X-Edge-Prefix": `/ns/${ns}` } });
check("origin: a verified long-poll gets an edge lifetime", r.status === 200 && r.headers.get("CDN-Cache-Control") === "max-age=20", [r.status, r.headers.get("CDN-Cache-Control")]);
r = await viaBunny(`${origin}/ns/${ns}/log?since=&live=long-poll`, { Cookie: cookie });
const lpCalls = originCalls;
const again = await viaBunny(`${origin}/ns/${ns}/log?since=&live=long-poll`, { Cookie: cookie });
check("verified long-polls share Bunny's cache", again.status === 200 && again.hit && originCalls === lpCalls, [again.status, again.hit]);

console.log(failed ? `\n${failed} failed` : "\nall passed");
process.exit(failed ? 1 : 0);
