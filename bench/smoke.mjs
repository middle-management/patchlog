// End-to-end checks against a running deployment (default: wrangler dev).
//   node bench/smoke.mjs [base-url]
// Exercises namespace creation, create/append/delete/restore with the ids of
// Addendum I.2, preconditions, idempotent retries, reads, log ranges and a
// long-poll that a write wakes.

import { EnvHttpProxyAgent, setGlobalDispatcher } from "undici";

if (process.env.HTTPS_PROXY) setGlobalDispatcher(new EnvHttpProxyAgent());

const base = process.argv[2] ?? "http://127.0.0.1:8787";
const ns = `smoke-${Date.now().toString(36)}`;
let failed = 0;

async function req(method, path, { body, headers = {} } = {}) {
  const h = { "X-Author": "smoke", ...(body !== undefined ? { "Content-Type": "application/json-patch+json" } : {}), ...headers };
  const r = await fetch(base + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), redirect: "manual" });
  const text = await r.text();
  let json;
  try { json = text ? JSON.parse(text) : undefined; } catch { json = text; }
  return { status: r.status, h: r.headers, json, text };
}

function check(name, cond, detail) {
  if (cond) console.log(`ok   ${name}`);
  else { failed++; console.log(`FAIL ${name}`, detail ?? ""); }
}

const p1 = [{ op: "add", path: "", value: { title: "Hello", views: 0 } }];
const p2 = [{ op: "replace", path: "/views", value: 1 }];
const g = "1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll", c = "1sywh54kpo3c4ezn2znktvl3avge4zl5d", t = "1idx6u2b3z42obqmwsgmlzvrfuutks2bq";

let r = await req("PATCH", `/ns/${ns}`, { body: [{ op: "add", path: "", value: { read: "public" } }], headers: { "If-None-Match": "*" } });
check("create namespace 201", r.status === 201, r);
const config = r.h.get("x-config-revision");
r = await req("PATCH", `/ns/${ns}`, { body: [{ op: "add", path: "", value: {} }], headers: { "If-None-Match": "*" } });
check("namespace name taken 412", r.status === 412, r);
r = await req("PATCH", `/ns/${ns}`, { body: [{ op: "add", path: "/rules", value: [] }], headers: { "If-Match": `"${config}"` } });
check("unimplemented member 422", r.status === 422 && r.json.errors?.[0]?.pointer === "/rules", r.json);

r = await req("PATCH", `/r/${ns}/derby`, { body: p1 });
check("no precondition 428", r.status === 428, r);
r = await req("PATCH", `/r/${ns}/derby`, { body: p1, headers: { "If-None-Match": "*" } });
check("create 201 with the genesis id of I.2", r.status === 201 && r.h.get("etag") === `"${g}"`, [r.status, r.h.get("etag"), r.json]);
const nsAfterCreate = r.h.get("x-namespace-revision");
r = await req("PATCH", `/r/${ns}/derby`, { body: p1, headers: { "If-None-Match": "*" } });
check("create retry is 200 (idempotent)", r.status === 200 && r.h.get("x-namespace-revision") === nsAfterCreate, r.status);
r = await req("PATCH", `/r/${ns}/derby`, { body: p1, headers: { "If-None-Match": "*", "X-Author": "someone-else" } });
check("create by another author 412", r.status === 412 && r.json.head === g, r.json);

r = await req("PATCH", `/r/${ns}/derby`, { body: p2, headers: { "If-Match": `"${g}"` } });
check("append 201 with the child id of I.2", r.status === 201 && r.h.get("etag") === `"${c}"`, [r.status, r.h.get("etag")]);
r = await req("PATCH", `/r/${ns}/derby`, { body: [{ op: "replace", path: "/views", value: 2 }], headers: { "If-Match": `"${g}"` } });
check("stale append 412 with head", r.status === 412 && r.json.head === c, r.json);
r = await req("PATCH", `/r/${ns}/derby`, { body: [{ op: "test", path: "/views", value: 5 }], headers: { "If-Match": `"${c}"` } });
check("failing test 422", r.status === 422 && r.json.code === "invalid", r.json);
r = await req("PATCH", `/r/${ns}/derby`, { body: p2, headers: { "If-Match": `"${c}"`, "Content-Type": "text/plain" } });
check("wrong content type 415", r.status === 415, r.status);
r = await req("PATCH", `/r/${ns}/derby`, { body: [{ op: "add", path: "/$schema", value: "/r/schemas/x/rev/1" }], headers: { "If-Match": `"${c}"` } });
check("typed documents refused 422", r.status === 422, r.json);
r = await req("PATCH", `/r/${ns}/derby`, { body: [{ op: "add", path: "/big", value: "x".repeat(70000) }], headers: { "If-Match": `"${c}"` } });
check("valueSize 422", r.status === 422 && r.json.limit === "patchSetSize" || r.json.limit === "valueSize", r.json);

r = await req("GET", `/r/${ns}/derby`);
check("head 302", r.status === 302 && r.h.get("location") === `/r/${ns}/derby/rev/${c}`, [r.status, r.h.get("location")]);
check("head cache class", r.h.get("cache-control")?.includes("s-maxage=1"), r.h.get("cache-control"));
r = await req("GET", `/r/${ns}/derby/rev/${c}`);
check("document 200", r.status === 200 && r.text === '{"title":"Hello","views":1}', r.text);
check("immutable", r.h.get("cache-control")?.includes("immutable") && r.h.get("repr-digest")?.startsWith("sha-256=:"), [...r.h]);
r = await req("GET", `/r/${ns}/derby/rev/${g}`);
check("old revision 200", r.status === 200 && r.text === '{"title":"Hello","views":0}', r.text);
r = await req("GET", `/r/${ns}/derby/rev/${c}`, { headers: { "If-None-Match": `"${c}"` } });
check("If-None-Match 304", r.status === 304, r.status);
r = await req("GET", `/r/${ns}/derby/rev/${c}/log`);
check("log range", r.status === 200 && r.json.length === 2 && r.json[1].parent === g && r.json[1].patches[0].op === "replace", r.json);
r = await req("GET", `/r/${ns}/derby/rev/${g}/log?since=${c}`);
check("since not an ancestor 404", r.status === 404, r.status);
r = await req("GET", `/r/${ns}/derby/rev/${c}/log?x=1`);
check("unknown query parameter 400", r.status === 400, r.status);
r = await req("GET", `/r/${ns}/Derby`);
check("malformed name 400", r.status === 400, r.status);
r = await req("GET", `/r/${ns}/derby%2F`);
check("percent-escape 400", r.status === 400, r.status);

// A long-poll waits, and the next write answers it.
r = await req("GET", `/ns/${ns}/log?since=&live=long-poll`);
check("long-poll without cursor answers at once", r.status === 200 && r.h.get("x-cursor"), r.status);
const cursor = r.h.get("x-cursor");
const head = r.h.get("x-namespace-revision");
const t0 = Date.now();
const poll = req("GET", `/ns/${ns}/log?since=${head}&live=long-poll&cursor=${cursor}`);
await new Promise((res) => setTimeout(res, 300));
r = await req("DELETE", `/r/${ns}/derby`, { headers: { "If-Match": `"${c}"` } });
check("delete 200 with the tombstone of I.2", r.status === 200 && r.json.tombstone === t, r.json);
const woke = await poll;
check("the write wakes the long-poll", woke.status === 200 && woke.json.length === 1 && woke.json[0].kind === "tombstone" && Date.now() - t0 < 5000, [woke.status, woke.json]);

r = await req("GET", `/r/${ns}/derby`);
check("tombstoned head 410", r.status === 410 && r.json.tombstone === t && r.json.last === c, r.json);
r = await req("PATCH", `/r/${ns}/derby`, { body: p2, headers: { "If-Match": `"${c}"` } });
check("append on a tombstone 410 gone", r.status === 410 && r.json.head === t, r.json);
r = await req("PATCH", `/r/${ns}/derby`, { body: [{ op: "replace", path: "/views", value: 7 }], headers: { "If-Match": `"${t}"` } });
check("restore 201", r.status === 201, r);
const restored = r.h.get("etag").slice(1, -1);
r = await req("GET", `/r/${ns}/derby/rev/${restored}`);
check("restored document", r.text === '{"title":"Hello","views":7}', r.text);

r = await req("GET", `/ns/${ns}`);
const nsHead = r.h.get("location");
r = await req("GET", nsHead + "/log");
check("namespace log", r.status === 200 && r.json.map((e) => e.kind).join() === "config,head,head,tombstone,head" && r.json[0].prev === null && r.json[1].prev === r.json[0].id, r.json.map((e) => e.kind));
r = await req("GET", nsHead);
check("namespace document", r.status === 200 && r.json.read === "public", r.json);

console.log(failed ? `\n${failed} failed` : "\nall passed");
process.exit(failed ? 1 : 0);
