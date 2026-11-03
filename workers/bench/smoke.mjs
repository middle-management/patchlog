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
r = await req("PATCH", `/ns/${ns}`, { body: [{ op: "add", path: "/keys", value: [] }], headers: { "If-Match": `"${config}"` } });
check("unimplemented member 422", r.status === 422 && r.json.errors?.[0]?.pointer === "/keys", r.json);

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

// Typed documents (§6.1, §6.2 step 5).
const D = "https://json-schema.org/draft/2020-12/schema";
const sns = `${ns}-s`;
await req("PATCH", `/ns/${sns}`, { body: [{ op: "add", path: "", value: { read: "public" } }], headers: { "If-None-Match": "*" } });
r = await req("PATCH", `/r/${sns}/name`, { body: [{ op: "add", path: "", value: { $schema: D, type: "string", minLength: 2, pattern: "^\\u00c5?[A-Za-z]" } }], headers: { "If-None-Match": "*" } });
check("schema document created", r.status === 201, r.json);
const nameRev = `/r/${sns}/name/rev/${r.h.get("etag").slice(1, -1)}`;
r = await req("PATCH", `/r/${ns}/post-schema`, { body: [{ op: "add", path: "", value: { $schema: D, type: "object", required: ["title"], properties: { title: { $ref: nameRev }, tags: { type: "array", items: { type: "string" } } }, additionalProperties: false, "x-index": { by: "title" } } }], headers: { "If-None-Match": "*" } });
check("schema referring to another namespace's schema", r.status === 201, r.json);
const postRev = `/r/${ns}/post-schema/rev/${r.h.get("etag").slice(1, -1)}`;
r = await req("PATCH", `/r/${ns}/post-1`, { body: [{ op: "add", path: "", value: { $schema: postRev, title: "Åsa", tags: ["a"] } }], headers: { "If-None-Match": "*" } });
check("typed document valid", r.status === 201, r.json);
const postHead = r.h.get("etag");
r = await req("PATCH", `/r/${ns}/post-1`, { body: [{ op: "replace", path: "/title", value: "x" }], headers: { "If-Match": postHead } });
check("append that breaks the schema 422 invalid", r.status === 422 && r.json.code === "invalid" && r.json.errors?.[0]?.pointer === "/title", r.json);
r = await req("PATCH", `/r/${ns}/post-2`, { body: [{ op: "add", path: "", value: { $schema: postRev, title: "Hi", extra: 1 } }], headers: { "If-None-Match": "*" } });
check("additional property 422 invalid", r.status === 422 && r.json.errors?.some((e) => e.pointer === "" || e.pointer === "/extra"), r.json);
r = await req("PATCH", `/r/${ns}/post-3`, { body: [{ op: "add", path: "", value: { $schema: "https://example.com/s", title: "Hi" } }], headers: { "If-None-Match": "*" } });
check("foreign $schema 422 schema_ref", r.status === 422 && r.json.code === "schema_ref", r.json);
r = await req("PATCH", `/r/${ns}/post-4`, { body: [{ op: "add", path: "", value: { $schema: `/r/${ns}/nope/rev/${c}`, title: "Hi" } }], headers: { "If-None-Match": "*" } });
check("unknown schema revision 422 schema_unavailable", r.status === 422 && r.json.code === "schema_unavailable" && r.json.path === `/r/${ns}/nope/rev/${c}`, r.json);
r = await req("PATCH", `/r/${ns}/post-5`, { body: [{ op: "add", path: "", value: { $schema: `/r/${ns}/derby/rev/${c}`, title: "Hi" } }], headers: { "If-None-Match": "*" } });
check("a non-schema document 422 schema_unavailable", r.status === 422 && r.json.code === "schema_unavailable", r.json);
for (const [what, bad] of [["$id", { $id: "x" }], ["an unknown keyword", { frob: 1 }], ["an unknown format", { format: "phone" }], ["a non-RE2 pattern", { pattern: "(a)\\1" }]]) {
  r = await req("PATCH", `/r/${ns}/bad-schema`, { body: [{ op: "add", path: "", value: { $schema: D, ...bad } }], headers: { "If-None-Match": "*" } });
  check(`schema with ${what} 422 invalid`, r.status === 422 && r.json.code === "invalid", r.json);
}

// A catalog namespace with the rules of §B.6.
const cat = `${ns}-cat`;
const catDoc = {
  read: "public",
  catalog: { trust: [ns], mode: "tree" },
  rules: [
    { op: "test", path: "/resource", schema: { pattern: `^([a-z0-9][a-z0-9_-]*|(${ns})\\.[a-z0-9][a-z0-9._-]*)$` } },
    { if: [{ op: "test", path: "/action", schema: { enum: ["create", "append", "restore"] } }, { op: "test", path: "/doc/parents", exists: true }],
      then: [{ op: "test", path: "/doc/parents", schema: { type: "array", maxItems: 1, items: { type: "object", required: ["href"], additionalProperties: false, properties: { href: { type: "string", pattern: `^/r/${cat}/[a-z0-9][a-z0-9_-]{0,127}$` }, order: { type: "string", pattern: "^[0-9A-Za-z]{1,64}$" } } } } }] },
    { if: [{ op: "test", path: "/action", value: "create" }], then: [{ op: "test", path: "/doc/parents", schema: { minItems: 1 } }] },
  ],
};
r = await req("PATCH", `/ns/${cat}`, { body: [{ op: "add", path: "", value: catDoc }], headers: { "If-None-Match": "*" } });
check("catalog namespace with rules created", r.status === 201, r.json);
r = await req("PATCH", `/r/${cat}/root`, { body: [{ op: "add", path: "", value: { title: "Root" } }], headers: { "If-None-Match": "*" } });
check("a new node without parents 422 rule", r.status === 422 && r.json.code === "rule" && r.json.path === "/rules/2/then/0", r.json);
r = await req("PATCH", `/r/${cat}/season`, { body: [{ op: "add", path: "", value: { title: "Season", parents: [{ href: `/r/${cat}/root`, order: "a0" }] } }], headers: { "If-None-Match": "*" } });
check("folder with one parent 201", r.status === 201, r.json);
r = await req("PATCH", `/r/${cat}/${ns}.post-1`, { body: [{ op: "add", path: "", value: { parents: [{ href: `/r/${cat}/season` }, { href: `/r/${cat}/root` }] } }], headers: { "If-None-Match": "*" } });
check("placement with two parents in a tree 422 rule", r.status === 422 && r.json.code === "rule" && r.json.rule === 1, r.json);
r = await req("PATCH", `/r/${cat}/elsewhere.post-1`, { body: [{ op: "add", path: "", value: { parents: [{ href: `/r/${cat}/season` }] } }], headers: { "If-None-Match": "*" } });
check("placement of an untrusted namespace's item 422 rule", r.status === 422 && r.json.rule === 0, r.json);
r = await req("PATCH", `/r/${cat}/${ns}.post-1`, { body: [{ op: "add", path: "", value: { parents: [{ href: `/r/${cat}/season`, order: "a1" }] } }], headers: { "If-None-Match": "*", Gesture: "abcdefghijklmnopqrstuvwxyz" } });
check("placement 201", r.status === 201, r.json);
const placement = r.h.get("etag").slice(1, -1);
r = await req("PATCH", `/ns/${cat}`, { body: [{ op: "add", path: "/rules/-", value: { op: "test", path: "/doc", schema: { $id: "x" } } }], headers: { "If-Match": `"${r.h.get("x-namespace-revision") && (await req("GET", `/ns/${cat}`)).h.get("x-config-revision")}"` } });
check("a rule with an invalid schema 422 invalid", r.status === 422 && r.json.code === "invalid", r.json);

// Resource logs (§7.1, §7.7), heads at a revision and gestures (§7.4).
r = await req("GET", `/r/${cat}/${ns}.post-1/log`);
check("resource log redirects to its range", r.status === 302 && r.h.get("location") === `/r/${cat}/${ns}.post-1/rev/${placement}/log`, [r.status, r.h.get("location")]);
r = await req("GET", `/r/${cat}/nothing-here/log`);
check("log of a resource with no entries 404", r.status === 404, r.status);
{
  const first = await req("GET", `/r/${cat}/season/log?since=&live=long-poll`);
  const since = first.h.get("x-revision"), cur = first.h.get("x-cursor");
  check("resource long-poll answers at once with entries", first.status === 200 && first.json.length === 1 && !!since, [first.status, first.json]);
  const poll = req("GET", `/r/${cat}/season/log?since=${since}&live=long-poll&cursor=${cur}`);
  await new Promise((res) => setTimeout(res, 300));
  await req("PATCH", `/r/${cat}/season`, { body: [{ op: "replace", path: "/title", value: "Season 2026" }], headers: { "If-Match": `"${since}"` } });
  const woke = await poll;
  check("a write to the resource wakes its long-poll", woke.status === 200 && woke.json.length === 1 && woke.json[0].patches?.[0]?.path === "/title", [woke.status, woke.json]);
}
r = await req("GET", `/ns/${cat}`);
const catRev = r.h.get("location");
r = await req("GET", `${catRev}/heads`);
check("heads at a revision", r.status === 200 && r.json.heads?.map((h) => h.resource).join() === ["season", `${ns}.post-1`].sort().join() && r.json.heads.find((h) => h.resource === `${ns}.post-1`)?.target === placement, r.json);
r = await req("GET", `/ns/${cat}/gestures/abcdefghijklmnopqrstuvwxyz`);
check("gesture listing", r.status === 200 && r.json.length === 1 && r.json[0].resource === `${ns}.post-1` && r.json[0].id === placement, r.json);
r = await req("GET", `/ns/${cat}/gestures/not-a-gesture`);
check("malformed gesture 400", r.status === 400, r.status);

console.log(failed ? `\n${failed} failed` : "\nall passed");
process.exit(failed ? 1 : 0);
