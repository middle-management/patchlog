// End-to-end checks against a running deployment (default: wrangler dev).
//   node bench/smoke.mjs [base-url]
// Exercises namespace creation, create/append/delete/restore with the ids of
// Addendum I.2, preconditions, idempotent retries, reads, log ranges and a
// long-poll that a write wakes.

import { EnvHttpProxyAgent, setGlobalDispatcher } from "undici";
import { load, save, listHeads } from "../client/patchlog.mjs";

if (process.env.HTTPS_PROXY) setGlobalDispatcher(new EnvHttpProxyAgent());

const base = process.argv[2] ?? "http://127.0.0.1:8787";
const ns = `smoke-${Date.now().toString(36)}`;
let failed = 0;

async function req(method, path, { body, headers = {}, raw } = {}) {
  const h = { "X-Author": "smoke", ...(body !== undefined ? { "Content-Type": "application/json-patch+json" } : {}), ...headers };
  const r = await fetch(base + path, { method, headers: h, body: raw ?? (body === undefined ? undefined : JSON.stringify(body)), redirect: "manual" });
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
r = await req("PATCH", `/ns/${ns}`, { body: [{ op: "add", path: "/retention", value: {} }], headers: { "If-Match": `"${config}"` } });
check("unimplemented member 422", r.status === 422 && r.json.errors?.[0]?.pointer === "/retention", r.json);

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
// A poll sent after the interval rolled over is answered 204 at once (§7.7);
// a client polls again with the cursor it got, as this does.
const poll = (async () => {
  let cur = cursor, p;
  for (let i = 0; i < 3; i++) {
    p = await req("GET", `/ns/${ns}/log?since=${head}&live=long-poll&cursor=${cur}`);
    if (p.status !== 204) return p;
    cur = p.h.get("x-cursor");
  }
  return p;
})();
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
  // Polls again on a 204: the interval may roll over first (§7.7).
  const poll = (async () => {
    let c = cur, p;
    for (let i = 0; i < 3; i++) {
      p = await req("GET", `/r/${cat}/season/log?since=${since}&live=long-poll&cursor=${c}`);
      if (p.status !== 204) return p;
      c = p.h.get("x-cursor");
    }
    return p;
  })();
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

// Batches (§7.5).
const bns = `${ns}-b`;
await req("PATCH", `/ns/${bns}`, { body: [{ op: "add", path: "", value: { read: "public" } }], headers: { "If-None-Match": "*" } });
const batch = (body, extra = "", headers = {}) => req("POST", `/ns/${bns}/batch${extra}`, { body: undefined, headers: { "Content-Type": "application/json", ...headers }, raw: JSON.stringify(body) });
r = await req("PATCH", `/r/${bns}/a`, { body: [{ op: "add", path: "", value: { n: 0 } }], headers: { "If-None-Match": "*" } });
const a0 = r.h.get("etag").slice(1, -1);
const g1 = "bcdefghijklmnopqrstuvwxyza";
const b1 = { gesture: g1, items: [
  { resource: "a", ifMatch: a0, steps: [[{ op: "replace", path: "/n", value: 1 }], [{ op: "replace", path: "/n", value: 2 }]] },
  { resource: "b", ifNoneMatch: "*", steps: [[{ op: "add", path: "", value: { n: 10 } }]] },
] };
r = await batch(b1, "?dry-run=1");
check("batch dry run reports, writes nothing", r.status === 200 && r.json.items?.every((i) => i.status === 201) && (await req("GET", `/r/${bns}/b`)).status === 404, r.json);
r = await batch(b1);
check("batch 201 with each item's ids", r.status === 201 && r.json.items?.[0]?.ids?.length === 2 && r.json.items?.[1]?.ids?.length === 1 && r.h.get("x-namespace-revision") === r.json.ns_id, r.json);
const b1ns = r.json.ns_id, aIds = r.json.items[0].ids;
r = await req("GET", `/r/${bns}/a/rev/${aIds[1]}`);
check("batch revisions readable", r.status === 200 && r.json.n === 2, r.json);
r = await batch(b1);
check("batch retry 200 with the same entry", r.status === 200 && r.json.ns_id === b1ns, r.json);
r = await req("GET", `/ns/${bns}/log?live=long-poll&since=`);
const bentry = r.json.find((e) => e.id === b1ns);
check("one batch entry in the namespace log, with gestures", bentry?.kind === "batch" && bentry.entries.length === 2 && bentry.gestures?.a?.length === 2 && bentry.gestures.a[0].gesture === g1, bentry);
r = await req("GET", `/r/${bns}/a/rev/${aIds[1]}/log`);
check("batch steps in the resource log", r.status === 200 && r.json.length === 3 && r.json[1].id === aIds[0], r.json.map((e) => e.id));
r = await batch({ items: [
  { resource: "a", ifMatch: aIds[1], steps: [[{ op: "replace", path: "/n", value: 3 }]] },
  { resource: "b", ifMatch: a0, steps: [[{ op: "replace", path: "/n", value: 11 }]] },
] });
check("a stale item fails the batch with 412", r.status === 412 && r.json.code === "batch" && r.json.items?.length === 1 && r.json.items[0].index === 1, r.json);
r = await req("GET", `/r/${bns}/a`);
check("nothing written by a failed batch", r.h.get("location")?.endsWith(aIds[1]), r.h.get("location"));
r = await batch({ items: [{ resource: "a", ifMatch: aIds[1], steps: [[{ op: "replace", path: "/n", value: 4 }], "delete", [{ op: "replace", path: "/n", value: 5 }]] }] });
check("append, delete and restore in one item", r.status === 201 && r.json.items[0].ids.length === 3, r.json);
r = await req("GET", `/r/${bns}/a/rev/${r.json?.items?.[0]?.ids?.[2]}`);
check("restored document", r.json?.n === 5, r.json);
r = await req("GET", `/ns/${bns}`);
const bcfg = r.h.get("x-config-revision");
r = await batch({ config: { ifMatch: bcfg, patches: [{ op: "add", path: "/x-note", value: "batched" }] }, items: [
  { resource: "schema-1", ifNoneMatch: "*", steps: [[{ op: "add", path: "", value: { $schema: D, type: "object", required: ["n"] } }]] },
] });
check("config change with items", r.status === 201 && r.json.config && r.h.get("x-config-revision") === r.json.config, r.json);
const schemaRev = `/r/${bns}/schema-1/rev/${r.json.items[0].ids[0]}`;
r = await batch({ items: [
  { resource: "schema-2", ifNoneMatch: "*", steps: [[{ op: "add", path: "", value: { $schema: D, type: "object", required: ["m"] } }]] },
  { resource: "typed", ifNoneMatch: "*", steps: [[{ op: "add", path: "", value: { $schema: schemaRev, n: 1 } }]] },
] });
check("typed item in a batch", r.status === 201, r.json);
const s2 = `/r/${bns}/schema-2/rev/${(await req("GET", `/r/${bns}/schema-2`)).h.get("location")?.split("/").pop()}`;
r = await batch({ items: [
  { resource: "schema-3", ifNoneMatch: "*", steps: [[{ op: "add", path: "", value: { $schema: D, type: "object", required: ["q"] } }]] },
  { resource: "typed-2", ifNoneMatch: "*", steps: [[{ op: "add", path: "", value: { $schema: s2, m: 1 } }]] },
  { resource: "typed-3", ifNoneMatch: "*", steps: [[{ op: "add", path: "", value: { $schema: s2, x: 1 } }]] },
] });
check("an invalid item fails the batch with 422", r.status === 422 && r.json.code === "batch" && r.json.items?.[0]?.index === 2 && r.json.items[0].code === "invalid", r.json);
r = await req("POST", `/ns/${cat}/batch`, { headers: { "Content-Type": "application/json" }, raw: JSON.stringify({ items: [{ resource: `${ns}.post-2`, ifNoneMatch: "*", steps: [[{ op: "add", path: "", value: { parents: [{ href: `/r/${cat}/season` }, { href: `/r/${cat}/root` }] } }]] }] }) });
check("a rule failing in a batch 422", r.status === 422 && r.json.items?.[0]?.code === "rule", r.json);
r = await batch({ items: [{ resource: "a", steps: [["x"]] }] });
check("item without a precondition 428", r.status === 428, r.status);
r = await batch({ items: [] });
check("a batch with neither items nor config 400", r.status === 400, r.status);

// Blobs (§7.8): upload, attach by reference, read, ranges, raw documents.
import { createHash } from "node:crypto";
function blobId(type, nonce, bytes) {
  const d = createHash("sha256").update(`patchlog-blob-v1\n${type}\n${nonce}\n`).update(bytes).digest().subarray(0, 20);
  const A = "abcdefghijklmnopqrstuvwxyz234567";
  let s = "1", acc = 0n, bits = 0;
  for (const b of d) { acc = (acc << 8n) | BigInt(b); bits += 8; while (bits >= 5) { bits -= 5; s += A[Number((acc >> BigInt(bits)) & 31n)]; } }
  return s;
}
const blns = `${ns}-blob`;
await req("PATCH", `/ns/${blns}`, { body: [{ op: "add", path: "", value: { read: "public" } }], headers: { "Content-Type": "application/json-patch+json", "If-None-Match": "*" } });
const bytes = Buffer.from("hello, blob world\n".repeat(100));
const bid = blobId("text/plain", "", bytes);
const put = (name, id, body, type = "text/plain", headers = {}) => req("PUT", `/r/${blns}/${name}/blob/${id}`, { raw: body, headers: { "Content-Type": type, ...headers } });
r = await put("doc", bid, Buffer.from("wrong bytes"));
check("upload with the wrong id 422 blob_mismatch", r.status === 422 && r.json?.code === "blob_mismatch" && r.h.get("x-content-type-options") === "nosniff", r.json);
r = await put("doc", bid, bytes, "text/plain", { "If-Match": "\"x\"" });
check("upload with a precondition 428", r.status === 428, r.status);
r = await put("doc", bid, bytes, "Text/Plain; charset=utf-8");
check("upload 201 with the blob's ETag", r.status === 201 && r.h.get("etag") === `"${bid}"`, r.json);
r = await req("GET", `/r/${blns}/doc/blob/${bid}`);
check("a pending blob isn't served", r.status === 404, r.status);
const ref = { $blob: bid, type: "text/plain", size: bytes.length };
r = await req("PATCH", `/r/${blns}/doc`, { body: [{ op: "add", path: "", value: { body: ref } }], headers: { "If-None-Match": "*" } });
check("a write referencing a pending blob attaches it", r.status === 201, r.json);
r = await req("PATCH", `/r/${blns}/other`, { body: [{ op: "add", path: "", value: { body: ref } }], headers: { "If-None-Match": "*" } });
check("another resource can't reference it", r.status === 422 && r.json?.code === "blob", r.json);
r = await req("PATCH", `/r/${blns}/other`, { body: [{ op: "add", path: "", value: { body: { ...ref, size: 1 } } }], headers: { "If-None-Match": "*" } });
check("a reference with the wrong size 422 blob", r.status === 422 && r.json?.code === "blob", r.json);
r = await req("GET", `/r/${blns}/doc/blob/${bid}`);
check("attached blob served", r.status === 200 && r.text === bytes.toString() && r.h.get("content-type") === "text/plain; charset=utf-8" && r.h.get("content-security-policy") === "sandbox" && /immutable/.test(r.h.get("cache-control") ?? ""), [r.status, r.h.get("content-type"), r.h.get("cache-control")]);
r = await req("GET", `/r/${blns}/doc/blob/${bid}`, { headers: { Range: "bytes=7-10" } });
check("range read 206", r.status === 206 && r.text === "blob" && r.h.get("content-range") === `bytes 7-10/${bytes.length}`, [r.status, r.text, r.h.get("content-range")]);
r = await req("GET", `/r/${blns}/doc/blob/${bid}`, { headers: { Range: `bytes=${bytes.length}-` } });
check("unsatisfiable range 416", r.status === 416, r.status);
r = await req("PUT", `/r/${blns}/other/blob/${bid}`, { raw: "", headers: { "Blob-From": `/r/${blns}/doc/blob/${bid}` } });
check("copy from another resource 201", r.status === 201, r.json);
r = await req("PATCH", `/r/${blns}/other`, { body: [{ op: "add", path: "", value: { body: ref } }], headers: { "If-None-Match": "*" } });
check("the copy can be referenced", r.status === 201, r.json);
const font = Buffer.from([0x77, 0x4f, 0x46, 0x32, 1, 2, 3]);
const nonce = "abcdefghijklmnopqrstuvwxyz";
const fid = blobId("font/woff2", nonce, font);
r = await put("font", fid, font, "font/woff2", { "Blob-Nonce": nonce });
check("upload with a nonce", r.status === 201, r.json);
r = await req("PATCH", `/r/${blns}/font`, { body: [{ op: "add", path: "", value: { $blob: fid, type: "font/woff2", size: font.length, nonce } }], headers: { "If-None-Match": "*" } });
check("a raw document", r.status === 201, r.json);
r = await req("GET", `/r/${blns}/font/raw`);
check("raw redirects to the blob", r.status === 302 && r.h.get("location") === `/r/${blns}/font/blob/${fid}`, [r.status, r.h.get("location")]);
r = await req("GET", `/r/${blns}/doc/raw`);
check("raw of a non-raw document 404", r.status === 404, r.status);
r = await req("GET", `/r/${blns}/font/blob/${fid}`);
check("font served", r.status === 200 && r.h.get("content-type") === "font/woff2" && r.h.get("content-length") === String(font.length), [r.status, r.h.get("content-type")]);
r = await req("PATCH", `/r/${blns}/bad`, { body: [{ op: "add", path: "", value: { x: { $blob: bid, type: "text/plain" } } }], headers: { "If-None-Match": "*" } });
check("malformed reference 422 blob", r.status === 422 && r.json?.code === "blob", r.json);
const b2 = Buffer.from("batched blob");
const b2id = blobId("text/plain", "", b2);
await put("batched", b2id, b2);
r = await req("POST", `/ns/${blns}/batch`, { headers: { "Content-Type": "application/json" }, raw: JSON.stringify({ items: [{ resource: "batched", ifNoneMatch: "*", steps: [[{ op: "add", path: "", value: { f: { $blob: b2id, type: "text/plain", size: b2.length } } }]] }] }) });
check("a batch attaches a blob", r.status === 201, r.json);
r = await req("GET", `/r/${blns}/batched/blob/${b2id}`);
check("batched blob served", r.status === 200 && r.text === "batched blob", r.status);

{
// Branches (§7.6): creation, listing, reading through, first writes, merging back.
const bb = `${ns}-base`, br = `${ns}-br`;
const etag = (r) => r.h.get("etag")?.slice(1, -1);
await req("PATCH", `/ns/${bb}`, { body: [{ op: "add", path: "", value: { read: "public" } }], headers: { "If-None-Match": "*" } });
r = await req("PATCH", `/r/${bb}/a`, { body: [{ op: "add", path: "", value: { v: 1 } }], headers: { "If-None-Match": "*" } });
const a1 = etag(r);
r = await req("PATCH", `/r/${bb}/b`, { body: [{ op: "add", path: "", value: { v: "b" } }], headers: { "If-None-Match": "*" } });
const b1 = etag(r);
r = await req("PATCH", `/r/${bb}/c`, { body: [{ op: "add", path: "", value: { v: "c" } }], headers: { "If-None-Match": "*" } });
r = await req("DELETE", `/r/${bb}/c`, { headers: { "If-Match": `"${etag(r)}"` } });
const pic = Buffer.from("pixels"), picId = blobId("image/png", "", pic);
await req("PUT", `/r/${bb}/pic/blob/${picId}`, { raw: pic, headers: { "Content-Type": "image/png" } });
r = await req("PATCH", `/r/${bb}/pic`, { body: [{ op: "add", path: "", value: { $blob: picId, type: "image/png", size: pic.length } }], headers: { "If-None-Match": "*" } });
check("base set up", r.status === 201, r.json);
const branchReq = (body, headers = { "If-None-Match": "*" }) => req("POST", `/ns/${bb}/branches`, { headers: { "Content-Type": "application/json", ...headers }, raw: JSON.stringify(body) });
r = await branchReq({ name: br }, { "If-Match": `"${a1}"` });
check("branch creation with If-Match 428", r.status === 428, r.status);
r = await branchReq({ name: `${br}-x`, at: "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" });
check("branch at an id outside the chain 422", r.status === 422, r.json);
r = await branchReq({ name: br, patches: [{ op: "add", path: "/x-purpose", value: "test" }] });
const branchedAt = r.h.get("x-namespace-revision");
check("branch created 201", r.status === 201 && r.h.get("location") === `/ns/${br}` && branchedAt, r.json);
r = await branchReq({ name: br, patches: [{ op: "add", path: "/x-purpose", value: "test" }] });
check("branch retry 200", r.status === 200 && r.h.get("x-namespace-revision") === branchedAt, r.status);
r = await branchReq({ name: br });
check("taken branch name 412", r.status === 412, r.status);
r = await req("GET", `/ns/${bb}/branches`);
const at0 = r.json?.[0]?.at;
check("branch listing", r.status === 200 && r.json.length === 1 && r.json[0].name === br && r.json[0].frozen === false && r.json[0].purged === false && at0, r.json);
r = await req("GET", `/ns/${bb}/rev/${branchedAt}/log`);
const be = r.json?.find?.((e) => e.kind === "branch");
check("base log has the branch entry", be?.name === br && be.at === at0 && be.id === branchedAt && be.target, r.json);
r = await req("GET", `/ns/${br}`);
r = await req("GET", r.h.get("location"));
check("branch document has base", r.json?.base?.ns === bb && r.json.base.at === at0 && r.json["x-purpose"] === "test" && r.json.read === "public", r.json);
r = await req("PATCH", `/r/${bb}/a`, { body: [{ op: "replace", path: "/v", value: 2 }], headers: { "If-Match": `"${a1}"` } });
const a2 = etag(r);
r = await req("GET", `/r/${br}/a`);
check("read through: the base's head as of at", r.status === 302 && r.h.get("location") === `/r/${br}/a/rev/${a1}` && etag(r) === a1, [r.status, r.h.get("location")]);
r = await req("GET", `/r/${br}/a/rev/${a1}`);
check("base revision under the branch's URL", r.status === 200 && r.json?.v === 1, r.json);
r = await req("GET", `/r/${br}/a/rev/${a2}`);
check("base revision after at 404", r.status === 404, r.status);
r = await req("GET", `/r/${br}/c`);
check("tombstoned at at 410", r.status === 410, r.status);
r = await req("GET", `/r/${br}/nope`);
check("absent at at 404", r.status === 404, r.status);
r = await req("GET", `/r/${br}/pic/raw`);
check("raw read through", r.status === 302 && r.h.get("location") === `/r/${br}/pic/blob/${picId}`, [r.status, r.h.get("location")]);
r = await req("GET", `/r/${br}/pic/blob/${picId}`);
check("base blob served by the branch", r.status === 200 && r.text === "pixels", r.status);
r = await req("PATCH", `/r/${br}/a`, { body: [{ op: "replace", path: "/v", value: 10 }], headers: { "If-Match": `"${a2}"` } });
check("first write against the base's later head 412", r.status === 412 && r.json?.head === a1, r.json);
r = await req("PATCH", `/r/${br}/a`, { body: [{ op: "replace", path: "/v", value: 10 }], headers: { "If-Match": `"${a1}"` } });
const ba = etag(r);
check("first write with a foreign parent", r.status === 201, r.json);
r = await req("GET", `/r/${br}/a/rev/${ba}`);
check("branch revision", r.json?.v === 10, r.json);
r = await req("GET", `/r/${bb}/a/rev/${a2}`);
check("base unchanged", r.json?.v === 2, r.json);
r = await req("GET", `/r/${br}/a/log`);
check("a branch's resource log points at its head", r.status === 302 && r.h.get("location") === `/r/${br}/a/rev/${ba}/log`, [r.status, r.h.get("location")]);
r = await req("GET", `/r/${br}/a/rev/${ba}/log`);
check("history crosses the foreign parent: the base's entries first", r.status === 200 && r.json?.length === 1 && r.json[0].id === a1 && r.h.get("x-log-next") === a1, [r.status, r.json, r.h.get("x-log-next")]);
r = await req("GET", `/r/${br}/a/rev/${ba}/log?since=${a1}`);
check("then the branch's", r.json?.length === 1 && r.json[0].id === ba && r.json[0].parent === a1 && !r.h.get("x-log-next"), r.json);
r = await req("GET", `/r/${br}/pic/log`);
const picLog = r.h.get("location");
r = await req("GET", picLog ?? "/");
check("log of a resource read through", picLog?.startsWith(`/r/${br}/pic/rev/`) && r.json?.length === 1, [picLog, r.json]);
r = await req("GET", `/r/${br}/a/rev/${ba}/log?since=${a2}`);
check("since a base revision after at 404", r.status === 404, r.status);
r = await req("DELETE", `/r/${br}/b`, { headers: { "If-Match": `"${b1}"` } });
const bt = r.json?.tombstone;
check("delete a resource read through", r.status === 200, r.json);
r = await req("PATCH", `/r/${br}/b`, { body: [{ op: "add", path: "/w", value: 1 }], headers: { "If-Match": `"${bt}"` } });
check("restore after deleting a resource read through", r.status === 201, r.json);
r = await req("GET", `/r/${br}/b`);
r = await req("GET", r.h.get("location") ?? "/");
check("restore over a foreign tombstone", r.json?.v === "b" && r.json.w === 1, r.json);
r = await req("PATCH", `/r/${br}/c`, { body: [{ op: "add", path: "/back", value: true }], headers: { "If-Match": `"${(await req("GET", `/r/${br}/c`)).h.get("etag").slice(1, -1)}"` } });
// The write's Location, not the head: head pointers may be a second old at the edge (§9).
r = await req("GET", r.h.get("location") ?? "/");
check("restore a resource tombstoned in the base", r.json?.v === "c" && r.json.back === true, r.json);
const brHead = (await req("GET", `/ns/${br}`)).h.get("etag").slice(1, -1);
r = await req("GET", `/ns/${br}/rev/${brHead}/heads`);
const hm = Object.fromEntries((r.json?.heads ?? []).map((x) => [x.resource, x]));
check("heads merge the branch's and the base's", hm.a?.target === ba && hm.pic?.kind === "head" && hm.c?.kind === "head" && hm.b?.kind === "head" && !r.json.next, r.json);
r = await req("POST", `/ns/${br}/batch`, { headers: { "Content-Type": "application/json" }, raw: JSON.stringify({ items: [{ resource: "pic", ifMatch: (await req("GET", `/r/${br}/pic`)).h.get("etag").slice(1, -1), steps: [[{ op: "add", path: "", value: { img: { $blob: picId, type: "image/png", size: pic.length }, alt: "x" } }]] }] }) });
check("batch first write in a branch keeps the base's blob", r.status === 201, r.json);
const np = Buffer.from("new pixels"), npId = blobId("image/png", "", np);
await req("PUT", `/r/${br}/img/blob/${npId}`, { raw: np, headers: { "Content-Type": "image/png" } });
r = await req("PATCH", `/r/${br}/img`, { body: [{ op: "add", path: "", value: { $blob: npId, type: "image/png", size: np.length } }], headers: { "If-None-Match": "*" } });
const brAt = r.h.get("x-namespace-revision");
check("branch-only blob", r.status === 201, r.json);
r = await req("POST", `/ns/${bb}/batch`, { headers: { "Content-Type": "application/json" }, raw: JSON.stringify({ source: { ns: br, at: brAt }, items: [
  { resource: "img", ifNoneMatch: "*", steps: [[{ op: "add", path: "", value: { $blob: npId, type: "image/png", size: np.length } }]] },
  { resource: "a", ifMatch: a2, steps: [[{ op: "replace", path: "/v", value: 10 }]] },
] }) });
check("merge back with source makes the branch's blob available", r.status === 201, r.json);
r = await req("GET", `/r/${bb}/img/blob/${npId}`);
check("merged blob served by the base", r.status === 200 && r.text === "new pixels", r.status);
r = await req("PATCH", `/ns/${br}`, { body: [{ op: "add", path: "/frozen", value: true }], headers: { "If-Match": `"${(await req("GET", `/ns/${br}`)).h.get("x-config-revision")}"` } });
const frozenCfg = r.h.get("x-config-revision");
r = await req("GET", `/ns/${bb}/branches`);
check("freezing shows in the base's listing", r.json?.[0]?.frozen === true, r.json);
r = await req("PATCH", `/ns/${br}`, { body: [{ op: "replace", path: "/base/at", value: branchedAt }], headers: { "If-Match": `"${frozenCfg}"` } });
check("base never changes 422", r.status === 422, r.json);
r = await req("PATCH", `/ns/${ns}-plain`, { body: [{ op: "add", path: "", value: { base: { ns: bb, at: at0 } } }], headers: { "If-None-Match": "*" } });
check("a namespace can't be created with base 422", r.status === 422, r.json);
}

// A batch on a fresh object using many schemas from another namespace, and
// a $ref chain, at once: every missing schema is fetched in a few rounds.
{
  const D = "https://json-schema.org/draft/2020-12/schema";
  const sn = `${ns}-many-s`, tn = `${ns}-many`;
  await req("PATCH", `/ns/${sn}`, { body: [{ op: "add", path: "", value: { read: "public" } }], headers: { "If-None-Match": "*" } });
  await req("PATCH", `/ns/${tn}`, { body: [{ op: "add", path: "", value: {} }], headers: { "If-None-Match": "*" } });
  let prev = null;
  const paths = [];
  for (let i = 0; i < 12; i++) {
    // Each schema refers to the one before: a chain 12 deep.
    const value = { $schema: D, type: "object", properties: { [`f${i}`]: { type: "integer" } }, ...(prev ? { allOf: [{ $ref: prev }] } : {}) };
    const w = await req("PATCH", `/r/${sn}/s${i}`, { body: [{ op: "add", path: "", value }], headers: { "If-None-Match": "*" } });
    prev = `/r/${sn}/s${i}/rev/${w.h.get("etag").slice(1, -1)}`;
    paths.push(prev);
  }
  const items = [];
  for (let k = 0; k < 168; k++) {
    const i = k % paths.length;
    items.push({ resource: `doc-${k}`, ifNoneMatch: "*", steps: [[{ op: "add", path: "", value: { $schema: paths[i], [`f${i}`]: k } }]] });
  }
  r = await req("POST", `/ns/${tn}/batch`, { headers: { "Content-Type": "application/json" }, raw: JSON.stringify({ items }) });
  check("a fresh object's batch of 168 documents over 12 chained schemas", r.status === 201 && r.json?.items?.length === 168, [r.status, r.json?.message]);
  items[0].steps[0][0].value.f0 = "not an integer";
  items[0].resource = "bad";
  r = await req("POST", `/ns/${tn}/batch`, { headers: { "Content-Type": "application/json" }, raw: JSON.stringify({ items: [items[0]] }) });
  check("and still validates against them", r.status === 422 && r.json?.items?.[0]?.code === "invalid", r.json);
}

// CORS (§7, browsers), and the client's rebase over a stale head (§11).
{
  r = await fetch(`${base}/r/${ns}/x`, { method: "OPTIONS", headers: { Origin: "https://studio.example", "Access-Control-Request-Method": "PATCH", "Access-Control-Request-Headers": "if-match, content-type, x-author" } });
  check("preflight", r.status === 204 && r.headers.get("access-control-allow-origin") === "*" && /PATCH/.test(r.headers.get("access-control-allow-methods")) && /If-Match/.test(r.headers.get("access-control-allow-headers")) && r.headers.get("access-control-max-age"), [r.status, [...r.headers]]);
  const cn = `${ns}-cors`;
  r = await req("PATCH", `/ns/${cn}`, { body: [{ op: "add", path: "", value: { read: "public" } }], headers: { "If-None-Match": "*", Origin: "https://studio.example" } });
  check("CORS on a write", r.h.get("access-control-allow-origin") === "*" && /X-Namespace-Revision/.test(r.h.get("access-control-expose-headers") ?? ""), [...r.h]);
  r = await req("GET", `/r/${cn}/missing`);
  check("CORS on an error, without Origin", r.status === 404 && r.h.get("access-control-allow-origin") === "*", [...r.h]);
  const first = await save(base, cn, "page", { head: null }, [{ op: "add", path: "", value: { title: "A", body: "x" } }], { author: "studio" });
  for (let i = 0; i < 2; i++) {
    r = await req("GET", `/r/${cn}/page/rev/${first.head}`);
    check(`CORS on a revision read ${i ? "(cached)" : ""}`, r.status === 200 && r.h.get("access-control-allow-origin") === "*" && /ETag/.test(r.h.get("access-control-expose-headers") ?? ""), [...r.h]);
  }
  const loaded = await load(base, cn, "page");
  check("client load", loaded.head === first.head && loaded.doc.title === "A", loaded);
  // Someone else writes; the studio still holds the old head, as after a stale CDN read.
  await save(base, cn, "page", loaded, [{ op: "replace", path: "/body", value: "theirs" }], { author: "other" });
  const mine = await save(base, cn, "page", loaded, [{ op: "replace", path: "/title", value: "B" }], { author: "studio" });
  check("save from a stale head rebases and keeps both changes", mine.rebased === 1 && mine.doc.title === "B" && mine.doc.body === "theirs", mine);
  let err;
  try { await save(base, cn, "page", loaded, [{ op: "test", path: "/body", value: "x" }, { op: "replace", path: "/body", value: "mine" }], { author: "studio" }); } catch (e) { err = e; }
  check("a test op stops a rebase onto changed data with 422", err?.status === 422, err?.body);
}

// Listing heads by prefix with `after` alone (§7.4), as the client does.
{
  const pn = `${ns}-prefix`;
  await req("PATCH", `/ns/${pn}`, { body: [{ op: "add", path: "", value: { read: "public" } }], headers: { "If-None-Match": "*" } });
  let at;
  for (const n of ["canvas", "canvas-x", "canvas.a", "canvas.b", "canvas.c", "canvasz", "other"]) {
    r = await req("PATCH", `/r/${pn}/${n}`, { body: [{ op: "add", path: "", value: { n } }], headers: { "If-None-Match": "*" } });
    at = r.h.get("x-namespace-revision");
  }
  const names = [];
  for await (const h of listHeads(base, pn, at, { prefix: "canvas." })) names.push(h.resource);
  check("heads by prefix", JSON.stringify(names) === JSON.stringify(["canvas.a", "canvas.b", "canvas.c"]), names);
  r = await req("GET", `/ns/${pn}/rev/${at}/heads?prefix=canvas.`);
  check("heads takes only after (§7)", r.status === 400, r.status);
}

console.log(failed ? `\n${failed} failed` : "\nall passed");
process.exit(failed ? 1 : 0);
