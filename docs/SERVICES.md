# Patch Log — Services

Status: draft v0.90 · 2026-11-24. A companion to the [Patch Log specification](SPEC.md), versioned with it. Changes are listed there and in [CHANGELOG.md](CHANGELOG.md).

**Scope.** Services that follow namespaces through the protocol's public API and answer queries over them:

- **Addendum A (suggested):** an index, for search and reverse references.
- **§E.2.6 (optional):** how a service seals what it derives from sealed and end-to-end namespaces.

A server needs nothing from this document. Filtered reads, which the index's private results follow, are in the core (§7.9).

**Reading.** "Reading this spec" in [SPEC.md](SPEC.md) applies here, and so do its terms (§2, §2.1). The three documents share one numbering: §1–§10, §12, §13, §C, §E (but §E.2.6), §G.1, §G.4.1, §G.5–§G.7 and §I are in SPEC.md; §11, §F, §G.2, §G.4.2–§G.4.4, §H and §J are in [TOOLS.md](TOOLS.md).

---

# Addendum A — Indexing service (suggested)

A search service for typed documents: a namespace consumer (§10) with its own process, storage and origin.

## A.1 Following the namespace

- Follow the namespace as in §10, with one checkpoint per namespace, under a grant with unrestricted `read` (§2.1): a filtered log (§7.9) leaves documents out.
- For each coalesced `head` entry:
  1.  Fetch `/r/{ns}/{name}/rev/{id}`, or, at E3 where that is `404` (`not_offered`), fold the resource's log (§10 step 5).
  2.  Without `$schema`, remove the resource's rows.
  3.  A schema document (`$schema` a dialect URL, §6.1) is indexed against the dialect's meta-schema: `schema=` with the dialect URL lists schema documents, and the revision paths of `$ref`s at schema positions, fragment dropped, are its references (§A.2).
  4.  Otherwise fetch the pinned schema revision and index the annotated fields and references (§A.2). A schema revision answering a `4xx` other than `408` and `429`, or that the service lacks keys to open (§6.1, §E.2.3), leaves the document indexed as untyped. A schema or key fetch that fails transiently (transport error, `5xx`, `408`, `429`) is retried.
- `tombstone` or `purge` → remove the resource's rows. `purge`, or a `config` entry on which §9 purges `ns:{ns}` → purge `idx:{ns}` from the service's own cache and drop kept results (§A.4), serving or keeping none computed from what was read before it, as any result of `{ns}`, its scores and counts included, may derive from what it removes.
- Store the checkpoint in the same transaction as the index writes.

## A.2 What gets indexed: `x-index`

- Schemas opt fields in with `"x-index"`: `"text"`, `"facet"` or `"sort"`, or an array of them, collecting only strings, numbers and booleans, by the walk below and only through keywords that mark a path (§A.4):
  - `text`: full-text search, of strings only.
  - `facet`: exact-match filters and counts, one value per array element. A value matches and counts as its string form: a string itself, a number or boolean its canonical JSON (§3.1).
  - `sort`: ordering, ascending, or descending with `sort=-{path}`. In either direction a document sorts by its least value at the path (numbers before strings before booleans; numbers by value, strings by UTF-8 bytes, `false` before `true`), and documents without one sort last.
- **References** need no `x-index`: walk each document with its pinned schema revision, keeping the references §6.5's walk finds. Store each target as `{ ns, name }`, plus a pinned reference's revision and an `#id` one's entry, and its path: the full instance pointer, array indices included (`/related/0`). `x-index` rows name the field, without indices.
  - References in untyped documents aren't found.
  - Don't scan text for paths: embedded document copies and ids in prose aren't references.

## A.3 Storage (example, SQLite)

``` sql
CREATE TABLE checkpoints (ns TEXT PRIMARY KEY, ns_id TEXT NOT NULL);
CREATE TABLE docs  (ns TEXT, resource TEXT, head TEXT, schema TEXT, PRIMARY KEY (ns, resource));
CREATE VIRTUAL TABLE text USING fts5(ns UNINDEXED, resource UNINDEXED, schema UNINDEXED, path UNINDEXED, body);
CREATE TABLE facet (ns TEXT, resource TEXT, schema TEXT, path TEXT, value TEXT, PRIMARY KEY (ns, resource, path, value));
CREATE TABLE sort  (ns TEXT, resource TEXT, schema TEXT, path TEXT, value,      PRIMARY KEY (ns, resource, path));
CREATE TABLE refs  (ns TEXT, resource TEXT, schema TEXT, path TEXT, ref TEXT,  -- ref as written
                    target_ns TEXT, target TEXT, rev TEXT, entry TEXT, PRIMARY KEY (ns, resource, path));
CREATE INDEX facet_q ON facet (ns, schema, path, value);
CREATE INDEX sort_q  ON sort  (ns, schema, path, value);
CREATE INDEX refs_q  ON refs  (target_ns, target, rev, entry);
```

Current state only; for history, replay the resource log.

## A.4 Query API

Served on the indexing service's own origin, e.g. `https://search.example/`.

| Request                                                         | Response                                                                                              | Cache-Control                                                                                 |
|-----------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| `GET /{ns}?q=…&schema=…&facet[/blocks/type]=poll&sort=/kickoff` | `302` to `/{ns}/at/{checkpoint ns_id}?…`, or `/{ns}/view/{view}/at/…` for private namespaces (below) | head pointer; `private, no-store` where the redirect adds `/view/{view}`                      |
| `GET /{ns}/at/{ns_id}?…`                                        | `200` with `{ "at": ns_id, "hits": [{ "resource", "id", "url", "score", …facets }] }`                 | immutable, or `no-store` where §E.2.6 says. Tags `idx:{ns}` and `r:{ns}/{name}` for every hit |
| same, an `ns_id` the service no longer keeps results for        | `302` to the current checkpoint                                                                       | head pointer                                                                                  |

- **Bounded redirects.** A service SHOULD answer `200` at an `at` it redirected to for a while (e.g. a minute), computing or keeping the result, unless §A.1 dropped it, so a reader may be redirected again while purges keep coming. A kept result is keyed by its URL, `view` included, so it never outlives the rules it was filtered by.

- **Unavailable namespaces.** A query of a namespace that is:
  - unfollowed, a branch whose bases' namespace logs it doesn't all follow (§C.4 Keys follow the base), or a sealed or end-to-end one whose keys the service lacks (§E.2.6: `/keys` answers it a `4xx` other than `408` and `429`, or gives none it can unwrap): `404`, at its exchange too, which mints no cookie and answers `404` only where no other refusal is `401` or `403` (§C.5.2 All or nothing), also where the service learns this only during the read check;
  - purged: `410` (`purged`), once the read check passes against the last namespace document the service read;
  - followed, without a checkpoint yet: once the reader's grant verifies, `503`, `no-store`, with `code: "behind"` and `Retry-After` (§A.5).

- `schema` filters by an exact `$schema` reference, or by a schema's resource path `/r/{ns}/{name}` to match all its revisions.

- `ref` finds the documents of `{ns}` referencing a resource, combined with any other filters:

  - `?ref=/r/{ns2}/{name}`: references to it in any form, live, pinned or to an entry
  - `?ref=/r/{ns2}/{name}/rev/{id}`: those pinned to that revision
  - `?ref=/r/{ns2}/{name}%23{entry}`: those naming that entry, pinned or not.
  - `?ref=/r/{ns2}/{name}/rev/{id}%23{entry}`: those naming that entry and pinned to that revision.

  **Across namespaces.** `GET /_refs?to=<reference>`, `to` in any form above, asks every followed namespace the reader may see.

  - It redirects to `/_refs/view/{view}/at/{at}?to=…`. `at` is the **combined checkpoint**, `text(trunc160(sha256(canonical({ ns: ns_id, … }))))` over those namespaces, purged ones left out (§I.8).
  - **`view`** is `text(trunc160(sha256(canonical(markers))))`, `markers` an array in byte order of UTF-8 holding `{ns}:{v}` for each followed non-public namespace where the reader has a view `v` (Private namespaces, below). Readers with none, requests with neither a grant nor a cookie, and requests under an operator grant, which count as without one here (§C.4), share the empty array's `view`. They get `401` only as **Coverage** says. The path always has `/view/{view}`.
  - Its URLs and cookies are served as Private namespaces says, under the prefix `/_refs/view/{view}`. The exchange refuses only as **Coverage** and Private namespaces say. A cookie is `403`, until the reader exchanges again, once a namespace's coverage changes, or where the cookie of any of its markers' views would be.
  - It takes `?min={ns}:{ns_id}`, repeatable, as any `at` URL does (§A.5). A `min` is `400` for a namespace the reader can't see, that the service doesn't follow, or that **Coverage** leaves out, purged ones excepted (§A.5).
  - **Answers** are `{ "at", "namespaces": { ns: ns_id, … }, "hits": [ … ], "next"? }`. `namespaces` lists what `at` covers, one `ns_id` per namespace.
    - Hits carry `ns` beside a `ref` hit's fields.
    - Hits are filtered per namespace, as Private namespaces says.
    - Hits come in byte order of `ns`, then resource name.
    - A page holds at most `limit` hits, counted after filtering. Every page but the last holds exactly `limit`. The service sets the default and maximum, and a larger `limit` is `400`.
    - A page holds hits strictly after `after`, given as `{ns}/{name}`, split at its first `/` and compared as the pair (`ns`, name). `next`, absent on the last page, is the next page's `after`.
    - For a namespace read only in part, `at` and its `ns_id` show when it changed (§C.6).
    - Hits from sealed and end-to-end namespaces are sealed per entry (§E.2.6), never as a whole response.
  - **Coverage.** It includes branch previews (§F.8). It leaves out namespaces not yet reached, purged ones, and sealed or end-to-end ones whose keys it lacks.
    - Only a reader who may see none of the namespaces gets `401` or `403`, or, where every namespace its grant names is purged and the grant verifies in each, `410` as §C.5.2 gives it.
    - If the service can't read the namespace document of one the grant names, the answer is `502`.
    - Any other whose document it can't read is left out, as one the reader can't see.
  - It is tagged `idx:{ns}` for every namespace in `at`, and `r:{ns}/{name}` per hit, with base tags as §9 allows.

  Hits of a `ref` query, and only those, carry `refs: [{ "path", "ref" }]`, the matching locations and strings, as written.

  - Hits come in `sort` order if given. Otherwise, with `q`, they come by descending `score`, computed only from documents of `{ns}` the reader may see. Otherwise they come by resource name. Ties go by resource name.
  - Every query pages as `/_refs` does. `after` is a bare resource name or, with `q` or `sort`, the opaque value `next` gives.
  - A redirect from a head pointer or to another `at` keeps an `after` naming a resource, applied to the new result. It drops an opaque one, starting again. This applies to redirects here and on `/_refs`.
  - A self-referencing document is a hit of its own query, with `"self": true`.

- **Delete guards are advisory:** even with `?min=` (§A.5), a guard can race a write adding a reference.

- **Branches.** In a branch's preview index (§F.8), `ref` matches targets as written, naming the base, and hits are the branch's versions of the referrers.

- Hits carry the plain document URL (`/r/{ns}/{name}/rev/{id}`), served by the core's CDN, never by the search service.

- **Fields in hits.** Hits carry their facet and `sort` values, each as `"<path>": [values]` even for one value. Facet values are in string form (§A.2), deduplicated. A path marked both `facet` and `sort` shows its facet values.
  - `fields=/name,/title` also asks for those indexed fields, `text` ones included.
  - A path with a comma can't be named in `fields`, `counts` or `sort`.
  - `counts=/a,/b` adds `counts`, `{ "<path>": { "<value>": <hits> } }`, over every hit, not only the page.
  - A schema **marks** a path when an `x-index` is reachable from its root along that path, whatever the data. Array items count at their array's path (§A.2). The walk goes:
    - through `$ref` and `$dynamicRef`, `properties`, `patternProperties`, `additionalProperties`, `dependentSchemas`, `items`, `prefixItems` and `contains`;
    - through every branch of `allOf`, `anyOf`, `oneOf`, `if`, `then` and `else`;
    - never through `not`, `propertyNames` or `unevaluated*`.
  - The answer is `400` for:
    - a `fields` path that no schema indexed in `{ns}` for a document the reader may see marks with `x-index`;
    - a `facet[…]` or `counts` path that none of those schemas marks `facet`;
    - a `sort` path that none of them marks `sort`.
  - A hit omits marked paths it has no values at.

- **Public namespaces:** a query of one ignores any grant and is answered as one without it (§7 step 1).

- **Private namespaces:** results are served at `/{ns}/view/{view}/at/{ns_id}?…`.
  - **`view`** is the reader's `view` in `{ns}` as §7.9 computes it, at every level and whether or not the origin serves §7.9. A reader whose grant doesn't allow `read` in `{ns}`, or whose block or key-scope rules refer to `/now`, has none, and gets `401` or `403`.
  - **Hits are filtered per revision.** A hit is shown only where its head revision as of `at` is visible to the reader's `view`, judged as §7.9 judges it, `doc` being `null` in end-to-end namespaces (§6.4.1). A document of `{ns}` the reader "may see" anywhere in §A.4 is one shown so. Each judgement gets the origin's `validationSteps` (§6.6), which `GET /ns/{ns}/principal` gives the service's own grant in `writer.limits` (§7.4). The service SHOULD judge each revision once per `view` (§7.9 Cost).
  - **Cookies.** The service mints cookies for the prefix `/{ns}/view/{view}` with a key of its own, at an exchange of its own that follows §C.5.2's issuance rules as §7.9 changes them for a `view` prefix, and applies `exchangeRate` (§6.6) to it. A cookie is `403` where §7.9's `view` cookie would be; another reader's exchange revives none. The service judges it by every namespace-document entry after the checkpoint it judged the exchange at, in a branch by its bases' entries after their checkpoints then too (§C.4 Keys follow the base). A cookie it can't judge so, such as one minted before it restarted from a snapshot or one past an entry whose document it can't read, is `403`. The service keeps, per `view`, the rules and values it digests, and judges a request under a cookie from those, never from a grant the request doesn't carry. Services needn't compute the same `view` as the origin or each other.
  - A grant in `Authorization` reads only at its own `view` (`403` elsewhere), and a URL without `/view/{view}` is redirected to its `…/view/{view}/at/…` form by it, `private, no-store`. A request that needs `/view/{view}` and carries neither a grant that verifies in a namespace the service follows nor a cookie it verifies is `401`.
  - An exchange whose cookie would be `403` at once, as a key or role its `view` draws on has changed since the checkpoint it is judged at, answers `503` (`behind`) with `Retry-After`. So does one with no `exp` left (§C.5.2). Other moves of the namespace document while an exchange is judged are retried, the exchange answering `503` only after a bounded number of tries (§A.5).

- **Sealed and end-to-end namespaces:** results are sealed as in §E.2.6.

## A.5 Consistency

- The index is **eventually consistent**. Every response states `at`, the `ns_id` it reflects. An index whose checkpoints keep moving while it computes a result MAY answer `503` (`behind`, `no-store`, with `Retry-After`) after a bounded number of tries.
- **Read-your-writes:** `?min={ns_id}`, once, on a query of one namespace (or `?min={ns}:{ns_id}`, repeatable, on `/_refs`, §A.4) waits (bounded, e.g. 2 s) until the checkpoint is at or past `min`. Failing that, the service answers `503`, `no-store`, with `code: "behind"` and `Retry-After`. A client takes `min` from `X-Namespace-Revision` on its own write (§7.2).
- **`min` always redirects.** The `302` drops `min`. It goes to the current checkpoint or, on an `…/at/{at}/…` URL whose `at` already includes every `min`, to the same URL.
  - A service that can't tell whether `at` includes them redirects to the current checkpoint, in one hop. It can't tell when it no longer keeps that `at`'s per-namespace checkpoints, or when `min` names a namespace the reader may see that the current checkpoint covers but `at` doesn't.
  - A `min` naming any other namespace is `400` (§A.4), the body's `min` listing those refused. On a query of one namespace, it is `400` only after that namespace's own `401`, `403`, `404` and `410`.
  - On `/_refs`, a `min` naming a purged namespace redirects to the current checkpoint without a read check (a purge is no secret, §E.4).
  - A tool keeps each `min` from its own writes until a query carrying it is answered `200` after its redirect, for ten minutes at most. It drops those a `400` lists. A tool whose grant can't see a namespace shows its writes there from what it wrote.
  - A `200` is never served at a URL with `min` (§E.2.6).
- **Canonical URLs.** A service's redirects give the query in one form. Parameters are sorted by name, then value, comparing their decoded UTF-8 bytes. Every byte other than ALPHA, DIGIT, `-`, `.`, `_` and `~` is percent-encoded in uppercase hex (so a space is `%20`, never `+`). Indexes answer `200` only at that form and redirect others to it (§E.2.6). Repeatable parameters, such as `min`, are sets, sorted like the rest. A parameter the service doesn't define, or a non-repeatable one given twice, is `400` (§7), and a list whose order matters is one value, such as `fields=/name,/title`.

## A.6 Operations

- **Rebuild:** delete the index and replay from `""` (§10); a new schema revision needs none.
- **Access control:** the service MUST enforce the namespace's read permissions by verifying the reader's grant locally (§C.6).

---

# Addendum E — Encryption: derived views (optional)

The rest of Addendum E is in [SPEC.md](SPEC.md). This section binds a service that serves anything derived from a sealed or end-to-end namespace.

### E.2.6 Derived views

For services serving views derived from sealed and end-to-end namespaces, such as search results (Addendum A):

- **Getting keys.** A service fetches epoch keys like any reader (§E.2.3), with its own key pair and a grant with `read`. At E3, one whose public key isn't a recipient in the namespace's `keyring` can derive nothing: it skips the namespace, says so in its status, and MUST NOT index ciphertext as if it were content. A `keyring` entry whose `from` it doesn't trust (§E.3.2) counts as no key.
- **What gets sealed.** Every value a view derives from such a namespace's content is sealed, such as facets, scores, snippets and fields. What §E.2.2 leaves in the clear stays so: names, ids, URLs and heads, and the view's own structure, `at`, `ns`, result order and pagination cursors. A cursor never encodes a sealed value, such as a sort key. Each plaintext sealed here is canonical JSON (§3.1), before any padding (§E.2.2).
- **Whole-response sealing.** The service MAY serve the whole response as one JWE in the §E.2.2 format when all of these hold:
  - every sealed value in the response comes from one namespace that isn't public;
  - every reader its URL admits has unrestricted `read` of that namespace (§2.1, §A.4);
  - every such value derives from revisions served under one epoch.

  The JWE is sealed under that epoch's `K_n` (§E.2.1), with `kid` naming that epoch, `Content-Type: application/jose` and `pl: { "ns", "view" }` (`pl.view`, below). Its plaintext is the response body.
- **Per-entry sealing.** Otherwise, including a single-source view for a reader whose grant gives only per-resource or view keys (§E.2.3), the response stays JSON. Each entry (a hit) that carries sealed values replaces them with `"sealed": "<JWE compact>"`, whose plaintext is the object of the members it replaces:
  - at E2 under the `K_rev` of the revision it derives from, at E3 under the `K_r` of the entry's own resource (§E.2.1), both in a branch the branch's, read-through entries included (§E.2.5);
  - with `kid` naming the epoch the revision it derives from is served under (§E.2.2), at E3 the one a prune's `snapshot` of that revision would carry (§E.3.1). The epoch is judged once, when the service first seals a value derived from that revision; at E2 the service takes it from the `kid` of that revision's JWE as the origin serves it (§E.2.2). Until it can judge it, the service seals nothing derived from that revision: it serves the entry by name only and leaves such values out of other entries, in a response that is `no-store` and isn't stored, or, while it may yet judge it, answers `503` (`behind`, §A.5) instead;
  - with `pl: { "ns", "name", "view" }`.

  An entry whose epoch the service's grant gets no key for (§E.2.3) is served by name only, or left out where the service never opened that revision. A reader decrypts the entries it holds keys for, a partial reader with the `K_rev`s its origin's filtered answers carry (§E.2.2), and shows the rest by name only. Of an entry that carries `sealed`, it takes from outside it only what this section leaves in the clear (above).
- **Aggregates.** Values that combine several resources, such as facet counts, have no entry of their own and are served only in whole-response form. A service refuses them (`400`) to a reader that would get per-entry sealing.
- **`pl.view`** is the request target, in origin form (path, then `?` and the query where there is one; no scheme or host), of the `…/at/{at}/…` URL that the response is served at, byte for byte as the service's redirect gave it (§A.5). Readers MUST compare `pl` with the URL they fetched, so nothing between service and reader may rewrite it.
- **View keys.** Where this section seals a view's JWE under a `K_n`, `K_rev` or `K_r`, the key used is `HKDF-SHA256(ikm = that key, salt = "patchlog-view", info = pl.view)`, 32 bytes. So views count toward no epoch key's message bound (§E.2.1).
- **Stored once, served forever.** A view at a given `at`, other than a `no-store` one (Per-entry sealing), is sealed once, under the epochs above, and then served unchanged, like revisions (§E.2.2), until a config entry on which §9 purges a source's `ns:{ns}` drops it (§A.1). A stored view is keyed by its URL and the shape of the reader's keys, as kept results are (§A.4). Padding (`pad`) follows the source namespace. Whole-response sealing pads only when every source is padded.
- **Caching** is public only for a view whose sources are all public (§9); other views are private results (§C.6). Tags are those of §A.4.
- **Local storage.** A service keeps what it derives from a sealed or end-to-end namespace in storage encrypted as at E1 (§E.1), such as an encrypted volume or database, with keys held outside it. Views it has sealed (above) may be stored as they are. A purge of the source, or the destruction of its keys, MUST remove the derived data: rows are deleted and freed pages overwritten, stored sealed views are deleted, and cached keys are forgotten.
- **Queries are metadata:** query strings are in URLs, so the service, the CDN and anyone who sees them learn them at every level (§E.4).
