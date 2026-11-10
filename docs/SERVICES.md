# Patch Log — Services

Status: draft v0.81 · 2026-11-10. A companion to the [Patch Log specification](SPEC.md), versioned with it. Changes are listed there and in [CHANGELOG.md](CHANGELOG.md).

**Scope.** Services that follow namespaces through the protocol's public API and answer queries over them:

- **Addendum A (suggested):** an index, for search and reverse references.
- **Addendum B (suggested):** catalogs, which organise documents in trees kept in namespaces of their own, and derive access from those trees.

A server needs nothing from this document, with one exception: an origin MAY serve filtered namespace reads itself (§B.11.9), and one that does implements that section, with what it cites from §A.4, §B.5 and §B.11. A tree service that serves file trees or release previews also follows §H.2, §H.3 and §F.9, in TOOLS.md.

- **§E.2.6 (optional):** how a service seals what it derives from sealed and end-to-end namespaces.

**Reading.** "Reading this spec" in [SPEC.md](SPEC.md) applies here, and so do its terms (§2, §2.1). The three documents share one numbering: §1–§10, §12, §13, §C, §E (but §E.2.6), §G.1, §G.3, §G.4.1, §G.5–§G.7 and §I are in SPEC.md; §11, §F, §G.2, §G.4.2–§G.4.4 and §H are in [TOOLS.md](TOOLS.md).

---

# Addendum A — Indexing service (suggested)

A search service for typed documents: a namespace consumer (§10) with its own process, storage and origin.

## A.1 Following the namespace

- Follow the namespace as in §10, with one checkpoint per namespace.
- For each coalesced `head` entry:
  1.  Fetch `/r/{ns}/{name}/rev/{id}`, or, at E3 where that is `404` (`not_offered`), fold the resource's log (§10 step 5).
  2.  Without `$schema`, remove the resource's rows.
  3.  A schema document (`$schema` a dialect URL, §6.1) is indexed against the dialect's meta-schema: `schema=` with the dialect URL lists schema documents, and the revision paths of `$ref`s at schema positions, fragment dropped, are its references (§A.2).
  4.  Otherwise fetch the pinned schema revision and index the annotated fields and references (§A.2). A schema revision answering a `4xx` other than `408` and `429`, or that the service lacks keys to open (§6.1, §E.2.3), leaves the document indexed as untyped. A schema or key fetch that fails transiently (transport error, `5xx`, `408`, `429`) is retried.
- `tombstone` or `purge` → remove the resource's rows. `purge`, or a `config` entry on which §9 purges `ns:{ns}` → purge `idx:{ns}` from the service's own cache and drop kept results (§A.4), serving or keeping none computed from what was read before it.
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

| Request                                                         | Response                                                                                        | Cache-Control                                                                 |
|-----------------------------------------------------------------|-------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| `GET /{ns}?q=…&schema=…&facet[/blocks/type]=poll&sort=/kickoff` | `302` to `/{ns}/at/{checkpoint ns_id}?…`, or `/{ns}/g/{gs}/at/…` for private namespaces (below) | head pointer; `private, no-store` where the redirect adds `/g/{gs}` (§B.11.5) |
| `GET /{ns}/at/{ns_id}?…`                                        | `200` with `{ "at": ns_id, "hits": [{ "resource", "id", "url", "score", …facets }] }`           | immutable. Tags `idx:{ns}` and `r:{ns}/{name}` for every hit                  |
| same, an `ns_id` the service no longer keeps results for        | `302` to the current checkpoint                                                                 | head pointer                                                                  |

- **Bounded redirects.** A service SHOULD answer `200` at an `at` it redirected to for a while (e.g. a minute), computing or keeping the result, unless §A.1 dropped it. A kept result mustn't outlive the reads it was computed for: it is keyed also by what the reader reads whole, and dropped if computed before reads narrowed.

- **Unavailable namespaces.** A query of a namespace that is:
  - unfollowed, or a sealed or end-to-end one whose keys the service lacks (§E.2.6: `/keys` answers it a `4xx` other than `408` and `429`, or gives none it can unwrap): `404`;
  - purged: `410` (`purged`);
  - followed, without a checkpoint yet: once the reader's grant verifies, `503`, `no-store`, with `code: "behind"` and `Retry-After` (§B.5).

- `schema` filters by an exact `$schema` reference, or by a schema's resource path `/r/{ns}/{name}` to match all its revisions.

- `ref` finds the documents of `{ns}` referencing a resource, combined with any other filters:

  - `?ref=/r/{ns2}/{name}`: references to it in any form, live, pinned or to an entry
  - `?ref=/r/{ns2}/{name}/rev/{id}`: those pinned to that revision
  - `?ref=/r/{ns2}/{name}%23{entry}`: those naming that entry, pinned or not.
  - `?ref=/r/{ns2}/{name}/rev/{id}%23{entry}`: those naming that entry and pinned to that revision.

  **Across namespaces.** `GET /_refs?to=<reference>`, `to` in any form above, asks every followed namespace the reader may see.

  - It redirects to `/_refs/g/{gs}/at/{at}?to=…`. `at` is the combined checkpoint (§B.5) over only those namespaces and, for those §B.11.9 covers, every namespace it reads there (§B.11.9 URLs).
  - **`gs`** is computed, and its URLs served, as in §B.11.5, but over these markers. There is at most one marker for each followed non-public namespace, and the service's exchange refuses only as **Coverage** says. The marker for `{ns}` is:
    - `reads:{ns}` where the reader's grant would be issued a namespace-wide edge grant (§C.5.2);
    - `reads:{ns}:g:{gs}`, with its `gs` there, for a partial reader where §B.11.9 covers `{ns}`;
    - none for a partial reader where it doesn't but `{ns}` is neither sealed nor end-to-end and is a catalog (§B.6) or its `catalogs`, or a local base's, names one;
    - otherwise `reads:{ns}:scope:{digest}` where the grant allows `read`, as for a partial reader (§B.11.9, §C.2 item 5), and, if it fixes `/resource`, its rules pass now for at least one name it fixes. `digest` covers the rules that limit it there (of its blocks, its key's scope and each effective role that lists `read`, §2.1), the `/principal` values they refer to and its key's `key:` string (§B.11.9 `gs`).

    A cookie is `403` until the reader exchanges again:
    - once a namespace's coverage changes and its marker for it has the old form;
    - or where a marker's key, rules or roles would end a `gs` cookie (§B.11.9 `gs`).

    Readers with no marker, and requests with neither a grant nor a cookie, share the empty set's `gs`. They get `401` only as **Coverage** says. The path always has `/g/{gs}`.
  - It takes `?min={ns}:{ns_id}`, repeatable, as any `at` URL does (§A.5). A `min` is `400` for a namespace the reader can't see, that the service doesn't follow, or that **Coverage** leaves out, purged ones excepted (§A.5). A namespace that `at` covers only because §B.11.9 reads it is none of these.
  - **Answers** are `{ "at", "namespaces": { ns: ns_id, … }, "hits": [ … ], "next"? }`. `namespaces` lists what `at` covers, one `ns_id` per namespace.
    - Hits carry `ns` beside a `ref` hit's fields.
    - Hits are filtered per item by those rules, as catalog listings are (§B.11.5). For a partial reader where §B.11.9 covers `{ns}`, they are filtered by visibility (§B.11.9) instead. For that reader, a document of `{ns}` it "may see" anywhere in §A.4 is one visible to it.
    - Hits come in byte order of `ns`, then resource name.
    - A page holds at most `limit` hits, counted after filtering. Every page but the last holds exactly `limit`. The service sets the default and maximum, and a larger `limit` is `400`.
    - A page holds hits strictly after `after`, given as `{ns}/{name}`, split at its first `/` and compared as the pair (`ns`, name). `next`, absent on the last page, is the next page's `after`.
    - For a namespace read only in part, `at` and its `ns_id` show when it changed (§C.6).
    - Hits from sealed and end-to-end namespaces are sealed per entry (§E.2.6), never as a whole response.
  - **Coverage.** It includes branch previews (§F.8). It leaves out namespaces not yet reached, purged ones, and sealed or end-to-end ones whose keys it lacks.
    - Only a reader who may see none of the namespaces gets `401` or `403`, or, where every namespace its grant names is purged and the grant verifies in each, `410` as §C.5.2 gives it.
    - If the service can't read the namespace document of one the grant names, the answer is `502`.
    - Any other whose document it can't read is left out, as one the reader can't see.
  - It is tagged `idx:{ns}` for every namespace in `at`, and `r:{ns}/{name}` per hit.

  Hits of a `ref` query, and only those, carry `refs: [{ "path", "ref" }]`, the matching locations and strings, as written.

  - Hits come in `sort` order if given. Otherwise, with `q`, they come by descending `score`, computed only from documents of `{ns}` the reader may see. Otherwise they come by resource name. Ties go by resource name.
  - Every query pages as `/_refs` does. `after` is a bare resource name or, with `q` or `sort`, the opaque value `next` gives.
  - A redirect from a head pointer or to another `at` keeps an `after` naming a resource, applied to the new result. It drops an opaque one, starting again. This applies to redirects here, on `/_refs` and of a tree listing (§B.5).
  - A self-referencing document is a hit of its own query, with `"self": true`.

- **Delete guards are advisory:** even with `?min=` (§A.5), a guard can race a write adding a reference.

- **Branches.** In a branch's preview index (§F.8), `ref` matches targets as written, naming the base (§F.9), and hits are the branch's versions of the referrers.

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

- **Private namespaces:** results are served at `/{ns}/g/{gs}/at/{ns_id}?…`, with `gs` and its URLs as for `/_refs` (above). Hits are filtered as there, over `{ns}` alone. A reader with no marker for `{ns}` gets `401` or `403`. Where §B.11.9 covers `{ns}`:
  - The service follows the namespaces visibility reads, as §B.5 does.
  - It answers a partial reader `503` (`behind`, §B.5) until it has reached each, and `502`, naming no namespace, while it can't read one, or lacks the keys (above) to open a sealed one's documents. Both answers hold here and on `/_refs`.
  - For partial readers, `at`, in place of the `ns_id` (§A.5), is §B.11.9's combined checkpoint, which answers list as `namespaces` and `min` may name as `{ns}:{ns_id}`. Their answers are tagged `idx:{m}` for every namespace `m` in it.

- **Sealed and end-to-end namespaces:** results are sealed as in §E.2.6.

## A.5 Consistency

- The index is **eventually consistent**. Every response states `at`, the `ns_id` it reflects.
- **Read-your-writes:** `?min={ns_id}`, once, on a query of one namespace (or `?min={ns}:{ns_id}`, repeatable, for a service following several namespaces, §B.5) waits (bounded, e.g. 2 s) until the checkpoint is at or past `min`. Failing that, the service answers `503`, `no-store`, with `code: "behind"` and `Retry-After`. A client takes `min` from `X-Namespace-Revision` on its own write (§7.2).
- **`min` always redirects.** The `302` drops `min`. It goes to the current checkpoint or, on an `…/at/{at}/…` URL whose `at` already includes every `min`, to the same URL.
  - A service that can't tell whether `at` includes them redirects to the current checkpoint, in one hop. It can't tell when it no longer keeps that `at`'s per-namespace checkpoints, or when `min` names a namespace the reader may see, or one §B.11.9 reads for it (§A.4), that the current checkpoint covers but `at` doesn't.
  - A `min` naming any other namespace is `400` (§A.4), the body's `min` listing those refused. On a query of one namespace, it is `400` only after that namespace's own `401`, `403`, `404` and `410`.
  - On `/_refs` and tree listings, a `min` naming a purged namespace redirects to the current checkpoint without a read check (a purge is no secret, §E.4).
  - In tree listings, which cover every followed namespace, `302` against `503` shows whether an `ns_id` is in the chain of a namespace whose items the reader can't see. `400` shows which namespaces aren't followed. Ids and names aren't secrets (§C.5, §E.4).
  - A tool keeps each `min` from its own writes until a listing carrying it is answered `200` after its redirect, for ten minutes at most. It drops those a `400` lists. A tool whose grant can't see a namespace lists its writes there from what it wrote.
  - A `200` is never served at a URL with `min` (§E.2.6).
- **Canonical URLs.** A service's redirects give the query in one form. Parameters are sorted by name, then value, comparing their decoded UTF-8 bytes. Every byte other than ALPHA, DIGIT, `-`, `.`, `_` and `~` is percent-encoded in uppercase hex (so a space is `%20`, never `+`). Indexes and tree services (§B.5) answer `200` only at that form and redirect others to it (§E.2.6). Repeatable parameters, such as `min`, are sets, sorted like the rest. A parameter the service doesn't define, or a non-repeatable one given twice, is `400` (§7), and a list whose order matters is one value, such as `fields=/name,/title`.

## A.6 Operations

- **Rebuild:** delete the index and replay from `""` (§10); a new schema revision needs none.
- **Access control:** the service MUST enforce the namespace's read permissions by verifying the reader's grant locally (§C.6).

---

# Addendum B — Organising documents (suggested)

Trees and DAGs over documents, kept apart from them in **catalog namespaces** of folders and **placements**. A **tree service** serves listings, and a **catalog service** also derives access from the tree and issues grants (§B.11); both are namespace consumers (§10). The core never interprets any of it, except an origin that implements §B.11.9.

## B.1 Principles

- **Names are identity; organisation is separate data.** Names are flat and stable (§3.6) and positions are recorded in catalogs, so a move never changes a document's URL, history or cache keys.
- **A catalog is a namespace,** with its own documents, rules, keys, history and log; several can organise the same content independently.
- **Separate histories, separate permissions.** Moves are in the catalog's history, edits in the content's; neither needs write access to the other.
- **Edges live on the node that moves:** a move is one write to one catalog document, contending only with other moves of that node.

## B.2 Catalog namespaces: folders and placements

A catalog namespace (e.g. `cat-season`) contains two kinds of **node**, told apart by their names:

| Node          | Name                                                      | Purpose                                            |
|---------------|-----------------------------------------------------------|----------------------------------------------------|
| **Folder**    | no dot, e.g. `season-2026`                                | a catalog-native grouping: title, settings, access |
| **Placement** | `{ns}.{name}` of the item it places, e.g. `matches.derby` | positions one content document in this catalog     |

A placement name splits at its first dot into the **item** `/r/{ns}/{name}` (§3.6); there is no `item` field. An item can be placed only where `{ns}.{name}` has at most 128 characters (§3.6).

``` json
// /r/cat-season/season-2026  (folder)
{ "$schema": "/r/schemas/folder/rev/1f…",
  "title": "Season 2026",
  "parents": [{ "href": "/r/cat-season/root", "order": "a0" }] }
```

``` json
// /r/cat-season/matches.derby  (placement of /r/matches/derby)
{ "$schema": "/r/schemas/placement/rev/1p…",
  "parents": [
    { "href": "/r/cat-season/season-2026", "order": "a1" },
    { "href": "/r/cat-season/derbies",     "order": "Zz" } ] }
```

- **`parents`:** live links to folders **in the same catalog**, each with its own `order`: a folder's children sort by the order on their edge to it. One entry makes a tree node, several a DAG node, as the catalog's rules choose (§B.6); none (absent or `[]`) makes a root. Folders nest the same way.
- **`order`:** an optional fractional-index sort key among siblings, compared by UTF-8 bytes: any key between `a1` and `a2`, such as `a1V`, goes between them, rewriting no sibling. Unordered siblings sort after ordered ones, and siblings with equal or no `order` by node name.
- **At most one placement per item per catalog,** enforced by the name `/r/{catalog}/{ns}.{name}`.
- **Operations:** place by creating the placement, move with `replace /parents`, reorder with `replace /parents/{i}/order`, and remove from the catalog by deleting the placement, leaving the content document unaffected.
- **Item-level settings** (e.g. `$access`, §B.11) live on its placement, never in the content.

## B.3 Links

A link is a live (`/r/{ns}/{name}`) or pinned (`/r/{ns}/{name}/rev/{id}`) path on this service, as for `x-ref` (§6.5), with names valid under §3.6.

- **Referential integrity** is not enforced. A placement whose item is deleted, or a `parents` entry naming a missing folder or anything but a live link to a folder of this catalog, is **dangling**. The tree service drops it from traversals and reports it (§B.5).

## B.4 Manifests (pinned snapshots)

A **manifest** is a document whose links are all pinned, so its revision id fixes the content of everything it lists.

``` json
{
  "$schema": "/r/schemas/manifest/rev/1m…",
  "catalog": "cat-season",
  "root": "/r/cat-season/season-2026/rev/1a…",
  "entries": [
    { "href": "/r/matches/derby/rev/1q3f…",  "path": ["season-2026"], "order": "a1" },
    { "href": "/r/matches/opener/rev/1c9d…", "path": ["season-2026"], "order": "a0" }
  ]
}
```

- **Creation:** the tree service generates a manifest for a subtree as of a catalog `ns_id` (§B.5), and the client creates it as an ordinary resource.
- **Shared items.** In a DAG, an item reached along several paths has one entry per path, each with that path and its last edge's order, so an `href` can repeat.

## B.5 Tree service

A consumer of a **catalog namespace**:

- For each coalesced `head` of a node, it replaces that node's outgoing edges from `parents`; `tombstone` and `purge` remove them.
- It also follows the content namespaces the catalog trusts (§B.6), and marks a placement whose item is gone, or in a namespace the catalog doesn't trust, dangling.

``` sql
CREATE TABLE checkpoints (ns TEXT PRIMARY KEY, ns_id TEXT NOT NULL);           -- the catalog and each trusted content namespace
CREATE TABLE nodes (href TEXT PRIMARY KEY, kind INTEGER NOT NULL,              -- 0 folder · 1 placement
                    item TEXT, item_head TEXT, title TEXT, state INTEGER NOT NULL DEFAULT 0);  -- 0 live · 1 gone · 2 dangling
CREATE TABLE edges (child TEXT NOT NULL, parent TEXT NOT NULL, ord TEXT, PRIMARY KEY (child, parent));
CREATE INDEX edges_by_parent ON edges (parent, ord, child);
```

**Query API.** Served on the tree service's own origin, or under a root of its own (§C.5.3), which paths below are relative to.

- Listings redirect (`302`, head-pointer caching) to `/{catalog}/at/{at}/…` or `/{catalog}/g/{gs}/at/{at}/…`, as §B.11.5 says.
- `at` is the service's **combined checkpoint**, `text(trunc160(sha256(canonical({ ns: ns_id, … }))))` over the catalog and the content namespaces it follows, purged ones left out.
- A listing at a given `at` never changes. It uses the immutable class (§9), tagged with every item it shows (`r:{ns}/{name}`) and every namespace in the checkpoint (`ns:{ns}`). A service whose cache the origin's purges don't reach purges these tags itself, as §A.1 does.
- The service answers `200` at an `at` only if it is current or that exact result was stored, else `302` to the current one. It SHOULD store the result at an `at` it redirects to for a while (§A.4).
- `?min={ns}:{ns_id}`, repeatable, gives read-your-writes (§A.5). A service following several catalogs keeps a combined checkpoint per catalog. It judges `?min` against that of the catalog in the URL, even for a content namespace other catalogs follow too.

| Request                           | Returns                                                                                                                                                                              |
|-----------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `…/children?of={folder}`          | direct children (folders and items), ordered, paginated as `/_refs` is (§A.4), with an opaque `next`, with `total`, the number of visible children; each node carries `born` (below) |
| `…/lookup?path={titles}`          | the node a path of titles, joined with `/`, names (below)                                                                                                                            |
| `…/ancestors?of={node}`           | every path to a root, for breadcrumbs                                                                                                                                                |
| `…/subtree?of={folder}&depth={n}` | nested listing                                                                                                                                                                       |
| `…/roots`                         | nodes without parents, or, in a listing filtered by subject set, those §B.11.5 makes roots                                                                                           |
| `…/orphans`                       | cyclic nodes, and nodes with parents, all of them gone, dangling or cyclic                                                                                                           |
| `…/problems`                      | cycles, dangling items and dangling parents                                                                                                                                          |
| `…/where?item={/r/ns/name}`       | the item's placement and paths in this catalog                                                                                                                                       |
| `…/manifest?of={folder}`          | a manifest for the subtree, pinned as of the checkpoint                                                                                                                              |

- **`born`** (in `children`) is the `created` of the node's first revision.
  - For an implicit placement (§B.9), it is its item's, left out for a sealed or end-to-end item.
  - It is left out where that entry is pruned.
  - It is sealed per entry in a sealed or end-to-end catalog (§E.2.6).

- **`lookup`** starts from the folder `root` of a file tree (§H.2), or, where `root` is hidden from the reader or missing, from the visible roots of its subject set (§B.11.5). It is filtered like `children`.
  - Titles compare after NFC and Unicode simple case folding (§H.2).
  - A numbered or escaped display name doesn't resolve, and a tool then lists the folder.
  - Where siblings share a title, it answers the earliest `born`, nodes without one last, then node name.
  - A path that doesn't resolve to a visible node is `404` (§B.11.5).
  - Not offered in catalogs without `files`, or in sealed or end-to-end ones (`404`, `not_offered`).

- **Parameters** name a node by its node name (§B.2), and an item as `/r/{ns}/{name}`. One not in this catalog is `404`, and so is one hidden from the reader (§B.11.5).

- **Fresh listings after a write.** Browsers cache the redirect too, so a client relisting right after its own write adds `?min` (§A.5), not `no-store`.

- **Behind.** Until it has caught up with the catalog and every namespace it follows, a service answers listings `503`, once the reader's grant verifies, never a listing whose placements dangle for want of data.
  - The `503` is `no-store`, with `code: "behind"` and `Retry-After`. It names, as `ns`, the namespace it waits for only to a reader with unrestricted `read` (§2.1) of the catalog.
  - Caught up means reaching the head read when catch-up started (§10), not a first checkpoint. A restart on the same store doesn't wait again.
  - A namespace it can't follow as configured (purged, refused it, unknown, or sealed or end-to-end without keys it can have) isn't waited for, and its placements dangle (§B.7).
  - A fetch that failed transiently (transport error, `5xx`, `408`, `429`) is waited for.

- **Items in listings** carry their content URL and current head, and, in a file tree, `file` (§H.3); the document itself is always fetched from the core's CDN. A catalog may set `"title": <JSON Pointer>` in its `catalog` object; the service then lists as `title` the string at that pointer in each item's head, except for items in sealed or end-to-end namespaces. A placement's own `title` wins over the item's.

- **Cycles.** The core can't prevent them; they are handled per node:

  - every node on a cycle (a strongly connected set of more than one node, or a node that is its own parent) is **cyclic**;
  - a cyclic node and all its edges, including edges to parents off the cycle, are left out of traversals, listings and access (§B.11.2);
  - `/problems` lists each cycle as its set of nodes, and `/orphans` lists them too.

  Walks are bounded at depth 64, and deeper paths are flagged too.

- **Shared nodes in DAGs.** `subtree`, `ancestors` and `where` show a node with several parents under each of them. Services MUST bound a response by the depth limit and a per-response node limit, and report when one was cut. They SHOULD expand a shared node only at its first occurrence in a `subtree` response and mark later occurrences `"repeat": true`, without children.

- **Previews of a release** (§F.9). A tree service previewing a release follows the branches its release document lists in place of their bases: `checkpoints` holds those branches, and a placement resolves to the release's branch of its item's namespace, if it lists one. It answers `403`, minting no edge grant (§B.11.5), to a viewer without unrestricted `read` (§2.1) on every listed non-public branch, serves previews only, and issues no grants (§F.8). A long-running preview service follows the release document's own log (§10), so its new revisions take effect without a restart.

- **`mode` is enforced by the catalog's rules** (§B.6), not by consumers: a `tree` catalog whose rules allow several parents is served as a DAG. A service MAY report nodes with several parents in a `tree` catalog under `/problems`.

## B.6 Catalog namespace document and rules

``` json
{
  "catalog": { "trust": ["matches", "docs"], "mode": "tree" },
  "rules": [
    { "op": "test", "path": "/resource", "schema": { "pattern": "^([a-z0-9][a-z0-9_-]*|(matches|docs)\\.[a-z0-9][a-z0-9._-]*)$" } },

    { "if":   [{ "op": "test", "path": "/action", "schema": { "enum": ["create", "append", "restore"] } },
               { "op": "test", "path": "/doc/parents", "exists": true }],
      "then": [{ "op": "test", "path": "/doc/parents", "schema": { "type": "array", "maxItems": 1, "items": {
        "type": "object", "required": ["href"], "additionalProperties": false,
        "properties": {
          "href":  { "type": "string", "pattern": "^/r/cat-season/[a-z0-9][a-z0-9_-]{0,127}$" },
          "order": { "type": "string", "pattern": "^[0-9A-Za-z]{1,64}$" } } } } }] },

    { "if":   [{ "op": "test", "path": "/action", "value": "create" }],
      "then": [{ "op": "test", "path": "/doc/parents", "schema": { "minItems": 1 } }] }
  ]
}
```

- **`catalog.trust`:** the content namespaces whose items may be placed here. The first rule enforces it on placement names, and also allows folder names.
- **`files`** (optional) makes the catalog a file tree (§H.2).
- **`mode`:** `tree` or `dag`. The `maxItems: 1` in the second rule implements `tree`; drop it for a DAG.
- **Parents** are **folders** of this catalog: no dot in the name.
- **No new roots:** every new node must be placed somewhere.

## B.7 Lifecycle

- **Create and place** are two writes, in either order, with no transaction: a placement may name an item that doesn't exist yet, and dangles until it does, granting `create` until it is removed (§B.11.2). Tooling SHOULD unplace stale ones, which `problems` reports.
- **Deleting content** leaves its placements dangling: they drop out of listings and access immediately, and are reported for cleanup.
- **Deleting a placement** removes the item from this catalog only.
- **Deleting a folder does not cascade.** Its children appear under `/orphans`. A recursive delete is a client-driven sequence of `DELETE`s.
- **Restoring** a folder or placement re-attaches everything that pointed at it.

## B.8 Whole-tree documents (small, curated trees)

A small tree, such as a menu (hundreds of nodes, edited rarely and by few people), can be **one document**:

``` json
{ "$schema": "/r/schemas/menu/rev/1n…",
  "root": { "title": "Site", "children": [
    { "title": "News",   "item": "/r/docs/news" },
    { "title": "Season", "children": [ { "item": "/r/matches/derby" }, { "item": "/r/matches/opener" } ] } ] } }
```

- **Atomic reorganisation.** Any reorganisation is one patch set; a move is a JSON Patch `move` between two `children` arrays.
- **Snapshots for free.** Every revision is a whole-tree snapshot, and pinning one gives a manifest.
- **Trade-offs:** all edits contend on one head, the document grows with the tree (§6.6), and access is per whole tree; use catalogs (§B.2) for large or busy trees, or where access follows the tree.

## B.9 Self-placing documents (optional shortcut)

A content document MAY carry `$parents` (shaped as `parents`, linking to folders of one catalog), which a tree service configured to accept it for a trusted namespace treats as an **implicit placement**. An explicit placement for the same item, live, deleted or purged, wins.

- **Trade-off:** moving the document means editing it, and organising needs write access to content.
- **Not accepted by default:** the catalog (§B.11) doesn't derive access from self-placements unless the content namespace's rules protect `/$parents` as strictly as the catalog protects placements. Where it does, a Place of a self-placed item also needs what a Move from its `$parents` needs (§B.11.4): `move` on each, and no widening.

## B.10 Access control

- **The core never inherits permissions down a tree;** it checks only the request's grant.
- **A catalog may derive grants from the tree** (§B.11); authority still flows only through grants.
- **A separate namespace is the strongest boundary** for a whole body of content needing a different audience.
- **Services that list content** MUST enforce read permissions for every node and item they list, titles and structure included.

## B.11 Catalog: tree-derived access

A **catalog service** is a tree service that also **issues grants**. It reads `$access` from folders and placements, computes each subject's roles at each item, and signs narrow, short-lived grants with a scoped key. The key is listed in the catalog namespace (for organising) and in each trusted content namespace (for reading and editing items).

**Invariant.** Only a role the caller holds at the decision, counted through the catalog's key (§B.11.2), grants, shows or powers anything, and an organising grant permits only the change it judged. Unless its writer is in `catalog-admins`, no write widens any subject's roles at a node that exists or existed, or at an item that is or was placed, as §B.11.4 judges it at the grant's decision (§B.11.8). A hidden node is answered as a missing one, except to `catalog-admins` organising and where §B.11.4 answers `409` (names are not secrets). A listing URL serves a reader only the subject set its credentials prove.

### B.11.1 `$access` and roles

The catalog decides **who has which role where**. Each content namespace decides **what a role means** for its documents, in its `roles`; a namespace that doesn't define a role grants nothing through it.

``` json
// folder
{ "$schema": "/r/schemas/folder/rev/1f…", "title": "Season 2026",
  "parents": [{ "href": "/r/cat-season/root" }],
  "$access": {
    "group:match-desk":  ["desk"],
    "group:translators": ["translator"],
    "group:fan-club":    ["reader"],
    "user:li":           ["reader"] } }
```

``` json
// embargoed sub-folder
{ "$schema": "/r/schemas/folder/rev/1f…", "title": "Transfer rumours",
  "parents": [{ "href": "/r/cat-season/season-2026" }],
  "$access": { "inherit": false, "group:editors-in-chief": ["desk"] } }
```

``` jsonc
// content namespace document (e.g. matches): what each role may do to its documents (§C.1.1)
"roles": {
  "desk":       { "can": ["read", "create", "append", "restore"] },
  "translator": { "can": ["read", "append"], "rules": [ { "op": "writes", "within": ["/i18n"] } ] },
  "reader":     { "can": ["read"] } }

// catalog namespace document: what each role may do in the tree
"roles": {
  "desk":       { "move": true, "place": true },
  "translator": {},
  "reader":     {} }
```

- **`$access`** maps subjects (`group:…` or `user:…`) to role names, applied to the **items** below the folder. Role names are all the catalog hands out. **Placements** may carry `$access` too, and the folder and placement **schemas** validate its structure.

- **The catalog namespace defines tree powers:** **`move`**, moving nodes out of or into a folder, and **`place`**, placing new items directly into a folder. Where a role has them, and how **`inherit: false`** and **`inheritPowers: true`** change the walk up, is §B.11.2's.

- **`user:` entries** are for exceptions: grant through groups, as each user with direct entries gets their own listing cache (§B.11.5).

### B.11.2 Effective access

- **Subjects.** A caller's subject set is its `sub`, if it starts with `user:` (e.g. `user:li`), plus `group:{g}` for each of its groups (§B.11.6).
- **Walk up.** A subject `s`'s **roles at a node** are the **union**, over every path from the node up to a root, of the `$access[s]` role names along it, the node's own included; an item's are those at its placement. A caller's are the union over its subjects.
- **Where a path stops:**
  - it stops collecting **after** a node with `inherit: false`
  - a path that reaches a **tombstoned, purged, dangling or cyclic** node ends there, and that node contributes nothing
  - a dangling placement grants nothing, except, for an item in a namespace the catalog trusts:
    - `create` for an item that has never existed
    - `restore` for an item that is tombstoned, not purged, to those of the roles it had when it was deleted that it would have now if live (§B.11.4)
  - deleting a node that isn't cyclic (§B.5) can therefore never widen access
- **Through the key.** In a content namespace, a role **counts** for a verb when the namespace defines it with that verb and the catalog's key there may grant it to the caller. It may when all hold (§B.11.3, §C.4):
  - the key's `can` lists the verb;
  - its `roles` scope allows the role;
  - its `sub` scope, if it has one, matches the caller's `sub`, which must start with `user:`;
  - the role was collected through the caller's `sub` or a group its `groups` scope allows.
- **Across catalogs.** Each catalog the item's namespace trusts issues grants from its own computation, and an item's total access is their union. A content namespace should list, with scoped keys, only the catalogs it trusts to open it up.
- **Allow-only.** There are no denies.
- **Tree powers** (`move`, `place`) apply only at the folder where a role granting them is assigned.
  - If the folder's `$access` sets `"inheritPowers": true`, roles collected on the walk up from it grant them there too.
  - Powers count only at a live folder that isn't cyclic, and only through subjects the catalog's key in the catalog may assert.
  - At a folder without `$access` but with parents, a subject's role has a power when that subject's same role has it at every one of them. Each `parents` entry counts, and a tombstoned, purged, dangling or cyclic parent gives none.

### B.11.3 Keys and namespace documents

**In the catalog namespace** (writes to folders and placements):

``` json
{ "read": "grant",
  "keys": [
    { "kid": "ops-2026",   "alg": "Ed25519", "pub": "…", "can": ["*"] },
    { "kid": "catalog-01", "alg": "Ed25519", "pub": "…",
      "can": ["read", "create", "append", "delete", "restore"], "maxTtl": "PT15M", "requireAt": true,
      "groups": { "deny": ["catalog-admins", "ops"] },
      "rules": [
        { "if":   [{ "op": "test", "path": "/action", "schema": { "enum": ["create", "restore"] } }],
          "then": [{ "op": "test", "path": "/doc/$access", "exists": false }] },
        { "if":   [{ "not": { "op": "test", "path": "/action", "schema": { "enum": ["create", "restore"] } } }],
          "then": [{ "not": { "op": "writes", "overlaps": "/$access" } }] } ] } ],
  "maxLag": "PT60S",
  "rules": [
    { "if":   [{ "any": [
                { "all": [{ "op": "test", "path": "/action", "schema": { "enum": ["create", "restore"] } },
                          { "op": "test", "path": "/doc/$access", "exists": true }] },
                { "all": [{ "not": { "op": "test", "path": "/action", "schema": { "enum": ["create", "restore"] } } },
                          { "op": "writes", "overlaps": "/$access" }] } ] }],
      "then": [{ "op": "test", "path": "/principal/groups", "schema": { "contains": { "const": "catalog-admins" } } }] } ] }
```

**In each trusted content namespace** (reading and editing items):

``` json
{ "keys": [
    { "kid": "catalog-01", "alg": "Ed25519", "pub": "…",
      "can": ["read", "create", "append", "restore"], "maxTtl": "PT15M", "readScope": "resource", "requireAt": "cat-season",
      "groups": { "deny": ["ops"] }, "roles": { "allow": ["desk", "translator", "reader"] },
      "rules": [{ "op": "test", "path": "/principal/roles", "schema": { "minItems": 1 } }] } ],
  "roles": { "desk": { … }, "translator": { … }, "reader": { … } },
  "catalogs": { "cat-season": { "place": ["group:match-desk", "group:editors-in-chief"] } } }
```

- **Scoped keys bound the catalog service:**
  - in the catalog it may create, move and delete nodes, but never change `$access`;
  - in content namespaces it grants only by a key whose `requireAt` names the catalog, in one whose `catalogs` names it (§B.11.9 Where);
  - there it may only grant reading, creating, appending and restoring, reading only in grants that fix `/resource` (§2.1);
  - there it grants only through the roles the content namespace allows it, which its key's `rules` require every grant to carry;
  - it may never assert admin groups.
- **Only `catalog-admins` change access settings**, including via root replaces or `move` from `/$access`, or create or restore a folder or placement whose resulting document has `$access`. Deletes write nothing and pass these rules (§B.11.2).
- **Content owners decide who may bring their content into a catalog.** `catalogs.{catalog}.place` in the *content* namespace lists the subjects (`group:…` or `user:…`) allowed to place its items in that catalog (§B.11.4).

### B.11.4 Issuing grants

``` http
POST /grants
Authorization: Bearer <base grant from the identity provider>
{ "item": "/r/matches/derby", "want": ["append"] }
```

1.  **Resolve** the caller's subjects (§B.11.6) and its roles at the item at the current checkpoint, keeping only those that count there for a wanted verb (§B.11.2).
2.  **Sign a root grant** for exactly that resource, carrying those role names, with an absolute `exp` within `maxTtl`:

``` jsonc
{ "kid": "catalog-01", "sub": "user:anna", "groups": ["translators"], "roles": ["translator"],
  "ns": ["matches"], "can": ["append"], "exp": "2026-10-04T18:10:00Z", "at": { "ns": "cat-season", "id": "1k…" },
  "rules": [ { "op": "test", "path": "/resource", "value": "derby" } ] }
```

The catalog grants role names without evaluating their rules, which the gate applies (§C.1.1), so it may still refuse a write under them.

Item requests other than Place answer, in order:

- first `403` for an item in a namespace the catalog doesn't trust;
- then, for those other than Create, as Restore's list does (below):
  - in a purged namespace, `410`;
  - `404` for a name that never existed;
  - for a purged item, `403` without a role that makes it visible (§B.11.5) at its placement, computed as for a live item, and `410` otherwise;
  - then `403` when no role is kept.

**Read-your-writes.** `POST /grants` and `POST /read-grants` accept `?min={ns}:{ns_id}`, repeatable: the service decides at a checkpoint at or past every `min`, or answers `503` as listings do (§A.5). After creating a document it placed, or restoring one, a client passes `min` for both the catalog and the content namespace.

- **`checkpoint`.** Answers carry `checkpoint`, `{ ns: ns_id, … }`: the `ns_id`, as of the decision, of every namespace whose state it read. These are the catalog, each named item's namespace, and any other content namespace whose roles or `includes` it read (a folder's visibility, a move's no-widening check).
  - A client that caches a decision keys it by those entries.
  - It goes beside each grant, never inside it, and beside refusals decided at it (`403`, `404`, `409`, `410`).
  - A refusal from state it doesn't pin, such as a name the core has and the service hasn't seen yet, has none and isn't cached.
  - A refused `/read-grants` item isn't cached either. Its answer still carries the one `checkpoint`.
  - It isn't the grants' own `at` (§B.11.7).
  - `POST /grants` answers `200` with `{ "grant", "checkpoint", "parents"?, "head"? }`. `parents` and `head`, the node's parents and head revision as decided, are for a Move or an Unplace or delete.
  - `POST /read-grants` answers `200` with `{ "items": [{ "item", "grant"?, "public"?, "keys"?, "keysWithheld"?, "status"?, "code"? }], "checkpoint" }`, one per item in request order. An item refused or undecided has `status` and `code` (§12.1).

Organising requests yield grants for the **catalog** namespace, without `roles`. Each grant:

- has the verb its write needs, unless a request below gives another: `create` for Place and Create a folder, `append` for Move, `delete` for Unplace or delete a folder;
- fixes `/resource` to the node name;
- fixes `/doc/parents` to exactly the requested target set, compared by `href`: each entry's `order` is the writer's (§B.2).

The answers, unless a request below gives its own, in order:

- `400` for a malformed request;
- `404`, a new folder's `node` excepted, for a `node` that isn't an untombstoned node of this catalog, a `to` entry that isn't a live folder of it, or, to a caller not in `catalog-admins`, one hidden from it (§B.11.5);
- `403` for a requirement below that fails, or an `item` in a namespace the catalog doesn't trust;
- then `409`.

In an end-to-end catalog the service issues no organising grants (`404`, `not_offered`).

A caller in `catalog-admins` needs no tree power, though a Place still needs the place list. Any other caller also needs a non-empty `to` in a request that takes one. It can't move, unplace or delete a node without parents, or one with a parent hidden from it.

- **Place** (`{ "item": …, "want": ["place"], "to": [folders] }`) requires that the caller is in the content namespace's `catalogs.{catalog}.place` list and has a role with `place` on **every** folder in `to`.
  - If an earlier placement of the item was deleted, the grant carries only `restore`, and restores it with a root replace, which must not widen (below). If the placement is live again when the grant is used, the write is an append, refused at step 2 (§6.2).
  - A Place of an item whose placement is live is `409`, and one whose placement was purged `410`, both where the answers above put `409`.
  - Placements should carry a fresh `$nonce` (§C.7).

- **Move** (`{ "node": …, "want": ["move"], "to": [folders] }`) requires a role with `move` on **every** current parent the node leaves and on **every** folder in `to`, and no widening.
  - A `to` entry that is the node or below it is `403`.
  - A Move grant may also change the node's other members, `$access` excepted (§B.11.3): a rename is a move to the node's current parents.
  - Unless the caller is in `catalog-admins`, a Move grant also requires its patch set to begin with a `test` of `/parents` against the node's parents as decided. The answer gives these as `parents`.

- **No widening:** for every subject, the roles of every node after the write must be a subset of those before, unless the caller is in `catalog-admins`.
  - For a move, both are roles at a node (§B.11.2), computed as for live items, even for an item that is deleted or not yet created.
  - For re-placing a placement (above) or restoring an item (below), the item's roles from its placement after the write are compared with its frozen rows (§B.11.7).
  - A role counts as present before if it, or a role that includes it, was. A content namespace may declare `"desk": { "can": [ … ], "includes": ["reader"] }`.
  - `includes` is transitive, is read from the item's own content namespace, and is trusted as declared (§C.1.1).
  - A folder's roles compare by name.

- **Copies.** The service sees no content, so it can't tell a copy from any other write. A copy, or a move that copies (§H.5), is written by a caller who can read the source, which Protection allows (§2.1). What bounds where an item's content goes is who may read it.

- **Unplace or delete a folder** (`want: ["delete"]` on a node) requires a role with `move` on every current parent, and its grant fixes `/doc/parents` to exactly those parents. Folders are restored only by `catalog-admins`, under grants of their own: the service answers a request naming a tombstoned folder `404`, as above.

- **Create a folder** (`{ "node": …, "want": ["create"], "to": [folders] }`) requires a role with `move` on every folder in `to`. `node` must be:
  - a folder name (§B.2; `400` otherwise);
  - a name that no node has or had, and no `parents` entry or accepted `$parents` (§B.9) names, hidden ones included (`409`, §E.4).

- **Create** (`{ "item": "/r/matches/final", "want": ["create"] }`): the caller first **places** the new item (above), which dangles until it exists (§B.7). The catalog then resolves the caller's roles at that placement and keeps those that count for `create` (§B.11.2). It signs a grant fixed to that name with `can: ["create"]`, which can only produce the genesis. The answers, in order:
  - in a purged namespace, `410` (below);
  - `409` for a name that exists or existed in the content namespace (§E.4);
  - then `403` for a caller whose item has no placement in this catalog, or who has no role kept.

- **Restore** (`{ "item": "/r/matches/final", "want": ["restore"] }`) keeps the caller's roles in the item's `effective` rows frozen at its tombstone (§B.11.7) that count for `restore` (§B.11.2) both there and at its placement now, computed as for a live item. It signs a grant fixed to that name with `can: ["restore"]`.
  - If the item is live when the grant is used, the write is an append, refused at step 2 (§6.2).
  - The frozen rows stay those of its deletion even if it was unplaced and placed again.
  - The answers, in order:
    - in a purged namespace, every name is `410`, for restores and creates alike (§8.5, §E.4);
    - a name that never existed is `404`;
    - a caller gets `403` without a role that makes the item visible (§B.11.5) to the caller's subjects (§B.11.2) both at its placement now, computed as for a live item, and, if it is deleted, in its frozen rows;
    - then a purged item is `410` (§8.3), and a live item `409`;
    - then `403` for a caller without a role kept, one whose item has no placement in this catalog, or one whose restore would widen (above).

- **Accountability.** Revisions record the grant, with its `at`, and `via` (§C.3, §7.1).

### B.11.5 Reads and listings

- **Listing URLs carry the subject set.**
  - A listing whose combined checkpoint (§B.5) has only public namespaces is served at `/{catalog}/at/{at}/…`, unfiltered, while they stay public.
  - Any other is served at `/{catalog}/g/{gs}/at/{at}/…`, where `gs` is `all` (below) or `text(trunc160(sha256(canonical(subjects))))`.
  - `subjects` is an array, in byte order of UTF-8 and without duplicates, of every `group:` entry of the caller's subject set. It adds the caller's `sub` only if the catalog has direct entries for that user, or the catalog's key in a content namespace the catalog trusts (§B.6) has a `sub` scope (§B.11.2).
  - A listing URL without `at` is under the prefix too, with the `gs` the exchange's `prefixes` gives.
  - A listing URL without `/g/{gs}` is redirected to its `…/g/{gs}/at/{at}/…` URL by the grant in `Authorization`, `private, no-store`.
  - A grant in `Authorization` reads only at its own `gs`, as of the URL's `at` or, as the service chooses, of the current checkpoint, or at `all` where it qualifies (below). Elsewhere it is `403`.
  - A request that needs `/g/{gs}` and carries neither a grant that verifies in a namespace the service follows nor a cookie it verifies is `401`.
  - A tree service without §B.11 serves only `all` (`403` otherwise).
  - The edge admits a request only if the caller's edge grant is bound to that exact `gs`. That edge grant is a cookie the service mints with a key of its own (§C.5) for the prefix `/{catalog}/g/{gs}`. The service mints it after resolving the caller's subjects, at an exchange endpoint of its own that follows §C.5.2's issuance rules, except as §A.4 says for the index.
  - Services apply §9 to their own origin.
  - A service keeps which subjects each `gs` stands for (§C.5.3). Services needn't compute the same `gs` for a reader, nor the same `scope:` digest (§A.4). A `gs` cookie other than `all` authorises listings of that subject set only: `problems`, `orphans` and manifests stay `403` under it.
  - A service applies `exchangeRate` (§6.6) to its own exchanges, its buckets shared across its instances as the origin's are. Listings are cached per (listing, subject set, `at`).
- **Listings are filtered by their subject set.** A node is **visible** to a subject set when the walk up from it collects a role that counts for `read` (§B.11.2) and whose own rules and the key's scope `rules` pass as a read would evaluate them (§6.4.1, §6.4.2). Here the caller's `sub` is that of the set's `user:` subject (a set without one fails a `sub` scope), and `/principal` holds only the groups the key may assert and, as `roles`, that role.
  - For an item, that is a role of its own content namespace, with `/resource` its name.
  - For a folder, it is a role of some trusted content namespace whose rules don't refer to `/resource`, through a key whose scope `rules` refer only to `/principal/groups` and `/principal/roles`.
  - A rule that refers to anything in `/principal` but `groups` and `roles` makes the role not count.
  - The roles, their definitions and the keys are those as of the content namespaces' `ns_id`s in the listing's combined checkpoint (§B.5).
  - `children`, `subtree`, `roots`, `ancestors` and `where` show visible nodes only, and only paths through visible folders. A visible node with no visible parent is a root for that subject set: `roots` lists it, and paths end at it.
  - Nothing about a hidden node appears, not even as a count. A request that names one is answered as one naming a node not in this catalog (`404`, body included). This holds here, as a catalog node in `/read-grants` (below) and, from a caller not in `catalog-admins`, in an organising request (§B.11.4), where a dangling placement is judged as if its item were live. The exceptions are a new folder's name and a Place of an item whose placement is live, which are `409` (§B.11.4).
  - Response limits, cut markers and pagination (§B.5) apply to the visible nodes.
  - `/read-grants` uses the same test for catalog nodes and their keys.
  - `problems`, `orphans` and `manifest` aren't filtered. They need unrestricted `read` (§2.1) on the catalog and on the content namespaces they cover (`403` otherwise). A public namespace counts as read unrestricted. The namespaces they cover are:
    - for a manifest, those of the items it pins;
    - for `problems` and `orphans`, every one in the combined checkpoint.
  - Unfiltered listings (`g/all`) are for readers whose grants would be issued a namespace-wide edge grant (`/r/{ns}` and `/ns/{ns}`, §C.5.2).
    - The catalog service issues an edge grant bound to `all` only after checking that for every namespace in its combined checkpoint (§B.5) that isn't public. The edge grant expires with the earliest of those grants.
    - Under such a cookie the service answers `403` at an `at` that includes a namespace that wasn't in its combined checkpoint at issuance, or has left it since, until the reader exchanges again.
    - A service that mints with the default format takes the issue time as `exp` less the 15-minute cookie maximum (§C.5.2), unless it recorded the issue.
    - A namespace that turns private stays readable under a live `g/all` cookie until it expires.
    - Without edge grants, `g/all` listings are served `private`, with a `max-age` no longer than such a cookie's lifetime.
- **Listings never embed signed URLs.** Readers get per-item grants from `POST /read-grants { items: [...] }` (`no-store`). The grants are short-lived, carry the roles that make each item visible (above), and are fixed to exactly `/r/{ns}/{name}` and `/r/{ns}/{name}/…`. They are exchanged at the origin's `POST /edge-grants` for cookies (§C.5.2), or for edge grants in a signed-URL form the deployment's edge verifies.
  - **Every item at once.** "May this reader read all of these?" is one call: it may if every item comes back with a grant, or as `"public": true`, which an item in a public namespace that isn't sealed does instead of a grant, or, for a catalog node or an item in a public sealed namespace, with its key alone.
    - A sealed item in a private namespace comes with both.
    - An item is refused as `POST /grants` refuses an item request (§B.11.4), only the roles that make it visible (above) counting. So a hidden item is answered as one without a placement (`403`).
    - A catalog node is `400` in a catalog that is neither sealed nor end-to-end, and otherwise `404` if hidden (above).
    - An item with a `4xx` status is refused, and one with a `5xx` undecided and asked again.
    - A service may cap the items of one request (e.g. 100, `400` above).
    - Revisions needn't be named.
  - **Keys.** For sealed items, and nodes of sealed or end-to-end catalogs, it also returns per-resource keys `K_r` (§E.2.1), wrapped to the caller's public key in the §E.2.3 format. The catalog service derives them from the epoch keys it holds as a consumer.
  - **Which keys.** A content item gets its own `K_r` in a sealed (E2) namespace, and none in an E3 one. When the catalog is sealed or E3, the item's placement node also gets its `K_r`. `items` may also name catalog nodes (`/r/{catalog}/{name}`), which get their `K_r`, and no grant, if visible to the caller (above).
  - **Checked like grants.** Keys are returned only for items that pass the same role check as the grants, items in **public** sealed namespaces included.
  - **Which epochs.** Keys cover the current epoch and the `encryption.historyEpochs` before it, or every epoch the service holds if the namespace sets no cap. As with `/keys`, losing a role takes effect at the next rotation (§E.2.4).
  - A caller whose grant carries no public key still gets its grants, with `"keysWithheld"` and the reason in place of keys.
- **Readers of a whole content namespace** use a namespace-wide edge grant instead (§C.5).

### B.11.6 Groups

- **Default:** group claims come in the base grant from the identity provider.
- **Alternative:** a `groups` namespace of documents (`{ "members": [...] }`) that the catalog service follows.
- **Either way,** key scopes limit which groups and roles the catalog may assert.

### B.11.7 Catalog storage

For example:

``` sql
CREATE TABLE nodes     (node TEXT PRIMARY KEY, inherit INTEGER NOT NULL DEFAULT 1);
CREATE TABLE acl       (node TEXT, subject TEXT, role TEXT, PRIMARY KEY (node, subject, role));
CREATE TABLE effective (item TEXT, subject TEXT, role TEXT, PRIMARY KEY (item, subject, role));
CREATE INDEX effective_by_subject ON effective (subject, item);
```

- **Maintenance.** A change to a node's `$access` or `parents`, a tombstone, or an item's deletion or restore recomputes `effective` for the affected subtree.
- **Role definitions** are applied at the gate, but a change to `/roles` in a content namespace recomputes the listing visibility it affects (§B.11.5).
- **Deleted items** keep their rows in `effective` as they were when the tombstone was seen, marked as tombstoned and no longer recomputed. A deleted placement's rows are kept apart the same way until it is placed again. Restores and re-placings are checked against them for no widening (§B.11.4).
- **Consistency.** The checkpoints are stored in the same transaction, so `effective` reflects a known catalog `ns_id`, which is the `at` of every grant issued from it.

### B.11.8 Staleness and revocation

- **Staleness is bounded by `maxLag` plus the grant's lifetime,** and for keys handed out for sealed items by the next rotation (§E.2.4).
- **Overtaken decisions.** A grant is judged at its decision. It doesn't see a later change by someone else, such as a move of an ancestor of the node or a `catalog-admins` edit: a Move grant can still take its node out of a folder narrowed since. So a Move grant's `exp` is at most the catalog's `maxLag` (§7.4) after its decision.
- **For immediate revocation,** add the grant's revocation id to `revoked` (§C.4) in the namespace where it applies.

### B.11.9 Filtered namespace reads

Optional. An origin that implements it gives **partial readers** a namespace's own reads, filtered. One that doesn't answers them as §C.5 says.

- **Where.** It covers, only while authentication is on (§1), a namespace that trusts a catalog, and that catalog. Each is covered only where it is neither a branch (§7.6), public, sealed nor end-to-end, as their documents alone decide. It applies where the origin implements it; §A.4 follows coverage whatever the origin implements.
  - A namespace trusts each catalog its `catalogs` names whose `catalog.trust` lists it, through its keys whose `requireAt` names that catalog (§B.11.3). Each such key counts alone as the catalog's key (§B.11.2).
  - Only such namespaces' roles count for that catalog's folders.
  - An end-to-end catalog, which the origin can't read, a branch or a purged one makes nothing visible.
- **Partial reader:** a caller for whom all hold:
  - its grant verifies in `{ns}` and allows `read` there (§C.2 items 1 and 2);
  - no block or key-scope rule refers to `/now` and, if it carries roles, it has an effective role that lists `read` without one (§C.2 item 5);
  - it lacks unrestricted `read` (§2.1), such as one signed by a key whose scope `rules` refer to `/resource` without fixing it, as `{ "op": "test", "path": "/resource", "schema": { "type": "string" } }` does.

  Unrestricted readers keep the unfiltered answers and URLs. At filtered ones their grant in `Authorization` is `403`, and a `/ns/{ns}` cookie, which covers them (§2.1), is served as that `gs`'s cookie would be.
- **Visible.** A resource is visible to a partial reader when both hold, at the answer's one combined checkpoint (URLs):
  1.  a catalog `{ns}` trusts makes it visible: §B.11.5's item visibility for the subject set of its `gs`, at the item's placement there;
  2.  the grant its `gs` stands for allows it: its blocks and key scope allow `read` of `/r/{ns}/{name}` as §C.2 judges that read, roles counting only as §B.11.5 counts them.
- **Placement.** Only a live placement makes a resource visible: one never placed, or whose placement was deleted, is hidden. So place before create (§B.11.4), unless the document should stay hidden until placed, as a release's do (§F.9).
- **Deleted resources.** A tombstoned or purged resource is judged at its placement as if it were live, at the answer's `at`. A purged catalog node is hidden.
- **Catalogs** show a node only if item 2 allows it and §B.11.5's node test makes it visible, never a placement whose item doesn't exist or is tombstoned; a node's own tombstone or purge is judged as Deleted resources says.
- **Answers** to a partial reader, other reads being answered as without this section:

  | Read                                                                     | Answer                                         |
  |--------------------------------------------------------------------------|------------------------------------------------|
  | `GET /ns/{ns}`                                                           | the head pointer of §7.4                       |
  | `GET /ns/{ns}/rev/{ns_id}`, `/ns/{ns}/grants/{gid}`, `/ns/{ns}/branches` | `403`, unchanged                               |
  | `/heads`, log ranges, long-poll and events                               | filtered, below                                |
  | the gestures listing (§7.4); index queries (§A.4)                        | filtered by visibility, the index as §A.4 says |

- **Log entries** keep their shapes; only the set changes.
  - `head`, `tombstone`, `purge` and `prune` are shown when their resource is visible, `config` and `purge-ns` always, and `branch` never.
  - A `batch` shows only its visible `entries`, and its `gestures` and `source.ids` without hidden names, each left out if none remains. One with no visible item is dropped, or kept as a `config`-only batch if it has a config entry.
  - A filtered log isn't chain-verifiable, as batch ids don't hash what is served and `prev` names unseen entries (§10).
- **Log ranges** are paged as §7.1 says, a batch counting as its visible items and a hidden entry as one. They serve each page's visible entries, possibly none. Long-poll and event pages count alike.
  - A range ends at the `ns_id` of `{ns}` in its `at`, which answers at an `at` carry as `X-Namespace-Revision`.
  - Every page but the last carries `X-Log-Next`, naming its last entry, visible or not, so a client reads pages until one without it.
- **`/heads`** lists only visible rows, as §7.4 gives them, in pages filled to `logPageSize`; `next`, the last row returned, is on every full page and no other.
- **Long-poll.** Only visible entries answer `200` or end a wait, so an interval with none ends `204`. `X-Namespace-Revision` names the newest entry scanned, so a follower moves past hidden ones, and a `since` naming one is accepted. `X-Cursor` is unchanged.
- **Events** carry only visible entries, visibility judged again, at a current checkpoint, with each read check §7.3 repeats; `Last-Event-ID` may name a hidden entry.
- **Cost (SHOULD).** On each wake a server evaluates each new entry's visibility at most once per `gs` and combined checkpoint that has waiting followers, who share the answer.
- **URLs.** Ranges are at `/ns/{ns}/g/{gs}/at/{at}/heads` and `…/log`.
  - `at` is the combined checkpoint (§B.5) of every namespace whose state visibility reads, each at its head: `{ns}`, each catalog deciding it and each namespace those catalogs' `catalog.trust` lists. So the cache key is `gs` and that checkpoint, never a catalog head alone.
  - Ranges are answered at an `at` as §B.5 says, or wherever the origin can compute that exact answer again but for purges since. They are immutable, and tagged as their unfiltered forms would be in each namespace in `at`.
  - Long-poll and events are at `/ns/{ns}/g/{gs}/log` and `/ns/{ns}/g/{gs}/events`.
  - A URL under that prefix without `at`, such as `…/g/{gs}/heads`, or `…/g/{gs}/log` without `live` (§7.7), or at an `at` not answered, answers `302` to its form at the current `at`, `private, no-store`, under the cookie (§B.11.5).
  - A partial reader's request at an unfiltered URL is answered `302` to its filtered form, ranges at the current `at`, `private, no-store`, by the grant in `Authorization`.
  - Otherwise these URLs are served as §B.11.5 serves listing URLs, except:
    - **`gs`** is §B.11.5's, never `all`. Its `subjects` are the following, so a narrowed grant never shares a cache entry with an unnarrowed one:
      - the caller's `group:` entries;
      - its `sub` where §B.11.5 would add it for any catalog `{ns}` trusts (for a catalog, for itself);
      - the string `scope:{digest}` of §A.4's marker for `{ns}`;
      - the string `key:{text(trunc160(sha256(canonical([kid, pub]))))}` of the key that verified the grant's root block.

      The origin keeps, per namespace and `gs`, its subjects and the rules and `/principal` values its marker digests. It judges item 2 under a cookie, a miss included, from those, never from a grant the request doesn't carry. A cookie whose `gs` it keeps nothing for is `401`.

      A `gs` cookie is `403` at an `at` where those rules differ, or the key its `key:` string names, or a key or role they came from, is gone or no longer allows `read`, until the reader exchanges again.
    - **Edge grants.** The origin's exchange (§C.5.2) gives a partial reader whose grant doesn't fix `/resource` the prefix `/ns/{ns}/g/{gs}`, after resolving its subjects. Its cookie never outlasts that grant. For that prefix, §C.5.2's checks change:
      - its refusals concerning `/resource` rules and qualifying roles don't apply;
      - its check that rules pass now covers only block and key-scope rules that don't refer to `/resource`, which item 2 judges per resource;
      - its refusal for no `read` still applies.
- **Purged namespaces** answer these URLs as §8.5 answers their unfiltered forms, `/heads` without `at` as `/heads`. Other namespaces this section doesn't cover, branches among them, answer them `403`, or `401`, in §7's order, where the request carries neither a grant that verifies in `{ns}` nor a cookie the origin verifies.
- **Accepted leaks** (§C.6):
  - that hidden writes happen, and when, through the namespace head, `X-Namespace-Revision` and long-poll wake-ups;
  - hidden `ns_id`s, through `prev`, `X-Namespace-Revision` and `X-Log-Next`;
  - that a batch also wrote hidden resources, through its `author`, `grant` and `created`;
  - who changed the configuration, and when.

## B.12 Open questions

- Should a content namespace be able to *require* that every item is placed in some catalog?

---

# Addendum E — Encryption: derived views (optional)

The rest of Addendum E is in [SPEC.md](SPEC.md). This section binds a service that serves anything derived from a sealed or end-to-end namespace.

### E.2.6 Derived views

For services serving views derived from sealed and end-to-end namespaces, such as search results (Addendum A) and tree and catalog listings (Addendum B):

- **Getting keys.** A service fetches epoch keys like any reader (§E.2.3), with its own key pair and a grant with `read`. At E3, one whose public key isn't a recipient in the namespace's `keyring` can derive nothing: it skips the namespace, says so in its status, and MUST NOT index or list ciphertext as if it were content. A `keyring` entry whose `from` it doesn't trust (§E.3.2) counts as no key.
- **What gets sealed.** Every value a view derives from such a namespace's content is sealed, such as facets, scores, snippets, titles and `$access`-derived details. What §E.2.2 leaves in the clear stays so: names, ids, URLs and heads, and the view's own structure, `at`, `ns`, result order and pagination cursors. A cursor never encodes a sealed value, such as a sort key.
- **Whole-response sealing.** The service MAY serve the whole response as one JWE in the §E.2.2 format when all of these hold:
  - every sealed value in the response, values drawn from another resource (below) excepted, comes from one namespace that isn't public;
  - every reader its URL admits may read that namespace whole (`g/all`, §B.11.5, or an index `gs` with `reads:{ns}`, §A.4);
  - every such value derives from revisions served under one epoch.

  The JWE is sealed under that epoch's `K_n` (§E.2.1), with `Content-Type: application/jose` and `pl: { "ns", "view" }`.
- **Per-entry sealing.** Otherwise, including a single-source view for a reader whose grant gives only per-resource keys, the response stays JSON. Each entry (a hit, a child, a node) that carries sealed values replaces them with `"sealed": "<JWE compact>"`:
  - under the `K_r` of the entry's own resource (§E.2.1);
  - with `kid` naming the epoch the revision it derives from is served under (§E.2.2), at E3 the one a prune's `snapshot` of that revision would carry (§E.3.1). The epoch is judged once, when the service first seals a value derived from that revision;
  - with `pl: { "ns", "name", "view" }`.

  A value it derives from a revision of another epoch is sealed in place as a value of another resource is (below). An entry whose epoch the service's grant gets no key for (§E.2.3) is served by name only, or left out where the service never opened that revision. A reader decrypts the entries it holds keys for and shows the rest by name only. Folders and placements from a sealed or end-to-end catalog namespace are entries of that namespace.
- **Aggregates.** Values that combine several resources, such as facet counts, have no entry of their own and are served only in whole-response form. A service refuses them (`400`) to a reader that would get per-entry sealing.
- **`view`** is the request target, path and query, of the `…/at/{at}/…` URL that the response is served at, exactly as the service's redirect gave it. Readers MUST compare `pl` with the URL they fetched.
- **View keys.** Where this section seals a view's JWE under a `K_n` or `K_r`, the key used is `HKDF-SHA256(ikm = that key, salt = "patchlog-view", info = view)`, 32 bytes. So views count toward no epoch key's message bound (§E.2.1).
- **Values of another resource.** A value an entry carries that derives from a resource other than the entry's own, such as a placement's `file` drawn from its item (§H.3), is replaced by `{ "sealed": "<JWE compact>" }`. That JWE:
  - has as plaintext an object of that one member;
  - is under that resource's `K_r`, with `kid` the epoch the revision it derives from is served under;
  - has `pl: { "ns", "name", "view" }`, where `ns` and `name` name the other resource and `view` is the response's;
  - has its namespace's padding.

  It nests inside a whole-response JWE where the rest of the response is sealed whole. While a fetch of that namespace's keys fails transiently (transport error, `5xx`, `408`, `429`), the service answers `503` rather than a view without the value. A value whose epoch the service's grant gets no key for, or whose namespace's keys it lacks (§A.4: `/keys` answers it another `4xx`, or gives none it can unwrap), is left out.
- **Stored once, served forever.** A view at a given `at` is sealed once, under the epochs above, and then served unchanged, like revisions (§E.2.2), until a config entry on which §9 purges a source's `ns:{ns}` drops it (§A.1). A stored view is keyed by its URL and the shape of the reader's keys, as kept results are (§A.4). Padding (`pad`) follows the source namespace. Whole-response sealing pads only when every source is padded.
- **Caching** is public only for a view whose sources are all public (§9); other views are private results (§C.6). Tags are those of §A.4 and §B.5.
- **Local storage.** A service keeps what it derives from a sealed or end-to-end namespace in storage encrypted as at E1 (§E.1), such as an encrypted volume or database, with keys held outside it. Views it has sealed (above) may be stored as they are. A purge of the source, or the destruction of its keys, MUST remove the derived data: rows are deleted and freed pages overwritten, stored sealed views are deleted, and cached keys are forgotten.
- **Queries are metadata:** query strings are in URLs, so the service, the CDN and anyone who sees them learn them at every level (§E.4).
