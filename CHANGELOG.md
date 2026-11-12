# Changelog

## Unreleased

## Unreleased

- **Playground: less on screen at once.** Cards collapse: each tab opens with its one or two
  main cards (Namespace: status and document; Resource: document and patch) and the rest as
  header lines that open on click, with Branches and Problems showing a count. A flow that leads
  into a closed card opens it. Catalog, Search, Schemas and Keys are under a **More** menu,
  which marks a service the deployment doesn't have as not configured. The request inspector
  starts closed, as a strip at the bottom with the last request and its status, red after a
  failed request. Explanatory notes are behind a "?" per card, or "Show all help"; the warnings
  on purge and prune stay visible. With no namespace selected the page shows a start panel:
  open a namespace, create one, or run an example. Open cards, the help setting and the
  inspector are remembered in the browser.
  The content is a centred column; closed cards form one joined list below the open ones, with
  destructive ones last and marked by a red title; paired cards share a row at equal height.

- **Playground: merge a branch (§F.3).** Each row of the Namespace tab's Branches table has a
  "merge…" button, and a branch offers "Merge into {base}…". The Merge card shows the plan per
  resource (class, status, steps, conflicts with their paths), takes a resolution for each
  conflicting resource (a patch set against the base's head, "keep base" or "delete"), shows the
  dry run, submits the batch and can then freeze the branch with `merged.at`. Planning is done
  by a new endpoint, `POST /playground/merge/plan`, which runs the same code as `patchlog merge
  plan` in process with the caller's own headers and writes nothing: its transport lets through
  reads and a batch dry run only. The page submits the batch itself through the normal API.
  A resolution is sent with the base head it was written against, and one whose resource the
  base has changed since isn't applied until it is confirmed or edited. Plain namespaces only: a
  sealed or e2e namespace and a base that requires signatures are refused with a pointer to
  `patchlog merge`, and planning needs unrestricted read on both namespaces. An explicit
  `config` change in the batch isn't offered. A second merge of the same branch re-conflicts on
  replayed resources unless the base lists the merger in `merge.authors` (§F.3).

- **Capacity: large documents with a schema, and writes to one document.** `cmd/capacity`'s
  `large` phase now also measures a document of many small objects, with and without a
  `$schema` that types every member, and a new `single` phase measures writers contending for
  one document, a batch item of many steps, and a document with up to 100,000 revisions.
  [docs/CAPACITY.md](docs/CAPACITY.md) has the results: the earlier large-document figures were
  for long strings without a schema; small typed values cost about ten times more (58 ms an
  append at 1 MiB, 225 ms at 3.5 MiB), and one document takes about 10 writes a second per
  principal, the per-resource rate.


## v0.28.0

Implements spec **v0.82** (previously **v0.81**). v0.82 answers the reference's 77 notes on
v0.81, most with a clause each, and takes its confirmed candidate vectors into Addendum I. The
rule changes are: a namespace event has its own `pl`, `{ ns, event }`; a tombstone's `/rev`
names its parent in `last`; a service seals nothing from a revision whose epoch it hasn't
judged, and seals a release preview under the branch's keys; the message bound covers a sealed
bundle's key; a cookie ends on any change to its key's entry; a trusted catalog that is a
remote branch makes nothing visible; and `ancestors` answers `paths`, `tooDeep` and
`truncated`. `GET /` answers `"spec": "0.82"`. The upgrade was done in six packages: sealed
forms, end-to-end reads and levels in the core, the client and the playground; access at the
origin; the tree and catalog services with derived views and the grant checker; bundles,
archives, merges and the WebDAV gateway; the index; and the vectors with cross-package tests.
Each package was reviewed and fixed, and a cross-review of the merged branch then fixed two
seams between the tree service and the playground. The schema changes are the core's
migrations `017_filtered_gs_entry` and `018_filtered_gs_entry_after`, on SQLite and Postgres,
the index's `011_edge_gs_keys_entry`, the tree service's `006_v082_rejudge` and the
derived-view cache's `003_v082_drop_sealed_views` (SQLite, the cache of the tree service and
the index). The catalog service's database and the services' own edge-grant tables have no
migration. Where the spec leaves a question open, the reference implements the reading noted
here and in [docs/SPEC-FEEDBACK.md](docs/SPEC-FEEDBACK.md) ("Open from v0.82").

**Upgrading.** Do these in order. An upgrade from before v0.27.0 does v0.27.0's steps as well.

1. **Before upgrading, namespaces raised to end-to-end by an earlier draft** are handled as in
   v0.27.0 (its Upgrading 1): the server refuses to start on a database holding one, or a
   remote branch of such a source, and `patchlog serve -purge-raised-e2e` purges them. v0.82
   now says a deployment may refuse or discard such data ("Reading this spec"). The check runs
   before every migration and cleanup of this release.
2. **Before upgrading, have identity grants allow `read` in the catalog namespace** where they
   are presented to a catalog service (a tree-derived catalog, the WebDAV gateway in gateway
   mode). The catalog service now answers `403` at `POST /read-grants`, and to any `want` at
   `POST /grants` that lists `read`, for a caller's grant that allows `read` nowhere it
   verifies in, which the reference judges in the catalog namespace (SERVICES §B.11.4 The
   caller's grant).
   - A grant with `can: []` is such a grant. Its user gets no read grants: through the gateway
     that user's files disappear from listings and `GET` and `COPY` answer `403`.
   - Have the identity provider issue grants whose `can`, or a role that counts for `read`,
     allows `read` in the catalog namespace. To keep such a grant from reading any node
     document there, scope the key or the grant with a rule that fixes `/resource` to a name no
     node has.
   - The same `403` goes to a grant with a block or key-scope rule on `/now`, whatever it
     wants, as in v0.27.0.
3. **Upgrade the origin, the services, the gateway and the playground together.** Three wire
   forms change, and mixed versions behave like this meanwhile:
   - A follower on SSE (`patchlog tree` or `patchlog index` started with SSE) against an origin
     of the other version fails on every sealed namespace event, since these moved to
     `pl { ns, event }`, and retries with backoff until both are upgraded. Long-poll followers,
     the default, are unaffected.
   - The `ancestors` answer changed shape. A v0.27.0 gateway against a v0.82 tree service
     answers `502` instead of judging a folder copy. The v0.82 gateway reads both shapes.
   - A v0.82 remote branch of a v0.27.0 source behaves as before (the source's tombstone `410`
     has no `last`). A v0.27.0 remote branch of a v0.82 source ignores `last`.
4. **At upgrade, migrations run.**
   - Core `017_filtered_gs_entry` and `018_filtered_gs_entry_after` add `entry` and
     `entry_after` to `filtered_gs` (5 below).
   - Index `011_edge_gs_keys_entry` drops and re-creates `edge_gs_keys` with an `entry` column
     and one row set per cookie (5 below).
   - Tree `006_v082_rejudge` resets every node's `born` epoch and has the epochs read in again
     (7 below).
   - Derived `003_v082_drop_sealed_views` deletes the stored sealed views of the tree service
     and the index. They are sealed again on demand, with canonical plaintexts and judged
     epochs, so a view at an unchanged `…/at/{at}/…` URL gets new bytes once.
   - At start the origin also deletes E3 snapshots stored away from their resource's
     horizon (an archive was restored, then a prune made at a lower revision), and for a
     resource with no horizon and several snapshots all of them, and logs the count. Their
     `/rev` then answers `404 not_offered` or `410 pruned` and readers fold from the log.
5. **Expect every `gs` cookie of the origin and every cookie of the index to be `403` until its
   reader exchanges the grant again.** The rows recorded before the upgrade name no key entry
   and vouch for nothing. At the origin a cookie from the new exchange can still be `403` when
   it expires no later than the last cookie issued for that `gs` before the upgrade, or before
   a later change to the key's entry: one from the same second, or from a grant that ends by
   then. That lasts at most a cookie's lifetime (15 minutes); the grant in `Authorization`
   reads meanwhile, and an exchange under a grant that lasts longer gets a cookie that holds.
6. **At upgrade, purge the CDN once,** as for v0.27.0, and for three more reasons: a
   tombstone's `/rev` body gains `last` under an unchanged immutable `ETag "{id}"`; tree
   listings at immutable `at` URLs change shape for `ancestors`, `where` and `subtree`; and
   sealed views are sealed again. Purge `ns:{ns}` for every namespace, or everything. Private
   caches can't be purged: a v0.82 client that meets a cached `410` without `last` falls back
   to the log, and a remote branch's creation that meets one answers `410 pruned`, as v0.27.0
   did.
7. **Expect sealed and end-to-end catalogs to list some nodes by name only for a while.** Until
   the tree service has read a node's epochs in again, the node is served without title and
   `born`, and its file metadata is `{"absent":"pending"}`. A release preview does more: its
   database held, for heads read through from the base, epoch numbers that were the base's, so
   at start it drops every node's epoch and `born` epoch and its stored listings and judges
   them again under the branch's keys. A head the tree service can't read for good stays by
   name only.
8. **Expect a purged catalog in an index database written by v0.27.0 to be repaired at the first
   start.** The database may hold the purge of a catalog it serves without that catalog's
   `catalog.trust`, so partial readers of the namespaces that trust it get `403` with no marker
   instead of reading them dark. On its first start, this version reads the trust again from the
   catalog's document at its purge-ns entry and records it, with no rebuild needed. A sealed
   catalog is the exception: the origin no longer serves its document (`410`), so it stays no
   catalog (`403`), which the index logs at each start, and a rebuild does not restore it.
9. **After upgrading, rotate each sealed (E2) namespace whose current epoch began before the
   v0.27.0 upgrade.** v0.27.0 seeded `seal_counts` from what was stored, which can't include
   sealings an earlier draft made and never stored (events, race losers), so the count of such
   an epoch may fall short of v0.82's "never under" (§E.2.1). New epochs are counted in full.
10. **Rebase remote branches whose source was raised to e2e after their `at`** (a source on an
   earlier draft). Such a branch served the content its source had at `at` sealed; it now
   answers `502 upstream` for it, for good (CONFORMANCE scenario 74). The change comes with
   the upgrade and purges no tag: purge `ns:{branch}` at the CDN and rebase the branch.
11. **Set `-expect-level ns=e2e`** (`client.WithExpectedLevel`) on tools and services for
    namespaces known to be end-to-end. The client keeps the highest level it has learnt only in
    memory, so on a first contact it can't detect a server or cache that claims a lower level
    (CLI, below).
12. **Files written before:**
    - A prune archive of an e2e namespace written before v0.82 has no `access` in its header.
      It reads as private content, and the importer refuses its sealed ops at step 1, so it
      can be restored but not imported.
    - A bundle exported from an e2e branch by v0.27.0 carries read-through lines, which every
      importer refused. Export it again.
    - An archive or bundle whose grant line disagrees with its `root` is rejected whole. The
      reference never wrote one.

**Security fixes:**
- **Tree service: a release preview is sealed under the branch's keys** (SERVICES §E.2.6
  Per-entry sealing, §B.5 Previews). v0.27.0 sealed a preview's listings under the base
  catalog's keys, with the base's epochs, so they opened for holders of the base's keys rather
  than the branch's, and a rotation of the branch cut no reader off. `kid` and `pl.ns` now
  name the branch, read-through entries included, and `view` keeps the URL as served. Stored
  epochs are judged again (Upgrading 7).
- **Origin and index: a cookie ends on any change to the entry of the key that verified its
  grant, or to the definition of a role it read through** (SERVICES §B.11.9 `gs`, §A.4 `gs`).
  In v0.27.0 an origin `gs` cookie ended only on a changed rule or `pub` or on losing `read`,
  so narrowing a key's `sub`, `groups`, `attrs`, `maxTtl`, `requireAt` or `can` left cookies
  reading until they expired; and the index never checked a `reads:{ns}` cookie, which read
  the namespace whole until it expired. Such a cookie is now
  `403`, and no other reader's exchange makes the origin or the index serve it again: the
  origin refuses a cookie that expires no later than the last one issued before the change,
  and the index records a cookie's keys once and gives a later exchange with other keys or
  entries another `exp`.
- **WebDAV gateway: a save whose reads fail writes nothing** (TOOLS §H.4 The base, §H.6). In
  v0.27.0 a failed read of the key history, of the user's identity or of the logs a save
  decides by counted someone else's entry as the user's own, so a save during a core outage
  could overwrite another user's write, or restore over another user's delete. Such a read now
  fails the save (`503` or `502`, below).
- **Tree service: a listing computed for one reader across a purge is not served** (SERVICES
  §A.1, §B.5). v0.27.0 guarded kept listings only: a listing that isn't kept (a reader's
  `problems` or `orphans`) computed from rows read before a purge was served once. It is now
  computed again, up to three times, then `503 behind`.
- **Client and playground: the highest encryption level learnt is kept, and plaintext under it
  is refused** (§7.1 End-to-end namespaces, Addendum E Levels). Before, both took the level
  from the namespace document or `/keys` as served, so a server or a cache that claimed a
  lower level could have a document served in the clear accepted. The Go client now holds the
  level per namespace in memory and the playground in `localStorage`; a lower claim is refused
  (`client.ErrLevelLowered`), and so is a plaintext `200` in a namespace held as e2e. The
  review of this work found that the playground's first level table took a level named after
  an `Object.prototype` member (`"constructor"`, `"__proto__"`) or a non-string (`["e2e"]`) as
  no lowering and then read a plaintext `200`; that was fixed before any release, and a level
  is now one of `none`, `at-rest`, `sealed` and `e2e` or it is refused.
- **Playground: a listing shows a title, `born` or hit value only from a sealed value that
  opened** (SERVICES §E.2.6 Per-entry sealing). In a listing, `ancestors`, `where` answer or
  search result sealed per entry, the playground merged an opened value over the cleartext
  beside it, so a node whose sealed value was absent, did not open or had no title was shown
  with its cleartext title, unmarked. Cleartext copies beside such a sealed value are now
  dropped, so those entries show by name only. This was found in a second, scoped review before
  release.
- **Playground: an entry's own sealed value must be of the namespace being read** (SERVICES
  §E.2.6 Values of another resource). The playground opened an entry's value under whatever
  namespace its `kid` named. It must now be of the catalog or namespace being read (or of the
  entry's `href` namespace), or of a confirmed branch of it; a value sealed for another
  namespace is refused.
- **Playground: an entry's `branch` counts only for a branch of the item's namespace**
  (SERVICES §B.5 Previews, §E.2.6). An entry's cleartext `branch` stood for its item's
  namespace with nothing behind it. It is accepted only when that namespace's own document
  names the item's namespace as its base; otherwise the value is refused.
- **Playground: a nested sealed value that stands for its entry's own is opened only for the
  namespace being read** (SERVICES §E.2.6). A nested sealed value that stands for its entry's
  own (a `born` in place, a `file`) is opened only if sealed for the namespace the answer is of
  (or the entry's `href` names) or a confirmed branch of it, also where the entry's own sealed
  value is absent or didn't open. A `{ "sealed" }` that hangs on no entry is opened only if of
  the answer's namespace or a branch of it.
- **Playground: a JWE's `kid` and `pl` are checked before any request** (§3.6). The namespace
  of a JWE's `kid` and the resource name of its `pl` are checked against the §3.6 grammar
  before any request or key lookup, so a service-supplied header can't steer a credentialed
  request to another path.
- **Playground: a lower level in a namespace document is not accepted as the source of a
  branch's `base`** (§7.1, Levels). A namespace document naming a lower encryption level than
  this browser holds is not accepted as the source of a branch's `base`. Reading one listing
  asks at most once per namespace whether it is a branch.
- **Catalog service: a namespace the service stopped following reads public to no one**
  (SERVICES §B.5 Behind). The service judged `"public": true` at `POST /read-grants` from the
  document it had stopped at, so a public namespace made private by the write that stopped
  the service still read as public, as in v0.27.0. Its roles now count for no folder's
  visibility either.

**Sealed forms and the message bound** (§E.2.1, §E.2.2, §7.3, §G.5.1.1):
- A sealed namespace event is sealed under `K_n` with `pl { ns, event: id }`
  (`seal.NamespaceEventPL`), at each serve and never stored; every serve counts against the
  bound. Clients refuse the v0.81 range form with no fallback, and a range reader refuses an
  event's JWE. A resource stream's `purge` and `prune` events keep `pl { ns, name, kind }`.
- Sealed bundles: the writer refuses, and a reader rejects whole, a line numbered 2³² − 1 or
  more, so `K_b` stays under the bound.
- Derived views: every sealed plaintext is canonical JSON, in the tree service and the index
  (SERVICES §E.2.6 What gets sealed).
- Already as v0.82 fixes them, now pinned by tests: a stored count never falls below the
  sealings made; the origin's own rotation entries carry no `grant` and no `via`, with
  authentication disabled too, and a frozen namespace is rotated; a keyring's `$nonce` is new
  on every write.

**End-to-end reads and remote branches** (§7.1, §E.3.1, §G.3, §G.5.2):
- `GET` and `HEAD /r/{ns}/{name}/rev/{T}` of a tombstone answer `410` with
  `{ "code": "gone", "tombstone", "last" }`, `last` its parent, at every level and below a
  horizon, after the read check. `ETag` and cache class are unchanged (Upgrading 6). The
  `/raw` form in sealed and end-to-end namespaces stays `404 not_offered`.
- `PruneE2E` takes a tombstone horizon's parent from that `410` and refuses a `last` that
  isn't the parent; against a server or cache without `last` it finds the parent in the log as
  before.
- A stored E3 snapshot is served until a purge or a later prune that moves the horizon, to a
  lower revision too. v0.27.0 kept serving a tombstone snapshot at its parent after the
  horizon had moved.
- A remote branch of an E3 source pruned at a tombstone that is the resource's head at `at`
  can now be created: B learns the parent from A's `410` and mirrors the snapshot. A `last`,
  `pl.id` or `kid` that doesn't fit is `502`. Creation was `410 pruned`.
- A remote branch whose source is raised to e2e after `at` answers `502 upstream` for
  everything the source had at `at`, though the branch itself follows to sealed (Upgrading 10).
- Go client: the walk of an e2e branch's bases follows the whole local chain, so content
  sealed in a base's base is read through; it stopped at the first base.

**Access at the origin** (§C.4, §2.1, SERVICES §B.11.9):
- A `gs` cookie ends on any change to its key's entry or a read role's definition (Security
  fixes). Long-poll and events judge it at the current checkpoint. A cookie for `/ns/{ns}`
  read at a `gs` URL is held to the same.
- A trusted catalog that is a remote branch keeps a namespace covered and makes nothing
  visible: a partial reader gets filtered `/heads` with no rows, a log with config and
  `purge-ns` entries only, and a gestures listing without hidden resources. It got `403`
  before (scenario 119).
- A purged covered namespace: a partial reader's unfiltered `/heads` is `410` directly, with
  no `302`; at its filtered `/heads` an unrestricted reader's grant is `403`, as at a live
  namespace's, where it was `410` (scenario 124).
- A key's `requireAt` refusal is `403` with the one text `at rejected by requireAt`, whether
  the namespace doesn't exist, `at` isn't in its chain, is beyond `maxLag`, names another
  namespace or is malformed. It named the namespace before.
- Grant verification checks a key's `sub` scope before `maxTtl` (§C.2 item 3).
- Unrestricted `read` leaves out roles with a rule on `/now` at its source (§2.1); no
  behaviour changes.
- Already as v0.82 fixes them, now pinned by tests: a public namespace ignores any grant,
  `POST /keys` excepted; a malformed `{gs}` or `{at}` is `400 bad_input` before
  authentication; an `Authorization` field that isn't `Bearer` is a malformed grant (`401`).

**Services** (SERVICES §A.1, §A.4, §B.5, §B.11.2, §B.11.4, §B.11.9, §E.2.6):
- Tree service: `ancestors` and `where` answer `paths` as arrays of node names from a root
  down to the node itself, with each node's `href` and `title` (or `sealed`) in a top-level
  `nodes` map keyed by name; `tooDeep` and `truncated` are top-level booleans, on `subtree`
  too (§B.5 Shared nodes in DAGs).
- Tree service: nothing is sealed from a revision whose epoch isn't judged. Such a node is
  listed by name only until its head is read again, and a head read without a `kid` is read
  again rather than judged as the epoch in force (§E.2.6 Per-entry sealing). While a
  database's epochs were still being read in, v0.27.0 sealed such values under the current
  epoch. In an e2e catalog a head the service can't read for good is never judged.
- Tree service: a preview service that lacks the branch's keys answers `404`, as for any
  catalog whose keys it lacks.
- Tree service: at `POST /edge-grants` an unreadable `requireAt` chain is `503` only if every
  cause is transient, else `502`; a rejected `at` is `403`, naming no namespace (§C.5.2,
  §C.4).
- Tree and catalog services: a namespace the service stopped following counts for no folder's
  visibility, so filtered listings may lose folders visible only through such a namespace's
  role (§B.5 Behind).
- Catalog service: `POST /grants` and `POST /read-grants` answer `401`, then request-shape
  `400`s, then the `403` (`no-store`) for the caller's own grant, before the `?min` wait and
  any `404`, `409`, `410` or `503` (§B.11.4 The caller's grant; Upgrading 2).
- Catalog service: a read `want` keeps no content role that has a rule on `/now` or on the
  whole envelope; with none kept the answer is `403`, and a mixed want keeps its other verbs
  (§B.11.2).
- Catalog service: a `502 upstream` says what the service couldn't read and no longer relays
  the origin's error text, which is logged.
- Index: cookies are recorded per key set. Readers through different keys, or through one key
  before and after its entry changes, don't share a cookie, and a change to one key ends only
  the cookies minted through it. A cookie's `exp` may be a few seconds earlier than the
  grant's `exp` or the edge TTL would give; where no second is left before the grant expires,
  `POST /edge-grants` answers `503 behind` with `Retry-After`.
- Index: on a purged namespace a cookie that had ended, or was minted before this release, is
  `403` instead of `410` with the purge's head (§8.5).
- Index: a trusted catalog that is a remote branch counts for coverage and makes nothing
  visible: a partial reader gets `200` with no hits instead of `403`.
- Index: started after a trusted catalog was purged, it marks the catalog purged, so the
  namespace is covered and dark. Before, a partial reader got `502` for good and the
  catalog's follower restarted in a loop, in v0.27.0 too.
- Index exchange: with several unreadable `requireAt` chains or namespace documents the
  answer is `502` if any failure is lasting and `503` only if all are transient, whatever the
  order of the grants; and `404 not_offered` follows what the origin's `GET /` says now, not
  what it said at the first exchange (§B.11.9 Where).
- Index: nothing is sealed from a revision whose epoch isn't judged; a result that met one is
  computed again, or `503 behind`.
- Already as v0.82 fixes them, now pinned by tests: a grant at an all-public listing of the
  tree service, or at a public query of the index, gets the anonymous answer, while a public
  catalog whose listing isn't all public still answers a grant with a rule on `/now` `403`;
  the authentication mode is never taken from an
  earlier read that has since failed; a branch of a branch of a covered namespace gets no
  marker.
- Index: a purged catalog the index serves keeps the `catalog.trust` it read. Stopping the
  follower for visibility that stood in until the index reached the catalog no longer forgets
  the trust the index's own follower recorded, and a catalog met purged from a snapshot has its
  trust read at its purge-ns entry. A partial reader of a namespace that trusts it reads it
  covered and dark (a `g:` marker, no hits) rather than, depending on timing, `403` with no
  marker. The earlier answer failed closed (SERVICES §B.11.9 Where, §A.4). A database that already lost it is repaired at the next start (see Upgrading).

**Bundles, archives and the gateway** (§G.4.1, §G.5.1, §8.6, TOOLS §G.4.2, §H.4, §H.5):
- Bundles: a reader and a writer reject a bundle whose grant line's `grant` isn't the id of
  its `root`, or whose `stored` block doesn't decode or doesn't carry `canonical(root)`; no
  key or signature is needed. The exporter leaves such a grant off, with a note.
- Export: an `e2e` branch is exported from after its foreign parent. `requires` names the
  base's head, documents the branch never wrote are pinned in `external`, and the keyring
  comes whole. No read-through line is written. A `requires` before the foreign parent, or an
  `e2e` branch of a remote base whose document doesn't start with the branch's own line,
  refuses that document.
- Import: a pinned `external` is looked up in the target's chain where reading its revision
  can't answer: in an `e2e` target, which serves no document by revision, and for a pinned
  tombstone (`410 gone`) at any level. So an `e2e` branch's bundle imports into a same-named
  branch of a target holding the base, a base with a deleted resource included. A purged
  resource is still refused.
- Import: a bundle with a `sealed` op in a namespace its header doesn't call `e2e` is refused
  at step 1, override or not (Upgrading 12).
- Prune archives carry `access` in their header: `e2e`, else `sealed`, else `public` or
  `private` by `read`. Restore ignores it.
- Gateway saves: a failed read of anything a `PUT` decides by fails the save: `503` with
  `Retry-After` after the core's `429` or `503`, and `502` after its `408` or another `5xx`
  (v0.27.0 gave `503` for `408` and `502` for `503`). That covers the key history, the logs,
  the head of a new file's placement node, the reads of a restore by write, and `GET
  /ns/{ns}/principal` and the namespace document of every namespace the request asked about.
  A gateway-side timeout stays `503` with `Retry-After`. Requests other than saves answer as
  in v0.27.0.
- Gateway copies: a folder copy is judged from the tree service's `ancestors` in the v0.82
  shape and in v0.27.0's. A reported cut, missing `paths`, a path that doesn't end at the node
  or an unreadable shape is `403`, never `502`.
- Known limit: a flat `PUT` still falls back to tree settings learned with another grant when
  the catalog's settings can't be read for the moment, and fails only when none were learned.
- Already as v0.82 fixes them, now pinned by tests: a bundle member §G.4.1 doesn't define is
  rejected; a release branch grant fixed to base resources reads nothing else through the
  branch (TOOLS §F.8); a give-up is recorded nowhere and a later replay may take the rest
  (TOOLS §F.5, §F.6).

**Client and playground** (§7.1, §E.2.1, §E.3.1, SERVICES §B.5, §E.2.6):
- Go client: levels (Security fixes). Only the current namespace document and `/keys` teach a
  level; an unknown level string from a server while a level is held counts as lowered.
  `ErrLevelLowered` also comes from a base on an e2e branch's chain whose document names a
  lower level than the client holds. New: `client.WithExpectedLevel`, `client.ErrLevelLowered`,
  `APIError.Tombstone`.
- Playground: keeps levels per origin and namespace, with controls to expect and to forget
  one; counts sealings per resource key at E3 from the log and its own writes and refuses past
  2³²; reads the new `ancestors` and `where` shape.
- Playground: in a sealed or end-to-end catalog it opens each entry of the `nodes` map under
  the key of the node its map key names and compares `pl.name` with it; an entry that carries
  another node's value isn't opened. It refuses a nested sealed value drawn from another
  resource than its entry names. Where a listing entry of a release preview names a `branch`,
  a value drawn from its item must be that branch's resource, never the base's.
- Known limit (TOOLS §H.5, scenario 130): for a reader who sees a destination below the copied
  folder only through a chain of 65 or more inheriting folders, a `COPY` fails part-way (`403`
  at a nested level) after 64 resources are written, rather than writing nothing. Open with the
  spec writer.
- Known limit: the playground's Catalog tab still accepts a cleartext namespace document that
  names a lower level than held for the catalog and its trusted namespaces, and its other URL
  builders (reads of documents, logs, blobs, heads) put core- or service-supplied names into
  paths unchecked. The sealed-value path is checked.

**Test vectors** (Addendum I, `docs/TESTVECTORS.md`, `docs/VECTORS-PROPOSED.md`):
- The candidates the reference confirmed for v0.81, P.1–P.7, are now Addendum I
  §I.15–§I.21: plan digests, file renderings, sealed bundles, hostnames, sealed entries,
  documents and ranges, `via` lines and failing Biscuit tokens. They are checked against the
  values printed in `docs/SPEC.md` (`TestI15PlanDigests` … `TestI21BiscuitRefusals`); no value
  changed.
- The v0.82 candidates C.1–C.3 are all confirmed byte for byte through production code: C.1,
  the resource `purge` and `prune` events and the namespace event under `{ event, ns }`; C.2,
  the view string, both view keys, both JWEs and both padded tags, with the four altered
  `pl.view` forms rejected; C.3, three bundle rejections. Two remarks go to the spec writer:
  C.1's closing sentence says the resource events' `pl` is no longer accepted, against its own
  table and §E.2.2, and C.2 seals a whole response at a `gs` where §E.2.6 seals per entry.
- New cross-package tests cover sealed events over SSE to the tree service and the index, the
  gateway's folder copy over the real `ancestors` answer, scenario 119 at an origin and an
  index together, and a tombstone horizon pruned, mirrored by a remote branch and read back.

**CLI:**
- `-expect-level ns=level` (`at-rest`, `sealed` or `e2e`; repeatable) on `patchlog index`,
  `tree`, `merge`, `rebase`, `janitor`, `release` and `e2e`, beside `-keyring-sender`: the
  tool holds that level for the namespace from its first request, so a server or cache that
  claims a lower one is refused, and with `e2e` a document served in the clear is too. A value
  that isn't `ns=level` is an error.

## v0.27.0

Implements spec **v0.81** (previously **v0.77**). v0.78 cut four features and the special cases
for data written under earlier drafts: a namespace is end-to-end from its creation or never, a
`gs` holds all the caller's groups, filtered reads cover no branch, and a rule on `/now` never
passes for a read. v0.79 and v0.80 restructured and split the text with no rule changes. v0.81
settles the open items: a namespace key `K_n` and view keys, a message bound per key, and E3
reads the server never folds. `GET /` answers `"spec": "0.81"`. The upgrade was done in six
packages: encryption, end-to-end and remote branches in the core; access at the origin; the
grant checker, the tree service and the index; bundles, merges and the WebDAV gateway; the
`seal` package and the client; and derived views with the candidate vectors. A cross-review
then ported the playground, and a last package re-seals compressed sealings and takes the
playground's keys as the Go client does. The schema changes are the core's migration
`016_v081_encryption`, on SQLite and Postgres, and the derived-view cache's `002_v081_view_keys`
(SQLite, the cache of the tree service and the index). The tree service and the index have no
migration. Where the spec leaves a question open, the reference implements the reading noted
here and in [docs/SPEC-FEEDBACK.md](docs/SPEC-FEEDBACK.md) ("Open from v0.81").

**Upgrading.** Do these in order.

1. **Before upgrading, find namespaces raised to end-to-end by a config write**, and remote
   branches whose source was raised before their `at` (Addendum E Levels, v0.78). Their
   content from before the raise has no read path any more, and the E3 paths would serve it in
   the clear, so the server refuses to start on such a database and names each one.
   - No reference tool makes that content end-to-end: the bundle importer (v0.26.1 and this
     release) takes an e2e namespace only under its own name and no plaintext into one, and no
     reference client re-seals an import (§G.5.1's re-sealing import is a MAY).
   - To keep a copy, export each with the v0.26.1 tools. To keep it end-to-end, a key holder
     writes it into a new e2e namespace, with a third-party importer that re-seals it or by
     recreating the current documents with a client (`CreateDocSealed`). Then purge it, its
     local branches first. A remote branch is purged and created again against a source that
     is e2e from its creation.
   - Or start once with `patchlog serve -purge-raised-e2e` (`core.Options.PurgeRaisedE2E`).
     It purges them and their local branches at start, destroying their keys and content, and
     they answer `410 purged`. It records what it will purge before migration 016 drops the
     marker tables; a start that fails in between leaves the record, and the next start refuses
     until one with the flag finishes the purges.
   - Prune archives written for such namespaces hold plaintext revisions from before the raise,
     which a restore into an e2e namespace skips and an importer refuses for an e2e target. The
     files are the operator's and stay as they are.
2. **Before upgrading, migrate E3 keyrings in the format before v0.63** with the v0.26.1 client's
   `patchlog e2e migrate-keyring`. This release removes that command. `/keys` relays nothing
   from a keyring that isn't of the §E.3.2 form with a fresh `$nonce` or none, so its readers
   get no keys; the server lists such keyrings as warnings at start (§E.3.2, v0.78 Legacy).
   That includes a keyring of the §E.3.2 form whose `$nonce` was written before v0.76, which
   `migrate-keyring` doesn't rewrite. **After upgrading**, the next keyring write by a v0.81
   client mends one: `client.E2E` and the playground write a fresh `$nonce` in place of a
   stored one, so a key holder adds a reader (`AddReader`, even of a reader the keyring has) or
   rotates (`RotateEpoch`).
3. **Before upgrading, check rules on `/now` that apply to reads** (office hours, deadlines;
   §C.2 item 5). Read envelopes carry no `now`. A grant whose block or key-scope rule refers to
   `/now`, or to the whole envelope, is refused every read (`403`, or `404` at a resource URL
   of a private namespace). A role with such a rule doesn't count for `read`, and branching
   under such a grant is `403`. Writes are unchanged. Partial readers also lose filtered access
   to branches, and `/branches` is `403` for them (below).
4. **Before upgrading, note stored release plans** whose steps hold a `test` at `""` with a
   fresh `$nonce`: their digest changes, so they fail closed with `ErrPlanChanged`; plan and
   approve them again (TOOLS §F.9).
5. **At upgrade, migrations run.** Core `016_v081_encryption`:
   - drops `e2e_raises` and `remote_pending_sealings`;
   - deletes `sealed`, `blob_epochs` and `rev_epochs` rows of end-to-end namespaces (the server
     seals nothing at E3), and plaintext `snapshots` rows of purged namespaces;
   - deletes stored namespace log ranges, which were sealed under `K_e` and are sealed again
     on request under `K_n`, and grant rows keyed `{gid}` (before v0.73, already not served);
   - adds `kver` to `sealed`, `seal_counts` (the message bound, seeded from the stored
     sealings and reservations for unsealed revisions; the first start completes it), and a
     `reason` to `rotations_due`.

   Derived `002_v081_view_keys` deletes the stored sealed views, which are sealed again on
   demand, so a view at an unchanged `…/at/{at}/…` URL gets new bytes once.
6. **At upgrade, purge the CDN once:** `ns:{ns}` for every sealed or end-to-end namespace
   (namespace documents and grants were cached immutable under `K_e` bytes, and E3 fold
   redirects and `410`s carrying a snapshot were cached long); `r:{ns}/{name}` for E3
   resources, and for sealed namespaces' resources whose documents or log entries were stored
   compressed before v0.65 (sealed again, below); `idx:{ns}` for sealed sources' index views;
   and `ns:{branch}` for branches of covered namespaces (filtered branch ranges, at most 15
   minutes). Copies of namespace documents and of compressed sealings in browsers
   and private caches revalidate to `304` on their unchanged `ETag` and then fail closed in
   v0.81 readers (SPEC-FEEDBACK, Open from v0.81).
7. **After the first start, read its warnings:** keyrings `/keys` no longer relays (2 above);
   E3 prune snapshots answered `410 pruned` instead (below); and namespaces purged with
   `-purge-raised-e2e`, whose schema revisions other namespaces' `$schema` pins now resolve as
   purged (`422 schema_unavailable` for a write pinning one).
8. **Upgrade sources before their readers.** A v0.81 remote branch, client or tool can't open a
   v0.26.1 sealed source's namespace documents, ranges and grants, which v0.26.1 sealed under
   `K_e`: it fails closed with a decryption error (`seal: decryption failed`,
   `errors.Is(err, seal.ErrDecrypt)`).
9. **Expect the tree service's `at` to move once at deploy**, as stopped namespaces leave its
   combined checkpoint (Services, below): kept listings are judged again, and `g/all` cookies
   are `403` until exchanged again.

**Security fixes:**
- **Tree service: a listing's cache key counts only the namespaces its reader reads whole**
  (§A.4, §B.11.5). Between a namespace's stop and the purge of its listings, a `g/all` reader
  without `read` on it could be served listings kept from before the stop, with its items,
  heads and URLs; that window is new with this release's stopped-namespace rule (Services,
  below). A subject set's reader could be served the same way once a public namespace stopped,
  as already in v0.26.1. Kept and stored listings of the readers concerned are now computed
  again under their new keys, and are still purged by tag.
- **Catalog service: a grant on `/now` gets no read grants or keys** (§C.2 item 5, §B.11.5).
  `POST /read-grants` (read grants, and keys in a sealed catalog) and `POST /grants` refuse a
  grant whose block or key-scope rules refer to `/now`, or whose read roles all do: `403
  forbidden`, `no-store`, before `?min` and body errors, as the tree service refuses its
  listings. The catalog's API checked only the grant's identity, ignoring its block and key
  rules, as in v0.26.1; since a rule on `/now` no longer passes any read, ignoring it handed out
  what every other read refuses. `POST /merge-grants`, which issues write grants only, is
  unchanged.

**Keys and the message bound** (§E.2.1, §E.2.2, §E.2.6):
- `K_e` is only HKDF input. Namespace documents, namespace log ranges, long-poll answers,
  namespace events and grants are sealed under `K_n = HKDF-SHA256(K_e, "patchlog-e2", ns ‖ LF)`
  (`seal.NamespaceKey`); clients and bundle export derive it. `/keys` still hands out `K_e`
  or `K_r` only.
- Namespace documents and grants stored before v0.81 under `K_e` are sealed again under `K_n`
  of their stored epoch when first served, with the plaintext computed again; the old bytes are
  never served, and the `ETag` `"{id}.{e}"` stays the same. If that epoch's key is gone, the
  answer is `500`, saying the row was sealed under an earlier draft's key. Revision documents
  and log entries (`K_r`) keep their bytes, except those below.
- A sealed namespace's revision documents and log entries stored compressed (`zip: "DEF"`,
  before v0.65), which no v0.81 reader opens, are sealed again without compression at first
  read, under the same `K_r` and with the same `ETag`, the plaintext computed as for a new row
  (so a genesis entry gains `"parent": ""`). The re-seal counts against the bound. If their
  epoch's key is gone the answer is `500`, never the compressed bytes.
- The origin counts its sealings per key (`K_n` of an epoch, each `K_r`), reserving room for
  what a revision or namespace entry may still have sealed after its epoch ends. A request that
  would seal past the bound (2³²) is `503 behind` with `Retry-After: 60`, and nothing is
  sealed. A key of the current epoch reaching 2³¹ makes the namespace's rotation due, which
  the leader makes as `system:rotate`, frozen namespaces included. The thresholds are
  `core.Options.SealBound`, `SealRotateAt` and `SealBlock`; `serve` has no flags for them.
  Reading a sealed revision's document or entry draws on what its write reserved, so filled
  reservations never make it unreadable.
- Derived views (tree, catalog and index) are sealed under view keys,
  `HKDF-SHA256(K_n or K_r, "patchlog-view", view)`: a whole response under `K_n`, an entry or a
  value of another resource under that resource's `K_r`, `view` the request target exactly as
  the service's redirect gave it. Services take no key `/keys` relays without a keyring sender
  they trust, for any epoch of an e2e namespace (§E.2.6 Getting keys).
- A namespace event's sealed plaintext is the entry object itself, sealed at each serve and
  never stored.

**End-to-end namespaces** (Addendum E Levels, §7.1, §E.3.1, §G.5.2):
- A config write raising a namespace to `e2e` is `422 invalid`, by `PATCH`, batch or remote
  branch; a remote branch's raise is refused before its source is read. Raises to at-rest and
  sealed are unchanged. Everything for content from before a raise to e2e is gone, at E3 and in
  remote branches, and `…/blob/{bid}/e/{e}` at E3 is `404 not_offered`.
- **The server never folds.** `GET /r/{ns}/{name}/rev/{id}` serves a prune's stored snapshot
  (`200 application/jose`, immutable), and at a tombstone horizon serves it at the tombstone's
  parent. Any other revision that would be `200` is `404 not_offered` with `horizon`, and with
  `last` at a tombstone horizon, in the short cache class, for the reader to fold the log from
  `last`, else `horizon`, else genesis. The `302` with `X-E2E: fold`, the `410` carrying a
  snapshot and the `X-E2E` header are gone (CORS no longer exposes it).
- A prune at a tombstone horizon takes a snapshot bound to the tombstone's parent. A stored
  snapshot bound to the tombstone, or with a pre-v0.63 `pl` kind or `zip`, is never served: its
  revision answers `410 pruned` with `horizon` and `archive`.
- `/keys` relays only keyrings of the §E.3.2 form with a fresh `$nonce` or none (Upgrading 2).
- A remote branch of an E3 source pruned before `at` mirrors the source's stored snapshot
  verbatim (a strict compact JWE, size-capped, no redirect followed, `pl` and `kid` checked)
  and answers `/rev` from it; creation was `410`. Where that horizon is a tombstone that is the
  resource's head at `at`, whose parent the source names nowhere, creation is still `410 pruned`.
  A source raised to e2e rather than e2e from its
  creation is `502 upstream` at creation. A source's later raise to e2e is still followed only
  as far as sealed, recorded for a rebase.
- Export of an e2e namespace refuses a rev line that is neither the keyring's, one sealed op
  nor a restore's `[]`, naming it, and e2e namespaces no longer count as protected plaintext
  (§G.5.1 step 1).

**Access** (§C.2 item 5, §B.11.5, §B.11.9, §A.4):
- **`/now` for reads** (Upgrading 3). The refusal is part of the read check, so it comes before
  a purged namespace's `410`, `not_offered` and a partial reader's `302`, and it covers `/keys`.
  `POST /ns/{ns}/keys` is `403` for a grant whose read roles all have a rule on `/now`. The
  gestures listing's and the exchange's per-endpoint `/now` cases are gone; the gestures
  listing is `403` for a grant none of whose roles counts for `read`. In a public namespace the
  origin still ignores the grant, except at `/keys`.
- **A `gs` holds every `group:` of the caller**, its `sub` where a trusted catalog has a direct
  entry for it or the key is sub-scoped, the scope digest and the key subject; "deciding"
  groups and `"partial"` are gone, at the origin, the index and the tree service alike. So
  readers with groups no rule named get new subject sets, filtered URLs and prefixes once. A
  stored subject set holding `"partial"` is `403`: exchange the grants again (core
  `filtered_gs`, the tree's `edge_subjects`, the index's `g:` markers). The index's scope
  markers come only from roles that count for `read`.
- **Filtered reads cover no branch.** A branch's `/ns/{ns}/g/…` URLs answer `403` (`401`
  without credentials), a partial reader of a branch gets `403` at its unfiltered URLs with no
  redirect, `POST /edge-grants` issues no `/ns/{branch}/g/` prefix, and a partial reader's
  `/ns/{ns}/branches` is `403`. A trusted catalog that is a local branch makes nothing visible
  and is in no checkpoint, an `at` recorded earlier included. The index covers no branch either:
  a partial reader of one is `403`, and `/_refs` leaves it out.

**Services** (§B.5, §B.7, §B.11.5, §A.4, §E.2.6):
- Tree service: a grant whose block or key-scope rules refer to `/now`, or whose read roles all
  do, is refused (`403`) for listings, problems, orphans, manifests and the edge-grant exchange,
  in public catalogs too; anonymous public URLs are unchanged.
- Tree service: a namespace it stopped following (keys it lacks, a refusal) is out of the
  combined checkpoint, so a public catalog's listings stay anonymous-readable without it. Its
  self-placed nodes leave the graph meanwhile, and explicit placements of its items dangle as
  `"unfollowed"`; `problems`, `orphans` and `where` don't name them to readers without `read`
  on it. `at` moves on a stop and when following resumes, and a `g/all` cookie is `403` at an
  `at` the namespace re-entered.
- Tree service: an e2e namespace's `born` epoch ignores a `kid` the core serves.
- Index: a namespace raised to sealed whose keys the index lacks as configured answers `404`
  and shows as skipped in `/_status` at once, as after a restart, instead of `502`.
- Index and tree service: a namespace rotated between the service reading its encryption and
  asking `/keys` for that epoch's key is no longer judged to lack keys. Before, that stopped
  following it, purged its kept results and stored views, and could leave it unfollowed (`404`)
  until a restart; the check now reads the encryption again and judges by the current epoch
  (§E.2.3, §E.2.4, §A.4, §E.2.6). This was so before v0.26.1 too.
- Catalog service: the `/now` refusal at `POST /grants` and `POST /read-grants` (Security
  fixes, above).

**Bytes and tools** (§7.1, §7.4, TOOLS §F.3, §F.9, §H.5):
- A resource log entry always carries `parent` (`""` at genesis) and a namespace entry `prev`
  (`""` first), in clear pages, events and sealed plaintext. Genesis entries sealed before v0.81
  without `parent` are served as stored, and readers take an absent `parent` as `""`.
- A release plan's digest strips a fresh top-level `$nonce` only from an `add` or `replace` at
  `""` (Upgrading 4).
- Merge: a document referencing a blob a sealed op can't declare still gets no item and is
  offered again, now as a defensive check, as no e2e writer should produce one.
- Rebase: a keyring not in the §E.3.2 form, the namespace's own or its base's, is an error
  naming the namespace.
- WebDAV gateway: a folder that carries, sits under or holds `$access` is copied, and may be
  moved to another tree, each new folder made without `$access`; a move within a tree that
  widens access is still refused by the catalog service (§B.11.4 Copies). A reader who lists a
  tree through the tree service can copy a folder too; the copy is refused (`403`) into the
  folder itself or below it as that reader sees the tree, `403` when the service's `ancestors`
  answer is cut short, and `503` while the service hasn't caught up with the user's writes.
  Such a reader still can't delete a folder or move one to another tree (`403`).
- Already as v0.81 fixes them, now pinned by tests or vectors: every production IV is random;
  prune archives carry no closure and no `external`; a bundle with authorship members and
  without `"authors": true` is rejected; Biscuit symbols are judged unused per block; A-labels
  match in any case; a plan digest's `release` is `/r/{ns}/{name}/rev/{id}`.
- Test vectors: every candidate in `docs/VECTORS-PROPOSED.md` (P.1–P.7) is confirmed through
  the reference's code; `docs/TESTVECTORS.md` gains I.7's `K_n` and I.13's grant under `K_n`.

**Client and playground** (§7.1, §E.2.1, §E.2.2, §E.3.1, §E.3.2):
- E3 reads: `client.E2E` opens `/rev/{id}`'s `200 application/jose` as the stored snapshot of
  `id`, and on `404 not_offered` folds the log up to `id` from `last`, else `horizon`, else
  genesis. It no longer follows a fold redirect or reads a snapshot from a `410` body. Any
  other `200` for a resource of an e2e namespace is refused (`seal.ErrMismatch`).
- `PruneE2E` at a tombstone horizon, mid-chain included, binds the snapshot to the tombstone's
  parent, checked against the tombstone however it was learned, and re-pruning at the current
  tombstone horizon works. Snapshots are sealed under a trusted key of the pruned namespace.
- No compatibility with earlier drafts (v0.78): `pl` must match exactly, so the pre-v0.63
  snapshot and namespace-document `pl`s are refused; a JWE with a `zip` header doesn't open
  (`ErrFormat`), though its header still parses for `ETag`s and detectors; patch sets and
  snapshots open under `K_r` only, so one sealed under `K_e` (or with `zip`) is flagged and
  folded as `[]`; keys wrapped under the pre-v0.63 info, keyrings in the format before v0.63
  and keys relayed without a sender no longer open. Namespace events are opened as the entry
  object; the pre-v0.73 sealed `purge` and `prune` event form is refused.
- Keyring writes (`InitKeyring`, `AddReader`, `RotateEpoch`, and the playground's Add reader
  and Rotate) carry a fresh `$nonce` where the keyring read has one, never the stored one, and
  none where it has none (§E.3.2, §C.7). A keyring whose `$nonce` was written before v0.76 was
  copied with it and refused (`422`), so such a namespace could neither add a reader nor
  rotate (Upgrading 2).
- Message bound: the client counts sealings under each resource's `K_r` per epoch, from the log
  (read once per process, on its first sealing for the resource) and its own writes. It
  reports when rotation is due (`E2E.SealStatus`) and refuses a sealing past the bound
  (`ErrSealBound`). A count it can't complete (below a pruning horizon, a log it can't read or
  verify) is marked partial, and a margin of 2³¹ stands for what it can't see.
- Playground (the browser client `patchlog serve` hosts): opens namespace documents and log
  ranges under `K_n` and views under view keys; at E3 reads a prune's stored snapshot or folds
  the log on `404 not_offered`, without `X-E2E`; refuses an e2e document served in the clear
  (where it knows the namespace is e2e), `zip` JWEs and namespace documents sealed with the
  pre-v0.63 kind `"config"`; flags patch sets not sealed under `K_r`; and wraps `K_e`, never a
  derived key, when adding a keyring reader.
  The History tab reads a pruned resource's log from its horizon, at E3 from the fold's start.
- Playground: keys are taken from `/keys` and the keyring as the Go client takes them: at E3
  only keyring entries from a known sender, nothing from a keyring in the format before v0.63 or
  under the pre-v0.63 wrap info; at E2 no relayed keyring entry. A grant that can't read the
  namespace document uses the level `/keys` names.

**CLI:**
- `patchlog serve -purge-raised-e2e` (Upgrading 1).
- `patchlog e2e migrate-keyring` is removed: it exits with an error pointing to the v0.26.1
  client. Error messages (the core's `422` for a keyring in the format before v0.63, the bundle
  importer's refusal of one) no longer advise it as if this version had it.
- `patchlog e2e seal-status -api URL -ns NS -name NAME [-bearer T] [-json]` reports a
  resource's `K_r` count, whether it is partial, and whether rotation is due.
- `patchlog serve -remote-origin-url` no longer has any effect: it only told where to read the
  start times of a source's epochs from before its raise to e2e. It is still accepted, so
  command lines keep working, and a start with it logs a warning. `core.RemoteEndpoint.OriginURL`
  is removed.

## v0.26.1

Security release. A review of v0.26.0 found leaks in the tree service and the search index
(most of them also in v0.25.0), a way for a hostile remote base to stall every remote branch
on a server, and vulnerable dependencies. Still implements spec **v0.77**. The schema changes
are the core's migration `015_remote_pending_backoff` (backoff for pending pre-raise sealings;
it also deletes rows earlier purges left), on SQLite and Postgres, safe in a rolling upgrade,
and the index's migration `010_ns_stopped` (namespaces it can't follow, and the checkpoint it
purged them at).

**After upgrading, purge your CDN.** Listings and query results computed before a narrowing
(a namespace made private, or raised to sealed or end-to-end) could be served after it with
`Cache-Control: public, immutable`, and the services never told the CDN. For every catalog
that was, or trusts a namespace that was, made private or raised while v0.25.0 or v0.26.0 ran,
purge the tag `ns:{catalog}`; for every namespace made private or raised, purge `idx:{ns}`.
Do the same by hand when a tree or index database is created from scratch (not `-rebuild`)
for catalogs an earlier instance served. Copies already in browsers (up to `max-age=86400`)
can't be recalled. The services' own kept results are in memory and go at the restart.

**Changes to check before upgrading:**
- **A namespace just made public reads public only once the service has applied the change.**
  The tree service and the index now take a reader as public only if the namespace is public as
  they have applied it *and* per its current namespace document (and, in the tree, the service
  can follow it). Until a widening is applied, anonymous readers get `401`; grant holders read
  by their grant; an anonymous `/_refs` leaves the namespace out. Databases from v0.26.0 seed
  their applied read modes from the documents at their checkpoints.
- **A namespace the tree service or the index can't follow is stopped.** One it lacks keys
  for, or that refuses it (`401`, `403`, or `404` on both its log and its head), also when
  met while applying a batch, is marked stopped and its cached results purged (`ns:{ns}`,
  `idx:{ns}`, once per checkpoint): it reads public to no one until the service follows it
  again, and a stopped catalog answers `404`. A stopped trusted namespace makes its catalog
  non-public meanwhile.
- **Remote branches:** each remote origin gets one `-remote-follow-timeout` (new flag,
  `RemoteOptions.FollowTimeout`, default 10 minutes) of its own time per sync for all its
  branches; branches that don't fit wait for the next sync, and branches are followed in a random order. Creating
  a remote branch is bounded by the same timeout (`502 upstream` if the base doesn't answer in
  time). No request to a remote base follows redirects; a `3xx` is the base's answer.
- **A canceled `requireAt` check** answers `503 behind`, not `502 upstream`.

**Security fixes:**
- **Tree service: a narrowing now purges.** A config entry that makes a catalog, or a namespace
  it trusts, private, or raises it to sealed or end-to-end, purges `ns:{ns}`: kept and stored
  listings, the service's CDN purge and the queued second purge. Before (v0.25.0, v0.26.0), a
  listing computed in the clear before the change was still served at its `at` with
  `public, immutable` caching, to anonymous readers. The same now holds for a narrowing the
  service can't apply (keys it lacks, a refusal), one made while it was down followed by
  `-rebuild`, a snapshot bootstrap, and an untrust (with or without edge grants).
- **Tree service: a change mid-listing can't leak.** A listing reads the catalog's encryption,
  its file metadata's sealing and who reads public again once it has read the graph, before it
  judges, keeps or serves anything. A raise, rotation or narrowing applied meanwhile can no
  longer have it served in the clear, kept as public, or sealed under the replaced epoch. (The
  v0.26.0 fix for this only narrowed the window.)
- **Index: a namespace being made private is no longer served as public.** The index tells its
  grant checker about a config change before it purges, and checks the reader's access again
  just before it keeps a result; a result could otherwise be kept and served under the public
  URL with `public, immutable` caching, including documents written after the change. A
  revoked grant is refused the same way. After a snapshot restart (`follow.WithSnapshot`), a
  namespace narrowed while the index was down has `idx:{ns}` purged.
- **Index:** a key rotation that lands while a query seals its results no longer leaves pending
  documents sealed for good under the replaced epoch; a purged catalog's outdated
  `catalog.trust` (after a snapshot rebuild, or for a catalog no longer served) no longer makes
  a namespace count as covered (an empty answer where `403` is owed; no content was exposed).
- **Grant checker:** a namespace-document load that a follower's notice overtook is no longer
  cached for the TTL; a grant whose `requireAt` `at` is in no chain no longer makes every check
  read the chain's heads again (once per namespace at a time, at most once a second, shared).
- **Remote branches (a hostile base):**
  - Log pages for pending pre-raise sealings must advance through the mirrored chain
    (`X-Log-Next` must name an entry on the page, after its `since`); before, one base could
    page a sync forever and stop every other remote branch from following its base's purges.
  - A `410 pruned` horizon is final only if it is a revision of the mirrored chain strictly
    after the content (for a blob epoch, after every revision referencing it under that epoch;
    a tombstone horizon doesn't prune the last live document before it); one past the branch's `at` is accepted only if the base's log from the
    branch's head verifies, and is retried with backoff rather than final. Before, any horizon
    string was stored and served for good. Rows written by other versions are rechecked.
  - Sealings must be strict compact JWEs, opened and verified, and are bounded by the size of
    the content mirrored; before, a base could make a branch store and serve copies padded to
    about 1 GiB. Reads are capped by kind (log page, sealing, blob, error), settled row by row.
  - No request to a remote base follows redirects (before: a blind SSRF at every sync, and the
    branch's grant forwarded to other ports on the base's host); a sealed blob's redirect is
    followed only to `…/blob/{bid}/e/{n}`.
  - Purging a remote branch's resource or namespace deletes its pending-sealing rows and the
    shadow's stored copies of the base's sealings. Pending sealings back off (1 minute doubling
    to 4 hours, at most 64 per branch per sync). A blob pruned under one epoch no longer
    answers `410` under another.
- **Dependencies:** `golang.org/x/net` v0.60.0 (GO-2026-6603, -6611, -6612, -6617: HTTP/2
  server denial of service) and `github.com/klauspost/compress` v1.20.2 (GO-2026-6865: a zstd
  panic).

## v0.26.0

Implements spec **v0.77**: its answers to the reference's notes on v0.76. `GET /` answers
`"spec": "0.77"`. The upgrade was done in five packages: the origin's filtered reads and remote
branches; the search index; the grant checker and the shared client and follow libraries; the
tree and catalog services; and undo, rebase and the WebDAV gateway. The schema changes are the
core's migration `014_remote_pending_sealings` (sealings of pre-raise content a remote branch
still has to fetch from its base), on SQLite and Postgres, and the index's migration
`009_catalog_trust` (the last `catalog.trust` it applied for each catalog). Where the spec leaves a question open,
the reference implements the reading noted here and in
[docs/SPEC-FEEDBACK.md](docs/SPEC-FEEDBACK.md) ("Open from v0.77").

**Changes to check before upgrading:**
- **A `requireAt` chain a service can't read is an outage, not a refusal** (§C.4 requireAt,
  §12.1). The index, tree and catalog services, and the grant checker they share, answer
  `503 behind` (with `Retry-After`) while the cause is transient and `502 upstream` otherwise,
  with a fixed message that names no namespace, instead of `403 "at rejected: namespace …"`. It
  covers a failing `/keys` or namespace fetch, a target namespace answering `404` or refusing the
  service, an unreadable log (a stored range sealed under an epoch whose key `/keys` doesn't
  give the checker, say), and a purged namespace in the chain, for listings, `POST
  /edge-grants` and the catalog's `POST /grants`, `/read-grants` and `/merge-grants` alike. The
  chain is reported even where a later check would have refused. A grant whose `at` is newer than
  the service's cached head of the `requireAt` namespace makes it read the head again, instead
  of being refused as "not in the chain".
- **`408` is transient everywhere** (§A.4, §12.1). The shared client, read-through chains, key
  fetches, the index, the tree and the catalog retry a `408` from the origin or from `/keys`; it
  no longer leaves keys lacking for good or a namespace skipped.
- **A purged catalog keeps its namespaces covered** (§B.11.9 Where). Like an end-to-end catalog
  it makes nothing visible, so partial readers keep their `/g/` URLs and edge-grant prefix and
  see only config and purge entries, instead of `403`. A branch's head-trust check skips such
  catalogs as it skips end-to-end ones. `/ns/{ns}/g/{gs}/heads`, with or without `at`, of a
  covered purged namespace answers `410 purged` with `head` to a grant that reads it
  unrestricted, as §8.5 answers `/heads`, where it answered `302`, or `403` for a purged catalog.
- **Index scope cookies bind their key** (§A.4 Across namespaces gs). A
  `reads:{ns}:scope:{digest}` marker digests the key's `key:` string too, so readers through two
  keys with the same rules get different `gs`, cookies and prefixes. Older scope cookies are
  `403` until the reader exchanges again, as is one whose key is gone, no longer lists `read`
  or has another `pub`, or whose role is gone or no longer lists `read`.
- **The index gives no marker where §B.11.9 doesn't cover a catalog** (§A.4). A namespace that
  is not sealed or end-to-end and is a catalog, or whose `catalogs`, or a local base's, names
  one, gives a partial reader no marker: `403` there and no hits at `/_refs`, never hits
  filtered by rules alone, and its scope cookies are `403`. Nothing is covered while the core's
  root says authentication is disabled.
- **Edge-grant exchange at the index answers `410` more strictly** (§A.4 Coverage, §C.5.2).
  `410 purged` only where every namespace the grant names is followed, purged and verifies the
  grant; otherwise `403`, or `401` if a refusal was. `/_refs` answers `410` the same way when the
  grant would see no namespace at all.
- **Redirects drop an opaque `after`** (§A.4, §B.5). A redirect from the head pointer, or to
  another `at`, drops a position (`q`, a sort position, a children listing's `after` or a
  `next` carrying one), and the listing starts again; a redirect at the same `at` keeps it.
  Clients follow `next` at the page's `at` URL.
- **Undo widens as merges do** (§11.2 The inverse, The guard; §F.3). A gesture's writes and the
  later writes the guard compares are widened to the whole outermost array holding a write whose
  last segment indexes an array, or appends with `-`, judged before or after its op; undo cut to
  the immediate parent array before. An object member named `-` is no longer widened, in merges
  either (`pointer.WidenArray`).
- **Rebase Switch waits for every change** (§F.5 Switch, §F.6). Switch stops until every resource
  the old branch changed is recorded in the successor, apart from §F.6's exceptions (resources
  purged in the old branch, the keyring at E3), or a person gives the rest up. That includes a
  resource purged only in the successor and, under a limit to some resources
  (`RebaseOptions.Plan.Resources`), every resource outside it; the catch-up after the freeze
  replays all resources changed since the first replay, not only the limited ones, and reports
  what it leaves unrecorded on the same terms (`merge.Plan.Unrecorded()`). A stopped switch names
  the resources and the flag below.
- **WebDAV gateway: a failed read is never a `409`** (§H.4, §H.6). A save over someone else's
  delete that can't read the file's last revision, or the tombstone's log entry, because the
  read failed (a timeout, `408`, `429`, `5xx`, a failing key fetch, or the identity read that
  decides whether the delete was the user's) answers `503` with `Retry-After` (`408`, `429`,
  timeouts) or `502` (`5xx`, core unreachable) and writes nothing. The core's `408` and request
  timeouts now map to `503` instead of `502` in every answer.

- **`gs` values change** (§B.11.9 gs). The `scope:{digest}` subject of a filtered read's `gs`
  is now §A.4's marker digest, which includes the key's `key:` string, at the origin and the
  index alike. A `g:` cookie the index issued before is `403` until the reader exchanges again.

**New:**
- Remote branches of end-to-end sources raised from sealed (§G.3 Creating one, §G.5.2):
  - B no longer stores a source sealing of pre-raise content it hasn't opened and verified.
  - Creation is `422 invalid` where the endpoint's grant gets no key of an epoch such content is
    sealed under, whether A's `/keys` refuses or omits it. A `408` or `429` from the base,
    from its `/keys` too, is no refusal: `502 upstream` at creation, retried by the follower.
  - A sealing A doesn't serve at creation (refused, `410`, or a transient failure) no longer
    fails creation or stays `502` for good: it is recorded as pending and fetched again at every
    sync. Once it opens and verifies, B stores and serves A's bytes; until then the URLs needing
    it answer `502 upstream`, or `410 pruned` with A's horizon once A says so.
  - A resource log A answers `410 pruned` from genesis no longer marks every pending entry
    pruned: B asks for each entry in its own range (`…/rev/{id}/log?since={parent}`) and records
    it as pruned only if A answers that range `410`, at creation and at every sync.
- Tooling: `patchlog rebase -switch -leave-out` and `patchlog merge release rebase -leave-out`
  (`RebaseReleaseOptions.LeaveOut`) switch anyway and print what was given up.
- Index, §B.11.9 and §A.4:
  - A purged catalog that a namespace names through a `requireAt` key keeps it covered with
    nothing visible, so partial readers get a `g:` marker and no hits.
  - A base that branches read only as of different `at`s is listed in `/_refs` `namespaces` at
    the earliest in its chain.
  - A namespace raised to sealed while a query of it was being computed no longer has a cleartext
    result kept and served after the raise, and the head pointer no longer keeps a result
    computed under the encryption a raise replaced (§A.1, §9, §E.2.6).
  - The core's root (`GET /`, which says whether authentication is on) is read only for
    namespaces §B.11.9 could cover. A transient failure is `503 behind` with `Retry-After`,
    others `502`; neither names a namespace.
- End-to-end epochs (§E.2.6, §E.3.1): where a value's snapshot would carry the epoch in force
  (a base's op read through, a revision in the clear from before a raise), the first listing or
  answer that seals it judges the epoch once, which is stored and kept across rotations and
  restarts, at the tree service and the index alike; a node's `born` and head from the same
  revision share it. Whether a revision's op is the namespace's own is told by the op's `pl.ns`,
  not by its kid's namespace; a base's op read through is "not known" for derived views, and
  the client gives no epoch for an own op whose kid names another namespace.

**Fixes:**
- Index: a query whose result lost to a purge is computed again, with the read check,
  checkpoint and encryption read after it, or answered `503 behind`; `/_refs` computes its views
  again before retrying (§A.1). A `503 behind` for a namespace visibility reads but hasn't
  reached yet no longer names it.
- Index: a `/keys` or schema-revision `408` is transient (`503 behind`, retried), no longer a
  missing key or an untyped document.
- Tree service: a grant whose `requireAt` chain can't be read because a namespace in it is
  purged gets `502 upstream` for a listing and for `POST /edge-grants`; a sealed or end-to-end
  catalog answered `403`, taking the chain's purge for the catalog's own.
- Tree service, end-to-end catalogs: while a database's head epochs are still being read in,
  listings judge no epoch and listings stored meanwhile are dropped when the fill finishes; a
  pending `born`'s epoch is judged once even if the node's head changes while it is recorded.
  An own op's value is no longer kept under the epoch in force instead of its own kid's.
- Rebase: a change outside a resource limit that lands just before the freeze is no longer
  left only in the frozen branch with `merge.ErrLeftOut`.
- WebDAV gateway: a core request that times out or is cancelled is answered `503` with
  `Retry-After` (§H.4 Answers).
- Tree service: a listing is never computed, kept or served under the catalog's encryption as
  it was before a raise to sealed or end-to-end that applied while the listing was being
  computed. Before (also in v0.25.0), such a listing could show titles, born dates and nodes
  written after the raise in the clear, and keep them, immutable in a public catalog. A listing
  read before a purge of what it shows (§A.1) is no longer served either: it is computed again,
  and if it keeps losing to purges the answer is `503 behind`.
- Index: a purged catalog counts for a namespace's coverage only if the last `catalog.trust`
  the index applied for it listed that namespace, as at the origin (§B.11.9 Where); a catalog
  whose documents the index never applied counts as no catalog.

## v0.25.0

Implements spec **v0.76**: v0.75's filtered namespace reads for readers a catalog limits
(§B.11.9), and v0.76's answers to the reference's notes on v0.75 and v0.74. `GET /` answers
`"spec": "0.76"`. The v0.75 upgrade was done in five packages: the visibility engine of
filtered reads and the edge grants for them; `GET /ns/{ns}/principal` roles and the Go client;
the origin's filtered routes, `?prefix=` on `/heads`, the gestures listing and `/branches`; the
tree and catalog services; and the search index. v0.76's was done in six: the origin's filtered
reads; the index's coverage, markers and exchange; deciding groups, the catalog and the tree
service; encryption and remote branches; merges and the janitor; and the index following the
namespaces visibility reads. The schema changes are the core's migrations `011_filtered_reads`
(`filtered_gs`, the subject sets edge grants were issued for, and `filtered_ats`, the
checkpoints filtered URLs were minted at, kept 7 days), `012_filtered_gs_pub` (the `pub` of the
key each subject set came from) and `013_remote_chain_read` (whether an E3 remote branch last
read each deeper base's namespace document), all on SQLite and Postgres, and the index's
`005_edge_gs`, `006_edge_gs_pub`, `007_edge_gs_keys` (every key a `g:` marker's live cookies
came from) and `008_member_checkpoints` (the checkpoints of the namespaces it follows only for
visibility). The tree service's schema is unchanged; its first start refills `born` epochs once
(below). Where the spec leaves a question open, the reference implements the reading noted here
and in [docs/SPEC-FEEDBACK.md](docs/SPEC-FEEDBACK.md) ("Open from v0.76").

**Changes to check before upgrading:**
- **Filtered namespace reads are on by default** (§B.11.9). They cover a namespace that is
  neither public, sealed nor end-to-end and trusts a catalog (its `catalogs` names the catalog,
  whose `catalog.trust` lists it, through a key whose `requireAt` names it), its local branches,
  and that catalog (Where). A partial reader there, a grant that verifies and allows `read`
  without unrestricted read (one whose key scope tests `/resource` without fixing it, say), is
  no longer `403` at `/heads`, log ranges, long-poll and events: it is redirected `302`,
  `private, no-store`, `Vary: Authorization`, to their filtered forms under `/ns/{ns}/g/{gs}`.
  There it sees only what a trusted catalog shows its subject set and its grant may read
  (Visible). `GET /ns/{ns}` answers it the head pointer, and `/rev/{ns_id}` and `/grants` stay
  `403`. `core.Options.NoFilteredReads` restores the v0.74 answers (there is no `serve` flag).
  Nothing is covered with authentication disabled, where every reader reads unrestricted (§1),
  nor are a catalog's own branches or remote branches. A local branch stays covered only while
  the namespace that trusts the catalog, at its head, still trusts it through every key counted
  at the branch's `baseAt`, each key entry unchanged (compared whole, so a `maxTtl` edit
  counts; keys added at the head don't): otherwise its partial readers get `403` at filtered
  URLs and no `/ns/{branch}/g/{gs}` prefix, at the origin and the index alike (v0.76, §B.11.9
  Branches, §C.4). The WebDAV gateway counts the core's `302` to a filtered read as the `403` it
  was.
- **Partial readers' subject sets name their key** (v0.76, §B.11.9 gs, §C.4). A filtered read's
  `gs` also holds `key:{…}`, a digest of the grant's `kid` and its key's `pub`
  (`catvis.KeySubject`), at the origin and the index alike, so readers through different keys
  with the same rules no longer share a `gs`, a stored subject set or an index marker. Each
  partial reader's `gs`, and so its filtered URLs, index result URLs and cookie prefixes,
  changes once. A cookie whose key has another `pub` than at its exchange, in the namespace or,
  for a branch, in its base, is `403` until the reader exchanges again, and so is every cookie
  whose subject set was recorded before core migration `012_filtered_gs_pub` or index migrations
  `006_edge_gs_pub` and `007_edge_gs_keys`.
- **Place before create** (§B.11.9 Placement, Branches, Catalogs). Only a live placement makes a
  document visible to a partial reader. A document never placed, one whose placement was
  deleted, and in a branch one without a live base document of its name as of the branch's
  `at` (a document new in the branch) are hidden. A filtered catalog read shows no placement
  whose item doesn't exist or is tombstoned. Tools that create before placing leave documents
  hidden from partial readers until the placement lands.
- **`GET /ns/{ns}/principal` gives `roles` as objects** `{ "name", "can", "rules" }`, each
  effective role as the configuration of `X-Config-Revision` defines it, `rules` `[]` if none
  (§7.4). Operator grants and auth-disabled answers keep `[]`, and `principal.roles` in the
  envelope stays the names (§6.4.1). Clients that read `roles` as strings must change; the Go
  client takes both forms (below).
- **Catalog listings' `gs` covers the caller's deciding subjects only** (§B.11.5 Listing URLs
  carry the subject set): the groups the catalog's `$access`, or a role or key rule of a
  trusted content namespace, names (every key's rules since v0.76, not only those of keys whose
  `requireAt` names the catalog), plus its user subject as before. Every group is kept where
  such a rule tests `/principal/groups` otherwise than by positive tests of named groups (a
  position, a negation, a pattern). Since v0.76 a positive test is exactly a `contains` of a
  `const` or `enum`, optionally with `"type": "array"`, or an `allOf` of such schemas, reached
  through `all` and `any`; mixes such as `contains` beside `allOf`, or a nested `allOf`, keep
  every group. When a group is left out, the subjects also hold `"partial"`.
  So private listing URLs and the prefixes `POST /edge-grants` gives change once for readers
  with groups nothing names, who now share listings. Edge grants issued before carry full
  subject sets and stay valid. A `"partial"` subject set is `403`, `no-store`, at an `at` where
  every group is kept, its head pointer included, until the reader exchanges again, as for
  `g/all`; at other `at`s a newly named group only shows it less.
- **The search index answers a covered namespace at §B.11.9's combined checkpoint** (§A.4
  Private namespaces, §B.11.9). There a partial reader's marker is `reads:{ns}:g:{gs}`, `gs`
  being the origin's subject set. Its hits, facets, counts and the schemas fields are judged by
  follow visibility, and its results are at the combined checkpoint over `{ns}`, the trusted
  non-e2e catalogs, their `catalog.trust` members and a branch's bases, each listed once: at its
  head where it is read there (a branch's root, as a trust member, included), a base read only
  as a base at `baseAt` (v0.76, §A.4 Answers). Answers
  list it as `namespaces`, `?min={ns}:{ns_id}` may name any of them, and they are tagged
  `idx:{m}` for each. Since v0.76 the index follows those namespaces itself (below), so their
  purges reach its kept answers; until it has a namespace's first checkpoint, partial readers of
  a namespace covered through it get `503 behind` with `Retry-After`, at `/{ns}` and `/_refs`.
  Coverage is decided from the namespace documents alone. The index's own
  grant must read what decides coverage, or partial readers get `502` (the next item).
  Unrestricted readers are answered as before, and so are partial readers of a namespace
  §B.11.9 doesn't cover, where the index's grant can read what decides it. Result URLs of partial
  readers change once, and their index cookies for `reads:{ns}:scope:{digest}`, issued while
  `{ns}` wasn't covered, are `403` on `/{ns}/…` and `/_refs/…` once it is, until they exchange
  again.
- **The search index's grant must read the namespaces that decide coverage** (§B.11.9 Where,
  §A.4 Private namespaces, §C.6). To tell whether §B.11.9 covers a namespace it follows, for a
  reader it doesn't let read the namespace whole, the index reads other namespaces through its own
  grant (`index.Options.Client`): every catalog the followed namespace's `catalogs` names through
  a key whose `requireAt` names it, every namespace a followed catalog's `catalog.trust` lists
  (their documents only, not the catalogs they name), and a followed branch's bases. It needs this
  whether or not the namespace turns out to be covered, so scoped readers of an uncovered
  namespace depend on it too. Where the grant can't read one, such readers get `502` `upstream`
  with a message saying the index's grant lacks a namespace that decides how this one is read, and
  the index's log names it (the answer doesn't, as `/principal` hides `catalog.trust` from readers
  who can't read the catalog whole). Before, they got a generic 'cannot read the namespace
  configuration'. While only the keys to open a sealed one can't be fetched yet (a `5xx` or `429`
  from `/keys`, or the core unreachable), they get `503 behind` with `Retry-After` instead; a
  `/keys` `4xx` other than `429` stays `502` (v0.76, scenario 100). **Widen the indexer's
  grant before scoped readers use the index** when upgrading from v0.24.0; unrestricted readers
  are unaffected.
- **The index's exchange is judged per namespace** (v0.76, §A.4 Across namespaces, Coverage).
  `POST /edge-grants` at the index leaves out a namespace where the grant gets no marker (no
  `/{ns}/g/{gs}` prefix, nothing in the `/_refs` set), and a purged one where another namespace
  gives an edge grant. It refuses only a grant left with none: `401` if any refusal was `401`,
  else `403`, and `410 purged` only where every refusal is a purge. A named namespace whose
  document can't be read is still `502`. It was all or nothing. A grant whose rules fix
  `/resource` and pass for none of the names they fix has no marker in that namespace: a query
  there is `403` (it was an empty answer under its own `gs`), and `/_refs` leaves it out. At
  another `gs`'s `/_refs` URL a grant that verifies in any followed namespace is `403`, not
  `401`; one that verifies in none, or none at all, stays `401`.
- **`POST /edge-grants` gives a partial reader of a covered namespace** whose grant doesn't fix
  `/resource` an edge grant for `/ns/{ns}/g/{gs}` alone, instead of `403` (§B.11.9 Edge grants,
  §C.5.2). §C.5.2's `/resource` and qualifying-role refusals are skipped for it, and the refusals
  for no `read` and for `/now` still apply. `/ns/{ns}/g/{gs}` is a core edge prefix (§2.1 Edge
  prefix): the origin's key vouches for it, `DELETE /edge-grants?prefix=/ns/{ns}/g/{gs}`
  withdraws it (§C.5.4), and `g/all` or a malformed id is `400`. Such a cookie authorises no
  unfiltered read (`403`). An edge that checks the origin's cookies must accept the new prefix
  form (`edge.ParseCorePrefix`). A grant that fixes `/resource` gets its `/r/{ns}/{name}`
  prefixes as before.
- **Gestures listing** (§7.4): an `after` must name a row the listing would give the caller,
  one written with the gesture or undoing it; one of another gesture is `404`. A partial reader
  of a covered namespace lists only resources visible to it at the current combined checkpoint,
  rows and `after` alike (§B.11.9 Answers), and is `403` if its grant has rules on `/now`
  (before, a `200` filtered per resource). In a
  purged namespace the `410 purged` comes as soon as the read check passes (§8.5).
- **The catalog service's key in a content namespace** (v0.76, §B.11.3, §B.11.9 Where) is the
  entry for its `-kid` only where that key's `requireAt` names the catalog and the namespace's
  `catalogs` names the catalog too. Otherwise its items' grants, from `POST /grants` (every
  verb) and `/read-grants` alike, are `403` ("does not list the catalog's key"), after a purge's
  `410`, and roles reached only through that key show nothing in listings; a `catalog.trust`
  member whose `catalogs` doesn't name the catalog adds no roles to visibility. Give the
  service's key that `requireAt` before upgrading. `/read-grants` answers an item of a namespace
  the catalog doesn't trust `403` before `"public": true`, a public namespace's included
  (§B.11.5 Every item at once).
- **`g/all` is judged against the combined checkpoint only** (v0.76, §B.11.5, §B.5). A trusted
  namespace the tree service doesn't follow no longer withholds `g/all` cookies. A cookie is
  `403` at an `at` that includes a namespace that entered the combined checkpoint after its
  issue; the service records those entry times as `meta` `inckpt:{ns}`, and drops v0.24.0's
  `trusted:{ns}` rows on start.
- **`born` in sealed and end-to-end catalogs** (v0.76, §E.2.6, §E.3.1). At E3 a node's `born`
  is sealed under the epoch a prune's `snapshot` of its first revision would carry, not under
  the first entry's served `kid`; a `born` whose epoch can't be told is left out, never sealed
  with the node's other values under the head's epoch. The first start after the upgrade reads
  in again, once, the borns an earlier release stored without an epoch (`meta` `bornsnap`), so
  they don't drop out of listings.
- **A key no recipient key opens is lacking for good** (v0.76, §A.4, §E.2.6, §12.1): a key
  `/keys` wraps to the grant's `enc` where the service has no recipient key configured
  (`client.ErrNoKeys`), one that doesn't open (`seal.ErrDecrypt`), or one from a keyring sender
  the service doesn't trust. The index skips such a sealed namespace (`404`) instead of answering
  `503 behind`, tree listings show nodes served under it by name only, and a remote branch of
  such a base is `422` at creation (§G.5.2). A `/keys` `5xx` or `429`, or an unreachable core,
  stays transient (`client.ErrKeyFetch`).
- **A remote branch whose raise failed answers `502 upstream`** (v0.76, §1, §G.5.2, §12.1). Its
  read-through resources, and writes to them other than purges, get `502` `{code: "upstream",
  origin}` without `Retry-After`, as for a level B's server lacks, instead of `503
  encryption_unavailable`. The raise is still retried at every sync and at start.
- **E3 remote branches serve only A's own sealings** of content from before A's raise (v0.76,
  §G.5.2 E3 sources). B never seals that content itself: it stores A's bytes, after a shape
  check of `kid` and `pl` where it lacks the epoch key, asks A's `…/blob/{bid}` so that A fixes a
  blob's epoch, and answers `502 upstream` naming the origin where A doesn't serve it a sealing
  (`403`, `404`, a refused log page). B relays no keyring entries or pre-raise keys of a base
  deeper in A's chain, and uses no last-seen epoch for it, while its latest read of that base's
  namespace document failed. It reads those documents at creation, when its follower starts and
  at every sync (core migration `013_remote_chain_read`), so branches created before read them
  on the first start after the upgrade.
- **A keyring write needs a fresh `$nonce`** (v0.76, §E.3.2, §C.7): another form is `422
  invalid`, and a bundle import refuses it at step 1. Keyrings stored or mirrored before, with
  another `$nonce`, are still relayed and readable.
- **A check that fixes an epoch stores it** (v0.76, §E.2.2 Epochs, §2.1, §6.1). A blob copy's
  source check, a batch's local-source check or a schema resolution that judges a sealed
  namespace's content by an epoch nothing has fixed yet stores that sealing with the request,
  so after a rotation the content is served under the epoch the check judged.
- **The janitor counts a batch only through its items** (v0.76, §F.6, CONFORMANCE Merge 61): its
  head and tombstone items, not the keyring's at E3. A config-only batch is no longer the
  branch's own work, nor a `batch` entry after `source.at` that fails `merged` or `superseded`.
  So a branch whose only writes are config-only batches, or batches whose items are all for
  resources purged in it, now counts as merged, and **the janitor may purge branches it kept
  before** once their `cleanup` allows. A batch with items after `source.at` still fails the
  check, even for resources purged later.
- **Merges judge array writes at the outermost array** (v0.76, §F.3 Conflicts inside arrays). A
  write whose last segment is an index or `-` of an array counts as a write to the whole
  outermost array holding it, not the innermost, so appends to arrays inside different elements
  of one array now conflict. A write to an object member, one named `-` included, is unchanged.
  Bundle imports' array rule (§G.4.4) follows.
- **An E3 merge leaves out an item it can't seal, and `rebase -switch` stops for it** (v0.76,
  §F.3 kept bullet, §F.5, §E.3.1). A replayed, fast-forwarded or re-sealed item whose document
  references a blob a sealed op can't declare (one from before a raise to `e2e`, say) gets no
  item and a note: it stays unmerged and is offered again, and the rest of the batch commits
  (the whole batch was `422 blob`). A rebase with `Switch` whose first replay leaves a resource
  out, this way or by a `keep` over a tombstoned or absent base resource, now stops before
  freezing the old branch with `merge.ErrLeftOut` naming the resources, unless
  `RebaseOptions.LeaveOut`; a catch-up after the switch that leaves some out reports them the
  same way (`RebaseResult.LeftOut`).

**New:**
- Filtered namespace reads at the origin (§B.11.9 URLs):
  - Routes `/ns/{ns}/g/{gs}/at/{at}/heads` and `…/log`, immutable; `/ns/{ns}/g/{gs}/heads` and
    `…/log` without `live`, which redirect `302` to the current `at`, `private, no-store`;
    `/ns/{ns}/g/{gs}/log?live=long-poll`; and `/ns/{ns}/g/{gs}/events`. `{gs}` and `{at}` are
    ids, `all` is `400`.
  - `at` is the combined checkpoint of `{ns}`, the trusted non-e2e catalogs, their
    `catalog.trust` members and a branch's bases, one `ns_id` each: a namespace read at its head
    is listed at it, a branch's root among the trust members included, and a base read only as a
    base at `baseAt` (v0.76; visibility still reads a branch's bases as of `baseAt`, and an `at`
    recorded with v0.75's layout is still answered). An `at` that is neither the current one
    nor one the origin minted a URL for in the last 7 days is `302` to the current one.
    Answers carry `X-Namespace-Revision` and `Cache-Tag` `ns:{x}` for every other member of
    `at`; `/heads` also carry `heads:{x}`.
  - At an unfiltered URL, by the grant in `Authorization`: `/rev/{id}/heads` (`after` and
    `prefix` kept) and log ranges redirect to the filtered form at the current `at`, recorded
    first, and `/ns/{ns}/log?live=long-poll` and `/events` to their `/g/{gs}` forms.
  - `gs` joins every trusted catalog's deciding subjects, `"partial"` where one leaves a group
    out, `scope:{digest}` of §A.4's marker and, since v0.76, `key:{…}` of the grant's key; rules
    on `/now` are `403`. A grant in
    `Authorization` reads at its own `gs` as of the URL's `at` and is `403` at another, an
    unrestricted reader's is `403` at every filtered URL, and a `/ns/{ns}` cookie is served as
    the URL's `gs`'s cookie would be. A `gs` cookie is judged from its stored row alone. It is
    `401` without one, and `403` where the rules its digest covers differ at `at` (a kid or role
    gone included, or one that no longer lists `read`: a cookie never reads where its grant
    couldn't), where its key's `pub` differs from the one stored (v0.76), or where a
    `"partial"` set meets a catalog that keeps every group.
  - The filtered URLs of a namespace §B.11.9 doesn't cover, a public one included, are `401
    unauthenticated` to a request with neither a grant that verifies in `{ns}` nor a verified
    cookie, and `403` otherwise; a purged one answers them as §8.5 answers their unfiltered
    forms once the read check passes: `410 purged` with `head` for `/heads` (with or without an
    `at`), for long-poll and events from its `purge-ns` entry, and for every form in a sealed
    namespace (v0.76, §B.11.9 Purged namespaces, §B.11.5).
- Filtered `/heads` list only visible rows, in pages filled to `logPageSize`, with `next` on
  every full page (§B.11.9 /heads).
- Filtered log ranges (§B.11.9 Log entries, Log ranges):
  - `config` and `purge-ns` entries are always shown, `branch` entries never.
  - A batch keeps its visible entries, `gestures` and `source.ids` (an emptied member is left
    out), stays as a config-only batch if only its config entry is visible, and is dropped if
    nothing is.
  - A batch counts as its visible items and every other entry as one, so pages can be empty;
    `X-Log-Next` names the last entry scanned, and the range ends at `X-Namespace-Revision`.
- Filtered long-poll waits past hidden entries: a `204` names the newest entry scanned, and a
  `since` naming a hidden entry is accepted (§B.11.9 Long-poll). Filtered events re-admit and
  judge visibility again at the current checkpoint on every page and keep-alive, and end when
  the check fails, a changed `gs` included (§B.11.9 Events, §7.3). Waiters of one `gs` share
  each page and each entry's judgement per checkpoint (§B.11.9 Cost).
- Purged namespaces answer the filtered URLs as their unfiltered forms (§B.11.9, §8.5):
  filtered `/heads` are `410` after admission at any `at`, the current one or not, with no
  redirect first, ranges end with `purge-ns`, and long-poll and
  events from `purge-ns` are `410`; an event stream sends `purge-ns` before it ends.
- `GET /ns/{ns}/branches` to a partial reader of a covered namespace lists only the local
  branches in which its grant verifies and allows `read`, without remote registrations,
  `private, no-store` (§B.11.9 Answers).
- `?prefix=` on `GET /ns/{ns}/rev/{ns_id}/heads`, for every reader: only names starting with it,
  read-through names of a branch included, `next` absent on the last page. A prefix that isn't
  a resource name (§3.6), the empty one included, is `400 bad_input` before authorisation; an
  `after` below the prefix starts at it (§7.4, §12.4).
- Client:
  - `PrincipalInfo.RoleDefs` gives each effective role's `can` and `rules`. `Roles` keeps the
    names, from v0.75's objects or the strings older servers send (§7.4).
  - `HeadsPrefixPage` and `HeadsPrefix` send `?prefix=`, checked as a resource name before
    sending (§7.4). A server before v0.75 answers `400`, which is returned as is.
  - A key `/keys` wraps to the grant's `enc` while no recipient key is configured is
    `ErrNoKeys`, lacking, not a failure to retry; key fetch failures that may pass wrap the new
    `ErrKeyFetch` (v0.76, §A.4, §E.2.6).
  - `FilteredHeadsPage`, `FilteredHeadsAt` and `FilteredHeads` follow a partial reader's
    redirect to `/ns/{ns}/g/{gs}/at/{at}/heads` (`FilteredAt` says which `gs` and `at`, and a
    `200` means an unrestricted reader). A page whose `next` isn't its last row, or whose rows
    don't ascend after `after`, is refused. `FilteredHeads` restarts up to 3 times if the `at`
    moves.
  - `FilteredLog`, `FilteredLogAt` and `FilteredLogPage` read filtered ranges, empty pages and
    an `X-Log-Next` naming a hidden entry included, and refuse a range whose end changes
    between pages. `FilteredLongPoll` and `FilteredNSEvents` read `/ns/{ns}/g/{gs}/log` and
    `/events`.
  - `LongPoll` and `NSEvents` don't follow a redirect into a filtered log, which isn't
    chain-verifiable (§B.11.9 Log entries, §10). They return it as a `*FilteredError` naming
    `gs` (`AsFiltered`), still an `*APIError` with status `302` that isn't retryable, so
    followers stop rather than apply filtered batches as whole ones. The unfiltered `NSLog`,
    `NSLogPage`, `HeadsPage` and `Heads` are unchanged.
- Tree and catalog services (§B.11.5):
  - A grant in `Authorization` reads at its own `gs` as of the URL's `at`. A listing kept at an
    older `at` stays readable to it under the `gs` it had there, also once served again from a
    sealed or file-sealing catalog's store and after a restart. Redirects to the current `at`,
    a checkpoint that moved during the computation included, name the grant's `gs` there. At an
    `at` whose deciding inputs the service no longer holds, the grant is judged at the current
    one.
  - The listing and `/read-grants` node test is now `internal/catvis`, the implementation the
    origin's filtered reads and the index use. Answers are unchanged but for v0.76's deciding
    groups and catalog key (above).
- Search index (§A.4, §B.11.9):
  - In a covered branch's preview index, a partial reader sees a document only where its base
    had a live one as of the branch's `at` (§B.11.9 Branches). A covered catalog shows it only
    the nodes the node test shows, never a placement whose item isn't live (§B.11.9 Catalogs).
  - `/_refs` takes each covered namespace's checkpoint into its `at` and `namespaces`, and
    accepts `min` for those namespaces (§A.4 Across namespaces). An answer read before a purge is
    never stored after it.
  - Its edge grants for a `g:` marker record the subject set's subjects and read roles, and
    every key its live cookies came from with that key's `pub` and the cookies' `exp`
    (`edge_gs`, `edge_gs_keys`, migrations 005–007). A cookie is judged from that record alone:
    `403` where the rules its digest covers have changed (a role or the key no longer listing
    `read` included), where one of those keys is gone or has another `pub` (v0.76), where a
    `"partial"` set meets a catalog in which every
    group decides, or where the namespace is no longer covered (§B.11.9 gs).
  - Where §B.11.9 covers a namespace, the index follows the namespaces visibility reads there
    without serving them: trusted catalogs, their `catalog.trust` members and a covered
    branch's bases (v0.76, §A.4 Private namespaces). A purge in one of them, or a config entry
    on which §9 purges `ns:{m}`, purges `idx:{m}` and drops kept results and `/_refs` answers,
    those computed from a view read just before it included (§A.1); before, those namespaces
    were read at their heads through the grant checker, and a kept answer could outlive a purge
    in its catalog. Answers take such a namespace at its follower's committed checkpoint,
    waiting up to `Options.MinWait` for the head the grant checker read. A follower starts when
    coverage first reads its namespace and stops, forgetting its checkpoint, once none does,
    purging `idx:{m}` each time; a restart resumes those still needed (index migration
    `008_member_checkpoints`). `(*index.Index).Members` lists them.
  - `/{ns}/g/{gs}/at/{at}` and `/_refs/g/{gs}/at/{at}` under the `gs` a grant had as of an older
    `at` the index still holds are answered as that reader's older `at`s are: its kept result,
    a redirect to the canonical form or from a `min` it includes, otherwise `302` to the current
    `at` (§B.11.5). Only the kept canonical URL used to be answered; the rest were `403`.

**Fixes:**
- Tree service, sealed catalogs: a listing sealed under an old epoch could be
  served for good after the epoch backfill a start runs (`nodes.born_epoch`, v0.24.0), or
  another backfill or reload that changes listings at an unchanged `at`. A sealed view read
  from the database, or computed, while a purge of its tags was committing outlived the purge.
  Sealed views are now kept only if no purge carrying one of their tags came since they were
  read, and the tree service and the index drop them from memory again once a purging
  transaction commits (`internal/derived`). v0.24.0 is affected too.

## v0.24.0

Implements spec **v0.74**. `GET /` answers `"spec": "0.74"`. The upgrade was done in five
packages: core keys, epochs, E3 gate checks and grant answers; core remote branches, reads, live
streams, gestures and blob copies; schema compilation and the search index; the tree and catalog
services; and grant tokens, the edge exchange header, sealed bundles and vectors, the janitor, the
WebDAV gateway, bundle imports and merge releases. The one schema change is the tree service's
migration `005_nodes_born_epoch`; the core's and the index's schemas are unchanged (the index
rebuilds its tables from the logs once, below). Where the spec leaves a question open, the
reference implements the reading noted here.

**Changes to check before upgrading:**
- **No key from before a raise from `sealed` without `nbf`.** After a raise from sealed to e2e,
  `POST /ns/{ns}/keys` gives the epochs before the raise only within the §E.2.3 window judged
  against the namespace's current epoch and current namespace document (Addendum E Levels): a
  grant without `nbf` gets none of them, and the current `historyEpochs` caps the rest. Copies, a
  batch's local source and schema resolution of content from before the raise take only what
  those keys open. A reader or writer that needs content from before the raise (an E3 fold that
  starts before it, say) needs a grant with an `nbf` reaching back. A remote branch whose
  endpoint grant has no `nbf` gets no pre-raise keys from its source, and creating one over
  sealed history from before the raise is then `422`.
- **With authentication disabled, `/keys` gives the current epoch alone** (§E.2.3), and the
  server's own key checks take the same: no earlier epoch, and none from before a raise. A
  `serve -dev` server's playground, and the index, tree and derived services reading it without
  grants, can no longer open sealed content of earlier epochs after a rotation. An index or tree
  service that already holds such content keeps it, and serves the hits it can't seal by name only
  (below). One that reads the namespace afresh (a new service, `-rebuild`, or the index's one-time
  rebuild below) can't read those documents: it leaves them out of its results, and of the
  catalog's tree, and indexes and lists the rest. Upgrading an auth-disabled deployment whose
  sealed namespaces were rotated therefore drops their earlier epochs' documents from the index;
  a service grant with an `nbf` reaching back keeps them. Such a service no longer stops at the
  namespace's genesis document, sealed under epoch 1: the namespace document at the head stands
  in for it (§E.2.3, §E.2.6, §A.4).
- **A branch's `/keys` relays its bases' entries for at most that base's `historyEpochs` at
  `at`** before its epoch there (§E.2.3 At E3). The keys a base had before a raise from sealed
  follow that base-epoch rule alone (Addendum E Levels, Branches of a raised base), not the raised
  namespace's own window, so a base that lowers `historyEpochs` or rotates after the branch's
  `at` doesn't withhold them from the branch; blob copies, a batch's local source and schema
  resolution through the branch give the same epochs as its `/keys`.
- **A verified grant that may not read is `403`, not `404`,** at `/ns/{ns}` and every URL under
  it (the gestures listing included) and at `POST /ns/{ns}/keys`, a public namespace's included,
  and at E3 `/keys` for a grant whose rules refuse every read (§7, §C.2, §E.2.3). A grant whose
  read is limited to some resources gets `403` on `/ns/…` URLs too. Only a resource's own URLs
  keep the `404` that hides it; unauthenticated callers keep `401`, and a purged namespace's
  `410` still comes after the read check.
- **Every schema compiles under v0.74, whatever version stored it** (§6.1, §6.2 step 5, §6.6). A
  stored schema revision that only an earlier version accepted (a format outside 2020-12 such as
  `semver` or `period`, a `\x{D800}`-style pattern, a root `$id` equal to its own path, a nested
  dialect `$schema`) is now an invalid schema, and a write pinning it is `422 invalid`: stored
  legacy schemas may now refuse writes. Formats are asserted as they are now (`idn-*` below). The
  `revisions.rules` marker and the `X-Schema-Rules` header are kept as metadata only, so remote
  branches still mirror them and nothing is migrated. At E3 the client re-validates folded
  revisions under current rules, so revisions typed by such a schema, or whose verdict changed,
  are flagged, and a document's valid head can move back to an earlier revision; a schema
  document that itself names `semver`/`period`, carries its own `$id` or a nested `$schema` is
  flagged the same way (pending a spec ruling on invariant Valid). Stored rule fragments keep
  their present compile.
- **`idn-hostname` and `idn-email` follow RFC 5890** (IDNA2008 registration) without UTS 46
  mapping, with RFC 5892's CONTEXTO rules (MIDDLE DOT, GREEK KERAIA, HEBREW GERESH/GERSHAYIM,
  KATAKANA MIDDLE DOT, Arabic-Indic digit sets) for U-labels and for A-labels once decoded (§6.2
  step 5). An uppercase or fullwidth letter in a U-label (`Bücher.example`) is `422`; an all-ASCII
  host name in any case (`EXAMPLE.com`) still passes.
- **Sealed bundles are framed strictly** (§G.5.1.1). Readers reject a non-canonical envelope,
  blank lines, CRLF line ends, a last line without its 0x0A, a non-canonical protected header, and
  one with members other than `alg`, `enc` and `pl`, so `last` beside `pl`: sealed bundles
  exported by v0.22.0 and earlier no longer import. A server-read encrypted archive's envelope
  line is framed as strictly.
- **Bearer tokens signed over Biscuit's version 0 payload are `401`** (§C.8, CONFORMANCE Grant
  scope 52); stored grants from before still verify. Tokens made by biscuit-go v2.2.0, which signs
  version 0, no longer verify as bearers.
- **Under `grants`, a retry no longer matches an entry recorded without a grant**, even by its
  author (§7.2): resource writes, batches, config writes, branch creation and remote
  registrations retried after enabling authentication are `412`.
- **E3 sealed ops and prune snapshots need a canonical protected header** with only `alg`,
  `enc`, `kid` and `pl` (§E.3.1, §E.2.2): any other is `422 invalid`. The Go client and the
  playground already write such headers.
- **An empty `Authorization` counts as present** (§C.5.2, §C.5.3, §B.11.5): `POST /edge-grants`
  and the services' exchanges answer a body with one `400` (before, `415`), and edge cookies,
  the origin's and the catalog's and index's own, count only on a read without any
  `Authorization` field.
- **Gestures listing:** an `after` not of the form `{resource}/{id}` is `400 bad_input`, before
  the namespace lookup (so ahead of a private namespace's `401`/`403`); one naming an entry of a
  purged resource is `404` (§7.4, §6.2).
- **Blob copies:** a sent precondition is `428`, after the copy's `400`s and before the
  different-bid `422` and the source check's `404` (§7.8 Copying).
- **A purged namespace's events and long-polls from its `purge-ns` entry** (`since` or
  `Last-Event-ID`) answer `410 purged` with `head` instead of an empty stream or `204` (§8.5).
  The immutable `/rev/{id}/log` range is unchanged.
- **Remote branches follow a raise to `e2e` to `sealed`:** a remote branch whose source is raised
  to `e2e` raises itself and its dependents, leaves first, to `sealed`, as far as Levels allow,
  and is marked for a rebase (§G.5.2). `502 upstream` is reserved for a server lacking the level
  (no key store, or a key store that has gone) (§1). A raise the server could make but whose
  config writes fail for another reason is recorded for a rebase and retried on start and at every
  sync, and meanwhile the branch holds what it had at `at` rather than serve it below the source's level
  (Addendum E Levels Invariant): reads and writes of those resources other than purges answer
  `503 encryption_unavailable` with `Retry-After`. `/heads` rows of resources answering `502` or
  so held leave out `created`, `size` and `digest`, at the remote branch and at branches reading
  through it (§7.4).
- **Remote branches v0.23 left below `sealed` are raised on the first start.** v0.23 followed a
  source's raise to `e2e` only as far as the source's level before it, so a remote branch of a
  source raised from `none` to `e2e` stayed at `none`, recorded for a rebase, and served its
  content in the clear. On a server with a key store, the first start raises such a branch and its
  dependents, leaves first, to `sealed` before anything is served (§G.5.2, Addendum E Levels), as
  it does any raise recorded but not yet made: from then on that content is served only sealed,
  and readers without keys to it lose access to content they could read before. A raise that still
  fails holds the content, `503 encryption_unavailable`, until a later sync makes it (above).
- **Remote branches take the start times of a source's epochs before its `e2e` raise only from
  `base.origin` itself** (§G.5.2), never from a mirror the endpoint may be. A `-remote-url` other
  than the origin now counts as a possible intermediary; set `-remote-origin-url ORIGIN=URL`
  (below) where the origin itself answers at another address. When the origin can't be read, an
  E3 remote branch still holds the source's keys of those epochs, mirrors its sealings verbatim
  and serves that content as the source does, but hands none of the keys out until a later sync
  reads their start times from the origin.
- **Search index:** on a query of one namespace, a `min` naming any other namespace is `400` with
  the body's `min` listing it (before, a readable followed one was waited for and redirected, a
  purged one redirected, and one skipped for keys was `503`) (§A.5). The index database format
  goes to 2, so existing indexes rebuild from the logs on start (with authentication disabled,
  without documents of a rotated sealed namespace's earlier epochs, above).
- **Catalog service:** without a merge key, `POST /merge-grants` is `404 not_offered`, whoever
  asks (§F.8); a key's `sub` scope matches only a caller sub starting with `user:`, so `svc:` and
  other subs fail every `sub` scope (§B.11.4 Through the key); item requests other than Place
  answer `403` first for an item in a namespace the catalog doesn't trust, before `410 purged`,
  `/read-grants` items too (§B.11.4).
- **Tree service:** in a sealed or e2e catalog, a node's `born` whose first revision is served
  under another epoch than its head is sealed apart in place as `"born": {"sealed": JWE}` under
  that epoch's `K_r`, and left out when that key can't be had; such a listing is no longer sealed
  whole (§E.2.6). The epoch is stored in `nodes.born_epoch` (migration 005) and backfilled on
  start, nodes edited while the backfill runs included. The WebDAV gateway decodes such entries.
- **Merge service:** every catalog batch of an end-to-end catalog goes under
  `ReleaseOptions.AdminGrant`, which must be a catalog-admins member's grant (its root `groups`),
  narrowed with the merge service's `via`; without one it is `ErrAdminNeeded`. Unplaces and
  narrowing moves were refused as not offered before (§F.8).
- **Janitor:** once a successor is purged, a superseded claim counts through a branch `*` key
  only with a grant the janitor read from the successor's `/grants` before the purge; it no
  longer reads it from the successor's base or the old branch, so such branches are kept for a
  manual decision (§F.6, §8.5). `patchlog janitor` keeps the grants it read while it runs, at
  most 4096, least recently used dropped first, and only successors'.

**New:**
- `patchlog serve -remote-origin-url ORIGIN=URL` (`RemoteEndpoint.OriginURL`) says where the
  deployment at `ORIGIN` itself answers, for example the internal address given with
  `-remote-url` (§G.5.2).
- E3 remote branches of a source raised from `sealed` mirror the source's sealings of pre-raise
  revisions, log entries and blobs byte for byte, each checked against the mirrored content and
  keeping its epoch, also for content of deeper bases in `base.chain` (§G.5.2). A sealing whose
  epoch key the branch lacks is sealed by the branch itself, as before.
- An E3 prune at a horizon from before a raise from sealed first stores that document's sealing
  if none is stored (for a tombstone, the last live document's), and `/rev/{H}` keeps serving
  those bytes (Addendum E Levels).
- `POST /edge-grants` accepts block and key rules that refer to `/resource` in other forms when
  the grant fixes `/resource`, and runs them for every fixed name, so one name they refuse is
  `403` (§C.5.2).
- Search index: a hit served under an epoch whose key the index's grant gets none of, for good
  (`/keys` answering a `4xx` other than `429`, no key for that epoch, or a key it can't unwrap or
  won't take from an untrusted sender), is served by name only (`resource`, `id`, `url`, plus `ns`
  on `/_refs`), where it used to be `503`. Such a result is sealed per entry and `counts` over it
  are `400`. Any other key failure, a reader disconnecting while the key is read included, is
  still `503 behind`, and a result built after the request ended is never kept or stored
  (§E.2.6, §A.4).
- Search index: a schema revision answering any `4xx` other than `429` (a `401` to the service's
  own grant included) leaves the document indexed as untyped instead of retrying forever (§A.1);
  values are collected through `dependentSchemas` whatever members the document holds (§A.2,
  §A.4); a redirect from an `at` URL to another `at` drops an opaque `after` (a `q` or `sort`
  position) and keeps one naming a resource (§A.4).
- Catalog service: `POST /grants` answers `parents` (the node's parents as decided) for every
  Move, admins' included, and for every Unplace or folder delete, beside `head` (§B.11.4
  checkpoint). A purged item's read check and Restore judge "a role that makes it visible" as
  listings do, with role and key-scope rules evaluated for the item (a rule on `/now` never
  counts), and with the grant's own subjects, `user:{sub}` always among them, so a role held in a
  deleted item's frozen rows through a since-removed `user:` entry still counts (§B.11.2,
  §B.11.4, §B.11.5).
- Tree service: in a subject set's listings, a visible node with no visible parent is a root,
  including one whose parents are all gone, dangling or cyclic; `roots` lists it and its paths
  end at it. Unfiltered listings keep §B.5's roots and orphans (§B.11.5). Purged namespaces leave
  the combined checkpoint `at`, listings' `ns:{ns}` tags, the coverage of problems and orphans,
  and `g/all` trust timing (§B.5).
- WebDAV gateway: a user's own entries are judged by the key their kid named when they were
  written, from the namespace's config history, so entries written before a kid was given to
  another key no longer count as the new holder's own (§H.7). The history is read once per
  gateway and namespace and shared with another token only after that token has read one log
  entry, showing it may read the namespace log; tokens that can't still use the current mapping.
- WebDAV gateway: a save over a deleted file whose last revision the gateway can't read (sealed)
  is `409`, naming the new path where the head gives it, never a new file (§H.4, §H.6).
- Bundle import: a partial import treats the upstream of a held snapshot document as nonced where
  the target requires nonces (§G.4.4).
- Vectors: `re2.json` gains I.11's `\ud83dA` row, and the `\x{D800}` refusal is no longer marked
  informative. `sealedbundle.json`'s three informative cases are now rejections, with new
  rejections for an extra `pl` member, a non-canonical protected header, CRLF line ends and a
  missing final 0x0A. `biscuit.json` gains two refused version-0 tokens (Addendum I.11, I.14,
  §G.5.1.1).

**Fixes:**
- Janitor: a branch whose only own entries are for resources purged in it counts as merged
  (§F.6, MRG-4), while a batch carrying a config change (config and no items, §7.5, or config
  with items only for resources purged later) still counts as the branch's own work, at E3 too,
  so such a branch is never purged as merged with that change unmerged; at E3 an epoch bump
  (config and keyring) with nothing else still doesn't count (§F.6).
- References (§6.5): the static x-ref walk reads a stored schema revision as the version that
  stored it accepted it (a format outside 2020-12, a root `$id` equal to its own path, a nested
  dialect `$schema`, a pattern only raw RE2 accepts), so bundle export, import and rename and the
  index's `/_refs` keep finding the references of documents typed by such schemas, though writes
  pinning them are now `422`.
- Encrypted archives: the server reads an archive's sealed-bundle envelope line as strictly as
  bundle import does, taking off only its 0x0A (§G.5.1.1); before, surrounding spaces or a CRLF
  were trimmed and such an archive restored.
- Pre-raise blobs (Addendum E Levels, §7.8): a remote branch of an e2e branch of a base raised
  from sealed serves a blob a pre-raise revision references as the source does, `…/blob/{bid}`
  redirecting to its epoch and `…/e/{e}` the source's sealing; before, the shadow of the
  branch, which has no raise of its own, ended the search, so the epoch URL was `404` and
  `…/blob/{bid}` served the plaintext. Its resource logs page as the source's too (§7.1
  Paging): the first page ends before the raise, its entries sealed as the source serves them;
  before, one page spanned the raise and served the entries from before it in the clear.
- Follower: a namespace purged between the head a follower reads when it starts and its check
  for a purge at that head (the `/heads` 410, §8.5) is delivered from the log up to its `purge-ns`
  entry, the freeze before it applied and reported as `Frozen`; before, a synthetic `purge-ns`
  unit at the 410's head skipped those entries, so `WithOnState` never reported the freeze. A
  purge's state now reports `Frozen` too (only a frozen namespace is purged, §8.5), including a
  sealed one whose freeze is `410` with the rest of its log.

## v0.23.0

Implements spec **v0.73**, the whole upgrade from v0.55. v0.56 folds in the reference's notes
1–79; v0.57–v0.64 restructure the text (Requirements blocks, §12 as registries, the checklist
moved to CONFORMANCE.md, about 15% shorter) and answer the cases §1–§13 and the addenda left
open; v0.65–v0.73 answer four cold sweeps and the closing sweep, and state each security
cluster's invariant where its rule lives (protection in §2.1, grant scope in §C.2, levels in
Addendum E, tree-derived access in §B.11), with a list of regression scenarios. The first wave
brought the request-shape layer, grant semantics, the schema dialect, the sealed formats,
limits, the merge tools, catalog access, index queries, gateway saves, the janitor, the bundle
format, the test vectors, tree listings and remote branch creation to v0.73; the second brings
gate preconditions, retries and dry runs, config writes and branch creation, read scopes, guard
paths, allowances and shared rate buckets, `/keys` and the e2e keyring document, entries, heads
and `/principal`, rule evaluation, organising grants, index access, gateway moves and tree
access; the third brings the step-6 rule order, purges and prunes, schema protection, live
reads, E3 client rules and raises to e2e, catalog item answers and merges, remote branches
following their base's level, gateway users and tree-derived writes, and encrypted archives; the
fourth brings serving what came before a raise to e2e (a raise from `sealed` included), keys and
branches after a raise, the index's own edge grants, derived values sealed under the epoch their
source is served under, the proposed Addendum I additions, and fixes to flaky Postgres tests.
`GET /` answers `"spec": "0.73"`. Where the spec leaves a question open, the reference
implements the default the plan states.

The schemas of the core, the tree service (with the catalog) and the search index are now
[mmmigrate](https://github.com/middle-management/mmmigrate) migrations (README "Schema
migrations"), applied on start and recorded in each database, instead of schema statements run on
every start with checks for what each older version lacked. The v0.22.0 schemas are the first
migration of each (`001_baseline_schema`), unchanged; v0.73's schema changes below are the
migrations after them: the core's 002–010 (on SQLite and Postgres alike: new columns and tables,
and three that fix data an earlier version stored, each run once), the tree service's and the
index's 002–004, and those of the services' edge grants (`internal/svcedge`, 001).

**Changes to check before upgrading:**
- **Databases from before v0.22.0 are no longer migrated.** Start v0.22.0 on such a database once
  first (the core's, the tree service's and the index's alike). A database v0.22.0 created or
  migrated is adopted as it is.
- **Migrations are recorded in new tables:** `mmmigrate_applied` and `mmmigrate_current` on
  SQLite, the schema `mmmigrate` on Postgres (per schema the core's tables are in, so deployments
  in different schemas of one database stay apart). On Postgres the database user needs `CREATE`
  on the database on every start, not only the first.
- **A rebuild of the tree service or the index empties its tables** rather than dropping and
  recreating them; it replays from the beginning as before.
- **Development tools need `-author`** (§7.2). With authentication disabled, a write without
  `X-Author` is `400 bad_input`; reads are unaffected. `patchlog janitor`, `merge`, `rebase`,
  `import` and `schema` against a `-dev` server must pass `-author`, and so must `patchlog dav`
  in local mode, which starts without it but has every save refused; `compose.yaml` and
  `compose.host.yaml` now start the janitor with `-author=janitor`, whose namespace purges had
  been failing. A remote registration sent without a bearer names this deployment's origin as
  its author. The playground sends `X-Author: anonymous` until its author box is filled.
- **Origins must be canonical** (§3.5, §7, §C.3, §G.3, §G.4.1): `scheme://host[:port]` in
  lowercase ASCII, an IDN host as its A-label, without a default port, path or trailing slash
  (`sig.CanonicalOrigin`, the one test now used everywhere). `serve -origin` (and
  `core.Options.Origin`) in any other form is refused at startup: such a deployment's bundles
  couldn't be imported elsewhere, since an import copies the header's origin into each batch's
  `source.origin`. Bundle readers refuse a header or `written` origin in another form when the
  bundle is read (`bundle verify` included) instead of at the import's first batch, so a bundle
  exported by a deployment with a non-canonical origin, or edited by hand, no longer verifies.
  Remote origins (`base.origin`, a registration's `remote.origin`, `serve -remote-*`) also
  refuse a Unicode host and a port written with leading zeros.
- **Malformed ids are `400 bad_input`**, `no-store`, before authentication and before an
  unknown namespace's `404` (§7): in URLs (`/rev/{id}` with its `/log` and `/raw`,
  `/ns/{ns}/rev/{ns_id}` with `/log` and `/heads`, `/grants/{gid}`, `/blob/{bid}`), in `since`
  and in `Last-Event-ID`. They were `404`; well-formed unknown ids stay `404`. On event
  streams a non-empty `Last-Event-ID` wins over `since` (§7.3).
- **Request shapes refused before authentication** (long-poll parameters before
  authorisation, and a batch body's once its grant is verified, below; §3.1, §3.5, §6.2, §7,
  §7.2, §7.5, §7.7, §C.3.1), each `400 bad_input`:
  - a request body with a Unicode noncharacter (U+FDD0–U+FDEF, U+nFFFE, U+nFFFF), raw or
    escaped; blob uploads are not affected;
  - a precondition that isn't one strong tag around a text id or `If-None-Match: *`:
    `If-Match: *`, a weak tag, a list, a sealed `"{id}.{e}"`, an empty value, a header given
    twice; a malformed config `If-Match` (it was ignored, giving `412`); a batch item with both
    `ifMatch` and `ifNoneMatch`, or a malformed item or config `ifMatch` (the batch's own `400`,
    no longer an item report); a malformed branch name, branch or registration `at`, prune
    `horizon` or `keep` entry. `DELETE` with `If-None-Match: *` is no longer a shape error: it
    is judged after authorisation and stays `410`/`412` until the gate answers `428`;
  - a batch `source` that isn't `{ origin?, ns, at, bundle?, ids? }`, with text ids, `ids`
    members naming the batch's resources, and `origin` canonical (`scheme://host[:port]`,
    lowercase ASCII, an IDN host as its A-label, no default port), refused rather than
    normalised (F-B4 default);
  - `Gesture` or `Undoes` given both as a batch header and in its body (the headers are now
    the batch's defaults);
  - a `Signature` header or step `signature` whose `<sig>` isn't exactly 86 base64url
    characters (such signatures used to be stored unverified), and a `Signature` header on any
    write other than a resource `PATCH` or `DELETE` (for blob uploads and copies, at check 4 of
    §7.8). Signatures already stored keep reading: bundle checks report an unlisted kid as
    `unverifiable` whatever the length of its `<sig>`;
  - on long-polls, a `live` other than `long-poll` (`live=` used to redirect) and a `cursor`
    that isn't decimal (`cursor=`, `+5`);
  - a batch body is read only up to the verified principal's `batchSize` (§6.2, §7.5), so the
    shapes above that are in its body (a noncharacter, an item's preconditions, a malformed
    config `ifMatch`, `source`, `gesture` or `undoes` beside its header, a step `signature`)
    are answered once the grant is verified: an undecodable bearer is `401`, and one over
    `grantSize` `413`, before them. The batch's headers are still judged first.
- **Content types** (§7.2, §12.1): batch, branch creation, remote registration, prune and
  `POST /keys` bodies need `Content-Type: application/json`. Media types compare
  case-insensitively and the only parameter allowed is `charset=utf-8`, for JSON Patch and JSON
  bodies and both edge-grant exchanges (core and tree service). Every `415` has code
  `unsupported_type` (it was `bad_input`), an E3 upload that isn't a sealed blob included.
- **Limits** (§6.6, §7.5, §12.2):
  - Step-4 limit refusals are **`422`** `limit` (they were `413`), with `limit`, `measured` and
    `max`: `patchSetSize`, `documentSize`, `valueSize`, `pathSize`, `itemsPerBatch`,
    `batchSize` and config-write limits. `413` stays for body cut-offs, `grantSize` and blob
    sizes. Tools that matched `413` should use `client.IsLimit`, which takes both.
  - A batch body is cut off at 4 × max(the principal's `batchSize`, the deployment maximum of
    `documentSize`), 64 MiB at the defaults, still `413 batchSize`. Config writes, namespace
    creations and branch bodies too large to read are `413` naming `documentSize` with the
    deployment maximum (they named `patchSetSize`).
  - Config writes, a batch's config change, namespace creation, branch creation and remote
    branch creation are held to `patchSetSize`, `opsPerSet`, `documentSize`, `nestingDepth`,
    `valueSize` and `pathSize` as resource writes are; a creation counts as a create.
  - For limits on the resulting document, `measured` is left out when the caller can't read the
    resource (for a namespace document, without unrestricted read).
  - **§6.6 Values holds every namespace**: a creation, a branch's, and a config write that
    changes `limits` or `encryption` other than its `epoch` are `422 limit patchSetSize` unless
    `3 × (valueSize + pathSize) + 1 KiB ≤ patchSetSize` (E3 adds `36 B × blobsPerDocument`). A
    namespace can no longer set `patchSetSize` at or below 1 KiB without lowering `valueSize` and
    `pathSize`. Stored documents aren't held to it, and epoch rotations go through.
  - **`grantSize` and `rulesPerGrant` are deployment only**: a namespace document that sets or
    changes either is `422 invalid`; documents stored with them still load and the values are
    ignored, and `/principal` reports the deployment's.
  - **An allowance `bucket` above the deployment maximum of `ratePerNamespace` is `422 limit`**
    (FEEDBACK F-L3 default), and stored ones are clamped to it. Deployments that give importers
    or load harnesses larger buckets (above 500/s) set the new `serve -max-rate-per-namespace
    RATE,BURST`; docs/CAPACITY.md runs the harness with `1e9,1e9`.
  - `rulesPerNamespace` counts every rule form, role and key-scope rules and nested
    `all`/`any`/`not`/`if`/`then` forms included, and holds a branch's creation as a namespace's.
  - Lowering a deployment maximum no longer makes existing namespaces fail ("stored namespace
    document is invalid"): stored limits, allowances and rule counts are held to the new
    maximums, and values a write keeps unchanged are held, not refused.
  - A key scope's `attrs` schema is compiled as a rule schema when the document is written:
    `422 invalid` at `/keys/{i}/attrs`, instead of a `403` on every request the key verifies.
- **Grants** (§2.1, §C.2–§C.5, §C.8):
  - A grant carries roles when any block lists roles; a narrowing block listing roles over a
    root without them leaves no effective role, so the grant allows no verb (the delegate kept
    the root's `can`). Only the root block's `can` is held to the key's (`403`); a narrowing
    block's verbs outside it are ignored.
  - `"*"` in `ns` outside an operator grant is `401` (was `403`), on every request and at
    `POST /edge-grants`, where an operator grant naming `"*"` is `401` too.
  - `maxTtl` is judged on the root block alone, `exp − max(now, nbf)`. Under a `requireAt` key,
    issuance is the later of the root's `nbf` and `exp − maxTtl`; a grant with neither fails the
    key scope (`403`) instead of counting as issued now.
  - A rule that doesn't compile (an unknown form, a pattern RE2 refuses) makes the grant
    invalid: `401` on every request that doesn't ignore the grant, `/principal` and edge-grant
    issuance included, before the `ns` check (it was `403`, and only when evaluated).
    `{ "op": "compare", "in": { "value": <not an array> } }` is valid and evaluates false
    (§6.4.2), in namespace documents and grants alike.
  - `rulesPerGrant` counts every rule form of the token's blocks, nested ones included, not
    key-scope rules, as the bearer is decoded: `413 { limit: "rulesPerGrant", measured, max }`
    before step 1 and the `ns` check (was `422` after verification, counting top-level rules).
  - A root block's revocation id is its grant id (§C.4); old root-signature ids in `revoked`
    still revoke.
  - The server stores a grant's authority SignedBlock alone, without narrowing blocks or proof
    (§C.3, §C.8); rows stored earlier are read and served as their authority block.
  - At `POST /edge-grants`, a role may test `/resource` when the grant fixes it, and then
    qualifies only if its rules pass for every name fixed (§2.1 Qualifying role, §C.5.2).
  - Services (`grantcheck`) take keys and revocations only from local bases, never a remote
    branch's base, and refuse tokens over `rulesPerGrant` or with a rule that doesn't compile
    when decoding them. `edge.Cookies.Check` gives no claims to a request carrying
    `Authorization` (§C.5.3).
- **Gate preconditions, retries and dry runs** (§6.2, §7.2, §7.5, §C.2, §12.1):
  - On a tombstoned resource a create (`If-None-Match: *`) is now **`410 gone` with `head`** (the
    tombstone) instead of `412`, and an append on another head and a `DELETE` are `410 gone`
    with `head` instead of carrying a `tombstone` member (§7.2, §8.1). Clients that read a
    create's `412` as "exists, restore" must handle this `410` too. The merge tool (re-classifying
    such items), the release lock, the importer (a batch failing at step 2.5 with any mix of
    such `410`s and `412`s is "the target moved … import again"; a `412` batch that lists
    another step-2.5 failure, such as a `428`, isn't), `client.Undo` and the playground's Undo /
    redo card (re-planning, as after a `412`, so a delete meanwhile is reported as a conflict),
    and the WebDAV gateway do.
  - A batch `"delete"` step right after another `"delete"` is `422 invalid` at step 2.5,
    reported with the other precondition failures in request order, instead of at step 3.
  - A batch item under `ifNoneMatch` whose first step is `"delete"`, and a `DELETE` with
    `If-None-Match: *`, get `428 precondition_required` after authorisation, whatever the
    resource's state; a purged namespace still answers `410 purged` first. Such a write has no
    usable precondition, so its signatures aren't checked: in a namespace with
    `"signatures": "required"` it gets the `428`, not `422 signature`, with or without one, dry
    runs included (§C.3.1).
  - A resource `PATCH`, or a batch item whose first step is a patch set, sent without a
    precondition is checked against `create`, `append` and `restore` at step 1 and then gets
    `428`: a create-only grant now sees `428` instead of `403` (§C.2 item 2).
  - A `412 stale` no longer carries `"head": null` when the resource has no head, nor does the
    `412` renewing a remote-branch registration with `If-Match` when none exists (§G.3).
  - **An idempotent retry needs the same root `sub` and the same signing `kid`**: a retry under
    another key with the same `sub` gets `412`. Entries written with authentication disabled
    still match on author. The same holds for config writes and branch creation (below).
  - A create's patches apply to the document `null`; a create that writes nothing (`[]`, or only
    tests) is still `422 invalid`, one that writes `null` stores the document `null`, as
    `add "" null` always did, and `[move "" -> ""]` and `[copy "" -> ""]` store `null` too, as
    they write `""` (§6.3). Stored histories read, archive, mirror and replay their genesis the
    same way (§6.2 step 3).
  - Step 4 checks a batch's local `source` (`422 source`) right after the batch limits, before
    any item's own limits, and a `source.origin` equal to this deployment's own is `422` with
    code `source`, not `invalid`.
  - A batch with a `config` change sets `X-Config-Revision` on its `201` and on its retry's
    `200`.
  - **Dry runs** (`?dry-run=1`): an item that would pass reports `status: 201`; a batch a submit
    would answer as an idempotent retry reports every item at `200` with its ids, and its
    `config` change as `{ status: 200, config }`; a dry run carries no `ns_id`,
    `X-Namespace-Revision` or `X-Config-Revision`. Its `config` change is reported as
    `{ status: 201, config: <id> }` on success; a failure after the change's step 1, the
    `*`-key guard and rules included, is reported as `{ status, code, … }`, the items judged
    against the current configuration, and only a step-1 failure answers as the config write
    would. Such a batch draws the same tokens submitted or dry-run once its items pass step 1:
    one per item, and one for the change unless a `*` key made it, so an empty bucket answers
    `429` to both (§6.6; F-G4 default). `patchlog merge plan`, the dry run before each release
    step and `patchlog import`'s dry runs fail when the config change fails after its step 1,
    with the error the submit would give (a stale merge config change used to show "dry run
    ok").
- **Config writes, namespace creation and branches** (§6.2 step 4, §7.4, §7.6, §C.2, Addendum
  E):
  - **Config writes validate before the limits and the `*`-key guard**: the namespace document a
    config write or a namespace's creation produces is validated first (members, `base`,
    `drafts`, levels, a base's `*` keys, a public branch, the base's nonce requirement,
    `successor`), then come the patch-set and document limits and an unfrozen branch's
    `branchesPerNamespace`; step 6 runs the `*`-key guard (`403`), then the `in_use` refusals
    (`409`), then the rules. A write without a `*` key that touches a guarded member and breaks a
    branch field now gets `422`, not `403`.
  - **Branch fields answer `422 invalid` with `errors`** pointing at the member (`/base`,
    `/base/at`, `/drafts`, `/encryption`, `/encryption/epoch`, `/keys`, `/read`, `/nonce`,
    `/successor`), at branch creation and in config writes, before the `*`-key guard. A branch's
    level is compared with its base's only at creation and on a raise to `e2e`.
  - **`successor` is checked only by a write that sets or changes it**: another namespace that
    exists and isn't purged; for a branch, a branch of the same base or of a namespace further up
    its base chain, as after a rebase onto a base up the chain (§F.4, §F.5), so `rebase -onto
    … -switch` up the chain now switches; for a namespace that isn't a branch, one that isn't
    either. A branch's creation whose patches set `successor` is checked the same way; a
    namespace's creation still refuses any `successor`.
  - **A namespace creation under a taken name is `412` without `config`**, as for a branch; an
    `If-Match` mismatch keeps `{ config }`.
  - **Operator grants need `config`** for a namespace's creation and for a taken name's `412`
    (§C.2 item 2, §C.4): one minted with, for example, `can: ["create"]` alone is `403`. The
    creating operator grant passes the `*`-key guard whatever its key's `can`.
  - **Branch creation** (§7.6): a taken name is `412` before an `at` outside the base's chain
    gets its `422`. A retry that omits `at` counts as naming the branch's recorded `at`, and
    matches on principal, `at` and `patches` only, judged against the base document in force at
    the creation (or the pre-v0.73 starting document, which kept the base's `cleanup`), so config
    writes to the base since then no longer turn it into a `412`. **`cleanup` is no longer copied
    into a new branch**; branches created earlier keep what they inherited, which the janitor
    still reads.
  - A namespace becoming sealed may start at any epoch (§E.2.1); only one already at `sealed` or
    `e2e` moves its `encryption.epoch` by one. An absent `epoch` still reads as 1, not §12.3's
    default 0, because existing sealed namespaces' epoch keys are numbered from 1.
- **Purges and prunes** (§6.1, §6.2, §6.6, §7.2, §8.3, §8.5, §8.6, §12.1):
  - **Security: going below what retention keeps needs a `*` key.** Retention keeps everything
    where no rule matches a resource, so a prune that moves the horizon there now needs a grant
    chained to a `*` key (`403`), whether or not an archive is configured; before, any holder of
    `prune` could drop all history wherever no retention rule existed. So does a prune that
    changes only the keep set and so drops documents retention keeps, such as those an earlier
    `*` prune kept (`keep: []` at the current horizon). A prune that moves nothing, adds to the
    keep set, resends the same set or drops only documents below what a matching rule keeps
    needs only `prune`.
  - **Keep sets:** a prune that sends `keep` replaces the resource's keep set, and `[]` clears
    it; one without `keep` leaves the set alone, and its documents stay as the horizon moves past
    them (a prune without `keep` used to clear it). A prune that changes only the keep set
    appends a `prune` entry targeting the effective horizon, with `X-Namespace-Revision`; one that
    changes nothing writes nothing. Outside a branch every `keep` id must be a revision whose
    document is still served (`422 invalid` otherwise), whether or not the horizon moves. The
    rule envelope's `doc` is `{ horizon, keep? }`, `keep` only when it was sent (§6.4.1).
  - **The prune answer is `{ "horizon": id }`** only: `archive` is gone, and the pruned
    revisions' `410` still links the archive.
  - **A prune in a branch** is no longer `422`: after its checks (verb, rate limits, purged
    namespace or resource, `428`, an unknown resource's `404`, the horizon in its ancestry, the
    rules) it moves nothing, ignores `keep`, writes nothing, needs no archive and no `*` key, and
    answers `200` with the resource's horizon as the branch sees it, else its genesis id. At E3
    the snapshot is still required and its header checked, so one sealed under a base's `kid` is
    `422` (§13 default).
  - **A prune's checks, in order:** one token each from the principal, namespace and
    per-resource buckets at the end of step 1 (`429`); the purged namespace's `410`, a remote
    branch's `502 upstream` (remote branches, below) and the purged resource's `410` (step 2.1);
    `If-Match` or `If-None-Match`, which a prune doesn't take, `428` at step 2.5, before an
    unknown resource's `404` and the horizon and keep checks; at E3 the `422` for an effective
    horizon other than the requested one and the snapshot's header (its `kid` included, see
    end-to-end namespaces) come before the `*`-key `403`.
  - **A resource purge** answers, in order: the verb; a purged namespace `410`; a purged resource
    `410 gone`, now before the precondition; a missing precondition `428`; a name never written
    `404`; a stale precondition `412` with `head`; then `in_use` and the rules (§8.3). **A
    namespace purge**: the verb; purged `410`; `409 not_frozen`, now before the precondition;
    `428`; `412`; dependents, then schema references, `409 in_use`; the rules (§8.5).
  - **`?force=1` under a grant that can't force is `403`** right after authorisation, before the
    `410`, `428`, `412` and `not_frozen`, even when the purge needs no forcing, for resource and
    namespace purges alike. A grant can force when chained to a deployment operator key or, for
    a purge in or of a branch, to a `*` key of that branch (§6.1).
  - **An operator-forced purge is judged by its grant's own rules (`403`), and by namespace
    rules unless it was forced past an `in_use` refusal** (§6.4.3 "Operator overrides"). Any
    purge authenticated with an operator grant used to skip every rule, so an operator grant
    whose block rules refuse a purge could purge, and an operator's `?force=1` on a purge that
    needed no forcing skipped the namespace's rules.
- **Read scopes, guard paths and allowances** (§6.6, §7, §7.4, §C.2):
  - **Key-scope failures are `403` outside resource URLs** (§C.2 item 1): a grant its key's scope
    doesn't allow (`readScope`, `sub`, `groups`, `maxTtl`, `requireAt`) gets `403` on `/ns/{ns}`
    and every URL under it in a private namespace, and on `POST /ns/{ns}/keys`. Reads of a
    resource URL keep the `404` that hides the resource. `POST /ns/{ns}/keys` in a public
    namespace no longer ignores the grant: one that doesn't name the namespace, or that its key's
    scope refuses, is `403`, one that can't be used, or none, `401` (it was `401` "missing
    grant").
  - **Branching and remote registration judge read roles by all their rules** (§C.2 item 2): the
    unrestricted read of the base still evaluates key-scope and block rules with the step-1
    filter, but a role that counts for read must pass all its rules against a read envelope, as a
    read does, so a role whose rule reads `/doc` or `/writes` no longer lets its grant branch or
    register a namespace it can't read.
  - **`/catalogs` and `/maxLag` need a `*` key** (§7.4): config writes and a branch's `patches`
    that cover or overlap either are `403` under any other key.
  - **Allowances**: the first matching entry whose `until` hasn't passed applies; an ended entry
    no longer hides a later one (with authentication disabled, entries match on `sub` alone).
  - **Rate-limit buckets are shared on Postgres** (§6.6 Cost): instances sharing a database draw
    on the same buckets (new table `rate_buckets` and function `rate_draw`, both created by
    migration `004_rate_buckets`), each draw one atomic statement that locks the buckets in key
    order and commits on its own before the write it admits can commit, so the instances
    together admit no more than a bucket's burst; an admitted write's deduction is never lost, and a request refused after
    admission keeps it. Each instance deletes full buckets once a minute, without waiting on a
    draw, and a draw rolled back as a deadlock victim runs again. SQLite keeps buckets in
    memory, and so does a single Postgres instance started with **`serve -local-rate-buckets`**
    (`Options.LocalRateBuckets`), which saves the draw's round trip. Cost measured with
    `cmd/capacity`: about +1.2 ms per write for one writer, and about 25% lower peak throughput
    for 32 writers on one namespace (a hot bucket's row lock).
- **Schemas written now follow v0.73's dialect** (§6.1, §6.2 step 5, §6.5, §6.6): `$id` in any
  subschema, root included, and `$schema` in any subschema but the root are `422 invalid` (`$id`
  was `schema_ref`); a `format` draft 2020-12 doesn't define is `422 invalid`, and `semver` and
  `period` are no longer asserted for such schemas; `idn-email` and `idn-hostname` are checked by
  UTS 46 processing; `definitions` is accepted as `$defs` is. Regular expressions (`pattern`,
  `patternProperties`, `format: regex`) read `\uXXXX` as a code point, join surrogate pairs and
  refuse lone surrogates. Schemas stored before the upgrade keep compiling and validating as they
  did (§6.1, invariant 3), also inside a new schema's `$ref` closure. A revision reached by any
  `$ref` whose path is a revision path counts as referenced, whatever its fragment, for `in_use`
  purges, the index's reference rows and bundle renames. **Each revision now records the schema
  rules it was written under** (migration `003_revisions_rules` adds `revisions.rules`; revision
  ids are unchanged): revisions stored before count as written under the earlier rules; a schema revision
  whose id rows of the namespace written, its local bases or a batch's local source already have
  (a fast-forward merge, a same-deployment import, a branch's replay) is a copy of them and keeps
  their marker, so core merges, imports and replays of stored schema documents are no longer
  refused by today's write rules; and a document is validated under the rules of the schema
  revision it names, each revision of its `$ref` closure compiled under its own marker, so schemas
  written now assert `idn-email` and `idn-hostname` while a revision stored before, reached
  directly or through a new schema's `$ref`, keeps its `semver` and `period` assertions and its
  patterns as RE2 took them. Documents from another deployment, namespace documents included, are
  judged by today's rules (§G.4.4; F-S3 default). **A schema revision read in the clear carries
  its marker** in a new response header, `X-Schema-Rules: v0.73` or `legacy` (an addition; sealed
  and e2e namespaces send none, and a server that sends none compiles every schema as `legacy`;
  `client.Doc.Rules`, `client.SchemaRules`). A remote branch's schema mirror keeps the marker its
  base serves each revision with, so a revision compiles alike on both (a base that sends none is
  mirrored as `legacy`, as before; F-S1). E3 clients validate a typed document, when sealing it
  and when a fold re-validates it, under each closure revision's served marker, as the core
  validates it; they used to apply the earlier rules to every revision, so `idn-email` and
  `idn-hostname` were never asserted at E3.
- **Blob uploads, copies and schema references** (§2.1, §6.1, §7.1, §7.8, §E.2.3, §12.1):
  - An upload or copy (`PUT …/blob/{bid}`) that sends `If-Match` or `If-None-Match` is `428
    precondition_required` at check 4, after authorisation, rate limits, purges, a frozen
    namespace and a copy's source checks. A `Blob-Nonce` that is present but empty, repeated or
    not 26 base32 characters is `400 bad_input` there; a blob without a nonce sends none.
  - Upload and copy answers, errors included, carry `X-Content-Type-Options: nosniff` and
    `Content-Security-Policy: sandbox`.
  - `GET …/blob/{bid}/e/{e}` outside sealed namespaces is `404 not_offered`, after the resource's
    read check and a purged resource's `410`, cached short.
  - **Copies rank the source and the target apart** (§2.1 Protection): a sealed namespace counts
    as private as a source whatever its `read`, and as public as a target when its `read` is
    `public`, so private content can no longer be copied into a public sealed namespace; a copy
    into another namespace of lower rank is `404`. Ranks don't apply within one namespace.
  - **Content from a sealed namespace needs keys that open it**, from the request's grant or one
    in `Source-Authorization`, under an epoch it is served under: without them a blob copy is
    `404`, within one namespace too; a batch's local `source` doesn't make such a blob available
    (`422 blob`); and a `$schema` or `$ref` revision is `422 schema_unavailable`, in the
    namespace written too. Grants without `nbf` get only the current epoch, so after a rotation
    they no longer open older content.
  - `422 schema_unavailable` names the revision that didn't resolve as `path` (`ref` still carries
    it, for one release). A `$schema` or `$ref` naming a branch is `422 schema_ref` only for a
    writer who can read the revision there, `schema_unavailable` for anyone else. `schemaReads.for`
    never matches a branch: a write to a branch qualifies only through the namespace at the root
    of its local bases, and documents in branches don't open schema revisions to their readers.
- **Rule evaluation** (§6.2, §6.4.2, §6.4.3, §6.6, §7.5, §C.2, §C.8):
  - **Step 6 runs grant, key and role rules (`403 forbidden`) before namespace rules (`422
    rule`)**, after the `*`-key guard and a config write's `in_use` refusals, for resource
    writes, config writes, branch creation, purges, prunes and remote registration, so a write
    that fails both is now `403`, not `422` (§6.2 step 6, §6.4.3, §C.2 item 4). In a batch each
    sub-step runs for every item before the next starts: the batch fails with the status of the
    earliest sub-step that fails and lists only the items that failed it (a batch whose item 0
    fails a namespace rule and whose item 1 a grant rule is `403 batch` listing item 1 only), and
    a dry run drops the items that fail grant rules and checks namespace rules for the rest.
  - **E3 rules are three-valued** (§6.2, `rules.EvalTri`): for sealed creates, appends and
    restores, whose `writes` and `doc` the server can't see, a namespace, grant, key or role rule
    fails as a whole only when its outcome depends on them; one that passes or fails whatever
    they hold is decided as usual, so `{ if: [action == delete], then: [test /doc/x] }` no longer
    refuses a sealed create (any rule that merely referred to them used to). A delete, of
    anything but the keyring, treats `doc` as unknown too, so a delete-scoped `not: test
    /doc/locked` fails as a whole (it was evaluated against `doc: null`), while rules on its
    `writes` (`[]`) are decided. A namespace rule that fails as a whole reports `path`
    `/rules/{i}`, the rule itself, instead of `writes` or `/doc`.
  - A failing namespace rule's `422` `path` is the JSON Pointer to the failing rule form in the
    namespace document, such as `/rules/3/then/0`, descending only through the first failing
    member of an `all` or a `then`; it was the pointer the failing leaf tested, such as
    `/doc/$schema` (§6.4.3).
  - `compare` with `lt`, `le`, `gt` or `ge` orders RFC 3339 date-times as UTC instants at the
    full precision of their fractional seconds; a leap second (`:60`) or a lowercase `t`/`z` is
    still an unsupported type, so the compare is false (F-G5 default).
  - **Rule `schema` fragments** written in a namespace document (in `rules`, role rules,
    key-scope rules and key `attrs`) or carried by a grant follow §6.4.2: no `$id`; no `$schema`
    in any subschema; `$ref` and `$dynamicRef` only to fragments of the same document; unknown
    keywords, and formats outside draft 2020-12's set, are invalid; `definitions` is allowed. A
    namespace document that breaks these is `422 invalid`, a grant `401`. Formats are asserted as
    draft 2020-12 defines them, `idn-email` and `idn-hostname` included, whenever a rule is
    evaluated: namespace rules from the configuration in force, key-scope and role rules, a
    grant's block rules and a key scope's `attrs`. Stored namespace documents compile their rules
    leniently, and a config write or branch creation that keeps an older rule unchanged isn't
    refused for it (F-S3 default); but a rule stored before v0.73 that names `idn-email` or
    `idn-hostname` is now asserted, where v0.55 ignored those formats, while stored rules keep
    asserting `semver` and `period` as before.
  - Regular expressions in rule schemas and in key-scope `sub` read `\uXXXX` as `\x{XXXX}`: a
    surrogate pair is one code point and a lone surrogate is refused. A config write that sets a
    key `sub` RE2 doesn't accept under that reading, such as `\x{D800}`, is `422 invalid` at
    `/keys/{i}/sub`; stored keys keep working (§6.6, §C.4; F-S4 default).
  - A bearer grant whose blocks contain a Unicode noncharacter is `401`; stored grants are still
    read as stored (§3.1, §C.8).
- **Reads: entries, heads, `/principal`, blobs** (§5, §7, §7.1, §7.4, §7.8, §8.3, §9,
  §C.3.1):
  - Resource and namespace log entries carry **`via`**, the delegatees of the grant they were
    written under, in order, unhashed: absent when there are none, sealed with the entry at E2,
    never recorded on entries the server writes itself, and mirrored by remote branches (§G.3).
    A new `ns_log.via` column (migration `002_ns_log_via`) stores it; entries written before
    have none (`LogEntry.Via`, `NSEntry.Via`).
  - **Breaking:** `GET /ns/{ns}/rev/{ns_id}/heads` answers `{ "heads": [...], "next"? }` instead
    of `{ items, next? }`. The client and playground still read `items` from older servers.
  - **A sealed `200`** of `/r/{ns}/{name}/rev/{id}` and `/ns/{ns}/rev/{ns_id}` has
    `ETag: "{id}.{e}"`, `e` the epoch of the stored sealing, and `If-None-Match` is compared
    with that tag, so `"{id}"` alone no longer gets a `304`. Head pointers keep `"{id}"`, and
    write preconditions still take the bare id (§E.2.2).
  - `GET /ns/{ns}/branches` of a purged namespace is `410 purged` with `head`, after the
    unrestricted-read check, in the long class (§8.5). The janitor and namespace followers treat
    it as having no branches; the release planner reports a release branch whose target is
    purged too as a `purged` conflict, and the janitor reports a superseded claim whose
    successor's base is purged as not verified, and a branch already purged as such.
  - Short answers (unknown-id `404`) and long ones (`410` of a purged resource or namespace)
    carry `Cache-Tag`/`Surrogate-Key` `ns:{ns}`, plus `r:{ns}/{name}` on resource URLs (§9).
  - **`GET /ns/{ns}/principal` adds** `key`, the RFC 7638 thumbprint of the verifying key, the
    same in every namespace; `operator`, true for operator grants (false otherwise and while
    authentication is disabled); and, for a namespace whose document has `catalog`,
    `catalog: { trust, files? }`, or, to a grant without unrestricted read (an operator grant
    outside public namespaces included), `files` without its `x-` members and `trusted` in place
    of `trust` (`PrincipalInfo.Key`, `Operator`, `Catalog`; §B.6, §C.4, §H.2, §H.7).
  - **Blobs of type `application/pdf`** are served with `Content-Disposition: attachment` (on
    `200` and `206`) and keep the sandbox; **`serve -inline-pdf`** serves their `200` and `206`
    inline without the sandbox, still with `nosniff` (`304` and `416` keep it). `text/*` blobs are
    served as `{type}; charset=utf-8`.
  - `…/raw` of a purged resource in a sealed or end-to-end namespace is `410`, before
    `not_offered`.
  - `GET /ns/{ns}/grants/{gid}` serves `stored` as one string, the authority `SignedBlock`, in
    the clear and sealed; a grant answer sealed by an earlier version, with `stored` as an array,
    is sealed again in the new shape, in the same epoch, the first time it is read.
  - **Purges a branch reads through** (§8.3, invariant 7): a branch created later at an `at`
    before a purge sees a name as purged only where it would read an entry for it through; there
    it answers `410`, and `/heads` lists it as `purge` with its head as of `at`. Any other name is
    `404`, isn't listed and can be created anew. A branch that purges a resource it reads through
    keeps it purged at every `ns_id` where it read an entry for it: its `/heads` lists it as
    `purge` with the head it read through as `target`, and branches of it, created before or
    after the purge and at any `at`, answer `410`, never the base's live content.
- **Live reads** (§7.3, §7.7, §8.5, §C.2, §C.5.3, §E.2.2):
  - **Long-poll:** a request without a cursor is answered at once, `200` with the entries after
    `since`, else `204` with the current `X-Cursor`, and so is one whose cursor is behind by an
    hour's worth of intervals or less; one further behind is `400 bad_input`, as one that far
    ahead already was. Clients that relied on a first request without a cursor waiting should
    send the cursor they were given. A resource with no entries waits as for an empty `since`,
    and its create wakes the request; a `204` for an empty `since` carries no `X-Revision` or
    `X-Namespace-Revision`; without `live` that URL still answers `404`, cached short.
    Followers (`internal/follow`) and `cmd/capacity` drop a cursor refused with `400 bad_input`
    and poll again (the follower used to stop).
  - **Event streams:** a resource stream without `since`, or with an empty one, on a resource
    with no entries starts and waits for its first entry; an unknown non-empty `since` stays
    `404`, a purged resource `410`. A namespace stream ends after its `purge-ns` event, and one
    whose `since` or `Last-Event-ID` names that entry sends the headers and ends; a follower
    restarted at that entry ends with `ErrPurged` (it used to reconnect or poll forever), and the
    playground's live namespace stream closes on that event. A stream judges its read check again
    before each page and each keep-alive comment, ending without sending anything when the check
    fails (a resource stream sent keep-alives without one), and ends at the latest when the grant
    (its earliest block `exp`) or edge cookie it was admitted under expires, even when idle.
  - **Breaking:** a resource stream's `purge` and `prune` events carry, as data, the namespace
    entry that records them without its `id` and `prev`, and have no SSE `id:` line, so an
    EventSource's `Last-Event-ID` stays the last revision and a reconnect no longer gets `404`;
    EventSource clients stop storing namespace entry ids from them. In sealed namespaces their
    data is a JWE under the resource's `K_r` of the current epoch, `pl { ns, name, kind }`,
    padded as the namespace pads, so a grant for that resource alone opens it (it was the
    namespace range under `K_e`). `client.ResourceEvents` opens it, and the older form from
    servers before v0.73, and gives these events no `ID`; the playground follows.
- **Sealed formats** (§E.2.2, §E.2.3, §E.3.1):
  - No JWE the server seals carries `zip`, whatever it binds; bytes stored with `zip: "DEF"`
    are still served and still open.
  - A sealed namespace document is bound to `pl: { ns, id, kind: "doc" }` (was `"config"`), an
    E3 prune snapshot to `pl: { ns, name, id }` without `kind`; readers still accept the old
    forms in stored bytes, but a prune whose snapshot carries `kind: "snapshot"` is now `422
    invalid`. The playground opens both forms.
  - **E3 keyrings:** keys are wrapped under the HPKE info `"patchlog-key-v1"` LF kid LF name
    (name empty for `K_e`). Entries of a keyring stored in the format before v0.63 under the old
    info still open: the client (`client.E2E`, and so services through `derived.Keys`) and the
    playground try the old info when the current one fails (`seal.UnwrapKeyLegacy`), for
    entries read in the keyring and relayed by `/keys` alike, and a relayed entry that opens
    under neither no longer stops a reader that may read the keyring from trying it. The server
    now requires the §E.3.2 keyring document, and such a keyring is migrated with `patchlog e2e
    migrate-keyring` (see `/keys` and the e2e keyring below).
  - The playground reads `/keys` entries as `seal.ParseWrappedKey` does: it refuses an entry
    whose `name` and `resource` differ, whose `suite` isn't the reference's, whose `from` isn't
    a thumbprint, or without a `kid` or `wrapped`, as `wrappedkeys.json` rejects them (§E.2.3).
- **`/keys` and the e2e keyring** (§E.2.3, §E.2.5, §E.3.1, §E.3.2, §9):
  - **Breaking for E3 keyrings:** the `keyring` resource of an e2e namespace must be the keyring
    document `{ "keys": [{ "kid", "to", "from", "wrapped" }] }` (nothing else but `$nonce`,
    entries of exactly those members, no two for one `kid` and `to`, kids of this namespace, no
    epoch after `encryption.epoch`); anything else, a keyring in the format before v0.63
    included, is `422 invalid`. Entries are wrapped in HPKE auth mode under the admin's X25519
    key and name recipient and admin by RFC 7638 thumbprint. `client.E2E` `InitKeyring`,
    `AddReader` and `RotateEpoch` write it under the view's own recipient key. A keyring stored
    in the old format is still relayed as stored until a key holder runs **`patchlog e2e
    migrate-keyring -ns NS -identity admin.jwk -reader pub.jwk…`** (`client.E2E.MigrateKeyring`;
    `-current-reader` for a reader of the newest epoch only), which wraps each epoch again only
    for the readers given, never the stored lists; the earlier remedy, `AddReader(ns, reader,
    true)`, no longer applies to an old-format keyring. A key holder that can't open every
    epoch, such as one added at a later epoch, migrates those it can with `-skip-unopenable`
    (`MigrateKeyringOpenable`; it must open the newest), which reports those left out, and can
    then rotate, so revocation works again; a left-out epoch's key is in the keyring's history
    only, and `/keys` doesn't relay it, until a holder of it runs `migrate-keyring` again, which
    puts it back from the keyring's last revision in the old format.
  - **Readers must know the keyring's admin key:** an auth-mode entry opens only with its
    sender's public key, so `client.E2E.WithSenders(adminPub…)` or
    `client.WithKeyringSenders(adminPub…)` (services: the client passed to `derived.Keys`)
    configures it; a view always knows its own key, and the playground its identity and the keys
    remembered with its new "Remember key" button. The services and tools take them as
    `-keyring-sender` (see end-to-end namespaces and New, below).
  - **E3 rebase** (§F.8.1): `merge.Rebase` no longer drops readers of the old branch silently.
    The successor's keyring wraps its key for `RebaseOptions.SuccessorReaders` (**`patchlog
    rebase -reader pub.jwk`**, repeatable), for the view's own key and for the old branch's
    readers whose keys the view knows; `RebaseResult.DroppedReaders` lists by thumbprint the
    readers of the old branch's newest epoch the successor's keyring lacks, and with `-switch`
    the rebase stops before replaying (`merge.ErrReadersDropped`) and the old branch stays in
    use, until it is run again with them named. A keyring read through from a base counts as
    none, so a base still in the old format no longer blocks rebasing its e2e branches; a branch
    whose own keyring is in the old format is refused, naming the namespace to migrate.
  - **`POST /ns/{ns}/keys` entries:** `{ kid, name?, from?, wrapped }`, or `{ kid, name?, key }`
    at E2 without `enc`; `name` replaces `resource`, `suite` is gone, relayed keyring entries
    carry `from`. Clients read both forms.
  - **`/keys` epochs:** from the epoch in force at the latest `nbf` among all the grant's blocks,
    a narrowing block's included; a grant with no `nbf` gets the current epoch only, so grants
    that need older epochs need an `nbf`. `historyEpochs: h` gives the current epoch and the `h`
    before it, and `0` (refused before, and read by services as no cap) the current only. Epochs
    that began after the grant's `exp` are no longer left out.
  - **Per-resource keys:** only a grant whose rules fix `/resource` (§2.1) gets `K_r`, by default
    for every name it fixes; a requested name it doesn't fix or may not read is `403`, and
    `"resources": []` asks for none. A grant whose role rules merely refer to `/resource`, without
    an unrestricted role that passes, is now `403`.
  - **`/keys` draws `exchangeRate`:** one token per request answered with keys (`429`,
    `limit: "exchangeRate"`); refused requests, an E3 one without `enc` included, draw none.
  - **E3 branches:** `/keys` relays the branch's own keyring and each local base's keyring as of
    `at`, even after the branch wrote its own, for the base's epochs up to `at` (without `nbf`:
    the base's current epoch, while it is still its epoch at `at`). A remote branch relays its
    source's keyring entries by the same rule, the request's `epochs` no longer narrowing them; a
    grant without `nbf` gets none once the source, or a deeper base of its `base.chain`, has moved
    past its epoch at `at`, which the follower learns from the source's log and each chain base's
    current document at every sync (§E.2.3, §G.5.2).
  - **After a raise from `sealed`** (Levels, §E.2.3): `/keys` at E3 gives the keys of the epochs
    before the raise as at E2, wrapped to the grant's `enc` in base mode, without `from`: `K_e` to
    a grant that reads the namespace unrestricted, `K_r` of the names it fixes and may read to one
    whose rules fix names, for the epochs of the grant's §E.2.3 window as at E2, with the last
    epoch and namespace document before the raise standing for the current ones (so a grant
    without `nbf`, or with one after the raise, gets the last epoch before the raise, as it did at
    E2, and the earlier ones take an `nbf` reaching back); what E2 would refuse with `403` is left
    out instead. A branch's `/keys` gives its base's pre-raise keys, `kid` and `K_r` naming the
    base, for the base epochs that window selects, which the request's `epochs` don't narrow.
    The server's own key checks for content from before the raise (schema resolution, blob
    copies, a batch's local `source`; §6.1, §2.1 Protection, §7.8) apply the same window, so
    they are never looser than `/keys`, and the grant that wrote a resource at E2 keeps reading
    and appending to it at E3. Readers open content
    with them; nothing new is sealed under them (no sender, §E.3.2) but a prune snapshot of
    content from before the raise, which the server held with its keys anyway.
  - **E3 gate** (§E.3.1): a sealed op or prune snapshot with `zip` in its header is `422
    invalid`; a write's sealed op must name the epoch in force, for batch items the one the
    batch's config change produces (`422 invalid`); a declared blob with a nonce is `422 blob`.
  - Sealed namespace log ranges are sealed under the current epoch (§E.2.2); stored ranges keep
    their bytes.
  - **Caching:** sealed and e2e namespaces are cached by read mode (§E.2.5, §9): with `read:
    "grant"` privately, with edge lifetimes only on reads a verifying edge verified. They used to
    be cached publicly: on the first open after upgrading, the server queues a purge of their
    `ns:{ns}` tags, which the leader sends with its second purges. Deployments that turn the
    second purge off (`RepurgeDelay` < 0) should purge those tags by hand.
  - **`-rotate-on-revoke`:** the rotation is recorded as due in the revocation's own
    transaction, for the namespace and every sealed branch below it, and retried every minute
    until a new epoch begins (any new epoch, an operator's config write included, clears it),
    instead of being only logged when it failed.
- **End-to-end namespaces** (Addendum E Levels, §E.3.1, §E.3.2):
  - **Raising to e2e:** an existing namespace may be raised to `e2e` from none, at-rest or
    `sealed` (a `*` key; the epoch must be at least 1, F-E1 default, and from `sealed` the current
    one + 1, as for any rotation). The server records the raise point (new table `e2e_raises`) and
    an `e2e_epochs` row, writes from the raising entry on go through the E3 gate, and any raise
    into `sealed` or `e2e`, `sealed` to `e2e` included, purges `ns:{ns}` (§9). What was stored
    before the raise stays usable: a schema revision written before it still resolves for
    documents elsewhere that pin it (only one written at e2e is `schema_unavailable`, §6.1), and
    `patchlog archive restore` checks each archived patch set by the level it was written at, so
    the history of a resource pruned before the raise, or archived by an E3 prune after it,
    comes back, is served as at the level before like the rest of it, and clears the horizon (it
    was skipped).
  - **Serving what came before a raise** (Addendum E Levels, After a raise; §7.1 Paging): the
    revisions, resource log entries, namespace documents and log ranges from before a raise are
    served as at the level before. After a raise from none or at-rest they stay in the clear, and
    `/rev/{id}` of a revision from before the raise serves its document instead of the fold
    redirect (without `Last-Modified` or `Repr-Digest`; a schema revision keeps `X-Schema-Rules`,
    so E3 clients validate under the rules the server resolves it with). After a raise from
    `sealed` they are served sealed as §E.2.2 says, each revision under the epoch it is served
    under (the one it was written in, else the last before the raise) with the `pad` setting
    before the raise, events and resource purge/prune events too, and a sealing stored at E2
    keeps its bytes; a purged raised namespace answers `410 purged` for them. No log page spans
    the raise: a namespace log page ends before the raising entry, a resource log page before the
    first revision written with or after it, and a page still holds one entry.
  - **Grants** first recorded before a raise from `sealed` stay sealed (`pl { ns, grant }`);
    later ones are served in the clear. Both forms are `Cache-Control: private` with
    `CDN-Cache-Control`/`Surrogate-Control: no-store`, in public namespaces too (§C.3.1, §9).
  - **Blobs** referenced by revisions from before a raise from `sealed` keep their `/e/{e}` URLs
    under those revisions' epochs only, `…/blob/{bid}` redirects to them with `302`, and they are
    never served in the clear; other blobs at E3 answer `/e/{e}` with `404 not_offered` (§7.1,
    §E.2.2). A schema revision from before a raise from `sealed` resolves (§6.1), and such blobs
    are copied or made available through a batch's local `source` (§2.1, §7.8), only with keys
    that open it under the epoch it is served under, as `/keys` gives them as at E2.
  - **Folds across the raise** (F-E1 default): the fold redirect of a revision written end to end
    starts at the latest prune snapshot or, if later, the resource's last revision from before
    the raise (its last live one before a tombstone). The Go client and the playground fold from
    that document, opening sealed pre-raise documents and entries with the keys of their epoch
    (`E2EDoc.PreRaise`, `E2E.Log`), and merge plans read e2e logs through the key holder's view,
    so a merge plans across a raise from `sealed` (MF-5).
  - **Branches of a raised base** (Levels, §7.4): creating a branch with an `at` before its base's
    `e2e` raise is `422` (`invalid`, `errors` at `/base/at`). A branch serves what it reads
    through from before the raise as the base serves it, the same bytes, `kid` and `pl` naming
    the base, and readers of an e2e branch accept the base's `ns` there for documents, log entries
    and blobs; they ask the branch's `/keys` first and then the `kid`'s namespace (§F.8.1), and a
    transient failure while reading the branch's base chain is reported as itself and isn't
    remembered. A prune snapshot of a base's pre-raise content in a branch is sealed under the
    epoch the base serves it under: `kid` and `K_r` name the base, `pl` the branch, as the server
    checks and `E2E.PruneE2E` seals it, with the key `/keys` gives as at E2 (§E.3.1).
  - **E3 prunes and restores after a raise** (§8.6, §E.3.1): a horizon whose document is from
    before the raise keeps that document and its stored sealing, and the sealings of pre-raise
    content pruned below it are deleted; a restore with `[]` may keep a pre-raise document's plain
    blob list (it was `422 blob`); other later writes still declare only sealed blobs.
  - **Trusted senders (breaking for keyrings stored before v0.63):** writers, prunes,
    `AddReader`, re-encrypted merges and services' derived views seal only under an epoch key
    whose keyring entry comes from a sender they trust, never under one without a sender: a key
    `/keys` relays without `from` or in the clear, or an entry of a keyring stored before v0.63,
    which the server could have wrapped itself. A view trusts its own identity and the keyring
    senders it knows (`WithKeyringSenders`, `-keyring-sender`), narrowed to those named once any
    trusted sender is (`client.WithTrustedKeyringSenders`, `E2E.WithTrusted`,
    `-trusted-sender`); reads still open every known sender's keys. Where the first key found
    isn't trusted, the client looks through the `/keys` relays and the keyring for an entry from
    a trusted sender; otherwise the write fails with `client.ErrUntrustedKey`, and services skip
    the namespace for want of keys. A namespace whose keyring is still in the format before v0.63
    needs `patchlog e2e migrate-keyring` before anyone can write to it or a service can seal its
    views.
  - **E3 content is sealed under `K_r`** = HKDF(`K_e`, "patchlog-e2", ns LF name), patch sets
    and snapshots alike, `ns` from `pl.ns`; readers try `K_r`, then `K_e`, under which existing
    ciphertext was sealed (§E.3.1). The playground follows.
  - **Prune snapshots:** a snapshot's `kid` must name the epoch set by the newest revision of the
    horizon's chain that isn't a tombstone and whose patch set isn't `[]` (its sealed op's
    epoch, for content from before a raise the epoch it is served under, otherwise the epoch in
    force), `422 invalid` otherwise, and the client seals snapshots so (§E.3.1).
  - **Folds:** a revision that fails validation, its declared blob list or its padding is flagged
    and still applied (it was left out); one whose patch set doesn't apply is flagged and folded
    as `[]` from its parent, and a genesis that opens but doesn't parse or apply folds as `[]`
    on `null`, where the read failed with "no valid revision". Padding is judged by the
    namespace document in force at each entry, a batch's by the configuration it produces.
    `OpenLog` and merges follow (§E.3.1).
  - **E3 branches** accept a base's namespace in `pl` or `kid` only for entries up to the
    branch's fork point, read from the base's `/heads` at `base.at`, in every log range a client
    opens (`OpenLog` places the forks against what the range follows); remote bases, and readers
    that can't read the base's `/heads`, keep the depth rule (§E.3.1).
- **Patch writes** (§6.2 step 3, §6.4.1, §F.3): an add, copy or move into an array below its
  length, and a remove or move-from of an element that isn't the last, also write the array
  itself, once per op, so rules on `writes`, merge and rebase conflict checks and undo see these
  writes. A create's patch set applies to the document `null` (`test "" null`, root replace,
  copy and move work); see gate preconditions above for what the gate makes of the result. Merge
  and rebase count the `from` of a branch's `copy` as a branch write.
- **Merge, rebase and releases** (§F.3, §F.5, §F.9):
  - Rebase creates the successor with the old branch's `read`, or `"grant"` where that would
    rank it lower (public < private = sealed < e2e; sealed and public ranks public), refuses to
    replay into a successor that ranks lower, and allows `-switch` up the base chain (§7.4,
    §F.5), refusing only a successor outside it; the core accepts such a successor since wave 2
    (config writes and branches, below).
  - A merger without unrestricted `read` on the branch copies the blobs its items reference
    into the target first, or uploads them where the copy is `404`, release steps included. At
    E3 a resource kept at a base head that references a blob a `sealed` op can't declare stays
    unmerged and is offered again.
  - Release plans: each branch's `base` must be the namespace it is keyed by or the earlier
    release's branch; the plan digest follows the spec's plan shape (F-F1 defaults: no gesture,
    undoes or signatures), so **plans stored or
    approved earlier but not yet merging are planned and approved again** (a merge already
    under way resumes under the step digests it was approved with); every batch's `source.at`
    is the branch's `ns_id` before the freeze; a split's halves must each change the node
    (`bad_split` otherwise).
  - The merge lock is `merge-lock.{catalog}` in the release document's namespace, `{ holder,
    plan? }` while held and `{}` while free; `-state-ns` no longer moves it. A `{ "release" }`
    lock an earlier version took is taken over by the resumed merge it names; any other is
    released by a person appending `{}`.
- **Janitor** (§F.6): a branch is purged as a state only under its own `cleanup` for that state
  (the base's only sets minimums), counted from the last config write that froze the branch or
  set or changed `merged`, `successor` or `abandoned`. **Branches that relied on their base's
  `cleanup` are now kept** ("no cleanup period … in the branch") until they set their own.
  `superseded` counts only successor batches whose grant's root `sub` and `kid` are in the base's
  current `merge.authors` or that are signed by a current `*` key of the old branch (verified
  against the stored grant), and every resource the branch changed must be merged or replayed
  (the closing rule). `abandoned` counts only if set under the branch's current `*` key, not
  merely its kid, from local bases only. A successor may sit anywhere up the base chain, as the
  core accepts it; one purged after the freeze is verified from its log. `Decision.FrozenAt` is
  the start of the cleanup period.
- **Catalog access** (§B.11.2–§B.11.5, §B.11.7): only a `user:` sub is a subject, groups are
  always `group:{g}`, and only the exact admin group counts as `catalog-admins`. A role counts
  only if the catalog's key in the content namespace may grant it to the caller, `sub` scope
  included; a `sub` scope adds the caller's `user:` subject to its listings' subject set (`gs`).
  Visibility evaluates each role's rules and the key's scope rules as a read would. Tree powers
  count only at live, acyclic folders through subjects the catalog's key may assert, and
  `catalog-admins` need none. Folders' roles compare by name in no-widening checks. A deleted
  placement's rows are kept until it is placed again or purged; one deleted before the upgrade
  has none, so only `catalog-admins` can re-place it.
- **Organising grants** (catalog service, §B.11.3, §B.11.4, §B.11.5, §B.11.8):
  - The answers come in the spec's order: malformed `400` (a Place, Move or Create a folder
    without `to` included); a node that isn't an untombstoned node of the catalog, or a `to`
    entry that isn't a live folder, `404`, and so is either one hidden from a caller not in
    `catalog-admins`, with the same answer and checkpoint as a missing node; failed requirements
    (place list, powers, an untrusted item namespace) `403`, then `409`. The `422` codes
    `not_folder`, `untrusted` and `not_placement` are gone.
  - A dangling placement is judged as if its item were live, and cyclic nodes are hidden. A new
    folder's name and a Place over a live placement stay `409` even when hidden. A non-admin
    can't move, unplace or delete a node with a parent hidden from it (`403`, naming nothing
    hidden), and a widening refusal at a hidden node names only the moved node.
  - Roots and an empty `to` need `catalog-admins`: anyone else gets `403` for `to: []` and for
    moving, renaming, unplacing or deleting a node without parents. Admins may give `to: []` for
    Place, Move and Create a folder, and the grant then fixes `/doc/parents` to none.
  - A Place of an item whose placement was purged is `410 gone`, without `checkpoint`; a live
    placement is still `409`. A Move whose `to` names the node or a node below it is `403`, not
    `409`.
  - **Breaking for clients:** a Move grant may change the node's other members, `$access`
    excepted, and a rename is a move to the current parents; unless the caller is in
    `catalog-admins`, it requires the patch set to begin with `{ "op": "test", "path":
    "/parents", "value": <answer.parents> }`, and refuses writes to `$access` itself, as a
    non-admin's Place grant refuses a placement document with `$access`. A Move grant expires at
    most the catalog's `maxLag` (default 60 s) after its decision.
  - `POST /grants` answers `parents` for a Move grant that pins them, and `head` (the node's head
    as decided) for Move and Unplace or delete, beside `ns`, `resource`, `can`, `roles`, `exp` and
    `at` (F-B8).
  - `want: ["delete"]` deletes folders too: it needs move on every parent, and the grant fixes
    `/doc/parents` to those parents by `href`. A tombstoned folder is `404`, and a request to
    restore a catalog node is `404` (`409` if it is live). An end-to-end catalog gets no
    organising grants (`404 not_offered`).
  - `checkpoint` names every namespace the decision read: a non-admin move's, and any decision
    judging a folder's visibility, names every trusted namespace, and so does a catalog folder's
    entry in `POST /read-grants`.
- **Catalog item answers and `/read-grants`** (catalog service, §B.11.4, §B.11.5, §8.5, §12.1):
  - **Breaking:** `POST /read-grants` answers `{ "items": [{ item, grant?, exp?, public?, keys?,
    keysWithheld?, status?, code? }], "checkpoint" }`: one entry per item in request order, a
    refused (`4xx`) or undecided (`5xx`) item with `status` and `code` (`message` as an extra,
    `head` on a `410 purged`), and one checkpoint over every namespace any decision read. The
    `grants` member, the per-entry `checkpoint` and the `error` object are gone; `exp` stays
    beside each grant (F-T3 default). An item whose keys can't be fetched yet is `503` with code
    `behind`, not `keys`. The WebDAV gateway reads both shapes.
  - A `/read-grants` item is refused as `POST /grants` refuses a read of it, counting only the
    roles that make it visible by the listing test: a role whose rules refer to `/now` or to
    other `/principal` members no longer yields a read grant, a hidden item is answered as an
    unplaced one (`403`), and the grant carries only the roles that make the item visible. A
    catalog node there is `400 bad_input` in a catalog that is neither sealed nor end-to-end, and
    a hidden one `404` (was `403`). A public sealed item comes back with its keys alone;
    `public: true` is only for public items that aren't sealed.
  - **Every name of a purged content namespace is `410 { code: "purged", head }`**, `head` its
    `purge-ns` entry, first among item answers, for creates, restores, other verbs and
    `/read-grants` items, also before the service has applied the purge of an unsealed
    namespace (a Create used to answer `409` "exists or existed"); a purged sealed namespace's
    document is no longer answered `410 gone`, and a purged item stays `410 gone`. Create a
    folder and Place in a purged catalog are `410 purged` too.
  - **Create** answers `410`, then `409` for a name that exists or existed, placed or not, then
    `403` (no placement, an untrusted namespace, no catalog key, no role kept). **Other item
    requests**: `410`; `404` for a name that never existed (was `403`); for a purged item `403`
    without a role counting for read at its placement, else `410`; `403` when no role is kept,
    with one message whether the item is unplaced, its placement dangles or no role counts.
    **Restore**: `410`; `404`; `403` without a role counting for read both at the placement now
    and, if deleted, in the frozen rows; `410` for a purged item, `409` for a live one (a reader
    without restore gets `409`, not `403`); `403` when restore isn't kept in both, there is no
    placement, or the restore would widen, so a role removed from the placement after the
    deletion no longer restores.
  - An item of a namespace the catalog doesn't trust is `403`, with the checkpoint, for read,
    create and restore and as a `/read-grants` entry, without the service reading that
    namespace's document; where the service's grant didn't cover it, it was `502 upstream`, an
    undecided entry clients retried, whose message named the service's grant scope.
  - **Create a folder** is `409` for a name that a `parents` entry or accepted `$parents` names,
    hidden ones included, decided at the checkpoint, so a dangling edge no longer re-attaches to
    a new folder (scenario 41).
- **Catalog merges** (`POST /merge-grants`, §F.8, §B.11.4, §B.11.7):
  - **Security: no batch that needs `catalog-admins` gets a merge-key grant, whoever approves.**
    A batch that changes `$access`, restores a folder or widens is answered as an admin dry run
    (`admin: true`, no grant), and only to an approver in `catalog-admins`; anyone else gets
    `403` (scenario 44). An admin approver's widening move used to get a merge-key grant.
  - A merge is checked as the approver's own organising requests would be: no widening at every
    node it reaches, not only below moved nodes (a new folder a dangling `parents` entry already
    names, a deleted node that breaks a cycle), and a re-placing compared with the deleted
    placement's kept rows; a node hidden from a non-admin approver, and a new or kept parent that
    isn't a live folder or is hidden, `404`; only admins make roots or move, delete or edit a
    node without parents or with a hidden parent; a node can't move under itself; refusals never
    name a hidden node. An item that changes a node's parents needs `move` on every parent it has
    afterwards, kept ones included. A new folder whose name a `parents` entry or accepted
    `$parents` names is `409`, for admins too. A purged placement (`410`) or purged folder name
    (`409`) is answered after the approver's `404`s and `403`s, without a checkpoint; a
    non-admin restoring a tombstoned folder gets `404`; a placement in an untrusted namespace is
    `403` even where the service can't read it. A batch's create applies to `null` as the core
    applies it.
  - **`Admin-Authorization`:** an admin dry run is also judged with the admin whose grant the
    batch goes under as the caller (F-T4 default). The merge service sends its admin grant
    (`ReleaseOptions.AdminGrant`) in this header after an `Admin` answer; answers carry
    `checkedAs`; a non-admin grant there is refused after the approver's `404`s and `403`s.
  - **An end-to-end catalog** gets no merge grants and no batch check: `404 not_offered`, before
    the merge-key check, so its catalog service may run without `-merge-key`. The merge service
    judges such a catalog's batches itself, with its keys: those that need `catalog-admins` go
    under its admin grant (narrowed with its `via`) without the service's dry run, others are
    refused.
  - Go API: `merge.MergeGranter.MergeGrant` takes an `adminGrant` argument, and
    `catalog.IssueMerge` the admin's verified grant.
- **Tree listings** (§A.4, §A.5, §B.2, §B.5, §B.9, §B.11.5, §H.3, §12.1):
  - A visible node whose parents are all hidden is a root for that subject set (`roots`, and
    the ends of `ancestors` and `where` paths); `where?item=` naming an item not in the catalog,
    or whose placement is hidden, is `404`.
  - `children` pages as `/_refs` does: `next` is still the following page's query, with an
    opaque `after` (`{pos}~{at}~{last}`), pages are kept at their `at`, a `next` sent back as
    `after` continues, and a `limit` above 1000 is `400`. The v0.55 `after={order}` cursor with
    `name`/`unordered` is accepted for this release.
  - Sibling `order` keys compare by UTF-8 bytes; an explicit placement wins over `$parents`
    whether live, deleted or purged.
  - A refused `min` is `400` with `min` listing the refused values; a `min` naming a namespace
    held as purged counts as reached. The `503` while keys can't be fetched yet has code
    `behind`.
  - The tree service's database gains `born` and explicit-placement records; on the first start
    it fills them in beside the followers, a few logs at a time.
- **Tree access** (tree service, §B.5, §B.11.5, §C.5.2, §C.8, §E.2.6, §12.1):
  - **Breaking:** while the catalog and every namespace in the combined checkpoint are public,
    listings are served unfiltered at `/{catalog}/at/{at}/…` to everyone, and a grant is
    ignored; any other listing lives only under `/{catalog}/g/{gs}/…`, and a request with
    neither a grant nor a cookie the service verifies is `401`. The anonymous filtered listing of
    a public catalog that trusts a private namespace is gone.
  - A grant in `Authorization` reads only at its own `gs`, or at `all` where it qualifies; at
    another `gs` it is `403`, never redirected. URLs without `/g/{gs}` still redirect, now with
    `Cache-Control: private, no-store`. New head pointer `GET /{catalog}/g/{gs}/{op}` under the
    edge grant's prefix, redirecting to `/{catalog}/g/{gs}/at/{cur}/{op}` (`403` at another
    reader's `gs`).
  - **Without §B.11 (no `-access`)** the service serves only `g/all`, to readers whose grants
    would be issued namespace-wide edge grants; other grants are `403`, so plain tree services,
    release previews included, lose filtered listings; the WebDAV gateway then lists the folder
    from the node documents where the grant reads them (F-T6).
  - `g/all` requires grants that would be issued namespace-wide edge grants for every namespace
    in the combined checkpoint that isn't public, so a block, key or role rule on `/now`
    disqualifies a grant even while it passes; with a public catalog the grant needn't name the
    catalog. `problems`, `orphans` and manifests keep §2.1 unrestricted read, judged per request,
    over the trusted namespaces in the combined checkpoint (a trusted namespace the service can't
    follow no longer makes them `403` for everyone), and are `403` under a subject set's cookie.
  - A `503 behind` has a generic message, and its `ns` member names the awaited namespace only to
    readers with unrestricted read of the catalog. A catalog whose keys the service lacks is
    `404 not_found`, and one whose keys it can't fetch yet `503 behind`; the code `skipped` is
    gone. A followed namespace raised meanwhile to a level whose keys a service lacks as
    configured (to e2e without `-enc-key`) is skipped and unfollowed when the raise is applied,
    in the index and the tree service alike, so its queries are `404` at once, as after a
    restart, instead of `503 behind` forever.
  - A sealed catalog's listing is sealed whole only for `g/all` of a catalog that isn't public,
    per entry otherwise; whole listings earlier releases stored elsewhere are dropped at start.
  - `exchangeRate` buckets are shared by every instance on one `-db`, with an atomic
    check-and-draw.
  - A grant over `grantSize` or `rulesPerGrant` is `413 limit` naming the limit, on listings,
    `/read-grants` and the exchange, as the origin and the catalog service answer it; it was
    `401` (F-C3 default). Exchange bodies refuse noncharacters (`400`), and a body over 50 grants of
    `grantSize` is `400 bad_input` before it is parsed; it was `413`.
- **Index queries** (§A.1, §A.2, §A.4, §A.6, §E.2.6, §12.1):
  - **Breaking:** `counts=/a,/b` is one comma-separated value (a repeated `counts` is `400`),
    answered as `counts: { "<path>": { "<value>": <hits> } }` by string form (F-I2 default:
    JSON Pointer tokens with commas can't be named); every query
    pages as `/_refs` does, `next` being the following page's `after` (a resource name, or an
    opaque position with `q` or `sort`), not a URL.
  - A sealed or e2e namespace whose keys the index lacks is `404`, like one it doesn't follow,
    and a `min` naming it `400`; one whose keys can't be fetched yet is `503 behind`. The
    `skipped` and `keys` codes are gone (F-I3 default for what lack of keys covers).
  - `facet[…]` and `counts` paths must be marked `facet`, `sort` and range paths `sort`, by a
    schema of a document the reader may see (`400` otherwise).
  - Values are collected by a static walk through only the keywords that mark a path, whatever
    the document's validity; only strings, numbers and booleans are collected, `text` strings
    only (F-I5 default). A document sorts by its least value at the path in either direction
    (F-I6 default), numbers, then strings by bytes, then booleans, missing last; hits show every
    sort value as `"<path>": [values]`, and the `gt`/`ge`/`lt`/`le` extensions need a `sort`
    mark and compare the least value; with `q` and `sort`, score no longer breaks ties.
    `schema=` matches an exact `$schema`, or `/r/{ns}/{name}` for its revisions. A document
    whose schema answers `403`/`404`/`410` or can't be opened for want of keys is indexed as
    untyped.
  - The index database is rebuilt from the logs once on upgrade (`user_version`).
- **Index access** (§A.1, §A.4, §A.5, §B.11.5, §C.8, §E.2.6, §12.1):
  - A `400` for refused `min`s lists every one refused, as given and in order, malformed ones too,
    in the body's `min` (`{ code: "bad_input", message, min: [...] }`, `no-store`), with one
    message whether the namespace is hidden or unfollowed; every bare `min` on `/_refs`, and two
    different bare `min`s on a query of one namespace, are listed too. A bare `?min={ns_id}` is
    given at most once; identical values count once.
  - On `/_refs`, a `min` naming a purged namespace the service follows counts as reached and
    redirects to the current `at`, without a read check. A `min` naming a followed namespace
    whose keys the service can't fetch for now is `503 behind` at once, on single-namespace
    queries and on `/_refs` alike, to a reader who may see it. On a single-namespace query a
    `min` naming another followed namespace the reader may see is still waited for and then
    redirected (the v0.51 behaviour), pending F-I1; the strict `400` sits behind `strictMins`.
  - **Private result URLs change once:** results are served under `gs = SubjectSetID([marker])`,
    as `/_refs` computes it: `reads:{ns}` for a grant that would get a namespace-wide edge grant,
    else `reads:{ns}:scope:{digest}`, so readers of a whole namespace share one `gs` whatever
    their groups. A grant whose block, key-scope or read-role rules refer to `/now` finds the
    namespace unreadable: `403` on a query of it, and `/_refs` leaves it out.
  - A grant at another `gs`'s `at` URL is `403 forbidden`, `no-store`, never redirected; a
    request there without a grant the service verifies is `401` with `WWW-Authenticate: Bearer`
    on `/_refs` too. Only the head pointer and `at` URLs without `/g/{gs}` redirect into the
    reader's `gs`, and redirects decided by a grant are `Cache-Control: private, no-store` (was
    `private, no-cache`).
  - A grant over `grantSize` or `rulesPerGrant` is `413 limit` naming the limit, on a query of a
    private namespace and on `/_refs`, as the origin and the tree and catalog services answer it;
    it was `401`, and `/_refs` answered only the public namespaces (§C.8, §C.6).
  - A hit's `score` depends on its document alone: each word counts `tf·2.2/(tf+1.2)` (BM25's
    term weight, fixed idf). Scores no longer change with other namespaces or hidden documents,
    and their values differ from before; a word of one token takes its term frequency from the
    FTS5 index, at about the cost of v0.55's ranking.
  - Any resource purge purges `idx:{ns}` (CDN, second purge, kept and stored sealed results,
    `/_refs` answers), so every cached result of the namespace goes; the `idx:{ns}:counts` tag
    is gone. A followed namespace that turns private, or is raised to sealed or e2e, purges
    `idx:{ns}` and drops its kept and stored sealed results; each private or sealed namespace
    gets one such purge when the index first applies its document.
  - Whole-response sealing only for a private sealed namespace read whole: a public sealed or e2e
    namespace's results are JSON with each hit sealed per entry under `K_r`, and `counts` there is
    `400`. Opening the index drops results stored sealed whole at a public URL before v0.73,
    which were served until the namespace's checkpoint moved.
- **Derived values and epochs** (index and tree services, §E.2.6, §E.2.2):
  - Values derived from sealed and e2e namespaces are sealed under the epoch their source revision
    is served under (the `kid` of the sealed document at E2, of the sealed op at E3, of the
    document served sealed as at E2 for content from before a raise from `sealed`), not the epoch
    current when the view is sealed. A result or listing is sealed whole only when every value
    comes from one epoch, otherwise per entry, and index `counts` over several epochs are `400`;
    a file tree's file metadata (`{ "sealed": JWE }` of `{ "file": … }`) is sealed under the epoch
    of its item's head.
  - **Services need older keys:** to seal views over revisions from before a rotation after a
    restart, the service's grant needs an `nbf` reaching back before those epochs (§E.2.3). Without
    one the index answers `503 behind`, and the tree service shows the nodes served under an epoch
    it can never get by name only, with no `sealed` values; a key it can't fetch for the moment is
    `503 behind`, only for listings that show such nodes, and is fetched outside the graph lock.
  - **Services past a raise from `sealed`** (Levels, §E.2.6, §E.3.2): a service whose view of
    the namespace already says `e2e` (after a restart, or once it followed the raise) takes the
    key of an epoch before the raise as a sealed namespace's, from `/keys` without a sender, for
    an epoch older than the current one that the keyring names no key of; the server held that
    content and its key before the raise. Keyring epochs still seal only under keys from a sender
    the service trusts. Index queries and tree listings over pre-raise documents no longer stay
    `503 behind` after a restart. A failure to get a key that lasts until the configuration
    changes is answered again for a second, and a `429` until its `Retry-After`, without asking
    `POST /ns/{ns}/keys` anew, so a query no longer spends the service's `exchangeRate`.
  - **Upgrade:** an index database that follows a sealed or e2e namespace is rebuilt once, to
    record each document's epoch. A tree database reads in, on start, the epoch each node head
    and each sealed item's file metadata is served under; heads it can never read keep sealing
    under the current epoch, as before.
  - A rotation that leaves the service out of the new epoch's readers (§E.2.4) skips the
    namespace, as a raise whose keys it lacks does: the follower stops and queries are `404`. The
    index applies the same check to branches it follows with their base (`-branches`).
- **WebDAV gateway** (§H.1, §H.4, §H.5, §H.7): a `MOVE`'s `If-Match` names its source (`412`
  when stale, before anything is written; for a folder, the folder node's head, F-H1 default);
  the writer's own uploaded bytes are served under `W/"{id}"` (F-H2); a raw save is always
  stored with the uploaded bytes or refused (re-saving an unchanged old version over someone
  else's change is `409`); a `DELETE` without a tag deletes the head it read; an `If-Match`
  that isn't an entity tag is `412`; types follow §H.1's order, with `text/` types needing
  UTF-8; a save over a file moved away is `409` naming its new path; expired records count as
  evicted (F-H3 default: per document); dangling placements the grant can't delete are
  orphaned rather than failing a folder `DELETE`; `VerifyEvery` above five minutes is refused.
- **WebDAV moves, copies and names** (§7.2, §7.8, §H.2, §H.5, §H.6):
  - Folders can be copied: a COPY of a tree folder makes a new folder titled with the
    Destination's last segment, without the source's `$access`, then copies its visible children
    one by one (an app's scratch folder in it as a scratch folder, before the folder's files);
    `Depth: 0` copies the folder alone. A folder MOVE to another file tree makes the folder there
    and moves its visible children one by one, files as moves across trees naming their copies
    in `$successor`, and deletes the source folder once empty. A part-way failure leaves what
    was done and is answered as that child's. Onto an existing folder or a file either is `403`
    (`412` with `Overwrite: F`). Until §B.12 is settled, a folder that carries `$access` or sits
    under one is not copied or moved to another tree (`403`, the F-H12 default).
  - A COPY or MOVE of a file onto an existing folder is `403`, not `405` (`412` with
    `Overwrite: F`). A refused COPY of a file sets the 10-second guard, onto an existing file and
    to another case of a sibling's name alike.
  - **A served file tree's `catalog.files.ns`, if also served flat (`-ns`), is read-only there**:
    PUT, DELETE, MKCOL and LOCK in it, MOVE into or out of it and COPY into it are `403`; its files
    are still listed, read and copied out. Deployments that wrote to a tree's content namespace
    through the flat view must write through the tree. The rule fails closed: until a user whose
    grant reads a served catalog's settings opens its tree, writes in every served flat namespace
    are `403`, saying why.
  - Placements of items in namespaces the catalog doesn't trust are left out when a tree is
    listed from its node documents too, and a folder's DELETE deletes them first as dangling
    placements.
  - A create the core refuses with `410 gone` (the name tombstoned meanwhile, as cores answer it
    from v0.73) is written over the tombstone: a move restores the name, a new file the
    tombstoned resource; a `412` keeps meaning "made meanwhile". A raw file written over a
    tombstone whose restore the core refuses is answered as that write would be.
  - A PDF (stored type exactly `application/pdf`) is served on `200`/`206` without
    `Content-Security-Policy: sandbox`, still with `nosniff`, and as `Content-Disposition:
    attachment` unless **`patchlog dav -inline-pdf`**.
  - Scratch files now also include LibreOffice lock files (`.~lock.*#`), vim's `*.swo`/`*.swx`
    and `sed -i`'s `sedXXXXXX`: kept in the gateway and never written to the core; an existing
    file of such a name stays a real file.
  - File and folder titles may hold any `Cf` character except the bidirectional controls
    U+202A–U+202E and U+2066–U+2069 (joiners, soft hyphens, LRM/RLM), shown unescaped. The
    seeded `drive` catalog's title rule follows.
- **WebDAV users and trees** (§H.2–§H.5, §H.7, §B.5, §B.11.4, §B.11.5):
  - **A gateway's user is the root sub with the key** `GET /ns/{ns}/principal` names by
    thumbprint (`key`), whichever namespace or kid verified the grant, so after a key rotation
    the person is a new user, with none of the old one's records, temporary files or locks; a
    core before v0.56, which names no key, keeps the (namespace, kid, sub) user. Operator grants
    are `403` (was `401`), as `/principal`'s `operator` says, and the refusal is cached. In
    `-gateway` mode over a core with authentication disabled, the Basic user name is the
    `X-Author` of the user's requests and keys the user; whether authentication is disabled is
    read again every `VerifyEvery`, and after the core refuses an `X-Author`. Over such a core no
    tree is tree-derived (below), since a user has no grant a catalog service could issue
    against: files are read and written as the user's `X-Author`, in local mode too (`-author`),
    as through a plain tree service (they were `401`, or `502` in local mode).
  - A user's own entries (§H.4 "Others' writes") also include log entries under the user's sub
    and a kid naming their key, or the catalog's key in a tree with tree-derived access, and,
    with authentication disabled, entries with the user's `X-Author`.
  - **Tree service:** a folder whose `children` `total` is over the listing bound is refused at
    once with `403`; duplicate titles are numbered by the listing's `born`, with no log reads;
    paths that only read resolve with one `lookup`, the folder listed instead for numbered or
    escaped names, another case in a case-sensitive gateway, and users whose writes it is
    waiting for. Where `files.root` is hidden from the user, the top level is the tree service's
    `roots` (over the bound, `403`): a new file or folder there is `404`, and a top-level node's
    rename, move or delete `403`. A tree's settings (`catalog.files`, `trust` or `trusted`) come
    from the token's own `/principal`, never from another grant's read. A tree service without
    §B.11 that refuses a limited grant (`403`) has the folder listed from the node documents
    where the grant reads them, else a `403` saying why. The tree service client has its own
    connection pool.
  - **Tree-derived access** (the tree service is a catalog service): writes and item reads go
    under the catalog's grants. A new file is placed first, then created with `If-None-Match: *`
    under the Create grant, and the placement is deleted if the create fails; a rename or move is
    one append under a Move grant whose patch set begins with the `/parents` test (a stale test
    is `409`, asking for a reload), made only from the folder the path names (`404` when the
    catalog's decided parents no longer hold it); placements and folders are deleted under
    Unplace or delete grants, and folders made under Create a folder grants. A grant that can't
    read the node documents keeps the listing's names, checked against the node's own document
    where it can be read (`404` when stale), deletes no folder (`403`), moves a folder only after
    reading the folders above the destination (`403` when it can't), and unlinks one path of a
    file placed in several folders from that folder only.
- **Archives of encrypted namespaces are sealed bundles** (§8.6, §G.5.1.1, §8.3, §E.1): in
  at-rest, sealed and e2e namespaces each pruning archive is a sealed bundle
  (`application/vnd.patchlog.sealed-bundle+jsonl`), one per resource, whose only recipient is the
  resource's archive key, an X25519 key derived from its data key (HKDF-SHA256, info
  `patchlog-archive-key-v1`) and named by its thumbprint, so purging the resource destroys it
  with the data key. Lines are padded where the namespace sets `encryption.pad`, and are written
  and read without the sealed-bundle reader's 256 MiB line bound, so attachments of any size
  `-max-blob-size` allows restore. Archives written before, in the chunked `PLAR\x01` format,
  stay readable by `patchlog archive restore`. Tools that read archive files directly now see
  sealed bundles: `Engine.ArchiveIdentity` gives the key that opens them (e.g. with
  `bundle.Unseal`), and `Engine.ArchiveReader` and `Engine.ReadArchive` replace
  `Engine.OpenArchive`, which reads only the old format.
- **Bundles** (§2.1, §G.4.1, §G.4.4, §G.5.1):
  - With `"authors": true`, history lines carry `via`, the delegatees of the grant the revision
    was written under (absent when none), in exports and pruning archives; a bundle without
    authors whose line carries `via`, or a `via` that isn't a non-empty array of non-empty
    strings, is rejected. `via` isn't hashed, and imports don't carry it into their steps
    (§7.1).
  - Readers reject a blank line, a line that isn't byte for byte its canonical JSON, or a last
    line without its 0x0A, and digest the bytes as written: hand-edited or pretty-printed
    bundles no longer import.
  - Sealed bundles mark the last line inside `pl` (`{ bundle, line, last: true }`); earlier
    readers reject them, while bundles from earlier versions still read. Readers strip padding.
  - Grant lines carry `stored` as one string, the authority SignedBlock; older arrays read as
    their first element, but earlier versions can't read new bundles that include authors.
  - Import refuses at step 1 a bundle from another origin than the imports that wrote an
    existing `{ns}-upstream`; ranks a sealed target with `read: "public"` as public, so it now
    needs the target's keys before planning; refuses e2e lines other than one sealed op naming
    the namespace or a restore's `[]`, and an existing target whose keyring history differs.
    e2e imports move the target up one epoch at a time, each raise in the batch with its keyring
    line (atomic mode is atomic per epoch), and existing targets below the bundle's highest
    epoch are no longer refused.
  - An e2e bundle whose keyring history holds a revision in the format before v0.63, or a
    keyring line that isn't a keyring document, is refused at step 1, before anything is
    written, with the reason (§G.5.1, §E.3.2). **Such history can't be imported at all**, since
    migrating the keyring at the source leaves its earlier revisions as they are: e2e backups of
    namespaces whose keyring was ever stored before v0.63 can't be restored by bundle import, and
    only a client holding the keys can carry the content over, sealed again with new ids.
  - The importer counts the `from` of each `copy` on the bundle's side when looking for
    conflicts, as a merge does for a branch (§F.3, §G.4.4), and accepts a dry run's `201`.
  - Export refuses to write unsealed, unless `Plaintext` (`-plaintext`) or `Recipients` is
    given, an e2e namespace whose exported history from before it became end-to-end is sealed
    content, as after a raise from `sealed`, or plaintext of a namespace whose `read` isn't
    public (§G.5.1, §2.1, Levels): the exporter's client opens that history, so the bundle
    carries it in plaintext under access `e2e`, as it refuses for a sealed namespace.
- **Remote branches** (§G.3, §G.5.2, §12.1):
  - **Breaking:** a creation that fails at the base's deployment answers `502` with code
    `upstream` (was `remote`) and `origin`; what the base answers for its own URLs at creation
    (`401`, `403`, `404`, another `4xx`), and keys this deployment can't get, are `422 invalid`
    (`422 schema_unavailable` for a schema namespace answering `401`/`403`).
  - **Breaking:** the genesis must give `base.chain` (`422` at `/base/chain` before anything
    is fetched) and is no longer rewritten, so the config id is that of the genesis as sent.
  - A schema mirror starts as exactly `{ "read": "public" }` or `{ "read": "grant" }` by its
    source's protection, and one that ranks below its source, is end-to-end with history to
    write, is frozen (`409 frozen`) or purged (`410 purged`), or holds the base's history purged
    (`410 gone`), refuses it. `409 name_conflict` is only for a branch or a different history.
  - Creation is judged against the base's current namespace document; an `at` before an e2e
    base's raise, and an e2e base's chain naming the branch, are `422`. The creating operator
    grant must allow `config`. Registration retries answer `200` only while the latest
    registration is unexpired, and "same principal" is the root `sub` and `kid`, or the author
    when no grant was recorded.
  - **Remote branches follow their base's level** (Addendum E Levels): a config entry in the
    base's log that raises its level makes the deployment raise the remote branch's local
    branches, leaves first, then the branch itself, by config writes of its own (author
    `system:remote`, no grant), sealing what the branch reads through as a local raise does and
    removing `schemaReads` at `sealed`. A raise to `e2e`, which Levels refuse a branch whose `at`
    is before the base's raise, is recorded and the branch marked for a rebase; where the branch
    missed the base's raise to `sealed` before it (the follower before v0.73 skipped config
    entries), it first raises, local dependents first, to the level the base had just before the
    raise to `e2e`, read only from the base. A base whose
    `read` stops being public makes a public remote branch, and its public branches first,
    `read: "grant"`. These show as `config` notices in `RemoteNotices`; what couldn't be followed
    is in the new `Engine.RemoteLevels` (table `remote_levels`).
  - **Remote branches of a source raised from `sealed` to `e2e` before `at`** (§G.3, §G.5.2,
    MF-37) can be created where creation answered `502`: the deployment mirrors the history from
    before the raise, fetches the keys of the epochs before it from the source's `POST
    /ns/{ns}/keys` with the endpoint's grant (which needs `enc`, and an `nbf` reaching back for
    any epoch before the last one before the raise) and their start times only from the source's own log, records the epoch each mirrored
    entry is served under, and gives those keys as at E2, named for the source. It serves what it
    mirrored from before the raise as the source does: sealed under that epoch, `kid` and `pl`
    naming the source, never in the clear. A prune snapshot in the branch of such content is
    checked against that epoch, and the refusal names the source, not the internal shadow.
    Purging the branch destroys the source's keys it held (§8.5, §E.2.4).
  - **`502 upstream`** (§1, §6.2, §7.8): on a server without a key store, which offers no
    encryption level, a remote branch whose base is raised to any level answers `502 upstream`,
    with `origin`, for every resource the base had at `at`, read through or written on since,
    and so does every local branch reading through it. Writes other than purges (prunes, blob
    uploads and copies included) get the same `502` at step 2.1, before the idempotent-retry
    lookup; a resource purged since stays `410`, purges still work, and namespace listings
    still answer.
  - **A config write that makes a remote branch public, raises it to `e2e` or turns off a nonce
    requirement** is judged by the base's current namespace document, read for that write
    outside the write lock (an `e2e` raise also needs the base's raise to lie before `at`), not
    by what the base was at creation: refusals are `422 invalid` with `errors`; a base that
    doesn't answer `502 upstream`, any other unreadable base `422`, and one purged whose
    documents can't be read `410 purged` with `origin`, `ns` and `head`, as at creation; nothing
    is applied. Batches with a config change, dry runs included, are judged the same way (§7.4).
  - **Breaking:** `-remote-ignore-purges` and `RemoteOptions.IgnorePurges` are removed: a
    deployment that sees a remote base's purge always applies it (§4, §G.3);
    `-remote-follow-interval 0` stops following bases altogether.
  - **Upgrading:** remote branches created before this version read their base's namespace
    document once more on the first follow after the upgrade, as of the follower's checkpoint
    (migration `010_remote_catch_up`, table `remote_catchup`), since the earlier follower
    moved its checkpoint past config entries unread and so never followed a raise or a `read`
    made non-public before the upgrade. A branch on a server without the new level then answers
    `502 upstream` instead of serving the base's content in the clear, and a public branch is
    restricted.
- **Stored digests at rest** (§E.1, §7.1): namespaces encrypted at rest store no plaintext head
  size or sha-256, and the first start clears those stored before (migration
  `008_clear_at_rest_digests`, once); `/heads` lists `size` and `digest` only without encryption. Revision reads still
  send `Repr-Digest`, computed when served.
- `docs/TESTVECTORS.md`, the v0.55 draft of the vectors, now points at SPEC.md Addendum I, and
  `docs/vectorgen` is removed: the draft listed the integer literal 10²¹ and the id
  `1l2gi2hhm3vt72ls2oufqpkqpsh6uvmlm` as rejected, but both are valid (§3.1, §3.2).

**New:**
- **`…/lookup?path={titles}`** on the tree service (§B.5, §H.2): resolves a `/`-joined path
  of titles from a file tree's `root`, or from the reader's roots where `root` is hidden,
  comparing after NFC and simple case folding; siblings sharing a title answer the earliest
  `born`. Catalogs without `files`, and sealed or e2e ones, answer `404 not_offered`.
  `files.TitleKey` and `files.FoldRune` are the shared comparison.
- **`children` carries `total`, and every node `born`** (§B.5), the `created` of its document's
  first revision (sealed per entry with the title in sealed and e2e catalogs; an implicit
  placement's only with its item, and never for items of sealed or e2e namespaces, whose copied
  titles and `born` are dropped when their namespace is raised). In a file
  tree, `file` says why it is absent: `{ "absent": "e2e" | "pending" }` (§H.3).
- **`internal/vectors`** pins Addendum I's vectors (I.1–I.10) to the production functions the
  reference uses for them, I.1–I.3 also against an in-process deployment and I.8 also for the
  index's `_refs` checkpoint; `internal/ids` has unit tests and `internal/files` pins the I.10
  rendering.
- **`internal/seal`**: HPKE auth mode written from RFC 9180 with the standard library
  (`WrapKeyAuth`, `UnwrapKeyAuth`, checked against RFC 9180 A.1.1/A.1.3 and the CFRG vectors),
  RFC 7638 thumbprints (`Thumbprint`), the §E.3.2 keyring document (`KeyringV2`,
  `ParseKeyringV2`, `BuildKeyringV2`), `ResourceEventPL`, and fixed-IV and fixed-ephemeral
  variants for test vectors.
- **`internal/pattern`** (`Translate`, `Compile`), the §6.6 reading of regular expressions;
  `schema.Rules` (`Legacy`, `V073`), `schema.CheckFragment`, `schema.ParseRefTarget` and
  `Validator.ValidateRules`. A `$ref` to a schema revision may end in a percent-decoded
  plain-name fragment resolved by `$anchor` or `$dynamicAnchor` (§6.1); a schema document may
  carry a top-level `$successor` of the §8.1 form.
- **`patchlog export -pad`** (with `-recipient`) pads each line of a sealed bundle to its
  §E.2.2 bucket (§G.5.1.1).
- **`patchlog merge -source-grant`** (repeatable) for blob copies, and `patchlog merge release
  status` shows the merge locks and which ones `apply` will take over.
- **`patchlog serve -max-rate-per-namespace RATE,BURST`**, the deployment maximum of
  `ratePerNamespace` (§6.6).
- **Catalog merge grants name resources per action** (§F.8, §F.9, §12.2): the catalog service's
  merge grant and the admin grant the merge service narrows for a batch changing `$access` are
  `{ any: [ { all: [ test /action, compare /resource in [...] ] } per action ] }`, at most 13
  rule forms whatever the batch size, allowing exactly the batch's pairs.
- **`patchlog e2e migrate-keyring -api URL -ns NS -identity admin.jwk [-reader pub.jwk]…
  [-current-reader pub.jwk]… [-skip-unopenable]`** migrates an e2e keyring stored in the
  format before v0.63 to the §E.3.2 document (`client.E2E.MigrateKeyring`,
  `MigrateKeyringOpenable`).
- **`patchlog rebase -reader pub.jwk`** (repeatable), the readers an e2e successor's keyring
  wraps its key for.
- **`patchlog serve -local-rate-buckets`** (Postgres, one instance) and **`-inline-pdf`**;
  **`patchlog dav -inline-pdf`**.
- The tree service's head pointer `GET /{catalog}/g/{gs}/{op}` under an edge grant's prefix.
- **`internal/svcedge`**: a service's own edge grants (exchange, withdrawal, cookies, `gs`
  subjects, shared buckets), used by the tree service and the index.
- Client: `LogEntry.Via`, `NSEntry.Via`, `PrincipalInfo.Key`, `Operator` and
  `Catalog`, `BatchResult.ConfigReport` and `ConfigError()` (a dry run's report for its config
  change; `BatchResult.Config` is set only on a submit), `E2E.WithSenders`,
  `WithKeyringSenders`, `E2E.MigrateKeyring`, `MigrateKeyringOpenable` and `KeyringReaders`;
  merge: `RebaseOptions.SuccessorReaders`, `RebaseResult.DroppedReaders`,
  `ErrReadersDropped`.
- **`-keyring-sender pub.jwk` and `-trusted-sender pub.jwk`** (repeatable) on `patchlog index`,
  `tree`, `merge` (and `merge release`), `rebase`, `janitor` and `e2e migrate-keyring`: the
  keyring admins whose e2e entries the tool or service opens, and those it trusts to distribute
  the keys it seals under (§E.3.2).
- **`patchlog merge release rebase -identity admin.jwk -reader pub.jwk`** (repeatable) keeps e2e
  readers on each successor (`RebaseReleaseOptions.SuccessorReaders`), no longer reads an e2e
  branch's schemas in the clear, and explains `ErrReadersDropped` (§F.9).
- Client: `IsBadInput`, `E2E.WithTrusted`, `WithTrustedKeyringSenders`, `ErrUntrustedKey` and
  `Head.PurgedNS` (the `purge-ns` entry of a resource's purged namespace); merge:
  `RebaseReleaseOptions.SuccessorReaders`, `ErrAdminNeeded`, `ErrNotOffered` and
  `MergeGrantResult.CheckedAs`; catalog: `AdminHeader`; core: `Engine.RemoteLevels`,
  `ArchiveReader`, `ReadArchive` and `ArchiveIdentity`; seal: the sealed-bundle writer and reader,
  moved from `bundle`, whose API and messages are unchanged (`seal.NewBundleWriter`,
  `BundleWriter.MaxLine`, `OpenBundle`, `OpenBundleMax`, `ParseBundleEnvelope`,
  `BundleEnvelope.OpenMax`, `MaxBundleLine`). `bundle.SealedWriter`, and so a sealed export,
  refuses a line whose sealed form exceeds what its readers take, instead of writing a bundle
  import refuses.
- `rules.EvalTri`, three-valued (Kleene) rule evaluation with hidden envelope members, which the
  E3 rule check of §6.2 uses; `grantcheck.LimitError`; and
  `schema.Rules.ConfigureFragment`, the format set rule schemas compile with.
- `rules.CountForms`, `grant.DecodeLimited` and `grant.Limits`, `grant.Verified.Operator`,
  `grantcheck.NamespaceWide` and `WithMaxGrantRules`, `jsonv.ParseInput` and `jsonv.MediaType`,
  `sig.ParseInput`, `bundle.StoredAuthority`, `merge.BranchWrites`, `merge.PlanObject`,
  `merge.ReadLock`, and `core.PruneRequest.{KeepSent,Precondition}` and
  `core.BlobUpload.{NonceSent,Precondition,ShapeErr}` for the waves that follow.

- **The index's own edge grants** (§A.4, §B.11.5, §C.5): `POST /edge-grants` on the index
  exchanges grants for cookies minted under the index's own key, for `/{ns}/g/{gs}` of each
  private namespace it follows and `/_refs/g/{gs}` of the reader's subject set, following the
  core's issuance (`application/json`, `415`, all or nothing: the first refusal in the order of
  the grants' root blocks, `401`, then `403`, then others, then `410 purged` with `ns` and `head`,
  the index's own purged namespaces included; `403` for a grant whose rules fix `/resource` to
  names no read check passes for; `413 limit`; at most 100 prefixes; `429` from `exchangeRate`
  buckets shared by the instances on one `-db`), and `DELETE /edge-grants` withdraws them. A GET
  carrying only such a cookie is authorised from it, a reader limited to some resources getting
  hits filtered as under its grant (the index keeps the rules and principal behind each scope
  marker until its last cookie expires), and gets edge lifetimes behind a verifying edge; a
  request needing `/g/{gs}` with neither a grant nor a cookie is `401`. The head pointers
  `/{ns}/g/{gs}?…` and `/_refs/g/{gs}?to=…` are served under the prefix. **`patchlog index`**
  gains `-edge-grant-key [KID=]FILE` (without one, cookies are minted under a random key of the
  process), `-edge-grant-kid` (default `index`), `-origin-edge-grant-kid` and `-exchange-rate
  RATE,BURST`.
- **Proposed Addendum I additions** (I.11 and the spec writer's list, CIS-38), computed through
  production code and kept in `internal/vectors/testdata/*.json`, each naming the function that
  produced it; the tests check the stored files byte for byte and the verdicts on their own, and
  `go test ./internal/vectors/ ./internal/grant/ ./internal/merge/ ./internal/core/ -run Vector
  -update` rewrites them. They cover RE2 `\uXXXX` in patterns, schemas, key `sub` and grant rules
  (§6.6); keys wrapped in HPKE base mode (`K_e`, `K_r`) and auth mode with RFC 7638 thumbprints,
  and `/keys` entries, as full decrypt vectors (§E.2.3, §E.3.2); sealed payloads for every `pl`,
  with the plaintexts a server seals (§E.2.2, §E.3.1); sealed blobs with E2 and E3 headers;
  sealed bundles and the rules they break (§G.5.1.1); the plan digest (§F.9); Biscuit grant
  tokens failing each §C.8 rule, strict Ed25519 included, and revocation ids (§C.8, §C.4); file
  renderings (§H.1); noncharacters (§3.1); `/principal`'s `key` (§7.4); a history line with
  `via` (§G.4.1); the archive key (§8.6, informative) and sealed resource purge/prune events
  (§7.3). Randomness is fixed with the reference's test hooks; sealed bundles, which have none,
  are decrypt vectors written under a fixed seed. Cases the spec leaves open (a blank line
  between sealed bundle lines, a non-canonical envelope, a top-level `last`, RE2 `\x{D800}`) are
  marked informative. No behaviour changes. The sealed resource log entry rows seal the entry
  as the core serves it: author and created on a tombstone's too, and no `parent` member on a
  genesis revision's (§7.1, §E.2.2); a test checks both against a sealed deployment's log.
- Client: `E2EDoc.PreRaise` and `Kid()`, `E2E.Log`, `Doc.Kid`, `LogEntry.Kid`; derived:
  `Cache.Drop`, `Keys.KeyAt`, `EpochOf`; index: `Options.EdgeGrants`, `Options.ExchangeRate`.

**Fixes:**
- **Creating a namespace or a remote branch under the operator grant runs that grant's own
  key-scope and block rules** at step 6 against the genesis's config envelope (`403`, nothing
  created; §6.2 step 6, §C.2 item 4). Only rules on `/action`, `/resource`, `/principal` or
  `/now` were checked, at step 1, so a narrowed operator grant, or an operator key whose scope
  has rules, could create namespaces its rules forbid. Namespace rules still don't judge a
  creation (§6.4.3); for a remote branch the rules run after the genesis checks that need the
  base, so a genesis failing one of those is still `422`.
- **`patchlog archive restore`** no longer stalls on encrypted archives when the database allows
  one connection: it reads the resource's keys before its write transaction.
- **Documents whose genesis applies to `null`** (`[test "" null, add "" …]`, accepted since wave
  1) no longer fail a renamed import's replay (§G.4.4), undo, or a catalog merge batch that
  creates one (§6.2 step 3).
- **`patchlog merge plan`** and the dry run before each merge report a non-fast-forward item
  whose replay fails (a `412` after the target moved) as that failure, no longer as "dry run ok"
  (§7.5).
- **Config writes to a branch after its base changed a `*` key** (§7.4 Branch fields, §7.6,
  §C.4): any config write to an existing branch failed with `422` at `/keys` once one of its
  bases added, replaced or rotated a `*` key, freezes, the merge tool's and janitor's
  merged/successor writes, a branch of a branch and the server's own epoch rotation included,
  so after a base swapped its `*` key (a revocation) its sealed branches stayed on the epoch
  whose key revoked readers already had (§E.2.1). A write now keeps only the base `*` key
  entries the branch's document already holds (keys follow the base); removing or changing a
  copied one is still `422`, and an entry the base later makes a `*` key may stay without `*`
  but can't be removed.
- **WebDAV: files and folders share one set of names** (§H.2 "Siblings", §H.6): a PUT, COPY or
  MOVE to another case of a folder's name (`/cat/EMPTY` beside folder `Empty`) is `409` naming
  the folder and sets the 10-second guard, so rclone's cleanup DELETE, which matched the folder
  whatever its case, no longer deletes it; a folder copied or moved to another case of a
  sibling's name is `409` and guarded too, a PUT or COPY refused onto a folder's own name sets the
  guard, and a DELETE of a tree's folder honours guards.
- **Catalog subjects and key scopes** (§B.11.2, §B.11.5; security): a bare sub, or one such as
  `group:editors-in-chief`, collected roles as a user (scenario 14), and key scope rules were
  ignored by listings and `/read-grants` (scenario 15).
- **Tree powers at broken parents** (§B.11.4; security, scenario 46): a non-admin could move a
  node off, or unplace it under, a missing, tombstoned, purged, cyclic or non-folder parent.
- **A successor's batches count for `superseded` only when trusted** (§F.6; security): any
  writer of the successor could get unmerged work purged. `abandoned` set under a key since
  removed or replaced under the same kid no longer counts.
- **Remote branch creation over a schema path holding only a pending blob** is mirrored into
  instead of failing with `409` (§G.3, §7.8).
- **A renamed import rewrites a `$successor` naming a mapped namespace** (`/r/{src}/…`) in
  history lines and snapshot documents (§8.1, §G.4.4). Snapshot imports into a sealed target
  give upstream patch sets a fresh `$nonce` (a private source's snapshots failed with `422
  nonce`), and upstream diffs ignore `$nonce`.
- **Import reports a document over a document limit as that item's failure**, not as a batch
  too large for an allowance, and recognises limit refusals as `413` or `422 limit` (§6.6).
- **Index**: `$ref` and `$dynamicRef` to anchors inside `definitions` resolve, and
  `patternProperties` patterns are read as the core validates them (§6.5, §6.6).
- **Playground**: the catalog tab and namespace views open namespace documents sealed with
  `kind: "doc"`, and the search tab's `404` for a namespace the index lacks keys for says so.
- **Prunes keep the stored sealing of preserved schema revisions** (pinned revisions already below
  an earlier horizon), which a later prune deleted, so the next read sealed them again with other
  bytes (§E.2.2, §8.6).
- **Catalog service:** a merge batch over a catalog the core holds as purged answers `410 purged`
  with the `purge-ns` entry as `head`, even before the service has applied the purge (§8.5,
  §B.11.4); it was `403`.
- **Postgres:** a rate-limit draw (§6.6) rolled back for a deadlock pauses about 10 ms, then 20 ms,
  with jitter, before running again; retrying at once could lose the rows to the statement that
  survived the deadlock and close the same cycle on every attempt, failing the request. Such
  deadlocks need a statement that locks bucket rows out of key order, such as an operator's.
- **Postgres: fewer connections per instance.** The rate-limit draws' pool of its own holds up to
  `GOMAXPROCS` connections (at least 2), not twice that, beside the 4 × `GOMAXPROCS` of the main
  pool. The URL's `pool_max_conns=N` caps the main pool at `N` and the draws' at a quarter of it,
  and `pool_max_conn_idle_time=D` closes idle connections (README "Postgres", Connections), so
  several instances fit a server's `max_connections`.
- **Tests:** `TestPGGroupCommitCancelBlockedGroup`, `TestPGGroupCommitCancelOneOfGroup`,
  `TestPGGroupCommitLostRaceLeavesLoserOut` and `TestV073P17DrawRetriesDeadlock` (Postgres) wait for
  the state they test instead of any lock wait or a fixed sleep (a rate draw's wait for a bucket
  row looked like the group's), a failure in the group-commit helpers no longer panics and ends
  the whole `internal/core` run, and the index's restart test reads the reopened checkpoint
  before following.

## v0.22.0

Implements spec **v0.55**. v0.53 restructures the text with no change in behaviour (terms
defined once in §2.1, a purged namespace's answers in one table, edge grants split into
§C.5.2–§C.5.4); v0.54 serves file-style and sync clients, from the reference's notes 13–19:
what this branch had added beyond v0.52 for them is now specified, outside E2 and E3 only, and
raw documents, moves, whole-document appends and `logPageBytes` are new; v0.55 adds Addendum
H, files, from the reference's WebDAV gateway, and in the core `GET /ns/{ns}/principal`, limit
refusals that name the limit and the sizes, and `catalog.files`, with file metadata in the tree
service's listings.

**Changes to check before upgrading:**
- **New columns `revisions.size` and `revisions.digest`**, added on the first start on SQLite and
  Postgres (nullable, no default: instant on Postgres; nothing is backfilled). They take about 40
  bytes per revision a write leaves as a head outside sealed and e2e namespaces, in the clear in
  encrypted-at-rest ones too, as ids are: a backup lets a guess of a head's document without a
  `$nonce` be confirmed against its digest, even after a purge (§C.7). Heads written before
  the upgrade, or by an older instance during a rolling one, are listed without `size` and
  `digest` until written again; a purge by an older instance leaves the columns and doesn't
  purge cached `/heads` pages (the README gives the SQL to clear them). Responses cached before
  the upgrade lack the new fields and headers, so clients treat all of them as optional (§7.4).
- **A config write that raises a namespace to sealed purges `ns:{ns}`** (§9), public or
  private, as making it private does; and **a resource purge also purges `heads:{ns}`**, a new
  tag on `/heads` pages, in every namespace it reaches, besides `r:{ns}/{name}` (the
  reference's own; §8.3 doesn't require it).
- **Resource log pages are also bounded by `logPageBytes`** (§6.6, deployment only, default
  16 MiB, `serve -log-page-bytes`): ranges, long-polls and event-stream catch-up of large patch
  sets come in more, shorter pages, each with `X-Log-Next` as before; in a sealed namespace the
  bound counts the entries' JWEs, so with `pad` a page ends where padded sizes say (§E.2.2). A
  namespace document setting `limits.logPageBytes` is `422`.
- **Blob responses carry `X-Content-Type-Options: nosniff` and
  `Content-Security-Policy: sandbox`** (§7.8), errors and the sealed `302` included: an HTML or
  SVG blob no longer runs as a page on the API's origin, and browsers no longer sniff a type
  other than the uploaded one. Images and text still display inline, but Chromium shows a
  sandboxed PDF as a blank page: download PDFs, or show them with a viewer on another origin.
- **Appends and restores that overwrite the root may be as large as `documentSize`** (§6.6):
  one whose first operation other than `test` is a root `replace` or `add`. Such an append was
  `413` above `patchSetSize`, and a restore got `documentSize` only when its very first
  operation was a root `replace`.
- **A top-level `$successor` of the §8.1 form is left out of validation** (§6.2 step 5), the
  index's `x-index` and `x-ref` walks and the bundle closure, as `$schema` and a fresh `$nonce`
  are: closed schemas accept it, and walks that found it as a reference no longer do.
- **Verification applies a key's `readScope: "resource"`** (§C.2 item 1, §C.4, v0.55): a `read`
  grant such a key signs whose rules don't fix `/resource` (§2.1) is refused on every request,
  `403` (`404` on a read of a private namespace, as any refusal there). It used to verify, and
  read every resource. Edge-grant issuance refused it already. `grant.Verify` applies it, so the
  tree, catalog and index services (`grantcheck`) refuse it too: the tree service listed heads
  and file metadata of a private namespace's items to it.
- **A namespace's own `rulesPerGrant`, `grantSize` and `rulesPerNamespace` are enforced**
  (§6.6): a grant chain over the namespace's `rulesPerGrant` is `422`, a bearer over its
  `grantSize` `413`, and a namespace creation or a config write that changes the rules or
  `limits.rulesPerNamespace`, whose document has more rules than its own `rulesPerNamespace`,
  `422`; only the deployment maximums were. Stored documents are read as before, and one stored
  over its own `rulesPerNamespace` takes other config writes, freezes included.
- **Limit refusals carry `limit`, `measured` and `max`** (§6.6, §12, v0.55), batch items' reports
  too; the bodies of `POST …/prune` and `POST /ns/{ns}/keys`, which no limit of §6.6 covers, are
  `400 bad_input` above 1 MiB, and so is a `POST /edge-grants` body over room for 50 grants
  (§12: an exchange over its limits), all three `413 limit` before.
- **The tree service's `items` table gains `created` and `file` columns**, added on the first
  start (nullable). In a file tree (`catalog.files`, §H.2) the service reads every head of its
  trusted namespaces as it applies it, sealed ones with keys, to give placements file metadata;
  on the first start with a file tree it reads every live item's head once (meta `filed`,
  retried until every head is read) and purges the catalog's cached listings. While a sealed
  namespace's epoch key can't be had for the moment, its listings are `503` with `Retry-After`.
- **Undo by a writer that can't read the namespace document asks `GET /ns/{ns}/principal`**
  (§11.2) for the namespace's `opsPerSet` and `patchSetSize`, and splits inverses by them rather
  than by §6.6's defaults; against a server before v0.55, which answers `404` there, the
  defaults hold as before. Such writers still add a fresh `$nonce` in private namespaces
  (`client.NeedsNonce`), as §C.7 recommends for one that doesn't ask.
- `GET /` answers `"spec": "0.55"`.

**New:**
- **`GET /ns/{ns}/principal`** (§7.4, v0.55; README design notes): what the grant in
  `Authorization` is in a namespace, `{ principal, kid, can, roles }`, and what a writer needs
  from the namespace document, `writer: { frozen, successor?, nonce, signatures, level?, limits
  }`, the limits in force as §6.6 writes them, with `X-Config-Revision`. Only the `ns` check and
  verification apply, so a grant limited to some resources or without `read` gets it; none, or
  one that can't be used, is `401` even in a public namespace; an edge-grant cookie is no grant;
  an operator grant gets `404` for an absent namespace; a purged namespace is `410 purged` once
  the grant verifies; every answer is `no-store`. With authentication disabled it leaves out
  `principal` and `kid`. Client: `Client.NSPrincipal`, `PrincipalInfo`, `WriterInfo`.
- **Limit refusals name the limit** (§6.6, §12, v0.55): every `413`/`422` `limit` carries
  `limit`, its §6.6 key, and for sizes and counts `measured` and `max`; durations and rates the
  key alone; a body the server stopped reading names the deployment's limit (the principal's
  `batchSize` for a batch) with the bytes read as a lower bound. Client: `APIError.Limit`,
  `client.IsLimit`; `grant.TooLargeError` carries a bearer's sizes.
- **`catalog.files`** (§7.4, §H.2): a catalog namespace document may say `"files": { "ns",
  "root", "folder"?, "placement"? }`, checked in shape (`422 invalid` at its pointer otherwise).
- **File metadata in tree listings** (§H.3, §E.2.6; README "File trees"): in a file tree, every
  placement entry with a head carries `file: { size, type, modified }` of that head (a raw
  file's reference, a JSON file's rendering length and `application/json`, the head's
  `created`), sealed per entry under the item's `K_r` for items of sealed namespaces and left
  out at E3; `catalog.files` coming or going reads every head, or drops the metadata.
  `follow.Change` carries `Created`.
- **`internal/files`** (§H.1): `files.Rendering`, the rendering of a JSON file (its canonical
  text without a fresh `$nonce` or §8.1 `$successor`, laid out as `JSON.stringify(v, null, 2)`
  with JCS's tokens and order), `files.Layout` and `files.MetaOf`, for the tree service and file
  gateways alike.
- **Revision metadata** (§7.1, §7.4; README "Files and sync clients"): outside sealed and e2e
  namespaces, judged by the namespace serving the read, a revision's `200` carries
  `Last-Modified`, its created time, with `If-Modified-Since` answered `304`, and
  `Repr-Digest: sha-256=:…:` (RFC 9530) of the canonical document; `/heads` entries carry
  `created`, and live heads `size` and `digest`, stored at write time so a listing reads no
  document; branches list their base's values for what they read through. Sealed and e2e
  namespaces send none of them, the e2e keyring and prune snapshots included (§E.2.2), and
  ignore `If-Modified-Since` there, so no `304` reveals a created time; `If-None-Match` still
  gives one. The Go client exposes `HeadItem.Created`, `Size` and `Digest`, `Doc.Modified` and
  `Digest`, and `client.ReprDigest`.
- **Raw documents** (§7.1, §7.8): `GET /r/{ns}/{name}/raw` and `…/rev/{id}/raw` redirect (`302`)
  to the blob a document whose root is only a blob reference stands for, cached as the document
  URL; a document that isn't raw is `404 not_found`, sealed and e2e namespaces `404
  not_offered`. A blob reference at a document's root may carry `$schema`, a fresh `$nonce` and
  a well-formed `$successor`, so raw documents can be typed, nonced and moved. Client:
  `client.RawBlobOf`, `Client.Raw`.
- **Moves** (§8.1): a tombstoned head's `410` carries `successor`, copied from the last
  document's well-formed `$successor` (a bare name or `/r/{ns}/{name}`), outside sealed and e2e
  namespaces, read through branches and remote branches' mirrors. Client: `Head.Successor`,
  `Client.Moved` (which reads the document at `last` where the `410` names none),
  `E2E.Moved` (which always folds that document and ignores a `410`'s successor, since the
  server is outside the trust boundary at E3), `client.SuccessorOf`,
  `client.ResolveSuccessor`.
- **`serve -log-page-bytes`**, and `LogPageBytes` in `core.Limits` and `clienttest.Options`.
- **`patchlog dav`: namespaces and catalogs over WebDAV (a prototype)** (`internal/dav`), so
  file managers, editors and sync tools (Finder, Explorer, GNOME Files, vim, VS Code, rclone and
  its mounts) open and save files through the core's public API only, following spec Addendum H
  (files):
  - **Files** (§H.1): a file other than a JSON file is a raw document, its root a blob reference
    to its bytes, kept exactly and typed by §H.1's extension table (else the upload's
    `Content-Type`); a JSON file is a document, read as its rendering (the canonical text laid
    out as `JSON.stringify(v, null, 2)`, without a fresh `$nonce` or a `$successor`), made by
    `internal/files` as for the tree service (`files.Show`, `files.Bare`, both new). A new
    `.json` file that isn't I-JSON is raw, and an empty file is a raw file of 0 bytes. Raw files
    are streamed from their blobs through this server, with ranges; every answer carries
    `nosniff` and a sandbox policy, and `POST` is `405`. Every file's ETag is its head revision.
    Raw files are written up to `-max-raw-size` (64 MiB), JSON files up to `-max-file-size`.
  - **Layout** (§H.2, §H.3): a namespace (`-ns`) is the flat view, a raw document by its name and
    any other as `{name}.json`, listed from `/heads` with sizes and types read once per revision;
    a catalog with `catalog.files` (`-catalog`) is a file tree whose folders and files are named
    by their nodes' titles (NFC, compared after simple case folding unless `-case-sensitive`, a
    name a sibling has under another case refused for writes, duplicates numbered, unsafe titles
    escaped), with new files created as opaque items in `files.ns` and renames and moves one
    append to the node; dot folders are folders. Sealed and end-to-end namespaces aren't offered
    (§H.7).
  - **Listings through the tree service** (§H.3, §H.7; `-tree-url [CATALOG=]URL`, as `serve`'s,
    and `-tree-wait`): a tree's folder is listed from the tree service's `children`, every page
    (a folder over 10 pages of 1000 is `403` as a listing, never cut short, and its files are
    still reached by name, from the node documents), with the request's grant passed through as
    bearer, which the tree service filters by (§B.11.5), so a grant limited to some resources
    lists a tree; sizes, types and times come from its `file` metadata and ETags from its heads,
    so no item is read; names and path resolution are the node documents', placements whose
    `file` is sealed aren't listed, and the tree service down, or not caught up with a trusted
    namespace, is `502`/`503`, never an empty folder. Writes check what a listing named against
    the node documents and resolve the path from them where it lags (a name renamed, moved or
    just given by another user), so a stale name is never deleted, moved or created twice, a
    folder's emptiness is the node documents', and a folder is deleted, or a file in several
    folders unlinked from one, only while still named as the path named it. A grant limited to
    some resources edits the files it lists and reads; a new file or folder, a move or a delete
    by it, which the node documents decide, is `403`, a move before anything is written, as is a
    move whose source the grant's verbs (`GET /ns/{ns}/principal`'s `can`) don't let it delete,
    a tree's file or a flat one (only what rules decide is met after the copy). A user's listings after their own writes,
    through any of their tokens, wait for the entries those produced (`?min=`, keyed by the
    writes' `X-Namespace-Revision`) until a listing that waited came back, for at most 10
    minutes, each up to `-tree-wait`, then read the node documents (a token that can't read
    them gets `503` for 30 s, then the tree service's listing); entries the tree service refuses
    (`400`) are found per namespace and not asked for again. Without a tree service, folders are
    listed from the node documents as before. Client: `client.WithTransport`,
    `Client.Bearer`.
  - **Saves** (§H.4): the base is the revision `If-Match` (or the `If` header's first applicable
    entity tag) names, else the closest of the versions the user was served whole or wrote in
    the last day; the edit from it is rebased on the head, others' edits since kept, overlapping
    ones (what differs and what the log entries in between wrote) a `409`, as is a delete or
    restore by someone else in between, a pruned base, lost records, versions that would apply
    the save differently, or a path that came to name another file; after a `409`, a save
    without a base by the same login is refused again until that login reads the file (an
    rclone mount retrying its upload isn't rebased on another program's read), its conditional
    GET answered in full, and those refusals, and any other of that login's before its read (a
    retry whose rebase clashes, a raw file's), ask no reload of the user's other programs, whose
    records stay (a file keeps 8 such logins; one pushed out by a ninth leaves the file's
    records lost); lost records are a `409` until the reload it asks for; a raw file is
    checked
    against every version the user had, conflicts as a whole when someone else changed its bytes
    since, and sets its reference's members one by one. A JSON patch set over `opsPerSet` or
    `patchSetSize` is a root replace when the base is the head, else `413`. An `If-Match` where
    no file is is `412`. Answers follow
    §H.4's table: an ETag only for a revision that holds exactly what was sent (and the next
    read in full after a merge), `410` for purged, `403` naming the successor for frozen, `413`
    for any limit, naming the limit, what was measured and the limit in force as the core gives
    them (`too large: documentSize 1048577 > 1048576 (§6.6): document too large`), the
    gateway's own checks (`blobSize`, `opsPerSet`, `patchSetSize`, `-max-file-size`,
    `-max-raw-size`) alike, and `503` with Retry-After for long rate limits.
  - **Moves** (§H.5, §H.8): within a tree, a rename or move of the node; onto an existing file, a
    save into it, then a delete of the source's revision copied, so the target keeps its history;
    across trees or namespaces, a copy and a delete with `$successor`; in the flat view, to a free
    name, one
    batch creating the new resource and deleting the old with `$successor`. A file moved to a
    scratch name stays (an editor's backup).
  - **Clients as they are** (§H.6): editors' and systems' own files (`.DS_Store`, `._*`, `*.swp`,
    `*~`, `.goutputstream-*`, …) and apps' folders stay in memory per user and narrowing, reached
    only by a token whose grant names their namespace, and nothing else can be at the root; locks and dead properties are kept in memory, bounded, and a DELETE or MOVE
    drops the locks on its path; a write to a path the user deleted within 30 seconds restores the file
    rebased on its last live document, and a refused one undoes that DELETE; a refused PUT, or a
    refused MOVE onto a file, sets a guard that refuses the user's DELETE of the path within 10
    seconds once per refusal (rclone deletes every file whose upload failed), ending only by
    time. `PROPFIND` without `Depth` is `1`, `Depth: infinity` `403`.
  - **Users** (§H.7): local mode sends one `-bearer` grant behind a password, one user; gateway
    mode (`-gateway`) sends each request's Basic password upstream as its grant and needs TLS
    beyond loopback. It verifies a grant with `GET /ns/{ns}/principal` in a served namespace the
    grant names, keeps nothing for one the core hasn't accepted (`401`; a purged namespace is
    `410`, an absent one `404` to an operator grant; one an operator key signed `401`, told by
    its signature under the operator key history at `jwks_uri`, unless the namespace lists that
    key under that kid too, as the core serves it; a key set it can't read, a `200` that isn't a
    JWK Set too, has the core asked of each grant), asks again every 5 minutes (at most the 15
    minutes edge grants live) or after the core's `401`, and keys its state by the root `sub`
    and `kid` `/principal` names (with the namespace that verified it, asked first again for the
    same token, kept past the token for the 256 tokens of each user verified last, 16384 in
    all, the verifying namespace and then the key keeping the most giving way, so one key
    holder minting grants for many subs pushes out only its own, and for its
    kid and sub, every served namespace that did, the first never pushed out), never the token,
    so every token
    of one person, minted again or attenuated offline, shares their records, guards, own
    tombstones and the writes their tree listings wait for; a token verified again as another
    user (once admitted as that user) must read every document its old user had records of
    itself before saving it without a base, the new user's other tokens unaffected. Scratch
    files, locks and dead properties are shared by the tokens the issuer minted with the same
    rights (the root block's `ns`, `can`, `roles`, `rules`, `groups`, `attrs`, the sets in any
    order), and a token
    minted limited to some resources or attenuated offline (another ns, can, rules, a via) has
    its own. A refused token loses its access and has the user's other tokens asked again; the
    user's state stays for their accepted tokens. At most 256 users and 8 tokens a user, and 8
    scopes of tokens as issued and 8 of tokens narrowed offline from each of at most 8 tokens
    (a delegate's narrowings fill only its own), one keeping scratch files or locks never
    dropped to make room (`MaxPrincipals`, `MaxTokensPerPrincipal`). Writer settings (frozen,
    nonces, level, limits in force) come from `/principal`'s writer block, which a grant
    limited to some resources gets too, kept per token for 30 seconds and asked again after a
    refusal over one of them; what is read with a grant (documents, catalog trees, tree-service
    listings) stays per token, the trees and listings within `-cache-size` over every token.
  - **In the compose stack** (`dav`, http://localhost:8090/, any user name, password
    `patchlog-dev` or `DAV_PASSWORD`'s, delivered as a compose config file read when the
    container is created, so `up -d --force-recreate dav` changes it; this needs Docker Compose
    2.23.1 or newer, for the whole stack): `demo` as a flat directory and `drive` as a file tree,
    listed by the stack's tree service, which follows `drive` too. `files`, drive's content
    namespace, isn't served flat, where a rename or delete would leave drive's placement
    dangling; the gateway doesn't mount the data volume. The seed creates `files` and `drive` (`catalog.files`, with folder and
    placement schemas and `cat`'s rules plus §H.2's titles) with two folders, raw Markdown, text
    and PNG files and a JSON file. README "WebDAV in the stack" has Finder, Windows, rclone
    and davfs2 how-tos.
  - Not yet: new files, folders, moves and deletes in a tree through the tree service alone
    (a grant limited to some resources edits files only), catalog-issued grants, text merges,
    history, live invalidation, batches.

**Fixes:**
- **A tree service's listings are `503 behind` until it has caught up with every namespace the
  catalog trusts** (§B.5, §H.3, §10), not only with the catalog. Started with a fresh database,
  rebuilt, or trusting a namespace lately, it answered every folder with its placements of that
  namespace missing, so folders listed empty, which a sync tool mirrors as deleted files. Caught
  up means to the head the namespace's follower read when it started, not a first log page
  (`follow.WithOnCatchUp`), recorded so that a restart on the same database doesn't wait again.
  A trusted namespace it can't follow (purged, skipped for its keys as configured, refused or
  absent at the core) isn't waited for, until the core serves it again, and a `?min=` naming it
  is `400`; one whose epoch key can't be fetched for the moment (a transport error, a `5xx`, a
  `429`: `derived.Retryable`, `client.Transient`; `Keys.Check` reports it), sealed or end-to-end
  (`client.E2E.Key` answers such a failure of the relay's keys and the keyring with it, not
  `ErrNoKeys`), is skipped but still waited for. A
  namespace the catalog stops trusting loses its catch-up, also one its follower reports after
  that apply (stopped, also after it is trusted again), and a record of one left by a stop, so
  trusted again it is waited for again. A
  catalog trusting a large new namespace now lists nothing until the service has caught up with
  it.
- **Stored listings of the tree service are keyed by the reader's shape** (§A.4, §E.2.6), as
  kept ones are: by URL and what the reader reads whole. A public namespace that turns private
  moves neither the anonymous URL space nor a `gs`, so until the service's `at` moved, readers
  were served the stored listing computed while it was public, with heads and urls of its items,
  and it stayed stored at that `at`. This held for sealed and e2e catalogs, and with file
  metadata for every file tree trusting a sealed namespace. Listings stored before the upgrade
  are computed again.
- **A second CDN purge from the index and the tree/catalog services** (D.8, as the core's): a
  request in flight when an apply committed a purge could hand the CDN a result or listing it
  read before the commit, immutable and tagged with what was just purged, after that purge had
  gone out, and the CDN kept it for a year. The transaction that commits a purge now also queues
  it in `cdn_repurge` in the service's own database, and the service sends it again two minutes
  later (`RepurgeDelay` of `index.Options` and `tree.Options`, longer than a CDN's first-byte
  timeout, 75 s in `deploy/varnish`, since the services set no response deadline of their own;
  `RepurgeInterval`, 10 s), so a crash or restart loses no second purge, and `-rebuild` keeps
  the queue. This covers resource purges and purge-ns in both services, the `ns:{catalog}` purge
  for drift that a tree start or a failed apply's reload fixes, and the catalog's
  `ns:{catalog}` purge when its trust list loses a namespace, which used to be added after the
  commit.

## v0.21.0

**Changes to check before upgrading:**
- **`documentSize` defaults to 1 MiB** (was §6.6's 4 MiB), measured in
  [docs/CAPACITY.md](docs/CAPACITY.md): an append re-serialises and validates the whole
  document, 3–4 times slower at 3.5 MiB than at 16 KiB. 4 MiB stays the deployment maximum
  (`serve -max-document-size` changes it), and a namespace may set `limits.documentSize` up to
  it. **In namespaces holding documents over 1 MiB, appends to them are `413` until the
  namespace sets `documentSize`** (or the deployment runs with `serve -document-size 4MiB`, the
  old default). Bundle imports and remote branches of such documents need the same.
- **New indexes on the namespace log** (`ns_log_ns_seq` on `(ns, seq)`, `ns_log_ns_config` on
  `(ns, config_seq, seq)`), built on the first start, on SQLite and Postgres. On Postgres the
  build runs in the schema migration and blocks writes until it commits, a few seconds per 5
  million namespace entries; to avoid that, create them beforehand with
  `CREATE INDEX CONCURRENTLY` under the same names (see the README's Postgres section).
- **SQLite database paths with `#`, `?` or `%`** (the core's `-db`, the index and tree/catalog
  services' databases): earlier releases opened another file for such a path. With `#` or `?`
  it was the file named by the path up to that character, so two paths that agree up to there
  shared one file; with `%XX` escapes it was the file with them decoded (`%2F` as `/`, so
  possibly in another directory), the name ending at a `%00`. This release opens exactly the
  path given. When there is no file there but there is one at the old name, it refuses to start
  and names both: stop the old release cleanly, move that file with its `-wal` and `-shm` files
  to the full path (a copy for each, where two shared one), then start again. Started on an
  empty database instead, the core's blob sweep would delete the blob files, whose directory
  (`<db>.blobs`, or `-blob-dir`) is already at the full path.

**Improvements:**
- **Long-polls of a namespace share their reads** (§7.7, README design notes): a write woke every
  waiting long-poll, and each read the log again in a transaction of its own, so a private
  namespace followed by thousands of devices (which a CDN can't collapse without verifying edge
  grants) cost a transaction and a log query per follower per write. A long-poll's read check now
  stands for its later reads while the configuration and its grant are unchanged and its rules
  don't read `/now`, and those reads are shared by the waiters woken by the same commit. One
  write to 5,000 private followers: 3.7–4.1 s of core CPU before, 0.3–1 s now, delivered in
  0.35–0.7 s instead of 3.1 s (docs/CAPACITY.md).
- **The local CDN's VCL** lets long-polls with credentials (`Authorization` or cookies) skip
  Varnish's waiting list: a private namespace's long-poll was held behind an identical one in
  flight until the next write, then sent to the origin with the rest a few at a time. Identical
  long-poll misses without credentials (devices following a public namespace) still collapse.
- **Caches bounded by bytes, evicting gradually** (README design notes): the bearer grant cache
  keeps 65,536 verified grants (was 1,024, emptied when full, so a fleet of devices with grants
  of their own verified on nearly every request), the least recently used out first
  (`serve -grant-cache`); the document cache 256 MiB (was 4,096 documents, up to 16 GiB of
  4 MiB ones; `serve -doc-cache-size`); the read cache 64 MiB, now evicting a quarter rather
  than everything when full (`serve -read-cache-size`). Compiled schemas, kept forever before,
  are the 512 most recently used (and 2,048 schema documents), and rate-limit buckets, one per
  resource and principal written and never dropped before, are swept once refilled.
- **Namespace log pages bound items too**: a page holds at most the log page size in resource
  entries as well as in entries, a batch entry counting as its items (it carries them), ending
  before an entry that would take it past and always holding one. A page of 1,000 batch entries
  of 1,000 items held a million. Ranges, long-polls and event streams' catch-up; readers follow
  `X-Log-Next` as before.

**Fixes:**
- **Namespace log pages in long namespaces:** a page (ranges, long-polls, event streams) had no
  index to read a namespace's entries in order, so Postgres could read the whole namespace and
  sort it for every page, and SQLite did: O(namespace) per page rather than O(page). With
  `(ns, seq)` it reads the page's rows (a page of a 5,000-entry namespace among 5 million
  entries: 3.7 ms to 0.35 ms on Postgres).
- **Idempotent retries of config writes and batches with a config change** looked up the
  first namespace entry under a configuration by scanning all of `ns_log` (about 400 ms at 5
  million entries, growing with the table); `(ns, config_seq, seq)` makes it one index probe.
- **Snapshot bootstraps of large namespaces** (`follow.WithSnapshot`, new branches followed by
  the index, the janitor and release previews): the follower read the whole `/heads` listing
  into memory and delivered it as one batch, which a consumer applied in one transaction with a
  document fetch per resource before anything was recorded, so a namespace of millions of
  resources needed memory for all of them and an interruption started over. The listing now
  comes a page per batch (`Batch.After`, `More`; `Replaces` for the first page, `Partial` for
  every page but the last), the checkpoint with the last page. `SQLCheckpoints.SaveBatch` (and
  `MemoryCheckpoints.SaveBatch`) record the pages in between in a table of their own
  (`checkpoints_bootstrap`, created by `Init`), and a follower restarted meanwhile resumes after
  the last page recorded (`Resumer`), or starts again from the first page if the origin no
  longer lists from there. The index serves the namespace only once the last page is applied,
  as before; the tree service holds the pages and applies the listing whole at its last page,
  since its listings are cached by checkpoint.
- **A purged namespace in the index right after its purge** (§8.5, §12): between committing a
  purge-ns and publishing it in memory, the index decided whether the namespace was purged from
  memory but redirected by the committed checkpoint, so its head pointer sent readers to
  `/{ns}/at/{purge-ns}`, which answered an empty `200` cached as immutable and tagged `idx:{ns}`
  after that tag's purge had gone out, and `/_refs` still covered the namespace. Both now go by
  the committed state, so the namespace is `410 purged` at every URL from the commit on.
- **SQLite database paths with `#`, `?` or `%`:** the core, the index and the tree/catalog
  services built SQLite connection strings by appending the path unescaped, so SQLite cut it at
  `#` or `?` and decoded `%XX` in it, a `?` also cost the database its WAL journal mode, and a
  path starting with `//` failed to open. Paths are now escaped, so the database opens at
  exactly the path given with every setting applied (see "Changes to check before upgrading").
- **Writes cancelled before their commit** (shutdown timeout): a write cancelled right before
  its commit, as at `-shutdown-timeout`, could still commit and be answered `201` on SQLite,
  and on Postgres for a group commit whose requests were all cancelled: database/sql checks a
  transaction context that learns of the cancellation a moment later, the SQLite driver commits
  regardless, and a group's context learned of it late too. Its client lost the response when
  the shutdown closed the connection, which an idempotent retry finds (§7.2). Such a write now
  rolls back. One cancelled while it commits may still commit and is answered as committed (on
  Postgres, as cancelled with its outcome unknown); the README's graceful shutdown section says
  so.
- **Restores in a purged namespace** (tree/catalog, §B.11.4, §8.5): a service started after a
  trusted content namespace was purged, sealed or not, answered a catalog restore of one of its
  items `404` "has never existed" instead of `410`, because it holds no rows for most of those
  items. Any name the service holds no row for, in a namespace it holds as purged, is now
  purged, as the core answers `410 purged` for every name there. So a restore of a name that
  never existed in a purged namespace is `410` too, also on a service that followed the purge;
  in a namespace that isn't purged it is still `404`. Late-started, restarted and following
  services give the same answers and checkpoints, and their placements dangle as `purged`, not
  `missing`, in `/problems`, also after a restart.
- **Listings that change at an unchanged `at`:** a start that finds the derived rows drifted
  from what the graph gives now purges `ns:{catalog}` (stored sealed and kept listings, and
  through `-purge-url`), since edges cache listings at an `at` as immutable. The first start
  after upgrading does this once for a service that showed a purged namespace's never-seen
  names as `missing`.

## v0.20.0

Implements spec **v0.52**. v0.51 settles all fifteen of the reference's v0.50 notes, most as
the reference did them; v0.52, from Doors, gives edge-grant exchanges a rate bucket of their
own.

**Changes to check before upgrading:**
- **Exchanges draw on `exchangeRate`** (v0.52, §6.6, §C.5): each `POST /edge-grants` draws one
  token from the `exchangeRate` bucket of each distinct principal among its grants, however
  many grants it carries, and none from write buckets or allowances; `429` with
  `limit: "exchangeRate"` when one is empty. It is deployment only, default 10/s with a burst of
  100: `serve -exchange-rate RATE,BURST`, and `tree -exchange-rate` for the catalog service's
  own exchange. A namespace document setting it is `422`.
- **The prefix cap** (v0.51): an exchange that would issue more than 100 distinct prefixes is
  `400 bad_input`, once nothing is refused; a namespace-wide grant counts two prefixes per
  namespace. It was `403` for more than 100 names.
- **Edge headers:** `X-Edge-Verified` and `X-Edge-Prefix` give edge lifetimes only as exactly
  one header line without a comma, and an edge secret containing a comma is refused (§9).
- **Listing URLs put the subject set first** (§A.4, §B.11.5): catalog listings are
  `/{catalog}/g/{gs}/at/{at}/…`, private index results `/{ns}/g/{gs}/at/{ns_id}?…` and
  `/_refs/g/{gs}/at/{at}?to=…`. The old forms redirect (`301`) to the new.
- **Catalog `checkpoint`** is `{ ns: ns_id, … }`: the catalog's and each named item's
  namespace's `ns_id`s a decision was made at, not the combined checkpoint string (§B.11.4).
  `POST /read-grants` has no top-level `checkpoint` any more: each entry of `grants` carries its
  own, and refusals not decided at a checkpoint, `5xx` entries and public items of namespaces
  the service doesn't follow have none.
- **A `min` naming a namespace the reader can't see** gets the same `400` as one the service
  doesn't follow, on index, `/_refs` and tree URLs, so it doesn't reveal which private
  namespaces are indexed (§A.5).
- **A purged sealed namespace** answers `410 purged` with `head` for its documents, log,
  events and long-polls; it was `500 encryption_unavailable` (§8.5). Followers, the index,
  tree, catalog, janitor, merge and remote branches take that `410` as the purge.
- **`POST /ns/{ns}/keys`** is `404 not_offered` in a namespace that isn't sealed (was
  `422 invalid`). At E3 it relays a grant's own keyring entries to any grant that reads the
  namespace, a limited one included, without a read of the `keyring` resource.
  `core.Engine.Keys` returns `*core.KeysAnswer`.
- **Undo from resource logs** reports a gesture found in no named document as impossible
  (`pruned`) when one of them has a pruning horizon (§11.2).
- **Imports:** an upstream namespace with an invalid name, usually a renamed namespace's
  over-long `{dst}-upstream`, is a check failure at step 1, before anything is written
  (§G.4.4).
- **`serve` no longer derives the edge-grant cookie key from `-edge-secret`.** The catalog
  service and the search index hold that secret for their own edge lifetimes, so they could
  derive the key and mint core cookies. Without `-edge-grant-key`, each `serve` process signs
  with its own random key: cookies verify only at the instance that minted them, not after a
  restart, and no edge can verify them; `serve` warns when `-edge-secret` is set without key
  files. Origins with several instances, and edges that verify cookies, need the same
  `-edge-grant-key` key files. Cookies signed under the derived key stop verifying, and clients
  exchange again. `-edge-grant-key KID=edge-secret` still holds the derived key, with a warning,
  for migrating only: every edge must drop it 15 minutes after the origin does, since anything
  holding the edge secret can mint cookies it accepts.
- **The catalog service's `g/all` listings** get an edge lifetime of the cookie lifetime plus a
  minute (`CDN-Cache-Control: max-age=960`), not a year, and when the catalog's trust list loses
  a namespace the service purges `ns:{catalog}` through `-purge-url`. Purge `ns:{catalog}` at the
  edge once after upgrading, for listings cached before.
- `-edge-grant-key` takes `KID=FILE` only when no `/` comes before its first `=`; a file named
  `edge-secret` in the working directory is given as `./edge-secret`. `tree`'s
  `-edge-grant-key`, `-edge-grant-kid`, `-origin-edge-grant-kid` and `-exchange-rate` without
  `-access` are fatal.
- `GET /` answers `"spec": "0.52"`.

**New (v0.51):**
- **Key rotation:** `serve -edge-grant-key [KID=]FILE`, repeatable; the origin mints with the
  last and accepts all, so a key is rotated by adding the next to the edges, then to the
  origin, and dropping the old one once its cookies have expired, without clients exchanging
  again. `-edge-grant-key [KID=]edge-secret` names the key derived from `-edge-secret`, to move
  off it (above). `edge.Cookies.AddKey`, `Kid` and `Kids` (§C.5). The catalog service's
  `tree -edge-grant-key [KID=]FILE` rotates the same way, and `-origin-edge-grant-kid` takes
  every origin kid (repeatable or comma-separated), none of which a service kid may be.
- **The catalog service mints its own edge grants** for private listings (§B.11.5): `POST
  /edge-grants` on the tree service, following §C.5's issuance rules, gives cookies for
  `/{catalog}/g/{gs}` under a key of its own (`tree -edge-grant-key`, `-edge-grant-kid`,
  default `catalog-{catalog}`), which vouches only for its own prefixes. A read under one,
  without `Authorization`, is the subject set's, and gets edge lifetimes only behind a
  verifying edge. A `g/all` cookie is refused at an `at` that includes a namespace the catalog
  came to trust after it was issued, and such listings are `no-store` at the edge while an
  older `g/all` cookie may be live. `edge.Cookies.Vouches` sets which prefixes a service's key
  vouches for.
- **`/keys` names `epoch`, `level` and `pad`** (§E.2.3), so a writer limited to some resources
  learns the level at E2 and E3 and seals at E3 without the namespace document: E2E writes, `PruneE2E`, `UploadBlob` and
  undo take them from `/keys` (`client.FetchKeysAnswer`, `client.IsNotOffered`). Undo by such a
  writer now works at E3 with `UndoE2E`.
- Behind a tree service that serves several catalogs, a `min` naming a namespace only another
  of its catalogs follows is waited for there, then redirects to the current `at` (§A.5).
- `client.IsPurged`, and `grantcheck.Checker.PurgedRead` for a purged sealed namespace's read
  check.

**Fixes:**
- A `min` naming a purged sealed namespace (index, or another catalog of a tree service) is
  decided by the core's read check, never `502`. The catalog service's `POST /edge-grants`, and
  reads under its cookies, answer `410 purged` for a purged catalog, sealed or not (a subject
  set's cookie without `head`), not `502` or `401`. A purged content namespace no longer ends
  `g/all` listings: 16 minutes after the purge, it counts as read whole by every reader.
- `client.With` no longer sets the redirect policy of the HTTP client it shares, which raced
  with requests in flight.
- The catalog grant service answers `410 gone` for items of a purged sealed content namespace,
  or catalog, instead of `502`; remote branches no longer re-apply a sealed base's purge on
  every sync; the janitor keeps sweeping when one of its bases is purged.
- A limited writer's E3 fold no longer fails on an unpadded revision.
- Playground: a purged sealed namespace shows as purged; limited-grant undo asks `/keys` for
  the level.

## v0.19.0

Implements spec **v0.50**, which settles all fifteen of the reference's v0.49 notes and takes
up Doors' S15–S19 and F12–F14: edges, purged namespaces, catalog decisions, canonical query
URLs and renamed imports. Addendum D, the Bun prototype, has left the spec.

**Changes to check before upgrading:**
- **Private reads are no longer refused behind `-edge-secret`** (§9): `serve`, `index` and
  `tree` serve them with or without the edge's headers, and a private long-poll waits as any
  other; `403 edge_required` is gone (Doors S15). A private response gets edge lifetimes
  (`CDN-Cache-Control`) only when the edge verified it itself: `X-Edge-Verified` carries the
  secret, `X-Edge-Prefix` carries exactly one prefix that covers the URL, and the request has
  no `Authorization` or `Source-Authorization`. Everything else private is
  `CDN-Cache-Control: no-store` and `Surrogate-Control: no-store`, including reads with a grant
  in `Authorization` behind a verifying edge, which got lifetimes before (Doors S16). A
  verifying edge must now send the prefix it checked (`-edge-prefix-header`, default
  `X-Edge-Prefix`) and strip both headers from client requests.
- **Edge-grant cookies use §C.5's default format:** canonical JSON claims
  `{"exp","kid","p"}` (no `v`, `ns`, `r` or `sub`), the `kid` set with `-edge-grant-kid`
  (default `origin`). Cookies issued by earlier versions stop verifying at upgrade and count
  as absent until clients exchange their grants again, at most 15 minutes. An edge that
  copied the old format must switch (Doors S17).
- **`POST /edge-grants`** ranks a `"*"` grant and one that doesn't decode with the other
  refusals of the request, so `"*"` beside a namespace where the grant fails verification is
  `401`, not `403`. Each grant now draws one token from its principal's rate limits
  (`ratePerPrincipal`, or an allowance's bucket), the bucket writes use, so a busy exchanger
  can get `429`. Grants in the body need `Content-Type: application/json` (`415` otherwise), so
  a cross-site form can't set cookies. Its `410 purged` carries `ns` as well as `head`.
- **A path ending in `/`** (other than `/`) is `400 bad_input`, as dot segments and escapes
  are (§C.5).
- **A remote branch whose base, or a base in its chain, is purged** at the source is
  `410 purged` (was `gone`), with `origin`, `ns` and `head` naming the purged namespace there,
  for any `at` (§G.3, §12). A schema revision it would mirror that is purged at the source is
  `422 schema_unavailable` with `ref` (was `410`).
- **`min` always redirects** (§A.5) in the index, `/_refs` and tree services: a request with
  `?min=` is never answered `200`. After the wait, an `at` URL whose kept result already
  includes every `min` redirects to itself without `min`, anything else to the current
  checkpoint. `/_refs` answered such a kept result `200`.
- **Canonical query URLs** (§A.5): index, `/_refs` and tree `at` URLs are answered `200` only
  in the canonical form, for every namespace, not only sealed ones, and any other form is
  redirected to it. Parameters are sorted by name, then value, and everything but letters,
  digits and `-._~` is percent-encoded in uppercase hex (a space is `%20`). Kept and sealed
  results stored under other forms are computed again.
- **Index sort:** several keys are one comma-separated parameter, `sort=-/kickoff,/title`; a
  repeated `sort` is `400`. In tree services, any listing parameter but `min` given twice is
  `400` (the first value was used).
- **`POST /read-grants`** answers `{ "checkpoint", "grants": [ … ] }` and may answer
  `503 behind` while the catalog service's checkpoint keeps moving. Catalog decisions read
  roles, their definitions, the catalog key, includes, place lists and namespaces' read and
  encryption settings as of the checkpoint they report, so a `/roles` change applies to new
  grants once the service has followed it, as for listings (§B.11.4, §B.11.5).
- **`patchlog import -ns src=dst` renames** (§G.4.4): references to `src` are rewritten and
  documents that change get new ids. It copied bodies unchanged and refused namespaces that
  schemas name. A mapping onto a branch of `src` keeps references and ids. A renamed
  namespace's snapshot documents go through `{dst}-upstream`. Import reports gain the doc
  class `resume`, `renamed` flags and entries.
- **Undo** (client): where the gesture listing and the namespace log can't be read, `PlanUndo`,
  `Undo`, `Redo` and `UndoStack` return `client.ErrNeedResources` unless `UndoResources` names
  the documents to scan.
- `GET /` answers `"spec": "0.50"`.

**New (v0.50):**
- **Several grants per exchange:** `POST /edge-grants` takes up to 50 grants as
  `{ "grants": [ … ] }` with no `Authorization`. A prefix several grants give gets one cookie,
  lasting as long as the longest; the body's `exp` is the earliest (Doors F12).
- **Finite sets of resources:** a rule testing `/resource` with a `schema` of only `enum`, or
  `compare` with `in` and a literal array, at top level or inside `all`, fixes it to those
  names, one cookie each; `compare` with `eq` counts as `value`, several fixing rules
  intersect, and more than 100 names over a request is `403` (Doors F12).
- **`edge.Cookies.Check` and `edge.CanonicalPath`** make §C.5's six MUST checks, for an edge
  written in Go; `edge.ParsePrefix` parses the core prefixes. The README gives the default
  format, the checks and an example cookie, which `TestCookieVector` pins.
- **Catalog decisions carry `checkpoint`**, the combined checkpoint they were decided at (the
  listings' `at`), in `POST /grants`, `/read-grants` and `/merge-grants` answers and in
  refusals that hold at it, so clients key cached decisions by it. `/read-grants` decides
  every item at one checkpoint: a reader may read all the items it named if no entry has an
  `error` (public items count as readable); a `4xx` entry is a refusal, and a `5xx` one is
  undecided, so the client asks again (Doors S19, F13).
- **Renamed imports** clone a set of namespaces, on another deployment or the same one:
  full-history documents are rewritten step by step with new ids, never fast-forwarded, with
  `source.ids` recording the source ids; pins take the new ids, in the order they need them;
  rewritten steps get fresh nonces where the target requires them; a re-run writes nothing, and
  one that stopped part-way resumes. References at undeclared positions are reported, not
  rewritten. Refused before anything is written: an incremental document that would change, a
  pin whose new id can't be known, and a schema whose `$id` names its own revision path.
  Catalog placement names aren't renamed, and configuration isn't in the bundle (Doors F14).
- **Undo for writers limited to some resources** (§11.2): `client.UndoResources(names…)` undoes,
  redoes and rebuilds the stack from those documents' logs; `UndoPlan.Level` is learned from
  what is read (a JWE log means sealed); e2e is refused (`ErrUndoE2ELimited`), since sealing
  needs the namespace document, and so is a gesture that may reach below a pruning horizon,
  which resource logs can't show. The playground's Undo and Redo do the same for the open
  resource.
- `derived.CanonicalQuery` builds the canonical form; the index's and tree's `next` URLs use
  it, so they answer without a redirect. The playground's Search tab sends one `sort`.
- The Varnish VCL strips `X-Edge-Verified` and `X-Edge-Prefix` from requests.

**Fixes:**
- `POST /edge-grants` decodes each grant once, however many namespaces it names, and stops at
  the first `401`, so a refused exchange of fifty large grants stays cheap.
- Index and tree: a non-sealed `at` URL in a non-canonical form was answered `200` there.
- The index no longer checks a `min` against the core's log before waiting for it.
- `import -ns` with a single plain name finds schema namespaces named by `$ref` values with a
  `#fragment`.

**Docs:** v0.15.0's upgrade notes now name `?min` on `POST /grants` and `/read-grants` (Doors
S14).

## v0.18.1

- **Weak ETags.** A reverse proxy that compresses responses (nginx `gzip`, Caddy `encode`, a
  CDN) turns the server's strong ETags into weak ones, `W/"…"`, around the same id. The
  playground kept the `W/"` in the ids it read, so its namespace logs and listings asked for
  `/ns/{ns}/rev/W/"…` and got `400 non-canonical URL`, and the Go client (`patchlog import`,
  export, follow) did the same. Both now take the id either way. Conditional reads already
  matched weak validators.

## v0.18.0

Server time per write. On the synthetic Demo Play bundle under a 10,000/s allowance, `patchlog
import` of its content takes 10.8 s into Postgres 16 (default settings, fsync on) and 11.1 s
into SQLite, against 19.6 s and 16.4 s with v0.17.0; of the whole bundle, 24.4 s and 28.5 s,
against 39.7 s on both. Into Postgres the whole bundle's batches now take about as long as the
allowance paces them.

- **Postgres: large values compressed with lz4.** Patch sets, documents, namespace entries'
  bodies and blob bytes were compressed with pglz, Postgres's default, which took most of the
  time of inserting revisions. The schema now sets lz4 on those columns where the server has it
  (PostgreSQL 14 or later built with lz4), for databases created before too, once, when opened;
  values written earlier stay as they are, and reads take either. On the synthetic Demo Play
  bundle into Postgres 16 (default settings, fsync on, 10,000/s allowance), inserting revisions
  took 16.3 s and takes 6.9 s, and `patchlog import` of the whole bundle took 39.7 s and takes
  26.6 s (batches 24.2 s to 19.0 s, of which the allowance's pacing is now 6.5 s); of its
  content, 19.6 s and 12.0 s.
- **A batch's schemas read ahead.** A write resolved each distinct schema path its documents
  name with three statements of its own, for the namespace, the resource and its head: a batch
  of the synthetic Demo Play bundle, whose data rows are typed by 1,149 schemas of one
  namespace, resolved about 260 on average. Step 5 now reads the revisions the documents pin by
  `$schema` ahead: the rows of their namespaces in one statement (on Postgres once their locks
  are held, taken in key order), then each namespace's resources and heads in two more, and the
  transaction keeps those namespace rows. Importing the whole bundle into Postgres ran 1.10
  million statements and runs 0.91 million (64,717 reads of a namespace by name are 428, 64,447
  of a resource by name 185, 64,289 of a revision 27, beside 333 new ones reading several at
  once); the server's CPU time in batches went from 19.3 s to 15.1 s, on SQLite from 25.8 s to
  22.4 s.
- **Server: a write's check does each thing once.** Step 3 copied every create's whole document
  out of its patch set, and an append's parent document after parsing it, and hashed each
  revision id again after the idempotent-retry lookup had; step 4 walked each resulting document
  for its depth, again for its strings and pointers and again for `$blob` members, and the blob
  check (on SQLite twice, before the write lock and in it) once more. A create's document is now
  its patch set's value, an append applies to the parent's document as parsed, each id is hashed
  once, and the limits are read in one pass from the document's canonical form, which step 4
  computes for `documentSize` anyway. Ids, stored bytes and the limits' answers are unchanged,
  except that of several strings or pointers over `valueSize` or `pathSize` the one reported no
  longer depends on map order. On the full synthetic bundle (in-process) the check phase uses
  27% less CPU on SQLite (15.1 s to 11.0 s) and 25% less on Postgres (18.5 s to 13.9 s), where
  the benchmark's peak heap went from 4.2 GiB to 3.3 GiB.

## v0.17.0

Bundle import on the shape of a measured deployment. `BenchmarkImportDemoPlay` builds a
synthetic copy from the measurements' document counts and sizes per namespace and kind: 64,887
documents, 1,149 of them schemas in the same namespace as snapshot documents, 48,532 data rows
most typed by them, 18 blobs. Under a 10,000/s allowance into a fresh SQLite target, `patchlog
import` of its content (16,355 documents) took 58.6 s with v0.16.1, 23.3 s with v0.16.2 and
takes 16.4 s, the importer's peak RSS 2.3 GB, 1.7 GB and 0.7 GB; of the whole bundle, 109.9 s,
50.8 s and 39.7 s (31.8 s with `-store-compression zstd`), RSS 3.2 GB, 2.8 GB and 1.5 GB. A
re-run of the whole bundle into the target that has it took 100 s, 12.8 s and takes 10.3 s.

- **Pacing by the allowance's burst.** Concurrent batches waited at the gate as if the bucket held
  nothing to spare, each for the draws of all those in flight: 28.5 s of waits on the whole
  bundle, now 2.5 s. The gate takes the bucket to hold what answered requests left (from one
  token when it starts, refilling to the burst), and sends a request once the server admits it
  and those in flight in whatever order it handles them: once the bucket holds a token more
  than they all draw but the least.
- **Namespaces ordered by pins.** Dependencies between namespaces come from pinned references
  only, as within a namespace: a pin of a full document needs its namespace, a snapshot
  document's pin of a bundled snapshot document its upstream namespace. Live references, which
  name no revision that must exist, made one cycle of a deployment's main namespaces, their data
  and both upstreams, which then went one after another.
- **Part of a bundle: `patchlog import -only ns,…`** imports only those source namespaces; `-ns`
  only maps names, so an import of part of a bundle needed a sub-bundle cut out of it, and asked
  for namespaces it then didn't write (a `403` on one it may not create). The others' documents
  are left out as `external` dependencies are (§G.4.1): before writing anything the import checks
  the target for what its documents reference in them, by id for pinned revisions of full
  documents and by name for live references, and requires a left-out snapshot document that
  they pin to be in its upstream namespace as the bundle has it. Staged imports, the namespaces
  others reference first, leave the target as one whole import does.
- **Server: a create stores its document once.** A resource whose head is its whole-document
  genesis, as after every create and every snapshot an import writes (upstream and target), kept
  the document twice: in its patch set and in `heads`. Reads cut it from the patch set, before
  looking for a heads row, with a scan for the value's end instead of a validation, and writes
  store no heads row for it. On the full synthetic bundle (in-process, file-backed SQLite) the
  database is 32% smaller, the write-locked phase uses 16% less CPU and the batches take 14% less
  time; cold reads of such documents are faster. Databases from earlier versions keep their heads
  rows until the head moves, and earlier versions read the new ones, folding from the genesis.
- **Server: compressed patch sets, opt-in (SQLite).** `patchlog serve -store-compression zstd`
  stores the patch sets of namespaces without encryption zstd-compressed, from 1 KiB and when
  that saves an eighth. They are compressed in the write's check phase, outside the write lock;
  ids, limits and reads stay over the canonical JSON, and heads, snapshots and encrypted
  namespaces are never compressed. On the full synthetic bundle (in-process, file-backed
  SQLite, on top of the change above) the database is 62% smaller, the write-locked phase uses
  17% less CPU and the batches take 12% less time; an uncached read of a created document takes
  47% longer at 15 KiB, 23% at 100 KiB. The synthetic content sets the ratio; real content may
  compress less. It is off by default because it is a one-way format change: earlier versions
  answer 500 for every resource with a compressed patch set, and turning it off again doesn't
  decompress them. The first start with it on records it in the database, and a start without
  it then logs that. Postgres refuses it: TOAST compresses there.
- **Snapshot documents held as their canonical bytes.** The importer kept every snapshot document
  as a parsed tree for the whole import, 1.3 to 5 times the size of its canonical form, though
  after planning it only serialised it again. It now keeps the canonical bytes, which the bundle
  reader computes for the digest anyway, and parses a document again only where planning reads
  it; batch requests are the same, byte for byte. x-ref and x-index walks no longer copy the
  instance location at every member. On the whole bundle (`BenchmarkImportDemoPlay`, two runs
  each, alternating), planning took 11.9–15.7 s and takes 5.8–6.3 s, the import 44.8–49.1 s and
  35.1–37.3 s, and the benchmark process's peak heap, its server's included, went from 3.2–3.3
  GiB to 2.4–2.5 GiB; on its content, planning from 7.3–11.6 s to 2.7–3.8 s.
- **Server: schemas resolved once per write.** A batch's documents typed by the same schemas
  resolved and parsed each for every document and `$ref`; a transaction now keeps what it
  resolved, per writer. Parsed schema revisions are kept by id apart from the document cache,
  which a large write fills with its own documents.

## v0.16.2

Bundle import speed. On a synthetic copy of a CMS deployment's content (6,900 snapshot documents,
121 MB, 350 layouts of 100–450 KB; `BenchmarkImportContent`), a `patchlog import` under a
10,000/s allowance into a fresh SQLite target took 58.6 s with v0.16.1 and takes 18.0 s: planning
27.8 s → 6.0 s. A re-run into a target that has it all took 26.7 s and takes 5.7 s, with 75
requests instead of 13,875.

- **Concurrent batches** (`-concurrency`, `ImportOptions.Concurrency`, default 4). A backfill
  under an allowance submits several batches at once, still in dependency order (§G.4.4): a
  namespace's batches start once those of the namespaces it depends on have committed, and a
  batch waits for one in flight that it goes on with or whose documents it pins. Each request
  waits at its namespace's gate until the allowance's bucket has refilled what the requests
  before it drew. A request in flight counts as drawing no earlier than now, so the server
  handling requests out of order doesn't overdraw the bucket. A namespace has only as many
  batches in flight as the allowance's burst holds the draws of, and, where the allowance ends,
  as its rate draws in half the minute before its `until`, so every batch is sent while it
  holds. The first failure stops the rest: batches waiting to send send nothing. The timings
  count wall time covered, not the sum of overlapping waits and requests. Without an
  allowance, batches go one at a time as before.
- **Ordering by pins.** Within a namespace, items follow the documents they pin (schemas
  included), not live references, which name no revision that must exist. An upstream
  namespace no longer depends on a target namespace that holds only snapshot documents (its
  pins of them point upstream once rewritten), so the two no longer form a cycle. Within a
  cycle, what upstream namespaces need of it (schemas, full documents) goes first, then the
  upstream namespaces (§G.4.4 "Upstream first"); they went by name.
- **Re-runs read nothing they can predict.** An upstream head that is the genesis revision of
  the rewritten snapshot, as an earlier import wrote it, is that snapshot: neither its document
  nor its chain is read. A chain is read only when a fast-forward needs it, and not for a target
  where the previous import left both.
- **Planning.** Patch sets the import already holds as values no longer go through JSON text
  and back for revision ids, sizes and blob scans; each is serialised once. Request bodies are
  written as canonical JSON instead of by reflection. Bundle lines are parsed, and snapshot
  documents' x-ref walks run, on parallel workers. Snapshot documents are rewritten in place
  instead of copied, and reference scans don't format a pointer for every string.
- `patchlog import` reads only the bundle's header before importing, unless `-ns` renames a
  namespace; it read the whole bundle once more first.
- **Server: a create's document isn't serialised twice.** The stored document is cut from its
  patch set's canonical form, and the rules envelope parses the patch set again only when a rule
  reads `patches`. Request bodies from clients are parsed as before.
- **Server: a genesis that adds the whole document is its snapshot** (D.4). It no longer gets an
  intermediate snapshot of its own, which doubled a large create's writes; the count of patch
  sets towards the next starts after it, and a read at the genesis cuts the document from it.
- **Server: rate buckets don't refill backwards.** A request that read the clock before another
  drew on the same bucket took tokens off it as negative time; concurrent requests could be
  answered `429` early.
- `BenchmarkImportContent` imports the synthetic content bundle (`PATCHLOG_CONTENT_SCALE`
  scales it), reporting planning, batch and total time, requests and peak heap.

## v0.16.1

- **Index and tree services: a purged namespace or catalog answers `410 purged` with `head`**,
  its `purge-ns` entry, as the core does (§8.5, §12), after the read check; it was `410 gone`
  before any check.
- **Index and tree services read namespaces unrestricted as §C.5 defines** (B8): one read role
  without rules on `/resource` is enough, so a grant with a rule-free reader role and a role
  testing `/resource` by pattern shares a plain reader's subject set and unfiltered answers,
  where it was filtered per item. `grantcheck.ReadsAll` is gone.
- `bundle import` into a namespace it creates splits and paces batches by the `limits` and the
  importer's `allowances` entry of the document it creates it with, not the §6.6 defaults.
- Outgoing HTTP without a configured client (remote branches, sealed grant export, release
  granters, CDN purges, schema fetches, `patchlog health`, `internal/client`) goes over one
  shared clone of `http.DefaultTransport`, never the default transport itself.

## v0.16.0

Implements spec **v0.49**. v0.47 settles all sixteen of the reference's v0.46 notes, most as
the reference did them; v0.48 adds withdrawing edge-grant cookies, references across
namespaces and namespaces that require nonces; v0.49 settles all twenty of the reference's
notes on those two, most with changes here: purged namespaces, access, nonces, import dry runs
and `/_refs`. Fixes implementer reports B7, B8 and B9.

**Changes to check before upgrading (v0.47, v0.49):**
- **`/ns/{ns}` URLs need unrestricted read** (§C.5): the namespace document, its log, events
  and long-polls, `/heads`, `/branches` and `/grants/…`, everything under `/ns/{ns}` but the
  gestures listing and `POST /ns/{ns}/keys`. A grant that reads only some resources (a key
  with `readScope`, or a rule referring to `/resource` in its blocks, its key's scope or every
  read role it carries) now gets `404` there, as for any read it may not make. `/grants/…` was
  `403`; the others answered it, listing names and heads its reads hide. A resource's own
  event stream needs `read` on that resource only, so per-resource grants can now follow it.
  Roles are alternatives, so one read role without `/resource` rules is enough, also for
  branching, remote registration and a batch's source check, which refused a grant with any
  role testing `/resource`. Branching and registration check read as gate step 1 checks verbs
  (v0.49), in a public namespace too: the grant must allow `read`, read unrestricted and pass
  its rules on `/action`, `/principal` and `/now` with `/action` `read`, leaving rules on
  `/doc` to step 6. Registration on a public namespace didn't check read, and branching a
  public base skipped those rules.
- **A purged namespace answers `410` with `code: "purged"`** (was `gone`) **and `head`**, the
  `ns_id` of its `purge-ns` entry, which is the log's last, so a consumer needn't re-read
  `/ns/{ns}` (§8.5, §12, v0.49):
  - on `/r/{ns}/…`, `/ns/{ns}/grants/…`, `/ns/{ns}/gestures/…` (in sealed and e2e namespaces
    too, which answered `404 not_offered`), `POST /ns/{ns}/keys` (`404` before any check) and
    `/heads` at any revision, which listed the resources before; after the read check, the
    grant's rules included, cached with the long class (§9). `/ns/{ns}` and its log stay
    readable: the log's `purge-ns` entry says what happened.
  - on every write, after authorisation and rate limits and before any other check, the
    idempotent-retry lookup included: resource writes, batches, blob uploads and copies,
    purges, prunes, config writes, namespace purges, branching from it and remote
    registration. A batch with a config change is refused only after its items'
    authorisation and its rate-limit draw.
  - The name stays reserved: creating a namespace or branch under it is `412`, also for a
    retry of the request that created a branch since purged, which replayed `200`.
- **Edge grants for grants with roles** (`POST /edge-grants`): one role that lists `read` and
  qualifies (none of its rules refers to `/resource` or `/now`, and they pass now for the
  principal) is enough; the grant's blocks and key scope apply on top and may fix `/resource`.
  A role whose own rules test `/resource` never qualifies, even one fixing it, which 0.15.4
  accepted. The answer is all or nothing: any refused namespace refuses the request, `401` if
  any would be `401`, else `403`, where the first refused namespace used to decide. A purged
  namespace is decided last, once the grant verifies and may read there, and the answer is
  `410 purged`, with the `head` of the first one the grant names, only if every refusal is
  one (v0.49). While authentication is disabled, issuance is `404 not_offered`.
- **`POST /ns/{ns}/keys` refuses as other reads do** (§7, §E.2.3, v0.49): a grant that doesn't
  name the namespace is `403`, as for one that doesn't exist (it was `404`), and is ignored in
  a public one (`401`). A `read` grant whose rules refuse reading the namespace unrestricted,
  and that has no read role referring to `/resource` through which it could get `K_r`, is
  `403` (was `404`): epoch keys open every resource. Without `read` it stays `404`.
- **Schema revisions pinned by a public referrer need no grant** (§6.1, v0.49): a
  `schemaReads` referrer in a listed namespace that is public, and neither sealed nor
  end-to-end, opens the revisions it pins to every request, a grant then being ignored as for
  public reads; without a grant such a read was `401`. Any other referrer, one in a public
  sealed namespace included, needs a grant that names its namespace, verifies there and may
  read it, where a grant naming a public listed namespace counted unverified. Answers stay
  `private, max-age=300`. Whether a revision is open is kept per revision path until a write
  to an open listed namespace or a change of configuration or namespaces, so anonymous reads
  don't scan those namespaces each time.
- **A missing or reused `$nonce` in a sealed namespace is `422 nonce`** (was `422 invalid`;
  §C.7, §E.2.5, v0.49), still at gate step 3, so it gets one code whether the namespace is
  sealed, requires nonces or both. A failed `test` or patch is still reported first, as
  `invalid`.
- **Index `?ref=` queries without `q` or `sort` page by resource name** (§A.4, v0.49): `after`
  is a bare name, any string serving as the bound, and `next` is the `after` of the following
  page, which a client sets on the `at` URL it got, as `/_refs` pages; `after` was an offset
  and `next` a URL. Counts still cover every hit. Other queries keep offsets and `next` URLs,
  and a non-numeric `after` is `400` there. The playground's "More results" follows both.
- **`429` bodies carry `retryAfter`**, the wait in seconds as a decimal (§6.6); `Retry-After`
  stays whole seconds, rounded up. `client.APIError.RetryAfter` prefers the body's.
- `GET /` answers `"spec": "0.49"`.

**Also in v0.47:**
- **`schemaReads` referrer reads reach the origin** (§6.1): a schema revision read by a
  reader of a referrer, with the grant in `Authorization` (none for a public referrer, above),
  is served whether or not the request carries the edge's verification, `private, max-age=300`
  and `no-store` for shared caches, since an edge that knows only prefixes forwards it
  undecided. Behind `-edge-secret` it was `403 edge_required`.
- **`fields=` follows the schemas** (§A.4): a path is checked against the `x-index` marks of
  the schemas the namespace's documents use, not against indexed values, so whether a query
  fails never depends on the data. A marked path no document has values at is accepted and
  left out of hits; an unmarked one is `400`; a schema that can't be read for now is `502`. A
  schema marks a path when an `x-index` is reachable from its root along it, as v0.49 now
  defines: through `$ref`, `$dynamicRef`, `properties`, `patternProperties`,
  `additionalProperties`, `dependentSchemas`, `items`, `prefixItems`, `contains` and every
  branch of `allOf`, `anyOf`, `oneOf`, `if`, `then` and `else`, never through `not`,
  `propertyNames` or `unevaluated*`, with array items at their array's path.
- **A read under an edge-grant cookie checks its `exp`**, so an event stream opened under one
  (the browser case: `EventSource` can't send `Authorization`) ends there; it kept serving
  past the grant's expiry.
- **A `401` no longer shows which namespaces exist:** a grant whose key a namespace doesn't
  list said `unknown key "<kid>"`, where a namespace that doesn't exist says `no key can
  verify the grant`; both now say the latter, also in `POST /edge-grants`' all-or-nothing
  answer (§C.4, §C.5).
- The text now says what the reference already did: operator grants to a missing namespace
  (`401`, a forced purge `404`), a branch's own `kid` applying again once its base removes the
  same `kid`, index hit values, placement titles over item titles, undoing carried gestures,
  dry runs drawing rate tokens, and allowances matching `sub` alone without authentication.

**New (v0.48):**
- **`DELETE /edge-grants?prefix=…`** withdraws edge-grant cookies at sign-out (§C.5): `prefix`
  repeatable, as issuance returned them (`/r/{ns}/{name}`, `/r/{ns}`, `/ns/{ns}`). It answers
  `204`, `no-store`, with an expired `Set-Cookie` of the same name and attributes per prefix (a
  repeated one once), and needs no grant; it answers the same with authentication disabled,
  so sign-out works either way. Another parameter, a bad prefix or none is `400 bad_input`.
  Its CORS preflight is allowed only for credentialed origins, so another site can't sign a
  reader out.
- **`GET /_refs?to=<reference>`** in the index (§A.4) answers "who uses this?" across every
  namespace the index follows that the reader may read, branch previews included, `to` in
  any form `?ref=` takes. It redirects to `/_refs/at/{at}/g/{gs}?to=…`: `at` is a combined
  checkpoint over only the namespaces the answer covers (the body's `namespaces`), so writes
  elsewhere don't move it. `gs` is computed over markers alone: `reads:{ns}` for each private
  namespace the grant reads unrestricted (one read role without `/resource` rules is enough),
  `reads:{ns}:scope:{digest}` for one it reads in part, the digest covering the rules that
  limit it there and the `/principal` values they refer to. Rules on `/now` there make such a
  namespace unreadable, and readers with no marker share the empty set's `gs`.
  - It leaves out namespaces not reached yet, purged ones, and sealed or e2e ones whose keys
    the index doesn't hold. `?min={ns}:{ns_id}` is repeatable, and `400` for a namespace the
    answer doesn't cover; on an `at` URL, a kept answer whose `at` includes every `min` is
    `200`, otherwise it waits and redirects. Only a reader who may see none of the
    namespaces gets `401` or `403`, and an unreadable namespace document is `502` only for a
    namespace the grant names; any other is left out as private.
  - Hits carry `ns` beside the `?ref=` fields, are filtered per resource and come in byte order
    of namespace, then resource name. A page holds `limit` hits after `after`, given as
    `{ns}/{name}`, and `next` is the following page's `after`, which a client sets on the `at`
    URL. Hits from sealed and e2e namespaces are sealed per entry, and an answer with any is
    served only at its canonical URL.
  - Answers are tagged `idx:{ns}` and `r:{ns}/{name}`, kept a minute as B9's results are, and
    dropped by purges.
- **Namespaces that require nonces** (§C.7): `"nonce": "optional" | "required"`, guarded like
  `keys` (in a branch, a `*` key of the base). Where it is required, gate step 3 refuses a
  resource create, append or restore whose resulting document lacks a fresh-form `$nonce`
  differing from its parent's (the last live document's for a restore) with `422 nonce`, item
  by item in batches and dry runs, whatever the patch set's origin; a `[]` restore sends a
  lone fresh `$nonce` instead. Deletes and config, branch and prune writes are exempt. A
  branch copies the setting and can't turn it off, and a base can't start requiring it while
  a branch at any depth that isn't purged, frozen ones included, doesn't: `409 in_use` with
  `dependents`, leaves first, the order to set them in (v0.49). It is `422` in an e2e
  namespace. A remote branch of a base whose current namespace document requires nonces must
  be created requiring them (`422` otherwise); it isn't a dependent at its base, which may
  start requiring them later. Schema namespaces created to mirror for it start optional,
  since their history keeps its ids, and take their source's setting with a config write by
  the creating operator once it is in; they stay optional if the source's namespace document
  can't be read. A schema document may carry a top-level fresh `$nonce`.
- **Tools add the nonces:** undo and redo give every patch-set step of an inverse a fresh
  `$nonce` where nonces are required (a tombstone's inverse is a lone-nonce restore); merge
  plans add one to kept-at-base steps, resolution and squash sets there and in sealed targets
  (new for resolution and squash sets), and squash diffs leave `$nonce` out. Snapshot imports
  create the upstream namespace with its target's setting and nonce the patch sets they
  generate; a full-history import whose revisions lack nonces is refused before anything is
  written (use snapshot mode). `schema import`, release documents (`internal/release`), the
  release tool's stored plans and locks, and the playground (editor restores and the "add
  `$nonce`" preset, catalog folders and moves, undo, blob uploads) add one too where
  required. A writer whose grant can't read the namespace document (rules on `/resource`,
  §C.5) doesn't know the setting, so in a private namespace undo, `schema import`, the release
  tools and the playground add one to every patch set whose document is an object (v0.49,
  §C.7, §11.2; `client.NeedsNonce`), and undo and redo take the encryption level as unknown
  rather than stopping at the document. Bundle imports need the target's namespace documents
  anyway. The playground's catalog panel adds one in sealed catalogs too.

**Also in v0.49:**
- The text now says what the reference already did: edge-grant prefixes are the cookie paths
  (`/r/{ns}/{name}`, `/r/{ns}`, `/ns/{ns}`), `DELETE /edge-grants`' answers, with `prefix` the
  core's one repeatable parameter, `POST /ns/{ns}/keys` serving grants limited per resource,
  a schema document's fresh `$nonce`, the operator creating an import's missing namespaces,
  and what marks a path with `x-index` (above).

**Faster bundle imports, again (B7).** A backfill dry-ran every batch before submitting it,
and a dry run draws the tokens its submit does (§6.6), so each batch paid twice, half of it
in `429` waits:
- **Dry runs:** an import dry-runs only the first batch of each existing target namespace,
  before anything is written, and submits the rest directly: a batch is atomic, so a failed
  submit writes nothing either, and it lists its items as a dry run did. In a namespace the
  import creates, the first item of the first batch is dry-run once the namespace exists, so
  a server that would give the revisions other ids stops the import before anything is
  written there. A later batch that moves heads the target had (a fast-forward, a resolved
  conflict, a restore; not a snapshot's diffs upstream, which no live reference sees) is
  dry-run before its submit, its blobs sent first, since a failure after it would leave
  those heads moved (§G.4.4, v0.49). An import that fast-forwards existing documents pays a
  dry run per such batch, about 20 s per 1,000 items at `-pace 1`; fresh imports pay none.
  `-dry-run` dry-runs the same batches, but for one that goes on with a chain an earlier
  batch cut, reports failures that only need earlier batches written as deferred, uploads no
  blobs (they show as deferred `blob` failures) and writes nothing. A batch that fails only
  for blobs left to its local source is sent again with them uploaded.
- **Pacing** counts every draw (dry runs, submits, blob uploads) with or without an
  allowance, paces dry runs too, and repays a chain cut between batches at
  `ratePerResource`, for its submit and its dry run alike, which an allowance doesn't
  replace (§G.4.4). After a `429` the importer waits by the body's `retryAfter`.
- At `-pace 1` a 1,000-item batch takes about 20 s instead of about 39 s, with no `429`s;
  under a 1,000/s allowance about 1.5 s instead of about 2 s. The reported import (64,887 documents
  in 145 batches into an empty deployment at `-pace 1`, no allowance) drew 894 tokens a batch
  at the principal's 50/s and took 55 min; it now takes about 22 min plus blob uploads. That
  is the floor the default `ratePerPrincipal` sets (64,887 / 50 = 1,298 s): only an allowance
  or a higher `ratePerPrincipal` lowers it, and under a 1,000/s allowance the import takes a
  few minutes.
- The report gains `timings` (planning, blobs, batch requests, paced, after `429`s), which
  the CLI prints as a `time` line. `TooLargeError`, `import -h` and `serve -h` name the
  deployment maximums (`serve -max-items-per-batch`, `-max-batch-size`), and a `401` or `403`
  on the first read of a target namespace says what grant the import needs: read and write in
  every target namespace; an operator grant only creates namespaces, so create missing ones
  first.
- Planning drops a `/heads` listing that answers `410` (a purged namespace) and looks the
  names up, as for a frozen one. `BenchmarkImport` runs against the default limits, adds 6 KB
  documents and reports per batch the batch requests' time, paced waits and `429` waits.

**Edge grants for catalog readers (B8).** A catalog read grant for a reader holding a
rule-free reader role and roles that test `/resource` by pattern was `403` at
`POST /edge-grants`; with roles as alternatives (above) it gets the item's prefix.

**Index answers stay at their checkpoint (B9).** A query redirected to `/{ns}/at/{current}`
was redirected again whenever a write moved the checkpoint before the reader followed it, so
under steady writes readers chased it. The redirect now computes the result at the checkpoint
it names and keeps it, as every result computed or served is kept: in memory, for a minute, at
most 64 MiB, keyed by the result's URL (namespace, `at`, query and the reader's subject set,
and for a sealed namespace the view the result is bound to). A kept result answers its `at`
with `200` however far the checkpoint has moved, so a query takes one redirect from the head
pointer and at most two from a stale `at`; the query's cost moves to the redirect. A purge
drops the kept results showing what it purged.
- Measured (`TestHopsUnderWrites`): at 40 writes/s and 4 readers, 2.7% of follows took two
  redirects on 0.15.4; with 20,000 documents, 200 writes/s and 16 readers, 8% were still
  redirected after five. Now every follow takes exactly one, also while purges of documents
  the queries don't show are applied.
- 0.15.4 redirected more than 0.15.2 because B6 made queries far cheaper: readers make many
  more follows, each racing the same checkpoint rate. Apply batch sizes didn't change.
- **Tree and catalog listings too** (v0.49, §A.4, §B.5): the tree service keeps every listing
  it computes, the one at the `at` a redirect names included, for a minute (at most 64 MiB per
  catalog), so one redirect suffices at any write rate, and an older `at` answers `200` while
  its listing is kept instead of `302`. Listings are keyed by their URL (subject set and
  sealing view included) and by what the reader reads whole, so a reader whose
  namespace-wide reads changed since (a public namespace turned private) isn't served one
  kept from before; listings that depend on the individual reader aren't kept, and sealed
  ones are served only at their canonical URL. A purge drops the kept listings it purged
  (`r:{ns}/{name}`, `ns:{ns}`, `rs:{catalog}`). The index, `/_refs` and the tree service share
  this store (`internal/kept`).
- **Consumers learn a purge from `/heads`** (§8.5, §10): `internal/follow` takes its
  `410 purged` (when starting from a snapshot, or for a branch purged before it got there) as
  the namespace's `purge-ns` entry, at the position the `410`'s `head` names (v0.49; it reads
  `/ns/{ns}` for it when there is none), reports the purge and ends with `ErrPurged`. The
  follower was restarted, or the branch reported failing, indefinitely; the index now answers
  `410` for such a branch.

## v0.15.4

**Faster bundle imports.** A backfill spent nearly all its time sleeping: it paces at half
the lower of the namespace and principal rates (25 items/s at default limits), 40 s per
1,000-item batch, against about half a second of work.
- **Under an allowance** (§6.6) the importer now paces at the allowance's full rate, since its
  bucket holds up no other writer, and splits batches by its `itemsPerBatch`/`batchSize`. It
  finds its own allowance as the core does (the grant's root `sub` and `kid`, or the author
  with authentication disabled), counts every draw (dry runs, uploads, copies) so it doesn't
  run into 429s, and from a minute before the allowance's `until` goes back to the
  namespace's limits. With an allowance of 1,000 items/s, 2,000 documents wait 3.5 s instead
  of 80 s; 145,000 would take minutes instead of over an hour. Without one, pacing is as
  before, less the time each batch took. Progress lines say what the import is paced by.
- **Planning** reads target heads from `/heads` pages instead of one `GET` per document
  (twice in snapshot mode): 0.005–0.014 requests per document instead of 1–2. A small import
  into a large namespace keeps per-document lookups.
- `BenchmarkImport` (`internal/bundle`) measures an import's work, requests per document and
  the time it would sleep.

The client's requests use a connection pool of their own, a clone of
`http.DefaultTransport`, so code that closes the default one's idle connections doesn't
break them.

## v0.15.3

**Index queries cost what their matches cost (B6).** Every index query read the namespace's
documents in order and tested each against its facets, ranges and `?ref=`, so a facet
matching 100 of 48.7k documents read all of them, and with `sort=` sorted them all. A query
is now driven by its most selective filter when that pays: its matches are read from the
filter's index and looked up, and the other filters tested per document. Which filter drives
is decided by a bounded count on the index, and the plan doesn't depend on SQLite's
statistics. On 48.7k documents, one query / 50 at once:

| query | before | after |
|---|---|---|
| `facet[/accountId]=…` | 109 ms / 6.2 s | 9.4 ms / 0.57 s |
| … `&sort=/accountId` | 237 ms / 17.2 s | 9.7 ms / 0.64 s |
| … `&counts=…` | 602 ms / 29.8 s | 10 ms / 1.15 s |
| … `&q=…` | 5.4 s / 193 s | 137 ms / 10.8 s |
| `ref=…` | 3.9 s / 421 s | 10 ms / 0.76 s |
| a facet with 5,000 values | 7.2 s | 39 ms |
| `ge[/score]=500&lt[/score]=501` | 289 ms | 3.7 ms |

Queries with no selective filter (a plain listing, a facet most documents match) scan as
before. The index replaces `refs_q` with `refs_t`, which leads with the namespace; it is
built when the index opens (about a second per 500k references).

**Development:** CI runs the race detector in jobs of its own; tests run in parallel
(`t.Parallel()`); and Postgres tests reuse migrated databases from a pool, emptied between
tests, instead of creating one each (`internal/pgtest`). CI takes about 2 minutes instead of
5.

## v0.15.2

**Performance**, follow-ups from the v0.15.1 review:
- **Branch `/heads` pages** looked up the branch's base namespace once per name that reads
  through. A read transaction now reads each namespace row once: a branch page takes 27–33 ms
  instead of 161–164 ms on Postgres (a branch of a branch, 34–38 ms instead of 288–297), and
  20–29 ms instead of 36–38 ms on SQLite.
- **The index's `-fetch-concurrency`** now limits fetches across all followed namespaces
  and branches together, not per namespace: `-ns a,b,c` sent up to 24 GETs at once to the
  core (whose Postgres pool has 16 connections) and now sends at most 8. It must be at least
  1.
- **The index reuses its connections** to the core: its client keeps an idle connection per
  fetch (new `client.WithIdleConns`), where `http.DefaultTransport` kept 2 and redialled the
  rest after every page. Catching up 3 × 2,000 documents opened 8–12 connections instead of
  1,500–2,100, at the same speed.

## v0.15.1

**Performance** (found by profiling with the new OpenTelemetry spans). End to end, against
v0.15.0 on a shared 4-CPU box, mixed reads (head pointers, revisions, logs, `/heads`) went
from 557 to 1,552 requests/s on SQLite and from 549 to 1,015 on Postgres, with p99 down from
281 to 66 ms and from 248 to 68 ms:
- **Namespace log pages** resolved each entry's `prev` with its own query (one per entry, a
  round trip each on Postgres). They now come from the page's own rows: a page takes 18 ms
  instead of 160 ms on Postgres, and 13 ms instead of 48 ms on SQLite.
- **`/heads` on SQLite** now batches its lookups as Postgres already did: 48 ms instead of
  218 ms per page.
- **The index** fetches a page's documents concurrently (`-fetch-concurrency`, default 8)
  instead of one at a time, applying them in log order as before. On Postgres under steady
  writes its lag fell from about 950 ms (max 2.6 s) to 24 ms, and `?min` reads no longer
  time out with `503`. The trade-off: it now keeps up, so its reads compete with writers, and
  write throughput with the index and tree following fell by about 23% in that test; lower
  `-fetch-concurrency` trades freshness back.
- **Authenticated reads** now use the read cache once the request is authorised (it served
  only public namespaces before), and verified grants are cached by token, keeping only
  grants that verified. Warm authenticated reads take 0.8 ms instead of 1.3 ms, and the
  authenticated workload ran 29% faster. Authorisation still runs on every request, and
  cache-control is unchanged.

**Build:**
- **Smaller release binaries:** releases, the Docker image and `make build` build with
  grpc-go's `grpcnotrace` tag. It drops gRPC's own request tracing (`golang.org/x/net/trace`,
  off unless `grpc.EnableTracing` is set, which nothing here does), and with it
  `html/template` and `text/template`, whose reflection disabled the linker's dead-code
  elimination. OTLP export over gRPC and HTTP is unchanged. linux/amd64 is 28.4 MB (32.2 MB
  in v0.15.0), linux/arm64 26.7 MB (30.3 MB), darwin/arm64 27.5 MB (31.2 MB),
  windows/amd64 29.0 MB (32.8 MB). A plain `go build`/`go install` works the same, about
  3.8 MB larger.

## v0.15.0

Implements spec **v0.46**, which adopts most of Doors' feedback, fixes the server bugs
Doors reported, and adds OpenTelemetry.

**Changes to check before upgrading:**
- **Keys follow the base both ways:** a branch now accepts keys added to its base after
  it was created (recursively through local bases); a kid both have is the base's entry
  only (§C.4).
- **Operator grants** authorise only creating namespaces (remote branches included) and
  forced purges. A request under one to a namespace that doesn't exist is now `401`, not
  `404` (a forced purge still gets `404`).
- **The gestures listing** answers any reader, filtered to resources its grant may read
  (§7.4); a `?after` naming a resource it can't read is `404`.
- **Unfreezing a branch** whose base already has `branchesPerNamespace` live branches is
  `422 limit`; frozen branches no longer count toward the limit (Doors B3).
- **CORS:** `-cors-origin '*'` with credentials no longer echoes an arbitrary origin;
  credentialed origins are listed with `-cors-credentials-origin`.
- **Catalog `?min`:** `POST /grants` and `POST /read-grants` now honour `?min` (§B.11),
  which earlier versions accepted and ignored. The service waits up to `-min-wait`
  (default 2 s) for it, then answers `503 behind` with `Retry-After: 1`; a malformed `min`,
  or one naming a namespace the service doesn't follow, is `400`. A client that already
  sent `min` must retry a `503` (Doors S14).
- **Tree database** gains an `items.title` column, and **index database** a `sort.raw`
  column; both are added or rebuilt on start.
- `GET /` answers `"spec": "0.46"`.

**New (v0.46):**
- `schemaReads: { for }` in a namespace document: its schema revisions resolve for writes
  in the listed namespaces that pin them, and can be read by revision path by readers of
  documents pinning them, without a grant on the namespace (§6.1).
- `POST /edge-grants` issues edge grants as `Secure`, `HttpOnly` cookies per prefix, which
  the origin verifies itself when no edge is in front (`-edge-grant-key`, else derived from
  `-edge-secret`); cookies authorise only `GET`/`HEAD` under their prefix (§C.5).
- Catalog: `?min` on `POST /grants` and `/read-grants`; a `title` pointer copied into
  listings; `inheritPowers` in `$access` (§B.5, §B.11).
- Index: schema documents indexed under their dialect, with their `$ref`s as references;
  `self: true` on self-references; hits carry sort values and `fields=` (§A).
- Client: undo stacks count a merged gesture for its source author, and `Undo` with
  `UndoAuthor` finds it (§11.2). Bundles look up keys through a branch's bases.

**OpenTelemetry** (off unless `OTEL_*` exporters are configured): traces and metrics over
OTLP (gRPC or HTTP), console output, W3C propagation; route-named HTTP server spans for
`serve` and every service, client spans on outbound calls, engine write spans
(`core.WriteResource`, `core.Batch`, …), transaction spans, and metrics for writes,
group-commit sizes, Postgres lock waits and consumer lag. See the README's Observability
section; `compose.yaml` has an optional Jaeger profile (`--profile otel`). No measurable
cost when off; the binary grows by about 11 MB (the OpenTelemetry SDK, protobuf and gRPC
libraries; the gRPC exporters themselves are about 0.4 MB of it).

**Fixes (reported by Doors):**
- The index's `?min=` redirect could bounce between two checkpoints during an update;
  redirects now follow the committed checkpoint and only move forward (B1).
- `schema_unavailable` named the dialect URL instead of the unresolved pin; it now names
  the revision path. A schema document could `$ref` a revision the writer can't read once
  the validator had cached it; read permission is now checked on the whole closure (B2).
- The standalone tree service left heads and URLs out of listings for grants reading only
  some resources of a content namespace (B4).
- The batch retry lookup read every batch the author had written; it now looks up one
  resource's history (5,000 earlier batches: 24.8 → 0.5 ms per batch on SQLite) (B5).

## v0.14.1

Implements spec **v0.45**, which settles the reference's remaining notes from v0.42 and
v0.44. Nothing changes in behaviour: the text now says what the reference already does.
`GET /` answers `"spec": "0.45"`.

## v0.14.0

Implements spec **v0.44**: reverse-reference queries in the indexing service (Addendum A).

**New:**
- The index collects every `x-ref` reference of typed documents by §6.5's walk, with the
  schema revision each document pins (no `x-index` needed), into a new `refs` table.
- `?ref=/r/{ns}/{name}` finds the documents that reference a resource in any form;
  `…/rev/{id}` only those pinned to that revision; `…%23{entry}` only those naming that
  entry. It combines with the other filters, and hits carry `refs: [{ path, ref }]`.
  Malformed or repeated `ref` is `400`.
- An index database from before v0.44 is rebuilt once at startup, so its references are
  collected.
- `GET /` answers `"spec": "0.44"`.

## v0.13.0

Implements spec **v0.43**, small fixes from the reference's v0.42 notes.

**Changes to check before upgrading:**
- **An operator key authorises only within its period:** grants it signed are refused
  before its `from` as well as after its `until` (§C.4). A key configured with
  `-operator-key` and no history entry is unaffected.
- `GET /` answers `"spec": "0.43"`.

The other v0.43 changes state what the reference already did: grants in sealed namespaces
are sealed under the epoch of the first entry recording them, repeated query parameters are
`400`, and a bundle line whose writing namespace is unknown carries neither `written` nor
`grant`.

## v0.12.0

Implements spec **v0.42**, which settles the reference's v0.41 notes on signatures.

**Changes to check before upgrading:**
- **Unknown query parameters are `400 bad_input`** on every core endpoint, before
  authentication, as are repeated parameters and flag values other than `1`
  (`dry-run=true` used to be ignored and the write made).
- **The gestures listing pages with `?after=`**, as §7.4 says; it took `?since=`. The Go
  client and the playground follow.
- **Author signatures are checked at §6.2 step 2.3**, after rate limits, the retry lookup
  and settling the verb: an idempotent retry is answered as first recorded whatever
  signature it carries, even after `required` was turned on; `403` and `429` come before
  `422`; a dry run reports `422 signature` per item; a write without a usable precondition
  gets `428`/`400`. A batch whose config change is stale fails with that change's `412`.
- **`GET /ns/{ns}/grants/{gid}`** is offered in sealed namespaces (sealed, `pl: { ns, grant }`,
  stored once) and end-to-end ones (clear, `Cache-Control: private`), and is `410` once the
  namespace is purged; `not_offered` is gone. `client.Grant` opens sealed answers.
- **An operator key past its `until` authorises nothing**; it used to be accepted after it.
- `GET /` answers `"spec": "0.42"`.

**Bundles and archives:**
- A grant line's `ns` is the namespace whose entry first recorded the grant; `key` is
  optional, looked up in the namespace document at that entry, then the operator key history
  at the first naming revision's `created`, and left out otherwise.
- History lines for revisions written elsewhere (a branch's read-through, a remote branch's
  base) carry `written`, used in the signing input, so branch bundles verify.
- Sealed and end-to-end exports carry grant lines (`ExportOptions.Bearer`/`Identity` for
  sealed grants); a grant the exporter can't fetch is left off the lines that would name it.
- Pruning archives (§8.6) carry authors and grant lines; restore skips them.

**Performance:**
- **Heads pages on Postgres take a few statements, not three per resource.** A page now
  reads its resources, their heads at `at` (one `LATERAL` join on `head_history`) and those
  revisions in one statement each per namespace level, and resolves from memory.

## v0.11.1

**Fixes:**
- **`GET /ns/{ns}/rev/{at}/heads` pages in time proportional to the page, not the
  namespace.** Each page used to list every name and resolve every head at `at`, and only
  then page, so listing a namespace cost O(N²): about 14 s for 20 000 documents on SQLite
  and 14 minutes for 50 000 on Postgres. A page now takes its names from the `(ns, name)`
  index after the cursor, in byte order (on Postgres, a new `name COLLATE "C"` index),
  and resolves only those. Names with no head at `at` are skipped by fetching further
  chunks. Reported by an implementer.

## v0.11.0

Implements spec **v0.41**: verifiable author signatures (§C.3.1), adopted from the
reference's proposal P1.

**Changes to check before upgrading:**
- **Signatures whose kid the grant lists are now verified** at the end of §6.2 step 1,
  before rate limits: `422 signature`. A malformed `Signature` is `400`, and so is a
  `Signature` header on a batch request (steps carry their own `signature`).
- **Grants:** a root block may list `signers`; a narrowing block carrying it, or a malformed
  entry, makes the grant invalid (`401`).
- Every batch step now stores its own signature; only an item's first step used to.
- `GET /` answers `"spec": "0.41"` and adds `jwks_uri`.

**New:**
- `"signatures": "optional" | "required"` namespace-document member, guarded by a `*` key
  (of the base, in branches). Under `required` every revision and tombstone needs a valid
  signature by a signer of its grant.
- Resource logs and write responses serve each revision's `grant: { id, sub, kid }`.
- `GET /ns/{ns}/grants/{gid}` serves stored grants (`{ id, root, stored }`), including those
  of local bases up to their `at`; `404 not_offered` in sealed and end-to-end namespaces.
- `/.well-known/patchlog-keys`: the operator key history as a JWK Set (`serve
  -operator-key-history`, `-jwks-uri`).
- Go client: `WithSigner`, `SignWrite`, `Step.Signature`, `Client.Grant`, `OperatorKeys`.
- Bundles with authors carry grant lines (with the key each verified against) and a `grant`
  member on history lines; `patchlog bundle verify -signatures [-source URL]` reports
  verified / attested / failed / unsigned / unverifiable per revision.
- `patchlog import`, `merge` (plan/apply/release) and `rebase` sign their own steps with
  `-sign-key kid:seed` or `$PATCHLOG_SIGN_KEY`.

## v0.10.0

Also implements spec **v0.40**, which adopts most of the reference's v0.39 notes.
Two came out the other way, and the reference now follows the text:

**Changes to check before upgrading:**
- **A batch's config change costs a rate token** from the principal and namespace
  buckets unless it is exempt (a `*` key, or only a freeze), as a config write does
  (§6.6). A config-only batch used to cost nothing.
- **A branch of a non-public base can't be `public`, sealed or not** (§7.4), and
  remote branches likewise. A public sealed branch also counts again as a
  dependent that keeps its base from going private (`409 in_use`). Existing public
  sealed branches of private bases are left as they are.
- `GET /` answers `"spec": "0.40"`.


A conformance review against spec v0.39. **This repository is the reference
implementation; the specification is maintained outside it and `docs/SPEC.md`
mirrors that text (see the note at the top of the README).**
[docs/SPEC-FEEDBACK.md](docs/SPEC-FEEDBACK.md) states the reference's positions
the mirror doesn't yet describe. The changes below fix the implementation to
match the spec as written.

**Fixed:**
- **The gate order of §6.2 now holds on every namespace-level write.** An
  unauthenticated caller answers `401` for resource writes, batches, `PATCH /ns`,
  branch creation, remote registration, purge, namespace purge and prune, whatever
  preconditions it omitted and whatever purged state the namespace is in (they were
  allowed to elicit `428` or `410` first). A valid grant without the verb now
  answers `403` before a purged namespace's `410`, which itself comes before the
  precondition's `428` — the order v0.32 pinned for blob uploads.
- **A config-stale batch's idempotent retry draws its rate tokens** (§6.6): the
  whole-batch replay answered `200` without the step-1 draw, so a client could
  re-send it for free.
- **§9's cache classes** on the answers the pagination work had missed: a non-live
  `/log` range's `404` is `short` and its purged `410` is `long`; an unknown id of
  `GET /ns/{ns}/rev/{id}` and `/heads` is `short` (`public, max-age=5`, or
  `private, max-age=5` at the edge) instead of `no-store`.
- **A batch's body-limit step no longer pre-empts the gate:** the purged-namespace
  `410` it answered before the items were authorised moved to the gate proper, so a
  batch's `400`/`403`/`410` report follows §6.2's order.
- A grant with `exp` exactly at an epoch's start is given that epoch's key
  (`POST /ns/{ns}/keys`, §E.2.3 reads "started after").
- Loopback origins accept the whole `127.0.0.0/8`, as §G.3 says (was only
  `localhost`, `127.0.0.1`, `[::1]`).
- The static `x-ref` walk finds references under `propertyNames` and `contentSchema`
  (§6.5), so exports and reverse-reference consumers no longer drop them.

**Added:**
- **A config write may carry `Gesture` and `Undoes`** (§7.2, §7.4): a config entry
  is a single write, so its headers are validated (`400` otherwise),
  stored with the entry outside its id, mixed into what its log entry serves, and
  echoed on the response — a retry answers with what was recorded. This was
  previously ignored silently.

## v0.9.0

Implements spec **v0.39**: gestures for undo and redo.

**Added:**
- **Gestures (§7.2).** Writes may carry `Gesture` and `Undoes` headers (26 base32 characters, `400` otherwise), stored with each revision or tombstone as metadata outside its id; retries answer with what was first recorded. Batch steps may be `{ "patches" | "delete": true, "gesture"?, "undoes"? }`, with item and batch defaults. Resource and namespace logs serve them (`gestures` per step for batches), pruning keeps them, and CORS allows and exposes both headers.
- `GET /ns/{ns}/gestures/{gesture}` lists a gesture's revisions and undos, paged, for readers of the whole namespace; not offered (`404`) in sealed and e2e namespaces.
- Merges carry each replayed revision's gesture (squashing drops them); bundles with `"authors": true` carry them too.
- **Undo and redo (§11.2)** in the Go client: `PlanUndo`, `Undo`, `Redo` and `UndoStack`. The inverse of a gesture's own entries, widened to whole arrays, is checked against the later log for overlapping writes (`ConflictError`) and written as one batch guarded by `ifMatch` with a fresh gesture and `Undoes`; pruned history, missing blobs and schema migrations are reported as `ImpossibleError`. Works for plaintext, sealed and (with `UndoE2E`) e2e namespaces, using the endpoint or a log scan.
- The playground sends a gesture per save, shows gestures in history and the namespace log, and has undo/redo for the current author (plaintext and sealed namespaces).

**Changes to check before upgrading:**
- `client.Delete` takes write options (`…, head string, opts ...WriteOption`) and returns a `*WriteResult`.

## v0.8.0

Implements spec **v0.38**.

**Changes to check before upgrading:**
- **`GET /`** answers `{ "spec": "0.38", "auth": "grants" | "disabled", "origin" }`. Merge, release and janitor tools read the mode from it; `client.WithAuthDisabled` is gone and the tools' `-dev` flag is accepted but ignored.
- **Entries written with authentication disabled record `"grant": null`.** While a deployment runs `disabled`, `merge.authors` and `abandoned` checks match them on their author; under `grants` they count for no one. Entries written in dev mode before this release serve no `grant` and count for no one, so a merge batch or `abandoned` flag written then must be written again.
- **Namespace-document errors** are `422` `code: "invalid"` with `errors: [{ pointer, message }]` (no `path`).
- **E3 prune snapshots** are served at `/rev/{H}` (`200 application/jose`, `X-E2E: snapshot`; a tombstone horizon answers `410` with the snapshot in the body) and are never log entries. Readers fold from `/rev/{H}` plus the range after it.
- **Catalog restore** answers in the spec's order (`404`, `410`, `403`, `409`) and refuses (`403`) a restore that would widen access compared with the item's state at deletion; catalog admins may still restore. Moves of deleted placements are checked like any other move.

**Added:**
- The addenda's namespace-document members (`catalog`, `catalogs.{catalog}`, `merge`, `merged`, `cleanup`) may carry `x-` members; a write may remove a member only an earlier version defined.
- Remote branches ignore members of the base's documents they don't define, whatever the base's spec version.
- Catalog visibility evaluates a role's rules as a read would (the spec's `translator` example now sees its items), counts roles only through subjects the catalog's key may assert, and is pinned to the listing's checkpoint. Grants are issued through those subjects only.
- A reader with namespace-wide read on the namespaces a manifest, `problems` or `orphans` answer covers gets it, without needing every trusted namespace.
- Schema namespaces mirrored for a remote branch record the creating operator's grant.

## v0.7.0

Implements spec **v0.36** and **v0.37**.

**Changes to check before upgrading:**
- **Namespace documents are strict (§7.4).** Only the members the spec defines are accepted (`read`, `keys`, `roles`, `revoked`, `rules`, `limits`, `allowances`, `retention`, `encryption`, `maxLag`, `base`, `frozen`, `successor`, `drafts`, `catalog`, `catalogs`, `merge`, `merged`, `cleanup`, `abandoned`); any other member must start with `x-` (`422` otherwise). Documents stored by earlier versions are served as they are, and a write that leaves such a member unchanged keeps it; rename with `{"op":"move","from":"/title","path":"/x-title"}`. A new branch can't inherit an undefined member. Addendum members are now checked in their shapes, `revoked` entries must be revocation ids, and key entries refuse `x-` fields.
- **Log ranges are paged (§7.1).** `…/rev/{id}/log?since=` answers at most the log page size (default 1,000, `serve -log-page-size`) with `X-Log-Next` when the range goes on. Every bundled client follows pages; other clients must too, and treat a page that stops short without `X-Log-Next` as an error.
- **Namespace log entries carry `grant: {id, sub, kid}`** instead of `kid` (§7.4). Existing databases are migrated: head, tombstone and batch entries get the grant their revisions recorded; older config, branch, purge, purge-ns and prune entries serve none. The merger and janitor match `merge.authors` against the recorded grant: an `abandoned` flag set before the upgrade must be set again, and in dev mode tools must be told so (`client.WithAuthDisabled`, implied by `-author`).
- A retry of a write to a purged resource is `410` (was `200` from the retry lookup, or `409`/`412`).
- `schema import` no longer adds `$schema` to closed schemas, since validation ignores it now (below); `-declare-schema` restores that for servers before this release.
- `tree -release` serves one catalog.
- Catalog listings follow §B.11.5's visibility exactly: folders are visible only through roles without rules, and `problems`, `orphans`, `manifest` and unfiltered `g/all` listings need namespace-wide `read`.

**Added:**
- Validation leaves out a document's top-level `$schema` and a top-level `$nonce` of the fresh-nonce form (§6.2 step 5), so closed schemas type documents as they are; reference walks, annotations, the e2e client and the playground validate the same instance.
- Restore a deleted item through the catalog (`want: ["restore"]`), decided by the roles frozen when it was deleted (§B.11.4).
- Release previews follow the release document live (§B.5); the playground relists with `?min` after its own writes.
- `GET /` answers `{ "spec": "0.37", "origin" }`; remote-branch creation refuses a base of a later version whose documents hold members this version doesn't know.
- `PATCH /ns` answers with `X-Namespace-Revision` and a body `{ config, ns_id }`.
- Blobs can be uploaded to a deleted resource before the restore that references them.
- `/heads` is in byte order of name on both backends.
- `serve`, `index` and `tree` speak HTTP/2 without TLS (h2c) as well as HTTP/1.1 (§7.7). CORS exposes `X-Log-Next`; with `*`, every response carries the allowance.
- **Postgres group commit per namespace** (D.8): under contention, checked writes of one namespace are committed together in one transaction (`-group-commit`, default 32; `-group-commit-wait`). Throughput in one namespace keeps rising with load instead of falling. `-group-commit 1` keeps the old behaviour.

**Fixed:**
- Event streams catch up a page per fetch instead of reading the whole history at once.

## v0.6.0

Implements spec **v0.35**: a delete's rule envelope carries the document being deleted.

**Changes to check before upgrading:**
- The rule envelope of a `delete` now carries the document being deleted as `doc` (before, `null`). A rule that relied on `/doc` being absent for deletes (e.g. `test /doc exists: false` to single out deletes) now behaves differently; test `/action` instead. Rules about a document's shape should exempt `delete`, or documents written under earlier rules can't be deleted.
- A batch item with two `"delete"` steps in a row is now `422 invalid` (it was `410`).

**Added:**
- Rules can decide deletes by content, e.g. only a document's owner may delete it (§6.4.1, §6.4.4). `doc` is read through the bases in a branch, and in a batch it is the document after the item's earlier steps. At E3 `doc` stays `null`, so a delete rule reading `/doc` refuses there. `purge`, `purge-ns` and `read` keep `doc: null`.
- Unplace grants from the catalog service fix `/doc/parents` to the placement's current parents, so it can't be moved before it is deleted (§B.11.4).

**Fixed:**
- A resource's event stream could end without its `purge` event when the purge committed between the stream's two reads (seen on Postgres).

## v0.5.0

Implements spec **v0.34**: feedback from implementing v0.33 (drafts, `in_use`, release tooling, D.8 locking).

**Changes to check before upgrading:**
- Forcing a purge refused as `in_use` (`?force=1`) now needs a grant chained to a deployment operator key (`serve -operator-key`), or, for a purge of a branch or of a resource in one, a `*` key of that branch. A `*` key of a namespace that isn't a branch no longer forces.
- Schema paths in another namespace are now read by the rule for other namespaces (§7.5): the request's grant or a `Source-Authorization` grant must name that namespace and verify under its keys. A grant naming only the namespace written no longer reads schemas in another private namespace.
- `drafts` is `422` in remote branches (and their branches) and in e2e branches.
- Catalog merge grants: the catalog service needs `-merge-key`, `-merge-kid` and `-merge-service`, and issues merge grants only to the merge service; list `{ "sub": <merge service>, "kid": <merge key> }` and every catalog admin who approves `$access` changes in the catalog base's `merge.authors`. `merge.MergeGranter` returns a `*MergeGrantResult`.
- Release plans now carry a digest: plans stored by v0.4.0 must be planned and approved again before `apply`.

### Spec v0.34: drafts and other namespaces (§6.1, §7.4, §7.5)

- **One rule reads other namespaces**, for batch sources, blob copies, drafts and the schema's own namespace: the request's grant or any `Source-Authorization` grant that names the namespace, verifies under its keys and allows the read (a public namespace needs none). Blob copies used the header's grants only when it was present; now either serves. A path `N` can't resolve for the writer, absent or unreadable, falls through to drafts (as before for absent; now also for unreadable by this rule).
- **`drafts`**: `"*"` serves every namespace; `422` outside local branches that aren't e2e; not inherited: branch creation drops `drafts`, `merged` and `abandoned` (besides `frozen` and `successor`). **`GET /ns/{ns}/branches` shows each branch's `drafts`.**
- **Client:** `Branch.Drafts`; `ResolveOptions.For` applies the candidates' visible `drafts.for` for the namespace a document is in (best effort; the index's schema cache and e2e validation pass it). `DraftsMatch`.
- **Exports** needing a draft fail with `bundle.ErrSchemaUnavailable` (`schema_unavailable`), unless the schema's namespace is declared external, when the export walks the draft's content (same everywhere) and the importer checks the target.

### Spec v0.34: forcing `in_use` (§3.5, §6.1, §8.5)

- `?force=1` with a deployment operator key (whose grant then acts without the namespace's rules), or a branch's `*` key for purges in that branch, on `POST /r/{ns}/{name}/purge` and `POST /ns/{ns}/purge`.
- **`forced: true`** on every entry a purge that overrode an `in_use` refusal writes, propagated ones included, in the hashed entry (`internal/verify`, `client.NSEntry.Forced`, remote-branch mirroring). A purge nothing refused isn't marked.
- The `referencing` list names the referencing namespaces in which the caller may read anything (one readable resource suffices), with the request's grant or any `Source-Authorization` grant (now passed on purges and config writes).

### Spec v0.34: releases and catalogs (§F.9, §F.8, §F.6, §B.11.4)

- **Plan digest** (`merge.PlanDigest`, `ReleasePlan.Digest`, `ReleaseStep.Digest`): over the release revision and, per step, every item with its precondition and plaintext steps, `$nonce` values left out, the second half of a split node as `"after": {step, key, item}`. `approve` fails unless planning again gives the stored digest (and `-digest`, if given: `ErrDigest`); `apply` rebuilds each step before submitting it and stops for a new approval if it differs (`ErrPlanChanged`).
- **Catalog merge grants** (`POST /merge-grants`): signed with a dedicated merge key (`catalog.Options.MergeKey/MergeKid/MergeService/MergeTTL`, `tree -merge-key -merge-kid -merge-service -merge-ttl`), only for the merge service, whose grant is the `Authorization`; the approver's grant (`Approver-Authorization`) is checked. Root `sub` the merge service, `attrs.approvedBy` the approver, no groups, rules exactly the batch's `/resource` and `/action` pairs, five minutes by default.
- **`$access` changes** are checked as a dry run and answered `{ "admin": true }`; the merge service submits them under the approver's (a catalog admin's) grant narrowed with its own `via`, the batch's actions and pairs (`ReleaseOptions.AdminGrant`, `Via`; `merge release -merge-bearer`).
- **Folder creation** (§B.11.4): `POST /grants {node, want: ["create"], to}` needs `move` on every folder in `to` and refuses `$access` for non-admins; in merge batches a new folder needs `move` on its parents (was `place`), and tree powers on a folder come only from its own `$access` (admins may enter one nobody holds powers on yet).
- **Step 2** creates a folder a narrowing move needs with its own `$access`, in one piece (no stripped "folder" halves); `catalog.Powers` and `StripPowers` are gone. Tombstoned schema resources merge in step 1. A `placed_item` is fine if step 2 removes the placement.
- **`merged.at`** is the target's `ns_id` after the last batch into it (for the catalog, step 4's), not its head when merged is recorded.
- **`abandoned`** (§F.6): the janitor verifies it (set by a config write under a `*` key of the branch, its own or a base's) and purges after `cleanup.abandoned`; `merge.AbandonRelease` / `patchlog merge release abandon` freeze every branch with it.
- Release previews (§B.5) already hid unreadable branches; the release lock and the release document's optional `at` already matched the definitions (documented).

### D.8 (Postgres)

- **A separate advisory log lock**, `pg_advisory_xact_lock(0x504e, ns)`, taken last and held through commit, orders namespace entries, replacing `SELECT … FOR NO KEY UPDATE` on the namespace row. Several are taken in ascending order (purge propagation, branch creation); a transaction holding one never waits for a namespace lock. Throughput (`-bench 'CreatesOneNamespace|Batch1000'`, interleaved runs, medians, before → after): 166 → 161 writes/s from one writer, 503 → 508 from 8, 431 → 464 from 32, 395 → 473 from 64; a 1,000-item batch 272 → 265 ms.
- **Blob uploads** keep the namespace lock shared; an uploader's pending total is now ordered by a row of its own (`blob_uploaders`): concurrent uploads by one uploader could together exceed `blobPending` before.


### Schema import

- **`schema import` keeps closed blueprints usable and remembers their source.** (1) A typed document's `$schema` is validated against the schema it names (§6.1), so a schema closed at the root (`additionalProperties: false`, `unevaluatedProperties: false`) rejected every document using it; the import didn't add the declaration. For every imported resource the subschemas applying at the instance root (the root, and what it reaches through `$ref` within and across resources, `allOf`, and every branch of `anyOf`/`oneOf`/`if`/`then`/`else`) that are closed now get `"$schema": {"type": "string"}` in `properties`, unless `properties` or a matching `patternProperties` already covers it. This is reported as a conversion (`declared $schema in N closed schemas…`, also in `-json` and the playground plan); a patched subschema also used below the root (a shared `$defs` entry) permits a `$schema` key there too, which is reported; one with `maxProperties`, or a `propertyNames` that rejects `$schema`, is left alone with a warning. `-no-declare-schema` (`Options.NoDeclareSchema`) opts out. (2) `$id` can't be kept (§6.1), so each imported resource's root, and each document bundled under `$defs` for a cycle, now carries `"x-source"` (fetched URL or upload name) and, when the document declared a different `$id` or draft-04 `id`, `"x-source-id"`. Both change content and so revision ids: re-running an import of schemas imported with v0.4.0 appends new revisions to each (and to what pins them); after that, re-runs are idempotent again.

## v0.4.0

Implements spec **v0.33**: schema drafts in branches and releases across namespaces. Also search and schema import in the playground, `patchlog schema import`, and graceful shutdown with health endpoints.

**Changes to check before upgrading:**
- A purge (resource or namespace) that would remove the last available copy of a schema revision that documents still reference is now refused with `409 in_use`. Override with `?force=1` and a `*` key.
- `Source-Authorization` may be repeated; any grant in it that verifies for a namespace serves for it.
- `serve`, `index` and `tree` now drain on SIGTERM (default `-shutdown-timeout 30s`). Give containers a stop grace period longer than that.
- Varnish probes moved to `/_health`.

### Search in the playground

- **Playground:** a **Search** tab queries the index service (Addendum A): a namespace, `q`, `schema`, facet and range filters, `sort`, `counts`, `limit` and paging. Hits show the resource, schema, score, facets and revision, and open in the Resource tab. The checkpoint the index redirected the query to is shown. "Wait for my last write" passes `min=` with the page's last `X-Namespace-Revision` for the namespace. Sealed results (§E.2.6), whole or per hit, are decrypted with the playground's keys; end-to-end namespaces get a note, and a core without an index says so.
- **`serve -index-url URL`:** mounts a read-only proxy to one index service (it serves several namespaces) at `/playground/index/`, like `-tree-url` does for the tree service: `GET`/`HEAD` only, `Authorization` forwarded, cookies and upstream CORS headers dropped, a sandbox CSP, the index's checkpoint redirects rewritten under the prefix, and a two-minute response timeout for `?min=` waits. The two proxies share one implementation.
- **compose:** `compose.yaml`, `compose.host.yaml` and `compose.postgres.yaml` pass `-index-url`, so the demo stack's Search tab finds the seeded `demo` documents.
- **Compose:** the index runs with `-branches`, so branches made in the demo (e.g. from the playground) get their own searchable preview index.

### Schema import

- **`patchlog schema import`:** brings external JSON Schemas (http(s) URLs such as schemastore.org, or local files) into a namespace as schema resources, so documents can use them under §6.1. It fetches every document they `$ref` (base URIs per JSON Schema, `$id` in subschemas, draft-04 `id`), converts them to draft 2020-12 as the server accepts it (`definitions`, array `items`, `dependencies`, boolean `exclusiveMaximum`; unknown keywords become `x-*`), and rewrites every `$ref` to a same-document pointer or a pinned revision path plus JSON Pointer, anchors resolved to pointers. Revision ids are predicted client-side so schemas are written leaves first; reference cycles are merged into one resource under `$defs`. Every schema is compiled before writing, then all are written in one atomic batch (chunked beyond the batch limits). Re-running with unchanged sources writes nothing; a changed source appends. `-name`, `-dry-run`, `-json`, `-max-docs`, `-max-bytes`, `-timeout`. See "Importing external schemas" in the README.
- **Playground:** a **Schemas** tab imports external JSON Schemas from the browser. `POST /playground/schema-import/plan` (`{ns, sources, files, name?}`) runs the `schema import` plan without writing (per document: source, resource, action create/append/restore/unchanged, predicted revision path, rewritten schema, warnings, merged cycles) and returns the batches to write; it reads current heads in process with the request's own `Authorization`/`X-Author`, so a caller plans against what they may read, and uploaded files resolve relative `$ref`s by file name. The tab plans, shows the table and each rewritten schema, then writes the plan itself through `POST /ns/{ns}/batch` with the user's grant (chunked beyond the limits), checks the server-assigned ids against the predicted ones, and shows the root's pinned `$schema` path with a copy button and a "start in the Resource editor" button.
- **`serve -schema-fetch` / `-schema-fetch-hosts`:** URL fetching by the plan endpoint is off by default (uploaded files only). `-schema-fetch` enables it; `-schema-fetch-hosts a,b` limits it to those hosts (redirects and references included), which are also trusted with private addresses. Other hosts are refused when any resolved address is loopback, private, link-local, CGNAT, multicast or unspecified (checked at dial time, connecting to the checked address; environment proxies are ignored). The demo composes enable it for schemastore and raw.githubusercontent.com.
- **`internal/schemaimport`:** `Options.Files`/`NoDisk` plan from in-memory files; `Result.Chunks`, `Resource.Item`/`WireItem` and `BatchLimits` separate planning from writing; `GuardedClient`/`DisabledClient` are the fetch guards.

### Graceful shutdown and health

- **Graceful shutdown** for `serve`, `index` and `tree`. On SIGTERM/SIGINT a server drains (health answers 503, keep-alives off), keeps serving for `-shutdown-delay` (default 0), then stops listening and waits up to `-shutdown-timeout` (default 30s) for requests in flight. Long-polls answer their normal `204` at once, event streams end, and `?min=` waits answer as if they had run out, instead of holding shutdown up. Only when the timeout expires are the remaining requests cancelled, so their transactions roll back; the core's database is closed, and the purge queue flushed, only after every handler has returned. Previously a fixed 5 s timeout closed the database under running handlers. A second signal exits at once. Each phase is logged with the requests it waited for or cancelled.
- **Health endpoints** on all three servers: `GET /_health` (200 `{"status":"ok"}`, 503 `{"status":"draining"}` once shutdown starts; no database access) and `GET /_ready` (also 503 if the core can't reach its database). Both are `no-store` for browsers and CDNs. The `_` prefix can't collide with a namespace or catalog name.
- **`patchlog health [URL]`:** exits 0 if the endpoint answers 200, for container healthchecks without curl or wget.
- **Compose:** healthchecks for the core, index and tree use `patchlog health`; they pass `-shutdown-timeout=20s` and stop with `stop_grace_period: 30s`; the CDN waits for all three origins to be healthy. `compose.host.yaml` keeps healthchecks off (those hosts refuse `docker exec`) and its seed polls `/_health`. The Varnish backend probes read `/_health`, so a draining origin leaves rotation, and health paths are never cached.
- **Core:** `Engine.Ping` (the `/_ready` check), and `Options.BeforeCommit`, a test hook that runs in every write transaction just before it commits.

### Spec v0.33: schema drafts in branches

- **Spec v0.33, core (§6.1, §7.4):** draft schema revisions in branches. In a write to a branch, a `$schema`/`$ref` path its namespace can't resolve is looked up among that namespace's local, non-e2e branches (branches of branches included, own revisions only) that serve the target: the branch itself and its branches, plus the namespaces a new `drafts: {"for": [...]}` member lists (names or `prefix*`) and their branches. The writer needs `read` there, with the request's grant or any grant of `Source-Authorization`, which may now be repeated everywhere it's read (resource writes, batches, blob copies). Paths naming a branch stay `422 schema_ref`; namespaces that aren't branches still resolve only in the path's namespace. Batches to a branch can reference schemas drafted by their earlier items.
- **`in_use` by last copy (§6.1):** references count every revision a branch wrote, and are satisfied by any available copy (in the path's namespace, or in a candidate branch serving the referencing branch). A resource or namespace purge that would remove the last such copy, narrowing `drafts.for`, or raising a draft branch to `e2e` is `409 in_use`, listing the `referencing` namespaces the caller can read. `?force=1` with a `*` key overrides purges, now also for namespace purges. On Postgres a purge locks other copy holders shared (D.8), so concurrent purges of the last two copies can't both succeed. The `revisions` index on `id` is renamed `revisions_by_id` (D.2) on both databases.
- **Federation and bundles (§G.3, §G.4):** creating a remote branch whose documents reference a draft is `422 schema_unavailable`; `patchlog export` refuses such a document with an error naming the branch.
- **Client:** `WithSourceAuthorization`, `WithSourceGrants`, `BatchRequest.SourceAuthorizations` and `CopyBlobWith` send several `Source-Authorization` grants; `ResolveSchema`, `SchemaResolver`, `FindDraft` and `IsBranch` find drafts as validating consumers must. The search index's schema cache resolves drafts for documents of branches; e2e merges validate as the target's gate would (`E2E.ValidateIn`); bundle imports find draft schemas for `x-ref` walks.

### Spec v0.33: releases across namespaces

- **Spec v0.33, release tooling (§F.9):** releases across namespaces.
  - **Release documents** (`internal/release`): `Doc` (`name`, `at`, `branches: {base: {ns, at}}`, `on`, `owners`, unknown fields kept), `Parse`/`Validate`, `ParseRef`, `Load` (live or pinned link, through the client) and `Write`.
  - **`patchlog merge release plan|approve|apply|status`** (`merge.PlanRelease`, `ApproveRelease`, `ApplyRelease`): the four-step merge: schema resources by fast-forward only in `$ref` order, catalog changes that narrow access (the §B.11.4 test on the step-2 batch as a whole; folders a narrowing move needs are created without roles carrying `place`/`move`, which step 4 adds), content branches, then catalog changes that widen access. Conflicts are reported before anything is submitted: `schema_changed`, `narrows_and_widens` (resolved with `-split KEY/NODE=narrow.json`, two halves), `step2_widens`, `placed_item` (`-accept-placement`), `dangling_pin`, `foreign_draft`, `schema_unavailable`, `merge` (content resolutions with `-resolve KEY/NAME=file.json`), and the pre-approval `base_chain`, `frozen`, `purged`. The plan is stored as `{release}.merge` in the release document's namespace (`-state-ns`) with the release revision; approval freezes every listed branch and records its config id; unfreezing a branch or changing the release document invalidates the plan; each step is classified again with a dry run before it is submitted and recorded when done, so `apply` resumes and never reverts; every branch records `merged` only after step 4. One release per catalog base at a time: a lock resource `merge-lock.{catalog}` in the state namespace.
  - **Catalog merge grants (§F.8):** the catalog service's `POST /merge-grants` folds a catalog branch's merge batch onto the base, checks every item as in §B.11.4 (`$access` needs the admin group; placements, moves with no widening, unplacing and edits need the tree powers; a new folder needs `place` on its parents) and signs one grant whose root is the caller under the catalog's key and whose rules allow exactly the batch's resources and actions. The release merge submits steps 2 and 4 under it (`merge.HTTPGranter`, `-catalog-service CAT=URL`), so the catalog's `merge.authors` lists the merging person with the catalog's `kid`.
  - **`patchlog merge release rebase -suffix S`** (`merge.RebaseRelease`): successors of every branch, schema branches first with `drafts.for` naming the other successors in their creation patches; resources whose entries reference a replayed draft are squashed onto its new revision; old branches are switched; a new revision of the release document lists the successors.
  - **Release previews (§B.5):** `tree.Options.Branches` / `patchlog tree -release LINK` follows the listed branches in place of their bases (bootstrapped from their `/heads` at their first entry, `follow.AsBranch`): checkpoints, the combined checkpoint, cache tags, `/_status`, item `url`s and read checks use the branches, so a viewer sees only branches it can read; previews only, no grants.
  - **Janitor:** draft branches (with `drafts`, or holding schema documents and listed by a `-release`) are purged after every other branch; a purge refused with `in_use` is retried at the end of the sweep, then reported as `retry`, never forced.
  - **Merge library:** `Options.SourceAuthorizations` and `Options.BatchClient`, `Plan.Order`, `Plan.Force` (an item for a resource that classifies as merged through a partial merge point), `Plan.SetBatchClient`, `RebaseOptions.Patches` and `Prepare`; `catalog.DiffAccess`, `Powers`, `StripPowers`, `ParseIncludes`; `tree.BuildGraph`, `Graph.With`, `Graph.Actual`, `Graph.ItemHref`.

## v0.3.3

CORS fixes: dev-mode writes and resumed blob downloads from other origins.

- **CORS:** `X-Author` (the author under `serve -dev`) and `If-Range` are allowed in requests, and `X-E2E` is exposed in responses.
- **Tests:** two index tests no longer race the index's checkpoint against the batch they inspect (seen once under `-race` in CI).

## v0.3.2

CORS for the servers, for demos and apps on other origins.

- **CORS** for `serve`, `index` and `tree`, for demos and apps on other origins:
  - `-cors-origin` (repeatable or comma-separated, or `*`) or `PATCHLOG_CORS_ORIGINS`.
  - Preflights are answered by the server; the headers the API reads (`Authorization`, `If-Match`, `Blob-From`, …) are allowed and the ones it sets (`ETag`, `Location`, `X-Namespace-Revision`, …) exposed.
  - With a list of origins, responses say `Vary: Origin`, so the CDN keeps one copy per origin; `*` keeps one for all.
  - `-cors-credentials` for pages that send cookies (grants travel in `Authorization` and don't need it); `-cors-max-age`.
  - The compose files pass `PATCHLOG_CORS_ORIGINS` through.

## v0.3.1

Faster writes on both databases. On Postgres, writes to different resources of one namespace now run in parallel.

### Postgres: writes in one namespace run in parallel

- Resource writes and batches hold their namespace's lock shared. Config writes, purges, prunes, branch operations and blob uploads still take it exclusively.
- Only the namespace-log append is serialized: two statements and the commit, under the namespace row's lock.
- Two writers racing on one resource still give one success and a 412 with the new head. A write that keeps losing retries with the namespace locked exclusively, so every write finishes.
- Every write is now checked inside its own transaction (`LockedCheckBytes` 0).
- Batches insert their rows in multi-row statements.
- Missing resources are cached within a transaction.
- The counts that decide intermediate snapshots live on the resource row.
- New columns, migrated on startup: `namespaces.head_id`, `resources.snap_revs`, `resources.snap_bytes`.

### CPU, both databases

- Blob-reference walks skip documents without `$blob`.
- Canonical key sorting compares ASCII names bytewise.
- Each document's and patch set's canonical form is computed once.

### Measured (4 vCPUs shared with the database, fsync on)

Writes/s, p99 in brackets, for 20–70 KiB creates into one namespace:

| | 1 writer | 8 | 32 | 64 | 1,000-create batch |
|---|---|---|---|---|---|
| Postgres, v0.3.0 | 35 (51 ms) | 51 (228 ms) | 52 (1,376 ms) | 54 (3,225 ms) | 2,623 ms |
| Postgres, now | 161 (11 ms) | 438–500 (40–60 ms) | 350 (282 ms) | 343 (799 ms) | 330 ms |
| SQLite, v0.3.0 | 43 (45 ms) | 81 (154 ms) | 98 (419 ms) | 108 (887 ms) | 1,079 ms |
| SQLite, now | 381 (18 ms) | 669 (32 ms) | 664 (83 ms) | 721 (118 ms) | 252 ms |

## v0.3.0

Implements spec **v0.32** (`docs/SPEC.md`). Blobs are now complete across every namespace level and tool, blob bytes live on disk, and writes on Postgres are faster.

### Blobs everywhere

- **Sealed namespaces (E2):** `GET …/blob/{bid}` redirects (`302`) to `…/blob/{bid}/e/{e}`, which serves the blob in the binary sealed form (`application/vnd.patchlog.sealed-blob`, zero-padded). Each epoch's sealing is stored once; the first instance to store it wins. A blob is served under exactly the epochs of the revisions that reference it. A request for a blob whose revisions have no epoch yet fixes one under the current epoch.
- **End-to-end namespaces (E3):** clients encrypt each blob under its own key, which travels in the sealed reference. Each `sealed` op declares in plaintext the blobs its document references. The server checks those lists (`blobsPerDocument`, availability, sealed type, no duplicates) and uses them for attaching, pruning, purge and bundles. Readers flag revisions whose list differs from the document.
- **Merges** keep E3 blob ids and carry the declared lists over.
- **Bundles** export blob lines and import them: blobs are uploaded, or copied with `Blob-From` within one deployment, before the batches that need them. Sealed bundles seal blob lines like any other line.
- **Archives:** restore brings back the blobs that pruning ended.
- **Remote branches** mirror their base's blobs up front, from plaintext, sealed and E3 bases, and check each one against its id.
- **Playground:** blob references show as chips with previews (images, text), open and download. An "Attach file" control uploads files into public, sealed (with `Blob-Nonce`) and E3 namespaces (encrypted in the browser).
- **Go client:** `GetBlobRef`, `EncryptBlob`/`DecryptBlob`, `E2E.UploadBlob`/`GetBlob`.

### Blob storage on disk

- Blob bytes are stored as files: `serve -blob-dir DIR` or `PATCHLOG_BLOB_DIR`. A SQLite file database defaults to `<db>.blobs/`.
- Each file is written and fsynced before its row commits, and deleted only after the commit that frees it. Every stored copy has its own name, so a cleanup can't delete a concurrent re-upload. A sweep on the leader removes orphan files.
- Range requests read only their range. Bytes encrypted at rest are still per-resource and decrypted whole.
- **Postgres:** several instances must share the directory. Without `-blob-dir`, Postgres keeps bytes in the database and logs a line at startup.
- Rows that the earlier table stored keep working; no migration is needed. Back up the database and the blob directory together.

### Postgres

- **Faster writes:** a small write sends 16 statements instead of about 32. That's 2.9 ms instead of 4.4 ms on a local `postgres:16` with fsync on, and 0.9 ms instead of 1.34 ms when writing in parallel.
  - Small writes are checked inside their namespace's lock, skipping the separate check transaction.
  - Author and namespace ids are cached.
  - Rows are reused within a transaction.
  - A few queries were merged.
- **A second CDN purge:** a durable queue (`cdn_repurge`) sends every CDN tag purge again once no stale instance or replica can still serve the old content.
- **Leader checks:** background jobs confirm they still hold leadership before each step.
- A retried transaction no longer draws rate-limit tokens twice.

### Spec v0.32 behaviour changes

- **Blob upload order (`PUT`):** a purged namespace answers `410` after authorisation and rate limits. A copy with a body or an unreadable `Blob-From` is `400` before anything is read.
- **Pending uploads:** a write that references a blob ends every pending upload of it in that resource, including blobs already attached.
- **Batch `source`:** a bad `source.at` is `422` with the new code `source`. It is checked only for callers who may read the source; for anyone else, the source makes no blobs available.
- **Dry runs** report missing blobs and carry on with the later steps.
- **E3 prune** no longer takes a `blobs` list: the server already keeps every revision's declared list. Clients sort declared lists by binary id.
- **Bundles:** a blob line comes before the first line that mentions the blob (`test` values included). A local import doesn't copy blobs that the batch's `source` already covers. E3 blob lines must have the sealed type and no nonce.
- **Clients** decrypt a sealed blob only when it was served through `…/e/{e}`.
- The merge tool reports batches whose `source.at` isn't in the branch's chain.

### Fixes

- `TestLongPollWakes` no longer fails when a long-poll's cursor boundary falls inside the test's pause.

### Known gaps

- Importing a private or sealed source into an E3 target (re-encrypting blobs) isn't implemented.
- No resumable uploads.
- Restoring an archive of a namespace encrypted at rest deadlocks on an in-memory SQLite database. File databases and Postgres are unaffected.
