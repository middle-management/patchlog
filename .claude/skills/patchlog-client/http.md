# patchlog over plain HTTP

Companion to [SKILL.md](SKILL.md) for clients that talk to the API directly: browsers, mobile
apps, services in other languages, or agents with only `curl`. Every `patchlog` client command is
a thin wrapper over the requests below (§7 of [docs/SPEC.md](../../../docs/SPEC.md)). Merge and
rebase are the exception: the tools run a whole client-side procedure (Addendum F), written out
in [merging.md](merging.md#merge-over-http).

## Conventions

| What | How |
|---|---|
| Base URL | The deployment origin, e.g. `https://pl.example` (the CLI's `--api` / `$PATCHLOG_API`) |
| Auth | `Authorization: Bearer <grant>`. Under `serve --dev`, no grant; send `X-Author: <name>` on every write instead, or get `400` |
| Resource writes | `PATCH`, `Content-Type: application/json-patch+json` (any other type is `415`) |
| Other JSON bodies | `Content-Type: application/json` (batches, branch creation, prune) |
| Ids | 33 characters, `1` + base32 (`1abc…`). Sent **quoted** in `If-Match` / `If-None-Match`, bare in URLs and JSON |
| Gestures | `Gesture: <id>` and `Undoes: <id>`, both exactly 26 characters of `[a-z2-7]` (128 random bits) that you generate when the action starts |
| Reads from other namespaces | `Source-Authorization: <grant>` (repeatable), e.g. for a batch's `source` or a blob copy |
| Every write | Exactly one precondition. None is `428`; both is `400` |

Response headers to keep:

| Header | On | Meaning |
|---|---|---|
| `ETag` / `X-Revision` | resource reads and writes | The revision id. The head comes from the `302`'s `ETag` |
| `X-Namespace-Revision` | every write | The namespace entry (`ns_id`) the write recorded |
| `X-Config-Revision` | `/ns/{ns}` reads and config writes | The config id. **Config writes match on this, not on the `ETag`** |
| `X-Log-Next` | log pages | Pass it back as the next `since` until you reach the `id` in the URL |
| `Retry-After` | `429` | Seconds to wait |
| `X-Cursor` | long-poll | Pass it back as `cursor` |

## CLI → HTTP

`R = /r/{ns}/{name}`, `N = /ns/{ns}`.

| CLI | HTTP |
|---|---|
| `get NS/NAME` | `GET R` → `302` to `R/rev/{head}` (head in `ETag`); `410` if deleted, with `{tombstone, last, successor?}` |
| `get NS/NAME --rev ID` | `GET R/rev/{id}` (immutable, cache it forever) |
| `log NS/NAME` | `GET R/rev/{head}/log?since=` (empty `since` = from genesis), paged by `X-Log-Next` |
| `log --follow`, `get --follow` | `GET R/events?since={id}` (SSE), or `GET R/log?since={id}&live=long-poll&cursor={c}` |
| `put NS/NAME DOC` | `PATCH R`, `If-None-Match: *`, body `[{"op":"add","path":"","value":DOC}]` → `201` |
| `patch NS/NAME '[…]'` | `PATCH R`, `If-Match: "{head}"` → `201`; `412 {head}` if someone wrote first |
| `rm NS/NAME` | `DELETE R`, `If-Match: "{head}"` → `200 {tombstone}` |
| `restore NS/NAME '[…]'` | `PATCH R`, `If-Match: "{tombstone}"`; the patches apply to the last live document |
| `batch NS FILE [--dry-run]` | `POST N/batch[?dry-run=1]`, body as in §7.5 (see [Batches](#batches)) |
| `ls NS [PREFIX]` | `GET N` → `302` to `N/rev/{ns_id}`; then `GET N/rev/{ns_id}/heads?after=&prefix=`, paged by the body's `next` |
| `ns create NS DOC` | `PATCH N`, `If-None-Match: *`, body `[{"op":"add","path":"","value":DOC}]` |
| `ns get NS` | `GET N` (follow the redirect); keep `X-Config-Revision` |
| `ns config NS '[…]'` | `PATCH N`, `If-Match: "{config_id}"` (from `X-Config-Revision`); `412 {config}` if stale |
| `ns log NS` | `GET N/rev/{ns_id}/log?since=`, paged |
| `watch NS` | `GET N/events?since={ns_id}` (SSE), or `GET N/log?since={ns_id}&live=long-poll` |
| `whoami NS` | `GET N/principal`: who you are there, your verbs and roles, and the limits in force |
| `branch create BASE NAME` | `POST /ns/{base}/branches`, `If-None-Match: *`, body `{"name","at"?,"patches"?}` → `201`, `Location: /ns/{name}` |
| `branch list BASE` | `GET /ns/{base}/branches` → `[{name, at, frozen, purged, successor?}]` |
| `blob put NS/NAME FILE --at /p` | `PUT R/blob/{bid}` with the file's `Content-Type` (and `Blob-Nonce` if you use one); then write `{"$blob":bid,"type":…,"size":…}` at `/p` with an ordinary `PATCH`. A blob stays invisible until a write references it |
| `undo` / `redo` | `GET N/gestures/{g}` lists the gesture's revisions; write the inverse as one batch with a new `Gesture` and `Undoes: g` (TOOLS §11.2) |
| freeze (part of `merge apply --freeze`, `rebase --switch`) | `PATCH N`, `If-Match: "{config_id}"`, `[{"op":"add","path":"/frozen","value":true}, …]` |
| `prune NS/NAME --below REV` | `POST R/prune`, `{"horizon":REV}` (destroys history) |
| `purge NS/NAME` | `POST R/purge`, `If-Match: "{head or tombstone}"` (destroys the resource) |
| `ns purge NS` | `POST N/purge`, `If-Match: "{ns_id}"` (namespace must be frozen) |

The blob id `bid` is computed by the client from the bytes (§3.7):
`"1" + base32lower(first 20 bytes of sha256("patchlog-blob-v1\n" + type + "\n" + nonce + "\n" + bytes))`.

## The save loop

```text
head = ETag of GET R (302)
loop (bounded):
  PATCH R  If-Match: "{head}"  Gesture: {g}  body: pending
    201         → head = ETag; done
    200         → idempotent retry matched; head = ETag; done
    412 {head}  → GET R/rev/{new}/log?since={head}; apply locally; head = new;
                  resend the SAME `pending` (a whole-document client first checks
                  for overlapping writes, TOOLS §11.3)
    429         → sleep Retry-After; keep combining edits into `pending`
    no response → resend the identical request (same body, same If-Match)
```

```sh
B=https://pl.example; AUTH="Authorization: Bearer $GRANT"; P='Content-Type: application/json-patch+json'
HEAD=$(curl -s -o /dev/null -w '%header{etag}' -H "$AUTH" $B/r/matches/derby)   # "\"1…\""
curl -i -X PATCH $B/r/matches/derby -H "$AUTH" -H "$P" -H "If-Match: $HEAD" \
  -H 'Gesture: abcdefghijklmnopqrstuvwxyz' \
  -d '[{"op":"test","path":"/score","value":"1-0"},{"op":"replace","path":"/score","value":"2-0"}]'
```

## Batches

```http
POST /ns/matches/batch?dry-run=1
Content-Type: application/json

{ "gesture": "abcdefghijklmnopqrstuvwxyz",
  "items": [
    { "resource": "derby", "ifMatch": "1a…", "steps": [ [ …part 1… ], [ …part 2… ] ] },
    { "resource": "final", "ifNoneMatch": "*", "steps": [ [ { "op": "add", "path": "", "value": { … } } ] ] },
    { "resource": "cup",   "ifMatch": "1c…", "steps": [ "delete" ] } ],
  "config": { "ifMatch": "<config_id>", "patches": [ … ] } }
```

- The dry run returns `200` with a report per item: `status` `201` (would pass), or the error,
  and the ids a submit would produce. Then send the same body without `?dry-run=1`.
- Success is `201 {ns_id, items:[{resource, ids}]}`. On failure nothing is written, and the
  body is `{code:"batch", items:[{index, status, code, …}]}`.
- A step can be an object, to give it its own gesture:
  `{"patches":[…],"gesture":"…","undoes":"…"}` or `{"delete":true}`.

## Merge and rebase

Merge and rebase are client procedures made of these requests. For the steps as plain HTTP, see
[merging.md, Merge over HTTP](merging.md#merge-over-http).
