#!/bin/sh
# Creates the demo namespaces the stack's services follow. Safe to re-run:
# existing namespaces and resources answer 412 and are left alone.
set -eu
API=${API:-http://patchlog:8080}
P='Content-Type: application/json-patch+json'
A='X-Author: seed'

create() { # create PATH JSON -> prints the new id (ETag), or nothing if it exists
  curl -s -o /dev/null -D - -X PATCH "$API$1" -H "$P" -H "$A" -H 'If-None-Match: *' \
    -d "[{\"op\":\"add\",\"path\":\"\",\"value\":$2}]" |
    tr -d '\r' | sed -n 's/^[Ee][Tt]ag: "\(.*\)"$/\1/p'
}
create_ns() { # create_ns NS JSON -> prints the config id, or nothing if it exists
  curl -s -o /dev/null -D - -X PATCH "$API/ns/$1" -H "$P" -H "$A" -H 'If-None-Match: *' \
    -d "[{\"op\":\"add\",\"path\":\"\",\"value\":$2}]" |
    tr -d '\r' | sed -n 's/^[Xx]-[Cc]onfig-[Rr]evision: \(.*\)$/\1/p'
}
head_of() { # head_of PATH -> the current revision id
  curl -s -o /dev/null -D - "$API$1" | tr -d '\r' | sed -n 's/^[Ee][Tt]ag: "\(.*\)"$/\1/p'
}
nonce() { # 26 random base32 characters, a fresh $nonce (§C.7)
  LC_ALL=C tr -dc 'a-z2-7' </dev/urandom | head -c 26
}

create_ns schemas '{"read":"public"}' >/dev/null
# Roles say what a catalog role means for demo's documents (§B.11.1); desk
# includes reader, so moving an item from desk to reader narrows access, and
# may restore, so a deleted item comes back through the catalog (§B.11.4).
create_ns demo '{"read":"public","roles":{"desk":{"can":["read","create","append","restore"],"includes":["reader"]},"translator":{"can":["read","append"]},"reader":{"can":["read"]}},"catalogs":{"cat":{"place":["group:match-desk"]},"topics":{"place":["group:match-desk"]}}}' >/dev/null
# The catalog: folders and placements of demo's documents (Addendum B). Its
# rules (added below, after the root exists) keep placement names to trusted
# items, parents to folders of this catalog, one parent per node, and no new
# roots (§B.6).
catcfg=$(create_ns cat '{"read":"public","catalog":{"trust":["demo"],"mode":"tree"},"roles":{"desk":{"move":true,"place":true},"translator":{},"reader":{}}}')
# A second catalog over the same documents, as a DAG (§B.6 mode dag): folders
# and items may have several parents. Same roles; its rules (added below)
# are cat's without maxItems: 1.
topicscfg=$(create_ns topics '{"read":"public","catalog":{"trust":["demo"],"mode":"dag"},"roles":{"desk":{"move":true,"place":true},"translator":{},"reader":{}}}')

# A schema whose fields the search index picks up (x-index, Addendum A).
schema=$(create /r/schemas/match '{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["title"],
  "properties": {
    "$schema": {"type": "string"},
    "title":   {"type": "string", "x-index": "text"},
    "league":  {"type": "string", "x-index": "facet"},
    "kickoff": {"type": "string", "format": "date-time", "x-index": "sort"}
  }
}')
[ -n "$schema" ] || schema=$(head_of /r/schemas/match)

# Folder and placement schemas (§B.2, §B.11.1: they validate $access).
PARENTS='"parents": {"type": "array", "items": {"type": "object", "required": ["href"], "properties": {"href": {"type": "string", "pattern": "^/r/[a-z0-9][a-z0-9_-]*/[a-z0-9][a-z0-9_-]*$"}, "order": {"type": "string", "pattern": "^[0-9A-Za-z]{1,64}$"}}}}'
ACCESS='"$access": {"type": "object", "properties": {"inherit": {"type": "boolean"}}, "patternProperties": {"^(group|user):": {"type": "array", "items": {"type": "string"}}}}'
folder=$(create /r/schemas/folder "{\"\$schema\": \"https://json-schema.org/draft/2020-12/schema\", \"type\": \"object\",
  \"properties\": {\"\$schema\": {\"type\": \"string\"}, \"title\": {\"type\": \"string\", \"minLength\": 1}, $PARENTS, $ACCESS}}")
[ -n "$folder" ] || folder=$(head_of /r/schemas/folder)
placement=$(create /r/schemas/placement "{\"\$schema\": \"https://json-schema.org/draft/2020-12/schema\", \"type\": \"object\", \"required\": [\"parents\"],
  \"properties\": {\"\$schema\": {\"type\": \"string\"}, $PARENTS, $ACCESS, \"\$nonce\": {\"type\": \"string\", \"pattern\": \"^[a-z2-7]{26}$\"}}}")
[ -n "$placement" ] || placement=$(head_of /r/schemas/placement)

create /r/demo/derby "{\"\$schema\":\"/r/schemas/match/rev/$schema\",\"title\":\"Stockholm derby\",\"league\":\"allsvenskan\",\"kickoff\":\"2026-10-04T18:00:00Z\"}" >/dev/null
create /r/demo/final "{\"\$schema\":\"/r/schemas/match/rev/$schema\",\"title\":\"Cup final\",\"league\":\"cup\",\"kickoff\":\"2026-11-01T15:00:00Z\"}" >/dev/null
create /r/demo/notes '{"text":"An untyped document: stored and versioned, not validated."}' >/dev/null
create /r/demo/djurgarden-aik "{\"\$schema\":\"/r/schemas/match/rev/$schema\",\"title\":\"Djurgården – AIK\",\"league\":\"allsvenskan\",\"kickoff\":\"2026-10-18T16:00:00Z\"}" >/dev/null
create /r/demo/mff-ifk "{\"\$schema\":\"/r/schemas/match/rev/$schema\",\"title\":\"Malmö FF – IFK Göteborg\",\"league\":\"allsvenskan\",\"kickoff\":\"2026-10-25T14:00:00Z\"}" >/dev/null

F="\"\$schema\":\"/r/schemas/folder/rev/$folder\""
PL="\"\$schema\":\"/r/schemas/placement/rev/$placement\""
create /r/cat/root "{$F,\"title\":\"Demo catalog\",\"\$access\":{\"group:catalog-admins\":[\"desk\"]}}" >/dev/null
create /r/cat/season-2026 "{$F,\"title\":\"Season 2026\",\"parents\":[{\"href\":\"/r/cat/root\",\"order\":\"a0\"}],\"\$access\":{\"group:match-desk\":[\"desk\"],\"group:translators\":[\"translator\"],\"group:fan-club\":[\"reader\"]}}" >/dev/null
create /r/cat/cups "{$F,\"title\":\"Cups\",\"parents\":[{\"href\":\"/r/cat/season-2026\",\"order\":\"a1\"}]}" >/dev/null
create /r/cat/editorial "{$F,\"title\":\"Editorial (embargoed)\",\"parents\":[{\"href\":\"/r/cat/root\",\"order\":\"a1\"}],\"\$access\":{\"inherit\":false,\"group:editors-in-chief\":[\"desk\"]}}" >/dev/null
create /r/cat/demo.derby "{$PL,\"parents\":[{\"href\":\"/r/cat/season-2026\",\"order\":\"a0\"}],\"\$nonce\":\"$(nonce)\"}" >/dev/null
create /r/cat/demo.final "{$PL,\"parents\":[{\"href\":\"/r/cat/cups\",\"order\":\"a0\"}],\"\$nonce\":\"$(nonce)\"}" >/dev/null
create /r/cat/demo.notes "{$PL,\"parents\":[{\"href\":\"/r/cat/editorial\"}],\"\$access\":{\"user:li\":[\"reader\"]},\"\$nonce\":\"$(nonce)\"}" >/dev/null
# Placed before it exists: dangling until /r/demo/upcoming is created (§B.7).
create /r/cat/demo.upcoming "{$PL,\"parents\":[{\"href\":\"/r/cat/season-2026\",\"order\":\"a2\"}],\"\$nonce\":\"$(nonce)\"}" >/dev/null

if [ -n "$catcfg" ]; then
  curl -s -o /dev/null -X PATCH "$API/ns/cat" -H "$P" -H "$A" -H "If-Match: \"$catcfg\"" -d '[{"op":"add","path":"/rules","value":[
    {"op":"test","path":"/resource","schema":{"pattern":"^([a-z0-9][a-z0-9_-]*|demo\\.[a-z0-9][a-z0-9._-]*)$"}},
    {"if":[{"op":"test","path":"/action","schema":{"enum":["create","append","restore"]}},{"op":"test","path":"/doc/parents","exists":true}],
     "then":[{"op":"test","path":"/doc/parents","schema":{"type":"array","maxItems":1,"items":{"type":"object","required":["href"],"additionalProperties":false,
       "properties":{"href":{"type":"string","pattern":"^/r/cat/[a-z0-9][a-z0-9_-]{0,127}$"},"order":{"type":"string","pattern":"^[0-9A-Za-z]{1,64}$"}}}}}]},
    {"if":[{"op":"test","path":"/action","value":"create"}],"then":[{"op":"test","path":"/doc/parents","schema":{"minItems":1}}]}]}]'
fi

# The DAG catalog (topics), a node listed under each of its parents, [order]:
#
#   root "Topics"                      catalog-admins: desk
#   ├─ stockholm [a0]                  stockholm-desk: desk
#   │  └─ derbies [a0]                 translators: translator  (two parents: a
#   │     ├─ demo.derby [a0]            diamond root → stockholm | rivalries → derbies)
#   │     └─ demo.djurgarden-aik [a1]
#   ├─ rivalries [a1]                  fan-club: reader
#   │  ├─ derbies [a0]                 (the same folder, and its items)
#   │  └─ demo.mff-ifk [a1]
#   ├─ competitions [a2]               match-desk: desk
#   │  ├─ league [a0]                  league-office: reader
#   │  │  ├─ big-games [a0]            (two parents: competitions → league | cup → big-games)
#   │  │  │  ├─ demo.mff-ifk [a0]
#   │  │  │  └─ demo.final [a1]
#   │  │  └─ demo.djurgarden-aik [a1]
#   │  └─ cup [a1]
#   │     ├─ big-games [a0]
#   │     └─ demo.final [a0]
#   ├─ editorial [a3]                  inherit: false; editors-in-chief: desk
#   │  ├─ demo.derby [a0]
#   │  └─ demo.notes [a1]              user:li: reader (on the placement)
#   └─ loop-a [a9] ⇄ loop-b            a cycle: the tree service flags every edge
#                                      inside it, lists neither folder, and reports
#                                      it under /problems (§B.5)
#
# Access differs by path (§B.11.2): demo.derby is desk for stockholm-desk only
# through Stockholm, reader for fan-club only through Rivalries, desk for
# editors-in-chief only through the embargoed Editorial, and catalog-admins'
# desk (on root) reaches it only around Editorial, whose inherit: false stops
# the walk. Its effective roles are the union over all three paths.
TF="\"\$schema\":\"/r/schemas/folder/rev/$folder\""
tp() { # tp NAME[@ORDER]... -> a parents array of topics folders
  out=''
  for p in "$@"; do
    case $p in
      *@*) out="$out,{\"href\":\"/r/topics/${p%@*}\",\"order\":\"${p#*@}\"}" ;;
      *) out="$out,{\"href\":\"/r/topics/$p\"}" ;;
    esac
  done
  echo "[${out#,}]"
}
create /r/topics/root "{$TF,\"title\":\"Topics\",\"\$access\":{\"group:catalog-admins\":[\"desk\"]}}" >/dev/null
create /r/topics/stockholm "{$TF,\"title\":\"Stockholm\",\"parents\":$(tp root@a0),\"\$access\":{\"group:stockholm-desk\":[\"desk\"]}}" >/dev/null
create /r/topics/rivalries "{$TF,\"title\":\"Rivalries\",\"parents\":$(tp root@a1),\"\$access\":{\"group:fan-club\":[\"reader\"]}}" >/dev/null
create /r/topics/competitions "{$TF,\"title\":\"Competitions\",\"parents\":$(tp root@a2),\"\$access\":{\"group:match-desk\":[\"desk\"]}}" >/dev/null
create /r/topics/editorial "{$TF,\"title\":\"Editorial (embargoed)\",\"parents\":$(tp root@a3),\"\$access\":{\"inherit\":false,\"group:editors-in-chief\":[\"desk\"]}}" >/dev/null
create /r/topics/derbies "{$TF,\"title\":\"Derbies\",\"parents\":$(tp stockholm@a0 rivalries@a0),\"\$access\":{\"group:translators\":[\"translator\"]}}" >/dev/null
create /r/topics/league "{$TF,\"title\":\"Allsvenskan\",\"parents\":$(tp competitions@a0),\"\$access\":{\"group:league-office\":[\"reader\"]}}" >/dev/null
create /r/topics/cup "{$TF,\"title\":\"Svenska Cupen\",\"parents\":$(tp competitions@a1)}" >/dev/null
create /r/topics/big-games "{$TF,\"title\":\"Big games\",\"parents\":$(tp league@a0 cup@a0)}" >/dev/null
create /r/topics/demo.derby "{$PL,\"parents\":$(tp derbies@a0 editorial@a0),\"\$nonce\":\"$(nonce)\"}" >/dev/null
create /r/topics/demo.djurgarden-aik "{$PL,\"parents\":$(tp derbies@a1 league@a1),\"\$nonce\":\"$(nonce)\"}" >/dev/null
create /r/topics/demo.mff-ifk "{$PL,\"parents\":$(tp rivalries@a1 big-games@a0),\"\$nonce\":\"$(nonce)\"}" >/dev/null
create /r/topics/demo.final "{$PL,\"parents\":$(tp cup@a0 big-games@a1),\"\$nonce\":\"$(nonce)\"}" >/dev/null
create /r/topics/demo.notes "{$PL,\"parents\":$(tp editorial@a1),\"\$access\":{\"user:li\":[\"reader\"]},\"\$nonce\":\"$(nonce)\"}" >/dev/null
# The cycle: loop-b under loop-a, then loop-b added as a second parent of
# loop-a. Only when loop-a was just created (its id guards the append), so a
# re-run doesn't add it again. Nothing else hangs below it.
loopa=$(create /r/topics/loop-a "{$TF,\"title\":\"Loop A (a cycle)\",\"parents\":$(tp root@a9)}")
create /r/topics/loop-b "{$TF,\"title\":\"Loop B (a cycle)\",\"parents\":$(tp loop-a)}" >/dev/null
if [ -n "$loopa" ]; then
  curl -s -o /dev/null -X PATCH "$API/r/topics/loop-a" -H "$P" -H "$A" -H "If-Match: \"$loopa\"" \
    -d '[{"op":"add","path":"/parents/-","value":{"href":"/r/topics/loop-b"}}]'
fi

if [ -n "$topicscfg" ]; then
  curl -s -o /dev/null -X PATCH "$API/ns/topics" -H "$P" -H "$A" -H "If-Match: \"$topicscfg\"" -d '[{"op":"add","path":"/rules","value":[
    {"op":"test","path":"/resource","schema":{"pattern":"^([a-z0-9][a-z0-9_-]*|demo\\.[a-z0-9][a-z0-9._-]*)$"}},
    {"if":[{"op":"test","path":"/action","schema":{"enum":["create","append","restore"]}},{"op":"test","path":"/doc/parents","exists":true}],
     "then":[{"op":"test","path":"/doc/parents","schema":{"type":"array","items":{"type":"object","required":["href"],"additionalProperties":false,
       "properties":{"href":{"type":"string","pattern":"^/r/topics/[a-z0-9][a-z0-9_-]{0,127}$"},"order":{"type":"string","pattern":"^[0-9A-Za-z]{1,64}$"}}}}}]},
    {"if":[{"op":"test","path":"/action","value":"create"}],"then":[{"op":"test","path":"/doc/parents","schema":{"minItems":1}}]}]}]'
fi

# A file tree (Addendum H), which the WebDAV gateway (dav) serves as a
# network drive: the catalog drive, whose files' items live in the namespace
# files. Its catalog.files (§H.2) names files as the namespace new files are
# created in (drive trusts it), root as the folder whose children are the
# top level, and the folder and placement schemas new nodes carry. Folders
# and files are named by their nodes' titles; the items have readable names
# here, which mean nothing once a file is renamed. Its rules (added below,
# after the root exists) are cat's, for files' items, and §H.2's titles.
#
#   root "Drive"
#   ├─ Reports [a0]                    reports
#   │  ├─ Q3 summary.md [a0]           files.q3-summary.md: a raw document (§7.8), text/markdown
#   │  └─ budget.json [a1]             files.budget: a JSON document
#   ├─ Photos [a1]                     photos
#   │  └─ logo.png [a0]                files.logo.png: a raw document, image/png
#   └─ README.txt [a2]                 files.readme.txt: a raw document, text/plain
create_ns files '{"read":"public"}' >/dev/null
drivecfg=$(create_ns drive "{\"read\":\"public\",\"catalog\":{\"trust\":[\"files\"],\"mode\":\"tree\",\"files\":{\"ns\":\"files\",\"root\":\"root\",\"folder\":\"/r/schemas/folder/rev/$folder\",\"placement\":\"/r/schemas/placement/rev/$placement\"}}}")

blob_id() { # blob_id TYPE FILE -> the id of FILE's bytes as a blob of TYPE, without a nonce (§3.7)
  { printf 'patchlog-blob-v1\n%s\n\n' "$1"; cat "$2"; } | sha256sum | awk '{
    hex = "0123456789abcdef"; b32 = "abcdefghijklmnopqrstuvwxyz234567"; bits = ""; id = "1"
    for (i = 1; i <= 40; i++) { # trunc160: the first 20 bytes, as bits
      v = index(hex, substr($1, i, 1)) - 1
      bits = bits int(v / 8) % 2 int(v / 4) % 2 int(v / 2) % 2 v % 2
    }
    for (i = 1; i <= 160; i += 5) { # base32lower, 5 bits a character (§3.2)
      v = 0
      for (j = 0; j < 5; j++) v = v * 2 + substr(bits, i + j, 1)
      id = id substr(b32, v + 1, 1)
    }
    print id
  }'
}
raw() { # raw NAME TYPE FILE: the raw document /r/files/NAME, unless it exists: FILE's bytes as a blob, then a document whose root is its reference
  [ -z "$(head_of "/r/files/$1")" ] || return 0
  bid=$(blob_id "$2" "$3")
  if ! curl -sS -f -o /dev/null -X PUT "$API/r/files/$1/blob/$bid" -H "Content-Type: $2" -H "$A" --data-binary "@$3"; then
    echo "seed: uploading the blob of /r/files/$1 failed" >&2
    return 0
  fi
  create "/r/files/$1" "{\"\$blob\":\"$bid\",\"type\":\"$2\",\"size\":$(wc -c <"$3" | tr -d ' ')}" >/dev/null
}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cat >"$tmp/q3-summary.md" <<'EOF'
# Q3 summary

- Two derbies and a cup final.
- Attendance up 12 % on last season.

A raw file: these bytes are a blob, kept exactly. Each save through the
WebDAV gateway is a revision of /r/files/q3-summary.md.
EOF
cat >"$tmp/readme.txt" <<'EOF'
This drive is the catalog drive (a file tree, spec Addendum H), served over
WebDAV by `patchlog dav` (in the compose stack, /drive/ on DAV_PORT, 8090 by
default).

Folders are folder nodes of drive, and files its placements, named by their
titles; each file's content is a document in the namespace files. Renaming
or moving a file changes only its placement, so the file keeps its history.
EOF
# A 16x16 PNG, a ring.
echo 'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQAQMAAAAlPW0iAAAABlBMVEX///8fb+uXBXurAAAAKklEQVR42mNgYGBgf8DA/4FB/geD/R+GGjuGCjkEAnKBgkApoAKgMgYGACOBDD38jlFXAAAAAElFTkSuQmCC' |
  base64 -d >"$tmp/logo.png"
raw q3-summary.md text/markdown "$tmp/q3-summary.md"
raw readme.txt text/plain "$tmp/readme.txt"
raw logo.png image/png "$tmp/logo.png"
create /r/files/budget '{"title":"Budget 2026","currency":"SEK","lines":[{"item":"Travel","amount":12000},{"item":"Equipment","amount":8500}],"total":20500}' >/dev/null

create /r/drive/root "{$F,\"title\":\"Drive\"}" >/dev/null
create /r/drive/reports "{$F,\"title\":\"Reports\",\"parents\":[{\"href\":\"/r/drive/root\",\"order\":\"a0\"}]}" >/dev/null
create /r/drive/photos "{$F,\"title\":\"Photos\",\"parents\":[{\"href\":\"/r/drive/root\",\"order\":\"a1\"}]}" >/dev/null
place() { # place ITEM TITLE FOLDER ORDER: a placement of /r/files/ITEM in FOLDER, its file name TITLE
  create "/r/drive/files.$1" "{$PL,\"title\":\"$2\",\"parents\":[{\"href\":\"/r/drive/$3\",\"order\":\"$4\"}],\"\$nonce\":\"$(nonce)\"}" >/dev/null
}
place q3-summary.md 'Q3 summary.md' reports a0
place budget budget.json reports a1
place logo.png logo.png photos a0
place readme.txt README.txt root a2

if [ -n "$drivecfg" ]; then
  curl -s -o /dev/null -X PATCH "$API/ns/drive" -H "$P" -H "$A" -H "If-Match: \"$drivecfg\"" -d '[{"op":"add","path":"/rules","value":[
    {"op":"test","path":"/resource","schema":{"pattern":"^([a-z0-9][a-z0-9_-]*|files\\.[a-z0-9][a-z0-9._-]*)$"}},
    {"if":[{"op":"test","path":"/action","schema":{"enum":["create","append","restore"]}},{"op":"test","path":"/doc/parents","exists":true}],
     "then":[{"op":"test","path":"/doc/parents","schema":{"type":"array","maxItems":1,"items":{"type":"object","required":["href"],"additionalProperties":false,
       "properties":{"href":{"type":"string","pattern":"^/r/drive/[a-z0-9][a-z0-9_-]{0,127}$"},"order":{"type":"string","pattern":"^[0-9A-Za-z]{1,64}$"}}}}}]},
    {"if":[{"op":"test","path":"/action","value":"create"}],"then":[{"op":"test","path":"/doc/parents","schema":{"minItems":1}}]},
    {"if":[{"op":"test","path":"/action","schema":{"enum":["create","append","restore"]}},{"op":"test","path":"/doc/title","exists":true}],
     "then":[{"op":"test","path":"/doc/title","schema":{"type":"string","minLength":1,"pattern":"^[^/\\\\\\p{Cc}\\p{Zl}\\p{Zp}\\u202A-\\u202E\\u2066-\\u2069]+$","not":{"enum":[".",".."]}}}]}]}]'
fi

# Encryption demos (Addendum E; the server needs -master-key). "private" is
# sealed for delivery (E2): documents leave the origin as JWEs, and every
# patch set carries a fresh $nonce. "vault" is end-to-end (E3): the server
# never sees plaintext; create its keyring from the playground's Keys tab.
create_ns private '{"read":"public","encryption":{"level":"sealed"}}' >/dev/null
curl -s -o /dev/null -X PATCH "$API/r/private/memo" -H "$P" -H "$A" -H 'If-None-Match: *' \
  -d "[{\"op\":\"add\",\"path\":\"\",\"value\":{\"title\":\"Sealed memo\",\"text\":\"Only key holders can read this.\"}},{\"op\":\"add\",\"path\":\"/\$nonce\",\"value\":\"$(nonce)\"}]"
create_ns vault '{"read":"public","encryption":{"level":"e2e"}}' >/dev/null

echo "seeded: namespaces schemas, demo, cat (catalog, a tree), topics (catalog, a DAG), files, drive (catalog, a file tree of files), private (E2), vault (E3); schema /r/schemas/match/rev/$schema"
