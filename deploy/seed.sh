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
# Roles name sets of verbs a grant can take (§C.4); desk includes reader and
# may restore a deleted document.
create_ns demo '{"read":"public","roles":{"desk":{"can":["read","create","append","restore"],"includes":["reader"]},"translator":{"can":["read","append"]},"reader":{"can":["read"]}}}' >/dev/null

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

create /r/demo/derby "{\"\$schema\":\"/r/schemas/match/rev/$schema\",\"title\":\"Stockholm derby\",\"league\":\"allsvenskan\",\"kickoff\":\"2026-10-04T18:00:00Z\"}" >/dev/null
create /r/demo/final "{\"\$schema\":\"/r/schemas/match/rev/$schema\",\"title\":\"Cup final\",\"league\":\"cup\",\"kickoff\":\"2026-11-01T15:00:00Z\"}" >/dev/null
create /r/demo/notes '{"text":"An untyped document: stored and versioned, not validated."}' >/dev/null
create /r/demo/djurgarden-aik "{\"\$schema\":\"/r/schemas/match/rev/$schema\",\"title\":\"Djurgården – AIK\",\"league\":\"allsvenskan\",\"kickoff\":\"2026-10-18T16:00:00Z\"}" >/dev/null
create /r/demo/mff-ifk "{\"\$schema\":\"/r/schemas/match/rev/$schema\",\"title\":\"Malmö FF – IFK Göteborg\",\"league\":\"allsvenskan\",\"kickoff\":\"2026-10-25T14:00:00Z\"}" >/dev/null

# Files the WebDAV gateway (dav) serves as a flat directory: raw documents
# (§7.8), kept as blobs, and a JSON document.
create_ns files '{"read":"public"}' >/dev/null

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
These files are the namespace files, served over WebDAV by `patchlog dav`
(in the compose stack, /files/ on DAV_PORT, 8090 by default).

Each file is a document of files; each save is a revision of it.
EOF
# A 16x16 PNG, a ring.
echo 'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQAQMAAAAlPW0iAAAABlBMVEX///8fb+uXBXurAAAAKklEQVR42mNgYGBgf8DA/4FB/geD/R+GGjuGCjkEAnKBgkApoAKgMgYGACOBDD38jlFXAAAAAElFTkSuQmCC' |
  base64 -d >"$tmp/logo.png"
raw q3-summary.md text/markdown "$tmp/q3-summary.md"
raw readme.txt text/plain "$tmp/readme.txt"
raw logo.png image/png "$tmp/logo.png"
create /r/files/budget '{"title":"Budget 2026","currency":"SEK","lines":[{"item":"Travel","amount":12000},{"item":"Equipment","amount":8500}],"total":20500}' >/dev/null

# Encryption demos (Addendum E; the server needs --master-key). "private" is
# sealed for delivery (E2): documents leave the origin as JWEs, and every
# patch set carries a fresh $nonce. "vault" is end-to-end (E3): the server
# never sees plaintext; create its keyring from the playground's Keys tab.
create_ns private '{"read":"public","encryption":{"level":"sealed"}}' >/dev/null
curl -s -o /dev/null -X PATCH "$API/r/private/memo" -H "$P" -H "$A" -H 'If-None-Match: *' \
  -d "[{\"op\":\"add\",\"path\":\"\",\"value\":{\"title\":\"Sealed memo\",\"text\":\"Only key holders can read this.\"}},{\"op\":\"add\",\"path\":\"/\$nonce\",\"value\":\"$(nonce)\"}]"
create_ns vault '{"read":"public","encryption":{"level":"e2e"}}' >/dev/null

echo "seeded: namespaces schemas, demo, files, private (E2), vault (E3); schema /r/schemas/match/rev/$schema"
