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
# includes reader, so moving an item from desk to reader narrows access.
create_ns demo '{"read":"public","roles":{"desk":{"can":["read","create","append"],"includes":["reader"]},"translator":{"can":["read","append"]},"reader":{"can":["read"]}},"catalogs":{"cat":{"place":["group:match-desk"]}}}' >/dev/null
# The catalog: folders and placements of demo's documents (Addendum B). Its
# rules (added below, after the root exists) keep placement names to trusted
# items, parents to folders of this catalog, one parent per node, and no new
# roots (§B.6).
catcfg=$(create_ns cat '{"read":"public","catalog":{"trust":["demo"],"mode":"tree"},"roles":{"desk":{"move":true,"place":true},"translator":{},"reader":{}}}')

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

# Encryption demos (Addendum E; the server needs -master-key). "private" is
# sealed for delivery (E2): documents leave the origin as JWEs, and every
# patch set carries a fresh $nonce. "vault" is end-to-end (E3): the server
# never sees plaintext; create its keyring from the playground's Keys tab.
create_ns private '{"read":"public","encryption":{"level":"sealed"}}' >/dev/null
curl -s -o /dev/null -X PATCH "$API/r/private/memo" -H "$P" -H "$A" -H 'If-None-Match: *' \
  -d "[{\"op\":\"add\",\"path\":\"\",\"value\":{\"title\":\"Sealed memo\",\"text\":\"Only key holders can read this.\"}},{\"op\":\"add\",\"path\":\"/\$nonce\",\"value\":\"$(nonce)\"}]"
create_ns vault '{"read":"public","encryption":{"level":"e2e"}}' >/dev/null

echo "seeded: namespaces schemas, demo, cat (catalog), private (E2), vault (E3); schema /r/schemas/match/rev/$schema"
