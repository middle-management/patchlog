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

create /ns/schemas '{"read":"public"}' >/dev/null
create /ns/demo '{"read":"public"}' >/dev/null
create /ns/cat '{"read":"public","catalog":{"trust":["demo"]}}' >/dev/null

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
if [ -z "$schema" ]; then
  schema=$(curl -s -o /dev/null -D - "$API/r/schemas/match" | tr -d '\r' | sed -n 's/^[Ee][Tt]ag: "\(.*\)"$/\1/p')
fi

create /r/demo/derby "{\"\$schema\":\"/r/schemas/match/rev/$schema\",\"title\":\"Stockholm derby\",\"league\":\"allsvenskan\",\"kickoff\":\"2026-10-04T18:00:00Z\"}" >/dev/null
create /r/demo/final "{\"\$schema\":\"/r/schemas/match/rev/$schema\",\"title\":\"Cup final\",\"league\":\"cup\",\"kickoff\":\"2026-11-01T15:00:00Z\"}" >/dev/null
create /r/demo/notes '{"text":"An untyped document: stored and versioned, not validated."}' >/dev/null

echo "seeded: namespaces schemas, demo, cat; schema /r/schemas/match/rev/$schema"
