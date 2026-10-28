#!/usr/bin/env bash
# A small load test of a running server: W resources made first, then W
# writers, each appending N revisions to its own resource chained on
# If-Match, while two readers read a resource's head and the namespace
# log. Prints p50, p95 and max latency (ms) and the rate of each kind, and
# the count of errors.
#
#   ./deploy/bench.sh [writers] [writes-per-writer]     (default 8 50)
#
# The server on $BASE (default http://localhost:8080) runs with -dev:
# writes carry an X-Author, no grant. Against DynamoDB Local, the table is
# made first (the server doesn't make it; docs/DYNAMODB.md §3):
#
#   aws dynamodb create-table --endpoint-url http://localhost:8000 --region us-east-1 \
#     --table-name patchlog --billing-mode PAY_PER_REQUEST \
#     --attribute-definitions AttributeName=PK,AttributeType=S AttributeName=SK,AttributeType=S \
#       AttributeName=G1PK,AttributeType=S \
#     --key-schema AttributeName=PK,KeyType=HASH AttributeName=SK,KeyType=RANGE \
#     --global-secondary-indexes 'IndexName=GSI1,KeySchema=[{AttributeName=G1PK,KeyType=HASH}],Projection={ProjectionType=ALL}'
#   patchlog serve -dev -db 'dynamodb://patchlog?region=us-east-1&endpoint=http://localhost:8000'
#
# DynamoDB Local serves about one request at a time: its numbers say how
# many calls a request makes, not what DynamoDB itself would answer in.
# Each request also pays for a curl process and a connection (a few ms),
# so compare runs with each other rather than read them as absolutes.
# Needs GNU date (date +%s%N; on macOS, coreutils' gdate as date).
set -euo pipefail
BASE=${BASE:-http://localhost:8080}
W=${1:-8}; N=${2:-50}; NS=bench$RANDOM
CT='Content-Type: application/json-patch+json'
AU='X-Author: bench'
OUT=$(mktemp)
TAGS=$(mktemp -d)
trap 'rm -rf "$OUT" "$TAGS"' EXIT

# The setup's requests say why they failed: the server's answer, or
# curl's (not listening, wrong port).
setup() { # setup URL BODY -> the response headers, or the failure on stderr and exit
  local out
  if ! out=$(curl -sS --fail-with-body -D - -o "$TAGS/body" -X PATCH "$1" -H "$CT" -H "$AU" -H 'If-None-Match: *' -d "$2"); then
    echo "bench: PATCH $1 failed: $(cat "$TAGS/body" 2>/dev/null)" >&2
    exit 1
  fi
  printf '%s\n' "$out"
}

setup "$BASE/ns/$NS" '[{"op":"add","path":"","value":{"read":"public"}}]' >/dev/null

etag() { awk 'tolower($1)=="etag:"{print $2}' | tr -d '\r'; }

# The resources, before the clock starts: a reader never asks for one not
# made yet.
for i in $(seq 1 "$W"); do
  setup "$BASE/r/$NS/r$i" '[{"op":"add","path":"","value":{"v":0}}]' | etag >"$TAGS/$i"
done

writer() { # writer I: appends N revisions to r$I, each on the last's ETag
  set -euo pipefail
  local name=r$1 tag t0
  tag=$(cat "$TAGS/$1")
  for i in $(seq 1 "$N"); do
    t0=$(date +%s%N)
    if tag=$(curl -sf -D - -o /dev/null -X PATCH "$BASE/r/$NS/$name" -H "$CT" -H "$AU" -H "If-Match: $tag" \
      -d "[{\"op\":\"replace\",\"path\":\"/v\",\"value\":$i}]" | etag) && [ -n "$tag" ]; then
      echo "write $(( ($(date +%s%N) - t0) / 1000000 ))"
    else
      echo "error write"
      return 1
    fi
  done
}

reader() { # a resource's head and the namespace log, N times each (following their 302s)
  for _ in $(seq 1 "$N"); do
    t0=$(date +%s%N)
    if curl -sfL "$BASE/r/$NS/r$(( RANDOM % W + 1 ))" >/dev/null; then
      echo "read $(( ($(date +%s%N) - t0) / 1000000 ))"
    else
      echo "error read"
    fi
    t0=$(date +%s%N)
    if curl -sfL "$BASE/ns/$NS/log" >/dev/null; then
      echo "log $(( ($(date +%s%N) - t0) / 1000000 ))"
    else
      echo "error log"
    fi
  done
}
export -f writer reader etag
export BASE NS N CT AU W TAGS

start=$(date +%s%N)
seq 1 "$W" | xargs -P "$W" -I{} bash -c 'writer {}' >>"$OUT" &
seq 1 2 | xargs -P 2 -I{} bash -c 'reader {}' >>"$OUT" &
wait || true
secs=$(awk -v ns="$(( $(date +%s%N) - start ))" 'BEGIN { printf "%.2f", ns / 1e9 }')

echo "namespace $NS, $W writers × $N writes, ${secs}s"
for k in write read log; do
  grep "^$k " "$OUT" | awk '{print $2}' | sort -n | awk -v k="$k" -v s="$secs" '
    {a[NR] = $1}
    END { if (NR) printf "%-5s n=%-5d p50=%-5d p95=%-5d max=%-6d (%.1f/s)\n",
      k, NR, a[int(NR * .5) + 1], a[int(NR * .95) + 1], a[NR], NR / s }'
done
echo "errors: $(grep -c '^error' "$OUT" || true)"
