#!/usr/bin/env bash
# A load test of a running server with oha (https://github.com/hatoo/oha):
# for S seconds, writes at a fixed rate while readers read resources' heads
# and follow the namespace logs, each at its own fixed rate. Prints, per
# kind, the requests answered, their rate, p50, p95, p99 and max latency
# (ms) and the statuses other than success.
#
#   ./deploy/bench.sh [writes/s] [seconds]      (default 100 20)
#
#   READS       reads of a resource's head per second, following its 302 to
#               the revision (default: writes/s)
#   LOGS        reads of a namespace's log per second (default: writes/s / 2)
#   NAMESPACES  namespaces the load is spread over, evenly (default 1)
#   BASE        the server (default http://localhost:8080)
#
# A log read follows the log as a follower does: the entries since a
# recent one (?since=), not the log from its start, whose first page (up
# to 1,000 entries) a CDN would serve. The bench runs in one-second
# slices, each reading since the head at its start.
#
# A write creates a resource (If-None-Match: *), a randomly named one, with
# its author's content: resources created with the same patches share
# their first revision's id (genesis twins), and so its GSI1 key, which
# DynamoDB holds to ~1,000 writes a second (docs/DYNAMODB.md §3). An
# append needs the head its writer last saw (If-Match), which a load tool
# firing fixed requests can't chain, and a create goes through the same
# commit, onto the namespace log, as an append. Rates are open loop: oha
# sends at the rate whatever the answers' latency, and counts from when a
# request was due (--latency-correction), so a slow server shows as latency,
# not as a lower rate.
#
# The server runs with -dev: writes carry an X-Author, no grant. Writes are
# limited per principal (ratePerPrincipal, 50/s with a burst of 100, §6.6),
# an author in -dev, so they're spread over authors at 40/s each. A rate
# above 400/s needs the namespace's own limit raised, which the server
# allows only up to -max-rate-per-namespace: start it with, say,
# -max-rate-per-namespace 100000,1000000.
#
# Against DynamoDB Local, the table is made first (the server doesn't make
# it; docs/DYNAMODB.md §3):
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
# deploy/ec2-bench.sh runs this, with the server, on an EC2 instance in a
# real table's region. Needs oha 1.14 or later, curl and python3.
set -euo pipefail
BASE=${BASE:-http://localhost:8080}
WRITES=${1:-100}; SECS=${2:-20}
READS=${READS:-$WRITES}; LOGS=${LOGS:-$(( WRITES / 2 ))}; NAMESPACES=${NAMESPACES:-1}
RUN=bench$RANDOM; RESOURCES=16; PER_AUTHOR=40
CT='Content-Type: application/json-patch+json'
command -v oha >/dev/null || { echo "bench: needs oha (https://github.com/hatoo/oha/releases)" >&2; exit 1; }
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

# The setup's requests say why they failed: the server's answer, or
# curl's (not listening, wrong port). Each namespace's are an author's
# own: one author's writes are limited (50/s, a burst of 100), and a fast
# backend makes eight namespaces' 136 in well under a second.
setup() { # setup URL BODY AUTHOR
  if ! curl -sS --fail-with-body -o "$OUT/body" -X PATCH "$1" -H "$CT" -H "X-Author: $3" -H 'If-None-Match: *' -d "$2"; then
    echo "bench: PATCH $1 failed: $(cat "$OUT/body" 2>/dev/null)" >&2
    exit 1
  fi
}

# Each namespace's share of a rate, n of NAMESPACES (1-based).
share() { echo $(( $1 / NAMESPACES + ($2 <= $1 % NAMESPACES ? 1 : 0) )); }

nss=""; names=""
for n in $(seq 1 "$NAMESPACES"); do
  ns=$RUN-$n
  config='{"read":"public"}'
  if [ "$(share "$WRITES" "$n")" -gt 400 ]; then
    config="{\"read\":\"public\",\"limits\":{\"ratePerNamespace\":{\"rate\":$(( WRITES * 2 )),\"burst\":$(( WRITES * 4 ))}}}"
  fi
  setup "$BASE/ns/$ns" "[{\"op\":\"add\",\"path\":\"\",\"value\":$config}]" "setup$n"
  for i in $(seq 1 "$RESOURCES"); do
    setup "$BASE/r/$ns/r$i" '[{"op":"add","path":"","value":{"v":0}}]' "setup$n"
  done
  nss="$nss${nss:+|}$ns"
done
for i in $(seq 1 "$RESOURCES"); do names="$names${names:+|}r$i"; done

# load KIND RATE ARGS…: one oha run, its JSON in $OUT/KIND.json. Requests
# under way at the end are waited for (-w). A write's 201 has a Location,
# which oha would follow with the write's method: -r 0.
load() {
  local kind=$1 rate=$2; shift 2
  [ "$rate" -gt 0 ] || return 0
  oha --no-tui --output-format json -z "${SECS}s" -w -q "$rate" --latency-correction \
    -c "$(( rate / 4 + 4 ))" "$@" >"$OUT/$kind.json"
}

# follow NS RATE: SECS one-second slices of log reads, each since the head
# at its start (the id in the log's redirect).
follow() {
  local ns=$1 rate=$2 head i
  [ "$rate" -gt 0 ] || return 0
  for i in $(seq 1 "$SECS"); do
    head=$(curl -s -o /dev/null -w '%{redirect_url}' "$BASE/ns/$ns/log" | sed -n 's|.*/rev/\([^/]*\)/log.*|\1|p')
    oha --no-tui --output-format json -z 1s -w -q "$rate" --latency-correction -c "$(( rate / 4 + 4 ))" \
      "$BASE/ns/$ns/log?since=$head" >"$OUT/log.$ns.$i.json"
  done
}

authors=0
for n in $(seq 1 "$NAMESPACES"); do
  ns=$RUN-$n; rate=$(share "$WRITES" "$n")
  k=$(( (rate + PER_AUTHOR - 1) / PER_AUTHOR ))
  for a in $(seq 1 "$k"); do
    r=$(( rate / k + (a <= rate % k ? 1 : 0) ))
    authors=$(( authors + 1 ))
    load "write.$n.$a" "$r" -r 0 -m PATCH -H "$CT" -H "X-Author: bench$n-$a" -H 'If-None-Match: *' \
      -d "[{\"op\":\"add\",\"path\":\"\",\"value\":{\"by\":\"bench$n-$a\"}}]" --rand-regex-url "$BASE/r/($ns)/w[a-z0-9]{16}" &
  done
  follow "$ns" "$(share "$LOGS" "$n")" &
done
load read "$READS" --rand-regex-url "$BASE/r/($nss)/($names)" &
wait

echo "$NAMESPACES namespace(s) $RUN-*, ${SECS}s: writes $WRITES/s ($authors authors), reads $READS/s, logs $LOGS/s"
python3 - "$OUT" "$SECS" <<'EOF'
import glob, json, os, sys
from collections import Counter

kinds = {}
for path in sorted(glob.glob(os.path.join(sys.argv[1], "*.json"))):
    kind = os.path.basename(path).split(".")[0]
    with open(path) as f:
        r = json.load(f)
    k = kinds.setdefault(kind, {"runs": [], "statuses": Counter(), "errors": Counter()})
    k["runs"].append(r)
    k["statuses"].update(r.get("statusCodeDistribution") or {})
    k["errors"].update(r.get("errorDistribution") or {})

def ms(s):
    return "-" if s is None else f"{s * 1000:.0f}"

for kind in ("write", "read", "log"):
    if kind not in kinds:
        continue
    k = kinds[kind]
    runs = k["runs"]
    n = sum(k["statuses"].values())
    ok = sum(c for s, c in k["statuses"].items() if s.startswith("2"))
    rate = ok / float(sys.argv[2])
    # Several runs of a kind (writes: one per author; logs: one per
    # namespace and second) at about the same rate: their percentiles are of
    # equal shares, so their mean stands for all.
    pct = {p: sum(r["latencyPercentiles"][p] or 0 for r in runs) / len(runs) for p in ("p50", "p95", "p99")}
    slowest = max(r["summary"]["slowest"] or 0 for r in runs)
    other = ", ".join(f"{c}×{s}" for s, c in sorted(k["statuses"].items()) if not s.startswith("2"))
    errs = ", ".join(f"{c}×{e}" for e, c in k["errors"].most_common())
    print(f"{kind:5} n={n:<6} ok={ok:<6} ({rate:.1f}/s)  p50={ms(pct['p50']):<5} p95={ms(pct['p95']):<5} "
          f"p99={ms(pct['p99']):<5} max={ms(slowest):<6}" + (f"  {other}" if other else "") + (f"  errors: {errs}" if errs else ""))
EOF
