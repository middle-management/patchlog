#!/usr/bin/env bash
# The write capacity of patchlog on Cloud Spanner (docs/SPANNER.md), for
# comparison with Postgres's in docs/CAPACITY.md ("Several namespaces on one
# database"): SERVERS instances of the core on Compute Engine share a Spanner
# database of the PostgreSQL dialect, and a load generator runs cmd/capacity's
# namespaces phase against them: BUSY counts of busy namespaces, each of
# BUSY_DOCS documents written BUSY_RATE times a second, closed loop. After the
# run it saves Spanner's own statistics of the run's minutes (transactions,
# locks, queries, from SPANNER_SYS) and the instance's CPU, beside the
# harness's JSON.
#
#   ./deploy/gcp-spanner.sh [-y]       a run
#   ./deploy/gcp-spanner.sh cleanup    the Spanner instance and service account
#
# Settings (environment), with their defaults:
#   PROJECT       gcloud config's project
#   REGION        europe-west1; the instance, the cores and the loader all in it
#   ZONE          ${REGION}-b
#   PU            1000 processing units (1 node); 100 to 1000 in steps of 100,
#                 then whole nodes of 1000
#   SERVERS       2 core instances; namespace i's writes go to one by a hash
#                 of its name (cmd/capacity -url)
#   SERVER_TYPE   c3-standard-8 (8 vCPU, 32 GiB)
#   LOADGEN_TYPE  c3-standard-8
#   POOL_CONNS    48, each core's pool_max_conns
#   GROUP_COMMIT  128, each core's --group-commit
#   BUSY          1,2,4,8,16,32 busy namespaces, a step each
#   BUSY_DOCS     100 documents per namespace
#   BUSY_RATE     10 writes a second per document
#   BUSY_SECS     60 seconds a step (Spanner's statistics come in minutes)
#   OUT           ./spanner-<time>, where the results go
#
# What it makes, after asking (-y doesn't ask):
#   - Spanner instance patchlog-bench (regional-$REGION, PU processing units),
#     if it's missing, and its database patchlog of the PostgreSQL dialect,
#     dropped and made anew each run. Billed by the hour while it exists:
#     `cleanup` deletes it.
#   - Service account patchlog-bench, kept for the next run, with
#     roles/spanner.databaseUser on the instance: the cores' and the loader's
#     identity (Application Default Credentials on the VMs).
#   - SERVERS + 1 VMs, deleted on exit, and by Compute Engine itself once the
#     run should have ended (--max-run-duration), should this script die first.
#
# The core and capacity are built from this checkout, uncommitted changes
# included, and copied with gcloud compute scp. Needs gcloud (logged in, with
# the Spanner, Compute Engine and IAM APIs enabled on PROJECT), Go, and curl.
# Not run yet: the first run is its test.
set -euo pipefail

PROJECT=${PROJECT:-$(gcloud config get-value project 2>/dev/null || true)}
REGION=${REGION:-europe-west1}
ZONE=${ZONE:-${REGION}-b}
PU=${PU:-1000}
SERVERS=${SERVERS:-2}
SERVER_TYPE=${SERVER_TYPE:-c3-standard-8}
LOADGEN_TYPE=${LOADGEN_TYPE:-c3-standard-8}
POOL_CONNS=${POOL_CONNS:-48}
GROUP_COMMIT=${GROUP_COMMIT:-128}
BUSY=${BUSY:-1,2,4,8,16,32}
BUSY_DOCS=${BUSY_DOCS:-100}
BUSY_RATE=${BUSY_RATE:-10}
BUSY_SECS=${BUSY_SECS:-60}
OUT=${OUT:-./spanner-$(date +%Y%m%d-%H%M%S)}
NAME=patchlog-bench
INSTANCE=$NAME DATABASE=patchlog
SA=$NAME@$PROJECT.iam.gserviceaccount.com
[ -n "$PROJECT" ] || { echo "gcp-spanner: set PROJECT (or gcloud config set project …)" >&2; exit 1; }
export CLOUDSDK_CORE_PROJECT=$PROJECT
for v in PU SERVERS POOL_CONNS GROUP_COMMIT BUSY_DOCS BUSY_SECS; do
  case ${!v} in ''|*[!0-9]*) echo "gcp-spanner: $v is a whole number" >&2; exit 2 ;; esac
done
[ "$SERVERS" -ge 1 ] || { echo "gcp-spanner: SERVERS is at least 1" >&2; exit 2; }

if [ "${1:-}" = cleanup ]; then
  if gcloud spanner instances describe $INSTANCE >/dev/null 2>&1; then
    gcloud spanner instances delete $INSTANCE --quiet
    echo "gcp-spanner: deleted Spanner instance $INSTANCE"
  fi
  if gcloud iam service-accounts describe "$SA" >/dev/null 2>&1; then
    gcloud iam service-accounts delete "$SA" --quiet
    echo "gcp-spanner: deleted service account $SA"
  fi
  exit 0
fi
YES=""
[ "${1:-}" = -y ] && YES=1
for tool in gcloud go curl python3; do
  command -v $tool >/dev/null || { echo "gcp-spanner: needs $tool" >&2; exit 1; }
done

# Before anything is made: the account may use the project, and its APIs
# are on.
need_apis="spanner.googleapis.com compute.googleapis.com iam.googleapis.com monitoring.googleapis.com"
if ! enabled=$(gcloud services list --enabled --format='value(config.name)' 2>&1); then
  echo "gcp-spanner: $(gcloud config get-value account 2>/dev/null) can't use project $PROJECT:" >&2
  echo "$enabled" | head -3 >&2
  echo "  It needs a role there, Owner or Editor for this script (it makes a service account and grants it Spanner)," >&2
  echo "  or at least roles/serviceusage.serviceUsageConsumer, Spanner Admin, Compute Admin and IAM roles." >&2
  exit 1
fi
missing=""
for api in $need_apis; do grep -qx "$api" <<<"$enabled" || missing="$missing $api"; done
if [ -n "$missing" ]; then
  echo "gcp-spanner: APIs not enabled in $PROJECT:$missing" >&2
  echo "  gcloud services enable$missing --project $PROJECT   (billing must be on)" >&2
  exit 1
fi

steps=$(( $(tr ',' '\n' <<<"$BUSY" | grep -c .) ))
run_min=$(( steps * (BUSY_SECS + 60) / 60 + 1 ))
life_min=$(( run_min + 45 ))
arch_of() {
  case $1 in c4a-*|t2a-*|n4a-*) echo arm64 ;; *) echo amd64 ;; esac
}
goarch=$(arch_of "$SERVER_TYPE")
[ "$(arch_of "$LOADGEN_TYPE")" = "$goarch" ] || { echo "gcp-spanner: SERVER_TYPE and LOADGEN_TYPE differ in architecture" >&2; exit 2; }
image_family=debian-12; [ "$goarch" = arm64 ] && image_family=debian-12-arm64
have_instance=$(gcloud spanner instances describe $INSTANCE --format='value(processingUnits)' 2>/dev/null || true)
have_sa=$(gcloud iam service-accounts describe "$SA" --format='value(email)' 2>/dev/null || true)
root=$(cd "$(dirname "$0")/.." && pwd)
rev=$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)
[ -z "$(git -C "$root" status --porcelain -- cmd internal go.mod go.sum 2>/dev/null)" ] || rev=$rev+changes

echo "project $PROJECT, region $REGION, zone $ZONE"
echo "  Spanner instance $INSTANCE: $([ -n "$have_instance" ] && echo "exists ($have_instance PU; set to $PU)" || echo "to make (regional-$REGION, $PU PU; billed hourly until cleanup)")"
echo "    database $DATABASE (PostgreSQL dialect), dropped and made anew"
echo "  service account $SA: $([ -n "$have_sa" ] && echo exists || echo 'to make')"
echo "  $SERVERS × $SERVER_TYPE core(s) and 1 × $LOADGEN_TYPE loader ($image_family), deleted on exit or after $life_min minutes"
echo "  core and capacity built from this checkout ($rev, linux/$goarch)"
echo "  run: $steps steps ($BUSY busy namespaces) of $BUSY_DOCS documents × $BUSY_RATE/s, ${BUSY_SECS}s each (about $run_min minutes);"
echo "    cores with pool_max_conns=$POOL_CONNS, --group-commit $GROUP_COMMIT; results in $OUT"
if [ -z "$YES" ]; then
  read -r -p "go ahead? [y/N] " ok
  [ "$ok" = y ] || exit 1
fi
mkdir -p "$OUT"

# The Spanner instance and a fresh database.
if [ -z "$have_instance" ]; then
  gcloud spanner instances create $INSTANCE --config=regional-$REGION --processing-units="$PU" --description="patchlog bench"
elif [ "$have_instance" != "$PU" ]; then
  gcloud spanner instances update $INSTANCE --processing-units="$PU"
fi
gcloud spanner databases delete $DATABASE --instance=$INSTANCE --quiet 2>/dev/null || true
gcloud spanner databases create $DATABASE --instance=$INSTANCE --database-dialect=POSTGRESQL
if [ -z "$have_sa" ]; then
  gcloud iam service-accounts create $NAME --display-name="patchlog bench"
  sleep 10 # the account reaches IAM
fi
gcloud spanner instances add-iam-policy-binding $INSTANCE --member="serviceAccount:$SA" --role=roles/spanner.databaseUser >/dev/null
# The Spanner client's own metrics (GFE and attempt latencies), written to
# Cloud Monitoring.
gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:$SA" --role=roles/monitoring.metricWriter --condition=None >/dev/null

# Binaries.
build=$(mktemp -d)
(cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=$goarch go build -o "$build/patchlog" ./cmd/patchlog \
  && CGO_ENABLED=0 GOOS=linux GOARCH=$goarch go build -o "$build/capacity" ./cmd/capacity)

# The VMs, deleted on exit.
vms=()
for i in $(seq 1 "$SERVERS"); do vms+=("$NAME-core-$i"); done
vms+=("$NAME-loader")
cleanup_vms() {
  echo "gcp-spanner: deleting the VMs"
  gcloud compute instances delete "${vms[@]}" --zone="$ZONE" --quiet >/dev/null 2>&1 || true
  rm -rf "$build"
}
trap cleanup_vms EXIT
make_vm() { # name type
  gcloud compute instances create "$1" --zone="$ZONE" --machine-type="$2" \
    --image-family=$image_family --image-project=debian-cloud --boot-disk-size=20GB \
    --service-account="$SA" --scopes=cloud-platform \
    --max-run-duration="${life_min}m" --instance-termination-action=DELETE >/dev/null
}
for i in $(seq 1 "$SERVERS"); do make_vm "$NAME-core-$i" "$SERVER_TYPE" & done
make_vm "$NAME-loader" "$LOADGEN_TYPE" &
wait
ip_of() { gcloud compute instances describe "$1" --zone="$ZONE" --format='value(networkInterfaces[0].networkIP)'; }
ssh_vm() { local vm=$1; shift; gcloud compute ssh "$vm" --zone="$ZONE" --quiet --command="$*"; }
for vm in "${vms[@]}"; do
  for _ in $(seq 1 30); do ssh_vm "$vm" true >/dev/null 2>&1 && break; sleep 5; done
done

# The cores: the first migrates the database, then the others start.
db="spanner://projects/$PROJECT/instances/$INSTANCE/databases/$DATABASE?pool_max_conns=$POOL_CONNS"
start_core() { # vm
  gcloud compute scp "$build/patchlog" "$1:patchlog" --zone="$ZONE" --quiet >/dev/null
  ssh_vm "$1" "ulimit -n 1048576 2>/dev/null || true
    nohup ./patchlog serve --dev --addr :8080 --db '$db' --blob-dir ./blobs --group-commit $GROUP_COMMIT \
      --max-rate-per-namespace 1e9,1e9 --max-rate-per-resource 1e9,1e9 --max-rate-per-principal 1e9,1e9 > server.log 2>&1 &
    pid=\$!
    for _ in \$(seq 1 180); do curl -sf -o /dev/null http://127.0.0.1:8080/_health && exit 0; kill -0 \$pid || { tail -20 server.log; exit 1; }; sleep 1; done
    tail -20 server.log; exit 1"
}
start_core "$NAME-core-1"
urls="http://$(ip_of "$NAME-core-1"):8080"
for i in $(seq 2 "$SERVERS"); do
  start_core "$NAME-core-$i" &
  urls="$urls,http://$(ip_of "$NAME-core-$i"):8080"
done
wait

# The run.
gcloud compute scp "$build/capacity" "$NAME-loader:capacity" --zone="$ZONE" --quiet >/dev/null
t0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ssh_vm "$NAME-loader" "ulimit -n 1048576 2>/dev/null || true; ./capacity --url $urls --only namespaces \
  --busy-namespaces $BUSY --busy-docs $BUSY_DOCS --busy-rate $BUSY_RATE --busy-seconds $BUSY_SECS --json result.json" | tee "$OUT/capacity.log"
t1=$(date -u +%Y-%m-%dT%H:%M:%SZ)
gcloud compute scp "$NAME-loader:result.json" "$OUT/result.json" --zone="$ZONE" --quiet >/dev/null
for i in $(seq 1 "$SERVERS"); do
  gcloud compute scp "$NAME-core-$i:server.log" "$OUT/server-$i.log" --zone="$ZONE" --quiet >/dev/null || true
done

# Spanner's statistics of the run: the top transactions, locks and queries
# of each minute (SPANNER_SYS, kept for hours), and the instance's CPU.
sleep 70 # the last minute's statistics are written after it ends
stats() { # table file
  gcloud spanner databases execute-sql $DATABASE --instance=$INSTANCE --format=json \
    --sql="SELECT * FROM spanner_sys.$1 WHERE interval_end >= '$t0' AND interval_end <= timestamptz '$t1' + interval '2 minutes' ORDER BY interval_end" \
    > "$OUT/$1.json" || echo "gcp-spanner: reading spanner_sys.$1 failed" >&2
}
stats txn_stats_top_minute
stats lock_stats_top_minute
stats query_stats_top_minute
stats txn_stats_total_minute
token=$(gcloud auth print-access-token)
for metric in instance/cpu/utilization_by_priority instance/cpu/utilization; do
  curl -sfG "https://monitoring.googleapis.com/v3/projects/$PROJECT/timeSeries" -H "Authorization: Bearer $token" \
    --data-urlencode "filter=metric.type=\"spanner.googleapis.com/$metric\" AND resource.labels.instance_id=\"$INSTANCE\"" \
    --data-urlencode "interval.startTime=$t0" --data-urlencode "interval.endTime=$t1" \
    > "$OUT/$(tr / _ <<<"$metric").json" || echo "gcp-spanner: reading $metric failed" >&2
done
python3 - "$OUT/result.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
print(f"{'busy':>5} {'asked/s':>8} {'written/s':>10} {'p50 ms':>8} {'p99 ms':>8} {'412':>6} {'429':>6} {'errors':>6}")
for k in sorted((k for k in r if k.startswith('namespaces_')), key=lambda k: int(k.split('_')[1])):
    s = r[k]
    print(f"{s['namespaces']:>5} {s['asked_per_second']:>8.0f} {s.get('per_second', 0):>10.0f} {s.get('p50_ms', 0):>8.1f} {s.get('p99_ms', 0):>8.1f} {s['stale_412']:>6} {s['limited_429']:>6} {s['errors']:>6}")
PY
echo "gcp-spanner: results in $OUT; the instance stays until ./deploy/gcp-spanner.sh cleanup"
