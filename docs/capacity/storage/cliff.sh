#!/bin/sh
# One point of the memory-cliff curve (README.md, "The memory cliff"): a new
# database, --cliff-resources resources created through the API, WRITES
# pruned writes loaded straight into it, then the database restarted cold
# under its memory limit and a paced load through the API, measured.
#
#   PG=postgres://postgres@localhost:55602/postgres CONTAINER=plx-cliff MEM=256m \
#     docs/capacity/storage/cliff.sh pg out.json 1000000
#   MEM=256m docs/capacity/storage/cliff.sh sqlite out.json 1000000
#
# pg: CONTAINER is the Postgres container PG names, started with the memory
# limit MEM (docker run --memory=MEM --memory-swap=MEM); the load runs with
# the limit raised to LOADMEM (default 2g), and the container is restarted
# under MEM with the host's page cache dropped (so this runs as root) and
# every table and index read once (pg_prewarm) before the paced load. sqlite: the core runs in a container (alpine,
# --network host) limited to MEM for the paced load, which reads the
# database file once before it, its database in a temporary directory (DIR
# to keep it elsewhere).
#
# RATE (100) writes a second for DURATION seconds (150); LABEL is recorded with the
# results; PORT (18191) is the core's; BIN, a directory holding patchlog
# (built with CGO_ENABLED=0, for the alpine container) and capacity, is
# used in place of building them from the working tree.
set -eu
store=$1 out=$2 writes=$3
mem=${MEM:-256m} loadmem=${LOADMEM:-2g} port=${PORT:-18191}
dir=${DIR:-$(mktemp -d)}
mkdir -p "$dir"
core=
trap 'if [ -n "$core" ]; then kill $core 2>/dev/null || true; fi; docker rm -f plx-cliff-core >/dev/null 2>&1 || true; wait 2>/dev/null || true' EXIT
if [ -n "${BIN:-}" ]; then # binaries built before, e.g. of another commit
	cp "$BIN/patchlog" "$BIN/capacity" "$dir/"
else
	CGO_ENABLED=0 go build -o "$dir/patchlog" ./cmd/patchlog
	go build -o "$dir/capacity" ./cmd/capacity
fi
keys=$("$dir/patchlog" keygen)
pub=$(echo "$keys" | awk '/^public/ {print $2}')
priv=$(echo "$keys" | awk '/^private/ {print $2}')
flags="--retention-interval 0 --max-rate-per-namespace 1000000000,1000000000 --max-rate-per-resource 1000000000,1000000000 --max-rate-per-principal 1000000000,1000000000"
cap() { "$dir/capacity" --url "http://localhost:$port" --operator-seed "$priv" --only cliff --cliff-db "$db" "$@"; }
serve() { # the core, natively, on $1
	"$dir/patchlog" serve --addr ":$port" --origin "http://localhost:$port" --db "$1" --operator-key "$pub" $flags >>"$dir/core.log" 2>&1 &
	core=$!
	for i in $(seq 100); do curl -sf "http://localhost:$port/" >/dev/null && return; sleep 0.2; done
	echo "the core did not start" >&2; exit 1
}
stop() { kill $core; wait $core 2>/dev/null || true; core=; }
cold() { sync; echo 3 >/proc/sys/vm/drop_caches; }
case $store in
pg)
	ctr=${CONTAINER:?set CONTAINER to the Postgres container}
	docker update --memory "$loadmem" --memory-swap "$loadmem" "$ctr" >/dev/null
	psql "$PG" -qc 'DROP DATABASE IF EXISTS capcliff' -c 'CREATE DATABASE capcliff'
	db=$(echo "$PG" | sed 's#/[^/?]*\([?]\|$\)#/capcliff\1#')
	serve "$db"
	cap --cliff-step setup
	stop
	cap --cliff-step preload --cliff-writes "$writes"
	docker update --memory "$mem" --memory-swap "$mem" "$ctr" >/dev/null
	docker restart "$ctr" >/dev/null
	cold
	for i in $(seq 100); do psql "$PG" -qc 'SELECT 1' >/dev/null 2>&1 && break; sleep 0.3; done
	# Every table, then every index, read once (largest first): the cache
	# holds what the memory allows, as it would on a server that has run.
	psql "$db" -qAt -c 'CREATE EXTENSION IF NOT EXISTS pg_prewarm' \
		-c "SELECT COUNT(pg_prewarm(oid, 'read')) FROM (SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = current_schema() AND c.relkind = 'r' ORDER BY pg_relation_size(c.oid) DESC) x" \
		-c "SELECT COUNT(pg_prewarm(oid, 'read')) FROM (SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = current_schema() AND c.relkind = 'i' ORDER BY pg_relation_size(c.oid) DESC) x" >/dev/null
	serve "$db"
	cap --cliff-step paced --cliff-rate "${RATE:-100}" --cliff-seconds "${DURATION:-150}" --cliff-label "${LABEL:-}" \
		--cliff-cgroup "/sys/fs/cgroup/memory/docker/$(docker inspect -f '{{.Id}}' "$ctr")" --json "$out"
	stop
	psql "$PG" -qc 'DROP DATABASE capcliff'
	;;
sqlite)
	db="$dir/cliff.db"
	rm -f "$db" "$db-wal" "$db-shm"
	serve "$db"
	cap --cliff-step setup
	stop
	cap --cliff-step preload --cliff-writes "$writes"
	cold
	docker run -d --name plx-cliff-core --memory "$mem" --memory-swap "$mem" --network host -v "$dir:$dir" alpine:3.22 \
		"$dir/patchlog" serve --addr ":$port" --origin "http://localhost:$port" --db "$db" --operator-key "$pub" $flags >/dev/null
	for i in $(seq 100); do curl -sf "http://localhost:$port/" >/dev/null && break; sleep 0.2; done
	# The database read once, in the container: its cache holds what the
	# memory allows.
	docker exec plx-cliff-core cat "$db" >/dev/null
	cap --cliff-step paced --cliff-rate "${RATE:-100}" --cliff-seconds "${DURATION:-150}" --cliff-label "${LABEL:-}" \
		--cliff-cgroup "/sys/fs/cgroup/memory/docker/$(docker inspect -f '{{.Id}}' plx-cliff-core)" --json "$out"
	docker rm -f plx-cliff-core >/dev/null
	rm -f "$db" "$db-wal" "$db-shm"
	;;
*) echo "store: sqlite or pg" >&2; exit 2 ;;
esac
