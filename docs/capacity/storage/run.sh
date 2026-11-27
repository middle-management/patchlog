#!/bin/sh
# Rerun the storage measurement on a new, empty database (README.md).
#
#   docs/capacity/storage/run.sh sqlite out.json [writes] [resources]
#   PG=postgres://postgres@localhost:5432/postgres docs/capacity/storage/run.sh pg out.json
#
# For pg, PG names a server whose user may create databases; the run
# creates (and drops) a database capstorage there.
set -eu
store=$1 out=$2 writes=${3:-1000000} resources=${4:-1000}
dir=$(mktemp -d)
trap 'kill $core 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$dir"' EXIT
go build -o "$dir/patchlog" ./cmd/patchlog
go build -o "$dir/capacity" ./cmd/capacity
keys=$("$dir/patchlog" keygen)
pub=$(echo "$keys" | awk '/^public/ {print $2}')
priv=$(echo "$keys" | awk '/^private/ {print $2}')
case $store in
sqlite) db="$dir/storage.db" ;;
pg)
	psql "$PG" -qc 'DROP DATABASE IF EXISTS capstorage' -c 'CREATE DATABASE capstorage'
	db=$(echo "$PG" | sed 's#/[^/?]*\([?]\|$\)#/capstorage\1#') ;;
*) echo "store: sqlite or pg" >&2; exit 2 ;;
esac
port=${PORT:-18181}
"$dir/patchlog" serve --addr ":$port" --origin "http://localhost:$port" --db "$db" --operator-key "$pub" \
	--retention-interval 0 --max-rate-per-namespace 1000000000,1000000000 \
	--max-rate-per-resource 1000000000,1000000000 --max-rate-per-principal 1000000000,1000000000 >"$dir/core.log" 2>&1 &
core=$!
for i in $(seq 50); do curl -sf "http://localhost:$port/" >/dev/null && break; sleep 0.2; done
"$dir/capacity" --url "http://localhost:$port" --operator-seed "$priv" --only storage \
	--storage-db "$db" --storage-writes "$writes" --storage-resources "$resources" --json "$out"
kill $core; wait $core 2>/dev/null || true
if [ "$store" = pg ]; then psql "$PG" -qc 'DROP DATABASE capstorage'; fi
