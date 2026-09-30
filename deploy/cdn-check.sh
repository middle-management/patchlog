#!/bin/sh
# Smoke test of the local CDN (deploy/varnish) in front of a running stack:
# `make cdn-check` after `make up`. It creates a resource in its own public
# namespace (cdncheck) through the CDN and shows
#
#   1. an immutable revision: MISS, then HIT (and its cache tags);
#   2. a head pointer micro-cached (s-maxage=1, stale-while-revalidate=5):
#      HIT on the old head right after an append, the new head a moment later;
#   3. long-poll followers collapsed onto one origin request (§7.7);
#   4. a purge (DELETE, then POST …/purge): the core sends PURGE with the
#      resource's tags, and the next fetch of the revision is a MISS (410);
#   5. the search service's listener: a result at a checkpoint, MISS then HIT.
#
# CDN, SEARCH: the CDN's core and search listeners (default localhost:8080
# and :8081, or PATCHLOG_PORT / INDEX_PORT).
set -eu
CDN=${CDN:-http://localhost:${PATCHLOG_PORT:-8080}}
SEARCH=${SEARCH:-http://localhost:${INDEX_PORT:-8081}}
P='Content-Type: application/json-patch+json'
A='X-Author: cdn-check'
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
# get URL [curl args…]: headers of a GET into $TMP/h, shown briefly
get() {
  u=$1; shift
  curl -s -o "$TMP/body" -D "$TMP/h" "$@" "$u"
  tr -d '\r' <"$TMP/h" >"$TMP/h2" && mv "$TMP/h2" "$TMP/h"
}
hdr() { grep -i "^$1: " "$TMP/h" | head -n 1 | cut -d' ' -f2-; }
status() { head -n 1 "$TMP/h" | cut -d' ' -f2; }
show() { printf '  %-34s %s %-4s age=%-3s %s\n' "$1" "$(status)" "$(hdr X-Cache)" "$(hdr Age)" "$2"; }
expect() { # expect WHAT GOT WANT
  [ "$2" = "$3" ] || fail "$1: got '$2', want '$3'"
}
write() { # write METHOD PATH [curl args…] -> headers in $TMP/h
  m=$1; p=$2; shift 2
  curl -s -o "$TMP/body" -D "$TMP/h" -X "$m" -H "$A" "$@" "$CDN$p"
  tr -d '\r' <"$TMP/h" >"$TMP/h2" && mv "$TMP/h2" "$TMP/h"
}
etag() { hdr ETag | tr -d '"'; }

echo "CDN $CDN, search $SEARCH"
get "$CDN/" || fail "CDN not reachable at $CDN (make up)"
[ -n "$(hdr X-Cache)" ] || fail "no X-Cache header: is $CDN the CDN, not the origin?"

write PATCH /ns/cdncheck -H "$P" -H 'If-None-Match: *' -d '[{"op":"add","path":"","value":{"read":"public"}}]'
name="r$(date +%s)$$"
write PATCH "/r/cdncheck/$name" -H "$P" -H 'If-None-Match: *' -d '[{"op":"add","path":"","value":{"n":1}}]'
expect "create /r/cdncheck/$name" "$(status)" 201
rev1=$(etag)
[ "$(hdr X-Cache)" = PASS ] || fail "a write went through the cache (X-Cache $(hdr X-Cache))"

echo "1. immutable revision /r/cdncheck/$name/rev/$rev1"
get "$CDN/r/cdncheck/$name/rev/$rev1"
show "first fetch" "$(hdr Cache-Control)"
expect "first fetch" "$(hdr X-Cache)" MISS
[ -z "$(hdr Cache-Tag)" ] || fail "Cache-Tag leaked to a client without X-Cache-Debug"
get "$CDN/r/cdncheck/$name/rev/$rev1" -H 'X-Cache-Debug: 1'
show "second fetch (X-Cache-Debug: 1)" "Cache-Tag: $(hdr Cache-Tag)  ttl=$(hdr X-Cache-TTL)"
expect "second fetch" "$(hdr X-Cache)" HIT

echo "2. head pointer /r/cdncheck/$name"
get "$CDN/r/cdncheck/$name"
show "fetch" "-> $(hdr Location)"
expect "head" "$(status)" 302
get "$CDN/r/cdncheck/$name"
show "again (within s-maxage=1)" "-> $(hdr Location)"
expect "head again" "$(hdr X-Cache)" HIT
write PATCH "/r/cdncheck/$name" -H "$P" -H "If-Match: \"$rev1\"" -d '[{"op":"replace","path":"/n","value":2}]'
expect "append" "$(status)" 201
rev2=$(etag)
echo "  appended $rev2"
get "$CDN/r/cdncheck/$name"
show "right after the append" "-> $(hdr Location)"
i=0
while [ "$(hdr Location)" != "/r/cdncheck/$name/rev/$rev2" ]; do
  i=$((i + 1))
  [ $i -le 16 ] || fail "the head pointer still shows the old head after 8 s (s-maxage 1 + swr 5)"
  sleep 0.5
  get "$CDN/r/cdncheck/$name"
  show "after $((i * 5 / 10)).$((i * 5 % 10)) s" "-> $(hdr Location)"
done

echo "3. long-poll: 5 followers of /ns/cdncheck/log, one write wakes them"
get "$CDN/ns/cdncheck"
nshead=$(etag)
lp="$CDN/ns/cdncheck/log?since=$nshead&live=long-poll"
for k in 1 2 3 4 5; do
  curl -s -o /dev/null -D "$TMP/lp$k" "$lp" &
done
sleep 1
write PATCH "/r/cdncheck/$name" -H "$P" -H "If-Match: \"$rev2\"" -d '[{"op":"replace","path":"/n","value":3}]'
expect "append" "$(status)" 201
rev3=$(etag)
wait
hits=0
for k in 1 2 3 4 5; do
  tr -d '\r' <"$TMP/lp$k" >"$TMP/h"
  show "follower $k" "X-Namespace-Revision $(hdr X-Namespace-Revision)"
  expect "follower $k" "$(status)" 200
  [ "$(hdr X-Cache)" = HIT ] && hits=$((hits + 1))
done
expect "followers served from the collapsed request" $hits 4

echo "4. purge /r/cdncheck/$name"
get "$CDN/r/cdncheck/$name/rev/$rev1"
show "revision before" ""
expect "revision before the purge" "$(hdr X-Cache)" HIT
write DELETE "/r/cdncheck/$name" -H "If-Match: \"$rev3\""
expect "delete" "$(status)" 200
tomb=$(sed -n 's/.*"tombstone":"\([^"]*\)".*/\1/p' "$TMP/body")
write POST "/r/cdncheck/$name/purge" -H "If-Match: \"$tomb\""
expect "purge" "$(status)" 204
echo "  purged; the core sends PURGE X-Purge-Tags: r:cdncheck/$name (asynchronously)"
i=0
while :; do
  sleep 0.2
  get "$CDN/r/cdncheck/$name/rev/$rev1"
  [ "$(hdr X-Cache)" = HIT ] || break
  i=$((i + 1))
  [ $i -le 25 ] || fail "revision still cached 5 s after the purge (is -purge-url set on the core?)"
done
show "revision after" ""
expect "revision after the purge" "$(hdr X-Cache)" MISS
expect "revision after the purge" "$(status)" 410

echo "5. search $SEARCH/demo?q=derby"
get "$SEARCH/demo?q=derby"
show "query" "-> $(hdr Location)"
if [ "$(status)" = 302 ]; then
  loc=$(hdr Location)
  get "$SEARCH$loc"
  show "result" "$(hdr Cache-Control)"
  get "$SEARCH$loc"
  show "result again" ""
  expect "search result again" "$(hdr X-Cache)" HIT
else
  echo "  (search service not answering a 302 yet; skipped)"
fi
echo "OK"
