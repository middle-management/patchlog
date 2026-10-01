vcl 4.1;
# A local CDN for the compose stack (docs/SPEC.md §9). One varnishd listens
# once per origin and picks the backend by listener name:
#
#   varnishd -a core=:8080 -a search=:8081 -a tree=:8082 -f default.vcl
#
# What it does:
#
# - Edge lifetimes come from CDN-Cache-Control (RFC 9213) when the origin
#   sends it, else from Cache-Control: s-maxage, then max-age. no-store,
#   no-cache, errors and responses without Cache-Control aren't cached. Vary
#   is honoured (Varnish does that itself). Grace (serving
#   stale while refetching) is the stale-while-revalidate the same field
#   gives, and nothing otherwise: §9 grants it only to head pointers, and a
#   long-poll answer (§7.7) served stale would end a wait early.
# - Clients get Cache-Control exactly as the origin sent it. CDN-Cache-Control,
#   Cache-Tag and Surrogate-Key are removed, unless the request carries
#   `X-Cache-Debug: 1`, which also adds X-Cache-TTL, X-Cache-Grace and
#   X-Cache-Reason. Every response says X-Cache: HIT, MISS or PASS, and Age.
# - Reads are looked up whatever Authorization they carry: a public
#   namespace answers a request with a grant exactly as one without (§7), and
#   caches it publicly. Responses the origin marks `private` (non-public
#   namespaces, §9 and §C.5) are not cached here, because this CDN doesn't
#   verify edge grants: a cached copy would go to any caller. The origins run
#   without -edge-secret, so they already mark those responses
#   CDN-Cache-Control: no-store; this rule is belt and braces. The one
#   exception is a response that also says `Vary: Authorization`, which is
#   cached per credential.
# - `PURGE` (or `BAN`) with `X-Purge-Tags: tag1 tag2 …` from the compose
#   network bans every object whose Cache-Tag lists any of the tags, as a
#   whole token. That is what internal/cdnpurge sends (-purge-url).
# - Identical misses are collapsed onto one backend request (Varnish's
#   waiting list), which is what §7.7's long-poll URLs are built for. Event
#   streams (…/events) are passed and streamed unbuffered.
#
# Backend host names are resolved when the VCL is loaded, so the origins'
# containers must exist first (compose's depends_on sees to it), and a
# recreated origin container with a new address needs `docker compose restart cdn`.

import std;

# Health checks: a sick origin gets its graced copies served (up to their
# stale-while-revalidate) and a quick 503 otherwise. Every origin answers
# /_health without touching its database, 200 while serving and 503 once it
# drains for shutdown, so a stopping origin leaves rotation (with several
# instances behind one director, give them a -shutdown-delay of a probe
# interval or two).
probe core_up {
	.url = "/_health";
	.interval = 5s;
	.timeout = 2s;
	.window = 3;
	.threshold = 2;
	.initial = 2;
}

probe service_up {
	.url = "/_health";
	.interval = 5s;
	.timeout = 2s;
	.window = 3;
	.threshold = 2;
	.initial = 2;
}

# Timeouts: a long-poll answer comes at the latest at its interval boundary
# (20 s by default, §7.7) and event streams send a comment every 30 s, so
# 75 s leaves room for both.
backend core {
	.host = "patchlog";
	.port = "8080";
	.connect_timeout = 2s;
	.first_byte_timeout = 75s;
	.between_bytes_timeout = 75s;
	.probe = core_up;
}

backend search {
	.host = "index";
	.port = "8081";
	.connect_timeout = 2s;
	.first_byte_timeout = 75s;
	.between_bytes_timeout = 75s;
	.probe = service_up;
}

backend tree {
	.host = "tree";
	.port = "8082";
	.connect_timeout = 2s;
	.first_byte_timeout = 75s;
	.between_bytes_timeout = 75s;
	.probe = service_up;
}

# Who may purge: loopback and the private ranges Docker networks use. From
# the host, published ports arrive from the bridge's gateway, so the host
# can purge too (handy for experiments; this is a development CDN).
acl purgers {
	"localhost";
	"127.0.0.0"/8;
	"::1";
	"10.0.0.0"/8;
	"172.16.0.0"/12;
	"192.168.0.0"/16;
}

sub vcl_recv {
	if (local.socket == "search") {
		set req.backend_hint = search;
	} elsif (local.socket == "tree") {
		set req.backend_hint = tree;
	} else {
		set req.backend_hint = core;
	}
	unset req.http.X-Cache;

	if (req.method == "PURGE" || req.method == "BAN") {
		call purge_tags;
	}

	# Writes, batches, key requests and anything else that isn't a read.
	if (req.method != "GET" && req.method != "HEAD") {
		return (pass);
	}
	# Health endpoints are each origin's own state, never a cached copy.
	if (req.url ~ "^/_(health|ready)(\?|$)") {
		return (pass);
	}
	# Event streams (§7.3, §7.4) are no-store: pass them, streamed.
	if (req.url ~ "^/(r|ns)/[^?]*/events(\?|$)" || req.http.Accept ~ "text/event-stream") {
		return (pass);
	}
	# Unlike builtin.vcl, don't pass requests with Authorization or cookies:
	# the response decides (vcl_backend_response).
	return (hash);
}

# purge_tags turns X-Purge-Tags into a ban. Tags are separated by spaces or
# commas; each is matched literally (\Q…\E) as a whole comma-separated token
# of obj.http.Cache-Tag. The expression uses only obj.*, so the ban lurker
# can retire it in the background.
sub purge_tags {
	if (!(client.ip ~ purgers)) {
		return (synth(403, "Purge not allowed from " + client.ip));
	}
	set req.http.X-Purge-Tags = regsuball(req.http.X-Purge-Tags, "[\s,]+", " ");
	set req.http.X-Purge-Tags = regsuball(req.http.X-Purge-Tags, "^ | $", "");
	if (req.http.X-Purge-Tags == "") {
		return (synth(400, "X-Purge-Tags is required"));
	}
	# A backslash could end \Q…\E early; a quote could end the ban argument.
	if (req.http.X-Purge-Tags ~ {"[\\"]"}) {
		return (synth(400, "tags must not contain backslashes or quotes"));
	}
	# (In a regsuball replacement, a backslash escapes: "\\E" yields \E.)
	set req.http.X-Purge-Regex = "(^|,)\s*(\Q" + regsuball(req.http.X-Purge-Tags, " ", "\\E|\\Q") + "\E)\s*(,|$)";
	if (std.ban("obj.http.Cache-Tag ~ " + req.http.X-Purge-Regex)) {
		return (synth(200, "Purged " + req.http.X-Purge-Tags));
	}
	return (synth(400, "Bad purge: " + std.ban_error()));
}

sub vcl_hash {
	# The listener picks the origin; the Host header doesn't matter to the
	# origins (they build URLs from -origin), so localhost:8080 and
	# 127.0.0.1:8080 share one copy.
	hash_data(local.socket);
	hash_data(req.url);
	return (lookup);
}

sub vcl_hit {
	set req.http.X-Cache = "HIT";
}

sub vcl_miss {
	set req.http.X-Cache = "MISS";
}

sub vcl_pass {
	set req.http.X-Cache = "PASS";
}

sub vcl_backend_response {
	if (bereq.uncacheable) {
		# Passed: stream as it comes (event streams).
		set beresp.do_stream = true;
		return (deliver);
	}
	# Only statuses HTTP lets a cache store by default (Varnish's list,
	# including 204 for long-poll timeouts), never errors.
	if (!(beresp.status == 200 || beresp.status == 203 || beresp.status == 204 ||
	      beresp.status == 300 || beresp.status == 301 || beresp.status == 302 ||
	      beresp.status == 304 || beresp.status == 307 || beresp.status == 308 ||
	      beresp.status == 404 || beresp.status == 410 || beresp.status == 414)) {
		set beresp.http.X-Cache-Reason = "status";
		call uncacheable;
	}
	# Private downstream: needs edge-grant checks this CDN doesn't make,
	# unless the response is keyed by credential anyway.
	if (beresp.http.Cache-Control ~ "(?i)(^|[,\s])private\b" && beresp.http.Vary !~ "(?i)(^|[,\s])authorization\b") {
		set beresp.http.X-Cache-Reason = "private (no edge grants at this CDN)";
		call uncacheable;
	}
	if (beresp.http.Set-Cookie || beresp.http.Vary ~ "\*") {
		set beresp.http.X-Cache-Reason = "set-cookie or vary *";
		call uncacheable;
	}

	# The edge's directives: CDN-Cache-Control overrides Cache-Control.
	if (beresp.http.CDN-Cache-Control) {
		set beresp.http.X-Edge-CC = beresp.http.CDN-Cache-Control;
	} elsif (beresp.http.Cache-Control) {
		set beresp.http.X-Edge-CC = beresp.http.Cache-Control;
	} else {
		# No directive (e.g. GET /): the origin didn't say it may be
		# cached, so don't guess with Varnish's default_ttl.
		set beresp.http.X-Cache-Reason = "no Cache-Control";
		call uncacheable;
	}
	if (beresp.http.X-Edge-CC ~ "(?i)(^|[,\s])(no-store|no-cache)\b") {
		set beresp.http.X-Cache-Reason = "no-store";
		call uncacheable;
	}
	# Without a CDN-Cache-Control, `private` alone already made it
	# uncacheable above; with one, the edge may keep it (per credential).
	# (Varnish has already set beresp.ttl from Cache-Control and Expires;
	# this redoes it from the edge's field, less any Age from upstream.)
	if (beresp.http.X-Edge-CC ~ "(?i)(^|[,\s])s-maxage=\d+") {
		set beresp.ttl = std.duration(regsub(beresp.http.X-Edge-CC, "(?i)^.*(^|[,\s])s-maxage=(\d+).*$", "\2") + "s", 0s)
		    - std.duration(beresp.http.Age + "s", 0s);
	} elsif (beresp.http.X-Edge-CC ~ "(?i)(^|[,\s])max-age=\d+") {
		set beresp.ttl = std.duration(regsub(beresp.http.X-Edge-CC, "(?i)^.*(^|[,\s])max-age=(\d+).*$", "\2") + "s", 0s)
		    - std.duration(beresp.http.Age + "s", 0s);
	}
	if (beresp.http.X-Edge-CC ~ "(?i)(^|[,\s])stale-while-revalidate=\d+") {
		set beresp.grace = std.duration(regsub(beresp.http.X-Edge-CC, "(?i)^.*(^|[,\s])stale-while-revalidate=(\d+).*$", "\2") + "s", 0s);
	} else {
		set beresp.grace = 0s;
	}
	set beresp.keep = 0s;
	unset beresp.http.X-Edge-CC;

	if (beresp.ttl <= 0s) {
		# max-age=0 without s-maxage: nothing to keep, but collapse nothing
		# either (hit-for-miss, so the next response may still be cached).
		set beresp.http.X-Cache-Reason = "ttl 0";
		call uncacheable;
	}
	return (deliver);
}

# uncacheable marks the URL hit-for-miss for two minutes: requests for it
# go to the origin in parallel instead of queueing on each other, and a
# cacheable response in the meantime is still stored.
sub uncacheable {
	unset beresp.http.X-Edge-CC;
	set beresp.ttl = 120s;
	set beresp.grace = 0s;
	set beresp.uncacheable = true;
	return (deliver);
}

sub vcl_deliver {
	if (obj.uncacheable) {
		set resp.http.X-Cache = "PASS";
	} elsif (req.http.X-Cache == "HIT") {
		set resp.http.X-Cache = "HIT";
	} else {
		set resp.http.X-Cache = "MISS";
	}
	if (req.http.X-Cache-Debug == "1") {
		set resp.http.X-Cache-TTL = obj.ttl;
		set resp.http.X-Cache-Grace = obj.grace;
		set resp.http.X-Cache-Hits = obj.hits;
	} else {
		unset resp.http.CDN-Cache-Control;
		unset resp.http.Cache-Tag;
		unset resp.http.Surrogate-Key;
		unset resp.http.X-Cache-Reason;
		unset resp.http.X-Varnish;
	}
	unset req.http.X-Cache;
}

sub vcl_backend_error {
	# The origin is down or timed out, and nothing (not even in grace) is
	# cached for the URL. Not cached itself.
	set beresp.http.Cache-Control = "no-store";
	set beresp.http.Content-Type = "text/plain; charset=utf-8";
	set beresp.body = "CDN: origin unavailable (" + beresp.reason + {")
"};
	return (deliver);
}

sub vcl_synth {
	set resp.http.Cache-Control = "no-store";
	set resp.http.Content-Type = "text/plain; charset=utf-8";
	set resp.body = resp.reason + {"
"};
	return (deliver);
}
