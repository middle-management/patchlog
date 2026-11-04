//! patchlog on Cloudflare Workers.
//!
//! The front Worker answers `GET /`, refuses malformed URLs (§7), serves
//! immutable responses from the Cache API, and forwards everything else to
//! the namespace's Durable Object (`ns.rs`), addressed by the namespace name.

mod auth;
mod edge;
mod http;
mod ns;
mod nsdoc;

use futures_util::StreamExt;
use http::Err;
use patchlog_core::names::{is_namespace_name, is_resource_name};
use worker::*;

pub use ns::Namespace;

#[event(fetch)]
async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
    let origin = req.headers().get("Origin")?;
    let listed = edge::credentialed_origins(&env);
    if req.method() == Method::Options {
        return preflight(&req.path(), origin.as_deref(), &listed);
    }
    let resp = match front(req, env, ctx).await {
        Ok(r) => r,
        Err(e) => e.into_response(false)?,
    };
    with_cors(resp, origin.as_deref(), &listed)
}

/// §7, browsers: a page on a credentialed origin (§C.5.2) is named, with
/// credentials allowed; every other origin gets `*`. Every response carries
/// the exposed headers, `Origin` or not.
const CORS_METHODS: &str = "GET, HEAD, PATCH, PUT, POST, DELETE";
const CORS_ALLOW_HEADERS: &str = "Authorization, If-Match, Source-Authorization, Signature, Content-Type, Gesture, Undoes, Blob-Nonce, Blob-From, X-Author, If-None-Match, If-Modified-Since, Range, If-Range, Last-Event-ID";
const CORS_EXPOSE_HEADERS: &str = "ETag, Location, Repr-Digest, Retry-After, Content-Range, Gesture, Undoes, X-Revision, X-Namespace-Revision, X-Config-Revision, X-Cursor, X-Log-Next";

fn with_cors(resp: Response, origin: Option<&str>, listed: &[String]) -> Result<Response> {
    // Headers of a fetched or cached response are immutable: copy them.
    let h = resp.headers().clone();
    edge::cors(&h, origin, listed).map_err(|e| worker::Error::RustError(e.message))?;
    h.set("Access-Control-Expose-Headers", CORS_EXPOSE_HEADERS)?;
    no_transform(&h)?;
    let (builder, body) = resp.into_parts();
    Ok(builder.with_headers(h).body(body))
}

/// A response with an `ETag` says `no-transform`, so that no cache or CDN
/// re-encodes the bytes the tag names (and their `Repr-Digest`).
fn no_transform(h: &Headers) -> Result<()> {
    if h.get("ETag")?.is_none() {
        return Ok(());
    }
    match h.get("Cache-Control")? {
        Some(cc) if cc.split(',').any(|d| d.trim().eq_ignore_ascii_case("no-transform")) => {}
        Some(cc) if !cc.trim().is_empty() => h.set("Cache-Control", &format!("{cc}, no-transform"))?,
        _ => h.set("Cache-Control", "no-transform")?,
    }
    Ok(())
}

/// A preflight. `/edge-grants` is allowed only for credentialed origins
/// (§C.5.4); elsewhere every origin is. With credentialed origins the answer
/// varies by origin, so only browsers keep it.
fn preflight(path: &str, origin: Option<&str>, listed: &[String]) -> Result<Response> {
    let h = Headers::new();
    let named = origin.is_some_and(|o| listed.iter().any(|l| l == o));
    if path != "/edge-grants" || named {
        edge::cors(&h, origin, listed).map_err(|e| worker::Error::RustError(e.message))?;
        h.set("Access-Control-Allow-Methods", CORS_METHODS)?;
        h.set("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS)?;
        h.set("Access-Control-Max-Age", "86400")?;
    }
    if listed.is_empty() {
        h.set("Cache-Control", "public, max-age=86400")?;
    } else {
        h.set("Cache-Control", "private, max-age=86400")?;
        h.set("CDN-Cache-Control", "no-store")?;
    }
    Ok(ResponseBuilder::new()
        .with_status(204)
        .with_headers(h)
        .empty())
}

async fn front(req: Request, env: Env, ctx: Context) -> std::result::Result<Response, Err> {
    let path = req.path();
    if path == "/" {
        if req.method() != Method::Get && req.method() != Method::Head {
            return Err(Err::new(405, "bad_input", "method not allowed"));
        }
        // The canonical origin (§C.3): ORIGIN if the deployment sets it, else the request's.
        let origin = match env.var("ORIGIN") {
            Ok(v) => v.to_string(),
            Err(_) => req.url()?.origin().ascii_serialization(),
        };
        let h = Headers::new();
        http::cache_headers(&h, http::Class::Short, true)?;
        let grants = auth::enabled(&env);
        let mut body = vec![
            ("origin", http::s(origin)),
            ("spec", http::s("0.74")),
            ("auth", http::s(if grants { "grants" } else { "disabled" })),
        ];
        if grants {
            body.push(("jwks_uri", http::s(auth::JWKS_PATH)));
        }
        return http::json(200, h, &http::obj(body));
    }
    if path == "/edge-grants" {
        return edge_grants(req, env).await;
    }
    // §C.4: the deployment's operator key history, as a JWK Set.
    if path == auth::JWKS_PATH {
        if req.method() != Method::Get && req.method() != Method::Head {
            return Err(Err::new(405, "bad_input", "method not allowed"));
        }
        let h = Headers::new();
        h.set("Content-Type", "application/jwk-set+json")?;
        h.set("Cache-Control", "public, max-age=300")?;
        let set = auth::operator_jwks(&env)?;
        return http::respond(200, h, patchlog_core::json::canonical(&set));
    }
    // §7: empty, `.` and `..` segments, a trailing `/` and percent-escapes are 400.
    if path.contains('%') || path.ends_with('/') || path.contains("//") {
        return Err(Err::bad("non-canonical URL"));
    }
    let segs: Vec<&str> = path[1..].split('/').collect();
    if segs.iter().any(|s| *s == "." || *s == "..") {
        return Err(Err::bad("non-canonical URL"));
    }
    let ns = match segs.as_slice() {
        ["r", ns, name, ..] => {
            if !is_namespace_name(ns) || !is_resource_name(name) {
                return Err(Err::bad("malformed name"));
            }
            *ns
        }
        ["ns", ns, ..] => {
            if !is_namespace_name(ns) {
                return Err(Err::bad("malformed name"));
            }
            *ns
        }
        _ => return Err(Err::not_found()),
    };
    let url = req.url()?;
    // Revisions and blobs are immutable; a range read of a blob goes to the
    // object, which reads that range from R2.
    let cacheable = req.method() == Method::Get
        && (segs.contains(&"rev") || (segs.len() == 5 && segs[3] == "blob"))
        && !segs.ends_with(&["raw"])
        && req.headers().get("Range")?.is_none();
    let cache = Cache::default();
    if cacheable {
        // A deployment without a cache (plain workerd) just misses.
        if let Ok(Some(hit)) = cache.get(url.as_str(), false).await {
            // The Cache API matches by URL alone; answer conditionals here (§7.1).
            let inm = req.headers().get("If-None-Match")?;
            let etag = hit.headers().get("ETag")?;
            if let (Some(inm), Some(etag)) = (inm, etag) {
                if inm.split(',').any(|t| t.trim() == etag || t.trim() == "*") {
                    let h = Headers::new();
                    for k in [
                        "ETag",
                        "Cache-Control",
                        "X-Revision",
                        "Last-Modified",
                        "Cache-Tag",
                    ] {
                        if let Some(v) = hit.headers().get(k)? {
                            h.set(k, &v)?;
                        }
                    }
                    return http::respond(304, h, vec![]);
                }
            }
            return Ok(hit);
        }
    }
    let stub = env.durable_object("NAMESPACE")?.get_by_name(ns)?;
    if req.method() == Method::Get
        && (segs.as_slice() == ["ns", ns, "log"]
            || (segs.len() == 4 && segs[0] == "r" && segs[3] == "log"))
        && url
            .query_pairs()
            .any(|(k, v)| k == "live" && v == "long-poll")
    {
        return long_poll(&stub, &url, req.headers()).await;
    }
    let mut resp = stub.fetch_with_request(req).await?;
    if cacheable && resp.status_code() == 200 {
        let cc = resp.headers().get("Cache-Control")?.unwrap_or_default();
        if cc.starts_with("public") && cc.contains("immutable") {
            let copy = resp.cloned()?;
            let key = url.to_string();
            ctx.wait_until(async move {
                let _ = Cache::default().put(key.as_str(), copy).await;
            });
        }
    }
    Ok(resp)
}

/// §7.7 long-poll. The wait is held here, where it costs nothing while
/// nothing happens, not in the namespace's Durable Object: the object answers
/// at once if it can, and otherwise accepts a hibernatable WebSocket, which
/// lets it sleep until a write, when it sends the answer down the socket. At
/// the interval's end this Worker answers `204` itself.
async fn long_poll(stub: &Stub, url: &Url, from: &Headers) -> std::result::Result<Response, Err> {
    let h = Headers::new();
    h.set("Upgrade", "websocket")?;
    // The object authorises the poll (§7, §C.5): pass on what it reads.
    for k in ["Authorization", "Cookie", "X-Author"] {
        if let Some(v) = from.get(k)? {
            h.set(k, &v)?;
        }
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Get).with_headers(h);
    let resp = stub
        .fetch_with_request(Request::new_with_init(url.as_str(), &init)?)
        .await?;
    if resp.status_code() != 101 {
        return Ok(resp); // answered at once, or an error
    }
    let ws = resp
        .websocket()
        .ok_or_else(|| Err::new(500, "internal", "no WebSocket in a 101"))?;
    ws.accept()?;
    let mut events = ws.events()?;
    let mut armed: Option<Armed> = None;
    loop {
        let wait = match &armed {
            // Until the object says how long to wait, a short guard.
            None => 10_000,
            Some(a) => (a.deadline - Date::now().as_millis() as i64).max(0) as u64,
        };
        let next = Box::pin(events.next());
        let timeout = Box::pin(Delay::from(std::time::Duration::from_millis(wait)));
        match futures_util::future::select(next, timeout).await {
            futures_util::future::Either::Left((Some(Ok(WebsocketEvent::Message(m))), _)) => {
                let text = m.text().unwrap_or_default();
                if armed.is_none() {
                    armed = Some(Armed::parse(&text)?);
                    continue;
                }
                let _ = ws.close(Some(1000), Some("done"));
                return answer_from(&text);
            }
            // Closed without an answer (the object restarted), or timed out.
            _ => {
                let _ = ws.close(Some(1000), Some("interval over"));
                return match armed {
                    Some(a) => a.empty(),
                    None => Err(Err::new(502, "internal", "the namespace didn't answer")),
                };
            }
        }
    }
}

/// What the Durable Object sends when a long-poll starts waiting.
struct Armed {
    deadline: i64,
    cursor: i64,
    public: bool,
    since: String,
    ns_tag: String,
    /// The resource whose log is followed, if not the namespace log.
    resource: Option<String>,
}

impl Armed {
    fn parse(text: &str) -> std::result::Result<Armed, Err> {
        let v = patchlog_core::json::parse(text.as_bytes())
            .map_err(|e| Err::new(500, "internal", e.to_string()))?;
        let num = |k: &str| match v.get(k) {
            Some(patchlog_core::Value::Number(n)) => *n as i64,
            _ => 0,
        };
        Ok(Armed {
            deadline: num("deadline"),
            cursor: num("cursor"),
            public: matches!(v.get("public"), Some(patchlog_core::Value::Bool(true))),
            since: v
                .get("since")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string(),
            ns_tag: v
                .get("ns")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string(),
            resource: v.get("resource").and_then(|s| s.as_str()).map(String::from),
        })
    }

    /// The timeout answer of §7.7: `204`, the cursor the greater of the
    /// current interval and the request's plus one.
    fn empty(&self) -> std::result::Result<Response, Err> {
        let now = (Date::now().as_millis() as i64).div_euclid(http::LONG_POLL_INTERVAL_MS);
        let h = Headers::new();
        http::cache_headers(&h, http::Class::LongPollEmpty, self.public)?;
        http::tags(&h, &self.ns_tag, self.resource.as_deref())?;
        if !self.since.is_empty() {
            let header = if self.resource.is_some() {
                "X-Revision"
            } else {
                "X-Namespace-Revision"
            };
            h.set(header, &self.since)?;
        }
        h.set("X-Cursor", &now.max(self.cursor + 1).to_string())?;
        http::respond(204, h, vec![])
    }
}

/// An answer the Durable Object sent: status and headers as JSON, a newline, the body.
fn answer_from(text: &str) -> std::result::Result<Response, Err> {
    let (head, body) = text.split_once('\n').unwrap_or((text, ""));
    let v = patchlog_core::json::parse(head.as_bytes())
        .map_err(|e| Err::new(500, "internal", e.to_string()))?;
    let status = match v.get("status") {
        Some(patchlog_core::Value::Number(n)) => *n as u16,
        _ => 500,
    };
    let h = Headers::new();
    for pair in v
        .get("headers")
        .and_then(|a| a.as_array())
        .into_iter()
        .flatten()
    {
        if let Some([k, val]) = pair.as_array().map(|a| a.as_slice()) {
            if let (Some(k), Some(val)) = (k.as_str(), val.as_str()) {
                h.set(k, val)?;
            }
        }
    }
    http::respond(status, h, body.as_bytes().to_vec())
}

/// `POST /edge-grants` (§C.5.2) and `DELETE /edge-grants` (§C.5.4).
async fn edge_grants(mut req: Request, env: Env) -> std::result::Result<Response, Err> {
    let listed = edge::credentialed_origins(&env);
    let credentialed = !listed.is_empty();
    let url = req.url()?;
    if req.method() == Method::Delete {
        // Needs no grant, and answers the same with authentication off.
        let prefixes: Vec<String> = url
            .query_pairs()
            .map(|(k, v)| {
                if k != "prefix" {
                    return Err(Err::bad(format!("unknown query parameter {k:?} (§7)")));
                }
                if !edge::is_edge_prefix(&v) {
                    return Err(Err::bad(format!("{v} isn't an edge prefix")));
                }
                Ok(v.to_string())
            })
            .collect::<std::result::Result<_, _>>()?;
        if prefixes.is_empty() {
            return Err(Err::bad("DELETE /edge-grants takes prefix"));
        }
        let h = Headers::new();
        http::cache_headers(&h, http::Class::NoStore, false)?;
        let mut seen = std::collections::BTreeSet::new();
        for p in prefixes {
            if seen.insert(p.clone()) {
                let name = edge::cookie_name(&p);
                h.append(
                    "Set-Cookie",
                    &edge::set_cookie(&name, "", &p, 0, credentialed),
                )?;
            }
        }
        return http::respond(204, h, vec![]);
    }
    if req.method() != Method::Post {
        return Err(Err::new(405, "bad_input", "method not allowed"));
    }
    // Not offered with authentication off, or without a key to sign with.
    if !auth::enabled(&env) || edge::edge_keys(&env).is_empty() {
        return Err(edge::not_offered());
    }
    if url.query().is_some_and(|q| !q.is_empty()) {
        return Err(Err::bad("POST /edge-grants takes no query parameters (§7)"));
    }
    // The grants: one in Authorization, or several in the body.
    let bearer = auth::bearer(req.headers())?;
    let has_body = req
        .headers()
        .get("Content-Length")?
        .is_some_and(|l| l != "0")
        || req.headers().get("Content-Type")?.is_some();
    if bearer.is_some() && has_body {
        return Err(Err::bad("a body together with Authorization"));
    }
    let tokens: Vec<String> = match bearer {
        Some(t) => vec![t],
        None if !has_body => {
            return Err(auth::unauthorized(
                "send a grant in Authorization or the body",
            ))
        }
        None => {
            http::content_type_is(req.headers(), "application/json")?;
            let raw = req.bytes().await?;
            if raw.len() as u64 > edge::MAX_GRANTS as u64 * (auth::GRANT_SIZE * 2 + 64) {
                return Err(Err::bad("the body is larger than 50 grants can be"));
            }
            let v = patchlog_core::json::parse(&raw).map_err(|e| Err::bad(e.to_string()))?;
            let list = v
                .get("grants")
                .and_then(|g| g.as_array())
                .filter(|a| !a.is_empty() && a.len() <= edge::MAX_GRANTS)
                .ok_or_else(|| Err::bad("grants is an array of 1 to 50 grants"))?;
            list.iter()
                .map(|g| {
                    g.as_str()
                        .map(String::from)
                        .ok_or_else(|| Err::bad("grants are strings"))
                })
                .collect::<std::result::Result<_, _>>()?
        }
    };
    // Each grant, in every namespace all its blocks carrying ns name.
    let mut checks = Vec::new();
    for t in &tokens {
        let u = patchlog_core::grant::decode(t, auth::GRANT_SIZE, auth::RULES_PER_GRANT).map_err(
            |e| match e.status() {
                413 => Err::new(413, "limit", e.to_string()),
                _ => auth::unauthorized(e.to_string()),
            },
        )?;
        let names = |b: &patchlog_core::Value| -> Vec<String> {
            b.get("ns")
                .and_then(|n| n.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut nss = names(u.root());
        for b in u.narrowing() {
            if b.get("ns").is_some() {
                let keep = names(b);
                nss.retain(|n| keep.contains(n) || keep.iter().any(|k| k == "*"));
            }
        }
        if nss.iter().any(|n| n == "*") {
            return Err(auth::unauthorized(
                "an operator grant doesn't read namespaces",
            ));
        }
        for ns in nss {
            checks.push((t.clone(), ns));
        }
    }
    // All or nothing (§C.5.2): 401 before 403 before anything else.
    let mut answers = Vec::new();
    let mut worst: Option<Err> = None;
    for (t, ns) in &checks {
        let stub = env.durable_object("NAMESPACE")?.get_by_name(ns)?;
        let h = Headers::new();
        h.set("Authorization", &format!("Bearer {t}"))?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post).with_headers(h);
        let mut r = stub
            .fetch_with_request(Request::new_with_init(
                &format!("https://namespace/internal/{ns}/edge-check"),
                &init,
            )?)
            .await?;
        let status = r.status_code();
        let v = patchlog_core::json::parse(&r.bytes().await?)
            .map_err(|e| Err::new(500, "internal", e.to_string()))?;
        if status == 200 {
            answers.push(v);
            continue;
        }
        let rank = |s: u16| match s {
            401 => 0,
            403 => 1,
            _ => 2,
        };
        if worst.as_ref().is_none_or(|w| rank(status) < rank(w.status)) {
            let code = match status {
                401 => "unauthorized",
                403 => "forbidden",
                413 => "limit",
                _ => "internal",
            };
            let msg = v
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("refused")
                .to_string();
            worst = Some(
                Err::new(status, code, format!("{ns}: {msg}")).with("ns", http::s(ns.clone())),
            );
        }
    }
    if let Some(e) = worst {
        return Err(e);
    }
    let keys = edge::edge_keys(&env);
    let Some(key) = keys.last() else {
        return Err(edge::not_offered());
    };
    let now_s = Date::now().as_millis() as i64 / 1000;
    // Each prefix once, lasting as long as the longest of its grants.
    let mut prefixes: std::collections::BTreeMap<String, i64> = Default::default();
    let mut earliest = i64::MAX;
    for a in &answers {
        let exp_ms = match a.get("exp") {
            Some(patchlog_core::Value::Number(n)) => *n as i64,
            _ => 0,
        };
        let exp_s = (exp_ms / 1000).min(now_s + edge::MAX_LIFETIME_S);
        earliest = earliest.min(exp_s);
        for p in a
            .get("prefixes")
            .and_then(|p| p.as_array())
            .into_iter()
            .flatten()
        {
            if let Some(p) = p.as_str() {
                let e = prefixes.entry(p.to_string()).or_insert(0);
                *e = (*e).max(exp_s);
            }
        }
    }
    if prefixes.len() > edge::MAX_PREFIXES {
        return Err(Err::bad("more than 100 distinct prefixes"));
    }
    let h = Headers::new();
    http::cache_headers(&h, http::Class::NoStore, false)?;
    for (p, exp_s) in &prefixes {
        let value = edge::cookie_value(key, p, *exp_s);
        h.append(
            "Set-Cookie",
            &edge::set_cookie(&edge::cookie_name(p), &value, p, *exp_s, credentialed),
        )?;
    }
    let body = http::obj(vec![
        (
            "prefixes",
            patchlog_core::Value::Array(prefixes.keys().map(|p| http::s(p.clone())).collect()),
        ),
        (
            "exp",
            http::s(patchlog_core::fmt::rfc3339_ms(earliest * 1000)),
        ),
    ]);
    http::json(200, h, &body)
}
