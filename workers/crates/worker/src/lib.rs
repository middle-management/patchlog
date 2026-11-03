//! patchlog on Cloudflare Workers.
//!
//! The front Worker answers `GET /`, refuses malformed URLs (§7), serves
//! immutable responses from the Cache API, and forwards everything else to
//! the namespace's Durable Object (`ns.rs`), addressed by the namespace name.

mod http;
mod ns;

use futures_util::StreamExt;
use http::Err;
use patchlog_core::names::{is_namespace_name, is_resource_name};
use worker::*;

pub use ns::Namespace;

#[event(fetch)]
async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
    match front(req, env, ctx).await {
        Ok(r) => Ok(r),
        Err(e) => e.into_response(false),
    }
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
        let body = http::obj(vec![
            ("origin", http::s(origin)),
            ("spec", http::s("0.74")),
            ("auth", http::s("disabled")),
        ]);
        return http::json(200, h, &body);
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
    let cacheable = req.method() == Method::Get && segs.contains(&"rev");
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
        && segs.as_slice() == ["ns", ns, "log"]
        && url
            .query_pairs()
            .any(|(k, v)| k == "live" && v == "long-poll")
    {
        return long_poll(&stub, &url).await;
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
async fn long_poll(stub: &Stub, url: &Url) -> std::result::Result<Response, Err> {
    let h = Headers::new();
    h.set("Upgrade", "websocket")?;
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
        })
    }

    /// The timeout answer of §7.7: `204`, the cursor the greater of the
    /// current interval and the request's plus one.
    fn empty(&self) -> std::result::Result<Response, Err> {
        let now = (Date::now().as_millis() as i64).div_euclid(http::LONG_POLL_INTERVAL_MS);
        let h = Headers::new();
        http::cache_headers(&h, http::Class::LongPollEmpty, self.public)?;
        http::tags(&h, &self.ns_tag, None)?;
        if !self.since.is_empty() {
            h.set("X-Namespace-Revision", &self.since)?;
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
