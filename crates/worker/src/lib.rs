//! patchlog on Cloudflare Workers.
//!
//! The front Worker answers `GET /`, refuses malformed URLs (§7), serves
//! immutable responses from the Cache API, and forwards everything else to
//! the namespace's Durable Object (`ns.rs`), addressed by the namespace name.

mod http;
mod ns;

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
        let origin = env.var("ORIGIN").map(|v| v.to_string()).unwrap_or_default();
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
        if let Some(hit) = cache.get(url.as_str(), false).await? {
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
