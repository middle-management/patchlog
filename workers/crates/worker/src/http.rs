//! Response helpers: error bodies (§12.1), cache classes (§9), preconditions (§7).

use patchlog_core::json::{canonical, Value};
use patchlog_core::Id;
use std::collections::BTreeMap;
use worker::{Headers, Response, ResponseBuilder, Result};

/// Cache classes of §9. `public` is the namespace's `read`.
#[derive(Clone, Copy, PartialEq)]
pub enum Class {
    HeadPointer,
    Immutable,
    Short,
    LongPollOk,
    LongPollEmpty,
    NoStore,
}

pub const LONG_POLL_INTERVAL_MS: i64 = 20_000;

pub fn cache_headers(h: &Headers, class: Class, public: bool) -> Result<()> {
    let (cc, private_max) = match class {
        Class::HeadPointer => ("public, max-age=0, s-maxage=1, stale-while-revalidate=5", 0),
        Class::Immutable => ("public, max-age=86400, s-maxage=31536000, immutable", 86400),
        Class::Short => ("public, max-age=5", 5),
        Class::LongPollOk => ("public, max-age=0, s-maxage=20", 0),
        Class::LongPollEmpty => ("public, max-age=0, s-maxage=2", 0),
        Class::NoStore => {
            h.set("Cache-Control", "no-store")?;
            return Ok(());
        }
    };
    if public {
        h.set("Cache-Control", cc)?;
    } else {
        // §9: private responses are no-store at every CDN, unless the front
        // Worker finds the read verified by an edge (edge.rs), which takes
        // its edge lifetime from the class noted here.
        h.set("Cache-Control", &format!("private, max-age={private_max}"))?;
        h.set("CDN-Cache-Control", "no-store")?;
        h.set("Surrogate-Control", "no-store")?;
        h.set(CLASS_HEADER, class.name())?;
    }
    Ok(())
}

/// The cache class of a private response, from the namespace's object to
/// the front Worker, which removes it.
pub const CLASS_HEADER: &str = "X-Patchlog-Class";

impl Class {
    pub fn name(self) -> &'static str {
        match self {
            Class::HeadPointer => "head",
            Class::Immutable => "immutable",
            Class::Short => "short",
            Class::LongPollOk => "long-poll",
            Class::LongPollEmpty => "long-poll-empty",
            Class::NoStore => "no-store",
        }
    }

    /// The edge lifetime of the class, for `CDN-Cache-Control`: the public
    /// class's shared-cache values (§9).
    pub fn edge_lifetime(name: &str) -> Option<&'static str> {
        Some(match name {
            "head" => "max-age=1, stale-while-revalidate=5",
            "immutable" => "max-age=31536000, immutable",
            "short" => "max-age=5",
            "long-poll" => "max-age=20",
            "long-poll-empty" => "max-age=2",
            _ => return None,
        })
    }
}

pub fn tags(h: &Headers, ns: &str, resource: Option<&str>) -> Result<()> {
    let mut t = vec![format!("ns:{ns}")];
    if let Some(r) = resource {
        t.push(format!("r:{ns}/{r}"));
    }
    h.set("Cache-Tag", &t.join(","))?;
    h.set("Surrogate-Key", &t.join(" "))?;
    Ok(())
}

pub fn respond(status: u16, h: Headers, body: Vec<u8>) -> Res<Response> {
    Ok(ResponseBuilder::new()
        .with_status(status)
        .with_headers(h)
        .fixed(body))
}

pub fn json(status: u16, h: Headers, body: &Value) -> Res<Response> {
    h.set("Content-Type", "application/json")?;
    respond(status, h, canonical(body))
}

pub fn obj(members: Vec<(&str, Value)>) -> Value {
    Value::Object(
        members
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect::<BTreeMap<_, _>>(),
    )
}

pub fn s(v: impl Into<String>) -> Value {
    Value::String(v.into())
}

/// An error answer: `{ code, message, …extra }`, `no-store` unless `h` says otherwise.
pub struct Err {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
    pub extra: Vec<(&'static str, Value)>,
    pub class: Class,
    pub retry_after: Option<u32>,
}

impl Err {
    pub fn new(status: u16, code: &'static str, message: impl Into<String>) -> Err {
        Err {
            status,
            code,
            message: message.into(),
            extra: vec![],
            class: Class::NoStore,
            retry_after: None,
        }
    }
    pub fn with(mut self, k: &'static str, v: Value) -> Err {
        self.extra.push((k, v));
        self
    }
    pub fn class(mut self, c: Class) -> Err {
        self.class = c;
        self
    }
    pub fn bad(m: impl Into<String>) -> Err {
        Err::new(400, "bad_input", m)
    }
    pub fn not_found() -> Err {
        Err::new(404, "not_found", "not found").class(Class::Short)
    }
    pub fn not_offered(m: impl Into<String>) -> Err {
        Err::new(404, "not_offered", m).class(Class::Short)
    }
    pub fn into_response(self, public: bool) -> Result<Response> {
        let h = Headers::new();
        cache_headers(&h, self.class, public)?;
        if let Some(s) = self.retry_after {
            h.set("Retry-After", &s.to_string())?;
        }
        let mut members = vec![("code", s(self.code)), ("message", s(self.message))];
        members.extend(self.extra);
        json(self.status, h, &obj(members)).map_err(|e| worker::Error::RustError(e.message))
    }
}

impl From<worker::Error> for Err {
    fn from(e: worker::Error) -> Self {
        storage_err(e.to_string())
    }
}

/// A storage failure: `503` with `Retry-After` when the platform refuses
/// writes over a quota (such as the free tier's daily rows written), `500`
/// otherwise.
pub fn storage_err(message: String) -> Err {
    if message.contains("Exceeded allowed") {
        let mut e = Err::new(503, "unavailable", message);
        e.retry_after = Some(3600);
        e
    } else {
        Err::new(500, "internal", message)
    }
}

pub type Res<T> = std::result::Result<T, Err>;

/// A quoted strong entity tag holding a text id (§7).
pub fn etag_id(v: &str) -> Res<Id> {
    v.strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .and_then(Id::parse)
        .ok_or_else(|| Err::bad(format!("{v:?} isn't a quoted strong tag holding an id")))
}

pub fn quoted(id: &Id) -> String {
    format!("\"{id}\"")
}

pub enum Precondition {
    Match(Id),
    NoneMatchStar,
}

/// §7.2: exactly one of `If-Match: "{id}"` and `If-None-Match: *`.
pub fn precondition(h: &Headers) -> Res<Precondition> {
    let im = h.get("If-Match")?;
    let inm = h.get("If-None-Match")?;
    match (im, inm) {
        (Some(_), Some(_)) => Err(Err::bad("If-Match and If-None-Match together")),
        (Some(v), None) => Ok(Precondition::Match(etag_id(v.trim())?)),
        (None, Some(v)) if v.trim() == "*" => Ok(Precondition::NoneMatchStar),
        (None, Some(_)) => Err(Err::bad("a write's If-None-Match is *")),
        (None, None) => Err(Err::new(
            428,
            "precondition_required",
            "writes need If-Match or If-None-Match: *",
        )),
    }
}

/// §7.2: `Content-Type` compared as a media type, `charset=utf-8` allowed.
pub fn content_type_is(h: &Headers, want: &str) -> Res<()> {
    let ct = h.get("Content-Type")?.unwrap_or_default();
    let mut parts = ct.split(';');
    let ok = parts
        .next()
        .map(|t| t.trim().eq_ignore_ascii_case(want))
        .unwrap_or(false)
        && parts.all(|p| {
            let p = p.trim().to_ascii_lowercase().replace(' ', "");
            p == "charset=utf-8" || p == "charset=\"utf-8\""
        });
    if ok {
        Ok(())
    } else {
        Err(Err::new(
            415,
            "unsupported_type",
            format!("Content-Type must be {want}"),
        ))
    }
}

/// `Gesture` and `Undoes` (§7.2).
pub fn gesture_header(h: &Headers, name: &str) -> Res<Option<String>> {
    match h.get(name)? {
        None => Ok(None),
        Some(v) if patchlog_core::names::is_base32_26(&v) => Ok(Some(v)),
        Some(_) => Err(Err::bad(format!("{name} must be 26 base32 characters"))),
    }
}

/// Query parameters: only those allowed, each at most once (§7).
pub fn query(url: &worker::Url, allowed: &[&str]) -> Res<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for (k, v) in url.query_pairs() {
        if !allowed.contains(&k.as_ref()) {
            return Err(Err::bad(format!("unknown query parameter {k:?}")));
        }
        if out.insert(k.to_string(), v.to_string()).is_some() {
            return Err(Err::bad(format!("repeated query parameter {k:?}")));
        }
    }
    Ok(out)
}

/// SHA-256 by WebCrypto: native code, several times faster than hashing in wasm.
pub async fn sha256(bytes: &[u8]) -> Res<Vec<u8>> {
    use worker::js_sys::{global, Function, Promise, Reflect, Uint8Array};
    use worker::wasm_bindgen::{JsCast, JsValue};
    let fail = |_| Err::new(500, "internal", "WebCrypto unavailable");
    let crypto = Reflect::get(&global(), &JsValue::from_str("crypto")).map_err(fail)?;
    let subtle = Reflect::get(&crypto, &JsValue::from_str("subtle")).map_err(fail)?;
    let digest: Function = Reflect::get(&subtle, &JsValue::from_str("digest"))
        .map_err(fail)?
        .dyn_into()
        .map_err(fail)?;
    let p: Promise = digest
        .call2(
            &subtle,
            &JsValue::from_str("SHA-256"),
            &Uint8Array::from(bytes),
        )
        .map_err(fail)?
        .dyn_into()
        .map_err(fail)?;
    let ab = worker::wasm_bindgen_futures::JsFuture::from(p)
        .await
        .map_err(fail)?;
    Ok(Uint8Array::new(&ab).to_vec())
}
