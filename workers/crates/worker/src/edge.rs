//! Edge grants (§C.5.2–§C.5.4): cookies that let a browser read a private
//! namespace, minted by `POST /edge-grants` in exchange for grants, and the
//! credentialed CORS that page needs (§7, browsers).
//!
//! Settings: `CREDENTIALED_ORIGINS`, a JSON array of origins whose pages may
//! send cookies; `EDGE_KEYS`, a secret JSON array `[{ "kid", "key" }]` of
//! HMAC-SHA256 keys in hex, newest last, which mints. Older keys still verify
//! until their cookies expire (§C.5.3 Keys).

use patchlog_core::json::{self, canonical, Value};
use sha2::{Digest, Sha256};
use worker::{Env, Headers};

use crate::auth::base64url;
use crate::http::{obj, s, Err, Res};

/// Longest a cookie lives (§C.5.2 Answer).
pub const MAX_LIFETIME_S: i64 = 15 * 60;
pub const MAX_GRANTS: usize = 50;
pub const MAX_PREFIXES: usize = 100;

pub fn credentialed_origins(env: &Env) -> Vec<String> {
    env.var("CREDENTIALED_ORIGINS")
        .ok()
        .and_then(|v| json::parse(v.to_string().as_bytes()).ok())
        .and_then(|v| {
            v.as_array().map(|a| {
                a.iter()
                    .filter_map(|o| o.as_str().map(String::from))
                    .collect()
            })
        })
        .unwrap_or_default()
}

pub struct EdgeKey {
    pub kid: String,
    pub key: Vec<u8>,
}

pub fn edge_keys(env: &Env) -> Vec<EdgeKey> {
    let Some(v) = env
        .secret("EDGE_KEYS")
        .ok()
        .and_then(|v| json::parse(v.to_string().as_bytes()).ok())
    else {
        return vec![];
    };
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|k| {
            Some(EdgeKey {
                kid: k.get("kid")?.as_str()?.to_string(),
                key: hex(k.get("key")?.as_str()?)?,
            })
        })
        .collect()
}

fn hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let pad = |b: u8| k.map(|x| x ^ b);
    let inner = Sha256::new()
        .chain_update(pad(0x36))
        .chain_update(msg)
        .finalize();
    Sha256::new()
        .chain_update(pad(0x5c))
        .chain_update(inner)
        .finalize()
        .into()
}

/// `__Secure-pl-eg-` and the first 8 bytes of `sha256(prefix)` in hex.
pub fn cookie_name(prefix: &str) -> String {
    let d = Sha256::digest(prefix.as_bytes());
    let hex: String = d[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("__Secure-pl-eg-{hex}")
}

/// `base64url(c) "." base64url(HMAC-SHA256(key, base64url(c)))`.
pub fn cookie_value(k: &EdgeKey, prefix: &str, exp_s: i64) -> String {
    let c = obj(vec![
        ("exp", Value::Number(exp_s as f64)),
        ("kid", s(k.kid.clone())),
        ("p", s(prefix)),
    ]);
    let body = base64url(&canonical(&c));
    let mac = base64url(&hmac(&k.key, body.as_bytes()));
    format!("{body}.{mac}")
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    patchlog_core::grant::base64url_decode(s)
}

/// Checks one cookie (§C.5.3): its name derives from its own `p`, `c` is
/// exactly `{ exp, kid, p }` in canonical form, the MAC is over the value as
/// received, `exp` is in the future and `p` covers `path` segment by segment.
pub fn verify(
    name: &str,
    value: &str,
    path: &str,
    keys: &[EdgeKey],
    now_ms: i64,
) -> Option<(String, i64)> {
    let (body, mac) = value.split_once('.')?;
    let raw = b64url_decode(body)?;
    let c = json::parse(&raw).ok()?;
    let m = c.as_object()?;
    if m.len() != 3 || canonical(&c) != raw {
        return None;
    }
    let p = m.get("p")?.as_str()?;
    let kid = m.get("kid")?.as_str()?;
    let exp = match m.get("exp")? {
        Value::Number(n) if n.fract() == 0.0 => *n as i64,
        _ => return None,
    };
    if cookie_name(p) != name || exp * 1000 <= now_ms || !covers(p, path) || !is_edge_prefix(p) {
        return None;
    }
    let key = keys.iter().find(|k| k.kid == kid)?;
    let want = hmac(&key.key, body.as_bytes());
    let got = b64url_decode(mac)?;
    // Constant-time comparison.
    if got.len() != 32
        || got
            .iter()
            .zip(want.iter())
            .fold(0u8, |a, (x, y)| a | (x ^ y))
            != 0
    {
        return None;
    }
    Some((p.to_string(), exp))
}

/// The first edge-grant cookie in `Cookie` that verifies for `path`.
pub fn from_cookies(
    cookie: &str,
    path: &str,
    keys: &[EdgeKey],
    now_ms: i64,
) -> Option<(String, i64)> {
    cookie
        .split(';')
        .filter_map(|c| c.trim().split_once('='))
        .filter(|(n, _)| n.starts_with("__Secure-pl-eg-"))
        .find_map(|(n, v)| verify(n, v, path, keys, now_ms))
}

/// The path is `p` or starts with `p/` (§2.1 covers).
pub fn covers(p: &str, path: &str) -> bool {
    path == p || path.strip_prefix(p).is_some_and(|r| r.starts_with('/'))
}

/// `/r/{ns}/{name}`, `/r/{ns}` or `/ns/{ns}` with valid names (§2.1).
pub fn is_edge_prefix(p: &str) -> bool {
    use patchlog_core::names::{is_namespace_name, is_resource_name};
    let segs: Vec<&str> = p.split('/').collect();
    match segs.as_slice() {
        ["", "r", ns] | ["", "ns", ns] => is_namespace_name(ns),
        ["", "r", ns, name] => is_namespace_name(ns) && is_resource_name(name),
        _ => false,
    }
}

/// `Set-Cookie` for a prefix, until `exp_s` (or expired, to withdraw it).
pub fn set_cookie(name: &str, value: &str, prefix: &str, exp_s: i64, credentialed: bool) -> String {
    let max_age = (exp_s - worker::Date::now().as_millis() as i64 / 1000).max(0);
    format!(
        "{name}={value}; Path={prefix}; Max-Age={max_age}; Secure; HttpOnly; SameSite={}",
        if credentialed { "None" } else { "Lax" }
    )
}

/// CORS for a response (§7, browsers): a listed origin is named, with
/// credentials allowed; any other gets `*`. With a list, answers vary by
/// origin.
pub fn cors(h: &Headers, origin: Option<&str>, listed: &[String]) -> Res<()> {
    match origin.filter(|o| listed.iter().any(|l| l == o)) {
        Some(o) => {
            h.set("Access-Control-Allow-Origin", o)?;
            h.set("Access-Control-Allow-Credentials", "true")?;
        }
        None => h.set("Access-Control-Allow-Origin", "*")?,
    }
    if !listed.is_empty() {
        h.append("Vary", "Origin")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Addendum I.5.
    const VALUE: &str = "eyJleHAiOjE3OTAwMDA5MDAsImtpZCI6Im9yaWdpbiIsInAiOiIvci9kZW1vL2RlcmJ5In0.qn5oOZCcn6Au_LourbFpV2VbJ3u-XeiQlwNKAj43Lhw";

    fn key() -> Vec<EdgeKey> {
        vec![EdgeKey {
            kid: "origin".into(),
            key: hex("3dba7ab1a5240f2d1e3f4922b87f24be07b3e95885e0f515c57d6ac5c13dd708").unwrap(),
        }]
    }

    #[test]
    fn i5_cookie() {
        let p = "/r/demo/derby";
        assert_eq!(cookie_name(p), "__Secure-pl-eg-4390e78526d94754");
        assert_eq!(cookie_value(&key()[0], p, 1790000900), VALUE);
        let before = 1790000900 * 1000 - 1;
        let name = cookie_name(p);
        assert!(verify(&name, VALUE, "/r/demo/derby/rev/x", &key(), before).is_some());
        // Expired; a path only string-prefixed; a name for another prefix.
        assert!(verify(&name, VALUE, "/r/demo/derby", &key(), 1790000900 * 1000).is_none());
        assert!(verify(&name, VALUE, "/r/demo/derbyx", &key(), before).is_none());
        assert!(verify(
            &cookie_name("/r/demo"),
            VALUE,
            "/r/demo/derby",
            &key(),
            before
        )
        .is_none());
        // Claims reordered, or with a fourth member, are ignored.
        let k = &key()[0];
        for c in [
            r#"{"kid":"origin","exp":1790000900,"p":"/r/demo/derby"}"#,
            r#"{"exp":1790000900,"kid":"origin","p":"/r/demo/derby","x":1}"#,
        ] {
            let body = base64url(c.as_bytes());
            let v = format!("{body}.{}", base64url(&hmac(&k.key, body.as_bytes())));
            assert!(verify(&name, &v, "/r/demo/derby", &key(), before).is_none());
        }
        assert!(covers("/r/demo", "/r/demo/x") && !covers("/r/demo", "/r/demox"));
    }
}

pub fn not_offered() -> Err {
    Err::not_offered("edge grants need authentication on and EDGE_KEYS set")
}
