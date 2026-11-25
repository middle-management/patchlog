//! Blob references (§7.8) and media types (§3.7).

use crate::json::Value;
use crate::names::is_base32_26;
use crate::schema::{typed, Typed};
use crate::Id;

/// `{ "$blob": id, "type", "size", "nonce"? }`
#[derive(Debug, Clone, PartialEq)]
pub struct BlobRef {
    pub bid: Id,
    pub media_type: String,
    pub size: u64,
    pub nonce: Option<String>,
}

/// A media type as §3.7 hashes it: `type/subtype`, lowercased, without
/// parameters; `None` if it can't be parsed.
pub fn media_type(header: &str) -> Option<String> {
    let t = header.split(';').next()?.trim().to_ascii_lowercase();
    let (a, b) = t.split_once('/')?;
    let token = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&c))
    };
    (token(a) && token(b)).then_some(t)
}

/// The members a document's root may have besides a reference and still be
/// raw, and which a root reference ignores: those step 5 of §6.2 leaves out.
const ROOT_EXTRAS: &[&str] = &["$schema", "$nonce", "$successor"];

fn parse_ref(
    m: &std::collections::BTreeMap<String, Value>,
    root: bool,
    ptr: &str,
) -> Result<BlobRef, String> {
    let bad = |why: &str| {
        Err(format!(
            "malformed blob reference at {}: {why}",
            if ptr.is_empty() { "/" } else { ptr }
        ))
    };
    for k in m.keys() {
        let ok = matches!(k.as_str(), "$blob" | "type" | "size" | "nonce")
            || (root && ROOT_EXTRAS.contains(&k.as_str()));
        if !ok {
            return bad(&format!("member {k:?} isn't allowed"));
        }
    }
    let Some(bid) = m.get("$blob").and_then(Value::as_str).and_then(Id::parse) else {
        return bad("$blob is a blob id");
    };
    let media_type = match m.get("type").and_then(Value::as_str) {
        Some(t) if media_type(t).as_deref() == Some(t) => t.to_string(),
        _ => return bad("type is a media type, type/subtype in lowercase"),
    };
    let size = match m.get("size") {
        Some(Value::Number(n)) if n.fract() == 0.0 && *n >= 0.0 => *n as u64,
        _ => return bad("size is a non-negative integer"),
    };
    let nonce = match m.get("nonce") {
        None => None,
        Some(Value::String(n)) if is_base32_26(n) => Some(n.clone()),
        Some(_) => return bad("nonce is 26 base32 characters"),
    };
    Ok(BlobRef {
        bid,
        media_type,
        size,
        nonce,
    })
}

/// Every blob reference in a document, at any depth (§6.5, §7.8); none in
/// a schema document. A malformed one is an error (`422 blob`).
pub fn refs(doc: &Value) -> Result<Vec<BlobRef>, String> {
    if typed(doc) == Ok(Typed::Schema) {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    fn walk(v: &Value, ptr: &str, root: bool, out: &mut Vec<BlobRef>) -> Result<(), String> {
        match v {
            Value::Object(m) => {
                if matches!(m.get("$blob"), Some(Value::String(_))) {
                    out.push(parse_ref(m, root, ptr)?);
                    return Ok(());
                }
                for (k, x) in m {
                    walk(
                        x,
                        &format!("{ptr}/{}", crate::patch::escape_token(k)),
                        false,
                        out,
                    )?;
                }
            }
            Value::Array(a) => {
                for (i, x) in a.iter().enumerate() {
                    walk(x, &format!("{ptr}/{i}"), false, out)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    walk(doc, "", true, &mut out)?;
    Ok(out)
}

/// A raw document's reference (§7.8 Files): its root is a reference, with no
/// other members than those validation leaves out.
pub fn raw(doc: &Value) -> Option<BlobRef> {
    let m = doc.as_object()?;
    if !matches!(m.get("$blob"), Some(Value::String(_))) {
        return None;
    }
    parse_ref(m, true, "").ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    const BID: &str = "1m5jj344d7tz7cicfmq53ayhmwuubpmyt";

    #[test]
    fn media_types() {
        assert_eq!(media_type("Image/JPEG; q=1").as_deref(), Some("image/jpeg"));
        assert_eq!(media_type("text/plain").as_deref(), Some("text/plain"));
        assert_eq!(media_type("text"), None);
        assert_eq!(media_type("/plain"), None);
        assert_eq!(media_type("te xt/plain"), None);
    }

    #[test]
    fn references() {
        let doc = parse(format!(r#"{{"hero":{{"$blob":"{BID}","type":"image/jpeg","size":12}},"list":[{{"$blob":"{BID}","type":"text/plain","size":0,"nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaa"}}]}}"#).as_bytes()).unwrap();
        let r = refs(&doc).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[1].nonce.as_deref(), Some("aaaaaaaaaaaaaaaaaaaaaaaaaa"));
        for bad in [
            format!(r#"{{"x":{{"$blob":"{BID}","type":"image/jpeg"}}}}"#),
            format!(r#"{{"x":{{"$blob":"{BID}","type":"Image/JPEG","size":1}}}}"#),
            format!(r#"{{"x":{{"$blob":"{BID}","type":"image/jpeg","size":1,"extra":1}}}}"#),
            r#"{"x":{"$blob":"nope","type":"image/jpeg","size":1}}"#.to_string(),
        ] {
            assert!(refs(&parse(bad.as_bytes()).unwrap()).is_err(), "{bad}");
        }
        // `$blob` that isn't a string isn't a reference.
        assert!(refs(&parse(br#"{"x":{"$blob":1}}"#).unwrap())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn raw_documents() {
        let doc = parse(format!(r#"{{"$blob":"{BID}","type":"font/woff2","size":3,"$nonce":"abcdefghijklmnopqrstuvwxyz"}}"#).as_bytes()).unwrap();
        assert!(raw(&doc).is_some());
        assert_eq!(refs(&doc).unwrap().len(), 1);
        let not_raw = parse(
            format!(r#"{{"$blob":"{BID}","type":"font/woff2","size":3,"title":"x"}}"#).as_bytes(),
        )
        .unwrap();
        assert!(raw(&not_raw).is_none());
    }
}
