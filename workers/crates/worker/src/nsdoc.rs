//! Shapes of namespace-document members from the addenda (§12.3), as §7.4
//! validates them: strictly, except that `x-` members may appear inside the
//! addenda's objects (but not as keys of `catalogs`, which are catalog
//! names). Each check returns the JSON Pointer and message of the first
//! problem.

use patchlog_core::json::Value;
use patchlog_core::names::{is_namespace_name, is_resource_name};
use patchlog_core::patch::{escape_token, parse_pointer};
use patchlog_core::schema::is_revision_path;
use patchlog_core::Id;

pub type Problem = (String, String);

fn bad(p: &str, m: &str) -> Result<(), Problem> {
    Err((p.to_string(), m.to_string()))
}

fn obj<'a>(
    v: &'a Value,
    p: &str,
    what: &str,
) -> Result<&'a std::collections::BTreeMap<String, Value>, Problem> {
    v.as_object()
        .ok_or_else(|| (p.to_string(), format!("{what} is an object")))
}

/// Members allowed in an object besides `x-` ones; anything else is refused.
fn only(
    m: &std::collections::BTreeMap<String, Value>,
    p: &str,
    allowed: &[&str],
    x_ok: bool,
) -> Result<(), Problem> {
    for k in m.keys() {
        if !allowed.contains(&k.as_str()) && !(x_ok && k.starts_with("x-")) {
            return bad(&format!("{p}/{}", escape_token(k)), "unknown member");
        }
    }
    Ok(())
}

fn str_array<'a>(v: &'a Value, p: &str, what: &str) -> Result<Vec<&'a str>, Problem> {
    let a = v
        .as_array()
        .ok_or_else(|| (p.to_string(), format!("{what} is an array of strings")))?;
    a.iter()
        .enumerate()
        .map(|(i, x)| {
            x.as_str()
                .ok_or_else(|| (format!("{p}/{i}"), format!("{what} holds strings")))
        })
        .collect()
}

/// An ISO 8601 duration as `retention` uses them: `P[nD][T[nH][nM][nS]]`,
/// at least one part, integers (seconds may have a fraction).
pub fn is_duration(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('P') else {
        return false;
    };
    let (date, time) = match rest.split_once('T') {
        Some((d, t)) => (d, Some(t)),
        None => (rest, None),
    };
    let mut any = false;
    let mut parts = |s: &str, units: &[char], frac_last: bool| -> bool {
        let mut num = String::new();
        let mut next = 0;
        for c in s.chars() {
            if c.is_ascii_digit() || (frac_last && c == '.' && !num.is_empty()) {
                num.push(c);
            } else if let Some(i) = units.iter().skip(next).position(|&u| u == c) {
                if num.is_empty() || (num.contains('.') && units[next + i] != 'S') {
                    return false;
                }
                next += i + 1;
                num.clear();
                any = true;
            } else {
                return false;
            }
        }
        num.is_empty()
    };
    let ok_date = parts(date, &['Y', 'M', 'W', 'D'], false);
    let ok_time = match time {
        Some(t) => !t.is_empty() && parts(t, &['H', 'M', 'S'], true),
        None => true,
    };
    ok_date && ok_time && any
}

/// `catalog` (§B.5, §B.6, §H.2): `{ trust?, mode?, title?, files? }`.
pub fn catalog(v: &Value, p: &str) -> Result<(), Problem> {
    let m = obj(v, p, "catalog")?;
    only(m, p, &["trust", "mode", "title", "files"], true)?;
    if let Some(t) = m.get("trust") {
        for (i, n) in str_array(t, &format!("{p}/trust"), "trust")?
            .into_iter()
            .enumerate()
        {
            if !is_namespace_name(n) {
                return bad(&format!("{p}/trust/{i}"), "a namespace name");
            }
        }
    }
    if let Some(mode) = m.get("mode") {
        if !matches!(mode.as_str(), Some("tree" | "dag")) {
            return bad(&format!("{p}/mode"), "mode is \"tree\" or \"dag\"");
        }
    }
    if let Some(t) = m.get("title") {
        if !t.as_str().is_some_and(|t| parse_pointer(t).is_ok()) {
            return bad(&format!("{p}/title"), "title is a JSON Pointer");
        }
    }
    if let Some(f) = m.get("files") {
        let fp = format!("{p}/files");
        let fm = obj(f, &fp, "files")?;
        only(fm, &fp, &["ns", "root", "folder", "placement"], true)?;
        match fm.get("ns").and_then(Value::as_str) {
            Some(n) if is_namespace_name(n) => {}
            _ => return bad(&format!("{fp}/ns"), "ns is a namespace name"),
        }
        match fm.get("root").and_then(Value::as_str) {
            Some(n) if is_resource_name(n) && !n.contains('.') => {}
            _ => return bad(&format!("{fp}/root"), "root is a folder node name (no dot)"),
        }
        for k in ["folder", "placement"] {
            if let Some(x) = fm.get(k) {
                if !x.as_str().is_some_and(is_revision_path) {
                    return bad(&format!("{fp}/{k}"), "a schema revision path");
                }
            }
        }
    }
    Ok(())
}

/// `catalogs` (§B.11): `{ "<catalog>": { "place"?: [subjects] } }`.
pub fn catalogs(v: &Value, p: &str) -> Result<(), Problem> {
    let m = obj(v, p, "catalogs")?;
    for (name, c) in m {
        let cp = format!("{p}/{}", escape_token(name));
        if !is_namespace_name(name) {
            return bad(&cp, "keys of catalogs are catalog namespace names");
        }
        let cm = obj(c, &cp, "a catalog entry")?;
        only(cm, &cp, &["place"], true)?;
        if let Some(pl) = cm.get("place") {
            for (i, s) in str_array(pl, &format!("{cp}/place"), "place")?
                .into_iter()
                .enumerate()
            {
                let ok = s
                    .strip_prefix("group:")
                    .or_else(|| s.strip_prefix("user:"))
                    .is_some_and(|r| !r.is_empty());
                if !ok {
                    return bad(&format!("{cp}/place/{i}"), "a subject is group:… or user:…");
                }
            }
        }
    }
    Ok(())
}

fn rate(v: &Value, p: &str) -> Result<(), Problem> {
    let m = obj(v, p, "a rate")?;
    only(m, p, &["rate", "burst"], false)?;
    for k in ["rate", "burst"] {
        match m.get(k) {
            Some(Value::Number(n)) if *n > 0.0 => {}
            _ => return bad(&format!("{p}/{k}"), "a positive number"),
        }
    }
    Ok(())
}

/// `allowances` (§6.6). Stored and checked for shape; while authentication
/// is disabled (§1) no rate limit applies, so they change nothing yet.
pub fn allowances(v: &Value, p: &str) -> Result<(), Problem> {
    let a = v
        .as_array()
        .ok_or_else(|| (p.to_string(), "allowances is an array".to_string()))?;
    for (i, e) in a.iter().enumerate() {
        let ep = format!("{p}/{i}");
        let m = obj(e, &ep, "an allowance")?;
        only(
            m,
            &ep,
            &[
                "sub",
                "kid",
                "bucket",
                "itemsPerBatch",
                "batchSize",
                "blobRate",
                "blobPending",
                "until",
            ],
            true,
        )?;
        for k in ["sub", "kid"] {
            if !m
                .get(k)
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
            {
                return bad(&format!("{ep}/{k}"), "a non-empty string");
            }
        }
        match m.get("bucket") {
            Some(b) => rate(b, &format!("{ep}/bucket"))?,
            None => return bad(&format!("{ep}/bucket"), "an allowance has a bucket"),
        }
        if let Some(b) = m.get("blobRate") {
            rate(b, &format!("{ep}/blobRate"))?;
        }
        for k in ["itemsPerBatch", "batchSize", "blobPending"] {
            if let Some(x) = m.get(k) {
                if !matches!(x, Value::Number(n) if n.fract() == 0.0 && *n >= 1.0) {
                    return bad(&format!("{ep}/{k}"), "a positive integer");
                }
            }
        }
        if let Some(u) = m.get("until") {
            if !u.as_str().is_some_and(is_rfc3339) {
                return bad(&format!("{ep}/until"), "an RFC 3339 time");
            }
        }
    }
    Ok(())
}

fn is_rfc3339(s: &str) -> bool {
    // YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)
    let b = s.as_bytes();
    if b.len() < 20 {
        return false;
    }
    let digits = |r: std::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
    let tail = &s[19..];
    let tail = tail.strip_prefix('.').map_or(Some(tail), |t| {
        let n = t.bytes().take_while(u8::is_ascii_digit).count();
        (n > 0).then(|| &t[n..])
    });
    digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && matches!(b[10], b'T' | b't')
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19)
        && tail.is_some_and(|t| {
            t == "Z"
                || t == "z"
                || (t.len() == 6 && matches!(&t[..1], "+" | "-") && t.as_bytes()[3] == b':')
        })
}

/// The verbs of grants and roles (§C.1); `*` is for keys only.
pub const VERBS: &[&str] = &[
    "read", "create", "append", "restore", "delete", "purge", "config", "branch", "purge-ns",
    "export", "prune",
];

fn verbs(v: &Value, p: &str, star: bool) -> Result<(), Problem> {
    for (i, x) in str_array(v, p, "can")?.into_iter().enumerate() {
        if !(VERBS.contains(&x) || (star && x == "*")) {
            return bad(&format!("{p}/{i}"), "a verb (§C.1)");
        }
    }
    Ok(())
}

fn rule_forms(v: &Value, p: &str) -> Result<(), Problem> {
    match patchlog_core::rules::validate(v, u64::MAX) {
        Ok(()) => Ok(()),
        Err(patchlog_core::rules::RulesError::Invalid(errs)) => {
            let (ptr, m) = errs.into_iter().next().unwrap_or_default();
            Err((format!("{p}{ptr}"), m))
        }
        Err(patchlog_core::rules::RulesError::Limit { .. }) => bad(p, "too many rules"),
    }
}

fn allow_deny(v: &Value, p: &str) -> Result<(), Problem> {
    let m = obj(v, p, "an allow or deny list")?;
    if m.len() != 1 || !(m.contains_key("allow") || m.contains_key("deny")) {
        return bad(p, "exactly one of allow and deny");
    }
    let (k, list) = m.iter().next().unwrap();
    str_array(list, &format!("{p}/{k}"), k)?;
    Ok(())
}

/// A 43-character base64url Ed25519 public key, without padding.
pub fn is_pub_key(s: &str) -> bool {
    s.len() == 43
        && s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        // The last character carries 4 bits and 2 zero bits.
        && b"AEIMQUYcgkosw048".contains(&s.as_bytes()[42])
}

/// `keys` (§C.4): strict key entries, with their scope fields.
pub fn keys(v: &Value, p: &str) -> Result<(), Problem> {
    let a = v
        .as_array()
        .ok_or_else(|| (p.to_string(), "keys is an array".to_string()))?;
    let mut kids = std::collections::BTreeSet::new();
    for (i, e) in a.iter().enumerate() {
        let ep = format!("{p}/{i}");
        let m = obj(e, &ep, "a key entry")?;
        only(
            m,
            &ep,
            &[
                "kid",
                "alg",
                "pub",
                "can",
                "maxTtl",
                "maxLag",
                "sub",
                "groups",
                "roles",
                "attrs",
                "rules",
                "readScope",
                "rate",
                "requireAt",
            ],
            false,
        )?;
        match m.get("kid").and_then(Value::as_str) {
            Some(k) if !k.is_empty() => {
                if !kids.insert(k) {
                    return bad(&format!("{ep}/kid"), "kids are unique within keys");
                }
            }
            _ => return bad(&format!("{ep}/kid"), "a non-empty string"),
        }
        if m.get("alg").and_then(Value::as_str) != Some("Ed25519") {
            return bad(&format!("{ep}/alg"), "alg is \"Ed25519\"");
        }
        if !m.get("pub").and_then(Value::as_str).is_some_and(is_pub_key) {
            return bad(
                &format!("{ep}/pub"),
                "an Ed25519 public key, 43 characters of base64url",
            );
        }
        if let Some(c) = m.get("can") {
            verbs(c, &format!("{ep}/can"), true)?;
        }
        for k in ["maxTtl", "maxLag"] {
            if let Some(x) = m.get(k) {
                if !x.as_str().is_some_and(is_duration) {
                    return bad(&format!("{ep}/{k}"), "an ISO 8601 duration");
                }
            }
        }
        if let Some(x) = m.get("sub") {
            if !x
                .as_str()
                .is_some_and(|s| patchlog_core::schema::re2(s).is_ok())
            {
                return bad(&format!("{ep}/sub"), "a regular expression (§6.6)");
            }
        }
        for k in ["groups", "roles"] {
            if let Some(x) = m.get(k) {
                allow_deny(x, &format!("{ep}/{k}"))?;
            }
        }
        if let Some(x) = m.get("attrs") {
            if patchlog_core::schema::compile_fragment(x).is_err() {
                return bad(&format!("{ep}/attrs"), "a JSON Schema, as a rule's schema");
            }
        }
        if let Some(x) = m.get("rules") {
            rule_forms(x, &format!("{ep}/rules"))?;
        }
        if let Some(x) = m.get("readScope") {
            if x.as_str() != Some("resource") {
                return bad(&format!("{ep}/readScope"), "readScope is \"resource\"");
            }
        }
        if let Some(x) = m.get("rate") {
            rate(x, &format!("{ep}/rate"))?;
        }
        if let Some(x) = m.get("requireAt") {
            let ok = matches!(x, Value::Bool(true)) || x.as_str().is_some_and(is_namespace_name);
            if !ok {
                return bad(&format!("{ep}/requireAt"), "true or a namespace name");
            }
        }
    }
    Ok(())
}

/// `roles` (§C.1.1): open entries, of which `can` and `rules` are checked.
pub fn roles(v: &Value, p: &str) -> Result<(), Problem> {
    let m = obj(v, p, "roles")?;
    for (name, r) in m {
        let rp = format!("{p}/{}", escape_token(name));
        if name.is_empty() {
            return bad(&rp, "a role has a name");
        }
        let rm = obj(r, &rp, "a role")?;
        if let Some(c) = rm.get("can") {
            verbs(c, &format!("{rp}/can"), false)?;
        }
        if let Some(x) = rm.get("rules") {
            rule_forms(x, &format!("{rp}/rules"))?;
        }
    }
    Ok(())
}

/// `revoked` (§C.4): revocation ids.
pub fn revoked(v: &Value, p: &str) -> Result<(), Problem> {
    for (i, s) in str_array(v, p, "revoked")?.into_iter().enumerate() {
        if Id::parse(s).is_none() {
            return bad(&format!("{p}/{i}"), "a revocation id");
        }
    }
    Ok(())
}

/// `merge` (§F.3): `{ "authors": [{ "sub", "kid" }] }`.
pub fn merge(v: &Value, p: &str) -> Result<(), Problem> {
    let m = obj(v, p, "merge")?;
    only(m, p, &["authors"], true)?;
    if let Some(a) = m.get("authors") {
        let a = a
            .as_array()
            .ok_or_else(|| (format!("{p}/authors"), "authors is an array".to_string()))?;
        for (i, e) in a.iter().enumerate() {
            let ep = format!("{p}/authors/{i}");
            let em = obj(e, &ep, "an author")?;
            only(em, &ep, &["sub", "kid"], false)?;
            for k in ["sub", "kid"] {
                if !em
                    .get(k)
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty())
                {
                    return bad(&format!("{ep}/{k}"), "a non-empty string");
                }
            }
        }
    }
    Ok(())
}

/// `merged` (§F.3, §F.6): `{ "at": ns_id }`.
pub fn merged(v: &Value, p: &str) -> Result<(), Problem> {
    let m = obj(v, p, "merged")?;
    only(m, p, &["at"], true)?;
    if !m
        .get("at")
        .and_then(Value::as_str)
        .is_some_and(|s| Id::parse(s).is_some())
    {
        return bad(&format!("{p}/at"), "at is a namespace revision id");
    }
    Ok(())
}

/// `cleanup` (§F.6): durations for `merged`, `superseded`, `abandoned`.
pub fn cleanup(v: &Value, p: &str) -> Result<(), Problem> {
    let m = obj(v, p, "cleanup")?;
    only(m, p, &["merged", "superseded", "abandoned"], true)?;
    for (k, x) in m {
        if k.starts_with("x-") {
            continue;
        }
        if !x.as_str().is_some_and(is_duration) {
            return bad(&format!("{p}/{k}"), "an ISO 8601 duration");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        for ok in ["P30D", "PT5M", "P1DT2H", "PT0.5S", "P1Y2M3W4D", "PT1H30M"] {
            assert!(is_duration(ok), "{ok}");
        }
        for bad in ["P", "PT", "30D", "P1H", "PT1D", "P1.5D", "PDT1H"] {
            assert!(!is_duration(bad), "{bad}");
        }
    }

    #[test]
    fn times() {
        assert!(is_rfc3339("2026-10-08T00:00:00Z"));
        assert!(is_rfc3339("2026-10-08T00:00:00.123+02:00"));
        assert!(!is_rfc3339("2026-10-08 00:00:00Z"));
        assert!(!is_rfc3339("2026-10-08T00:00:00"));
    }
}
