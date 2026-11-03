//! Grants (Addendum C): the deployment's settings, and checking a grant
//! against a namespace (§C.2).
//!
//! `AUTH = "grants"` turns authentication on (§1); anything else leaves it
//! disabled, when `X-Author` names authors. Operator keys (§C.4) come from
//! `OPERATOR_JWKS`, a JWK Set the deployment also publishes at
//! [`JWKS_PATH`]; only public keys are configured here.

use std::collections::BTreeSet;
use std::rc::Rc;

use patchlog_core::grant::{self, Grant, GrantError, Unverified};
use patchlog_core::json::{self, Value};
use patchlog_core::rules;
use worker::{Env, Headers};

use crate::http::{obj, s, Err, Res};
use crate::nsdoc::{is_duration, is_pub_key};

pub const JWKS_PATH: &str = "/.well-known/patchlog-keys";
/// `grantSize` and `rulesPerGrant` (§12.2), deployment only.
pub const GRANT_SIZE: u64 = 8 * 1024;
pub const RULES_PER_GRANT: u64 = 32;

pub fn enabled(env: &Env) -> bool {
    env.var("AUTH")
        .map(|v| v.to_string() == "grants")
        .unwrap_or(false)
}

/// The operator key history as configured: `{ "keys": [ … ] }`.
pub fn operator_jwks(env: &Env) -> Res<Value> {
    let raw = env
        .var("OPERATOR_JWKS")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| r#"{"keys":[]}"#.to_string());
    let v = json::parse(raw.as_bytes())
        .map_err(|e| Err::new(500, "internal", format!("OPERATOR_JWKS: {e}")))?;
    if !v.get("keys").is_some_and(|k| k.as_array().is_some()) {
        return Err(Err::new(500, "internal", "OPERATOR_JWKS has no keys array"));
    }
    Ok(v)
}

pub struct OperatorKey {
    pub kid: String,
    pub key: [u8; 32],
    pub from: i64,
    pub until: Option<i64>,
    pub jwk: Value,
}

pub fn operator_keys(env: &Env) -> Res<Vec<OperatorKey>> {
    let set = operator_jwks(env)?;
    let mut out = Vec::new();
    for k in set
        .get("keys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let bad = || Err::new(500, "internal", "OPERATOR_JWKS holds a malformed key");
        let str_of = |n: &str| k.get(n).and_then(Value::as_str);
        if str_of("kty") != Some("OKP") || str_of("crv") != Some("Ed25519") {
            return Err(bad());
        }
        let x = str_of("x").filter(|x| is_pub_key(x)).ok_or_else(bad)?;
        let p = k.get("patchlog").ok_or_else(bad)?;
        let from = p
            .get("from")
            .and_then(Value::as_str)
            .and_then(parse_time)
            .ok_or_else(bad)?;
        let until = p.get("until").and_then(Value::as_str).and_then(parse_time);
        out.push(OperatorKey {
            kid: str_of("kid").ok_or_else(bad)?.to_string(),
            key: grant::decode_pub(x).ok_or_else(bad)?,
            from,
            until,
            jwk: k.clone(),
        });
    }
    Ok(out)
}

/// Who a request is from.
#[derive(Clone)]
pub enum Caller {
    /// Authentication disabled (§1): `X-Author`, if sent.
    Disabled(Option<String>),
    /// No `Authorization`.
    Anonymous,
    /// An edge-grant cookie for this prefix, on a `GET` or `HEAD` without
    /// `Authorization` (§C.5.3): reads under it, with no principal.
    Edge(#[allow(dead_code)] String),
    Grant(Rc<Checked>),
}

/// A verified grant, as it applies in one namespace.
pub struct Checked {
    pub grant: Grant,
    pub operator: bool,
    pub kid: String,
    pub sub: String,
    /// The key that verified the root block: a key entry, or the JWK.
    pub key: Value,
    /// The key's `can` holds `*` (§C.4).
    pub star: bool,
    pub principal: Value,
    /// The verbs every block and the key allow (§C.2 item 2), before roles.
    pub can: BTreeSet<String>,
    pub carries_roles: bool,
    /// Effective roles (§2.1), with their entries.
    pub roles: Vec<(String, Value)>,
    /// The key scope's rules and every block's, as one list of rule forms.
    pub rules: Vec<Value>,
}

/// The `Authorization: Bearer` value, if any.
pub fn bearer(hd: &Headers) -> Res<Option<String>> {
    let Some(a) = hd.get("Authorization")? else {
        return Ok(None);
    };
    match a.strip_prefix("Bearer ") {
        Some(t) if !t.trim().is_empty() => Ok(Some(t.trim().to_string())),
        _ => Err(unauthorized("Authorization is Bearer <grant>")),
    }
}

pub fn unauthorized(m: impl Into<String>) -> Err {
    Err::new(401, "unauthorized", m)
}

pub fn forbidden(m: impl Into<String>) -> Err {
    Err::new(403, "forbidden", m)
}

fn grant_err(e: GrantError) -> Err {
    match e {
        GrantError::TooLarge { measured, max } => limit("grantSize", measured, max),
        GrantError::TooManyRules { measured, max } => limit("rulesPerGrant", measured, max),
        GrantError::Invalid(m) => unauthorized(m),
    }
}

fn limit(name: &str, measured: u64, max: u64) -> Err {
    Err::new(413, "limit", format!("{name} is {max}"))
        .with("limit", s(name))
        .with("measured", Value::Number(measured as f64))
        .with("max", Value::Number(max as f64))
}

/// The checks before any key is looked up (§C.2 item 1, §7): the grant's
/// shape and limits, then the `ns` check.
pub fn decode(token: &str, ns: &str) -> Res<Unverified> {
    let u = grant::decode(token, GRANT_SIZE, RULES_PER_GRANT).map_err(grant_err)?;
    let blocks = std::iter::once(u.root()).chain(u.narrowing().iter());
    for b in blocks {
        if let Some(list) = b.get("ns").and_then(Value::as_array) {
            if !list
                .iter()
                .any(|n| n.as_str() == Some(ns) || n.as_str() == Some("*"))
            {
                return Err(forbidden(format!("the grant isn't for {ns}")));
            }
        }
    }
    Ok(u)
}

/// Verification and the key scope (§C.2 item 1), against the namespace
/// document in force (`None` for a namespace that doesn't exist) or the
/// operator keys; then the verbs, roles and principal it carries there.
pub fn check(
    u: &Unverified,
    config: Option<&Value>,
    ops: &[OperatorKey],
    now: i64,
) -> Res<Checked> {
    let kid = u.kid().to_string();
    let entry = config
        .and_then(|c| c.get("keys"))
        .and_then(Value::as_array)
        .and_then(|keys| {
            keys.iter()
                .find(|k| k.get("kid").and_then(Value::as_str) == Some(&kid))
        });
    // A namespace key first; an operator key with the same kid only if the
    // namespace's doesn't verify it (§C.4).
    let mut verified = None;
    if let Some(e) = entry {
        if let Some(k) = e
            .get("pub")
            .and_then(Value::as_str)
            .and_then(grant::decode_pub)
        {
            if let Ok(g) = u.verify(&k) {
                verified = Some((g, false, e.clone()));
            }
        }
    }
    if verified.is_none() {
        if let Some(op) = ops.iter().find(|o| o.kid == kid) {
            if let Ok(g) = u.verify(&op.key) {
                if now < op.from || op.until.is_some_and(|t| now >= t) {
                    return Err(unauthorized("the operator key isn't in force"));
                }
                verified = Some((g, true, op.jwk.clone()));
            }
        }
    }
    let Some((g, operator, key)) = verified else {
        return Err(unauthorized("no key here verifies the grant"));
    };
    g.check_times(now).map_err(grant_err)?;
    if !operator
        && u.root()
            .get("ns")
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().any(|n| n.as_str() == Some("*")))
    {
        return Err(unauthorized(
            "only operator grants may name every namespace",
        ));
    }
    if let Some(revoked) = config
        .and_then(|c| c.get("revoked"))
        .and_then(Value::as_array)
    {
        let ids: BTreeSet<String> = g.revocation_ids.iter().map(|i| i.text()).collect();
        if revoked
            .iter()
            .any(|r| r.as_str().is_some_and(|r| ids.contains(r)))
        {
            return Err(unauthorized("the grant is revoked"));
        }
    }
    let root = g.root.clone();
    let blocks: Vec<&Value> = std::iter::once(&g.root).chain(g.narrowing.iter()).collect();
    let str_list = |v: Option<&Value>| -> Vec<String> {
        v.and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };

    // Roles: those the root lists, kept by every narrowing block that lists
    // roles, and defined in the configuration in force (§2.1).
    let carries_roles = blocks.iter().any(|b| b.get("roles").is_some());
    let defined = config
        .and_then(|c| c.get("roles"))
        .and_then(Value::as_object);
    let mut roles = Vec::new();
    if carries_roles {
        for r in str_list(root.get("roles")) {
            let kept = g
                .narrowing
                .iter()
                .all(|b| b.get("roles").is_none() || str_list(b.get("roles")).contains(&r));
            if let (true, Some(entry)) = (kept, defined.and_then(|d| d.get(&r))) {
                roles.push((r, entry.clone()));
            }
        }
    }
    // Verbs: the intersection of every block that lists `can`; a root block
    // without `can` takes its verbs from its roles (§C.1).
    let mut can: BTreeSet<String> = match root.get("can") {
        Some(c) => str_list(Some(c)).into_iter().collect(),
        None => roles
            .iter()
            .flat_map(|(_, e)| str_list(e.get("can")))
            .collect(),
    };
    for b in &g.narrowing {
        if let Some(c) = b.get("can") {
            let keep: BTreeSet<String> = str_list(Some(c)).into_iter().collect();
            can = can.intersection(&keep).cloned().collect();
        }
    }
    let mut rule_forms: Vec<Value> = Vec::new();
    let mut star = false;
    if !operator {
        // The key's scope (§C.4). A grant it doesn't allow allows nothing.
        let key_can = str_list(key.get("can"));
        star = key_can.iter().any(|c| c == "*");
        if !star {
            if let Some(c) = root.get("can") {
                if let Some(v) = str_list(Some(c)).iter().find(|v| !key_can.contains(v)) {
                    return Err(forbidden(format!("the key can't grant {v}")));
                }
            }
            can.retain(|v| key_can.contains(v));
        }
        scope(&key, &root, now)?;
        if let Some(r) = key.get("rules").and_then(Value::as_array) {
            rule_forms.extend(r.iter().cloned());
        }
    }
    for b in &blocks {
        if let Some(r) = b.get("rules").and_then(Value::as_array) {
            rule_forms.extend(r.iter().cloned());
        }
    }
    let via: Vec<Value> = g
        .narrowing
        .iter()
        .filter_map(|b| b.get("via").cloned())
        .collect();
    let sub = root
        .get("sub")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let principal = obj(vec![
        ("id", s(sub.clone())),
        (
            "groups",
            root.get("groups").cloned().unwrap_or(Value::Array(vec![])),
        ),
        (
            "roles",
            Value::Array(roles.iter().map(|(r, _)| s(r.clone())).collect()),
        ),
        (
            "attrs",
            root.get("attrs")
                .cloned()
                .unwrap_or(Value::Object(Default::default())),
        ),
        ("via", Value::Array(via)),
        ("grant", s(g.id.text())),
    ]);
    let checked = Checked {
        grant: g,
        operator,
        kid,
        sub,
        key,
        star,
        principal,
        can,
        carries_roles,
        roles,
        rules: rule_forms,
    };
    if !operator
        && checked.key.get("readScope").and_then(Value::as_str) == Some("resource")
        && checked.may("read")
        && fixed_resources(&checked.scope_rules()).is_none()
    {
        return Err(forbidden(
            "the key's readScope needs grants that fix /resource",
        ));
    }
    Ok(checked)
}

/// `maxTtl`, `sub`, `groups`, `roles` and `attrs` of a key's scope.
fn scope(key: &Value, root: &Value, now: i64) -> Res<()> {
    if let Some(ttl) = key
        .get("maxTtl")
        .and_then(Value::as_str)
        .and_then(duration_ms)
    {
        let exp = root
            .get("exp")
            .and_then(Value::as_str)
            .and_then(parse_time)
            .unwrap_or(i64::MAX);
        let nbf = root
            .get("nbf")
            .and_then(Value::as_str)
            .and_then(parse_time)
            .unwrap_or(now);
        if exp - nbf.max(now) > ttl {
            return Err(forbidden("the grant outlives the key's maxTtl"));
        }
    }
    if let Some(pat) = key.get("sub").and_then(Value::as_str) {
        let sub = root.get("sub").and_then(Value::as_str).unwrap_or_default();
        let ok = patchlog_core::schema::re2(pat)
            .ok()
            .and_then(|p| regex::Regex::new(&format!("^(?:{p})$")).ok())
            .is_some_and(|re| re.is_match(sub));
        if !ok {
            return Err(forbidden("the key's scope doesn't allow this sub"));
        }
    }
    for k in ["groups", "roles"] {
        if let Some(sc) = key.get(k) {
            let asserted: Vec<&str> = root
                .get(k)
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let list = |n: &str| -> Option<Vec<&str>> {
                sc.get(n)
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
            };
            let ok = match (list("allow"), list("deny")) {
                (Some(allow), _) => asserted.iter().all(|x| allow.contains(x)),
                (_, Some(deny)) => !asserted.iter().any(|x| deny.contains(x)),
                _ => true,
            };
            if !ok {
                return Err(forbidden(format!(
                    "the key's scope doesn't allow these {k}"
                )));
            }
        }
    }
    if let Some(schema) = key.get("attrs") {
        let attrs = root
            .get("attrs")
            .cloned()
            .unwrap_or(Value::Object(Default::default()));
        let ok = patchlog_core::schema::compile_fragment(schema)
            .map(|f| f.check(&attrs).is_ok())
            .unwrap_or(false);
        if !ok {
            return Err(forbidden("the key's scope doesn't allow these attrs"));
        }
    }
    if key.get("requireAt").is_some() {
        // `at` against the chain and maxLag isn't checked yet: refuse rather
        // than accept grants the key means to bound.
        return Err(forbidden("keys with requireAt aren't supported yet"));
    }
    Ok(())
}

impl Checked {
    /// The verb is allowed by the blocks and key, and if the grant carries
    /// roles, listed by an effective role (§C.2 item 2).
    pub fn may(&self, verb: &str) -> bool {
        self.can.contains(verb)
            && (!self.carries_roles || self.roles.iter().any(|(_, e)| lists(e, verb)))
    }

    fn scope_rules(&self) -> Vec<Value> {
        self.rules.clone()
    }

    /// Item 2 and item 4 of §C.2 for `verb`: the verb, the grant and key
    /// rules, and at least one effective role listing it whose rules pass.
    /// At step 1 (`partial`), only rules that refer to nothing but `/action`,
    /// `/resource`, `/principal` and `/now`.
    pub fn allow(&self, verb: &str, envelope: &Value, partial: bool) -> Res<()> {
        if self.operator {
            return Err(unauthorized("an operator grant only creates namespaces"));
        }
        if !self.may(verb) {
            return Err(forbidden(format!("the grant doesn't allow {verb}")));
        }
        let pick = |rs: &[Value]| -> Value {
            Value::Array(
                rs.iter()
                    .filter(|r| !partial || early(r))
                    .cloned()
                    .collect(),
            )
        };
        let env = with_action(envelope, verb);
        if let Err(f) = rules::evaluate(&pick(&self.rules), &env) {
            return Err(forbidden(format!(
                "a grant or key rule fails: {}",
                f.message
            )));
        }
        if self.carries_roles {
            let ok = self.roles.iter().any(|(_, e)| {
                lists(e, verb)
                    && rules::evaluate(
                        &pick(
                            e.get("rules")
                                .and_then(Value::as_array)
                                .map(Vec::as_slice)
                                .unwrap_or(&[]),
                        ),
                        &env,
                    )
                    .is_ok()
            });
            if !ok {
                return Err(forbidden(format!("no role allows {verb} here")));
            }
        }
        Ok(())
    }

    /// The verbs among `verbs` that pass at step 1 (§C.2, several verbs).
    pub fn candidates(&self, verbs: &[&'static str], envelope: &Value) -> Vec<&'static str> {
        verbs
            .iter()
            .copied()
            .filter(|v| self.allow(v, envelope, true).is_ok())
            .collect()
    }

    /// Unrestricted `read` (§2.1): `read`, and no rule of the key, the blocks
    /// or a counting role refers to `/resource`.
    pub fn unrestricted_read(&self) -> bool {
        if self.operator || !self.can.contains("read") {
            return false;
        }
        if self.key.get("readScope").is_some() || self.rules.iter().any(|r| refers(r, "/resource"))
        {
            return false;
        }
        !self.carries_roles
            || self.roles.iter().any(|(_, e)| {
                lists(e, "read")
                    && !e
                        .get("rules")
                        .and_then(Value::as_array)
                        .is_some_and(|rs| rs.iter().any(|r| refers(r, "/resource")))
            })
    }
}

fn lists(role: &Value, verb: &str) -> bool {
    role.get("can")
        .and_then(Value::as_array)
        .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(verb)))
}

fn with_action(envelope: &Value, verb: &str) -> Value {
    let mut e = envelope.clone();
    if let Value::Object(m) = &mut e {
        m.insert("action".into(), s(verb));
    }
    e
}

/// A `read` envelope (§6.4.1).
pub fn read_envelope(c: &Checked, resource: Option<&str>, now: &str) -> Value {
    let mut m = vec![
        ("action", s("read")),
        ("principal", c.principal.clone()),
        ("now", s(now)),
    ];
    if let Some(r) = resource {
        m.push(("resource", s(r)));
    }
    obj(m)
}

/// The pointers a rule form refers to, through `all`, `any`, `not`, `if`
/// and `then`; a `writes` form refers to `/writes`.
fn pointers(r: &Value, out: &mut Vec<String>) {
    let Some(m) = r.as_object() else { return };
    for k in ["all", "any", "if", "then"] {
        if let Some(a) = m.get(k).and_then(Value::as_array) {
            for x in a {
                pointers(x, out);
            }
        }
    }
    if let Some(x) = m.get("not") {
        pointers(x, out);
    }
    match m.get("op").and_then(Value::as_str) {
        Some("writes") => out.push("/writes".into()),
        Some(_) => {
            if let Some(p) = m.get("path").and_then(Value::as_str) {
                out.push(p.to_string());
            }
            for k in ["eq", "lt", "le", "gt", "ge", "in"] {
                if let Some(p) = m.get(k).and_then(|o| o.get("path")).and_then(Value::as_str) {
                    out.push(p.to_string());
                }
            }
        }
        None => {}
    }
}

fn under(p: &str, top: &str) -> bool {
    p == top || p.starts_with(&format!("{top}/"))
}

pub fn refers(r: &Value, top: &str) -> bool {
    let mut ps = Vec::new();
    pointers(r, &mut ps);
    ps.iter().any(|p| under(p, top))
}

/// Refers only to `/action`, `/resource`, `/principal` and `/now`: checked
/// at gate step 1 (§6.2).
fn early(r: &Value) -> bool {
    let mut ps = Vec::new();
    pointers(r, &mut ps);
    ps.iter().all(|p| {
        ["/action", "/resource", "/principal", "/now"]
            .iter()
            .any(|t| under(p, t))
    })
}

/// The names the rules fix `/resource` to (§2.1), or `None`.
pub fn fixed_resources(rs: &[Value]) -> Option<BTreeSet<String>> {
    let mut sets: Vec<BTreeSet<String>> = Vec::new();
    fn walk(r: &Value, sets: &mut Vec<BTreeSet<String>>, bad: &mut bool) {
        let Some(m) = r.as_object() else { return };
        if let Some(a) = m.get("all").and_then(Value::as_array) {
            for x in a {
                walk(x, sets, bad);
            }
            return;
        }
        if m.get("path").and_then(Value::as_str) != Some("/resource") {
            return;
        }
        let names: Option<Vec<&Value>> = match m.get("op").and_then(Value::as_str) {
            Some("test") => match (m.get("value"), m.get("schema")) {
                (Some(v), _) => Some(vec![v]),
                (_, Some(sc)) => sc
                    .as_object()
                    .filter(|o| o.len() == 1)
                    .and_then(|o| o.get("enum"))
                    .and_then(Value::as_array)
                    .map(|a| a.iter().collect()),
                _ => None,
            },
            Some("compare") => match (m.get("eq"), m.get("in")) {
                (Some(e), _) => e.get("value").map(|v| vec![v]),
                (_, Some(i)) => i
                    .get("value")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().collect()),
                _ => None,
            },
            _ => None,
        };
        if let Some(ns) = names {
            let mut set = BTreeSet::new();
            for n in ns {
                match n.as_str() {
                    Some(x) if patchlog_core::names::is_resource_name(x) => {
                        set.insert(x.to_string());
                    }
                    _ => *bad = true,
                }
            }
            sets.push(set);
        }
    }
    let mut bad = false;
    for r in rs {
        walk(r, &mut sets, &mut bad);
    }
    if bad || sets.is_empty() {
        return None;
    }
    let mut it = sets.into_iter();
    let first = it.next()?;
    let all = it.fold(first, |a, b| a.intersection(&b).cloned().collect());
    (!all.is_empty()).then_some(all)
}

/// RFC 3339 to milliseconds since the epoch.
pub fn parse_time(t: &str) -> Option<i64> {
    let b = t.as_bytes();
    if b.len() < 20 {
        return None;
    }
    let num = |r: std::ops::Range<usize>| t.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (
        num(0..4)?,
        num(5..7)?,
        num(8..10)?,
        num(11..13)?,
        num(14..16)?,
        num(17..19)?,
    );
    let mut rest = &t[19..];
    let mut ms = 0;
    if let Some(f) = rest.strip_prefix('.') {
        let n = f.bytes().take_while(u8::is_ascii_digit).count();
        let digits = &f[..n];
        ms = format!("{:0<3}", &digits[..digits.len().min(3)])
            .parse::<i64>()
            .ok()?;
        rest = &f[n..];
    }
    let off = match rest {
        "Z" | "z" => 0,
        o if o.len() == 6 => {
            let sign = if o.starts_with('-') { -1 } else { 1 };
            sign * (o[1..3].parse::<i64>().ok()? * 60 + o[4..6].parse::<i64>().ok()?)
        }
        _ => return None,
    };
    // Days from the civil date (Howard Hinnant's algorithm).
    let (yy, mm) = if mo <= 2 {
        (y - 1, mo + 9)
    } else {
        (y, mo - 3)
    };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * mm + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(((days * 86400 + h * 3600 + mi * 60 + se) - off * 60) * 1000 + ms)
}

/// An ISO 8601 duration (`is_duration`) in milliseconds; years and months
/// count 365 and 30 days.
pub fn duration_ms(d: &str) -> Option<i64> {
    if !is_duration(d) {
        return None;
    }
    let mut total = 0f64;
    let mut num = String::new();
    let mut time = false;
    for c in d[1..].chars() {
        match c {
            'T' => time = true,
            '0'..='9' | '.' => num.push(c),
            u => {
                let n: f64 = num.parse().ok()?;
                num.clear();
                let secs = match (u, time) {
                    ('Y', false) => 365.0 * 86400.0,
                    ('M', false) => 30.0 * 86400.0,
                    ('W', false) => 7.0 * 86400.0,
                    ('D', false) => 86400.0,
                    ('H', true) => 3600.0,
                    ('M', true) => 60.0,
                    ('S', true) => 1.0,
                    _ => return None,
                };
                total += n * secs;
            }
        }
    }
    Some((total * 1000.0) as i64)
}

/// Base64url without padding.
pub fn base64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(b.len() * 4 / 3 + 3);
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..=c.len() {
            out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// `grant` of a log entry (§7.4): `{ id, sub, kid }`, or `null` while
/// authentication is disabled.
pub fn grant_ref(c: &Caller) -> Value {
    match c {
        Caller::Grant(g) => obj(vec![
            ("id", s(g.grant.id.text())),
            ("sub", s(g.sub.clone())),
            ("kid", s(g.kid.clone())),
        ]),
        _ => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        assert_eq!(parse_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_time("2026-10-05T00:00:00Z"), Some(1_791_158_400_000));
        assert_eq!(
            parse_time("2026-10-05T02:00:00.5+02:00"),
            Some(1_791_158_400_500)
        );
        assert_eq!(duration_ms("PT1H30M"), Some(5_400_000));
        assert_eq!(duration_ms("P1D"), Some(86_400_000));
    }
}
