//! The grant side of the gate (§6.2 steps 1 and 6, §C.2, §7 private
//! namespaces): who a request is from, what it may read, and the verbs and
//! rules a write passes.

use std::rc::Rc;

use super::*;
use crate::auth::{self, Caller, Checked};

/// Members a config write may cover or overlap only under a `*` key (§7.4).
const STAR_MEMBERS: &[&str] = &[
    "keys",
    "roles",
    "revoked",
    "limits",
    "allowances",
    "merge",
    "retention",
    "encryption",
    "signatures",
    "nonce",
    "schemaReads",
    "catalogs",
    "maxLag",
];

impl Namespace {
    /// The caller (§C.2 item 1, §7): with authentication disabled, its
    /// `X-Author`; reads of a public namespace ignore any grant.
    pub(super) fn caller(
        &self,
        ns: &str,
        path: &str,
        hd: &Headers,
        read: bool,
        now: i64,
    ) -> Res<Caller> {
        if !auth::enabled(&self.env) {
            return Ok(Caller::Disabled(
                hd.get("X-Author")?.filter(|a| !a.is_empty()),
            ));
        }
        let head = self.head()?;
        if read && head.as_ref().is_some_and(|h| h.public) {
            return Ok(Caller::Anonymous);
        }
        let Some(token) = auth::bearer(hd)? else {
            // An edge-grant cookie counts only on a GET or HEAD without
            // Authorization (§C.5.3).
            if read {
                if let Some(cookie) = hd.get("Cookie")? {
                    let keys = crate::edge::edge_keys(&self.env);
                    if let Some((p, _)) = crate::edge::from_cookies(&cookie, path, &keys, now) {
                        return Ok(Caller::Edge(p));
                    }
                }
            }
            return Ok(Caller::Anonymous);
        };
        let u = auth::decode(&token, ns)?;
        let ops = auth::operator_keys(&self.env)?;
        let c = auth::check(&u, head.as_ref().map(|h| &h.config), &ops, now)?;
        Ok(Caller::Grant(Rc::new(c)))
    }

    /// A read of a namespace that isn't public (§7, §C.5): `/ns/…` needs
    /// unrestricted `read`, a resource's URLs `read` on that resource, and
    /// without it the resource is `404` whether or not it exists.
    pub(super) fn gate_read(&self, ctx: &Ctx, resource: Option<&str>) -> Res<()> {
        let c = match &ctx.caller {
            Caller::Disabled(_) => return Ok(()),
            // The cookie's prefix covers the path: checked when it was read.
            Caller::Edge(_) => return Ok(()),
            Caller::Anonymous => {
                if self.head()?.is_some_and(|h| h.public) {
                    return Ok(());
                }
                return Err(auth::unauthorized("this namespace needs a grant to read"));
            }
            Caller::Grant(c) => c,
        };
        if c.operator {
            return Err(auth::unauthorized(
                "an operator grant doesn't read namespaces",
            ));
        }
        let env = auth::read_envelope(c, resource, &rfc3339_ms(ctx.now));
        match resource {
            None => {
                if c.unrestricted_read() && c.allow("read", &env, false).is_ok() {
                    Ok(())
                } else {
                    Err(auth::forbidden(
                        "this needs unrestricted read of the namespace",
                    ))
                }
            }
            Some(_) => c.allow("read", &env, false).map_err(|_| Err::not_found()),
        }
    }
}

impl Ctx {
    pub(super) fn grant(&self) -> Option<&Rc<Checked>> {
        match &self.caller {
            Caller::Grant(c) => Some(c),
            _ => None,
        }
    }

    /// Who writes: the root `sub` under grants, else `X-Author` (§7.2).
    pub(super) fn author(&self) -> Res<String> {
        match &self.caller {
            Caller::Disabled(Some(a)) => Ok(a.clone()),
            Caller::Disabled(None) => Err(Err::bad(
                "with authentication disabled, a write names its author in X-Author",
            )),
            Caller::Anonymous | Caller::Edge(_) => Err(auth::unauthorized("a write needs a grant")),
            Caller::Grant(c) => Ok(c.sub.clone()),
        }
    }

    /// The root `kid`: with `author`, the same principal for retries (§7.2).
    pub(super) fn kid(&self) -> Option<String> {
        self.grant().map(|c| c.kid.clone())
    }

    /// A pending blob's uploader (§7.8): the root `sub` and `kid`.
    pub(super) fn uploader(&self) -> Res<String> {
        let a = self.author()?;
        Ok(match self.kid() {
            Some(k) => format!("{a}\n{k}"),
            None => a,
        })
    }

    pub(super) fn principal(&self) -> Option<Value> {
        self.grant().map(|c| c.principal.clone())
    }

    /// Step 1 for a write that may be any of `verbs` (§C.2, several verbs):
    /// those that pass with what's known before the document. A caller
    /// without a grant can't write; with authentication disabled, all pass.
    pub(super) fn step1(
        &self,
        verbs: &[&'static str],
        resource: Option<&str>,
    ) -> Res<Vec<&'static str>> {
        match &self.caller {
            Caller::Disabled(_) => {
                self.author()?;
                Ok(verbs.to_vec())
            }
            Caller::Anonymous | Caller::Edge(_) => Err(auth::unauthorized("a write needs a grant")),
            Caller::Grant(c) => {
                if c.operator {
                    return Err(auth::unauthorized(
                        "an operator grant only creates namespaces",
                    ));
                }
                let mut m = vec![
                    ("principal", c.principal.clone()),
                    ("now", s(rfc3339_ms(self.now))),
                ];
                if let Some(r) = resource {
                    m.push(("resource", s(r)));
                }
                let found = c.candidates(verbs, &obj(m));
                if found.is_empty() {
                    // The first verb's own refusal says why.
                    let mut m = vec![
                        ("principal", c.principal.clone()),
                        ("now", s(rfc3339_ms(self.now))),
                    ];
                    if let Some(r) = resource {
                        m.push(("resource", s(r)));
                    }
                    c.allow(verbs[0], &obj(m), true)?;
                    return Err(auth::forbidden(
                        "the grant allows none of this write's verbs",
                    ));
                }
                Ok(found)
            }
        }
    }

    /// Step 6, the grant's part: every grant, key and role rule with the
    /// write's own envelope (§C.2 item 4), before the namespace rules.
    pub(super) fn step6(&self, verb: &str, envelope: &Value) -> Res<()> {
        match self.grant() {
            Some(c) => c.allow(verb, envelope, false),
            None => Ok(()),
        }
    }

    /// Whether the namespace rules judge a config write: not for `*` keys,
    /// nor while authentication is disabled (§1, §6.4.3).
    pub(super) fn config_rules_apply(&self) -> bool {
        self.grant().is_some_and(|c| !c.star && !c.operator)
    }

    /// The `*`-key guard of §7.4 and §C.2, for a config write or a branch's
    /// `patches`: run first at step 6.
    pub(super) fn star_guard(&self, writes: &[String], prev: &Value, doc: &Value) -> Res<()> {
        let Some(c) = self.grant() else { return Ok(()) };
        if c.star || c.operator {
            return Ok(());
        }
        // Covering or overlapping: the root, a member, or anything inside one.
        let guarded = writes
            .iter()
            .any(|w| match patchlog_core::patch::parse_pointer(w) {
                Ok(tokens) => tokens
                    .first()
                    .is_none_or(|f| STAR_MEMBERS.contains(&f.as_str())),
                Err(_) => true,
            });
        let to_public = doc.get("read").and_then(Value::as_str) == Some("public")
            && prev.get("read").and_then(Value::as_str) != Some("public");
        if guarded || to_public {
            return Err(auth::forbidden(
                "keys, roles, revocations, limits and exposure change only under a * key",
            ));
        }
        Ok(())
    }

    /// `grant` and `via` columns of a namespace entry (§7.4).
    pub(super) fn grant_cols(&self) -> (SqlStorageValue, SqlStorageValue) {
        match self.grant() {
            Some(c) => (
                canonical_string(&auth::grant_ref(&self.caller)).into(),
                canonical_string(c.principal.get("via").unwrap_or(&Value::Array(vec![]))).into(),
            ),
            None => (SqlStorageValue::Null, SqlStorageValue::Null),
        }
    }

    /// Records the grant a write was made under, for `/grants/{gid}` (§C.3).
    pub(super) fn grant_stmt(&self) -> Option<Stmt> {
        let c = self.grant()?;
        Some((
            "INSERT OR IGNORE INTO grants (id, root, stored) VALUES (?, ?, ?)",
            vec![
                c.grant.id.text().into(),
                canonical_string(&c.grant.root).into(),
                auth::base64url(&c.grant.stored).into(),
            ],
        ))
    }
}

impl Namespace {
    /// `GET /ns/{ns}/grants/{gid}` (§C.3): a grant recorded by this
    /// namespace's entries, as `{ id, root, stored }`.
    pub(super) fn get_grant(&self, ctx: &Ctx, gid: &str) -> Res<Response> {
        let ns = self.existing()?;
        let Some(id) = Id::parse(gid) else {
            return Err(Err::bad("malformed grant id"));
        };
        #[derive(Deserialize)]
        struct Row {
            root: String,
            stored: String,
        }
        let row: Row = self
            .one(
                "SELECT root, stored FROM grants WHERE id = ?",
                vec![id.text().into()],
            )?
            .ok_or_else(Err::not_found)?;
        let hd = Headers::new();
        cache_headers(&hd, Class::Immutable, ns.public)?;
        tags(&hd, &ctx.ns, None)?;
        let body = obj(vec![
            ("id", s(id.text())),
            ("root", parse_stored(&row.root)?),
            ("stored", s(row.stored)),
        ]);
        http::json(200, hd, &body)
    }

    /// `GET /ns/{ns}/principal` (§7.4): the grant in `Authorization` as it
    /// applies here. Only the `ns` check and verification apply.
    pub(super) fn get_principal(&self, ctx: &Ctx) -> Res<Response> {
        let head = self.head()?;
        let mut body: Vec<(&str, Value)> = Vec::new();
        let verbs = |v: &mut dyn Iterator<Item = String>| Value::Array(v.map(s).collect());
        match &ctx.caller {
            Caller::Anonymous | Caller::Edge(_) => {
                return Err(auth::unauthorized("principal describes a grant"))
            }
            Caller::Disabled(_) => {
                if head.is_none() {
                    return Err(Err::not_found());
                }
                body.push(("operator", Value::Bool(false)));
                body.push((
                    "can",
                    verbs(&mut crate::nsdoc::VERBS.iter().map(|v| v.to_string())),
                ));
                body.push(("roles", Value::Array(vec![])));
            }
            Caller::Grant(c) => {
                if c.operator && head.is_none() {
                    return Err(Err::not_found());
                }
                body.push(("principal", c.principal.clone()));
                body.push(("kid", s(c.kid.clone())));
                body.push(("key", s(thumbprint(&c.key))));
                body.push(("operator", Value::Bool(c.operator)));
                if c.operator {
                    body.push(("can", verbs(&mut c.can.iter().cloned())));
                    body.push(("roles", Value::Array(vec![])));
                } else {
                    body.push((
                        "can",
                        verbs(&mut c.can.iter().filter(|v| c.may(v)).cloned()),
                    ));
                    body.push(("roles", verbs(&mut c.roles.iter().map(|(r, _)| r.clone()))));
                }
            }
        }
        let hd = Headers::new();
        cache_headers(&hd, Class::NoStore, false)?;
        if let Some(h) = &head {
            let mut writer = vec![
                ("frozen", Value::Bool(h.frozen)),
                ("nonce", s("optional")),
                (
                    "signatures",
                    s(
                        if h.config.get("signatures").and_then(Value::as_str) == Some("required") {
                            "required"
                        } else {
                            "optional"
                        },
                    ),
                ),
                ("limits", limits_json(&h.limits)),
            ];
            if let Some(x) = h.config.get("successor") {
                writer.push(("successor", x.clone()));
            }
            body.push(("writer", obj(writer)));
            if let Some(cat) = h.config.get("catalog") {
                let mut cm = vec![(
                    "trust",
                    cat.get("trust").cloned().unwrap_or(Value::Array(vec![])),
                )];
                if let Some(f) = cat.get("files") {
                    cm.push(("files", f.clone()));
                }
                body.push(("catalog", obj(cm)));
            }
            hd.set("X-Config-Revision", &h.config_id.text())?;
        }
        http::json(200, hd, &obj(body))
    }
}

/// The RFC 7638 SHA-256 thumbprint of a key, base64url without padding: a
/// namespace key as `{"crv":"Ed25519","kty":"OKP","x":<pub>}`, an operator
/// key as its JWK's required members.
fn thumbprint(key: &Value) -> String {
    let x = key
        .get("pub")
        .or_else(|| key.get("x"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let jwk = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    use sha2::Digest;
    auth::base64url(&sha2::Sha256::digest(jwk.as_bytes()))
}

/// Every §6.6 limit in force, at the namespace's value or the default.
fn limits_json(l: &Limits) -> Value {
    let n = |x: u64| Value::Number(x as f64);
    obj(vec![
        ("patchSetSize", n(l.patch_set_size)),
        ("opsPerSet", n(l.ops_per_set)),
        ("documentSize", n(l.document_size)),
        ("valueSize", n(l.value_size)),
        ("pathSize", n(l.path_size)),
        ("nestingDepth", n(l.nesting_depth)),
        ("logPageSize", n(l.log_page_size)),
        ("logPageBytes", n(l.log_page_bytes)),
        ("grantSize", n(auth::GRANT_SIZE)),
        ("rulesPerGrant", n(auth::RULES_PER_GRANT)),
    ])
}

impl Namespace {
    /// What `POST /edge-grants` may issue here for the grant in
    /// `Authorization` (§C.5.2): `{ prefixes, exp }`, or the refusal.
    pub(super) fn edge_check(&self, ctx: &Ctx, hd: &Headers) -> Res<Response> {
        let Some(token) = auth::bearer(hd)? else {
            return Err(auth::unauthorized("no grant"));
        };
        let u = auth::decode(&token, &ctx.ns)?;
        let head = self.head()?;
        let ops = auth::operator_keys(&self.env)?;
        let c = auth::check(&u, head.as_ref().map(|h| &h.config), &ops, ctx.now)?;
        if c.operator {
            return Err(auth::unauthorized(
                "an operator grant doesn't read namespaces",
            ));
        }
        if !c.can.contains("read") {
            return Err(auth::forbidden("the grant has no read here"));
        }
        let fixed = auth::fixed_resources(&c.rules);
        // Rules on /resource where the grant doesn't fix it, or on /now: an
        // edge serves what it can't re-check.
        if c.rules.iter().any(|r| auth::refers(r, "/now"))
            || (fixed.is_none() && c.rules.iter().any(|r| auth::refers(r, "/resource")))
        {
            return Err(auth::forbidden(
                "the grant's rules refer to /now, or to /resource without fixing it",
            ));
        }
        let now = rfc3339_ms(ctx.now);
        let names: Vec<Option<String>> = match &fixed {
            Some(f) => f.iter().cloned().map(Some).collect(),
            None => vec![None],
        };
        let pass = |rules: &[Value]| {
            names.iter().all(|n| {
                patchlog_core::rules::evaluate(
                    &Value::Array(rules.to_vec()),
                    &auth::read_envelope(&c, n.as_deref(), &now),
                )
                .is_ok()
            })
        };
        if c.carries_roles {
            let qualifying = c.roles.iter().any(|(_, e)| {
                let rules: Vec<Value> = e
                    .get("rules")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                e.get("can")
                    .and_then(Value::as_array)
                    .is_some_and(|a| a.iter().any(|v| v.as_str() == Some("read")))
                    && !rules.iter().any(|r| auth::refers(r, "/now"))
                    && (fixed.is_some() || !rules.iter().any(|r| auth::refers(r, "/resource")))
                    && pass(&rules)
            });
            if !qualifying {
                return Err(auth::forbidden("no role qualifies for read"));
            }
        }
        if !pass(&c.rules) {
            return Err(auth::forbidden("the grant's rules don't pass for read now"));
        }
        let prefixes: Vec<Value> = match &fixed {
            Some(f) => f
                .iter()
                .map(|n| s(format!("/r/{}/{}", ctx.ns, n)))
                .collect(),
            None => vec![s(format!("/r/{}", ctx.ns)), s(format!("/ns/{}", ctx.ns))],
        };
        http::json(
            200,
            Headers::new(),
            &obj(vec![
                ("prefixes", Value::Array(prefixes)),
                ("exp", Value::Number(c.grant.exp_ms() as f64)),
            ]),
        )
    }
}
