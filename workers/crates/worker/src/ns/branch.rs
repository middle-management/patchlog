//! Branches (§7.6): creation and listing in the base, and reading through.
//!
//! Every namespace is its own Durable Object, so a branch can't read its
//! base's tables. It asks the base instead, over internal requests the front
//! Worker never forwards (`/internal/{ns}/…`), for a resource **as of `at`**.
//! That answer never changes (purges and pruning aside, which this server
//! doesn't offer), so the branch keeps it for good.

use std::rc::Rc;

use super::*;
use patchlog_core::blob::BlobRef;

/// `branchDepth` (§12.2).
const BRANCH_DEPTH: i64 = 8;
/// `branchesPerNamespace` (§12.2).
const BRANCHES_PER_NAMESPACE: i64 = 100;
/// Views of base resources kept in memory.
const VIEWS_CACHED: usize = 50_000;

pub(super) const SCHEMA: &[&str] = &[
    // A base's direct branches, and what their namespace documents say about
    // freezing (reported by each branch when it changes).
    "CREATE TABLE IF NOT EXISTS branches (name TEXT PRIMARY KEY, at TEXT NOT NULL, author TEXT NOT NULL, patches TEXT NOT NULL, target TEXT NOT NULL, ns_seq INTEGER NOT NULL, frozen INTEGER NOT NULL DEFAULT 0, successor TEXT) WITHOUT ROWID",
    // Facts about this namespace fixed at creation: `depth`, `base_public`.
    "CREATE TABLE IF NOT EXISTS ns_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL) WITHOUT ROWID",
];

/// A resource as a base saw it at the branch's `at`.
pub(super) struct Foreign {
    pub id: Id,
    pub kind: i64,
    /// The revision's document, or a tombstone's last live document.
    pub doc: Option<Value>,
    /// Blobs attached to the resource in the bases (§7.8 Availability).
    pub blobs: Vec<BlobRef>,
}

#[derive(Deserialize)]
struct BranchRow {
    name: String,
    at: String,
    author: String,
    patches: String,
    ns_seq: i64,
    frozen: i64,
    successor: Option<String>,
}

#[derive(Deserialize)]
struct MetaRow {
    v: String,
}

/// `base: { ns, at }` of a branch's namespace document.
pub(super) fn base_of(ns: &NsHead) -> Option<(String, String)> {
    let b = ns.config.get("base")?;
    Some((
        b.get("ns")?.as_str()?.to_string(),
        b.get("at")?.as_str()?.to_string(),
    ))
}

fn internal_url(ns: &str, rest: &str) -> String {
    format!("https://namespace/internal/{ns}/{rest}")
}

fn blob_from_json(v: &Value) -> Option<BlobRef> {
    Some(BlobRef {
        bid: Id::parse(v.get("bid")?.as_str()?)?,
        media_type: v.get("type")?.as_str()?.to_string(),
        size: match v.get("size")? {
            Value::Number(n) => *n as u64,
            _ => return None,
        },
        nonce: v.get("nonce").and_then(Value::as_str).map(String::from),
    })
}

fn grant_col(v: Option<&Value>) -> SqlStorageValue {
    match v {
        None | Some(Value::Null) => SqlStorageValue::Null,
        Some(x) => canonical_string(x).into(),
    }
}

fn kind_name(kind: i64) -> &'static str {
    if kind == TOMBSTONE {
        "tombstone"
    } else {
        "rev"
    }
}

async fn call(env: &Env, ns: &str, url: &str, body: Option<String>) -> Res<(u16, String)> {
    let stub = env.durable_object("NAMESPACE")?.get_by_name(ns)?;
    let mut resp = match body {
        None => stub.fetch_with_str(url).await?,
        Some(b) => {
            let mut init = RequestInit::new();
            init.with_method(Method::Post)
                .with_body(Some(JsValue::from_str(&b)));
            stub.fetch_with_request(Request::new_with_init(url, &init)?)
                .await?
        }
    };
    Ok((resp.status_code(), resp.text().await?))
}

impl Namespace {
    pub(super) fn meta(&self, k: &str) -> Res<Option<String>> {
        Ok(self
            .one::<MetaRow>("SELECT v FROM ns_meta WHERE k = ?", vec![k.into()])?
            .map(|r| r.v))
    }

    /// The cached view of `name` in the bases; `None` if the namespace isn't
    /// a branch, the view isn't fetched, or the resource didn't exist at `at`.
    pub(super) fn view(&self, name: &str) -> Option<Rc<Foreign>> {
        self.foreign.borrow().get(name).cloned().flatten()
    }

    /// Fetches the base's view of every name that has no entries here and
    /// isn't cached, before a synchronous step that needs it.
    pub(super) async fn prefetch(&self, names: &[&str]) -> Res<()> {
        let Some(ns) = self.head()? else {
            return Ok(());
        };
        let Some((base, at)) = base_of(&ns) else {
            return Ok(());
        };
        if self.foreign.borrow().len() + names.len() > VIEWS_CACHED {
            self.foreign.borrow_mut().clear();
        }
        for name in names {
            if self.foreign.borrow().contains_key(*name) || self.resource(name)?.is_some() {
                continue;
            }
            let v = fetch_view(&self.env, &base, &at, name).await?;
            self.foreign
                .borrow_mut()
                .insert(name.to_string(), v.map(Rc::new));
        }
        Ok(())
    }

    /// Blobs a batch's local `source` makes available: those attached to each
    /// item's resource there, or in a base it reads through (§7.8).
    pub(super) async fn load_source_blobs(
        &self,
        sns: &str,
        at: &str,
        names: &[&str],
    ) -> Res<HashMap<String, Vec<BlobRef>>> {
        let mut extra = HashMap::new();
        for name in names {
            if let Some(f) = fetch_view(&self.env, sns, at, name).await? {
                extra.insert(name.to_string(), f.blobs);
            } else {
                let v = fetch_view_json(&self.env, sns, at, name).await?;
                let blobs = v
                    .get("blobs")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(blob_from_json).collect())
                    .unwrap_or_default();
                extra.insert(name.to_string(), blobs);
            }
        }
        Ok(extra)
    }

    // ------------------------------------------------------------ base side

    /// `POST /ns/{base}/branches` (§7.6).
    pub(super) async fn create_branch(&self, ctx: &Ctx, hd: &Headers, raw: &[u8]) -> Res<Response> {
        http::content_type_is(hd, "application/json")?;
        let author = ctx.author()?;
        match http::precondition(hd)? {
            Precondition::NoneMatchStar => {}
            Precondition::Match(_) => {
                return Err(Err::new(
                    428,
                    "precondition_required",
                    "creating a branch takes If-None-Match: *",
                ));
            }
        }
        let v = json::parse(raw).map_err(|e| Err::bad(e.to_string()))?;
        let Some(m) = v.as_object() else {
            return Err(Err::bad("the body is an object"));
        };
        if m.contains_key("remote") {
            return Err(Err::not_offered("remote branches aren't offered yet"));
        }
        if let Some(k) = m
            .keys()
            .find(|k| !matches!(k.as_str(), "name" | "at" | "patches"))
        {
            return Err(Err::bad(format!("unknown member {k:?}")));
        }
        let name = match m.get("name").and_then(Value::as_str) {
            Some(n) if patchlog_core::names::is_namespace_name(n) && n != ctx.ns => n.to_string(),
            _ => return Err(Err::bad("name is a namespace name other than the base's")),
        };
        let at_given = match m.get("at") {
            None => None,
            Some(Value::String(a)) => Some(a.clone()),
            Some(_) => return Err(Err::bad("at is a namespace revision id")),
        };
        let patches = m.get("patches").cloned().unwrap_or(Value::Array(vec![]));
        let ops = parse_patch_set(&patches).map_err(|e| Err::bad(e.to_string()))?;
        let patches_canon = canonical_string(&patches);
        let ns = self.existing()?;
        // Step 1 (§C.2 item 2): `branch` on the base, with unrestricted
        // `read` of it, with what's known before the document.
        ctx.step1(&["branch"], Some(&name))?;
        if let Some(c) = ctx.grant() {
            let env = crate::auth::read_envelope(c, None, &rfc3339_ms(ctx.now));
            if !c.unrestricted_read() || c.allow("read", &env, true).is_err() {
                return Err(crate::auth::forbidden(
                    "branching needs unrestricted read of the base",
                ));
            }
        }

        // A taken name; a retry by the same author gets 200.
        let retry = |row: &BranchRow| -> Res<Option<Response>> {
            let same = row.author == author
                && self.entry_kid(row.ns_seq)? == ctx.kid()
                && at_given.as_deref().is_none_or(|a| a == row.at)
                && row.patches == patches_canon;
            if !same {
                return Ok(None);
            }
            let e: IdRow = self
                .one(
                    "SELECT id FROM ns_log WHERE seq = ?",
                    vec![row.ns_seq.into()],
                )?
                .ok_or_else(|| Err::new(500, "internal", "missing entry"))?;
            branch_created(200, &row.name, &e.id).map(Some)
        };
        if let Some(row) = self.one::<BranchRow>(
            "SELECT * FROM branches WHERE name = ?",
            vec![name.as_str().into()],
        )? {
            return match retry(&row)? {
                Some(r) => Ok(r),
                None => Err(Err::new(412, "stale", "that name is taken")),
            };
        }
        let at = match &at_given {
            None => ns.id.text(),
            Some(a) => {
                if Id::parse(a).is_none() {
                    return Err(Err::bad("at is a namespace revision id"));
                }
                if self.ns_seq_of(a)?.is_none() {
                    return Err(Err::new(422, "invalid", "at isn't in the base's chain"));
                }
                a.clone()
            }
        };
        let depth = self
            .meta("depth")?
            .and_then(|d| d.parse::<i64>().ok())
            .unwrap_or(0)
            + 1;
        if depth > BRANCH_DEPTH {
            return Err(limit_err(
                422,
                "branchDepth",
                depth as u64,
                BRANCH_DEPTH as u64,
            ));
        }
        #[derive(Deserialize)]
        struct Count {
            n: i64,
        }
        let live = self
            .one::<Count>(
                "SELECT COUNT(*) AS n FROM branches WHERE frozen = 0",
                vec![],
            )?
            .map_or(0, |c| c.n);
        if live + 1 > BRANCHES_PER_NAMESPACE {
            return Err(limit_err(
                422,
                "branchesPerNamespace",
                (live + 1) as u64,
                BRANCHES_PER_NAMESPACE as u64,
            ));
        }
        // The branch's document: the base's current one, less the members
        // that don't carry over, with `base`, then `patches`.
        let mut doc = ns.config.clone();
        if let Value::Object(m) = &mut doc {
            for k in [
                "frozen",
                "successor",
                "merged",
                "abandoned",
                "cleanup",
                "drafts",
                "schemaReads",
            ] {
                m.remove(k);
            }
            m.insert(
                "base".into(),
                obj(vec![("ns", s(ctx.ns.clone())), ("at", s(at.clone()))]),
            );
        }
        let writes = apply(&mut doc, &ops).map_err(|e| Err::new(422, "invalid", e.to_string()))?;
        validate_config(&doc)?;
        check_branch_fields(&Value::Null, &doc, true, ns.public)?;
        let lim = Limits::from_config(&doc);
        measure(&doc, &lim)
            .check(&lim)
            .map_err(|e| limit_err(422, e.limit, e.measured.unwrap_or(0), e.max))?;
        // Step 6: the `*`-key guard on `patches`, with a key of the base,
        // then grant rules, then the base's rules, on a `branch` envelope.
        let mut copied = ns.config.clone();
        if let Value::Object(m) = &mut copied {
            m.insert(
                "read".into(),
                doc.get("read").cloned().unwrap_or(Value::Null),
            );
        }
        ctx.star_guard(&writes, &copied, &doc)?;
        let env = envelope(ctx, "branch", &name, &writes, &doc, &patches);
        ctx.step6("branch", &env)?;
        check_rules(&ns, &env)?;
        let genesis = Value::Array(vec![obj(vec![
            ("op", s("add")),
            ("path", s("")),
            ("value", doc),
        ])]);
        let target = revision_id(None, &canonical(&genesis));

        let init = obj(vec![
            ("genesis", genesis),
            ("author", s(author.clone())),
            ("depth", Value::Number(depth as f64)),
            ("base_public", Value::Bool(ns.public)),
            // The creator's grant is recorded on both entries (§7.4).
            ("grant_ref", crate::auth::grant_ref(&ctx.caller)),
            (
                "via",
                ctx.principal()
                    .and_then(|p| p.get("via").cloned())
                    .unwrap_or(Value::Null),
            ),
        ]);
        let (status, text) = call(
            &self.env,
            &name,
            &internal_url(&name, "init"),
            Some(canonical_string(&init)),
        )
        .await?;
        match status {
            200 | 201 => {}
            412 => return Err(Err::new(412, "stale", "that name is taken")),
            _ => {
                return Err(Err::new(
                    502,
                    "internal",
                    format!("creating the branch failed: {status} {text}"),
                ))
            }
        }
        // While the branch was created, the same request may have finished.
        if let Some(row) = self.one::<BranchRow>(
            "SELECT * FROM branches WHERE name = ?",
            vec![name.as_str().into()],
        )? {
            return match retry(&row)? {
                Some(r) => Ok(r),
                None => Err(Err::new(412, "stale", "that name is taken")),
            };
        }
        let ns = self.existing()?;
        let entry = obj(vec![
            ("kind", s("branch")),
            ("name", s(name.clone())),
            ("at", s(at.clone())),
            ("target", s(target.text())),
        ]);
        let g = Gesture {
            gesture: None,
            undoes: None,
        };
        let (ns_seq, ns_id_new, ns_stmt) =
            self.ns_entry(ctx, &ns, &entry, &author, &g, ns.config_seq);
        let mut stmts = vec![
            ns_stmt,
            (
                "INSERT INTO branches (name, at, author, patches, target, ns_seq) VALUES (?, ?, ?, ?, ?, ?)",
                vec![name.as_str().into(), at.into(), author.into(), patches_canon.into(), target.text().into(), ns_seq.into()],
            ),
        ];
        stmts.extend(ctx.grant_stmt());
        self.commit(stmts)?;
        self.set_head(NsHead {
            seq: ns_seq,
            id: ns_id_new,
            ..ns
        });
        branch_created(201, &name, &ns_id_new.text())
    }

    /// `GET /ns/{ns}/branches` (§7.4).
    pub(super) fn get_branches(&self, ctx: &Ctx) -> Res<Response> {
        let ns = self.existing()?;
        let rows: Vec<BranchRow> = self.rows("SELECT * FROM branches ORDER BY name", vec![])?;
        let list = rows
            .into_iter()
            .map(|r| {
                let mut m = vec![
                    ("name", s(r.name)),
                    ("at", s(r.at)),
                    ("frozen", Value::Bool(r.frozen != 0)),
                    ("purged", Value::Bool(false)),
                ];
                if let Some(x) = r.successor {
                    m.push(("successor", s(x)));
                }
                obj(m)
            })
            .collect();
        let hd = Headers::new();
        cache_headers(&hd, Class::HeadPointer, ns.public)?;
        tags(&hd, &ctx.ns, None)?;
        http::json(200, hd, &Value::Array(list))
    }

    /// A branch reports its `frozen` and `successor` after a config write.
    pub(super) fn branch_state(&self, raw: &[u8]) -> Res<Response> {
        let v = json::parse(raw).map_err(|e| Err::bad(e.to_string()))?;
        let name = v.get("name").and_then(Value::as_str).unwrap_or_default();
        let frozen = matches!(v.get("frozen"), Some(Value::Bool(true)));
        let successor = v.get("successor").and_then(Value::as_str).map(String::from);
        self.commit(vec![(
            "UPDATE branches SET frozen = ?, successor = ? WHERE name = ?",
            vec![(frozen as i64).into(), successor.into(), name.into()],
        )])?;
        http::respond(204, Headers::new(), vec![])
    }

    /// The resource `name` as of the revision `at`, read through bases of
    /// bases: `{ kind: "rev" | "tombstone" | "none", id?, created?, doc?, blobs }`.
    pub(super) async fn view_at(&self, at: &str, name: &str) -> Res<Value> {
        let ns = self.existing()?;
        let at_seq = self.ns_seq_of(at)?.ok_or_else(Err::not_found)?.seq;
        #[derive(Deserialize)]
        struct Row {
            seq: i64,
            id: String,
            kind: i64,
            created: i64,
        }
        let row: Option<Row> = self.one(
            "SELECT seq, id, kind, created FROM res_log WHERE resource = ? AND seq <= ? ORDER BY seq DESC LIMIT 1",
            vec![name.into(), at_seq.into()],
        )?;
        let mut blobs: Vec<Value> = self
            .rows::<BlobRowJson>(
                "SELECT bid, type, nonce, size FROM res_blobs WHERE resource = ? AND uploader = ''",
                vec![name.into()],
            )?
            .into_iter()
            .map(|b| b.json())
            .collect();
        let base = base_of(&ns);
        let Some(row) = row else {
            // No entries by then: as the base saw it at our `at`.
            return match base {
                Some((b, bat)) => Ok(fetch_view_json(&self.env, &b, &bat, name).await?),
                None => Ok(obj(vec![
                    ("kind", s("none")),
                    ("blobs", Value::Array(blobs)),
                ])),
            };
        };
        if let Some((b, bat)) = base {
            // Blobs from before a foreign parent stay in the history.
            if let Some(Value::Array(more)) = fetch_view_json(&self.env, &b, &bat, name)
                .await?
                .get("blobs")
            {
                blobs.extend(more.iter().cloned());
            }
        }
        let doc_seq = if row.kind == TOMBSTONE {
            #[derive(Deserialize)]
            struct Seq {
                seq: Option<i64>,
            }
            self.one::<Seq>(
                "SELECT MAX(seq) AS seq FROM (SELECT seq FROM res_log WHERE resource = ?1 AND kind = 0 AND seq <= ?2 UNION ALL SELECT seq FROM res_snapshots WHERE resource = ?1 AND seq <= ?2)",
                vec![name.into(), row.seq.into()],
            )?
            .and_then(|s| s.seq)
        } else {
            Some(row.seq)
        };
        let doc = match doc_seq {
            Some(q) => self.doc_at(name, q, false)?,
            None => Value::Null,
        };
        Ok(obj(vec![
            ("kind", s(kind_name(row.kind))),
            ("id", s(row.id)),
            ("created", Value::Number(row.created as f64)),
            ("doc", doc),
            ("blobs", Value::Array(blobs)),
        ]))
    }

    /// A revision of `name` in its history as of `at`, read through bases:
    /// `{ kind, id, created, doc? }`, or `404`.
    pub(super) async fn rev_at(&self, at: &str, name: &str, id: &str) -> Res<Option<Value>> {
        let ns = self.existing()?;
        let at_seq = self.ns_seq_of(at)?.ok_or_else(Err::not_found)?.seq;
        let Some(rid) = Id::parse(id) else {
            return Ok(None);
        };
        if let Some(e) = self.entry_by_id(name, &rid)? {
            if e.seq > at_seq {
                return Ok(None);
            }
            let mut m = vec![
                ("kind", s(kind_name(e.kind))),
                ("id", s(e.id.clone())),
                ("created", Value::Number(e.created as f64)),
            ];
            if e.kind != TOMBSTONE {
                m.push(("doc", self.doc_at(name, e.seq, false)?));
            }
            return Ok(Some(obj(m)));
        }
        match base_of(&ns) {
            Some((b, bat)) => fetch_rev(&self.env, &b, &bat, name, id).await,
            None => Ok(None),
        }
    }

    /// A page of `name`'s log up to revision `upto`, after `since`, crossing
    /// a foreign parent into the base (§7.6 History): the base's entries
    /// first, a page at a time, then this namespace's. `at_seq` bounds what
    /// a branch of this namespace may see. `None` if `upto` or `since` isn't
    /// in the resource's history.
    pub(super) async fn log_range(
        &self,
        name: &str,
        upto: &str,
        since: &str,
        at_seq: Option<i64>,
    ) -> Res<Option<(Vec<Value>, bool)>> {
        let ns = self.existing()?;
        let Some(upto_id) = Id::parse(upto) else {
            return Err(Err::bad("malformed id"));
        };
        let base = base_of(&ns);
        let Some(top) = self.entry_by_id(name, &upto_id)? else {
            // A base revision, in a branch.
            return match base {
                Some((b, bat)) => fetch_log(&self.env, &b, &bat, name, upto, since).await,
                None => Ok(None),
            };
        };
        if at_seq.is_some_and(|a| top.seq > a) {
            return Ok(None);
        }
        // The foreign parent: the first entry's parent, if not an entry here.
        let first: Option<EntryRow> = self.one(
            "SELECT *, 0 AS ns_seq FROM res_log WHERE resource = ? ORDER BY seq LIMIT 1",
            vec![name.into()],
        )?;
        let fp = first.and_then(|f| f.parent).filter(|p| {
            Id::parse(p).is_some_and(|p| self.entry_by_id(name, &p).ok().flatten().is_none())
        });
        let after = if since.is_empty() {
            match (&fp, &base) {
                (Some(fp), Some((b, bat))) => {
                    // Everything up to the foreign parent comes first.
                    return Ok(fetch_log(&self.env, b, bat, name, fp, "")
                        .await?
                        .map(|(p, _)| (p, true)));
                }
                _ => 0,
            }
        } else {
            let Some(sid) = Id::parse(since) else {
                return Err(Err::bad("malformed since"));
            };
            match self.entry_by_id(name, &sid)? {
                Some(e) if e.seq <= top.seq => e.seq,
                Some(_) => return Ok(None),
                None if fp.as_deref() == Some(since) => 0,
                None => match (&fp, &base) {
                    (Some(fp), Some((b, bat))) => {
                        return Ok(fetch_log(&self.env, b, bat, name, fp, since)
                            .await?
                            .map(|(p, _)| (p, true)));
                    }
                    _ => return Ok(None),
                },
            }
        };
        Ok(Some(self.res_page(name, after, top.seq, &ns.limits)?))
    }

    // ---------------------------------------------------------- branch side

    /// Creates this namespace as a branch: its genesis config entry, with the
    /// document the base computed (§7.6 Configuration).
    pub(super) fn init_branch(&self, ctx: &Ctx, raw: &[u8]) -> Res<Response> {
        let v = json::parse(raw).map_err(|e| Err::bad(e.to_string()))?;
        let genesis = v
            .get("genesis")
            .cloned()
            .ok_or_else(|| Err::bad("no genesis"))?;
        let author = v
            .get("author")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let depth = match v.get("depth") {
            Some(Value::Number(n)) => *n as i64,
            _ => 1,
        };
        let base_public = matches!(v.get("base_public"), Some(Value::Bool(true)));
        let canon = canonical(&genesis);
        let id = revision_id(None, &canon);
        if self.head()?.is_some() {
            let first: Option<ConfigRow> =
                self.one("SELECT * FROM ns_config WHERE seq = 1", vec![])?;
            return match first {
                Some(c) if c.id == id.text() && c.author == author => {
                    http::respond(200, Headers::new(), vec![])
                }
                _ => Err(Err::new(412, "stale", "that name is taken")),
            };
        }
        let doc = genesis
            .as_array()
            .and_then(|a| a.first())
            .and_then(|op| op.get("value"))
            .cloned()
            .ok_or_else(|| Err::bad("malformed genesis"))?;
        let entry = obj(vec![("kind", s("config")), ("target", s(id.text()))]);
        let ns_id_new = ns_id(None, &canonical(&entry));
        let plan = ConfigPlan {
            id,
            parent: None,
            patches: String::from_utf8(canon).unwrap(),
            doc: doc.clone(),
        };
        self.commit(vec![
            (
                "INSERT INTO ns_log (seq, id, prev, entry, author, created, gesture, undoes, config_seq, grant_ref, via) VALUES (1, ?, NULL, ?, ?, ?, NULL, NULL, 1, ?, ?)",
                vec![
                    ns_id_new.text().into(),
                    canonical_string(&entry).into(),
                    author.as_str().into(),
                    ctx.now.into(),
                    grant_col(v.get("grant_ref")),
                    grant_col(v.get("via")),
                ],
            ),
            plan.insert(1, &author, 1),
            (
                "INSERT INTO ns_meta (k, v) VALUES ('depth', ?), ('base_public', ?)",
                vec![depth.to_string().into(), (if base_public { "1" } else { "0" }).into()],
            ),
        ])?;
        self.set_head(make_head(1, ns_id_new, 1, id, doc));
        http::respond(201, Headers::new(), vec![])
    }

    /// After a config change in a branch, tells the base what its listing
    /// shows: `frozen` and `successor`.
    pub(super) async fn report_to_base(
        &self,
        ctx: &Ctx,
        before: Option<(bool, Option<String>)>,
    ) -> Res<()> {
        let Some(ns) = self.head()? else {
            return Ok(());
        };
        let Some((base, _)) = base_of(&ns) else {
            return Ok(());
        };
        let now = (
            ns.frozen,
            ns.config
                .get("successor")
                .and_then(Value::as_str)
                .map(String::from),
        );
        if before.as_ref() == Some(&now) {
            return Ok(());
        }
        let mut m = vec![("name", s(ctx.ns.clone())), ("frozen", Value::Bool(now.0))];
        if let Some(x) = now.1 {
            m.push(("successor", s(x)));
        }
        call(
            &self.env,
            &base,
            &internal_url(&base, "branch-state"),
            Some(canonical_string(&obj(m))),
        )
        .await?;
        Ok(())
    }

    pub(super) fn freeze_state(&self) -> Res<Option<(bool, Option<String>)>> {
        Ok(self.head()?.map(|h| {
            (
                h.frozen,
                h.config
                    .get("successor")
                    .and_then(Value::as_str)
                    .map(String::from),
            )
        }))
    }

    /// `GET /r/{branch}/{name}` for a resource read through (§7.6).
    pub(super) fn get_head_foreign(&self, ctx: &Ctx, ns: &NsHead, name: &str) -> Res<Response> {
        let Some(f) = self.view(name) else {
            return Err(Err::not_found());
        };
        let hd = Headers::new();
        cache_headers(&hd, Class::HeadPointer, ns.public)?;
        tags(&hd, &ctx.ns, Some(name))?;
        hd.set("ETag", &quoted(&f.id))?;
        if f.kind == TOMBSTONE {
            return http::json(
                410,
                hd,
                &obj(vec![
                    ("code", s("gone")),
                    ("tombstone", s(f.id.text())),
                    ("last", Value::Null),
                ]),
            );
        }
        hd.set("Location", &format!("/r/{}/{}/rev/{}", ctx.ns, name, f.id))?;
        http::respond(302, hd, vec![])
    }

    /// `GET /r/{branch}/{name}/rev/{id}` for a revision from a base.
    pub(super) async fn get_rev_foreign(
        &self,
        ctx: &Ctx,
        ns: &NsHead,
        name: &str,
        id: &Id,
        req: &Headers,
    ) -> Res<Response> {
        let Some((base, at)) = base_of(ns) else {
            return Err(Err::not_found());
        };
        let Some(v) = fetch_rev(&self.env, &base, &at, name, &id.text()).await? else {
            return Err(Err::not_found());
        };
        let hd = Headers::new();
        cache_headers(&hd, Class::Immutable, ns.public)?;
        tags(&hd, &ctx.ns, Some(name))?;
        if v.get("kind").and_then(Value::as_str) == Some("tombstone") {
            return http::json(
                410,
                hd,
                &obj(vec![
                    ("code", s("gone")),
                    ("message", s("a tombstone has no document")),
                ]),
            );
        }
        let created = match v.get("created") {
            Some(Value::Number(n)) => *n as i64,
            _ => 0,
        };
        hd.set("ETag", &quoted(id))?;
        hd.set("X-Revision", &id.text())?;
        hd.set("Last-Modified", &http_date(created))?;
        if req.get("If-None-Match")?.is_some_and(|v| {
            v.split(',')
                .any(|t| t.trim() == quoted(id) || t.trim() == "*")
        }) {
            return http::respond(304, hd, vec![]);
        }
        let bytes = canonical(v.get("doc").unwrap_or(&Value::Null));
        let digest = http::sha256(&bytes).await?;
        hd.set("Repr-Digest", &format!("sha-256=:{}:", base64(&digest)))?;
        hd.set("Content-Type", "application/json")?;
        http::respond(200, hd, bytes)
    }

    /// The base's `/heads` at `at`, a page after `after`: `(heads, next)`.
    pub(super) async fn base_heads(
        &self,
        ns: &NsHead,
        after: &str,
    ) -> Res<Option<(Vec<Value>, Option<String>)>> {
        let Some((base, at)) = base_of(ns) else {
            return Ok(None);
        };
        let url = internal_url(&base, &format!("heads/{at}?after={after}"));
        let (status, text) = call(&self.env, &base, &url, None).await?;
        if status != 200 {
            return Err(Err::new(
                502,
                "internal",
                format!("the base's heads: {status}"),
            ));
        }
        let v =
            json::parse(text.as_bytes()).map_err(|e| Err::new(500, "internal", e.to_string()))?;
        let heads = v
            .get("heads")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let next = v.get("next").and_then(Value::as_str).map(String::from);
        Ok(Some((heads, next)))
    }
}

#[derive(Deserialize)]
struct BlobRowJson {
    bid: String,
    #[serde(rename = "type")]
    media_type: String,
    nonce: Option<String>,
    size: i64,
}

impl BlobRowJson {
    fn json(self) -> Value {
        let mut m = vec![
            ("bid", s(self.bid)),
            ("type", s(self.media_type)),
            ("size", Value::Number(self.size as f64)),
        ];
        if let Some(n) = self.nonce {
            m.push(("nonce", s(n)));
        }
        obj(m)
    }
}

fn branch_created(status: u16, name: &str, ns_id: &str) -> Res<Response> {
    let hd = Headers::new();
    cache_headers(&hd, Class::NoStore, false)?;
    hd.set("Location", &format!("/ns/{name}"))?;
    hd.set("X-Namespace-Revision", ns_id)?;
    http::json(status, hd, &obj(vec![("ns", s(name)), ("ns_id", s(ns_id))]))
}

async fn fetch_view_json(env: &Env, base: &str, at: &str, name: &str) -> Res<Value> {
    let (status, text) = call(
        env,
        base,
        &internal_url(base, &format!("view/{at}/{name}")),
        None,
    )
    .await?;
    if status != 200 {
        return Err(Err::new(
            502,
            "internal",
            format!("the base's view of {name}: {status} {text}"),
        ));
    }
    json::parse(text.as_bytes()).map_err(|e| Err::new(500, "internal", e.to_string()))
}

async fn fetch_view(env: &Env, base: &str, at: &str, name: &str) -> Res<Option<Foreign>> {
    let v = fetch_view_json(env, base, at, name).await?;
    let kind = match v.get("kind").and_then(Value::as_str) {
        Some("rev") => REV,
        Some("tombstone") => TOMBSTONE,
        _ => return Ok(None),
    };
    let id = v
        .get("id")
        .and_then(Value::as_str)
        .and_then(Id::parse)
        .ok_or_else(|| Err::new(500, "internal", "a view without an id"))?;
    Ok(Some(Foreign {
        id,
        kind,
        doc: v.get("doc").filter(|d| !matches!(d, Value::Null)).cloned(),
        blobs: v
            .get("blobs")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(blob_from_json).collect())
            .unwrap_or_default(),
    }))
}

async fn fetch_log(
    env: &Env,
    base: &str,
    at: &str,
    name: &str,
    upto: &str,
    since: &str,
) -> Res<Option<(Vec<Value>, bool)>> {
    let url = internal_url(base, &format!("log/{at}/{name}/{upto}?since={since}"));
    let (status, text) = call(env, base, &url, None).await?;
    match status {
        200 => {
            let v = json::parse(text.as_bytes())
                .map_err(|e| Err::new(500, "internal", e.to_string()))?;
            let entries = v
                .get("entries")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            Ok(Some((
                entries,
                matches!(v.get("more"), Some(Value::Bool(true))),
            )))
        }
        404 => Ok(None),
        _ => Err(Err::new(
            502,
            "internal",
            format!("the base's log: {status}"),
        )),
    }
}

async fn fetch_rev(env: &Env, base: &str, at: &str, name: &str, id: &str) -> Res<Option<Value>> {
    let (status, text) = call(
        env,
        base,
        &internal_url(base, &format!("rev/{at}/{name}/{id}")),
        None,
    )
    .await?;
    match status {
        200 => Ok(Some(
            json::parse(text.as_bytes()).map_err(|e| Err::new(500, "internal", e.to_string()))?,
        )),
        404 => Ok(None),
        _ => Err(Err::new(
            502,
            "internal",
            format!("the base's revision: {status}"),
        )),
    }
}

/// `base`, `successor` and `read` rules for branches (§7.4 Branch fields).
/// `prev` is the namespace document before the write (`null` on creation).
pub(super) fn check_branch_fields(
    prev: &Value,
    doc: &Value,
    creating_branch: bool,
    base_public: bool,
) -> Res<()> {
    let (pb, nb) = (prev.get("base"), doc.get("base"));
    if let Some(b) = nb {
        let ok = b.as_object().is_some_and(|m| {
            m.len() == 2
                && m.get("ns")
                    .and_then(Value::as_str)
                    .is_some_and(patchlog_core::names::is_namespace_name)
                && m.get("at")
                    .and_then(Value::as_str)
                    .and_then(Id::parse)
                    .is_some()
        });
        if !ok {
            return Err(invalid_config(
                "/base",
                "base is { ns, at }; remote bases aren't offered yet",
            ));
        }
    }
    if !creating_branch && pb != nb {
        return Err(invalid_config(
            "/base",
            "base is set when a branch is created and never changes",
        ));
    }
    if let Some(x) = doc.get("successor") {
        if !x
            .as_str()
            .is_some_and(patchlog_core::names::is_namespace_name)
        {
            return Err(invalid_config(
                "/successor",
                "successor is a namespace name",
            ));
        }
        if matches!(prev, Value::Null) && !creating_branch {
            return Err(invalid_config(
                "/successor",
                "a namespace's creation can't set successor",
            ));
        }
    }
    if nb.is_some() && !base_public && doc.get("read").and_then(Value::as_str) == Some("public") {
        return Err(invalid_config(
            "/read",
            "a branch of a namespace that isn't public can't be public",
        ));
    }
    Ok(())
}
