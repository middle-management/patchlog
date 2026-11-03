//! One Durable Object per namespace. It owns the namespace chain, the
//! namespace document chain and every resource log of the namespace, in its
//! SQLite storage. A DO runs one event at a time, and every write's checks
//! and inserts run without an `await` between them, inside `transactionSync`,
//! which gives §5's atomicity (invariants 2, 5 and 6).

use std::cell::RefCell;
use std::collections::HashMap;
use std::time::Duration;

use patchlog_core::fmt::{http_date, repr_digest, rfc3339_ms};
use patchlog_core::gate::{self, Body, GateError, WriteKind};
use patchlog_core::id::{ns_id, revision_id, tombstone_id};
use patchlog_core::json::{self, canonical, canonical_string, Value};
use patchlog_core::limits::{self, measure, settable_limit_max, Limits};
use patchlog_core::patch::{apply, parse_patch_set};
use patchlog_core::Id;
use serde::Deserialize;
use worker::js_sys;
use worker::wasm_bindgen::{closure::Closure, JsCast, JsValue};
use worker::wasm_bindgen_futures::JsFuture;
use worker::*;

use crate::http::{self, cache_headers, obj, quoted, s, tags, Class, Err, Precondition, Res};

/// A snapshot of the document is stored every `SNAPSHOT_EVERY` entries of a
/// resource, so a read of any revision folds at most that many patch sets.
const SNAPSHOT_EVERY: i64 = 16;
/// Head documents kept parsed in memory, by canonical size.
const DOC_CACHE_BYTES: u64 = 32 * 1024 * 1024;

const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS nslog (seq INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE, prev TEXT, entry TEXT NOT NULL, author TEXT NOT NULL, created INTEGER NOT NULL, gesture TEXT, undoes TEXT, config_seq INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS config (seq INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE, parent TEXT, patches TEXT NOT NULL, doc TEXT NOT NULL, author TEXT NOT NULL, ns_seq INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS resources (name TEXT PRIMARY KEY, head INTEGER NOT NULL, live INTEGER)",
    "CREATE TABLE IF NOT EXISTS entries (seq INTEGER PRIMARY KEY, resource TEXT NOT NULL, id TEXT NOT NULL, parent TEXT, kind INTEGER NOT NULL, patches TEXT, author TEXT NOT NULL, created INTEGER NOT NULL, gesture TEXT, undoes TEXT, ns_seq INTEGER NOT NULL, depth INTEGER NOT NULL)",
    "CREATE UNIQUE INDEX IF NOT EXISTS entries_by_id ON entries(resource, id)",
    "CREATE INDEX IF NOT EXISTS entries_by_resource ON entries(resource, seq)",
    "CREATE TABLE IF NOT EXISTS snapshots (seq INTEGER PRIMARY KEY, doc TEXT NOT NULL)",
];

const REV: i64 = 0;
const TOMBSTONE: i64 = 1;

#[derive(Clone)]
struct NsHead {
    seq: i64,
    id: Id,
    config_seq: i64,
    config_id: Id,
    config: Value,
    limits: Limits,
    frozen: bool,
    public: bool,
}

#[derive(Deserialize)]
struct NsRow {
    seq: i64,
    id: String,
    prev: Option<String>,
    entry: String,
    author: String,
    created: i64,
    gesture: Option<String>,
    undoes: Option<String>,
    config_seq: i64,
}

#[derive(Deserialize)]
struct ConfigRow {
    seq: i64,
    id: String,
    doc: String,
    author: String,
    ns_seq: i64,
}

#[derive(Deserialize, Clone)]
struct EntryRow {
    seq: i64,
    id: String,
    parent: Option<String>,
    kind: i64,
    patches: Option<String>,
    author: String,
    created: i64,
    gesture: Option<String>,
    undoes: Option<String>,
    ns_seq: i64,
    depth: i64,
}

#[derive(Deserialize)]
struct ResRow {
    head: i64,
    live: Option<i64>,
}

#[derive(Deserialize)]
struct SnapRow {
    seq: i64,
    doc: String,
}

#[derive(Deserialize)]
struct PatchRow {
    patches: String,
}

#[derive(Deserialize)]
struct IdRow {
    id: String,
}

struct Inner {
    loaded: bool,
    head: Option<NsHead>,
    /// resource → (entry seq, document at it)
    docs: HashMap<String, (i64, Value, u64)>,
    docs_bytes: u64,
}

#[durable_object(fetch)]
pub struct Namespace {
    state: State,
    sql: SqlStorage,
    inner: RefCell<Inner>,
    /// Long-poll waiters share one promise, resolved by the next write.
    wake: RefCell<Option<(js_sys::Promise, js_sys::Function)>>,
}

type Stmt = (&'static str, Vec<SqlStorageValue>);

struct Ctx {
    ns: String,
    now: i64,
}

impl DurableObject for Namespace {
    fn new(state: State, _env: Env) -> Self {
        let sql = state.storage().sql();
        for q in SCHEMA {
            sql.exec(q, None).expect("schema");
        }
        Namespace {
            state,
            sql,
            inner: RefCell::new(Inner {
                loaded: false,
                head: None,
                docs: HashMap::new(),
                docs_bytes: 0,
            }),
            wake: RefCell::new(None),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let public = || {
            self.inner
                .borrow()
                .head
                .as_ref()
                .map(|h| h.public)
                .unwrap_or(false)
        };
        match self.route(req).await {
            Ok(r) => Ok(r),
            Err(e) => {
                if e.status >= 500 {
                    console_error!("{}: {}", e.code, e.message);
                }
                e.into_response(public())
            }
        }
    }
}

impl Namespace {
    fn rows<T: for<'de> Deserialize<'de>>(&self, q: &str, b: Vec<SqlStorageValue>) -> Res<Vec<T>> {
        Ok(self.sql.exec(q, b)?.to_array::<T>()?)
    }

    fn one<T: for<'de> Deserialize<'de>>(
        &self,
        q: &str,
        b: Vec<SqlStorageValue>,
    ) -> Res<Option<T>> {
        Ok(self.rows::<T>(q, b)?.into_iter().next())
    }

    /// Runs `stmts` in one `transactionSync`: all or nothing.
    fn commit(&self, stmts: Vec<Stmt>) -> Res<()> {
        let storage = self.state.storage();
        let raw: &JsValue = storage.as_raw().as_ref();
        let f: js_sys::Function = js_sys::Reflect::get(raw, &JsValue::from_str("transactionSync"))
            .map_err(worker::Error::from)?
            .dyn_into()
            .map_err(|_| Err::new(500, "internal", "transactionSync isn't a function"))?;
        let sql = self.sql.clone();
        let cb = Closure::once_into_js(move || -> std::result::Result<JsValue, JsValue> {
            for (q, b) in stmts {
                sql.exec(q, b)
                    .map_err(|e| JsValue::from_str(&e.to_string()))?;
            }
            Ok(JsValue::UNDEFINED)
        });
        f.call1(raw, &cb)
            .map_err(|e| Err::new(500, "internal", format!("commit failed: {e:?}")))?;
        Ok(())
    }

    fn head(&self) -> Res<Option<NsHead>> {
        if self.inner.borrow().loaded {
            return Ok(self.inner.borrow().head.clone());
        }
        let last: Option<NsRow> =
            self.one("SELECT * FROM nslog ORDER BY seq DESC LIMIT 1", vec![])?;
        let head = match last {
            None => None,
            Some(r) => {
                let c: ConfigRow = self
                    .one(
                        "SELECT * FROM config WHERE seq = ?",
                        vec![r.config_seq.into()],
                    )?
                    .ok_or_else(|| Err::new(500, "internal", "missing config"))?;
                Some(make_head(
                    r.seq,
                    parse_id(&r.id)?,
                    c.seq,
                    parse_id(&c.id)?,
                    parse_stored(&c.doc)?,
                ))
            }
        };
        let mut inner = self.inner.borrow_mut();
        inner.loaded = true;
        inner.head = head.clone();
        Ok(head)
    }

    fn set_head(&self, h: NsHead) {
        self.inner.borrow_mut().head = Some(h);
        if let Some((_, resolve)) = self.wake.borrow_mut().take() {
            let _ = resolve.call0(&JsValue::NULL);
        }
    }

    fn existing(&self) -> Res<NsHead> {
        self.head()?
            .ok_or_else(|| Err::not_found().with("message", s("no such namespace")))
    }

    /// The namespace entry for a write, and the statement that records it.
    fn ns_entry(
        &self,
        ctx: &Ctx,
        h: &NsHead,
        entry: &Value,
        author: &str,
        g: &Gesture,
        config_seq: i64,
    ) -> (i64, Id, Stmt) {
        let id = ns_id(Some(&h.id), &canonical(entry));
        let seq = h.seq + 1;
        let stmt: Stmt = (
            "INSERT INTO nslog (seq, id, prev, entry, author, created, gesture, undoes, config_seq) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                seq.into(),
                id.text().into(),
                h.id.text().into(),
                canonical_string(entry).into(),
                author.into(),
                ctx.now.into(),
                g.gesture.clone().into(),
                g.undoes.clone().into(),
                config_seq.into(),
            ],
        );
        (seq, id, stmt)
    }

    async fn route(&self, mut req: Request) -> Res<Response> {
        let path = req.path();
        let url = req.url()?;
        let segs: Vec<String> = path[1..].split('/').map(String::from).collect();
        let segs: Vec<&str> = segs.iter().map(String::as_str).collect();
        let ctx = Ctx {
            ns: segs[1].to_string(),
            now: Date::now().as_millis() as i64,
        };
        let m = req.method();
        match (segs[0], &segs[2..]) {
            ("ns", []) => match m {
                Method::Get | Method::Head => {
                    http::query(&url, &[])?;
                    self.get_ns(&ctx)
                }
                Method::Patch => {
                    let body = req.bytes().await?;
                    self.write_config(&ctx, req.headers(), &body)
                }
                _ => Err(Err::new(405, "bad_input", "method not allowed")),
            },
            ("ns", ["rev", id]) if m == Method::Get || m == Method::Head => {
                http::query(&url, &[])?;
                self.get_ns_rev(&ctx, id)
            }
            ("ns", ["rev", id, "log"]) if m == Method::Get => {
                let q = http::query(&url, &["since"])?;
                self.get_ns_log_range(&ctx, id, q.get("since").map(String::as_str).unwrap_or(""))
            }
            ("ns", ["log"]) if m == Method::Get => {
                let q = http::query(&url, &["since", "live", "cursor"])?;
                self.get_ns_log_live(&ctx, &q).await
            }
            ("r", [name]) => match m {
                Method::Get | Method::Head => {
                    http::query(&url, &[])?;
                    self.get_head(&ctx, name)
                }
                Method::Patch => {
                    let body = req.bytes().await?;
                    self.write_resource(&ctx, name, req.headers(), &body)
                }
                Method::Delete => self.delete_resource(&ctx, name, req.headers()),
                _ => Err(Err::new(405, "bad_input", "method not allowed")),
            },
            ("r", [name, "rev", id]) if m == Method::Get || m == Method::Head => {
                http::query(&url, &[])?;
                self.get_rev(&ctx, name, id, req.headers())
            }
            ("r", [name, "rev", id, "log"]) if m == Method::Get => {
                let q = http::query(&url, &["since"])?;
                self.get_log_range(
                    &ctx,
                    name,
                    id,
                    q.get("since").map(String::as_str).unwrap_or(""),
                )
            }
            _ => Err(Err::not_offered(
                "this server doesn't offer that endpoint yet",
            )),
        }
    }

    // ---------------------------------------------------------------- namespace

    fn get_ns(&self, ctx: &Ctx) -> Res<Response> {
        let h = self.existing()?;
        let hd = Headers::new();
        cache_headers(&hd, Class::HeadPointer, h.public)?;
        tags(&hd, &ctx.ns, None)?;
        hd.set("Location", &format!("/ns/{}/rev/{}", ctx.ns, h.id))?;
        hd.set("ETag", &quoted(&h.id))?;
        hd.set("X-Config-Revision", &h.config_id.text())?;
        http::respond(302, hd, vec![])
    }

    fn ns_seq_of(&self, id: &str) -> Res<Option<NsRow>> {
        let Some(id) = Id::parse(id) else {
            return Err(Err::bad("malformed id"));
        };
        self.one("SELECT * FROM nslog WHERE id = ?", vec![id.text().into()])
    }

    fn get_ns_rev(&self, ctx: &Ctx, id: &str) -> Res<Response> {
        let h = self.existing()?;
        let row = self.ns_seq_of(id)?.ok_or_else(Err::not_found)?;
        let c: ConfigRow = self
            .one(
                "SELECT * FROM config WHERE seq = ?",
                vec![row.config_seq.into()],
            )?
            .ok_or_else(|| Err::new(500, "internal", "missing config"))?;
        let hd = Headers::new();
        cache_headers(&hd, Class::Immutable, h.public)?;
        tags(&hd, &ctx.ns, None)?;
        hd.set("ETag", &format!("\"{}\"", row.id))?;
        hd.set("X-Config-Revision", &c.id)?;
        hd.set("Content-Type", "application/json")?;
        http::respond(200, hd, c.doc.into_bytes())
    }

    fn ns_entry_json(&self, r: &NsRow) -> Res<Value> {
        let mut v = parse_stored(&r.entry)?;
        if let Value::Object(m) = &mut v {
            m.insert("id".into(), s(r.id.clone()));
            m.insert(
                "prev".into(),
                r.prev.clone().map(Value::String).unwrap_or(Value::Null),
            );
            m.insert("author".into(), s(r.author.clone()));
            m.insert("grant".into(), Value::Null);
            m.insert("created".into(), s(rfc3339_ms(r.created)));
            if let Some(g) = &r.gesture {
                m.insert("gesture".into(), s(g.clone()));
            }
            if let Some(u) = &r.undoes {
                m.insert("undoes".into(), s(u.clone()));
            }
        }
        Ok(v)
    }

    /// Up to one page of namespace entries after `after_seq`, up to `upto_seq`.
    fn ns_page(&self, h: &NsHead, after_seq: i64, upto_seq: i64) -> Res<(Vec<NsRow>, bool)> {
        let n = h.limits.log_page_size as i64;
        let mut rows: Vec<NsRow> = self.rows(
            "SELECT * FROM nslog WHERE seq > ? AND seq <= ? ORDER BY seq LIMIT ?",
            vec![after_seq.into(), upto_seq.into(), (n + 1).into()],
        )?;
        let more = rows.len() as i64 > n;
        rows.truncate(n as usize);
        Ok((rows, more))
    }

    fn ns_page_body(&self, rows: &[NsRow]) -> Res<Vec<u8>> {
        let arr = rows
            .iter()
            .map(|r| self.ns_entry_json(r))
            .collect::<Res<Vec<_>>>()?;
        Ok(canonical(&Value::Array(arr)))
    }

    fn since_seq(&self, since: &str) -> Res<Option<i64>> {
        if since.is_empty() {
            return Ok(Some(0));
        }
        Ok(self.ns_seq_of(since)?.map(|r| r.seq))
    }

    fn get_ns_log_range(&self, ctx: &Ctx, id: &str, since: &str) -> Res<Response> {
        let h = self.existing()?;
        let upto = self.ns_seq_of(id)?.ok_or_else(Err::not_found)?;
        let after = match self.since_seq(since)? {
            Some(a) if a <= upto.seq => a,
            _ => return Err(Err::not_found()),
        };
        let (rows, more) = self.ns_page(&h, after, upto.seq)?;
        let hd = Headers::new();
        cache_headers(&hd, Class::Immutable, h.public)?;
        tags(&hd, &ctx.ns, None)?;
        hd.set("Content-Type", "application/json")?;
        if more {
            hd.set("X-Log-Next", &rows.last().unwrap().id)?;
        }
        http::respond(200, hd, self.ns_page_body(&rows)?)
    }

    /// §7.7, for the namespace log.
    async fn get_ns_log_live(
        &self,
        ctx: &Ctx,
        q: &std::collections::BTreeMap<String, String>,
    ) -> Res<Response> {
        let h = self.existing()?;
        let since = q.get("since").map(String::as_str).unwrap_or("");
        match q.get("live").map(String::as_str) {
            None => {
                if q.contains_key("cursor") {
                    if !q["cursor"].bytes().all(|b| b.is_ascii_digit()) || q["cursor"].is_empty() {
                        return Err(Err::bad("cursor is a decimal number"));
                    }
                }
                let hd = Headers::new();
                cache_headers(&hd, Class::HeadPointer, h.public)?;
                tags(&hd, &ctx.ns, None)?;
                let qs = if since.is_empty() {
                    String::new()
                } else {
                    format!("?since={since}")
                };
                hd.set("Location", &format!("/ns/{}/rev/{}/log{qs}", ctx.ns, h.id))?;
                return http::respond(302, hd, vec![]);
            }
            Some("long-poll") => {}
            Some(_) => return Err(Err::bad("live is long-poll")),
        }
        let current = ctx.now.div_euclid(http::LONG_POLL_INTERVAL_MS);
        let per_hour = 3_600_000 / http::LONG_POLL_INTERVAL_MS;
        let cursor = match q.get("cursor") {
            None => None,
            Some(c) => {
                let c: i64 = c
                    .parse()
                    .ok()
                    .filter(|_| c.bytes().all(|b| b.is_ascii_digit()))
                    .ok_or_else(|| Err::bad("cursor is a decimal number"))?;
                if (c - current).abs() > per_hour {
                    return Err(Err::bad(
                        "cursor is more than an hour away from the server's",
                    ));
                }
                Some(c)
            }
        };
        let after = self.since_seq(since)?.ok_or_else(Err::not_found)?;
        let answer = |h: &NsHead, cursor_out: i64| -> Res<Option<Response>> {
            if h.seq <= after {
                return Ok(None);
            }
            let (rows, _) = self.ns_page(h, after, h.seq)?;
            let hd = Headers::new();
            cache_headers(&hd, Class::LongPollOk, h.public)?;
            tags(&hd, &ctx.ns, None)?;
            hd.set("Content-Type", "application/json")?;
            hd.set("X-Namespace-Revision", &rows.last().unwrap().id)?;
            hd.set("X-Cursor", &cursor_out.to_string())?;
            Ok(Some(http::respond(200, hd, self.ns_page_body(&rows)?)?))
        };
        let empty = |public: bool, cursor_out: i64| -> Res<Response> {
            let hd = Headers::new();
            cache_headers(&hd, Class::LongPollEmpty, public)?;
            tags(&hd, &ctx.ns, None)?;
            if !since.is_empty() {
                hd.set("X-Namespace-Revision", since)?;
            }
            hd.set("X-Cursor", &cursor_out.to_string())?;
            http::respond(204, hd, vec![])
        };
        if let Some(r) = answer(&h, current)? {
            return Ok(r);
        }
        let Some(cursor) = cursor.filter(|c| *c >= current) else {
            return empty(h.public, current);
        };
        // Wait for the next write or the end of the current interval.
        let deadline = (current + 1) * http::LONG_POLL_INTERVAL_MS;
        let wait = (deadline - ctx.now).max(0) as u64;
        let promise = {
            let mut w = self.wake.borrow_mut();
            if w.is_none() {
                let mut resolve = None;
                let p = js_sys::Promise::new(&mut |res, _| resolve = Some(res));
                *w = Some((p, resolve.unwrap()));
            }
            w.as_ref().unwrap().0.clone()
        };
        let woke = Box::pin(JsFuture::from(promise));
        let timeout = Box::pin(Delay::from(Duration::from_millis(wait)));
        futures_util::future::select(woke, timeout).await;
        let h = self.existing()?;
        let now = (Date::now().as_millis() as i64).div_euclid(http::LONG_POLL_INTERVAL_MS);
        if let Some(r) = answer(&h, now)? {
            return Ok(r);
        }
        empty(h.public, now.max(cursor + 1))
    }

    fn write_config(&self, ctx: &Ctx, hd: &Headers, body: &[u8]) -> Res<Response> {
        http::content_type_is(hd, "application/json-patch+json")?;
        let pre = http::precondition(hd)?;
        let g = Gesture::from(hd)?;
        let author = author(hd)?;
        let deployment = Limits::default();
        let body = gate::read_body(body, &Limits::deployment_max()).map_err(gate_err)?;
        let head = self.head()?;
        let (parent_id, parent_doc, limits) = match (&pre, &head) {
            (Precondition::NoneMatchStar, None) => (None, Value::Null, deployment),
            (Precondition::NoneMatchStar, Some(_)) => {
                return Err(Err::new(412, "stale", "a namespace of that name exists"));
            }
            (Precondition::Match(_), None) => return Err(Err::not_found()),
            (Precondition::Match(want), Some(h)) => {
                if *want != h.config_id {
                    // Idempotent retry (§7.2).
                    let id = revision_id(Some(want), &body.canonical);
                    if let Some(c) = self.one::<ConfigRow>(
                        "SELECT * FROM config WHERE id = ?",
                        vec![id.text().into()],
                    )? {
                        if c.author == author {
                            let ns: IdRow = self
                                .one("SELECT id FROM nslog WHERE seq = ?", vec![c.ns_seq.into()])?
                                .ok_or_else(|| Err::new(500, "internal", "missing entry"))?;
                            return config_written(ctx, 200, &c.id, &ns.id);
                        }
                    }
                    return Err(Err::new(412, "stale", "config moved")
                        .with("config", s(h.config_id.text())));
                }
                (Some(h.config_id), h.config.clone(), h.limits.clone())
            }
        };
        // Steps 3–4: apply, then the patch-set and document limits.
        let ops =
            parse_patch_set(&body.value).map_err(|e| Err::new(422, "invalid", e.to_string()))?;
        let mut doc = parent_doc;
        let writes = apply(&mut doc, &ops).map_err(|e| Err::new(422, "invalid", e.to_string()))?;
        if parent_id.is_none() && writes.is_empty() {
            return Err(Err::new(422, "invalid", "a create must write something"));
        }
        if body.canonical.len() as u64 > limits.document_size {
            return Err(limit_err(
                422,
                "documentSize",
                body.canonical.len() as u64,
                limits.document_size,
            ));
        }
        validate_config(&doc)?;
        let new_limits = Limits::from_config(&doc);
        measure(&doc, &new_limits)
            .check(&new_limits)
            .map_err(|e| limit_err(422, e.limit, e.measured.unwrap_or(0), e.max))?;
        let config_id = revision_id(parent_id.as_ref(), &body.canonical);
        let entry = obj(vec![("kind", s("config")), ("target", s(config_id.text()))]);
        let prev = head
            .clone()
            .unwrap_or_else(|| make_head(0, Id([0; 20]), 0, Id([0; 20]), Value::Null));
        let (seq, ns_id_new, ns_stmt) = if head.is_none() {
            let id = ns_id(None, &canonical(&entry));
            let stmt: Stmt = (
                "INSERT INTO nslog (seq, id, prev, entry, author, created, gesture, undoes, config_seq) VALUES (1, ?, NULL, ?, ?, ?, ?, ?, 1)",
                vec![
                    id.text().into(),
                    canonical_string(&entry).into(),
                    author.clone().into(),
                    ctx.now.into(),
                    g.gesture.clone().into(),
                    g.undoes.clone().into(),
                ],
            );
            (1, id, stmt)
        } else {
            self.ns_entry(ctx, &prev, &entry, &author, &g, prev.config_seq + 1)
        };
        let config_seq = prev.config_seq + 1;
        self.commit(vec![
            ns_stmt,
            (
                "INSERT INTO config (seq, id, parent, patches, doc, author, ns_seq) VALUES (?, ?, ?, ?, ?, ?, ?)",
                vec![
                    config_seq.into(),
                    config_id.text().into(),
                    parent_id.map(|p| p.text()).into(),
                    String::from_utf8(body.canonical.clone()).unwrap().into(),
                    canonical_string(&doc).into(),
                    author.into(),
                    seq.into(),
                ],
            ),
        ])?;
        self.set_head(make_head(seq, ns_id_new, config_seq, config_id, doc));
        config_written(ctx, 201, &config_id.text(), &ns_id_new.text())
    }

    // ---------------------------------------------------------------- resources

    fn resource(&self, name: &str) -> Res<Option<(ResRow, EntryRow)>> {
        let Some(r) = self.one::<ResRow>(
            "SELECT head, live FROM resources WHERE name = ?",
            vec![name.into()],
        )?
        else {
            return Ok(None);
        };
        let e = self.entry_by_seq(r.head)?;
        Ok(Some((r, e)))
    }

    fn entry_by_seq(&self, seq: i64) -> Res<EntryRow> {
        self.one("SELECT * FROM entries WHERE seq = ?", vec![seq.into()])?
            .ok_or_else(|| Err::new(500, "internal", "missing entry"))
    }

    fn entry_by_id(&self, name: &str, id: &Id) -> Res<Option<EntryRow>> {
        self.one(
            "SELECT * FROM entries WHERE resource = ? AND id = ?",
            vec![name.into(), id.text().into()],
        )
    }

    /// The document at revision entry `seq`: from the cache, or folded from
    /// the nearest snapshot at or before it.
    fn doc_at(&self, name: &str, seq: i64, take: bool) -> Res<Value> {
        {
            let mut inner = self.inner.borrow_mut();
            if let Some((s, _, _)) = inner.docs.get(name) {
                if *s == seq {
                    if take {
                        let (_, d, n) = inner.docs.remove(name).unwrap();
                        inner.docs_bytes -= n;
                        return Ok(d);
                    }
                    return Ok(inner.docs[name].1.clone());
                }
            }
        }
        let snap: SnapRow = self
            .one(
                "SELECT e.seq AS seq, s.doc AS doc FROM entries e JOIN snapshots s ON s.seq = e.seq WHERE e.resource = ? AND e.seq <= ? ORDER BY e.seq DESC LIMIT 1",
                vec![name.into(), seq.into()],
            )?
            .ok_or_else(|| Err::new(500, "internal", "no snapshot"))?;
        let mut doc = parse_stored(&snap.doc)?;
        let rows: Vec<PatchRow> = self.rows(
            "SELECT patches FROM entries WHERE resource = ? AND seq > ? AND seq <= ? AND kind = 0 ORDER BY seq",
            vec![name.into(), snap.seq.into(), seq.into()],
        )?;
        for r in rows {
            let ops = parse_patch_set(&parse_stored(&r.patches)?)
                .map_err(|e| Err::new(500, "internal", e.to_string()))?;
            apply(&mut doc, &ops).map_err(|e| Err::new(500, "internal", e.to_string()))?;
        }
        Ok(doc)
    }

    fn cache_doc(&self, name: &str, seq: i64, doc: Value, size: u64) {
        let mut inner = self.inner.borrow_mut();
        if inner.docs_bytes + size > DOC_CACHE_BYTES {
            inner.docs.clear();
            inner.docs_bytes = 0;
        }
        if let Some((_, _, n)) = inner.docs.insert(name.to_string(), (seq, doc, size)) {
            inner.docs_bytes -= n;
        }
        inner.docs_bytes += size;
    }

    fn write_resource(&self, ctx: &Ctx, name: &str, hd: &Headers, raw: &[u8]) -> Res<Response> {
        http::content_type_is(hd, "application/json-patch+json")?;
        let pre = http::precondition(hd)?;
        let g = Gesture::from(hd)?;
        let author = author(hd)?;
        let body: Body = gate::read_body(raw, &Limits::deployment_max()).map_err(gate_err)?;
        let ns = self.existing()?;
        let cur = self.resource(name)?;
        // Step 2.1: idempotent retry.
        let parent = match &pre {
            Precondition::Match(p) => Some(*p),
            Precondition::NoneMatchStar => None,
        };
        let id = gate::id_for(parent.as_ref(), &body);
        if cur.is_some() {
            if let Some(e) = self.entry_by_id(name, &id)? {
                if e.author == author && e.parent.as_deref().and_then(Id::parse) == parent {
                    return self.written(ctx, name, &e, 200);
                }
            }
        }
        // Step 2.2: settle the verb; 2.4 frozen; then the precondition.
        let kind = match (&pre, &cur) {
            (Precondition::NoneMatchStar, _) => WriteKind::Create,
            (Precondition::Match(_), Some((_, e))) if e.kind == TOMBSTONE => WriteKind::Restore,
            (Precondition::Match(_), _) => WriteKind::Append,
        };
        if ns.frozen {
            return Err(Err::new(409, "frozen", "the namespace is frozen"));
        }
        match (&pre, &cur) {
            (Precondition::NoneMatchStar, Some((_, e))) if e.kind == TOMBSTONE => {
                return Err(
                    Err::new(410, "gone", "the resource is deleted").with("head", s(e.id.clone()))
                );
            }
            (Precondition::NoneMatchStar, Some((_, e))) => {
                return Err(
                    Err::new(412, "stale", "the resource exists").with("head", s(e.id.clone()))
                );
            }
            (Precondition::Match(_), None) => {
                return Err(Err::new(412, "stale", "no such resource"))
            }
            (Precondition::Match(p), Some((_, e))) if p.text() != e.id => {
                if e.kind == TOMBSTONE {
                    return Err(Err::new(410, "gone", "the resource is deleted")
                        .with("head", s(e.id.clone())));
                }
                return Err(Err::new(412, "stale", "the head moved").with("head", s(e.id.clone())));
            }
            _ => {}
        }
        // Step 3: the parent's document.
        let (doc, depth) = match (&kind, &cur) {
            (WriteKind::Create, _) => (Value::Null, 0),
            (WriteKind::Append, Some((_, e))) => (self.doc_at(name, e.seq, true)?, e.depth + 1),
            (WriteKind::Restore, Some((r, e))) => {
                let live = r.live.ok_or_else(|| {
                    Err::new(500, "internal", "tombstone without a live revision")
                })?;
                (self.doc_at(name, live, true)?, e.depth + 1)
            }
            _ => unreachable!(),
        };
        let p = gate::apply_and_check(parent.as_ref(), doc, &body, kind, &ns.limits)
            .map_err(gate_err)?;
        // Step 7: hash and insert.
        let seq = self.next_entry_seq()?;
        let entry = obj(vec![
            ("resource", s(name)),
            ("kind", s("head")),
            ("target", s(p.id.text())),
        ]);
        let (ns_seq, ns_id_new, ns_stmt) =
            self.ns_entry(ctx, &ns, &entry, &author, &g, ns.config_seq);
        let canon_patches = String::from_utf8(body.canonical).unwrap();
        let mut stmts = vec![
            ns_stmt,
            (
                "INSERT INTO entries (seq, resource, id, parent, kind, patches, author, created, gesture, undoes, ns_seq, depth) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    seq.into(),
                    name.into(),
                    p.id.text().into(),
                    parent.map(|p| p.text()).into(),
                    canon_patches.into(),
                    author.clone().into(),
                    ctx.now.into(),
                    g.gesture.clone().into(),
                    g.undoes.clone().into(),
                    ns_seq.into(),
                    depth.into(),
                ],
            ),
            (
                "INSERT INTO resources (name, head, live) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET head = excluded.head, live = excluded.live",
                vec![name.into(), seq.into(), seq.into()],
            ),
        ];
        if depth % SNAPSHOT_EVERY == 0 {
            stmts.push((
                "INSERT INTO snapshots (seq, doc) VALUES (?, ?)",
                vec![seq.into(), canonical_string(&p.doc).into()],
            ));
        }
        self.commit(stmts)?;
        self.cache_doc(name, seq, p.doc, p.doc_size);
        self.set_head(NsHead {
            seq: ns_seq,
            id: ns_id_new,
            ..ns
        });
        let e = EntryRow {
            seq,
            id: p.id.text(),
            parent: parent.map(|p| p.text()),
            kind: REV,
            patches: None,
            author,
            created: ctx.now,
            gesture: g.gesture,
            undoes: g.undoes,
            ns_seq,
            depth,
        };
        written_response(ctx, name, &e, &ns_id_new.text(), 201)
    }

    fn next_entry_seq(&self) -> Res<i64> {
        #[derive(Deserialize)]
        struct M {
            m: Option<i64>,
        }
        Ok(self
            .one::<M>("SELECT MAX(seq) AS m FROM entries", vec![])?
            .and_then(|m| m.m)
            .unwrap_or(0)
            + 1)
    }

    fn written(&self, ctx: &Ctx, name: &str, e: &EntryRow, status: u16) -> Res<Response> {
        let ns: IdRow = self
            .one("SELECT id FROM nslog WHERE seq = ?", vec![e.ns_seq.into()])?
            .ok_or_else(|| Err::new(500, "internal", "missing entry"))?;
        written_response(ctx, name, e, &ns.id, status)
    }

    fn delete_resource(&self, ctx: &Ctx, name: &str, hd: &Headers) -> Res<Response> {
        let pre = http::precondition(hd)?;
        let g = Gesture::from(hd)?;
        let author = author(hd)?;
        let Precondition::Match(parent) = pre else {
            return Err(Err::new(
                428,
                "precondition_required",
                "DELETE takes If-Match",
            ));
        };
        let ns = self.existing()?;
        let tomb = tombstone_id(&parent);
        let cur = self.resource(name)?;
        if cur.is_some() {
            if let Some(e) = self.entry_by_id(name, &tomb)? {
                if e.author == author {
                    return self.written(ctx, name, &e, 200);
                }
            }
        }
        if ns.frozen {
            return Err(Err::new(409, "frozen", "the namespace is frozen"));
        }
        let Some((r, head)) = cur else {
            return Err(Err::new(412, "stale", "no such resource"));
        };
        if head.kind == TOMBSTONE {
            return Err(Err::new(410, "gone", "the resource is deleted").with("head", s(head.id)));
        }
        if head.id != parent.text() {
            return Err(Err::new(412, "stale", "the head moved").with("head", s(head.id)));
        }
        let seq = self.next_entry_seq()?;
        let entry = obj(vec![
            ("resource", s(name)),
            ("kind", s("tombstone")),
            ("target", s(tomb.text())),
        ]);
        let (ns_seq, ns_id_new, ns_stmt) =
            self.ns_entry(ctx, &ns, &entry, &author, &g, ns.config_seq);
        self.commit(vec![
            ns_stmt,
            (
                "INSERT INTO entries (seq, resource, id, parent, kind, patches, author, created, gesture, undoes, ns_seq, depth) VALUES (?, ?, ?, ?, 1, NULL, ?, ?, ?, ?, ?, ?)",
                vec![
                    seq.into(),
                    name.into(),
                    tomb.text().into(),
                    parent.text().into(),
                    author.clone().into(),
                    ctx.now.into(),
                    g.gesture.clone().into(),
                    g.undoes.clone().into(),
                    ns_seq.into(),
                    (head.depth + 1).into(),
                ],
            ),
            ("UPDATE resources SET head = ?, live = ? WHERE name = ?", vec![seq.into(), r.live.or(Some(head.seq)).into(), name.into()]),
        ])?;
        self.set_head(NsHead {
            seq: ns_seq,
            id: ns_id_new,
            ..ns
        });
        let e = EntryRow {
            seq,
            id: tomb.text(),
            parent: Some(parent.text()),
            kind: TOMBSTONE,
            patches: None,
            author,
            created: ctx.now,
            gesture: g.gesture,
            undoes: g.undoes,
            ns_seq,
            depth: head.depth + 1,
        };
        written_response(ctx, name, &e, &ns_id_new.text(), 200)
    }

    fn get_head(&self, ctx: &Ctx, name: &str) -> Res<Response> {
        let ns = self.existing()?;
        let Some((r, head)) = self.resource(name)? else {
            return Err(Err::not_found());
        };
        let hd = Headers::new();
        cache_headers(&hd, Class::HeadPointer, ns.public)?;
        tags(&hd, &ctx.ns, Some(name))?;
        hd.set("ETag", &format!("\"{}\"", head.id))?;
        if head.kind == TOMBSTONE {
            let last = r
                .live
                .map(|l| self.entry_by_seq(l))
                .transpose()?
                .map(|e| s(e.id))
                .unwrap_or(Value::Null);
            let body = obj(vec![
                ("code", s("gone")),
                ("tombstone", s(head.id)),
                ("last", last),
            ]);
            return http::json(410, hd, &body);
        }
        hd.set(
            "Location",
            &format!("/r/{}/{}/rev/{}", ctx.ns, name, head.id),
        )?;
        http::respond(302, hd, vec![])
    }

    fn get_rev(&self, ctx: &Ctx, name: &str, id: &str, req: &Headers) -> Res<Response> {
        let ns = self.existing()?;
        let Some(id) = Id::parse(id) else {
            return Err(Err::bad("malformed id"));
        };
        let e = self.entry_by_id(name, &id)?.ok_or_else(Err::not_found)?;
        let hd = Headers::new();
        cache_headers(&hd, Class::Immutable, ns.public)?;
        tags(&hd, &ctx.ns, Some(name))?;
        if e.kind == TOMBSTONE {
            let body = obj(vec![
                ("code", s("gone")),
                ("message", s("a tombstone has no document")),
            ]);
            return http::json(410, hd, &body);
        }
        hd.set("ETag", &quoted(&id))?;
        hd.set("X-Revision", &e.id)?;
        hd.set("Last-Modified", &http_date(e.created))?;
        let inm = req.get("If-None-Match")?;
        let not_modified = match &inm {
            Some(v) => v
                .split(',')
                .any(|t| t.trim() == quoted(&id) || t.trim() == "*"),
            None => req
                .get("If-Modified-Since")?
                .is_some_and(|v| v == http_date(e.created)),
        };
        if not_modified {
            return http::respond(304, hd, vec![]);
        }
        let doc = self.doc_at(name, e.seq, false)?;
        let bytes = canonical(&doc);
        hd.set("Repr-Digest", &repr_digest(&bytes))?;
        hd.set("Content-Type", "application/json")?;
        http::respond(200, hd, bytes)
    }

    fn get_log_range(&self, ctx: &Ctx, name: &str, id: &str, since: &str) -> Res<Response> {
        let ns = self.existing()?;
        let Some(id) = Id::parse(id) else {
            return Err(Err::bad("malformed id"));
        };
        let upto = self.entry_by_id(name, &id)?.ok_or_else(Err::not_found)?;
        let after = if since.is_empty() {
            0
        } else {
            let Some(a) = Id::parse(since) else {
                return Err(Err::bad("malformed since"));
            };
            match self.entry_by_id(name, &a)? {
                Some(e) if e.seq <= upto.seq => e.seq,
                _ => return Err(Err::not_found()),
            }
        };
        let n = ns.limits.log_page_size as i64;
        let rows: Vec<EntryRow> = self.rows(
            "SELECT * FROM entries WHERE resource = ? AND seq > ? AND seq <= ? ORDER BY seq LIMIT ?",
            vec![name.into(), after.into(), upto.seq.into(), (n + 1).into()],
        )?;
        let mut out = Vec::new();
        let mut bytes = 0u64;
        let mut more = false;
        for (i, r) in rows.iter().enumerate() {
            let plen = r.patches.as_ref().map(|p| p.len() as u64).unwrap_or(0);
            if i as i64 == n || (i > 0 && bytes + plen > ns.limits.log_page_bytes) {
                more = true;
                break;
            }
            bytes += plen;
            out.push(entry_json(r)?);
        }
        let hd = Headers::new();
        cache_headers(&hd, Class::Immutable, ns.public)?;
        tags(&hd, &ctx.ns, Some(name))?;
        hd.set("Content-Type", "application/json")?;
        if more {
            if let Some(Value::Object(m)) = out.last() {
                hd.set("X-Log-Next", m["id"].as_str().unwrap())?;
            }
        }
        http::respond(200, hd, canonical(&Value::Array(out)))
    }
}

struct Gesture {
    gesture: Option<String>,
    undoes: Option<String>,
}

impl Gesture {
    fn from(h: &Headers) -> Res<Gesture> {
        Ok(Gesture {
            gesture: http::gesture_header(h, "Gesture")?,
            undoes: http::gesture_header(h, "Undoes")?,
        })
    }
}

/// With authentication disabled, `X-Author` names the author (§7.2).
fn author(h: &Headers) -> Res<String> {
    match h.get("X-Author")? {
        Some(a) if !a.is_empty() => Ok(a),
        _ => Err(Err::bad(
            "with authentication disabled, a write names its author in X-Author",
        )),
    }
}

fn parse_id(s: &str) -> Res<Id> {
    Id::parse(s).ok_or_else(|| Err::new(500, "internal", "stored id malformed"))
}

fn parse_stored(s: &str) -> Res<Value> {
    json::parse(s.as_bytes()).map_err(|e| Err::new(500, "internal", e.to_string()))
}

fn make_head(seq: i64, id: Id, config_seq: i64, config_id: Id, config: Value) -> NsHead {
    let limits = Limits::from_config(&config);
    let frozen = matches!(config.get("frozen"), Some(Value::Bool(true)));
    let public = config.get("read").and_then(Value::as_str) == Some("public");
    NsHead {
        seq,
        id,
        config_seq,
        config_id,
        config,
        limits,
        frozen,
        public,
    }
}

fn entry_json(r: &EntryRow) -> Res<Value> {
    let mut m = vec![
        ("id", s(r.id.clone())),
        (
            "parent",
            r.parent.clone().map(Value::String).unwrap_or(s("")),
        ),
        (
            "kind",
            s(if r.kind == TOMBSTONE {
                "tombstone"
            } else {
                "rev"
            }),
        ),
        ("author", s(r.author.clone())),
        ("created", s(rfc3339_ms(r.created))),
    ];
    if let Some(p) = &r.patches {
        m.push(("patches", parse_stored(p)?));
    }
    if let Some(g) = &r.gesture {
        m.push(("gesture", s(g.clone())));
    }
    if let Some(u) = &r.undoes {
        m.push(("undoes", s(u.clone())));
    }
    Ok(obj(m))
}

fn written_response(
    ctx: &Ctx,
    name: &str,
    e: &EntryRow,
    ns_id: &str,
    status: u16,
) -> Res<Response> {
    let hd = Headers::new();
    cache_headers(&hd, Class::NoStore, false)?;
    hd.set("X-Namespace-Revision", ns_id)?;
    if let Some(g) = &e.gesture {
        hd.set("Gesture", g)?;
    }
    if let Some(u) = &e.undoes {
        hd.set("Undoes", u)?;
    }
    if e.kind == TOMBSTONE {
        return http::json(status, hd, &obj(vec![("tombstone", s(e.id.clone()))]));
    }
    hd.set("Location", &format!("/r/{}/{}/rev/{}", ctx.ns, name, e.id))?;
    hd.set("ETag", &format!("\"{}\"", e.id))?;
    http::respond(status, hd, vec![])
}

fn config_written(ctx: &Ctx, status: u16, config: &str, ns_id: &str) -> Res<Response> {
    let hd = Headers::new();
    cache_headers(&hd, Class::NoStore, false)?;
    hd.set("X-Config-Revision", config)?;
    hd.set("X-Namespace-Revision", ns_id)?;
    hd.set("Location", &format!("/ns/{}/rev/{}", ctx.ns, ns_id))?;
    http::json(
        status,
        hd,
        &obj(vec![("config", s(config)), ("ns_id", s(ns_id))]),
    )
}

fn limit_err(status: u16, limit: &str, measured: u64, max: u64) -> Err {
    let limit: &'static str = match limit {
        "documentSize" => "documentSize",
        "patchSetSize" => "patchSetSize",
        "opsPerSet" => "opsPerSet",
        "valueSize" => "valueSize",
        "pathSize" => "pathSize",
        "nestingDepth" => "nestingDepth",
        _ => "limit",
    };
    Err::new(status, "limit", format!("{limit} exceeded"))
        .with("limit", s(limit))
        .with("measured", Value::Number(measured as f64))
        .with("max", Value::Number(max as f64))
}

fn gate_err(e: GateError) -> Err {
    match e {
        GateError::BadInput(m) => Err::bad(m),
        GateError::Invalid(m) => Err::new(422, "invalid", m),
        GateError::Blob(m) => Err::new(422, "blob", m),
        GateError::Limit { status, err } => {
            let mut x = Err::new(status, "limit", format!("{} exceeded", err.limit))
                .with("limit", s(err.limit))
                .with("max", Value::Number(err.max as f64));
            if let Some(m) = err.measured {
                x = x.with("measured", Value::Number(m as f64));
            }
            x
        }
    }
}

/// §7.4, as far as this server goes: `read`, `limits`, `frozen` and `x-`
/// members. Members of addenda this server doesn't implement are refused.
fn validate_config(doc: &Value) -> Res<()> {
    let Some(m) = doc.as_object() else {
        return Err(invalid_config("", "a namespace document is an object"));
    };
    for (k, v) in m {
        let p = format!("/{}", patchlog_core::patch::escape_token(k));
        match k.as_str() {
            "read" => {
                if !matches!(v.as_str(), Some("public" | "grant")) {
                    return Err(invalid_config(&p, "read is \"public\" or \"grant\""));
                }
            }
            "frozen" => {
                if !matches!(v, Value::Bool(_)) {
                    return Err(invalid_config(&p, "frozen is a boolean"));
                }
            }
            "limits" => {
                let Some(l) = v.as_object() else {
                    return Err(invalid_config(&p, "limits is an object"));
                };
                for (lk, lv) in l {
                    let lp = format!("{p}/{}", patchlog_core::patch::escape_token(lk));
                    let Some(max) = settable_limit_max(lk) else {
                        return Err(invalid_config(
                            &lp,
                            "this server doesn't take that limit yet",
                        ));
                    };
                    match lv {
                        Value::Number(n) if n.fract() == 0.0 && *n >= 1.0 => {
                            if *n as u64 > max {
                                return Err(limit_err(422, lk, *n as u64, max));
                            }
                        }
                        _ => return Err(invalid_config(&lp, "a positive integer")),
                    }
                }
                // §6.6 Values.
                let l = Limits::from_config(doc);
                let left = 3 * (l.value_size + l.path_size) + limits::KIB;
                if left > l.patch_set_size {
                    return Err(limit_err(422, "patchSetSize", left, l.patch_set_size));
                }
            }
            k if k.starts_with("x-") => {}
            "keys" | "roles" | "revoked" | "rules" | "allowances" | "retention" | "encryption"
            | "maxLag" | "base" | "successor" | "drafts" | "signatures" | "nonce"
            | "schemaReads" | "catalog" | "catalogs" | "merge" | "merged" | "cleanup"
            | "abandoned" => {
                return Err(invalid_config(
                    &p,
                    "this server doesn't implement that member yet",
                ));
            }
            _ => {
                return Err(invalid_config(
                    &p,
                    "unknown member; extensions start with x-",
                ))
            }
        }
    }
    Ok(())
}

fn invalid_config(pointer: &str, message: &str) -> Err {
    Err::new(422, "invalid", "invalid namespace document").with(
        "errors",
        Value::Array(vec![obj(vec![
            ("pointer", s(pointer)),
            ("message", s(message)),
        ])]),
    )
}
