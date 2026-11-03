//! One Durable Object per namespace. It owns the namespace chain, the
//! namespace document chain and every resource log of the namespace, in its
//! SQLite storage. A DO runs one event at a time, and every write's checks
//! and inserts run without an `await` between them, inside `transactionSync`,
//! which gives §5's atomicity (invariants 2, 5 and 6).

use std::cell::RefCell;
use std::collections::HashMap;
use std::time::Duration;

use patchlog_core::fmt::{base64, http_date, rfc3339_ms};
use patchlog_core::gate::{self, Body, GateError, WriteKind};
use patchlog_core::id::{ns_id, revision_id, tombstone_id};
use patchlog_core::json::{self, canonical, canonical_string, Value};
use patchlog_core::limits::{self, measure, settable_limit_max, Limits};
use patchlog_core::patch::{apply, parse_patch_set};
use patchlog_core::rules;
use patchlog_core::schema::{self, SchemaError};
use patchlog_core::Id;
use serde::Deserialize;
use worker::js_sys;
use worker::wasm_bindgen::{closure::Closure, JsCast, JsValue};
use worker::wasm_bindgen_futures::JsFuture;
use worker::*;

mod access;
mod batch;
mod blob;
mod branch;

use crate::http::{self, cache_headers, obj, quoted, s, tags, Class, Err, Precondition, Res};

/// A snapshot of the document is stored every `SNAPSHOT_EVERY` entries of a
/// resource, so a read of any revision folds at most that many patch sets.
const SNAPSHOT_EVERY: i64 = 16;
/// Head documents kept parsed in memory, by canonical size.
const DOC_CACHE_BYTES: u64 = 32 * 1024 * 1024;

/// Every row and every index entry written counts as a billed "row written",
/// so a resource write costs 4: its namespace entry and that entry's `id`
/// index, and its resource entry and that entry's `id` index. A resource's
/// head is its newest entry, so nothing else is kept per resource.
///
/// The tables are named for this layout (earlier builds used `nslog`,
/// `config`, `resources`, `entries` and `snapshots`); objects created by
/// those builds keep their old tables, which this build doesn't read.
const SCHEMA: &[&str] = &[
    // The namespace chain (§3.5). `seq` is the rowid.
    "CREATE TABLE IF NOT EXISTS ns_log (seq INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE, prev TEXT, entry TEXT NOT NULL, author TEXT NOT NULL, created INTEGER NOT NULL, gesture TEXT, undoes TEXT, config_seq INTEGER NOT NULL)",
    // The namespace document chain.
    "CREATE TABLE IF NOT EXISTS ns_config (seq INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE, parent TEXT, patches TEXT NOT NULL, doc TEXT NOT NULL, author TEXT NOT NULL, ns_seq INTEGER NOT NULL)",
    // Resource logs, clustered by resource: a log range or a head is one
    // range of the primary key. `seq` is the `ns_log` entry that records it.
    "CREATE TABLE IF NOT EXISTS res_log (resource TEXT NOT NULL, seq INTEGER NOT NULL, id TEXT NOT NULL, parent TEXT, kind INTEGER NOT NULL, patches TEXT, author TEXT NOT NULL, created INTEGER NOT NULL, gesture TEXT, undoes TEXT, depth INTEGER NOT NULL, PRIMARY KEY (resource, seq)) WITHOUT ROWID",
    "CREATE UNIQUE INDEX IF NOT EXISTS res_log_by_id ON res_log(resource, id)",
    // The gesture listing (§7.4): only entries written with `Gesture` or
    // `Undoes` are indexed, so other writes pay nothing for it.
    "CREATE INDEX IF NOT EXISTS res_log_by_gesture ON res_log(gesture, seq) WHERE gesture IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS res_log_by_undoes ON res_log(undoes, seq) WHERE undoes IS NOT NULL",
    // A canonical document every SNAPSHOT_EVERY entries of a resource.
    "CREATE TABLE IF NOT EXISTS res_snapshots (resource TEXT NOT NULL, seq INTEGER NOT NULL, doc TEXT NOT NULL, PRIMARY KEY (resource, seq)) WITHOUT ROWID",
    // Blob attachments and pending uploads (§7.8); see `ns/blob.rs`.
    blob::SCHEMA,
    // Grants writes were made under (§C.3): the root block and the stored,
    // non-bearer form, by grant id.
    "CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, root TEXT NOT NULL, stored TEXT NOT NULL) WITHOUT ROWID",
];

/// Columns added since the tables were first created: each `ALTER` fails
/// harmlessly where the column exists.
const COLUMNS: &[&str] = &[
    // `grant` ({ id, sub, kid }, null while authentication is disabled) and
    // `via` of a namespace entry (§7.4).
    "ALTER TABLE ns_log ADD COLUMN grant_ref TEXT",
    "ALTER TABLE ns_log ADD COLUMN via TEXT",
    // The root kid a resource entry was written under: with `author`, the
    // principal a retry must match (§7.2).
    "ALTER TABLE res_log ADD COLUMN kid TEXT",
];

/// Long-polls that wait on hibernatable WebSockets before the rest wait in
/// the object itself.
const HIBERNATING_WAITERS_MAX: usize = 200;

/// `rulesPerNamespace` (§12.2): the default, and this deployment's maximum.
const RULES_PER_NAMESPACE: u64 = 256;

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
    /// The namespace's rules (§6.4), compiled once per config revision.
    rules: Option<Rules>,
}

#[derive(Clone)]
enum Rules {
    Compiled(std::rc::Rc<rules::CompiledRules>),
    /// Rules that no longer compile: evaluating them fails closed.
    Raw(Value),
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
    #[serde(default)]
    grant_ref: Option<String>,
    #[serde(default)]
    via: Option<String>,
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
    #[allow(dead_code)]
    depth: i64,
    /// The root kid of the grant it was written under (§7.2 same principal).
    #[serde(default)]
    kid: Option<String>,
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

/// A resource's head, as `resources` and its head entry record it.
#[derive(Clone)]
struct Head {
    seq: i64,
    id: String,
    kind: i64,
    depth: i64,
    live: Option<i64>,
}

/// Resource heads kept in memory; only this object writes them.
const HEADS_CACHED: usize = 100_000;

struct Inner {
    loaded: bool,
    head: Option<NsHead>,
    /// resource → its head, or `None` for a name with no entries
    heads: HashMap<String, Option<Head>>,
    /// resource → (entry seq, document at it)
    docs: HashMap<String, (i64, Value, u64)>,
    docs_bytes: u64,
}

#[durable_object]
pub struct Namespace {
    state: State,
    sql: SqlStorage,
    /// Tables are created on the first request rather than in the
    /// constructor, which can't report an error (storage can refuse writes,
    /// e.g. over a plan's quota).
    schema_ready: std::cell::Cell<bool>,
    inner: RefCell<Inner>,
    /// Long-poll waiters share one promise, resolved by the next write.
    wake: RefCell<Option<(js_sys::Promise, js_sys::Function)>>,
    env: Env,
    /// Schema documents by revision path, and validators compiled from them:
    /// revisions are immutable, so both are kept for good (§6.1, Validator
    /// cache), up to SCHEMAS_CACHED entries.
    schemas: RefCell<HashMap<String, Value>>,
    validators: RefCell<HashMap<String, std::rc::Rc<schema::Compiled>>>,
    /// Schema revisions written by earlier items of the batch being checked
    /// (§7.5): seen only by that batch, never cached.
    pending_schemas: RefCell<HashMap<String, Value>>,
    /// In a branch, resources as the bases saw them at `at` (§7.6); fixed,
    /// so kept for good. `None`: absent then.
    foreign: RefCell<HashMap<String, Option<std::rc::Rc<branch::Foreign>>>>,
    /// Blobs a batch's local `source` makes available, by resource (§7.8),
    /// for that batch only.
    extra_blobs: RefCell<HashMap<String, Vec<patchlog_core::blob::BlobRef>>>,
}

const SCHEMAS_CACHED: usize = 1024;

/// A write that needs schema revisions this object doesn't hold: they are
/// fetched, and the write runs again from the start.
enum Step {
    Done(Response),
    NeedSchemas(Vec<String>),
}

type Stmt = (&'static str, Vec<SqlStorageValue>);

struct Ctx {
    ns: String,
    now: i64,
    caller: crate::auth::Caller,
}

impl DurableObject for Namespace {
    async fn websocket_message(&self, _ws: WebSocket, _m: WebSocketIncomingMessage) -> Result<()> {
        Ok(())
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        _code: usize,
        _reason: String,
        _clean: bool,
    ) -> Result<()> {
        // The front Worker gave up at the interval's end; nothing to answer.
        let _ = ws.close(Some(1000), Some("closed"));
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, _e: Error) -> Result<()> {
        Ok(())
    }

    fn new(state: State, env: Env) -> Self {
        let sql = state.storage().sql();
        Namespace {
            state,
            sql,
            schema_ready: std::cell::Cell::new(false),
            inner: RefCell::new(Inner {
                loaded: false,
                head: None,
                heads: HashMap::new(),
                docs: HashMap::new(),
                docs_bytes: 0,
            }),
            wake: RefCell::new(None),
            env,
            schemas: RefCell::new(HashMap::new()),
            validators: RefCell::new(HashMap::new()),
            pending_schemas: RefCell::new(HashMap::new()),
            foreign: RefCell::new(HashMap::new()),
            extra_blobs: RefCell::new(HashMap::new()),
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
        let result = match self.ensure_schema() {
            Ok(()) => self.route(req).await,
            Err(e) => Err(e),
        };
        match result {
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
    fn ensure_schema(&self) -> Res<()> {
        if !self.schema_ready.get() {
            for q in SCHEMA.iter().chain(branch::SCHEMA) {
                self.sql.exec(q, None)?;
            }
            for q in COLUMNS {
                let _ = self.sql.exec(q, None);
            }
            self.schema_ready.set(true);
        }
        Ok(())
    }

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
            .map_err(|e| http::storage_err(format!("commit failed: {e:?}")))?;
        Ok(())
    }

    fn head(&self) -> Res<Option<NsHead>> {
        if self.inner.borrow().loaded {
            return Ok(self.inner.borrow().head.clone());
        }
        let last: Option<NsRow> =
            self.one("SELECT * FROM ns_log ORDER BY seq DESC LIMIT 1", vec![])?;
        let head = match last {
            None => None,
            Some(r) => {
                let c: ConfigRow = self
                    .one(
                        "SELECT * FROM ns_config WHERE seq = ?",
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
        self.inner.borrow_mut().head = Some(h.clone());
        if let Some((_, resolve)) = self.wake.borrow_mut().take() {
            let _ = resolve.call0(&JsValue::NULL);
        }
        self.answer_waiters(&h);
    }

    /// Answers the long-polls waiting on hibernatable WebSockets (§7.7): one
    /// log read per distinct `since`, sent to each socket, which is then
    /// closed. The front Worker turns the message into the HTTP answer.
    fn answer_waiters(&self, h: &NsHead) {
        let sockets = self.state.get_websockets();
        if sockets.is_empty() {
            return;
        }
        let now = Date::now().as_millis() as i64;
        let cursor_out = now.div_euclid(http::LONG_POLL_INTERVAL_MS);
        let mut messages: HashMap<(Option<String>, i64), Option<String>> = HashMap::new();
        for ws in sockets {
            let Ok(Some(w)) = ws.deserialize_attachment::<Waiter>() else {
                let _ = ws.close(Some(1011), Some("no attachment"));
                continue;
            };
            let msg = messages
                .entry((w.resource.clone(), w.after))
                .or_insert_with(|| {
                    match self.long_poll_answer(
                        &w.ns,
                        h,
                        w.resource.as_deref(),
                        w.after,
                        cursor_out,
                    ) {
                        Ok(Some((hd, body))) => Some(waiter_message(200, &hd, &body)),
                        _ => None,
                    }
                })
                .clone();
            if let Some(m) = msg {
                let _ = ws.send_with_str(&m);
                let _ = ws.close(Some(1000), Some("answered"));
            }
        }
    }

    /// The `200` answer to a long-poll after `after`, if there are entries:
    /// of the namespace log, or of `resource`'s log (§7.7).
    fn long_poll_answer(
        &self,
        ns: &str,
        h: &NsHead,
        resource: Option<&str>,
        after: i64,
        cursor_out: i64,
    ) -> Res<Option<(Headers, Vec<u8>)>> {
        if h.seq <= after {
            return Ok(None);
        }
        let hd = Headers::new();
        cache_headers(&hd, Class::LongPollOk, h.public)?;
        tags(&hd, ns, resource)?;
        hd.set("Content-Type", "application/json")?;
        hd.set("X-Cursor", &cursor_out.to_string())?;
        let body = match resource {
            None => {
                let (rows, _) = self.ns_page(h, after, h.seq)?;
                hd.set("X-Namespace-Revision", &rows.last().unwrap().id)?;
                self.ns_page_body(&rows)?
            }
            Some(name) => {
                let (out, _) = self.res_page(name, after, i64::MAX, &h.limits)?;
                let Some(Value::Object(last)) = out.last() else {
                    return Ok(None);
                };
                hd.set("X-Revision", last["id"].as_str().unwrap_or_default())?;
                canonical(&Value::Array(out))
            }
        };
        Ok(Some((hd, body)))
    }

    /// One page of `name`'s log after entry `after`, up to entry `upto`
    /// (§7.1 Paging), and whether more follow.
    fn res_page(
        &self,
        name: &str,
        after: i64,
        upto: i64,
        limits: &Limits,
    ) -> Res<(Vec<Value>, bool)> {
        let n = limits.log_page_size as i64;
        let rows: Vec<EntryRow> = self.rows(
            "SELECT *, (SELECT MIN(n.seq) FROM ns_log n WHERE n.seq >= res_log.seq) AS ns_seq FROM res_log WHERE resource = ? AND seq > ? AND seq <= ? ORDER BY seq LIMIT ?",
            vec![name.into(), after.into(), upto.into(), (n + 1).into()],
        )?;
        let mut out = Vec::new();
        let mut bytes = 0u64;
        let mut more = false;
        for (i, r) in rows.iter().enumerate() {
            let plen = r.patches.as_ref().map(|p| p.len() as u64).unwrap_or(0);
            if i as i64 == n || (i > 0 && bytes + plen > limits.log_page_bytes) {
                more = true;
                break;
            }
            bytes += plen;
            out.push(entry_json(r)?);
        }
        Ok((out, more))
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
            "INSERT INTO ns_log (seq, id, prev, entry, author, created, gesture, undoes, config_seq, grant_ref, via) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                ctx.grant_cols().0,
                ctx.grant_cols().1,
            ],
        );
        (seq, id, stmt)
    }

    async fn route(&self, mut req: Request) -> Res<Response> {
        let path = req.path();
        let url = req.url()?;
        let segs: Vec<String> = path[1..].split('/').map(String::from).collect();
        let segs: Vec<&str> = segs.iter().map(String::as_str).collect();
        let now = Date::now().as_millis() as i64;
        let m = req.method();
        // Object-to-object requests carry no grant; the front Worker never
        // forwards `/internal/…`.
        let read = matches!(m, Method::Get | Method::Head)
            && !(segs[0] == "ns" && segs.get(2) == Some(&"principal"));
        let caller = if segs[0] == "internal" {
            crate::auth::Caller::Disabled(None)
        } else {
            self.caller(segs[1], req.headers(), read, now)?
        };
        let ctx = Ctx {
            ns: segs[1].to_string(),
            now,
            caller,
        };
        if read && segs[0] != "internal" {
            let resource = (segs[0] == "r").then(|| segs[2]);
            self.gate_read(&ctx, resource)?;
        }
        // A branch reads resources without entries of its own through its base.
        if segs[0] == "r" && segs.len() > 2 {
            self.prefetch(&[segs[2]]).await?;
        }
        match (segs[0], &segs[2..]) {
            ("ns", []) => match m {
                Method::Get | Method::Head => {
                    http::query(&url, &[])?;
                    self.get_ns(&ctx)
                }
                Method::Patch => {
                    let body = req.bytes().await?;
                    let before = self.freeze_state()?;
                    let r = self.write_config(&ctx, req.headers(), &body)?;
                    self.report_to_base(&ctx, before).await?;
                    Ok(r)
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
            ("ns", ["rev", id, "heads"]) if m == Method::Get => {
                let q = http::query(&url, &["after"])?;
                self.get_heads(&ctx, id, q.get("after").map(String::as_str).unwrap_or(""))
                    .await
            }
            ("ns", ["gestures", gesture]) if m == Method::Get => {
                let q = http::query(&url, &["after"])?;
                self.get_gestures(&ctx, gesture, q.get("after").map(String::as_str))
            }
            ("ns", ["batch"]) if m == Method::Post => {
                let q = http::query(&url, &["dry-run"])?;
                let dry = match q.get("dry-run").map(String::as_str) {
                    None => false,
                    Some("1") => true,
                    Some(_) => return Err(Err::bad("dry-run takes only 1")),
                };
                let body = req.bytes().await?;
                let before = self.freeze_state()?;
                let r = self.post_batch(&ctx, req.headers(), &body, dry).await?;
                self.report_to_base(&ctx, before).await?;
                Ok(r)
            }
            ("ns", ["grants", gid]) if m == Method::Get || m == Method::Head => {
                http::query(&url, &[])?;
                self.get_grant(&ctx, gid)
            }
            ("ns", ["principal"]) if m == Method::Get || m == Method::Head => {
                http::query(&url, &[])?;
                self.get_principal(&ctx)
            }
            ("ns", ["branches"]) => match m {
                Method::Post => {
                    let body = req.bytes().await?;
                    self.create_branch(&ctx, req.headers(), &body).await
                }
                Method::Get | Method::Head => {
                    http::query(&url, &[])?;
                    self.get_branches(&ctx)
                }
                _ => Err(Err::new(405, "bad_input", "method not allowed")),
            },
            // Internal requests from other namespaces' objects; the front
            // Worker forwards only /r/… and /ns/… (§7.6).
            ("internal", ["init"]) => {
                let body = req.bytes().await?;
                self.init_branch(&ctx, &body)
            }
            ("internal", ["branch-state"]) => {
                let body = req.bytes().await?;
                self.branch_state(&body)
            }
            ("internal", ["view", at, name]) => {
                let v = self.view_at(at, name).await?;
                http::json(200, Headers::new(), &v)
            }
            ("internal", ["log", at, name, id]) => {
                let q = http::query(&url, &["since"])?;
                let since = q.get("since").map(String::as_str).unwrap_or("");
                let at_seq = self.ns_seq_of(at)?.ok_or_else(Err::not_found)?.seq;
                match self.log_range(name, id, since, Some(at_seq)).await? {
                    Some((out, more)) => http::json(
                        200,
                        Headers::new(),
                        &obj(vec![
                            ("entries", Value::Array(out)),
                            ("more", Value::Bool(more)),
                        ]),
                    ),
                    None => Err(Err::not_found()),
                }
            }
            ("internal", ["schema", name, "rev", id]) => {
                self.get_rev(&ctx, name, id, &Headers::new()).await
            }
            ("internal", ["heads", at]) => {
                let q = http::query(&url, &["after"])?;
                self.get_heads(&ctx, at, q.get("after").map(String::as_str).unwrap_or(""))
                    .await
            }
            ("internal", ["has", at]) => match self.ns_seq_of(at)? {
                Some(_) => http::respond(204, Headers::new(), vec![]),
                None => Err(Err::not_found()),
            },
            ("internal", ["rev", at, name, id]) => match self.rev_at(at, name, id).await? {
                Some(v) => http::json(200, Headers::new(), &v),
                None => Err(Err::not_found()),
            },
            ("ns", ["log"]) if m == Method::Get => {
                let q = http::query(&url, &["since", "live", "cursor"])?;
                let upgrade = req
                    .headers()
                    .get("Upgrade")?
                    .is_some_and(|u| u.eq_ignore_ascii_case("websocket"));
                self.get_log_live(&ctx, &q, upgrade, None).await
            }
            ("r", [name]) => match m {
                Method::Get | Method::Head => {
                    http::query(&url, &[])?;
                    self.get_head(&ctx, name)
                }
                Method::Patch => {
                    let body = req.bytes().await?;
                    self.write_typed(&ctx, name, req.headers(), &body).await
                }
                Method::Delete => self.delete_resource(&ctx, name, req.headers()),
                _ => Err(Err::new(405, "bad_input", "method not allowed")),
            },
            ("r", [name, "blob", bid]) => match m {
                Method::Put => self.put_blob(&ctx, name, bid, &mut req).await,
                Method::Get | Method::Head => {
                    http::query(&url, &[])?;
                    self.get_blob(&ctx, name, bid, req.headers()).await
                }
                _ => Err(Err::new(405, "bad_input", "method not allowed")),
            },
            ("r", [name, "raw"]) if m == Method::Get || m == Method::Head => {
                http::query(&url, &[])?;
                self.get_raw(&ctx, name, None)
            }
            ("r", [name, "rev", id, "raw"]) if m == Method::Get || m == Method::Head => {
                http::query(&url, &[])?;
                self.get_raw(&ctx, name, Some(id))
            }
            ("r", [name, "rev", id]) if m == Method::Get || m == Method::Head => {
                http::query(&url, &[])?;
                self.get_rev(&ctx, name, id, req.headers()).await
            }
            ("r", [name, "log"]) if m == Method::Get => {
                let q = http::query(&url, &["since", "live", "cursor"])?;
                let upgrade = req
                    .headers()
                    .get("Upgrade")?
                    .is_some_and(|u| u.eq_ignore_ascii_case("websocket"));
                self.get_log_live(&ctx, &q, upgrade, Some(name)).await
            }
            ("r", [name, "rev", id, "log"]) if m == Method::Get => {
                let q = http::query(&url, &["since"])?;
                self.get_log_range(
                    &ctx,
                    name,
                    id,
                    q.get("since").map(String::as_str).unwrap_or(""),
                )
                .await
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
        self.one("SELECT * FROM ns_log WHERE id = ?", vec![id.text().into()])
    }

    fn get_ns_rev(&self, ctx: &Ctx, id: &str) -> Res<Response> {
        let h = self.existing()?;
        let row = self.ns_seq_of(id)?.ok_or_else(Err::not_found)?;
        let c: ConfigRow = self
            .one(
                "SELECT * FROM ns_config WHERE seq = ?",
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
            // `{ id, sub, kid }`, or null while authentication is disabled.
            let grant = match &r.grant_ref {
                Some(g) => parse_stored(g)?,
                None => Value::Null,
            };
            m.insert("grant".into(), grant);
            if let Some(v) = &r.via {
                let v = parse_stored(v)?;
                if v.as_array().is_some_and(|a| !a.is_empty()) {
                    m.insert("via".into(), v);
                }
            }
            m.insert("created".into(), s(rfc3339_ms(r.created)));
            if let Some(g) = &r.gesture {
                m.insert("gesture".into(), s(g.clone()));
            }
            if let Some(u) = &r.undoes {
                m.insert("undoes".into(), s(u.clone()));
            }
            // A batch's gestures, per resource and step (§7.4).
            if m.get("kind").and_then(Value::as_str) == Some("batch") {
                #[derive(Deserialize)]
                struct G {
                    resource: String,
                    gesture: Option<String>,
                    undoes: Option<String>,
                }
                let rows: Vec<G> = self.rows(
                    "SELECT resource, gesture, undoes FROM res_log WHERE seq > COALESCE((SELECT MAX(seq) FROM ns_log WHERE seq < ?1), 0) AND seq <= ?1 ORDER BY seq",
                    vec![r.seq.into()],
                )?;
                if rows
                    .iter()
                    .any(|g| g.gesture.is_some() || g.undoes.is_some())
                {
                    let mut by: std::collections::BTreeMap<String, Value> = Default::default();
                    for g in rows {
                        let mut step = vec![];
                        if let Some(x) = g.gesture {
                            step.push(("gesture", s(x)));
                        }
                        if let Some(x) = g.undoes {
                            step.push(("undoes", s(x)));
                        }
                        if let Value::Array(a) =
                            by.entry(g.resource).or_insert(Value::Array(vec![]))
                        {
                            a.push(obj(step));
                        }
                    }
                    m.insert("gestures".into(), Value::Object(by));
                }
            }
        }
        Ok(v)
    }

    /// Up to one page of namespace entries after `after_seq`, up to `upto_seq`.
    fn ns_page(&self, h: &NsHead, after_seq: i64, upto_seq: i64) -> Res<(Vec<NsRow>, bool)> {
        let n = h.limits.log_page_size as i64;
        let mut rows: Vec<NsRow> = self.rows(
            "SELECT * FROM ns_log WHERE seq > ? AND seq <= ? ORDER BY seq LIMIT ?",
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
    /// §7.7 for the namespace log, or with `resource` for that resource's
    /// log; without `live`, the redirect to the immutable range (§7.7 Answer).
    async fn get_log_live(
        &self,
        ctx: &Ctx,
        q: &std::collections::BTreeMap<String, String>,
        upgrade: bool,
        resource: Option<&str>,
    ) -> Res<Response> {
        let h = self.existing()?;
        let since = q.get("since").map(String::as_str).unwrap_or("");
        let rev_header = if resource.is_some() {
            "X-Revision"
        } else {
            "X-Namespace-Revision"
        };
        // The resource's head, for its redirect; and where `since` is in its log.
        let res_head = match resource {
            Some(name) => self.resource(name)?,
            None => None,
        };
        match q.get("live").map(String::as_str) {
            None => {
                if q.contains_key("cursor")
                    && (!q["cursor"].bytes().all(|b| b.is_ascii_digit()) || q["cursor"].is_empty())
                {
                    return Err(Err::bad("cursor is a decimal number"));
                }
                let hd = Headers::new();
                cache_headers(&hd, Class::HeadPointer, h.public)?;
                tags(&hd, &ctx.ns, resource)?;
                let qs = if since.is_empty() {
                    String::new()
                } else {
                    format!("?since={since}")
                };
                let location = match (resource, &res_head) {
                    (None, _) => format!("/ns/{}/rev/{}/log{qs}", ctx.ns, h.id),
                    (Some(name), Some(head)) => {
                        format!("/r/{}/{}/rev/{}/log{qs}", ctx.ns, name, head.id)
                    }
                    // In a branch, a resource read through: its base's log.
                    (Some(name), None) => match self.view(name) {
                        Some(f) => format!("/r/{}/{}/rev/{}/log{qs}", ctx.ns, name, f.id),
                        // A resource with no entries: 404, cached as short.
                        None => return Err(Err::not_found()),
                    },
                };
                hd.set("Location", &location)?;
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
        let after = match resource {
            None => self.since_seq(since)?.ok_or_else(Err::not_found)?,
            // A resource with no entries waits as for an empty `since`.
            Some(_) if since.is_empty() => 0,
            Some(name) => {
                let Some(id) = Id::parse(since) else {
                    return Err(Err::bad("malformed since"));
                };
                self.entry_by_id(name, &id)?.ok_or_else(Err::not_found)?.seq
            }
        };
        let answer = |h: &NsHead, cursor_out: i64| -> Res<Option<Response>> {
            match self.long_poll_answer(&ctx.ns, h, resource, after, cursor_out)? {
                Some((hd, body)) => Ok(Some(http::respond(200, hd, body)?)),
                None => Ok(None),
            }
        };
        let empty = |public: bool, cursor_out: i64| -> Res<Response> {
            let hd = Headers::new();
            cache_headers(&hd, Class::LongPollEmpty, public)?;
            tags(&hd, &ctx.ns, resource)?;
            if !since.is_empty() {
                hd.set(rev_header, since)?;
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
        // Hibernating costs a close event per poll; an object that stays awake
        // costs its duration whatever the number of waiters. Past about 200
        // waiters on one namespace staying awake is cheaper (bench/COSTS.md),
        // so further polls wait in here, as plain HTTP.
        if upgrade && self.state.get_websockets().len() < HIBERNATING_WAITERS_MAX {
            // Through the front Worker: wait on a hibernatable WebSocket, so
            // this object can sleep, and isn't billed, until a write.
            let pair = WebSocketPair::new()?;
            self.state
                .accept_websocket_with_tags(&pair.server, &["long-poll"]);
            pair.server.serialize_attachment(Waiter {
                ns: ctx.ns.clone(),
                resource: resource.map(String::from),
                after,
            })?;
            let armed = obj(vec![
                ("armed", Value::Bool(true)),
                ("deadline", Value::Number(deadline as f64)),
                ("cursor", Value::Number(cursor as f64)),
                ("public", Value::Bool(h.public)),
                ("since", s(since)),
                ("ns", s(ctx.ns.clone())),
                ("resource", resource.map(s).unwrap_or(Value::Null)),
            ]);
            pair.server.send_with_str(canonical_string(&armed))?;
            return Ok(Response::from_websocket(pair.client)?);
        }
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
        let author = ctx.author()?;
        let body = gate::read_body(body, &Limits::deployment_max()).map_err(gate_err)?;
        let head = self.head()?;
        let plan = match self.prepare_config(ctx, &pre, &body, &head, &author)? {
            ConfigStep::Retry(r) => return Ok(r),
            ConfigStep::Plan(p) => p,
        };
        let entry = obj(vec![("kind", s("config")), ("target", s(plan.id.text()))]);
        let prev = head
            .clone()
            .unwrap_or_else(|| make_head(0, Id([0; 20]), 0, Id([0; 20]), Value::Null));
        let (seq, ns_id_new, ns_stmt) = if head.is_none() {
            let id = ns_id(None, &canonical(&entry));
            let stmt: Stmt = (
                "INSERT INTO ns_log (seq, id, prev, entry, author, created, gesture, undoes, config_seq, grant_ref, via) VALUES (1, ?, NULL, ?, ?, ?, ?, ?, 1, ?, ?)",
                vec![
                    id.text().into(),
                    canonical_string(&entry).into(),
                    author.clone().into(),
                    ctx.now.into(),
                    g.gesture.clone().into(),
                    g.undoes.clone().into(),
                    ctx.grant_cols().0,
                    ctx.grant_cols().1,
                ],
            );
            (1, id, stmt)
        } else {
            self.ns_entry(ctx, &prev, &entry, &author, &g, prev.config_seq + 1)
        };
        let config_seq = prev.config_seq + 1;
        let mut stmts = vec![ns_stmt, plan.insert(config_seq, &author, seq)];
        stmts.extend(ctx.grant_stmt());
        self.commit(stmts)?;
        self.set_head(make_head(seq, ns_id_new, config_seq, plan.id, plan.doc));
        config_written(ctx, 201, &plan.id.text(), &ns_id_new.text())
    }

    /// Steps 2–4 of a config write (§7.4), alone or as a batch's `config`
    /// change (§7.5): the precondition (with its idempotent retry), the
    /// patches, the patch-set and document limits, and the namespace
    /// document's validation. Rules are skipped: authentication is disabled,
    /// so every config write is a `*`-key one (§1, §6.4.3).
    fn prepare_config(
        &self,
        ctx: &Ctx,
        pre: &Precondition,
        body: &Body,
        head: &Option<NsHead>,
        author: &str,
    ) -> Res<ConfigStep> {
        // Step 1 (§C.2): creating a namespace takes the operator grant that
        // creates it; any other config write, a namespace grant with `config`.
        match (ctx.grant(), head) {
            (Some(c), None) if c.operator => {
                if !c.can.contains("config") {
                    return Err(crate::auth::forbidden(
                        "the operator grant doesn't allow config",
                    ));
                }
            }
            (Some(_), None) => {
                return Err(crate::auth::unauthorized(
                    "creating a namespace takes an operator grant",
                ))
            }
            (Some(_), Some(_)) => {
                ctx.step1(&["config"], None)?;
            }
            (None, _) => {}
        }
        let (parent_id, parent_doc, limits) = match (pre, head) {
            (Precondition::NoneMatchStar, None) => (None, Value::Null, Limits::default()),
            (Precondition::NoneMatchStar, Some(_)) => {
                return Err(Err::new(412, "stale", "a namespace of that name exists"));
            }
            (Precondition::Match(_), None) => return Err(Err::not_found()),
            (Precondition::Match(want), Some(h)) => {
                if *want != h.config_id {
                    // Idempotent retry (§7.2).
                    let id = revision_id(Some(want), &body.canonical);
                    if let Some(c) = self.one::<ConfigRow>(
                        "SELECT * FROM ns_config WHERE id = ?",
                        vec![id.text().into()],
                    )? {
                        if c.author == author && self.entry_kid(c.ns_seq)? == ctx.kid() {
                            let ns: IdRow = self
                                .one("SELECT id FROM ns_log WHERE seq = ?", vec![c.ns_seq.into()])?
                                .ok_or_else(|| Err::new(500, "internal", "missing entry"))?;
                            return Ok(ConfigStep::Retry(config_written(ctx, 200, &c.id, &ns.id)?));
                        }
                    }
                    return Err(Err::new(412, "stale", "config moved")
                        .with("config", s(h.config_id.text())));
                }
                (Some(h.config_id), h.config.clone(), h.limits.clone())
            }
        };
        let ops =
            parse_patch_set(&body.value).map_err(|e| Err::new(422, "invalid", e.to_string()))?;
        let prev_doc = parent_doc.clone();
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
        let base_public = self.meta("base_public")?.is_none_or(|v| v == "1");
        branch::check_branch_fields(&prev_doc, &doc, false, base_public)?;
        // Step 6: the `*`-key guard first, then grant rules, then the
        // namespace rules in force, which `*` keys skip (§C.2, §6.4.3).
        if let Some(h) = head {
            ctx.star_guard(&writes, &prev_doc, &doc)?;
            let mut env = envelope(ctx, "config", "", &writes, &doc, &body.value);
            if let Value::Object(m) = &mut env {
                m.remove("resource");
            }
            ctx.step6("config", &env)?;
            if ctx.config_rules_apply() {
                check_rules(h, &env)?;
            }
        }
        let new_limits = Limits::from_config(&doc);
        measure(&doc, &new_limits)
            .check(&new_limits)
            .map_err(|e| limit_err(422, e.limit, e.measured.unwrap_or(0), e.max))?;
        Ok(ConfigStep::Plan(ConfigPlan {
            id: revision_id(parent_id.as_ref(), &body.canonical),
            parent: parent_id,
            patches: String::from_utf8(body.canonical.clone()).unwrap(),
            doc,
        }))
    }

    // ---------------------------------------------------------------- resources

    fn resource(&self, name: &str) -> Res<Option<Head>> {
        if let Some(h) = self.inner.borrow().heads.get(name) {
            return Ok(h.clone());
        }
        #[derive(Deserialize)]
        struct Newest {
            seq: i64,
            id: String,
            kind: i64,
            depth: i64,
        }
        let newest: Option<Newest> = self.one(
            "SELECT seq, id, kind, depth FROM res_log WHERE resource = ? ORDER BY seq DESC LIMIT 1",
            vec![name.into()],
        )?;
        let h = match newest {
            None => None,
            Some(n) => {
                // The last live revision: the head, or for a tombstone the
                // newest revision before it.
                let live = if n.kind == TOMBSTONE {
                    // A branch's tombstone over a foreign parent keeps the
                    // deleted document as a snapshot at its own seq.
                    #[derive(Deserialize)]
                    struct Seq {
                        seq: Option<i64>,
                    }
                    self.one::<Seq>(
                        "SELECT MAX(seq) AS seq FROM (SELECT seq FROM res_log WHERE resource = ?1 AND kind = 0 UNION ALL SELECT seq FROM res_snapshots WHERE resource = ?1)",
                        vec![name.into()],
                    )?
                    .and_then(|r| r.seq)
                } else {
                    Some(n.seq)
                };
                Some(Head {
                    seq: n.seq,
                    id: n.id,
                    kind: n.kind,
                    depth: n.depth,
                    live,
                })
            }
        };
        self.remember(name, h.clone());
        Ok(h)
    }

    /// The resource's own head, or in a branch, for a resource without
    /// entries here, the base's head as of `at` (§7.6 First write) with
    /// depth -1, so the first entry here has depth 0 and is snapshotted.
    fn head_or_foreign(
        &self,
        name: &str,
    ) -> Res<(Option<Head>, Option<std::rc::Rc<branch::Foreign>>)> {
        if let Some(h) = self.resource(name)? {
            return Ok((Some(h), None));
        }
        let Some(f) = self.view(name) else {
            return Ok((None, None));
        };
        let h = Head {
            seq: -1,
            id: f.id.text(),
            kind: f.kind,
            depth: -1,
            live: None,
        };
        Ok((Some(h), Some(f)))
    }

    /// The root kid recorded with a namespace entry (§7.4 `grant`).
    fn entry_kid(&self, ns_seq: i64) -> Res<Option<String>> {
        #[derive(Deserialize)]
        struct G {
            grant_ref: Option<String>,
        }
        Ok(self
            .one::<G>(
                "SELECT grant_ref FROM ns_log WHERE seq = ?",
                vec![ns_seq.into()],
            )?
            .and_then(|g| g.grant_ref)
            .and_then(|g| json::parse(g.as_bytes()).ok())
            .and_then(|g| g.get("kid").and_then(Value::as_str).map(String::from)))
    }

    fn remember(&self, name: &str, h: Option<Head>) {
        let mut inner = self.inner.borrow_mut();
        if inner.heads.len() >= HEADS_CACHED {
            inner.heads.clear();
        }
        inner.heads.insert(name.to_string(), h);
    }

    fn entry_by_seq(&self, name: &str, seq: i64) -> Res<EntryRow> {
        self.one(
            "SELECT *, (SELECT MIN(n.seq) FROM ns_log n WHERE n.seq >= res_log.seq) AS ns_seq FROM res_log WHERE resource = ? AND seq = ?",
            vec![name.into(), seq.into()],
        )?
        .ok_or_else(|| Err::new(500, "internal", "missing entry"))
    }

    fn entry_by_id(&self, name: &str, id: &Id) -> Res<Option<EntryRow>> {
        self.one(
            "SELECT *, (SELECT MIN(n.seq) FROM ns_log n WHERE n.seq >= res_log.seq) AS ns_seq FROM res_log WHERE resource = ? AND id = ?",
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
                "SELECT seq, doc FROM res_snapshots WHERE resource = ? AND seq <= ? ORDER BY seq DESC LIMIT 1",
                vec![name.into(), seq.into()],
            )?
            .ok_or_else(|| Err::new(500, "internal", "no snapshot"))?;
        let mut doc = parse_stored(&snap.doc)?;
        let rows: Vec<PatchRow> = self.rows(
            "SELECT patches FROM res_log WHERE resource = ? AND seq > ? AND seq <= ? AND kind = 0 ORDER BY seq",
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

    /// A resource write, after fetching any schema revision it needs from
    /// other namespaces. The write itself runs without an `await`, so it
    /// starts again from the top once the schemas are here.
    async fn write_typed(&self, ctx: &Ctx, name: &str, hd: &Headers, raw: &[u8]) -> Res<Response> {
        let mut fetched = std::collections::HashSet::new();
        loop {
            match self.write_resource(ctx, name, hd, raw)? {
                Step::Done(r) => return Ok(r),
                Step::NeedSchemas(paths) => self.fetch_schemas(paths, &mut fetched).await?,
            }
        }
    }

    /// Fetches schema revisions from other namespaces, in parallel. Each
    /// round of a write's checks must ask for at least one revision not
    /// fetched before: revisions are immutable, so a closure needs at most
    /// one round per level of `$ref`s. Asking again for one already fetched
    /// means it fell out of the cache meanwhile, which only a write whose
    /// closure outgrows the cache can cause.
    async fn fetch_schemas(
        &self,
        paths: Vec<String>,
        fetched: &mut std::collections::HashSet<String>,
    ) -> Res<()> {
        let new: Vec<String> = paths
            .into_iter()
            .filter(|p| fetched.insert(p.clone()))
            .collect();
        if new.is_empty() {
            return Err(Err::new(
                503,
                "internal",
                "the schemas this write uses don't fit in the server's cache",
            ));
        }
        for r in futures_util::future::join_all(new.iter().map(|p| self.fetch_schema(p))).await {
            r?;
        }
        Ok(())
    }

    /// Reads a schema revision from another namespace's object (§6.1): it
    /// must exist, not be a tombstone, and be a schema document.
    async fn fetch_schema(&self, path: &str) -> Res<()> {
        let ns = path.split('/').nth(2).unwrap_or_default();
        let unavailable = |m: &str| {
            Err::new(422, "schema_unavailable", format!("{path}: {m}")).with("path", s(path))
        };
        let stub = self.env.durable_object("NAMESPACE")?.get_by_name(ns)?;
        let mut r = stub
            // `/r/{ns}/{name}/rev/{id}` as an internal request: schema
            // revisions resolve for writes whatever the namespace's read mode.
            .fetch_with_str(&format!(
                "https://namespace/internal/{}",
                path.strip_prefix("/r/")
                    .unwrap_or(path)
                    .replacen('/', "/schema/", 1)
            ))
            .await?;
        if r.status_code() != 200 {
            return Err(unavailable(match r.status_code() {
                410 => "a tombstone, or purged",
                _ => "no such revision",
            }));
        }
        let doc =
            json::parse(&r.bytes().await?).map_err(|e| Err::new(500, "internal", e.to_string()))?;
        if schema::typed(&doc) != Ok(schema::Typed::Schema) {
            return Err(unavailable("not a schema document"));
        }
        self.remember_schema(path, doc);
        Ok(())
    }

    fn remember_schema(&self, path: &str, doc: Value) {
        let mut m = self.schemas.borrow_mut();
        if m.len() >= SCHEMAS_CACHED {
            m.clear();
            self.validators.borrow_mut().clear();
        }
        m.insert(path.to_string(), doc);
    }

    /// The schema documents of `roots`' `$ref` closure: from memory, or this
    /// namespace's storage; `Err(paths)` names those in other namespaces to
    /// fetch first.
    fn schema_closure(
        &self,
        ctx: &Ctx,
        roots: &[String],
    ) -> Res<std::result::Result<HashMap<String, Value>, Vec<String>>> {
        loop {
            let mut known = self.schemas.borrow().clone();
            known.extend(
                self.pending_schemas
                    .borrow()
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone())),
            );
            let mut missing = std::collections::BTreeSet::new();
            for r in roots {
                missing.extend(schema::closure(r, &known).1);
            }
            if missing.is_empty() {
                return Ok(Ok(known));
            }
            let mut remote = Vec::new();
            for path in missing {
                let mut parts = path.split('/').skip(2);
                let (ns, name, id) = (
                    parts.next().unwrap_or_default(),
                    parts.next().unwrap_or_default(),
                    parts.nth(1).unwrap_or_default(),
                );
                if ns != ctx.ns {
                    remote.push(path);
                    continue;
                }
                let unavailable = |m: &str| {
                    Err::new(422, "schema_unavailable", format!("{path}: {m}"))
                        .with("path", s(path.clone()))
                };
                let Some(id) = Id::parse(id) else {
                    return Err(unavailable("not a revision id"));
                };
                let Some(e) = self.entry_by_id(name, &id)? else {
                    return Err(unavailable("no such revision"));
                };
                if e.kind == TOMBSTONE {
                    return Err(unavailable("a tombstone"));
                }
                let doc = self.doc_at(name, e.seq, false)?;
                if schema::typed(&doc) != Ok(schema::Typed::Schema) {
                    return Err(unavailable("not a schema document"));
                }
                self.remember_schema(&path, doc);
            }
            if !remote.is_empty() {
                return Ok(Err(remote));
            }
        }
    }

    /// Step 5 of §6.2 on the resulting document.
    fn check_typed(&self, ctx: &Ctx, doc: &Value) -> Res<Option<Vec<String>>> {
        match schema::typed(doc).map_err(schema_err)? {
            schema::Typed::Untyped => Ok(None),
            schema::Typed::Schema => {
                // A schema: its own checks, and its references resolve now.
                let refs = schema::check_schema(doc).map_err(schema_err)?;
                let roots: Vec<String> = refs.paths.iter().cloned().collect();
                match self.schema_closure(ctx, &roots)? {
                    Err(remote) => Ok(Some(remote)),
                    Ok(known) => {
                        schema::check_fragments(&refs, &known).map_err(schema_err)?;
                        Ok(None)
                    }
                }
            }
            schema::Typed::Instance(path) => {
                // A compiled validator had its whole closure: revisions are
                // immutable, so it needs nothing loaded again.
                if let Some(v) = self.validators.borrow().get(&path).cloned() {
                    v.validate(doc).map_err(schema_err)?;
                    return Ok(None);
                }
                let known = match self.schema_closure(ctx, std::slice::from_ref(&path))? {
                    Err(remote) => return Ok(Some(remote)),
                    Ok(k) => k,
                };
                let cached = self.validators.borrow().get(&path).cloned();
                let v = match cached {
                    Some(v) => v,
                    None => {
                        let v =
                            std::rc::Rc::new(schema::compile(&path, &known).map_err(schema_err)?);
                        // Not from a batch's uncommitted schemas.
                        if self.pending_schemas.borrow().is_empty() {
                            self.validators.borrow_mut().insert(path.clone(), v.clone());
                        }
                        v
                    }
                };
                v.validate(doc).map_err(schema_err)?;
                Ok(None)
            }
        }
    }

    fn write_resource(&self, ctx: &Ctx, name: &str, hd: &Headers, raw: &[u8]) -> Res<Step> {
        http::content_type_is(hd, "application/json-patch+json")?;
        let pre = http::precondition(hd)?;
        let g = Gesture::from(hd)?;
        let author = ctx.author()?;
        // Step 1: the verbs this write may be (§C.2, several verbs).
        let verbs: &[&'static str] = match &pre {
            Precondition::NoneMatchStar => &["create"],
            Precondition::Match(_) => &["append", "restore"],
        };
        let candidates = ctx.step1(verbs, Some(name))?;
        let body: Body = gate::read_body(raw, &Limits::deployment_max()).map_err(gate_err)?;
        let ns = self.existing()?;
        let (cur, foreign) = self.head_or_foreign(name)?;
        // Step 2.1: idempotent retry.
        let parent = match &pre {
            Precondition::Match(p) => Some(*p),
            Precondition::NoneMatchStar => None,
        };
        let id = gate::id_for(parent.as_ref(), &body);
        // The entry a retry would find exists only if the head moved past the
        // parent, so the lookup is needed only when the precondition fails.
        let pre_holds = match (&parent, &cur) {
            (None, None) => true,
            (Some(p), Some(h)) => p.text() == h.id,
            _ => false,
        };
        if !pre_holds && cur.is_some() {
            if let Some(e) = self.entry_by_id(name, &id)? {
                if e.author == author
                    && e.kid == ctx.kid()
                    && e.parent.as_deref().and_then(Id::parse) == parent
                {
                    return self.written(ctx, name, &e, 200).map(Step::Done);
                }
            }
        }
        // Step 2.2: settle the verb; 2.4 frozen; then the precondition.
        let kind = match (&pre, &cur) {
            (Precondition::NoneMatchStar, _) => WriteKind::Create,
            (Precondition::Match(_), Some(e)) if e.kind == TOMBSTONE => WriteKind::Restore,
            (Precondition::Match(_), _) => WriteKind::Append,
        };
        let verb = match kind {
            WriteKind::Create => "create",
            WriteKind::Append => "append",
            WriteKind::Restore => "restore",
        };
        if !candidates.contains(&verb) {
            return Err(crate::auth::forbidden(format!(
                "the grant doesn't allow {verb} here"
            )));
        }
        if ns.frozen {
            return Err(Err::new(409, "frozen", "the namespace is frozen"));
        }
        match (&pre, &cur) {
            (Precondition::NoneMatchStar, Some(e)) if e.kind == TOMBSTONE => {
                return Err(
                    Err::new(410, "gone", "the resource is deleted").with("head", s(e.id.clone()))
                );
            }
            (Precondition::NoneMatchStar, Some(e)) => {
                return Err(
                    Err::new(412, "stale", "the resource exists").with("head", s(e.id.clone()))
                );
            }
            (Precondition::Match(_), None) => {
                return Err(Err::new(412, "stale", "no such resource"))
            }
            (Precondition::Match(p), Some(e)) if p.text() != e.id => {
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
            // A first write in a branch builds on the base's document; its
            // entry is snapshotted (depth 0), having no parent here.
            (_, Some(_)) if foreign.is_some() => (
                foreign
                    .as_ref()
                    .and_then(|f| f.doc.clone())
                    .unwrap_or(Value::Null),
                0,
            ),
            (WriteKind::Append, Some(e)) => (self.doc_at(name, e.seq, true)?, e.depth + 1),
            (WriteKind::Restore, Some(e)) => {
                let live = e.live.ok_or_else(|| {
                    Err::new(500, "internal", "tombstone without a live revision")
                })?;
                (self.doc_at(name, live, true)?, e.depth + 1)
            }
            _ => unreachable!(),
        };
        let p = gate::apply_and_check(parent.as_ref(), doc, &body, kind, &ns.limits)
            .map_err(gate_err)?;
        // Step 4, blob references: each available to the resource.
        let blob_stmts = self.check_blob_refs(name, &p.doc, &ctx.uploader()?)?;
        // Step 5: the resulting document against its schema.
        if let Some(remote) = self.check_typed(ctx, &p.doc)? {
            return Ok(Step::NeedSchemas(remote));
        }
        // Step 6: namespace rules (§6.4), against the change envelope.
        let action = match kind {
            WriteKind::Create => "create",
            WriteKind::Append => "append",
            WriteKind::Restore => "restore",
        };
        let env = envelope(ctx, action, name, &p.writes, &p.doc, &body.value);
        ctx.step6(action, &env)?;
        check_rules(&ns, &env)?;
        // Step 7: hash and insert. The resource entry takes its namespace
        // entry's sequence number.
        let entry = obj(vec![
            ("resource", s(name)),
            ("kind", s("head")),
            ("target", s(p.id.text())),
        ]);
        let (ns_seq, ns_id_new, ns_stmt) =
            self.ns_entry(ctx, &ns, &entry, &author, &g, ns.config_seq);
        let seq = ns_seq;
        let canon_patches = String::from_utf8(body.canonical).unwrap();
        let mut stmts = vec![
            ns_stmt,
            (
                "INSERT INTO res_log (resource, seq, id, parent, kind, patches, author, created, gesture, undoes, depth, kid) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    name.into(),
                    seq.into(),
                    p.id.text().into(),
                    parent.map(|p| p.text()).into(),
                    canon_patches.into(),
                    author.clone().into(),
                    ctx.now.into(),
                    g.gesture.clone().into(),
                    g.undoes.clone().into(),
                    depth.into(),
                    ctx.kid().into(),
                ],
            ),
        ];
        if depth % SNAPSHOT_EVERY == 0 {
            stmts.push((
                "INSERT INTO res_snapshots (resource, seq, doc) VALUES (?, ?, ?)",
                vec![name.into(), seq.into(), canonical_string(&p.doc).into()],
            ));
        }
        stmts.extend(blob_stmts);
        stmts.extend(ctx.grant_stmt());
        self.commit(stmts)?;
        self.remember(
            name,
            Some(Head {
                seq,
                id: p.id.text(),
                kind: REV,
                depth,
                live: Some(seq),
            }),
        );
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
            kid: ctx.kid(),
        };
        written_response(ctx, name, &e, &ns_id_new.text(), 201).map(Step::Done)
    }

    fn written(&self, ctx: &Ctx, name: &str, e: &EntryRow, status: u16) -> Res<Response> {
        let ns: IdRow = self
            .one("SELECT id FROM ns_log WHERE seq = ?", vec![e.ns_seq.into()])?
            .ok_or_else(|| Err::new(500, "internal", "missing entry"))?;
        written_response(ctx, name, e, &ns.id, status)
    }

    fn delete_resource(&self, ctx: &Ctx, name: &str, hd: &Headers) -> Res<Response> {
        let pre = http::precondition(hd)?;
        let g = Gesture::from(hd)?;
        let author = ctx.author()?;
        let Precondition::Match(parent) = pre else {
            return Err(Err::new(
                428,
                "precondition_required",
                "DELETE takes If-Match",
            ));
        };
        ctx.step1(&["delete"], Some(name))?;
        let ns = self.existing()?;
        let tomb = tombstone_id(&parent);
        let (cur, foreign) = self.head_or_foreign(name)?;
        if cur.as_ref().is_some_and(|h| h.id != parent.text()) {
            if let Some(e) = self.entry_by_id(name, &tomb)? {
                if e.author == author && e.kid == ctx.kid() {
                    return self.written(ctx, name, &e, 200);
                }
            }
        }
        if ns.frozen {
            return Err(Err::new(409, "frozen", "the namespace is frozen"));
        }
        let Some(head) = cur else {
            return Err(Err::new(412, "stale", "no such resource"));
        };
        if head.kind == TOMBSTONE {
            return Err(Err::new(410, "gone", "the resource is deleted").with("head", s(head.id)));
        }
        if head.id != parent.text() {
            return Err(Err::new(412, "stale", "the head moved").with("head", s(head.id)));
        }
        // Step 6: rules see the document being deleted, with no writes (§6.4.1).
        let deleted = match &foreign {
            Some(f) => Some(f.doc.clone().unwrap_or(Value::Null)),
            None if ns.rules.is_some() || ctx.grant().is_some() => {
                Some(self.doc_at(name, head.seq, false)?)
            }
            None => None,
        };
        if let Some(doc) = &deleted {
            let env = envelope(ctx, "delete", name, &[], doc, &Value::Array(vec![]));
            ctx.step6("delete", &env)?;
            check_rules(&ns, &env)?;
        }
        let entry = obj(vec![
            ("resource", s(name)),
            ("kind", s("tombstone")),
            ("target", s(tomb.text())),
        ]);
        let (ns_seq, ns_id_new, ns_stmt) =
            self.ns_entry(ctx, &ns, &entry, &author, &g, ns.config_seq);
        let seq = ns_seq;
        let mut stmts = Vec::new();
        if let (Some(_), Some(doc)) = (&foreign, &deleted) {
            // The deleted document is the base's: kept here for a restore.
            stmts.push((
                "INSERT INTO res_snapshots (resource, seq, doc) VALUES (?, ?, ?)",
                vec![name.into(), seq.into(), canonical_string(doc).into()],
            ));
        }
        stmts.extend([
            ns_stmt,
            (
                "INSERT INTO res_log (resource, seq, id, parent, kind, patches, author, created, gesture, undoes, depth, kid) VALUES (?, ?, ?, ?, 1, NULL, ?, ?, ?, ?, ?, ?)",
                vec![
                    name.into(),
                    seq.into(),
                    tomb.text().into(),
                    parent.text().into(),
                    author.clone().into(),
                    ctx.now.into(),
                    g.gesture.clone().into(),
                    g.undoes.clone().into(),
                    (head.depth + 1).into(),
                    ctx.kid().into(),
                ],
            ),
        ]);
        stmts.extend(ctx.grant_stmt());
        self.commit(stmts)?;
        self.remember(
            name,
            Some(Head {
                seq,
                id: tomb.text(),
                kind: TOMBSTONE,
                depth: head.depth + 1,
                live: if foreign.is_some() {
                    Some(seq)
                } else {
                    head.live.or(Some(head.seq))
                },
            }),
        );
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
            kid: ctx.kid(),
        };
        written_response(ctx, name, &e, &ns_id_new.text(), 200)
    }

    fn get_head(&self, ctx: &Ctx, name: &str) -> Res<Response> {
        let ns = self.existing()?;
        let Some(head) = self.resource(name)? else {
            return self.get_head_foreign(ctx, &ns, name);
        };
        let hd = Headers::new();
        cache_headers(&hd, Class::HeadPointer, ns.public)?;
        tags(&hd, &ctx.ns, Some(name))?;
        hd.set("ETag", &format!("\"{}\"", head.id))?;
        if head.kind == TOMBSTONE {
            let last = head
                .live
                .map(|l| self.entry_by_seq(name, l))
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

    async fn get_rev(&self, ctx: &Ctx, name: &str, id: &str, req: &Headers) -> Res<Response> {
        let ns = self.existing()?;
        let Some(id) = Id::parse(id) else {
            return Err(Err::bad("malformed id"));
        };
        let Some(e) = self.entry_by_id(name, &id)? else {
            return self.get_rev_foreign(ctx, &ns, name, &id, req).await;
        };
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
        let digest = http::sha256(&bytes).await?;
        hd.set("Repr-Digest", &format!("sha-256=:{}:", base64(&digest)))?;
        hd.set("Content-Type", "application/json")?;
        http::respond(200, hd, bytes)
    }

    /// `GET /ns/{ns}/rev/{ns_id}/heads` (§7.4): each resource's newest
    /// entry as of that revision, by name, after `after`, a page at a time.
    async fn get_heads(&self, ctx: &Ctx, id: &str, after: &str) -> Res<Response> {
        let h = self.existing()?;
        let at = self.ns_seq_of(id)?.ok_or_else(Err::not_found)?;
        let n = h.limits.log_page_size as usize;
        #[derive(Deserialize)]
        struct HeadRow {
            resource: String,
            id: String,
            kind: i64,
            created: i64,
        }
        let rows: Vec<HeadRow> = self.rows(
            "SELECT r.resource AS resource, r.id AS id, r.kind AS kind, r.created AS created FROM (SELECT resource, MAX(seq) AS m FROM res_log WHERE seq <= ?1 AND resource > ?2 GROUP BY resource ORDER BY resource LIMIT ?3) g JOIN res_log r ON r.resource = g.resource AND r.seq = g.m ORDER BY r.resource",
            vec![at.seq.into(), after.into(), (n as i64 + 1).into()],
        )?;
        let own_more = rows.len() > n;
        let own: Vec<(String, Value)> = rows
            .into_iter()
            .take(n)
            .map(|r| {
                let v = obj(vec![
                    ("resource", s(r.resource.clone())),
                    (
                        "kind",
                        s(if r.kind == TOMBSTONE {
                            "tombstone"
                        } else {
                            "head"
                        }),
                    ),
                    ("target", s(r.id)),
                    ("created", s(rfc3339_ms(r.created))),
                ]);
                (r.resource, v)
            })
            .collect();
        // In a branch, the resources read through: the base's page at `at`,
        // merged by name, ours winning; a page ends where either source's did.
        let mut bound = own_more
            .then(|| own.last().map(|(k, _)| k.clone()))
            .flatten();
        let mut merged: std::collections::BTreeMap<String, Value> = Default::default();
        if let Some((base, base_next)) = self.base_heads(&h, after).await? {
            for v in base {
                if let Some(k) = v.get("resource").and_then(Value::as_str) {
                    merged.insert(k.to_string(), v.clone());
                }
            }
            bound = match (bound, base_next) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
        merged.extend(own);
        let mut page: Vec<(String, Value)> = merged
            .into_iter()
            .filter(|(k, _)| bound.as_ref().is_none_or(|b| k <= b))
            .collect();
        let more = bound.is_some() || page.len() > n;
        page.truncate(n);
        let next = page.last().map(|(k, _)| k.clone()).filter(|_| more);
        let mut body = vec![(
            "heads",
            Value::Array(page.into_iter().map(|(_, v)| v).collect()),
        )];
        if let Some(k) = next {
            body.push(("next", s(k)));
        }
        let hd = Headers::new();
        cache_headers(&hd, Class::Immutable, h.public)?;
        hd.set("Cache-Tag", &format!("ns:{0},heads:{0}", ctx.ns))?;
        hd.set("Surrogate-Key", &format!("ns:{0} heads:{0}", ctx.ns))?;
        http::json(200, hd, &obj(body))
    }

    /// `GET /ns/{ns}/gestures/{gesture}` (§7.4): the entries written with a
    /// gesture or undoing it, oldest first, a page at a time.
    fn get_gestures(&self, ctx: &Ctx, gesture: &str, after: Option<&str>) -> Res<Response> {
        if !patchlog_core::names::is_base32_26(gesture) {
            return Err(Err::bad("a gesture is 26 base32 characters"));
        }
        let h = self.existing()?;
        let after_seq = match after {
            None => 0,
            Some(a) => {
                let Some((name, id)) = a.split_once('/') else {
                    return Err(Err::bad("after is {resource}/{id}"));
                };
                let (Some(id), true) =
                    (Id::parse(id), patchlog_core::names::is_resource_name(name))
                else {
                    return Err(Err::bad("after is {resource}/{id}"));
                };
                match self.entry_by_id(name, &id)? {
                    Some(e)
                        if e.gesture.as_deref() == Some(gesture)
                            || e.undoes.as_deref() == Some(gesture) =>
                    {
                        e.seq
                    }
                    _ => return Err(Err::not_found()),
                }
            }
        };
        let n = h.limits.log_page_size as i64;
        #[derive(Deserialize)]
        struct Row {
            resource: String,
            id: String,
            kind: i64,
            gesture: Option<String>,
            undoes: Option<String>,
            author: String,
            ns_id: String,
        }
        let rows: Vec<Row> = self.rows(
            "SELECT r.resource AS resource, r.id AS id, r.kind AS kind, r.gesture AS gesture, r.undoes AS undoes, r.author AS author, n.id AS ns_id FROM res_log r JOIN ns_log n ON n.seq = (SELECT MIN(seq) FROM ns_log WHERE seq >= r.seq) WHERE (r.gesture = ?1 OR r.undoes = ?1) AND r.seq > ?2 ORDER BY r.seq LIMIT ?3",
            vec![gesture.into(), after_seq.into(), (n + 1).into()],
        )?;
        let more = rows.len() as i64 > n;
        let page: Vec<Value> = rows
            .iter()
            .take(n as usize)
            .map(|r| {
                let mut m = vec![
                    ("resource", s(r.resource.clone())),
                    ("id", s(r.id.clone())),
                    (
                        "kind",
                        s(if r.kind == TOMBSTONE {
                            "tombstone"
                        } else {
                            "rev"
                        }),
                    ),
                    ("author", s(r.author.clone())),
                    ("ns_id", s(r.ns_id.clone())),
                ];
                if let Some(g) = &r.gesture {
                    m.push(("gesture", s(g.clone())));
                }
                if let Some(u) = &r.undoes {
                    m.push(("undoes", s(u.clone())));
                }
                obj(m)
            })
            .collect();
        let hd = Headers::new();
        cache_headers(&hd, Class::NoStore, h.public)?;
        tags(&hd, &ctx.ns, None)?;
        if more {
            let last = &rows[n as usize - 1];
            hd.set("X-Log-Next", &format!("{}/{}", last.resource, last.id))?;
        }
        http::json(200, hd, &Value::Array(page))
    }

    async fn get_log_range(&self, ctx: &Ctx, name: &str, id: &str, since: &str) -> Res<Response> {
        let ns = self.existing()?;
        let (out, more) = self
            .log_range(name, id, since, None)
            .await?
            .ok_or_else(Err::not_found)?;
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

/// A config change ready to record, or the answer to an idempotent retry.
enum ConfigStep {
    Plan(ConfigPlan),
    Retry(Response),
}

struct ConfigPlan {
    id: Id,
    parent: Option<Id>,
    patches: String,
    doc: Value,
}

impl ConfigPlan {
    /// The `ns_config` row, recorded by the namespace entry `ns_seq`.
    fn insert(&self, config_seq: i64, author: &str, ns_seq: i64) -> Stmt {
        (
            "INSERT INTO ns_config (seq, id, parent, patches, doc, author, ns_seq) VALUES (?, ?, ?, ?, ?, ?, ?)",
            vec![
                config_seq.into(),
                self.id.text().into(),
                self.parent.map(|p| p.text()).into(),
                self.patches.clone().into(),
                canonical_string(&self.doc).into(),
                author.into(),
                ns_seq.into(),
            ],
        )
    }
}

/// What a long-poll waiting on a hibernatable WebSocket needs to be answered.
#[derive(serde::Serialize, Deserialize)]
struct Waiter {
    ns: String,
    /// The resource whose log is followed, or none for the namespace log.
    #[serde(default)]
    resource: Option<String>,
    after: i64,
}

/// A long-poll answer for the front Worker: its status and headers as JSON
/// on the first line, then the body.
fn waiter_message(status: u16, hd: &Headers, body: &[u8]) -> String {
    let headers: Vec<Value> = hd
        .entries()
        .map(|(k, v)| Value::Array(vec![s(k), s(v)]))
        .collect();
    let head = obj(vec![
        ("status", Value::Number(status as f64)),
        ("headers", Value::Array(headers)),
    ]);
    format!(
        "{}\n{}",
        canonical_string(&head),
        String::from_utf8_lossy(body)
    )
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
    // Stored rules were validated when written. Ones that don't compile now
    // (a later build's stricter checks) stay raw and fail closed.
    let rules = config
        .get("rules")
        .filter(|r| r.as_array().is_some_and(|a| !a.is_empty()))
        .map(|r| match rules::CompiledRules::new(r) {
            Ok(c) => Rules::Compiled(std::rc::Rc::new(c)),
            Err(_) => Rules::Raw(r.clone()),
        });
    NsHead {
        seq,
        id,
        config_seq,
        config_id,
        config,
        limits,
        frozen,
        public,
        rules,
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
        "rulesPerNamespace" => "rulesPerNamespace",
        _ => "limit",
    };
    Err::new(status, "limit", format!("{limit} exceeded"))
        .with("limit", s(limit))
        .with("measured", Value::Number(measured as f64))
        .with("max", Value::Number(max as f64))
}

/// The change envelope of §6.4.1. Authentication is disabled (§1), so it
/// has no `principal`.
fn envelope(
    ctx: &Ctx,
    action: &str,
    resource: &str,
    writes: &[String],
    doc: &Value,
    patches: &Value,
) -> Value {
    let mut m = vec![
        ("action", s(action)),
        ("resource", s(resource)),
        ("now", s(rfc3339_ms(ctx.now))),
        (
            "writes",
            Value::Array(writes.iter().map(|w| s(w.clone())).collect()),
        ),
        ("doc", doc.clone()),
        ("patches", patches.clone()),
    ];
    // Absent while authentication is disabled (§6.4.1).
    if let Some(p) = ctx.principal() {
        m.push(("principal", p));
    }
    obj(m)
}

/// Step 6 of §6.2: the namespace's rules; a failure is `422 rule` (§12.1).
fn check_rules(ns: &NsHead, envelope: &Value) -> Res<()> {
    let result = match &ns.rules {
        None => return Ok(()),
        Some(Rules::Compiled(c)) => c.evaluate(envelope),
        Some(Rules::Raw(v)) => rules::evaluate(v, envelope),
    };
    result.map_err(|f| {
        Err::new(422, "rule", f.message)
            .with("rule", Value::Number(f.rule as f64))
            .with("path", s(f.path))
    })
}

fn schema_err(e: SchemaError) -> Err {
    match e {
        SchemaError::Ref(m) => Err::new(422, "schema_ref", m),
        SchemaError::Unavailable { path, message } => {
            Err::new(422, "schema_unavailable", format!("{path}: {message}")).with("path", s(path))
        }
        SchemaError::Invalid(errors) => {
            let message = errors.first().map(|(_, m)| m.clone()).unwrap_or_default();
            Err::new(422, "invalid", message).with(
                "errors",
                Value::Array(
                    errors
                        .into_iter()
                        .map(|(pointer, message)| {
                            obj(vec![("pointer", s(pointer)), ("message", s(message))])
                        })
                        .collect(),
                ),
            )
        }
    }
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
            "catalog" | "catalogs" | "allowances" | "merge" | "merged" | "cleanup"
            | "abandoned" | "rules" | "keys" | "roles" | "revoked" => {
                let checked = match k.as_str() {
                    "keys" => crate::nsdoc::keys(v, &p),
                    "roles" => crate::nsdoc::roles(v, &p),
                    "revoked" => crate::nsdoc::revoked(v, &p),
                    "catalog" => crate::nsdoc::catalog(v, &p),
                    "catalogs" => crate::nsdoc::catalogs(v, &p),
                    "allowances" => crate::nsdoc::allowances(v, &p),
                    "merge" => crate::nsdoc::merge(v, &p),
                    "merged" => crate::nsdoc::merged(v, &p),
                    "cleanup" => crate::nsdoc::cleanup(v, &p),
                    "abandoned" => match v {
                        Value::Bool(_) => Ok(()),
                        _ => Err((p.clone(), "abandoned is a boolean".to_string())),
                    },
                    // §6.4.2, and at most rulesPerNamespace forms (§12.2).
                    _ => match rules::validate(v, RULES_PER_NAMESPACE) {
                        Ok(()) => Ok(()),
                        Err(rules::RulesError::Invalid(errs)) => {
                            let errors = Value::Array(
                                errs.into_iter()
                                    .map(|(pointer, message)| {
                                        obj(vec![("pointer", s(pointer)), ("message", s(message))])
                                    })
                                    .collect(),
                            );
                            return Err(Err::new(422, "invalid", "invalid namespace document")
                                .with("errors", errors));
                        }
                        Err(rules::RulesError::Limit { measured, max }) => {
                            return Err(limit_err(422, "rulesPerNamespace", measured, max));
                        }
                    },
                };
                if let Err((pointer, message)) = checked {
                    return Err(invalid_config(&pointer, &message));
                }
            }
            // Checked against the previous document by `check_branch_fields`.
            "base" | "successor" => {}
            "retention" | "encryption" | "maxLag" | "drafts" | "signatures" | "nonce"
            | "schemaReads" => {
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
