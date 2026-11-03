//! Batches (§7.5): writes to several resources of the namespace, and
//! optionally its document, checked step by step as §6.2 says and recorded
//! all or nothing as one `batch` entry.
//!
//! Sequence numbers: every resource entry needs its own, and the namespace
//! entry recording them takes the last of the run, so a resource entry's
//! namespace entry is the first one at or after it.

use super::*;

/// Items per batch and total canonical patch-set bytes (§12.2 defaults,
/// which are also this deployment's maximums).
const ITEMS_PER_BATCH: u64 = 1000;
const BATCH_SIZE: u64 = 16 * 1024 * 1024;

enum Op {
    Patch(Body),
    Delete,
}

struct StepIn {
    op: Op,
    gesture: Option<String>,
    undoes: Option<String>,
}

struct ItemIn {
    resource: String,
    pre: Precondition,
    steps: Vec<StepIn>,
}

struct BatchIn {
    items: Vec<ItemIn>,
    config: Option<(Precondition, Body)>,
    source: Option<Value>,
}

/// A resource entry the batch will write.
struct Planned {
    resource: String,
    id: Id,
    parent: Option<Id>,
    kind: i64,
    patches: Option<String>,
    /// The document after a revision, for its snapshot and the caches.
    doc: Option<Value>,
    doc_size: u64,
    depth: i64,
    gesture: Option<String>,
    undoes: Option<String>,
}

/// An item that fails, at a step of §6.2 (2 for preconditions, 3–6 after).
struct Failure {
    index: usize,
    step: u8,
    err: Err,
}

fn gesture_field(v: Option<&Value>, what: &str) -> Res<Option<String>> {
    match v {
        None => Ok(None),
        Some(Value::String(g)) if patchlog_core::names::is_base32_26(g) => Ok(Some(g.clone())),
        Some(_) => Err(Err::bad(format!("{what} is 26 base32 characters"))),
    }
}

fn body_of(v: &Value) -> Body {
    Body {
        value: v.clone(),
        canonical: canonical(v),
    }
}

/// Request-shape checks (§7.5 Items): `400`, `413` and `428` before any state.
fn parse(raw: &[u8], hd: &Headers) -> Res<BatchIn> {
    let max = 4 * BATCH_SIZE.max(Limits::deployment_max().document_size);
    if raw.len() as u64 > max {
        return Err(limit_err(413, "batchSize", raw.len() as u64, BATCH_SIZE));
    }
    let v = json::parse(raw).map_err(|e| Err::bad(e.to_string()))?;
    let Some(m) = v.as_object() else {
        return Err(Err::bad("a batch is an object"));
    };
    for k in m.keys() {
        if !matches!(
            k.as_str(),
            "items" | "config" | "source" | "gesture" | "undoes"
        ) {
            return Err(Err::bad(format!("unknown member {k:?}")));
        }
    }
    // Batch-wide gesture defaults, from the body or the headers but not both.
    let (hg, hu) = (
        http::gesture_header(hd, "Gesture")?,
        http::gesture_header(hd, "Undoes")?,
    );
    let (bg, bu) = (
        gesture_field(m.get("gesture"), "gesture")?,
        gesture_field(m.get("undoes"), "undoes")?,
    );
    if (hg.is_some() && bg.is_some()) || (hu.is_some() && bu.is_some()) {
        return Err(Err::bad(
            "gesture or undoes sent both as a header and in the body",
        ));
    }
    let (dg, du) = (hg.or(bg), hu.or(bu));

    let mut items = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    if let Some(list) = m.get("items") {
        let Some(list) = list.as_array() else {
            return Err(Err::bad("items is an array"));
        };
        for (i, it) in list.iter().enumerate() {
            let Some(im) = it.as_object() else {
                return Err(Err::bad(format!("item {i} is an object")));
            };
            let Some(name) = im.get("resource").and_then(Value::as_str) else {
                return Err(Err::bad(format!("item {i} names its resource")));
            };
            if !patchlog_core::names::is_resource_name(name) {
                return Err(Err::bad(format!("item {i}: malformed resource name")));
            }
            if !seen.insert(name.to_string()) {
                return Err(Err::bad(format!("resource {name} is named twice")));
            }
            let pre = match (im.get("ifMatch"), im.get("ifNoneMatch")) {
                (Some(_), Some(_)) => {
                    return Err(Err::bad(format!(
                        "item {i} has both ifMatch and ifNoneMatch"
                    )))
                }
                (Some(Value::String(id)), None) => Precondition::Match(
                    Id::parse(id).ok_or_else(|| Err::bad(format!("item {i}: ifMatch is an id")))?,
                ),
                (None, Some(Value::String(star))) if star == "*" => Precondition::NoneMatchStar,
                (None, None) => {
                    return Err(Err::new(
                        428,
                        "precondition_required",
                        format!("item {i} has no precondition"),
                    ));
                }
                _ => return Err(Err::bad(format!("item {i}: malformed precondition"))),
            };
            let (ig, iu) = (
                gesture_field(im.get("gesture"), "gesture")?,
                gesture_field(im.get("undoes"), "undoes")?,
            );
            let Some(steps) = im
                .get("steps")
                .and_then(Value::as_array)
                .filter(|s| !s.is_empty())
            else {
                return Err(Err::bad(format!("item {i} has no steps")));
            };
            let mut out = Vec::new();
            for (j, st) in steps.iter().enumerate() {
                let bad = || {
                    Err::bad(format!("item {i}, step {j}: a patch set, \"delete\", or an object with patches or delete"))
                };
                let (op, sg, su) = match st {
                    Value::Array(_) => (Op::Patch(body_of(st)), None, None),
                    Value::String(d) if d == "delete" => (Op::Delete, None, None),
                    Value::Object(sm) => {
                        for k in sm.keys() {
                            if !matches!(
                                k.as_str(),
                                "patches" | "delete" | "gesture" | "undoes" | "signature"
                            ) {
                                return Err(bad());
                            }
                        }
                        let op = match (sm.get("patches"), sm.get("delete")) {
                            (Some(p @ Value::Array(_)), None) => Op::Patch(body_of(p)),
                            (None, Some(Value::Bool(true))) => Op::Delete,
                            _ => return Err(bad()),
                        };
                        (
                            op,
                            gesture_field(sm.get("gesture"), "gesture")?,
                            gesture_field(sm.get("undoes"), "undoes")?,
                        )
                    }
                    _ => return Err(bad()),
                };
                out.push(StepIn {
                    op,
                    gesture: sg.or_else(|| ig.clone()).or_else(|| dg.clone()),
                    undoes: su.or_else(|| iu.clone()).or_else(|| du.clone()),
                });
            }
            items.push(ItemIn {
                resource: name.to_string(),
                pre,
                steps: out,
            });
        }
    }
    let config = match m.get("config") {
        None => None,
        Some(c) => {
            let Some(cm) = c.as_object() else {
                return Err(Err::bad("config is an object"));
            };
            let pre = match (cm.get("ifMatch"), cm.get("ifNoneMatch")) {
                (Some(Value::String(id)), None) => Precondition::Match(
                    Id::parse(id).ok_or_else(|| Err::bad("config.ifMatch is a config id"))?,
                ),
                (None, None) => {
                    return Err(Err::new(
                        428,
                        "precondition_required",
                        "config needs ifMatch",
                    ))
                }
                _ => return Err(Err::bad("config takes ifMatch, the config id")),
            };
            let Some(p @ Value::Array(_)) = cm.get("patches") else {
                return Err(Err::bad("config.patches is a patch set"));
            };
            Some((pre, body_of(p)))
        }
    };
    if items.is_empty() && config.is_none() {
        return Err(Err::bad("a batch has items or a config change"));
    }
    let source = m.get("source").cloned();
    if let Some(src) = &source {
        check_source_shape(src, items.len())?;
    }
    Ok(BatchIn {
        items,
        config,
        source,
    })
}

/// `source` (§3.5): `{ "origin"?, "ns", "at", "bundle"?, "ids"? }`.
fn check_source_shape(v: &Value, items: usize) -> Res<()> {
    let bad = |m: &str| Err::bad(format!("source: {m}"));
    let Some(m) = v.as_object() else {
        return Err(bad("an object"));
    };
    for k in m.keys() {
        if !matches!(k.as_str(), "origin" | "ns" | "at" | "bundle" | "ids") {
            return Err(bad(&format!("unknown member {k:?}")));
        }
    }
    if !m
        .get("ns")
        .and_then(Value::as_str)
        .is_some_and(patchlog_core::names::is_namespace_name)
    {
        return Err(bad("ns is a namespace name"));
    }
    if !m
        .get("at")
        .and_then(Value::as_str)
        .is_some_and(|a| Id::parse(a).is_some())
    {
        return Err(bad("at is a namespace revision id"));
    }
    if let Some(o) = m.get("origin") {
        if !o
            .as_str()
            .is_some_and(|o| o.starts_with("https://") || o.starts_with("http://"))
        {
            return Err(bad("origin is an origin"));
        }
    }
    if let Some(b) = m.get("bundle") {
        if !b.as_str().is_some_and(|b| Id::parse(b).is_some()) {
            return Err(bad("bundle is a digest"));
        }
    }
    if let Some(ids) = m.get("ids") {
        let Some(im) = ids.as_object() else {
            return Err(bad("ids is an object"));
        };
        if im.len() > items {
            return Err(bad("ids has at most one member per item"));
        }
        for (k, x) in im {
            if !patchlog_core::names::is_resource_name(k)
                || !x.as_str().is_some_and(|i| Id::parse(i).is_some())
            {
                return Err(bad("ids maps resource names to ids"));
            }
        }
    }
    Ok(())
}

/// The ids each item's steps produce, from the request alone: ids are
/// content hashes (§3.3, §3.4), so a retry can be recognised without state.
fn expected_ids(items: &[ItemIn]) -> Vec<Vec<(Id, i64)>> {
    items
        .iter()
        .map(|it| {
            let mut prev = match it.pre {
                Precondition::Match(p) => Some(p),
                Precondition::NoneMatchStar => None,
            };
            it.steps
                .iter()
                .map(|st| {
                    let (id, kind) = match &st.op {
                        Op::Patch(b) => (revision_id(prev.as_ref(), &b.canonical), REV),
                        Op::Delete => (tombstone_id(&prev.unwrap_or(Id([0; 20]))), TOMBSTONE),
                    };
                    prev = Some(id);
                    (id, kind)
                })
                .collect()
        })
        .collect()
}

/// The `batch` namespace entry (§3.5).
fn batch_entry(
    items: &[ItemIn],
    ids: &[Vec<(Id, i64)>],
    config: Option<&Id>,
    source: Option<&Value>,
) -> Value {
    let mut entries = Vec::new();
    if let Some(c) = config {
        entries.push(obj(vec![("kind", s("config")), ("target", s(c.text()))]));
    }
    for (it, ids) in items.iter().zip(ids) {
        let (id, kind) = ids.last().unwrap();
        entries.push(obj(vec![
            ("resource", s(it.resource.clone())),
            (
                "kind",
                s(if *kind == TOMBSTONE {
                    "tombstone"
                } else {
                    "head"
                }),
            ),
            ("target", s(id.text())),
        ]));
    }
    let mut e = vec![("kind", s("batch")), ("entries", Value::Array(entries))];
    if let Some(src) = source {
        e.push(("source", src.clone()));
    }
    obj(e)
}

fn success_body(
    items: &[ItemIn],
    ids: &[Vec<(Id, i64)>],
    ns_id: &str,
    config: Option<&Id>,
) -> Value {
    let list = items
        .iter()
        .zip(ids)
        .map(|(it, ids)| {
            obj(vec![
                ("resource", s(it.resource.clone())),
                (
                    "ids",
                    Value::Array(ids.iter().map(|(id, _)| s(id.text())).collect()),
                ),
            ])
        })
        .collect();
    let mut b = vec![("ns_id", s(ns_id)), ("items", Value::Array(list))];
    if let Some(c) = config {
        b.push(("config", s(c.text())));
    }
    obj(b)
}

fn batch_response(status: u16, body: &Value, ns_id: &str, config: Option<&Id>) -> Res<Response> {
    let hd = Headers::new();
    cache_headers(&hd, Class::NoStore, false)?;
    hd.set("X-Namespace-Revision", ns_id)?;
    if let Some(c) = config {
        hd.set("X-Config-Revision", &c.text())?;
    }
    http::json(status, hd, body)
}

/// §7.5 Failure: the status of the earliest failing step, and the items
/// that failed at it.
fn failure_response(mut fails: Vec<Failure>) -> Res<Response> {
    let step = fails.iter().map(|f| f.step).min().unwrap_or(2);
    fails.retain(|f| f.step == step);
    fails.sort_by_key(|f| f.index);
    let status = fails[0].err.status;
    let items = fails
        .into_iter()
        .map(|f| {
            let mut m = vec![
                ("index", Value::Number(f.index as f64)),
                ("status", Value::Number(f.err.status as f64)),
                ("code", s(f.err.code)),
                ("message", s(f.err.message)),
            ];
            m.extend(f.err.extra);
            obj(m)
        })
        .collect();
    let hd = Headers::new();
    cache_headers(&hd, Class::NoStore, false)?;
    let body = obj(vec![("code", s("batch")), ("items", Value::Array(items))]);
    http::json(status, hd, &body)
}

/// Which step of §6.2 a gate error belongs to.
fn gate_step(e: &GateError) -> u8 {
    match e {
        GateError::Invalid(_) => 3,
        _ => 4,
    }
}

impl Namespace {
    pub(super) async fn post_batch(
        &self,
        ctx: &Ctx,
        hd: &Headers,
        raw: &[u8],
        dry: bool,
    ) -> Res<Response> {
        http::content_type_is(hd, "application/json")?;
        let author = author(hd)?;
        let req = parse(raw, hd)?;
        self.existing()?;
        // A local source must be in its namespace's chain (§7.5 source),
        // checked before the synchronous part: namespace revisions never change.
        if let Some(src) = &req.source {
            if src.get("origin").is_none() {
                let (sns, at) = (
                    src.get("ns").and_then(Value::as_str).unwrap_or_default(),
                    src.get("at").and_then(Value::as_str).unwrap_or_default(),
                );
                let ok = if sns == ctx.ns {
                    self.ns_seq_of(at)?.is_some()
                } else {
                    let stub = self.env.durable_object("NAMESPACE")?.get_by_name(sns)?;
                    let r = stub
                        .fetch_with_str(&format!("https://namespace/ns/{sns}/rev/{at}"))
                        .await?;
                    r.status_code() == 200
                };
                if !ok {
                    return Err(Err::new(
                        422,
                        "source",
                        format!("{at} isn't in the chain of {sns}"),
                    ));
                }
            }
        }
        let names: Vec<&str> = req.items.iter().map(|it| it.resource.as_str()).collect();
        self.prefetch(&names).await?;
        let mut source_blobs = HashMap::new();
        if let Some(src) = &req.source {
            if let (None, Some(sns), Some(at)) = (
                src.get("origin"),
                src.get("ns").and_then(Value::as_str),
                src.get("at").and_then(Value::as_str),
            ) {
                if sns != ctx.ns {
                    source_blobs = self.load_source_blobs(sns, at, &names).await?;
                }
            }
        }
        let mut fetched = std::collections::HashSet::new();
        loop {
            // Set and cleared with no await between, so no other request sees them.
            *self.extra_blobs.borrow_mut() = source_blobs.clone();
            let step = self.batch_sync(ctx, &req, &author, dry);
            self.pending_schemas.borrow_mut().clear();
            self.extra_blobs.borrow_mut().clear();
            match step? {
                Step::Done(r) => return Ok(r),
                Step::NeedSchemas(paths) => self.fetch_schemas(paths, &mut fetched).await?,
            }
        }
    }

    /// The batch's checks and its commit, with no `await` between them.
    fn batch_sync(&self, ctx: &Ctx, req: &BatchIn, author: &str, dry: bool) -> Res<Step> {
        let ns = self.existing()?;
        if !req.items.is_empty() && ns.frozen {
            return Err(Err::new(409, "frozen", "the namespace is frozen"));
        }
        let ids = expected_ids(&req.items);

        // The config change first, as a config write (§7.4); the items are
        // checked against the configuration it produces.
        let mut failures: Vec<Failure> = Vec::new();
        let mut missing_schemas = std::collections::BTreeSet::new();
        let mut config_plan: Option<ConfigPlan> = None;
        let mut config_stale = false;
        if let Some((pre, body)) = &req.config {
            match self.prepare_config(ctx, pre, body, &Some(ns.clone()), author) {
                Ok(ConfigStep::Plan(p)) => config_plan = Some(p),
                // A single config write's retry; only batch entries match a batch.
                Ok(ConfigStep::Retry(_)) => config_stale = true,
                Err(e) if e.status == 412 => config_stale = true,
                Err(e) => return Err(e),
            }
        }
        let rules_head = match &config_plan {
            Some(p) => make_head(ns.seq, ns.id, ns.config_seq, p.id, p.doc.clone()),
            None => ns.clone(),
        };

        // Step 2 for every item: the verb, then the precondition.
        struct Start {
            doc: Option<Value>,
            live: Option<Value>,
            depth: i64,
            tombstoned: bool,
        }
        let mut starts: Vec<Option<Start>> = Vec::new();
        for (i, it) in req.items.iter().enumerate() {
            let (cur, foreign) = self.head_or_foreign(&it.resource)?;
            let fail = |err: Err| Failure {
                index: i,
                step: 2,
                err,
            };
            // "delete" first under ifNoneMatch, or twice in a row (step 2.5).
            if matches!(it.pre, Precondition::NoneMatchStar) && matches!(it.steps[0].op, Op::Delete)
            {
                failures.push(fail(Err::new(
                    428,
                    "precondition_required",
                    "a delete takes ifMatch",
                )));
                starts.push(None);
                continue;
            }
            if it
                .steps
                .windows(2)
                .any(|w| matches!((&w[0].op, &w[1].op), (Op::Delete, Op::Delete)))
            {
                failures.push(fail(Err::new(
                    422,
                    "invalid",
                    "a delete can't follow a delete",
                )));
                starts.push(None);
                continue;
            }
            let start = match (&it.pre, &cur) {
                (Precondition::NoneMatchStar, None) => Ok(Start {
                    doc: None,
                    live: None,
                    depth: -1,
                    tombstoned: false,
                }),
                (Precondition::NoneMatchStar, Some(h)) if h.kind == TOMBSTONE => {
                    Err(Err::new(410, "gone", "the resource is deleted")
                        .with("head", s(h.id.clone())))
                }
                (Precondition::NoneMatchStar, Some(h)) => {
                    Err(Err::new(412, "stale", "the resource exists").with("head", s(h.id.clone())))
                }
                (Precondition::Match(_), None) => Err(Err::new(412, "stale", "no such resource")),
                (Precondition::Match(p), Some(h)) if p.text() != h.id => {
                    if h.kind == TOMBSTONE {
                        Err(Err::new(410, "gone", "the resource is deleted")
                            .with("head", s(h.id.clone())))
                    } else {
                        Err(Err::new(412, "stale", "the head moved").with("head", s(h.id.clone())))
                    }
                }
                (Precondition::Match(_), Some(h)) => {
                    let live = match h.live {
                        Some(l) => Some(self.doc_at(&it.resource, l, false)?),
                        // In a branch, the base's document (§7.6 First write).
                        None => foreign.as_ref().and_then(|f| f.doc.clone()),
                    };
                    let tombstoned = h.kind == TOMBSTONE;
                    Ok(Start {
                        doc: if tombstoned { None } else { live.clone() },
                        live,
                        depth: h.depth,
                        tombstoned,
                    })
                }
            };
            match start {
                Ok(s0) => starts.push(Some(s0)),
                Err(e) => {
                    failures.push(fail(e));
                    starts.push(None);
                }
            }
        }
        if config_stale || !failures.is_empty() {
            // An idempotent retry of an earlier batch (§7.5) answers 200.
            if !dry {
                let config_id = req.config.as_ref().map(|(pre, b)| match pre {
                    Precondition::Match(p) => revision_id(Some(p), &b.canonical),
                    Precondition::NoneMatchStar => revision_id(None, &b.canonical),
                });
                let entry = canonical_string(&batch_entry(
                    &req.items,
                    &ids,
                    config_id.as_ref(),
                    req.source.as_ref(),
                ));
                if let Some(row) = self.one::<IdRow>(
                    "SELECT id FROM ns_log WHERE entry = ?1 AND author = ?2 AND seq > ?3 ORDER BY seq DESC LIMIT 1",
                    vec![entry.into(), author.into(), (ns.seq - 100_000).into()],
                )? {
                    let body = success_body(&req.items, &ids, &row.id, config_id.as_ref());
                    return batch_response(200, &body, &row.id, config_id.as_ref()).map(Step::Done);
                }
            }
            if config_stale {
                return Err(
                    Err::new(412, "stale", "config moved").with("config", s(ns.config_id.text()))
                );
            }
            return failure_response(failures).map(Step::Done);
        }

        // Batch limits (§6.6), from the current configuration, at step 4
        // before any item's own.
        if req.items.len() as u64 > ITEMS_PER_BATCH {
            return Err(limit_err(
                422,
                "itemsPerBatch",
                req.items.len() as u64,
                ITEMS_PER_BATCH,
            ));
        }
        let total: u64 = req
            .items
            .iter()
            .flat_map(|it| &it.steps)
            .map(|st| match &st.op {
                Op::Patch(b) => b.canonical.len() as u64,
                Op::Delete => 0,
            })
            .sum();
        if total > BATCH_SIZE {
            return Err(limit_err(422, "batchSize", total, BATCH_SIZE));
        }

        // Steps 3–6 for every step of every item, against the configuration
        // the batch produces.
        let limits = rules_head.limits.clone();
        let mut planned: Vec<Planned> = Vec::new();
        let mut item_ranges: Vec<std::ops::Range<usize>> = Vec::new();
        let mut blob_stmts: Vec<Stmt> = Vec::new();
        for (i, it) in req.items.iter().enumerate() {
            let begin = planned.len();
            let Some(st0) = starts[i].take() else {
                unreachable!()
            };
            let (mut doc, mut live, mut depth, mut tombstoned) =
                (st0.doc, st0.live, st0.depth, st0.tombstoned);
            let mut prev = match it.pre {
                Precondition::Match(p) => Some(p),
                Precondition::NoneMatchStar => None,
            };
            let mut failed = None;
            for st in &it.steps {
                match &st.op {
                    Op::Patch(body) => {
                        let kind = if tombstoned {
                            WriteKind::Restore
                        } else if prev.is_none() {
                            WriteKind::Create
                        } else {
                            WriteKind::Append
                        };
                        let base = if tombstoned {
                            live.clone()
                        } else {
                            doc.clone()
                        };
                        let p = match gate::apply_and_check(
                            prev.as_ref(),
                            base.unwrap_or(Value::Null),
                            body,
                            kind,
                            &limits,
                        ) {
                            Ok(p) => p,
                            Err(e) => {
                                failed = Some((gate_step(&e), gate_err(e)));
                                break;
                            }
                        };
                        match self.check_blob_refs(&it.resource, &p.doc, author) {
                            Ok(b) => blob_stmts.extend(b),
                            Err(e) => {
                                failed = Some((4, e));
                                break;
                            }
                        }
                        match self.check_typed(ctx, &p.doc) {
                            // Gather every item's missing schemas, so one
                            // round of fetches serves the whole batch.
                            Ok(Some(remote)) => missing_schemas.extend(remote),
                            Ok(None) => {}
                            Err(e) => {
                                failed = Some((5, e));
                                break;
                            }
                        }
                        let action = match kind {
                            WriteKind::Create => "create",
                            WriteKind::Append => "append",
                            WriteKind::Restore => "restore",
                        };
                        if let Err(e) = check_rules(
                            &rules_head,
                            &envelope(ctx, action, &it.resource, &p.writes, &p.doc, &body.value),
                        ) {
                            failed = Some((6, e));
                            break;
                        }
                        // Later items may use a schema this one writes (§6.1).
                        if schema::typed(&p.doc) == Ok(schema::Typed::Schema) {
                            self.pending_schemas.borrow_mut().insert(
                                format!("/r/{}/{}/rev/{}", ctx.ns, it.resource, p.id),
                                p.doc.clone(),
                            );
                        }
                        depth += 1;
                        planned.push(Planned {
                            resource: it.resource.clone(),
                            id: p.id,
                            parent: prev,
                            kind: REV,
                            patches: Some(String::from_utf8(body.canonical.clone()).unwrap()),
                            doc: Some(p.doc.clone()),
                            doc_size: p.doc_size,
                            depth,
                            gesture: st.gesture.clone(),
                            undoes: st.undoes.clone(),
                        });
                        prev = Some(p.id);
                        live = Some(p.doc.clone());
                        doc = Some(p.doc);
                        tombstoned = false;
                    }
                    Op::Delete => {
                        let parent = prev.expect("a delete under ifMatch, or after a step");
                        let deleted = doc.clone().unwrap_or(Value::Null);
                        if let Err(e) = check_rules(
                            &rules_head,
                            &envelope(
                                ctx,
                                "delete",
                                &it.resource,
                                &[],
                                &deleted,
                                &Value::Array(vec![]),
                            ),
                        ) {
                            failed = Some((6, e));
                            break;
                        }
                        let id = tombstone_id(&parent);
                        depth += 1;
                        planned.push(Planned {
                            resource: it.resource.clone(),
                            id,
                            parent: Some(parent),
                            kind: TOMBSTONE,
                            patches: None,
                            // Deleting a resource read through keeps the base's
                            // document here, as a snapshot, for a restore.
                            doc: (depth == 0).then(|| deleted.clone()),
                            doc_size: 0,
                            depth,
                            gesture: st.gesture.clone(),
                            undoes: st.undoes.clone(),
                        });
                        prev = Some(id);
                        doc = None;
                        tombstoned = true;
                    }
                }
            }
            if let Some((step, err)) = failed {
                failures.push(Failure {
                    index: i,
                    step,
                    err,
                });
            }
            item_ranges.push(begin..planned.len());
        }

        if !missing_schemas.is_empty() {
            return Ok(Step::NeedSchemas(missing_schemas.into_iter().collect()));
        }
        if dry {
            let items = req
                .items
                .iter()
                .enumerate()
                .map(|(i, _)| match failures.iter().find(|f| f.index == i) {
                    Some(f) => obj(vec![
                        ("index", Value::Number(i as f64)),
                        ("status", Value::Number(f.err.status as f64)),
                        ("code", s(f.err.code)),
                        ("message", s(f.err.message.clone())),
                    ]),
                    None => obj(vec![
                        ("index", Value::Number(i as f64)),
                        ("status", Value::Number(201.0)),
                        (
                            "ids",
                            Value::Array(ids[i].iter().map(|(id, _)| s(id.text())).collect()),
                        ),
                    ]),
                })
                .collect();
            let mut body = vec![("items", Value::Array(items))];
            if let Some(p) = &config_plan {
                body.push((
                    "config",
                    obj(vec![
                        ("status", Value::Number(201.0)),
                        ("config", s(p.id.text())),
                    ]),
                ));
            }
            let hd = Headers::new();
            cache_headers(&hd, Class::NoStore, false)?;
            return http::json(200, hd, &obj(body)).map(Step::Done);
        }
        if !failures.is_empty() {
            return failure_response(failures).map(Step::Done);
        }

        // Step 7: hash and insert, all at once.
        let start = ns.seq + 1;
        let ns_seq = start + (planned.len() as i64 - 1).max(0);
        let config_id = config_plan.as_ref().map(|p| p.id);
        let entry = batch_entry(&req.items, &ids, config_id.as_ref(), req.source.as_ref());
        let ns_id_new = ns_id(Some(&ns.id), &canonical(&entry));
        let config_seq = if config_plan.is_some() {
            ns.config_seq + 1
        } else {
            ns.config_seq
        };
        let mut stmts: Vec<Stmt> = vec![(
            "INSERT INTO ns_log (seq, id, prev, entry, author, created, gesture, undoes, config_seq) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?)",
            vec![
                ns_seq.into(),
                ns_id_new.text().into(),
                ns.id.text().into(),
                canonical_string(&entry).into(),
                author.into(),
                ctx.now.into(),
                config_seq.into(),
            ],
        )];
        if let Some(p) = &config_plan {
            stmts.push(p.insert(config_seq, author, ns_seq));
        }
        for (k, e) in planned.iter().enumerate() {
            let seq = start + k as i64;
            stmts.push((
                "INSERT INTO res_log (resource, seq, id, parent, kind, patches, author, created, gesture, undoes, depth) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    e.resource.clone().into(),
                    seq.into(),
                    e.id.text().into(),
                    e.parent.map(|p| p.text()).into(),
                    e.kind.into(),
                    e.patches.clone().into(),
                    author.into(),
                    ctx.now.into(),
                    e.gesture.clone().into(),
                    e.undoes.clone().into(),
                    e.depth.into(),
                ],
            ));
            if let (Some(doc), true) = (&e.doc, e.depth % SNAPSHOT_EVERY == 0) {
                stmts.push((
                    "INSERT INTO res_snapshots (resource, seq, doc) VALUES (?, ?, ?)",
                    vec![
                        e.resource.clone().into(),
                        seq.into(),
                        canonical_string(doc).into(),
                    ],
                ));
            }
        }
        stmts.extend(blob_stmts);
        self.commit(stmts)?;

        // The caches: each resource's head, and its document if live.
        for range in &item_ranges {
            let Some(last_k) = range.clone().last() else {
                continue;
            };
            let last = &planned[last_k];
            let live_k = range.clone().rev().find(|&k| planned[k].kind == REV);
            let live = match live_k {
                Some(k) => Some(start + k as i64),
                None => {
                    self.inner.borrow_mut().heads.remove(&last.resource);
                    self.resource(&last.resource)?.and_then(|h| h.live)
                }
            };
            let seq = start + last_k as i64;
            self.remember(
                &last.resource,
                Some(Head {
                    seq,
                    id: last.id.text(),
                    kind: last.kind,
                    depth: last.depth,
                    live,
                }),
            );
            if let Some(doc) = &last.doc {
                self.cache_doc(&last.resource, seq, doc.clone(), last.doc_size);
            }
        }
        let new_head = match config_plan {
            Some(p) => make_head(ns_seq, ns_id_new, config_seq, p.id, p.doc),
            None => NsHead {
                seq: ns_seq,
                id: ns_id_new,
                ..ns
            },
        };
        self.set_head(new_head);
        let body = success_body(&req.items, &ids, &ns_id_new.text(), config_id.as_ref());
        batch_response(201, &body, &ns_id_new.text(), config_id.as_ref()).map(Step::Done)
    }
}
