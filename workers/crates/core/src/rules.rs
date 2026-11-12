//! Namespace rules (§6.4): checking rule forms when a namespace document is
//! written (§6.4.2, §7.4, `rulesPerNamespace` of §12.2), and evaluating them
//! against a change envelope (§6.4.1, §6.4.3).
//!
//! The same forms serve grant, key-scope and role rules (§C.1, §C.4); those
//! callers pass their own base pointer ([`CompiledRules::at`], [`check`]).
//!
//! Rules are compiled once ([`CompiledRules`]), their `schema` fragments
//! included, so a caller can keep them per configuration revision.
//!
//! Evaluation is two-valued: the server never sees end-to-end (E3) writes in
//! the clear, so the strong Kleene logic of §6.2 for E3 isn't implemented.

use crate::json::Value;
use crate::patch::{escape_token, parse_pointer};
use crate::schema::{compile_fragment, Fragment, SchemaError};
use std::cell::OnceCell;
use std::cmp::Ordering;
use std::fmt;

/// Why a namespace document's rules are refused.
#[derive(Debug, Clone, PartialEq)]
pub enum RulesError {
    /// `422 invalid`, with `errors: [{ pointer, message }]` (§7.4).
    Invalid(Vec<(String, String)>),
    /// `422 limit`, `limit: "rulesPerNamespace"`, with `measured` and `max` (§6.6).
    Limit { measured: u64, max: u64 },
}

/// A failing rule: `422` with `code: "rule"`, `rule` and `path` (§6.4.3).
#[derive(Debug, Clone, PartialEq)]
pub struct Failure {
    /// Index of the failing top-level rule.
    pub rule: usize,
    /// JSON Pointer to the failing rule form in the namespace document, such
    /// as `/rules/2/then/0`, descending only through the first failing
    /// member of an `all` or a `then`.
    pub path: String,
    /// A human-readable reason.
    pub message: String,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rule {} fails at {}: {}",
            self.rule, self.path, self.message
        )
    }
}

/// Checks a namespace document's `rules` member and counts its rule forms
/// against `max_rules` (`rulesPerNamespace`). Rule forms in roles and key
/// scopes count toward the same limit (§12.2): a caller validating those too
/// sums [`check`]'s counts itself.
pub fn validate(rules: &Value, max_rules: u64) -> Result<(), RulesError> {
    let n = check(rules, "/rules").map_err(RulesError::Invalid)?;
    if n > max_rules {
        return Err(RulesError::Limit {
            measured: n,
            max: max_rules,
        });
    }
    Ok(())
}

/// Checks an array of rule forms found at `at` (a JSON Pointer into the
/// enclosing document) and returns how many rule forms it holds, every
/// nested one counted (§12.2). Errors point into the enclosing document.
pub fn check(rules: &Value, at: &str) -> Result<u64, Vec<(String, String)>> {
    let mut errors = Vec::new();
    let Some(list) = rules.as_array() else {
        return Err(vec![(at.to_string(), "rules is an array".into())]);
    };
    let mut count = 0;
    for (i, r) in list.iter().enumerate() {
        if let Ok(node) = compile(r, &format!("{at}/{i}"), &mut errors) {
            count += node.count();
        }
    }
    if errors.is_empty() {
        Ok(count)
    } else {
        Err(errors)
    }
}

/// Evaluates `rules` against `envelope` without keeping the compiled form.
/// Rules that don't compile fail closed: the first such rule fails, at the
/// pointer of its first error.
pub fn evaluate(rules: &Value, envelope: &Value) -> Result<(), Failure> {
    match CompiledRules::new(rules) {
        Ok(c) => c.evaluate(envelope),
        Err(errors) => {
            let (path, message) = errors.into_iter().next().unwrap_or_default();
            let rule = path
                .strip_prefix("/rules/")
                .and_then(|r| r.split('/').next())
                .and_then(|i| i.parse().ok())
                .unwrap_or(0);
            Err(Failure {
                rule,
                path,
                message: format!("invalid rule: {message}"),
            })
        }
    }
}

/// Rules compiled once, for a namespace document revision.
#[derive(Debug)]
pub struct CompiledRules {
    base: String,
    rules: Vec<Node>,
    count: u64,
}

impl CompiledRules {
    /// Compiles a namespace document's `rules` member (pointers under `/rules`).
    pub fn new(rules: &Value) -> Result<CompiledRules, Vec<(String, String)>> {
        CompiledRules::at(rules, "/rules")
    }

    /// Compiles rules found at `at` in their enclosing document, such as
    /// `/roles/translator/rules`; failures point under `at`.
    pub fn at(rules: &Value, at: &str) -> Result<CompiledRules, Vec<(String, String)>> {
        let Some(list) = rules.as_array() else {
            return Err(vec![(at.to_string(), "rules is an array".into())]);
        };
        let mut errors = Vec::new();
        let mut out = Vec::with_capacity(list.len());
        for (i, r) in list.iter().enumerate() {
            if let Ok(node) = compile(r, &format!("{at}/{i}"), &mut errors) {
                out.push(node);
            }
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        let count = out.iter().map(Node::count).sum();
        Ok(CompiledRules {
            base: at.to_string(),
            rules: out,
            count,
        })
    }

    /// No rules: anything goes (§6.4).
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The number of rule forms, nested ones included (§12.2).
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Runs every rule in order; the first failing one is the answer (§6.4.3).
    pub fn evaluate(&self, envelope: &Value) -> Result<(), Failure> {
        let ctx = Ctx {
            env: envelope,
            writes: OnceCell::new(),
        };
        for (i, r) in self.rules.iter().enumerate() {
            if let Err(f) = r.eval(&ctx) {
                return Err(Failure {
                    rule: i,
                    path: format!("{}/{i}{}", self.base, f.suffix),
                    message: f.message,
                });
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Compiled forms

type Pointer = Vec<String>;

#[derive(Debug)]
enum Node {
    TestValue {
        path: Pointer,
        text: String,
        value: Value,
    },
    TestExists {
        path: Pointer,
        text: String,
        exists: bool,
    },
    TestSchema {
        path: Pointer,
        text: String,
        schema: Box<Fragment>,
    },
    Covers {
        at: Pointer,
        text: String,
    },
    Overlaps {
        at: Pointer,
        text: String,
    },
    Within {
        at: Vec<Pointer>,
        text: String,
    },
    Compare {
        path: Pointer,
        text: String,
        op: CmpOp,
        rhs: Operand,
    },
    All(Vec<Node>),
    Any(Vec<Node>),
    Not(Box<Node>),
    If {
        cond: Vec<Node>,
        then: Vec<Node>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CmpOp {
    Eq,
    Lt,
    Le,
    Gt,
    Ge,
    In,
}

impl CmpOp {
    fn name(self) -> &'static str {
        match self {
            CmpOp::Eq => "eq",
            CmpOp::Lt => "lt",
            CmpOp::Le => "le",
            CmpOp::Gt => "gt",
            CmpOp::Ge => "ge",
            CmpOp::In => "in",
        }
    }
}

#[derive(Debug)]
enum Operand {
    Value(Value),
    Path(Pointer, String),
}

impl Node {
    fn count(&self) -> u64 {
        1 + match self {
            Node::All(v) | Node::Any(v) => v.iter().map(Node::count).sum(),
            Node::Not(n) => n.count(),
            Node::If { cond, then } => cond.iter().chain(then).map(Node::count).sum(),
            _ => 0,
        }
    }
}

/// Compiles one rule form at `p`, adding what's wrong with it to `errors`.
/// `Err(())` means it didn't compile; its errors are in `errors`.
fn compile(r: &Value, p: &str, errors: &mut Vec<(String, String)>) -> Result<Node, ()> {
    let mut fail = |ptr: String, m: String| {
        errors.push((ptr, m));
        Err(())
    };
    let Some(m) = r.as_object() else {
        return fail(p.into(), "a rule is an object".into());
    };
    let at = |k: &str| format!("{p}/{}", escape_token(k));
    // Members a form may carry besides those it requires.
    let only = |allowed: &[&str]| -> Option<String> {
        m.keys().find(|k| !allowed.contains(&k.as_str())).cloned()
    };
    if let Some(op) = m.get("op") {
        let Some(op) = op.as_str() else {
            return fail(at("op"), "op is a string".into());
        };
        return match op {
            "test" => compile_test(m, p, errors),
            "writes" => compile_writes(m, p, errors),
            "compare" => compile_compare(m, p, errors),
            _ => fail(
                at("op"),
                format!("unknown op {op:?}: one of test, writes, compare"),
            ),
        };
    }
    let list = |k: &str, errors: &mut Vec<(String, String)>| -> Result<Vec<Node>, ()> {
        let Some(a) = m[k].as_array() else {
            errors.push((at(k), format!("{k} is an array of rules")));
            return Err(());
        };
        let mut nodes = Vec::with_capacity(a.len());
        let mut ok = true;
        for (i, x) in a.iter().enumerate() {
            match compile(x, &format!("{}/{i}", at(k)), errors) {
                Ok(n) => nodes.push(n),
                Err(()) => ok = false,
            }
        }
        if ok {
            Ok(nodes)
        } else {
            Err(())
        }
    };
    if m.contains_key("if") || m.contains_key("then") {
        if let Some(k) = only(&["if", "then"]) {
            return fail(at(&k), format!("{k:?} isn't a member of an if/then rule"));
        }
        if !m.contains_key("then") {
            return fail(p.into(), "an if rule needs then".into());
        }
        if !m.contains_key("if") {
            return fail(p.into(), "a then rule needs if".into());
        }
        let cond = list("if", errors);
        let then = list("then", errors);
        return Ok(Node::If {
            cond: cond?,
            then: then?,
        });
    }
    for k in ["all", "any", "not"] {
        if m.contains_key(k) {
            if let Some(x) = only(&[k]) {
                return fail(at(&x), format!("{x:?} isn't a member of an {k} rule"));
            }
            return match k {
                "all" => list(k, errors).map(Node::All),
                "any" => list(k, errors).map(Node::Any),
                _ => compile(&m[k], &at(k), errors).map(|n| Node::Not(Box::new(n))),
            };
        }
    }
    fail(
        p.into(),
        "not a rule form: one with op test, writes or compare, or all, any, not, or if/then".into(),
    )
}

type Members = std::collections::BTreeMap<String, Value>;

fn pointer_member(
    m: &Members,
    k: &str,
    p: &str,
    errors: &mut Vec<(String, String)>,
) -> Result<(Pointer, String), ()> {
    let at = format!("{p}/{}", escape_token(k));
    match m.get(k) {
        None => {
            errors.push((p.into(), format!("missing {k}")));
            Err(())
        }
        Some(Value::String(s)) => match parse_pointer(s) {
            Ok(t) => Ok((t, s.clone())),
            Err(e) => {
                errors.push((at, e));
                Err(())
            }
        },
        Some(_) => {
            errors.push((at, format!("{k} is a JSON Pointer string")));
            Err(())
        }
    }
}

fn unexpected(m: &Members, allowed: &[&str], p: &str, form: &str) -> Option<(String, String)> {
    m.keys().find(|k| !allowed.contains(&k.as_str())).map(|k| {
        (
            format!("{p}/{}", escape_token(k)),
            format!("{k:?} isn't a member of a {form} rule"),
        )
    })
}

/// Exactly one of `keys` in `m`.
fn one_of<'a>(
    m: &Members,
    keys: &[&'a str],
    p: &str,
    form: &str,
    errors: &mut Vec<(String, String)>,
) -> Result<&'a str, ()> {
    let present: Vec<&str> = keys
        .iter()
        .copied()
        .filter(|k| m.contains_key(*k))
        .collect();
    match present.as_slice() {
        [k] => Ok(k),
        [] => {
            errors.push((
                p.into(),
                format!("a {form} rule has one of {}", keys.join(", ")),
            ));
            Err(())
        }
        _ => {
            errors.push((
                p.into(),
                format!("a {form} rule has only one of {}", present.join(", ")),
            ));
            Err(())
        }
    }
}

fn compile_test(m: &Members, p: &str, errors: &mut Vec<(String, String)>) -> Result<Node, ()> {
    if let Some(e) = unexpected(m, &["op", "path", "value", "exists", "schema"], p, "test") {
        errors.push(e);
        return Err(());
    }
    let path = pointer_member(m, "path", p, errors);
    let kind = one_of(m, &["value", "exists", "schema"], p, "test", errors)?;
    let (path, text) = path?;
    match kind {
        "value" => Ok(Node::TestValue {
            path,
            text,
            value: m["value"].clone(),
        }),
        "exists" => match m["exists"] {
            Value::Bool(exists) => Ok(Node::TestExists { path, text, exists }),
            _ => {
                errors.push((format!("{p}/exists"), "exists is true or false".into()));
                Err(())
            }
        },
        _ => match compile_fragment(&m["schema"]) {
            Ok(f) => Ok(Node::TestSchema {
                path,
                text,
                schema: Box::new(f),
            }),
            Err(e) => {
                let list = match e {
                    SchemaError::Invalid(v) => v,
                    SchemaError::Ref(m) | SchemaError::Unavailable { message: m, .. } => {
                        vec![(String::new(), m)]
                    }
                };
                errors.extend(
                    list.into_iter()
                        .map(|(ptr, msg)| (format!("{p}/schema{ptr}"), msg)),
                );
                Err(())
            }
        },
    }
}

fn compile_writes(m: &Members, p: &str, errors: &mut Vec<(String, String)>) -> Result<Node, ()> {
    if let Some(e) = unexpected(m, &["op", "covers", "overlaps", "within"], p, "writes") {
        errors.push(e);
        return Err(());
    }
    match one_of(m, &["covers", "overlaps", "within"], p, "writes", errors)? {
        "covers" => {
            let (at, text) = pointer_member(m, "covers", p, errors)?;
            Ok(Node::Covers { at, text })
        }
        "overlaps" => {
            let (at, text) = pointer_member(m, "overlaps", p, errors)?;
            Ok(Node::Overlaps { at, text })
        }
        _ => {
            let wp = format!("{p}/within");
            let Some(a) = m["within"].as_array() else {
                errors.push((wp, "within is an array of JSON Pointers".into()));
                return Err(());
            };
            let mut at = Vec::with_capacity(a.len());
            let mut ok = true;
            for (i, x) in a.iter().enumerate() {
                match x.as_str().map(parse_pointer) {
                    Some(Ok(t)) => at.push(t),
                    Some(Err(e)) => {
                        errors.push((format!("{wp}/{i}"), e));
                        ok = false;
                    }
                    None => {
                        errors.push((format!("{wp}/{i}"), "a JSON Pointer string".into()));
                        ok = false;
                    }
                }
            }
            if !ok {
                return Err(());
            }
            let text = a
                .iter()
                .filter_map(Value::as_str)
                .map(|s| format!("{s:?}"))
                .collect::<Vec<_>>()
                .join(", ");
            Ok(Node::Within { at, text })
        }
    }
}

fn compile_compare(m: &Members, p: &str, errors: &mut Vec<(String, String)>) -> Result<Node, ()> {
    const OPS: [&str; 6] = ["eq", "lt", "le", "gt", "ge", "in"];
    if let Some(e) = unexpected(
        m,
        &["op", "path", "eq", "lt", "le", "gt", "ge", "in"],
        p,
        "compare",
    ) {
        errors.push(e);
        return Err(());
    }
    let path = pointer_member(m, "path", p, errors);
    let k = one_of(m, &OPS, p, "compare", errors)?;
    let (path, text) = path?;
    let op = match k {
        "eq" => CmpOp::Eq,
        "lt" => CmpOp::Lt,
        "le" => CmpOp::Le,
        "gt" => CmpOp::Gt,
        "ge" => CmpOp::Ge,
        _ => CmpOp::In,
    };
    let kp = format!("{p}/{k}");
    let Some(o) = m[k].as_object() else {
        errors.push((
            kp,
            format!("{k} is {{ \"value\": … }} or {{ \"path\": \"…\" }}"),
        ));
        return Err(());
    };
    let rhs = match (o.get("value"), o.get("path"), o.len()) {
        (Some(v), None, 1) => Operand::Value(v.clone()),
        (None, Some(_), 1) => {
            let (t, s) = pointer_member(o, "path", &kp, errors)?;
            Operand::Path(t, s)
        }
        _ => {
            errors.push((kp, format!("{k} has exactly one member, value or path")));
            return Err(());
        }
    };
    Ok(Node::Compare {
        path,
        text,
        op,
        rhs,
    })
}

// ---------------------------------------------------------------------------
// Evaluation

struct Ctx<'a> {
    env: &'a Value,
    /// The envelope's `writes`, parsed once.
    writes: OnceCell<Vec<Pointer>>,
}

impl Ctx<'_> {
    fn get(&self, path: &[String]) -> Option<&Value> {
        resolve(self.env, path)
    }

    /// `writes` as reference tokens. Absent (a `read` envelope) is none; one
    /// that isn't a valid pointer, which the server never builds, counts as a
    /// root write, the strictest reading.
    fn writes(&self) -> &[Pointer] {
        self.writes.get_or_init(|| match self.env.get("writes") {
            Some(Value::Array(a)) => a
                .iter()
                .map(|w| {
                    w.as_str()
                        .and_then(|s| parse_pointer(s).ok())
                        .unwrap_or_default()
                })
                .collect(),
            _ => Vec::new(),
        })
    }
}

/// RFC 6901 evaluation; `None` where the value doesn't exist.
fn resolve<'a>(mut v: &'a Value, path: &[String]) -> Option<&'a Value> {
    for t in path {
        v = match v {
            Value::Object(m) => m.get(t)?,
            Value::Array(a) => {
                let ok = t == "0" || (!t.starts_with('0') && t.bytes().all(|b| b.is_ascii_digit()));
                if !ok || t.is_empty() {
                    return None;
                }
                a.get(t.parse::<usize>().ok()?)?
            }
            _ => return None,
        };
    }
    Some(v)
}

/// `a` is at or above `b`: a prefix of it, segment by segment.
fn at_or_above(a: &[String], b: &[String]) -> bool {
    a.len() <= b.len() && a.iter().zip(b).all(|(x, y)| x == y)
}

/// Where a rule failed, relative to the top-level rule, and why.
struct Fail {
    suffix: String,
    message: String,
}

fn fail<T>(message: String) -> Result<T, Fail> {
    Err(Fail {
        suffix: String::new(),
        message,
    })
}

fn deeper(prefix: String, f: Fail) -> Fail {
    Fail {
        suffix: format!("{prefix}{}", f.suffix),
        message: f.message,
    }
}

impl Node {
    fn eval(&self, ctx: &Ctx) -> Result<(), Fail> {
        match self {
            Node::TestValue { path, text, value } => match ctx.get(path) {
                None => fail(format!("{text:?} is absent")),
                Some(v) if v == value => Ok(()),
                Some(_) => fail(format!("{text:?} isn't the value the rule requires")),
            },
            Node::TestExists { path, text, exists } => match (ctx.get(path).is_some(), *exists) {
                (true, true) | (false, false) => Ok(()),
                (false, true) => fail(format!("{text:?} must exist")),
                (true, false) => fail(format!("{text:?} must not exist")),
            },
            Node::TestSchema { path, text, schema } => match ctx.get(path) {
                None => fail(format!("{text:?} is absent")),
                Some(v) => schema.check(v).or_else(|(at, msg)| {
                    let at = if at.is_empty() {
                        String::new()
                    } else {
                        format!(" at {at:?}")
                    };
                    fail(format!(
                        "{text:?} doesn't match the rule's schema{at}: {msg}"
                    ))
                }),
            },
            Node::Covers { at, text } => {
                if ctx.writes().iter().any(|w| at_or_above(w, at)) {
                    Ok(())
                } else {
                    fail(format!("no write is at or above {text:?}"))
                }
            }
            Node::Overlaps { at, text } => {
                if ctx
                    .writes()
                    .iter()
                    .any(|w| at_or_above(w, at) || at_or_above(at, w))
                {
                    Ok(())
                } else {
                    fail(format!("no write is at, above or below {text:?}"))
                }
            }
            Node::Within { at, text } => {
                match ctx
                    .writes()
                    .iter()
                    .find(|w| !at.iter().any(|a| at_or_above(a, w)))
                {
                    None => Ok(()),
                    Some(w) => fail(format!(
                        "the write at {:?} isn't within [{text}]",
                        crate::patch::pointer_string(w)
                    )),
                }
            }
            Node::Compare {
                path,
                text,
                op,
                rhs,
            } => {
                let (rv, rtext) = match rhs {
                    Operand::Value(v) => (Some(v), "the rule's value".to_string()),
                    Operand::Path(p, s) => (ctx.get(p), format!("{s:?}")),
                };
                let Some(lv) = ctx.get(path) else {
                    return fail(format!("{text:?} is absent"));
                };
                let Some(rv) = rv else {
                    return fail(format!("{rtext} is absent"));
                };
                if compare(*op, lv, rv) {
                    Ok(())
                } else {
                    fail(format!("{text:?} {} {rtext} is false", op.name()))
                }
            }
            Node::All(list) => {
                for (i, n) in list.iter().enumerate() {
                    n.eval(ctx).map_err(|f| deeper(format!("/all/{i}"), f))?;
                }
                Ok(())
            }
            Node::Any(list) => {
                if list.iter().any(|n| n.eval(ctx).is_ok()) {
                    Ok(())
                } else {
                    fail("none of the rules in any passes".into())
                }
            }
            Node::Not(n) => match n.eval(ctx) {
                Ok(()) => fail("the rule in not passes".into()),
                Err(_) => Ok(()),
            },
            Node::If { cond, then } => {
                if cond.iter().any(|n| n.eval(ctx).is_err()) {
                    return Ok(());
                }
                for (i, n) in then.iter().enumerate() {
                    n.eval(ctx).map_err(|f| deeper(format!("/then/{i}"), f))?;
                }
                Ok(())
            }
        }
    }
}

/// `compare` (§6.4.2), both sides present.
fn compare(op: CmpOp, l: &Value, r: &Value) -> bool {
    let ord = || -> Option<Ordering> {
        match (l, r) {
            (Value::Number(a), Value::Number(b)) => a.partial_cmp(b),
            (Value::String(a), Value::String(b)) => Some(instant(a)?.cmp(&instant(b)?)),
            _ => None,
        }
    };
    match op {
        CmpOp::Eq => l == r,
        CmpOp::In => r.as_array().is_some_and(|a| a.iter().any(|x| x == l)),
        CmpOp::Lt => ord() == Some(Ordering::Less),
        CmpOp::Le => matches!(ord(), Some(Ordering::Less | Ordering::Equal)),
        CmpOp::Gt => ord() == Some(Ordering::Greater),
        CmpOp::Ge => matches!(ord(), Some(Ordering::Greater | Ordering::Equal)),
    }
}

/// An RFC 3339 `date-time` as an instant: seconds since the epoch and the
/// fractional digits without trailing zeros, which then order as decimals
/// do. `None` for anything else, including a leap second (`:60`), a
/// lowercase `t` or `z`, or a space for `T` (§6.4.2).
fn instant(s: &str) -> Option<(i64, String)> {
    let b = s.as_bytes();
    let num = |from: usize, len: usize| -> Option<i64> {
        let d = b.get(from..from + len)?;
        if !d.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(d.iter().fold(0i64, |n, c| n * 10 + i64::from(c - b'0')))
    };
    let lit = |at: usize, c: u8| b.get(at) == Some(&c);
    if !(lit(4, b'-') && lit(7, b'-') && lit(10, b'T') && lit(13, b':') && lit(16, b':')) {
        return None;
    }
    let (y, mo, d) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
    let (h, mi, sec) = (num(11, 2)?, num(14, 2)?, num(17, 2)?);
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days_in = match mo {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if d < 1 || d > days_in || h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    let mut i = 19;
    let mut frac = String::new();
    if lit(i, b'.') {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return None;
        }
        frac = s[start..i].trim_end_matches('0').to_string();
    }
    let offset = match b.get(i) {
        Some(b'Z') if i + 1 == b.len() => 0,
        Some(&c @ (b'+' | b'-')) if i + 6 == b.len() && lit(i + 3, b':') => {
            let (oh, om) = (num(i + 1, 2)?, num(i + 4, 2)?);
            if oh > 23 || om > 59 {
                return None;
            }
            let o = oh * 3600 + om * 60;
            if c == b'+' {
                o
            } else {
                -o
            }
        }
        _ => return None,
    };
    // Days from 1970-01-01 to the civil date (proleptic Gregorian).
    let (yy, mm) = if mo <= 2 {
        (y - 1, mo + 9)
    } else {
        (y, mo - 3)
    };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * mm + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some((days * 86_400 + h * 3600 + mi * 60 + sec - offset, frac))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    fn v(s: &str) -> Value {
        parse(s.as_bytes()).unwrap()
    }

    fn env(action: &str, doc: &str, writes: &[&str], principal: Option<&str>) -> Value {
        let writes: Vec<String> = writes.iter().map(|w| format!("{w:?}")).collect();
        let principal = principal
            .map(|p| format!(r#","principal":{p}"#))
            .unwrap_or_default();
        v(&format!(
            r#"{{"action":"{action}","resource":"r1","now":"2026-10-04T18:02:11.482Z",
                "writes":[{}],"doc":{doc},"patches":[]{principal}}}"#,
            writes.join(",")
        ))
    }

    fn run(rules: &str, e: &Value) -> Result<(), Failure> {
        let c = CompiledRules::new(&v(rules)).unwrap_or_else(|e| panic!("{e:?}"));
        let r = c.evaluate(e);
        assert_eq!(r, evaluate(&v(rules), e));
        r
    }

    fn fails_at(r: Result<(), Failure>, rule: usize, path: &str) {
        match r {
            Err(f) => {
                assert_eq!((f.rule, f.path.as_str()), (rule, path), "{}", f.message)
            }
            Ok(()) => panic!("passed; expected a failure at {path}"),
        }
    }

    const EXAMPLES: &str = r#"[
      { "if":   [{ "op": "test", "path": "/action", "schema": { "enum": ["create", "append", "restore"] } }],
        "then": [{ "op": "test", "path": "/doc/$schema", "schema": { "type": "string", "pattern": "^/r/schemas/match/rev/" } }] },
      { "if":   [{ "not": { "op": "test", "path": "/action", "value": "create" } },
                 { "op": "writes", "overlaps": "/$schema" }],
        "then": [{ "op": "test", "path": "/doc/$schema", "exists": true }] },
      { "if":   [{ "op": "test", "path": "/action", "schema": { "enum": ["delete", "purge"] } }],
        "then": [{ "op": "test", "path": "/principal/groups", "schema": { "contains": { "const": "ops" } } }] },
      { "if":   [{ "op": "test", "path": "/action", "value": "append" }],
        "then": [{ "not": { "op": "writes", "covers": "" } }] }
    ]"#;

    const MATCH: &str =
        r#"{"$schema":"/r/schemas/match/rev/1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","title":"x"}"#;
    const OPS: &str =
        r#"{"id":"user:a","groups":["ops"],"roles":[],"attrs":{},"via":[],"grant":"1x"}"#;
    const DESK: &str =
        r#"{"id":"user:b","groups":["desk"],"roles":[],"attrs":{},"via":[],"grant":"1y"}"#;

    #[test]
    fn examples_typed_documents() {
        // Rule 0: creates, appends and restores must be match documents.
        run(EXAMPLES, &env("create", MATCH, &[""], Some(OPS))).unwrap();
        run(EXAMPLES, &env("append", MATCH, &["/title"], Some(OPS))).unwrap();
        fails_at(
            run(
                EXAMPLES,
                &env("create", r#"{"title":"x"}"#, &[""], Some(OPS)),
            ),
            0,
            "/rules/0/then/0",
        );
        fails_at(
            run(
                EXAMPLES,
                &env(
                    "restore",
                    r#"{"$schema":"/r/schemas/other/rev/1a"}"#,
                    &[""],
                    None,
                ),
            ),
            0,
            "/rules/0/then/0",
        );
        // Rule 1: after create, $schema may be changed but not removed.
        run(EXAMPLES, &env("append", MATCH, &["/$schema"], Some(OPS))).unwrap();
        // A delete isn't held to rule 0, and writes nothing.
        run(EXAMPLES, &env("delete", r#"{"title":"x"}"#, &[], Some(OPS))).unwrap();
        // A config write that removes $schema from a (namespace) document.
        fails_at(
            run(
                EXAMPLES,
                &env("config", r#"{"title":"x"}"#, &["/$schema"], Some(OPS)),
            ),
            1,
            "/rules/1/then/0",
        );
        // A config write elsewhere passes rule 1.
        run(
            EXAMPLES,
            &env("config", r#"{"title":"x"}"#, &["/title"], Some(OPS)),
        )
        .unwrap();
    }

    #[test]
    fn examples_deletes_and_root_replaces() {
        // Rule 2: deletes and purges need the ops group.
        fails_at(
            run(EXAMPLES, &env("delete", MATCH, &[], Some(DESK))),
            2,
            "/rules/2/then/0",
        );
        run(EXAMPLES, &env("purge", "null", &[], Some(OPS))).unwrap();
        // Without authentication there's no principal: absent fails.
        fails_at(
            run(EXAMPLES, &env("purge", "null", &[], None)),
            2,
            "/rules/2/then/0",
        );
        // Rule 3: an append may not replace the root.
        fails_at(
            run(EXAMPLES, &env("append", MATCH, &[""], Some(OPS))),
            3,
            "/rules/3/then/0",
        );
        run(EXAMPLES, &env("restore", MATCH, &[""], Some(OPS))).unwrap();
    }

    const OWNERSHIP: &str = r#"[
    { "if":   [{ "not": { "op": "test", "path": "/principal/roles", "schema": { "contains": { "const": "editor" } } } },
               { "op": "test", "path": "/action", "schema": { "enum": ["create", "append", "restore", "delete"] } }],
      "then": [{ "op": "compare", "path": "/doc/owner",  "eq": { "path": "/principal/id" } },
               { "op": "compare", "path": "/doc/region", "in": { "path": "/principal/attrs/regions" } },
               { "if":   [{ "op": "test", "path": "/action", "schema": { "enum": ["append", "restore"] } }],
                 "then": [{ "not": { "op": "writes", "overlaps": "/owner" } },
                          { "not": { "op": "writes", "overlaps": "/lockAt" } }] },
               { "if":   [{ "op": "test", "path": "/doc/lockAt", "exists": true }],
                 "then": [{ "op": "compare", "path": "/now", "lt": { "path": "/doc/lockAt" } }] }] }
    ]"#;

    #[test]
    fn example_attributes_and_ownership() {
        let bob = r#"{"id":"user:bob","groups":[],"roles":[],"attrs":{"regions":["se","no"]},"via":[],"grant":"1b"}"#;
        let editor =
            r#"{"id":"user:eve","groups":[],"roles":["editor"],"attrs":{},"via":[],"grant":"1e"}"#;
        let doc = r#"{"owner":"user:bob","region":"se","title":"t"}"#;
        run(OWNERSHIP, &env("create", doc, &[""], Some(bob))).unwrap();
        run(OWNERSHIP, &env("append", doc, &["/title"], Some(bob))).unwrap();
        // Someone else's document.
        let other = r#"{"owner":"user:ann","region":"se"}"#;
        fails_at(
            run(OWNERSHIP, &env("append", other, &["/title"], Some(bob))),
            0,
            "/rules/0/then/0",
        );
        // An editor may.
        run(OWNERSHIP, &env("append", other, &["/title"], Some(editor))).unwrap();
        // Out of region.
        fails_at(
            run(
                OWNERSHIP,
                &env(
                    "append",
                    r#"{"owner":"user:bob","region":"fi"}"#,
                    &["/title"],
                    Some(bob),
                ),
            ),
            0,
            "/rules/0/then/1",
        );
        // Ownership fields can't be written after creation, even by a root replace.
        fails_at(
            run(OWNERSHIP, &env("append", doc, &["/owner"], Some(bob))),
            0,
            "/rules/0/then/2/then/0",
        );
        fails_at(
            run(OWNERSHIP, &env("restore", doc, &[""], Some(bob))),
            0,
            "/rules/0/then/2/then/0",
        );
        fails_at(
            run(OWNERSHIP, &env("append", doc, &["/lockAt/x"], Some(bob))),
            0,
            "/rules/0/then/2/then/1",
        );
        // Locked documents: before lockAt passes, after fails.
        let open = r#"{"owner":"user:bob","region":"se","lockAt":"2026-10-04T18:02:11.4821Z"}"#;
        run(OWNERSHIP, &env("append", open, &["/title"], Some(bob))).unwrap();
        let open = r#"{"owner":"user:bob","region":"se","lockAt":"2026-10-04T20:02:11+02:00"}"#;
        fails_at(
            run(OWNERSHIP, &env("append", open, &["/title"], Some(bob))),
            0,
            "/rules/0/then/3/then/0",
        );
        let open = r#"{"owner":"user:bob","region":"se","lockAt":"2026-10-04T20:03:00+02:00"}"#;
        run(OWNERSHIP, &env("append", open, &["/title"], Some(bob))).unwrap();
        // A lockAt that isn't a date-time makes lt false.
        let bad = r#"{"owner":"user:bob","region":"se","lockAt":"2026-10-04t20:03:00Z"}"#;
        fails_at(
            run(OWNERSHIP, &env("append", bad, &["/title"], Some(bob))),
            0,
            "/rules/0/then/3/then/0",
        );
        // Without authentication /principal is absent: compare is false.
        fails_at(
            run(OWNERSHIP, &env("append", doc, &["/title"], None)),
            0,
            "/rules/0/then/0",
        );
    }

    const CATALOG: &str = r#"[
    { "op": "test", "path": "/resource", "schema": { "pattern": "^([a-z0-9][a-z0-9_-]*|(matches|docs)\\.[a-z0-9][a-z0-9._-]*)$" } },
    { "if":   [{ "op": "test", "path": "/action", "schema": { "enum": ["create", "append", "restore"] } },
               { "op": "test", "path": "/doc/parents", "exists": true }],
      "then": [{ "op": "test", "path": "/doc/parents", "schema": { "type": "array", "maxItems": 1, "items": {
        "type": "object", "required": ["href"], "additionalProperties": false,
        "properties": {
          "href":  { "type": "string", "pattern": "^/r/cat-season/[a-z0-9][a-z0-9_-]{0,127}$" },
          "order": { "type": "string", "pattern": "^[0-9A-Za-z]{1,64}$" } } } } }] },
    { "if":   [{ "op": "test", "path": "/action", "value": "create" }],
      "then": [{ "op": "test", "path": "/doc/parents", "schema": { "minItems": 1 } }] }
    ]"#;

    fn cat_env(action: &str, resource: &str, doc: &str) -> Value {
        let mut e = env(action, doc, &[""], None);
        if let Value::Object(m) = &mut e {
            m.insert("resource".into(), Value::String(resource.into()));
        }
        e
    }

    #[test]
    fn b6_catalog_rules() {
        assert_eq!(check(&v(CATALOG), "/rules").unwrap(), 8);
        let one = r#"{"parents":[{"href":"/r/cat-season/season-2026","order":"a1"}]}"#;
        run(CATALOG, &cat_env("create", "matches.derby", one)).unwrap();
        // A folder name.
        run(CATALOG, &cat_env("create", "season-2026", one)).unwrap();
        // tree mode: two parents fail.
        let two = r#"{"parents":[{"href":"/r/cat-season/season-2026","order":"a1"},
                                 {"href":"/r/cat-season/derbies","order":"Zz"}]}"#;
        fails_at(
            run(CATALOG, &cat_env("create", "matches.derby", two)),
            1,
            "/rules/1/then/0",
        );
        fails_at(
            run(CATALOG, &cat_env("append", "matches.derby", two)),
            1,
            "/rules/1/then/0",
        );
        // A parent in another catalog, or a placement as parent.
        let elsewhere = r#"{"parents":[{"href":"/r/cat-other/season-2026"}]}"#;
        fails_at(
            run(CATALOG, &cat_env("create", "matches.derby", elsewhere)),
            1,
            "/rules/1/then/0",
        );
        // No new roots.
        fails_at(
            run(CATALOG, &cat_env("create", "matches.derby", "{}")),
            2,
            "/rules/2/then/0",
        );
        fails_at(
            run(
                CATALOG,
                &cat_env("create", "matches.derby", r#"{"parents":[]}"#),
            ),
            2,
            "/rules/2/then/0",
        );
        // An append may make a root, by removing parents.
        run(CATALOG, &cat_env("append", "matches.derby", "{}")).unwrap();
        // Placements only from trusted namespaces.
        fails_at(
            run(CATALOG, &cat_env("create", "photos.derby", one)),
            0,
            "/rules/0",
        );
        fails_at(
            run(CATALOG, &cat_env("create", "Season", one)),
            0,
            "/rules/0",
        );
        // A config envelope has no resource: the first rule fails it.
        let mut cfg = env("config", "{}", &["/x"], None);
        if let Value::Object(m) = &mut cfg {
            m.remove("resource");
        }
        fails_at(run(CATALOG, &cfg), 0, "/rules/0");
    }

    #[test]
    fn writes_predicates() {
        let e = |w: &[&str]| env("append", "{}", w, None);
        let r = |form: &str| format!("[{form}]");
        let covers = r(r#"{"op":"writes","covers":"/a/b"}"#);
        run(&covers, &e(&["/a"])).unwrap();
        run(&covers, &e(&["/a/b"])).unwrap();
        run(&covers, &e(&[""])).unwrap();
        assert!(run(&covers, &e(&["/a/b/c"])).is_err());
        assert!(run(&covers, &e(&["/a/bc"])).is_err());
        assert!(run(&covers, &e(&[])).is_err());
        let overlaps = r(r#"{"op":"writes","overlaps":"/a/b"}"#);
        run(&overlaps, &e(&["/a/b/c"])).unwrap();
        run(&overlaps, &e(&["/x", "/a"])).unwrap();
        assert!(run(&overlaps, &e(&["/a/c"])).is_err());
        assert!(run(&overlaps, &e(&[])).is_err());
        let within = r(r#"{"op":"writes","within":["/i18n/sv","/t"]}"#);
        run(&within, &e(&[])).unwrap();
        run(&within, &e(&["/i18n/sv/title", "/t"])).unwrap();
        assert!(run(&within, &e(&["/i18n/sv/title", "/i18n"])).is_err());
        assert!(run(&within, &e(&[""])).is_err());
        // Segment by segment after unescaping, never as strings.
        let esc = r(r#"{"op":"writes","covers":"/a~1b"}"#);
        run(&esc, &e(&["/a~1b"])).unwrap();
        assert!(run(&esc, &e(&["/a"])).is_err());
        let tilde = r(r#"{"op":"writes","within":["/~0x"]}"#);
        run(&tilde, &e(&["/~0x/1"])).unwrap();
        assert!(run(&tilde, &e(&["/~01x"])).is_err());
    }

    #[test]
    fn tests_and_compare() {
        let e = env(
            "append",
            r#"{"n":3,"a":[1,2],"s":"x","nil":null,"t":"2026-10-04T18:02:11.482Z"}"#,
            &["/n"],
            None,
        );
        let ok = |form: &str| run(&format!("[{form}]"), &e).unwrap();
        let no = |form: &str| assert!(run(&format!("[{form}]"), &e).is_err(), "{form}");
        ok(r#"{"op":"test","path":"/doc/n","value":3.0}"#);
        ok(r#"{"op":"test","path":"/doc/nil","value":null}"#);
        no(r#"{"op":"test","path":"/doc/missing","value":null}"#);
        no(r#"{"op":"test","path":"/doc/missing","schema":true}"#);
        ok(r#"{"op":"test","path":"/doc/missing","exists":false}"#);
        ok(r#"{"op":"test","path":"/doc/a/1","exists":true}"#);
        ok(r#"{"op":"test","path":"/doc/a/2","exists":false}"#);
        ok(r#"{"op":"test","path":"/doc/a/-","exists":false}"#);
        ok(r#"{"op":"test","path":"/doc/a/01","exists":false}"#);
        ok(r#"{"op":"test","path":"/doc/t","schema":{"format":"date-time"}}"#);
        no(r#"{"op":"test","path":"/doc/s","schema":{"format":"date-time"}}"#);
        ok(
            r##"{"op":"test","path":"/doc","schema":{"$defs":{"n":{"type":"integer"}},"properties":{"n":{"$ref":"#/$defs/n"}}}}"##,
        );
        no(
            r##"{"op":"test","path":"/doc","schema":{"$defs":{"n":{"type":"integer"}},"properties":{"s":{"$ref":"#/$defs/n"}}}}"##,
        );
        ok(r#"{"op":"test","path":"/doc/s","schema":{"pattern":"^\\x{78}$"}}"#);
        ok(r#"{"op":"compare","path":"/doc/n","gt":{"value":2.5}}"#);
        ok(r#"{"op":"compare","path":"/doc/n","le":{"value":3}}"#);
        no(r#"{"op":"compare","path":"/doc/n","lt":{"value":"4"}}"#);
        ok(r#"{"op":"compare","path":"/doc/a/1","in":{"path":"/doc/a"}}"#);
        no(r#"{"op":"compare","path":"/doc/n","in":{"path":"/doc/a"}}"#);
        no(r#"{"op":"compare","path":"/doc/n","in":{"value":3}}"#);
        ok(r#"{"op":"compare","path":"/doc/a/0","in":{"value":[0,1]}}"#);
        no(r#"{"op":"compare","path":"/doc/missing","eq":{"value":null}}"#);
        no(r#"{"op":"compare","path":"/doc/nil","eq":{"path":"/doc/missing"}}"#);
        ok(r#"{"op":"compare","path":"/now","eq":{"path":"/doc/t"}}"#);
        ok(r#"{"op":"compare","path":"/now","ge":{"value":"2026-10-04T18:02:11.48200Z"}}"#);
        ok(r#"{"op":"compare","path":"/now","gt":{"value":"2026-10-04T18:02:11.4819999Z"}}"#);
        ok(r#"{"op":"compare","path":"/now","lt":{"value":"2026-10-04T18:02:11.482001Z"}}"#);
        ok(r#"{"op":"compare","path":"/now","gt":{"value":"2026-10-04T20:02:11.481+02:00"}}"#);
        no(r#"{"op":"compare","path":"/now","gt":{"value":"2026-10-04T18:01:60Z"}}"#);
        no(r#"{"op":"compare","path":"/now","gt":{"value":"2026-10-04 18:00:00Z"}}"#);
        no(r#"{"op":"compare","path":"/now","gt":{"value":"2026-10-04T18:00:00z"}}"#);
        no(r#"{"op":"compare","path":"/now","gt":{"value":"2026-02-30T18:00:00Z"}}"#);
        // all, any and their paths.
        ok(r#"{"all":[]}"#);
        no(r#"{"any":[]}"#);
        ok(
            r#"{"any":[{"op":"test","path":"/x","exists":true},{"op":"test","path":"/action","value":"append"}]}"#,
        );
        let r = run(
            r#"[{"op":"test","path":"/action","value":"append"},
                {"all":[{"op":"test","path":"/doc/n","value":3},
                        {"all":[{"op":"test","path":"/doc/s","value":"y"},{"op":"test","path":"/q","exists":true}]}]}]"#,
            &e,
        );
        fails_at(r, 1, "/rules/1/all/1/all/0");
        let r = run(
            r#"[{"any":[{"op":"test","path":"/x","exists":true}]},{"all":[]}]"#,
            &e,
        );
        fails_at(r, 0, "/rules/0");
        let r = run(r#"[{"not":{"all":[]}}]"#, &e);
        fails_at(r, 0, "/rules/0");
    }

    #[test]
    fn instants() {
        assert_eq!(instant("1970-01-01T00:00:00Z"), Some((0, String::new())));
        assert_eq!(
            instant("2000-03-01T00:00:00.500Z"),
            Some((951_868_800, "5".into()))
        );
        assert_eq!(
            instant("1970-01-01T01:00:00+01:00"),
            Some((0, String::new()))
        );
        assert_eq!(
            instant("2024-02-29T00:00:00Z").map(|x| x.0),
            Some(1_709_164_800)
        );
        assert!(instant("2023-02-29T00:00:00Z").is_none());
        assert!(instant("2026-10-04T18:02:11.Z").is_none());
        assert!(instant("2026-10-04T18:02:11").is_none());
        assert!(instant("2026-10-04T18:02:11+0100").is_none());
    }

    fn refused(rules: &str) -> Vec<(String, String)> {
        match validate(&v(rules), 256) {
            Err(RulesError::Invalid(e)) => e,
            r => panic!("{rules}: {r:?}"),
        }
    }

    #[test]
    fn validation_refusals() {
        validate(&v(EXAMPLES), 256).unwrap();
        validate(&v(OWNERSHIP), 256).unwrap();
        validate(&v(CATALOG), 256).unwrap();
        validate(&v("[]"), 0).unwrap();
        for (rules, pointer) in [
            (r#"{}"#, "/rules"),
            (r#"[1]"#, "/rules/0"),
            (r#"[{"op":"frob","path":""}]"#, "/rules/0/op"),
            (r#"[{"op":"test","path":"/a"}]"#, "/rules/0"),
            (r#"[{"op":"test","path":"a","value":1}]"#, "/rules/0/path"),
            (
                r#"[{"op":"test","path":"/a","value":1,"exists":true}]"#,
                "/rules/0",
            ),
            (
                r#"[{"op":"test","path":"/a","exists":"yes"}]"#,
                "/rules/0/exists",
            ),
            (
                r#"[{"op":"test","path":"/a","value":1,"x":2}]"#,
                "/rules/0/x",
            ),
            (r#"[{"op":"writes","within":"/a"}]"#, "/rules/0/within"),
            (
                r#"[{"op":"writes","within":["/a","b"]}]"#,
                "/rules/0/within/1",
            ),
            (
                r#"[{"op":"writes","covers":"/a","overlaps":"/b"}]"#,
                "/rules/0",
            ),
            (r#"[{"op":"compare","path":"/a","eq":3}]"#, "/rules/0/eq"),
            (
                r#"[{"op":"compare","path":"/a","eq":{"value":1,"path":"/b"}}]"#,
                "/rules/0/eq",
            ),
            (
                r#"[{"op":"compare","path":"/a","ne":{"value":1}}]"#,
                "/rules/0/ne",
            ),
            (r#"[{"frob":[]}]"#, "/rules/0"),
            (r#"[{"all":[{"op":"nope"}]}]"#, "/rules/0/all/0/op"),
            (r#"[{"all":[], "any":[]}]"#, "/rules/0/any"),
            (r#"[{"if":[]}]"#, "/rules/0"),
            (r#"[{"if":[],"then":[{"not":[]}]}]"#, "/rules/0/then/0/not"),
            // Schema fragments.
            (
                r#"[{"op":"test","path":"/a","schema":{"pattern":"(a)\\1"}}]"#,
                "/rules/0/schema/pattern",
            ),
            (
                r#"[{"op":"test","path":"/a","schema":{"pattern":"\\ud800"}}]"#,
                "/rules/0/schema/pattern",
            ),
            (
                r#"[{"op":"test","path":"/a","schema":{"properties":{"b":{"$id":"x"}}}}]"#,
                "/rules/0/schema/properties/b/$id",
            ),
            (
                r#"[{"op":"test","path":"/a","schema":{"$schema":"https://json-schema.org/draft/2020-12/schema"}}]"#,
                "/rules/0/schema/$schema",
            ),
            (
                r#"[{"op":"test","path":"/a","schema":{"$ref":"/r/s/x/rev/1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll"}}]"#,
                "/rules/0/schema/$ref",
            ),
            (
                r#"[{"op":"test","path":"/a","schema":{"$ref":"https://example.com/s"}}]"#,
                "/rules/0/schema",
            ),
            (
                r##"[{"op":"test","path":"/a","schema":{"$ref":"#/$defs/missing"}}]"##,
                "/rules/0/schema",
            ),
            (
                r#"[{"op":"test","path":"/a","schema":{"$dynamicRef":"/r/s/x"}}]"#,
                "/rules/0/schema",
            ),
            (
                r#"[{"op":"test","path":"/a","schema":{"format":"phone"}}]"#,
                "/rules/0/schema/format",
            ),
            (
                r#"[{"op":"test","path":"/a","schema":{"frobnicate":1}}]"#,
                "/rules/0/schema/frobnicate",
            ),
            (
                r#"[{"op":"test","path":"/a","schema":{"type":"integr"}}]"#,
                "/rules/0/schema/type",
            ),
            (
                r#"[{"op":"test","path":"/a","schema":3}]"#,
                "/rules/0/schema",
            ),
        ] {
            let errs = refused(rules);
            assert_eq!(errs[0].0, pointer, "{rules}: {errs:?}");
        }
        // Every error is reported, not only the first.
        let errs = refused(r#"[{"op":"x"},{"op":"test","path":"/a"},{"all":[1,2]}]"#);
        assert_eq!(errs.len(), 4, "{errs:?}");
        // Same-document references and x- annotations are fine.
        validate(
            &v(r##"[{"op":"test","path":"/doc","schema":{"$defs":{"n":{"type":"integer","x-note":1}},
                    "properties":{"a":{"$ref":"#/$defs/n"},"b":{"$ref":"#"}}}}]"##),
            256,
        )
        .unwrap();
    }

    #[test]
    fn rules_per_namespace() {
        // EXAMPLES: 3 + 5 + 3 + 4 forms.
        assert_eq!(check(&v(EXAMPLES), "/rules").unwrap(), 15);
        // OWNERSHIP: 1 + if(2 + 1) + then(1 + 1 + (1 + 1 + 2·2) + (1 + 1 + 1)).
        assert_eq!(check(&v(OWNERSHIP), "/rules").unwrap(), 15);
        validate(&v(EXAMPLES), 15).unwrap();
        assert_eq!(
            validate(&v(EXAMPLES), 14),
            Err(RulesError::Limit {
                measured: 15,
                max: 14
            })
        );
        // Invalid is reported before the count.
        assert!(matches!(
            validate(&v(r#"[{"op":"x"},{"all":[]}]"#), 0),
            Err(RulesError::Invalid(_))
        ));
        let c = CompiledRules::at(
            &v(r#"[{"op":"writes","within":["/i18n"]}]"#),
            "/roles/translator/rules",
        )
        .unwrap();
        assert_eq!(c.count(), 1);
        fails_at(
            c.evaluate(&env("append", "{}", &["/title"], None)),
            0,
            "/roles/translator/rules/0",
        );
    }

    #[test]
    fn invalid_rules_fail_closed() {
        let e = env("append", "{}", &[], None);
        let f = evaluate(&v(r#"[{"all":[]},{"op":"frob"}]"#), &e).unwrap_err();
        assert_eq!((f.rule, f.path.as_str()), (1, "/rules/1/op"));
        assert!(CompiledRules::new(&v("[]")).unwrap().is_empty());
        evaluate(&v("[]"), &e).unwrap();
    }
}
