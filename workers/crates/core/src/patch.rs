//! JSON Pointer (RFC 6901) and JSON Patch (RFC 6902), with the `writes` of
//! the change envelope (§6.4.1).

use crate::json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct PatchError {
    /// Index of the failing operation.
    pub op: usize,
    pub message: String,
}

impl std::fmt::Display for PatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "operation {}: {}", self.op, self.message)
    }
}

/// Parses a JSON Pointer into unescaped reference tokens.
pub fn parse_pointer(p: &str) -> Result<Vec<String>, String> {
    if p.is_empty() {
        return Ok(vec![]);
    }
    if !p.starts_with('/') {
        return Err(format!("pointer {p:?} doesn't start with '/'"));
    }
    p[1..]
        .split('/')
        .map(|t| {
            let mut out = String::with_capacity(t.len());
            let mut it = t.chars();
            while let Some(c) = it.next() {
                if c == '~' {
                    match it.next() {
                        Some('0') => out.push('~'),
                        Some('1') => out.push('/'),
                        _ => return Err(format!("bad escape in pointer {p:?}")),
                    }
                } else {
                    out.push(c);
                }
            }
            Ok(out)
        })
        .collect()
}

pub fn escape_token(t: &str) -> String {
    t.replace('~', "~0").replace('/', "~1")
}

pub fn pointer_string(tokens: &[String]) -> String {
    let mut s = String::new();
    for t in tokens {
        s.push('/');
        s.push_str(&escape_token(t));
    }
    s
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OpKind {
    Add,
    Remove,
    Replace,
    Move,
    Copy,
    Test,
}

#[derive(Debug, Clone)]
pub struct Op {
    pub kind: OpKind,
    pub path: Vec<String>,
    pub from: Option<Vec<String>>,
    pub value: Option<Value>,
}

/// Reads a patch set: an array of operation objects. Shape errors are `422`
/// (`invalid`): the body was I-JSON, so this is operation validation (§6.2 step 3).
pub fn parse_patch_set(v: &Value) -> Result<Vec<Op>, PatchError> {
    let arr = v.as_array().ok_or(PatchError {
        op: 0,
        message: "a patch set is an array".into(),
    })?;
    let mut ops = Vec::with_capacity(arr.len());
    for (i, o) in arr.iter().enumerate() {
        let e = |m: &str| PatchError {
            op: i,
            message: m.into(),
        };
        let obj = o
            .as_object()
            .ok_or_else(|| e("an operation is an object"))?;
        let kind = match obj.get("op").and_then(Value::as_str) {
            Some("add") => OpKind::Add,
            Some("remove") => OpKind::Remove,
            Some("replace") => OpKind::Replace,
            Some("move") => OpKind::Move,
            Some("copy") => OpKind::Copy,
            Some("test") => OpKind::Test,
            Some("sealed") => {
                return Err(e("a sealed op is only accepted in an end-to-end namespace"))
            }
            Some(other) => return Err(e(&format!("unknown op {other:?}"))),
            None => return Err(e("missing op")),
        };
        let path = obj
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| e("missing path"))?;
        let path = parse_pointer(path).map_err(|m| e(&m))?;
        let from = match kind {
            OpKind::Move | OpKind::Copy => {
                let f = obj
                    .get("from")
                    .and_then(Value::as_str)
                    .ok_or_else(|| e("missing from"))?;
                Some(parse_pointer(f).map_err(|m| e(&m))?)
            }
            _ => None,
        };
        let value = match kind {
            OpKind::Add | OpKind::Replace | OpKind::Test => Some(
                obj.get("value")
                    .cloned()
                    .ok_or_else(|| e("missing value"))?,
            ),
            _ => None,
        };
        if kind == OpKind::Move {
            let f = from.as_ref().unwrap();
            if f.len() < path.len() && path[..f.len()] == f[..] {
                return Err(e("can't move a value into itself"));
            }
        }
        ops.push(Op {
            kind,
            path,
            from,
            value,
        });
    }
    Ok(ops)
}

fn array_index(tok: &str, len: usize, allow_end: bool) -> Result<usize, String> {
    if allow_end && tok == "-" {
        return Ok(len);
    }
    let ok = !tok.is_empty()
        && tok.bytes().all(|b| b.is_ascii_digit())
        && (tok == "0" || !tok.starts_with('0'));
    if !ok {
        return Err(format!("{tok:?} isn't an array index"));
    }
    let i: usize = tok
        .parse()
        .map_err(|_| format!("{tok:?} is out of range"))?;
    let max = if allow_end {
        len
    } else {
        len.saturating_sub(1)
    };
    if i > max || (!allow_end && len == 0) {
        return Err(format!("index {i} is out of range"));
    }
    Ok(i)
}

fn get<'a>(doc: &'a Value, path: &[String]) -> Result<&'a Value, String> {
    let mut cur = doc;
    for t in path {
        cur = match cur {
            Value::Object(m) => m
                .get(t)
                .ok_or_else(|| format!("{} doesn't exist", pointer_string(path)))?,
            Value::Array(a) => &a[array_index(t, a.len(), false)?],
            _ => return Err(format!("{} doesn't exist", pointer_string(path))),
        };
    }
    Ok(cur)
}

fn get_mut<'a>(doc: &'a mut Value, path: &[String]) -> Result<&'a mut Value, String> {
    let mut cur = doc;
    for t in path {
        cur = match cur {
            Value::Object(m) => m
                .get_mut(t)
                .ok_or_else(|| format!("{} doesn't exist", pointer_string(path)))?,
            Value::Array(a) => {
                let i = array_index(t, a.len(), false)?;
                &mut a[i]
            }
            _ => return Err(format!("{} doesn't exist", pointer_string(path))),
        };
    }
    Ok(cur)
}

/// What one operation wrote, as tokens; `None` marks a root write.
struct Effect {
    writes: Vec<Vec<String>>,
}

fn add(doc: &mut Value, path: &[String], v: Value, eff: &mut Effect) -> Result<(), String> {
    let Some((last, parent)) = path.split_last() else {
        *doc = v;
        eff.writes.push(vec![]);
        return Ok(());
    };
    match get_mut(doc, parent)? {
        Value::Object(m) => {
            m.insert(last.clone(), v);
            eff.writes.push(path.to_vec());
        }
        Value::Array(a) => {
            let i = array_index(last, a.len(), true)?;
            let shifts = i < a.len();
            a.insert(i, v);
            let mut w = parent.to_vec();
            w.push(i.to_string());
            eff.writes.push(w);
            if shifts {
                eff.writes.push(parent.to_vec());
            }
        }
        _ => {
            return Err(format!(
                "the parent of {} isn't a container",
                pointer_string(path)
            ))
        }
    }
    Ok(())
}

fn remove(doc: &mut Value, path: &[String], eff: &mut Effect) -> Result<Value, String> {
    let Some((last, parent)) = path.split_last() else {
        eff.writes.push(vec![]);
        return Ok(std::mem::replace(doc, Value::Null));
    };
    let out = match get_mut(doc, parent)? {
        Value::Object(m) => m
            .remove(last)
            .ok_or_else(|| format!("{} doesn't exist", pointer_string(path)))?,
        Value::Array(a) => {
            let i = array_index(last, a.len(), false)?;
            if i + 1 < a.len() {
                eff.writes.push(parent.to_vec());
            }
            a.remove(i)
        }
        _ => return Err(format!("{} doesn't exist", pointer_string(path))),
    };
    eff.writes.push(path.to_vec());
    Ok(out)
}

/// Is this an `add` or `replace` of a fresh-form `$nonce` (§6.4.1)?
fn fresh_nonce(op: &Op) -> bool {
    matches!(op.kind, OpKind::Add | OpKind::Replace)
        && op.path.len() == 1
        && op.path[0] == "$nonce"
        && op
            .value
            .as_ref()
            .and_then(Value::as_str)
            .is_some_and(crate::names::is_base32_26)
}

/// Applies `ops` to `doc` in place and returns `writes` (§6.4.1) as pointer
/// strings. On error `doc` is left partly patched; callers work on a copy.
pub fn apply(doc: &mut Value, ops: &[Op]) -> Result<Vec<String>, PatchError> {
    let mut writes = Vec::new();
    for (i, op) in ops.iter().enumerate() {
        let mut eff = Effect { writes: Vec::new() };
        let r: Result<(), String> = (|| {
            match op.kind {
                OpKind::Add => add(doc, &op.path, op.value.clone().unwrap(), &mut eff)?,
                OpKind::Remove => {
                    remove(doc, &op.path, &mut eff)?;
                }
                OpKind::Replace => {
                    let target = get_mut(doc, &op.path)?;
                    *target = op.value.clone().unwrap();
                    eff.writes.push(op.path.clone());
                }
                OpKind::Move => {
                    let from = op.from.as_ref().unwrap();
                    if from == &op.path {
                        get(doc, from)?;
                        eff.writes.push(from.clone());
                    } else {
                        let v = remove(doc, from, &mut eff)?;
                        add(doc, &op.path, v, &mut eff)?;
                    }
                }
                OpKind::Copy => {
                    let v = get(doc, op.from.as_ref().unwrap())?.clone();
                    add(doc, &op.path, v, &mut eff)?;
                }
                OpKind::Test => {
                    let have = get(doc, &op.path)?;
                    if have != op.value.as_ref().unwrap() {
                        return Err(format!("test failed at {}", pointer_string(&op.path)));
                    }
                }
            }
            Ok(())
        })();
        r.map_err(|message| PatchError { op: i, message })?;
        if !fresh_nonce(op) {
            writes.extend(eff.writes.iter().map(|w| pointer_string(w)));
        }
    }
    Ok(writes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::{canonical_string, parse};

    fn run(doc: &str, patch: &str) -> Result<(String, Vec<String>), PatchError> {
        let mut d = parse(doc.as_bytes()).unwrap();
        let ops = parse_patch_set(&parse(patch.as_bytes()).unwrap())?;
        let w = apply(&mut d, &ops)?;
        Ok((canonical_string(&d), w))
    }

    #[test]
    fn genesis_and_append() {
        let (d, w) = run(
            "null",
            r#"[{"op":"add","path":"","value":{"title":"Hello","views":0}}]"#,
        )
        .unwrap();
        assert_eq!(d, r#"{"title":"Hello","views":0}"#);
        assert_eq!(w, vec![""]);
        let (d, w) = run(&d, r#"[{"op":"replace","path":"/views","value":1}]"#).unwrap();
        assert_eq!(d, r#"{"title":"Hello","views":1}"#);
        assert_eq!(w, vec!["/views"]);
    }

    #[test]
    fn rfc6902_ops() {
        let doc = r#"{"a":[1,2,3],"b":{"c":"x"},"m~/":1}"#;
        assert_eq!(
            run(doc, r#"[{"op":"add","path":"/a/-","value":4}]"#)
                .unwrap()
                .1,
            vec!["/a/3"]
        );
        assert_eq!(
            run(doc, r#"[{"op":"add","path":"/a/0","value":0}]"#)
                .unwrap()
                .1,
            vec!["/a/0", "/a"]
        );
        assert_eq!(
            run(doc, r#"[{"op":"remove","path":"/a/2"}]"#).unwrap().1,
            vec!["/a/2"]
        );
        assert_eq!(
            run(doc, r#"[{"op":"remove","path":"/a/0"}]"#).unwrap().1,
            vec!["/a", "/a/0"]
        );
        let (d, w) = run(doc, r#"[{"op":"move","from":"/b/c","path":"/d"}]"#).unwrap();
        assert_eq!(d, r#"{"a":[1,2,3],"b":{},"d":"x","m~/":1}"#);
        assert_eq!(w, vec!["/b/c", "/d"]);
        let (d, _) = run(doc, r#"[{"op":"copy","from":"/b","path":"/e"}]"#).unwrap();
        assert_eq!(d, r#"{"a":[1,2,3],"b":{"c":"x"},"e":{"c":"x"},"m~/":1}"#);
        assert_eq!(
            run(doc, r#"[{"op":"test","path":"/m~0~1","value":1.0}]"#)
                .unwrap()
                .1,
            Vec::<String>::new()
        );
        assert!(run(doc, r#"[{"op":"test","path":"/a","value":[1,2]}]"#).is_err());
        assert!(run(doc, r#"[{"op":"replace","path":"/zz","value":1}]"#).is_err());
        assert!(run(doc, r#"[{"op":"add","path":"/a/01","value":1}]"#).is_err());
        assert!(run(doc, r#"[{"op":"add","path":"/a/4","value":1}]"#).is_err());
        assert!(run(doc, r#"[{"op":"move","from":"/b","path":"/b/c"}]"#).is_err());
        assert!(run(doc, r#"[{"op":"frobnicate","path":"/a"}]"#).is_err());
        assert!(run(doc, r#"[{"op":"add","path":"a","value":1}]"#).is_err());
    }

    #[test]
    fn fresh_nonce_is_not_a_write() {
        let (_, w) = run(
            r#"{"a":1}"#,
            r#"[{"op":"add","path":"/$nonce","value":"abcdefghijklmnopqrstuvwxyz"}]"#,
        )
        .unwrap();
        assert!(w.is_empty());
        let (_, w) = run(
            r#"{"a":1}"#,
            r#"[{"op":"add","path":"/$nonce","value":"short"}]"#,
        )
        .unwrap();
        assert_eq!(w, vec!["/$nonce"]);
    }
}
