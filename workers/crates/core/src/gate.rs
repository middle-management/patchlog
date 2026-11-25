//! The platform-neutral parts of a resource write (§6.2): reading the body,
//! hashing the patch set, applying it and checking the result. Storage,
//! preconditions and the namespace entry are the caller's.

use crate::id::{revision_id, Id};
use crate::json::{self, canonical, Value};
use crate::limits::{measure, LimitError, Limits};
use crate::patch::{apply, parse_patch_set, Op, OpKind, PatchError};

#[derive(Debug, Clone, PartialEq)]
pub enum GateError {
    /// `400` `bad_input`.
    BadInput(String),
    /// `413` or `422` `limit`.
    Limit { status: u16, err: LimitError },
    /// `422` `invalid`.
    Invalid(String),
    /// `422` `blob`.
    Blob(String),
}

impl GateError {
    pub fn status(&self) -> u16 {
        match self {
            GateError::BadInput(_) => 400,
            GateError::Limit { status, .. } => *status,
            GateError::Invalid(_) | GateError::Blob(_) => 422,
        }
    }
}

impl From<PatchError> for GateError {
    fn from(e: PatchError) -> Self {
        GateError::Invalid(e.to_string())
    }
}

/// A patch set as read from a request, before any state is consulted.
#[derive(Debug, Clone)]
pub struct Body {
    pub value: Value,
    /// `canonical(patches)`, what is stored and hashed (§3.1).
    pub canonical: Vec<u8>,
}

/// §6.6: a `PATCH` body more than four times the larger of the deployment
/// maximums of `patchSetSize` and `documentSize` is `413` before parsing.
pub fn max_body(deployment: &Limits) -> u64 {
    4 * deployment.patch_set_size.max(deployment.document_size)
}

/// Request-shape checks: size before parsing, then I-JSON (§3.1).
pub fn read_body(bytes: &[u8], deployment: &Limits) -> Result<Body, GateError> {
    let max = max_body(deployment);
    if bytes.len() as u64 > max {
        return Err(GateError::Limit {
            status: 413,
            err: LimitError {
                limit: "documentSize",
                measured: Some(bytes.len() as u64),
                max: deployment.document_size,
            },
        });
    }
    let value = json::parse(bytes).map_err(|e| GateError::BadInput(e.to_string()))?;
    let canonical = canonical(&value);
    Ok(Body { value, canonical })
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WriteKind {
    Create,
    Append,
    Restore,
}

/// A checked write, ready to insert.
#[derive(Debug)]
pub struct Prepared {
    pub id: Id,
    pub doc: Value,
    pub doc_size: u64,
    pub writes: Vec<String>,
}

/// §6.6 "Whole documents": a create, or an append or restore whose first
/// operation other than `test` is a root `replace` or `add`, may be as large
/// as `documentSize`.
fn whole_document(kind: WriteKind, ops: &[Op]) -> bool {
    kind == WriteKind::Create
        || ops
            .iter()
            .find(|o| o.kind != OpKind::Test)
            .is_some_and(|o| o.path.is_empty() && matches!(o.kind, OpKind::Add | OpKind::Replace))
}

/// The id a write of `body` on `parent` gets (§3.3), for the idempotent-retry
/// lookup and the insert.
pub fn id_for(parent: Option<&Id>, body: &Body) -> Id {
    revision_id(parent, &body.canonical)
}

/// Steps 3 and 4 of §6.2 for a create, append or restore: apply the patches
/// to `doc` (consumed; `Value::Null` for a create) and check the result.
/// Schema validation (step 5) needs schema revisions resolved, so it is the
/// caller's (`schema`); rules (step 6) are not implemented.
pub fn apply_and_check(
    parent: Option<&Id>,
    mut doc: Value,
    body: &Body,
    kind: WriteKind,
    limits: &Limits,
) -> Result<Prepared, GateError> {
    let ops = parse_patch_set(&body.value)?;
    let writes = apply(&mut doc, &ops)?;
    if kind == WriteKind::Create && writes.is_empty() {
        return Err(GateError::Invalid("a create must write something".into()));
    }
    // Step 4: limits, then blob references.
    let patch_max = if whole_document(kind, &ops) {
        limits.document_size
    } else {
        limits.patch_set_size
    };
    let plen = body.canonical.len() as u64;
    if plen > patch_max {
        let limit =
            if patch_max == limits.document_size && limits.document_size != limits.patch_set_size {
                "documentSize"
            } else {
                "patchSetSize"
            };
        return Err(GateError::Limit {
            status: 422,
            err: LimitError {
                limit,
                measured: Some(plen),
                max: patch_max,
            },
        });
    }
    if ops.len() as u64 > limits.ops_per_set {
        return Err(GateError::Limit {
            status: 422,
            err: LimitError {
                limit: "opsPerSet",
                measured: Some(ops.len() as u64),
                max: limits.ops_per_set,
            },
        });
    }
    let m = measure(&doc, limits);
    m.check(limits)
        .map_err(|err| GateError::Limit { status: 422, err })?;
    Ok(Prepared {
        id: revision_id(parent, &body.canonical),
        doc,
        doc_size: m.size,
        writes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_append() {
        let l = Limits::default();
        let b = read_body(
            br#"[{"op":"add","path":"","value":{"title":"Hello","views":0}}]"#,
            &l,
        )
        .unwrap();
        let p = apply_and_check(None, Value::Null, &b, WriteKind::Create, &l).unwrap();
        assert_eq!(p.id.text(), "1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll");
        let b2 = read_body(br#"[ {"value":1, "op":"replace","path":"/views"} ]"#, &l).unwrap();
        let p2 = apply_and_check(Some(&p.id), p.doc, &b2, WriteKind::Append, &l).unwrap();
        assert_eq!(p2.id.text(), "1sywh54kpo3c4ezn2znktvl3avge4zl5d");
        assert_eq!(p2.doc_size, 27);
    }

    #[test]
    fn refusals() {
        let l = Limits {
            patch_set_size: 40,
            document_size: 60,
            ..Limits::default()
        };
        let doc = json::parse(br#"{"a":1}"#).unwrap();
        // Empty create.
        let b = read_body(br#"[{"op":"test","path":"","value":null}]"#, &l).unwrap();
        assert!(matches!(
            apply_and_check(None, Value::Null, &b, WriteKind::Create, &l),
            Err(GateError::Invalid(_))
        ));
        // Patch set over patchSetSize, but a root replace may reach documentSize.
        let b = read_body(br#"[{"op":"add","path":"/b","value":"0123456789"}]"#, &l).unwrap();
        let e = apply_and_check(None, doc.clone(), &b, WriteKind::Append, &l).unwrap_err();
        assert!(
            matches!(e, GateError::Limit { status: 422, ref err } if err.limit == "patchSetSize")
        );
        let b = read_body(
            br#"[{"op":"replace","path":"","value":{"b":"0123456789"}}]"#,
            &l,
        )
        .unwrap();
        apply_and_check(None, doc.clone(), &b, WriteKind::Append, &l).unwrap();
        // Blob references are counted here; whether they are well formed
        // and available is the caller's check (blob::refs, §7.8).
        let b = read_body(br#"[{"op":"add","path":"/f","value":{"$blob":"x"}}]"#, &l).unwrap();
        let d = Limits::default();
        apply_and_check(None, doc.clone(), &b, WriteKind::Append, &d).unwrap();
        // Not I-JSON.
        assert!(matches!(
            read_body(br#"[{"op":"add","op":"x"}]"#, &l),
            Err(GateError::BadInput(_))
        ));
    }
}
