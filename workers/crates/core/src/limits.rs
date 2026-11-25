//! The patch-set and document limits of §6.6 (defaults from §12.2), measured
//! in one walk of the resulting document.

use crate::json::{number_len, string_len, Value};

#[derive(Clone, Debug, PartialEq)]
pub struct Limits {
    pub patch_set_size: u64,
    pub ops_per_set: u64,
    pub document_size: u64,
    pub value_size: u64,
    pub path_size: u64,
    pub nesting_depth: u64,
    pub log_page_size: u64,
    pub log_page_bytes: u64,
}

pub const KIB: u64 = 1024;
pub const MIB: u64 = 1024 * 1024;

impl Default for Limits {
    fn default() -> Self {
        Limits {
            patch_set_size: 256 * KIB,
            ops_per_set: 1000,
            document_size: MIB,
            value_size: 64 * KIB,
            path_size: 2 * KIB,
            nesting_depth: 64,
            log_page_size: 1000,
            log_page_bytes: 16 * MIB,
        }
    }
}

impl Limits {
    /// This deployment's maximums. `documentSize` stops at 1.5 MiB rather
    /// than the 4 MiB §12.2 calls typical, so that a document's canonical
    /// form plus its row overhead stays under the 2 MB a SQLite-backed
    /// Durable Object allows per value, and a namespace's head documents fit
    /// in a 128 MB isolate.
    pub fn deployment_max() -> Limits {
        Limits {
            document_size: 3 * MIB / 2,
            ..Limits::default()
        }
    }

    /// Reads `limits` from a namespace document over the defaults. Unknown
    /// keys and values above the maximum are reported by the caller's
    /// validation; here they are ignored.
    pub fn from_config(cfg: &Value) -> Limits {
        let mut l = Limits::default();
        if let Some(m) = cfg.get("limits").and_then(Value::as_object) {
            let n = |k: &str| {
                m.get(k).and_then(|v| {
                    if let Value::Number(n) = v {
                        Some(*n as u64)
                    } else {
                        None
                    }
                })
            };
            if let Some(v) = n("patchSetSize") {
                l.patch_set_size = v;
            }
            if let Some(v) = n("opsPerSet") {
                l.ops_per_set = v;
            }
            if let Some(v) = n("documentSize") {
                l.document_size = v;
            }
            if let Some(v) = n("valueSize") {
                l.value_size = v;
            }
            if let Some(v) = n("pathSize") {
                l.path_size = v;
            }
            if let Some(v) = n("nestingDepth") {
                l.nesting_depth = v;
            }
        }
        l
    }
}

/// The keys this server accepts in a namespace document's `limits`, with
/// their maximums.
pub fn settable_limit_max(key: &str) -> Option<u64> {
    let m = Limits::deployment_max();
    Some(match key {
        "patchSetSize" => m.patch_set_size,
        "opsPerSet" => m.ops_per_set,
        "documentSize" => m.document_size,
        "valueSize" => m.value_size,
        "pathSize" => m.path_size,
        "nestingDepth" => m.nesting_depth,
        _ => return None,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct LimitError {
    pub limit: &'static str,
    pub measured: Option<u64>,
    pub max: u64,
}

/// What one walk of a document finds.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Measure {
    /// Length of the canonical form.
    pub size: u64,
    pub depth: u64,
    /// First string longer than `valueSize`, as canonical JSON.
    pub long_value: Option<u64>,
    /// First pointer longer than `pathSize`, as canonical JSON.
    pub long_path: Option<u64>,
    /// Objects whose `$blob` member is a string (§6.5).
    pub blob_refs: u64,
}

pub fn measure(doc: &Value, l: &Limits) -> Measure {
    let mut m = Measure::default();
    m.size = walk(doc, 0, 2, l, &mut m);
    m
}

/// Length of a reference token inside a canonical JSON string, after `~`
/// and `/` escaping, with its leading `/`.
fn token_len(t: &str) -> u64 {
    1 + (string_len(t) as u64 - 2) + t.bytes().filter(|&b| b == b'~' || b == b'/').count() as u64
}

/// Returns the canonical length of `v`; `path` is the canonical length of
/// the pointer to `v`, quotes included.
fn walk(v: &Value, depth: u64, path: u64, l: &Limits, m: &mut Measure) -> u64 {
    if path > l.path_size && m.long_path.is_none() {
        m.long_path = Some(path);
    }
    let check_str = |s: &str, m: &mut Measure| {
        let n = string_len(s) as u64;
        if n > l.value_size && m.long_value.is_none() {
            m.long_value = Some(n);
        }
        n
    };
    match v {
        Value::Null | Value::Bool(true) => 4,
        Value::Bool(false) => 5,
        Value::Number(n) => number_len(*n) as u64,
        Value::String(s) => check_str(s, m),
        Value::Array(a) => {
            m.depth = m.depth.max(depth + 1);
            let mut size = 2 + a.len().saturating_sub(1) as u64;
            for (i, x) in a.iter().enumerate() {
                let t = 1 + digits(i);
                size += walk(x, depth + 1, path + t, l, m);
            }
            size
        }
        Value::Object(o) => {
            m.depth = m.depth.max(depth + 1);
            if matches!(o.get("$blob"), Some(Value::String(_))) {
                m.blob_refs += 1;
            }
            let mut size = 2 + o.len().saturating_sub(1) as u64;
            for (k, x) in o {
                size += check_str(k, m) + 1;
                size += walk(x, depth + 1, path + token_len(k), l, m);
            }
            size
        }
    }
}

fn digits(mut i: usize) -> u64 {
    let mut n = 1;
    while i >= 10 {
        i /= 10;
        n += 1;
    }
    n
}

impl Measure {
    /// The first document limit exceeded, in §12.2's order.
    pub fn check(&self, l: &Limits) -> Result<(), LimitError> {
        if self.size > l.document_size {
            return Err(LimitError {
                limit: "documentSize",
                measured: Some(self.size),
                max: l.document_size,
            });
        }
        if let Some(n) = self.long_value {
            return Err(LimitError {
                limit: "valueSize",
                measured: Some(n),
                max: l.value_size,
            });
        }
        if let Some(n) = self.long_path {
            return Err(LimitError {
                limit: "pathSize",
                measured: Some(n),
                max: l.path_size,
            });
        }
        if self.depth > l.nesting_depth {
            return Err(LimitError {
                limit: "nestingDepth",
                measured: Some(self.depth),
                max: l.nesting_depth,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::{canonical, parse};

    #[test]
    fn walk_matches_canonical() {
        let v = parse(br#"{"a":[1,{"b~/":"x\n"}],"c":null,"d":-1.5e-7,"$blob":"1abc"}"#).unwrap();
        let m = measure(&v, &Limits::default());
        assert_eq!(m.size, canonical(&v).len() as u64);
        assert_eq!(m.depth, 3);
        assert_eq!(m.blob_refs, 1);
        let d = parse(br#"{"a":[1]}"#).unwrap();
        assert_eq!(measure(&d, &Limits::default()).depth, 2);
    }

    #[test]
    fn path_and_value_sizes() {
        let l = Limits {
            path_size: 10,
            value_size: 5,
            ..Limits::default()
        };
        // Pointer /ab~1c/0 is 8 characters, 10 with quotes: not over.
        let v = parse(br#"{"ab/c":[1]}"#).unwrap();
        assert_eq!(measure(&v, &l).long_path, None);
        let v = parse(br#"{"ab/cd":[1]}"#).unwrap();
        assert_eq!(measure(&v, &l).long_path, Some(11));
        let v = parse(br#"{"k":"abcd"}"#).unwrap();
        assert_eq!(measure(&v, &l).long_value, Some(6));
    }
}
