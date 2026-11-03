//! Typed documents (§6.1, §6.2 step 5): schema references, the checks a
//! schema document must pass, RE2 regular expressions (§6.6), and validation
//! of a document against a schema revision and its `$ref` closure.
//!
//! Resolving revision paths is the caller's: this module names the paths it
//! needs ([`refs_of`]) and works on a map of the schema documents found.

use crate::json::Value;
use crate::names::{is_base32_26, is_namespace_name, is_resource_name};
use crate::patch::{escape_token, parse_pointer};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// The dialect URL (§6.1): a document with it as `$schema` is a schema.
pub const DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

/// The base revision paths are resolved against, for the validator only.
const BASE: &str = "https://patchlog.invalid";

#[derive(Debug, Clone, PartialEq)]
pub enum SchemaError {
    /// `422 schema_ref`: a `$schema`, `$ref` or `$dynamicRef` of a form §6.1 doesn't accept.
    Ref(String),
    /// `422 schema_unavailable`: a revision path that doesn't resolve; `path` names it.
    Unavailable { path: String, message: String },
    /// `422 invalid`: the document fails validation, or a schema document is invalid.
    Invalid(Vec<(String, String)>),
}

impl SchemaError {
    fn invalid(pointer: impl Into<String>, message: impl Into<String>) -> SchemaError {
        SchemaError::Invalid(vec![(pointer.into(), message.into())])
    }
}

/// `^/r/{ns}/{name}/rev/1[a-z2-7]{32}$`
pub fn is_revision_path(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("/r/") else {
        return false;
    };
    let parts: Vec<&str> = rest.split('/').collect();
    matches!(parts.as_slice(), [ns, name, "rev", id]
        if is_namespace_name(ns) && is_resource_name(name)
            && id.len() == 33 && id.starts_with('1')
            && id[1..].bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')))
}

/// What a document's `$schema` says.
#[derive(Debug, Clone, PartialEq)]
pub enum Typed {
    /// No `$schema`: untyped, not validated.
    Untyped,
    /// The dialect URL: the document is a schema.
    Schema,
    /// Validated against this schema revision.
    Instance(String),
}

pub fn typed(doc: &Value) -> Result<Typed, SchemaError> {
    match doc.get("$schema") {
        None => Ok(Typed::Untyped),
        Some(Value::String(s)) if s == DIALECT => Ok(Typed::Schema),
        Some(Value::String(s)) if is_revision_path(s) => Ok(Typed::Instance(s.clone())),
        Some(Value::String(s)) => Err(SchemaError::Ref(format!(
            "$schema {s:?} is neither a schema revision path on this service nor {DIALECT}"
        ))),
        Some(_) => Err(SchemaError::Ref("$schema must be a string".into())),
    }
}

/// A well-formed `$successor` (§8.1): a bare resource name, or `/r/{ns}/{name}`.
fn is_successor(v: &Value) -> bool {
    let Some(s) = v.as_str() else { return false };
    if is_resource_name(s) {
        return true;
    }
    let Some(rest) = s.strip_prefix("/r/") else {
        return false;
    };
    matches!(rest.split('/').collect::<Vec<_>>().as_slice(), [ns, name] if is_namespace_name(ns) && is_resource_name(name))
}

/// The members step 5 of §6.2 leaves out of the instance it validates: the
/// top-level `$schema`, a fresh-form `$nonce` and a well-formed `$successor`.
pub fn strip(doc: &Value) -> Value {
    match doc {
        Value::Object(m) => {
            let mut m = m.clone();
            m.remove("$schema");
            if m.get("$nonce")
                .and_then(Value::as_str)
                .is_some_and(is_base32_26)
            {
                m.remove("$nonce");
            }
            if m.get("$successor").is_some_and(is_successor) {
                m.remove("$successor");
            }
            Value::Object(m)
        }
        other => other.clone(),
    }
}

// ---------------------------------------------------------------------------
// RE2 (§6.6)

/// Translates an RE2 pattern into the `regex` crate's syntax, which shares
/// RE2's semantics (no backreferences or lookaround, linear time) but differs
/// in a few spellings:
///
/// - `\uXXXX` is read as `\x{XXXX}`, a surrogate pair of such escapes as the
///   one code point it encodes, and a lone surrogate, or one written
///   `\x{…}`, is refused (§6.6, §I.11);
/// - `\Q…\E` quotes literally;
/// - `\d \D \w \W \s \S` and `\b \B` are ASCII, as in RE2.
pub fn re2(pattern: &str) -> Result<String, String> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len() + 8);
    let mut i = 0;
    let mut in_class = false;
    let hex4 = |i: usize| -> Option<u32> {
        let s: String = chars.get(i..i + 4)?.iter().collect();
        if s.len() == 4 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            u32::from_str_radix(&s, 16).ok()
        } else {
            None
        }
    };
    while i < chars.len() {
        let c = chars[i];
        if c != '\\' {
            match c {
                '[' if !in_class => in_class = true,
                ']' if in_class => in_class = false,
                _ => {}
            }
            out.push(c);
            i += 1;
            continue;
        }
        let Some(&e) = chars.get(i + 1) else {
            return Err("trailing backslash".into());
        };
        match e {
            '\\' => {
                out.push_str("\\\\");
                i += 2;
            }
            'Q' => {
                let start = i + 2;
                let mut j = start;
                while j < chars.len() && !(chars[j] == '\\' && chars.get(j + 1) == Some(&'E')) {
                    j += 1;
                }
                let lit: String = chars[start..j].iter().collect();
                out.push_str(&regex::escape(&lit));
                i = if j < chars.len() { j + 2 } else { j };
            }
            'E' => i += 2, // a stray \E is ignored, as in RE2
            'u' => {
                let Some(hi) = hex4(i + 2) else {
                    return Err(format!("bad \\u escape at {i}"));
                };
                let mut cp = hi;
                let mut used = 6;
                if (0xD800..0xDC00).contains(&hi) {
                    let lo = (chars.get(i + 6) == Some(&'\\') && chars.get(i + 7) == Some(&'u'))
                        .then(|| hex4(i + 8))
                        .flatten();
                    match lo {
                        Some(lo) if (0xDC00..0xE000).contains(&lo) => {
                            cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                            used = 12;
                        }
                        _ => return Err(format!("lone surrogate \\u{hi:04x}")),
                    }
                } else if (0xDC00..0xE000).contains(&hi) {
                    return Err(format!("lone surrogate \\u{hi:04x}"));
                }
                out.push_str(&format!("\\x{{{cp:X}}}"));
                i += used;
            }
            'x' if chars.get(i + 2) == Some(&'{') => {
                let end = chars[i + 3..]
                    .iter()
                    .position(|&c| c == '}')
                    .map(|p| i + 3 + p);
                let Some(end) = end else {
                    return Err("unterminated \\x{".into());
                };
                let hex: String = chars[i + 3..end].iter().collect();
                let cp = u32::from_str_radix(&hex, 16).map_err(|_| format!("bad \\x{{{hex}}}"))?;
                if (0xD800..0xE000).contains(&cp) || cp > 0x10FFFF {
                    return Err(format!("\\x{{{hex}}} isn't a Unicode scalar value"));
                }
                out.push_str(&format!("\\x{{{cp:X}}}"));
                i = end + 1;
            }
            'd' | 'D' | 'w' | 'W' | 's' | 'S' => {
                let (set, negated) = match e {
                    'd' => ("0-9", false),
                    'D' => ("0-9", true),
                    'w' => ("0-9A-Za-z_", false),
                    'W' => ("0-9A-Za-z_", true),
                    's' => ("\\t\\n\\x0C\\r ", false),
                    _ => ("\\t\\n\\x0C\\r ", true),
                };
                match (in_class, negated) {
                    // Inside a class, the ranges themselves: `[\d-]` is `[0-9-]`.
                    (true, false) => out.push_str(set),
                    // A negated set inside a class has no flat spelling: nest it.
                    (true, true) | (false, true) => out.push_str(&format!("[^{set}]")),
                    (false, false) => out.push_str(&format!("[{set}]")),
                }
                i += 2;
            }
            'b' | 'B' if !in_class => {
                out.push_str(if e == 'b' { "(?-u:\\b)" } else { "(?-u:\\B)" });
                i += 2;
            }
            _ => {
                out.push('\\');
                out.push(e);
                i += 2;
            }
        }
    }
    regex::Regex::new(&out).map_err(|e| e.to_string())?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Schema documents

/// Keywords of draft 2020-12 whose values are a subschema.
const ONE_SCHEMA: &[&str] = &[
    "additionalProperties",
    "items",
    "contains",
    "propertyNames",
    "if",
    "then",
    "else",
    "not",
    "unevaluatedItems",
    "unevaluatedProperties",
    "contentSchema",
];
/// Keywords whose values are arrays of subschemas.
const SCHEMA_ARRAY: &[&str] = &["prefixItems", "allOf", "anyOf", "oneOf"];
/// Keywords whose values are objects of subschemas.
const SCHEMA_MAP: &[&str] = &["properties", "dependentSchemas", "$defs", "definitions"];
/// The other keywords of draft 2020-12.
const OTHER: &[&str] = &[
    "type",
    "enum",
    "const",
    "multipleOf",
    "maximum",
    "exclusiveMaximum",
    "minimum",
    "exclusiveMinimum",
    "maxLength",
    "minLength",
    "maxItems",
    "minItems",
    "uniqueItems",
    "maxContains",
    "minContains",
    "maxProperties",
    "minProperties",
    "required",
    "dependentRequired",
    "contentEncoding",
    "contentMediaType",
    "title",
    "description",
    "default",
    "deprecated",
    "readOnly",
    "writeOnly",
    "examples",
    "$vocabulary",
    "$comment",
    "$anchor",
    "$dynamicAnchor",
];
/// The formats draft 2020-12 defines; any other is invalid (§6.2 step 5).
const FORMATS: &[&str] = &[
    "date-time",
    "date",
    "time",
    "duration",
    "email",
    "idn-email",
    "hostname",
    "idn-hostname",
    "ipv4",
    "ipv6",
    "uri",
    "uri-reference",
    "iri",
    "iri-reference",
    "uuid",
    "uri-template",
    "json-pointer",
    "relative-json-pointer",
    "regex",
];

/// What a schema document refers to, found by [`check_schema`].
#[derive(Debug, Default, Clone)]
pub struct Refs {
    /// Revision paths its `$ref`s name, without fragments.
    pub paths: BTreeSet<String>,
    /// Every `$ref` with a fragment: (path, or "" for this document; fragment).
    pub fragments: Vec<(String, String)>,
}

/// The checks of §6.1 and §6.5 on a document whose `$schema` is the dialect
/// URL, against the dialect's meta-schema too. Returns the references it
/// makes; whether they resolve is checked with the documents they name.
pub fn check_schema(doc: &Value) -> Result<Refs, SchemaError> {
    let schema = strip_members(doc);
    let mut refs = Refs::default();
    walk(&schema, "", true, &mut refs)?;
    let json = to_json(&schema);
    if let Err(e) = jsonschema::meta::validate(&json) {
        return Err(SchemaError::invalid(
            e.instance_path().as_str(),
            format!("not a valid 2020-12 schema: {e}"),
        ));
    }
    // Fragments into this document must name something in it.
    for (path, frag) in &refs.fragments {
        if path.is_empty() && !fragment_resolves(&schema, frag) {
            return Err(SchemaError::invalid(
                "",
                format!("$ref #{frag} names nothing in this schema"),
            ));
        }
    }
    Ok(refs)
}

/// A schema document without the members step 5 leaves out (§6.5): its
/// `$schema` stays, being the dialect, but a fresh `$nonce` and a
/// well-formed `$successor` go.
fn strip_members(doc: &Value) -> Value {
    let mut s = strip(doc);
    if let (Value::Object(m), Some(d)) = (&mut s, doc.get("$schema")) {
        m.insert("$schema".into(), d.clone());
    }
    s
}

fn walk(v: &Value, ptr: &str, root: bool, refs: &mut Refs) -> Result<(), SchemaError> {
    let m = match v {
        Value::Bool(_) => return Ok(()),
        Value::Object(m) => m,
        _ => {
            return Err(SchemaError::invalid(
                ptr,
                "a schema is an object or a boolean",
            ))
        }
    };
    for (k, x) in m {
        let p = format!("{ptr}/{}", escape_token(k));
        if k.starts_with("x-") {
            continue; // annotations for consumers (§6.5), not walked
        }
        match k.as_str() {
            "$schema" if root => {
                if x.as_str() != Some(DIALECT) {
                    return Err(SchemaError::Ref(format!("a schema's $schema is {DIALECT}")));
                }
            }
            "$schema" => {
                return Err(SchemaError::invalid(
                    &p,
                    "$schema is allowed only at a schema's root",
                ))
            }
            "$id" => {
                return Err(SchemaError::invalid(
                    &p,
                    "$id isn't allowed: schemas are named by revision path",
                ))
            }
            "$ref" => {
                let Some(r) = x.as_str() else {
                    return Err(SchemaError::invalid(&p, "$ref is a string"));
                };
                let (path, frag) = match r.split_once('#') {
                    Some((path, frag)) => (path, Some(frag)),
                    None => (r, None),
                };
                if !path.is_empty() {
                    if !is_revision_path(path) {
                        return Err(SchemaError::Ref(format!(
                            "$ref {r:?} at {p} is neither a fragment nor a schema revision path"
                        )));
                    }
                    refs.paths.insert(path.to_string());
                }
                if let Some(f) = frag {
                    refs.fragments.push((path.to_string(), percent_decode(f)));
                } else if path.is_empty() {
                    return Err(SchemaError::Ref(format!("$ref at {p} is empty")));
                }
            }
            "$dynamicRef" => {
                if !x.as_str().is_some_and(|s| s.starts_with('#')) {
                    return Err(SchemaError::Ref(format!(
                        "$dynamicRef at {p} must be a same-document fragment"
                    )));
                }
            }
            "dependencies" | "$recursiveAnchor" | "$recursiveRef" => {
                return Err(SchemaError::invalid(
                    &p,
                    format!("{k} isn't a 2020-12 keyword"),
                ));
            }
            "pattern" => {
                let Some(s) = x.as_str() else {
                    return Err(SchemaError::invalid(&p, "pattern is a string"));
                };
                re2(s).map_err(|e| SchemaError::invalid(&p, format!("not an RE2 pattern: {e}")))?;
            }
            "patternProperties" => {
                let Some(o) = x.as_object() else {
                    return Err(SchemaError::invalid(&p, "patternProperties is an object"));
                };
                for (pat, sub) in o {
                    let pp = format!("{p}/{}", escape_token(pat));
                    re2(pat).map_err(|e| {
                        SchemaError::invalid(&pp, format!("not an RE2 pattern: {e}"))
                    })?;
                    walk(sub, &pp, false, refs)?;
                }
            }
            "format" => {
                if !x.as_str().is_some_and(|f| FORMATS.contains(&f)) {
                    return Err(SchemaError::invalid(
                        &p,
                        "not a format draft 2020-12 defines",
                    ));
                }
            }
            k if ONE_SCHEMA.contains(&k) => walk(x, &p, false, refs)?,
            k if SCHEMA_ARRAY.contains(&k) => {
                let Some(a) = x.as_array() else {
                    return Err(SchemaError::invalid(&p, format!("{k} is an array")));
                };
                for (i, sub) in a.iter().enumerate() {
                    walk(sub, &format!("{p}/{i}"), false, refs)?;
                }
            }
            k if SCHEMA_MAP.contains(&k) => {
                let Some(o) = x.as_object() else {
                    return Err(SchemaError::invalid(&p, format!("{k} is an object")));
                };
                for (name, sub) in o {
                    walk(sub, &format!("{p}/{}", escape_token(name)), false, refs)?;
                }
            }
            k if OTHER.contains(&k) => {}
            _ => {
                return Err(SchemaError::invalid(
                    &p,
                    format!("unknown keyword {k:?}; extensions start with x-"),
                ))
            }
        }
    }
    Ok(())
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 3 <= b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether a decoded fragment names something in `schema`: a JSON Pointer
/// (empty or starting with `/`) to a value, or an `$anchor`/`$dynamicAnchor`.
pub fn fragment_resolves(schema: &Value, frag: &str) -> bool {
    if frag.is_empty() || frag.starts_with('/') {
        let Ok(tokens) = parse_pointer(frag) else {
            return false;
        };
        let mut cur = schema;
        for t in &tokens {
            cur = match cur {
                Value::Object(m) => match m.get(t) {
                    Some(v) => v,
                    None => return false,
                },
                Value::Array(a) => match t.parse::<usize>().ok().and_then(|i| a.get(i)) {
                    Some(v) => v,
                    None => return false,
                },
                _ => return false,
            };
        }
        return true;
    }
    fn has_anchor(v: &Value, name: &str) -> bool {
        match v {
            Value::Object(m) => {
                ["$anchor", "$dynamicAnchor"]
                    .iter()
                    .any(|k| m.get(*k).and_then(Value::as_str) == Some(name))
                    || m.values().any(|x| has_anchor(x, name))
            }
            Value::Array(a) => a.iter().any(|x| has_anchor(x, name)),
            _ => false,
        }
    }
    has_anchor(schema, frag)
}

// ---------------------------------------------------------------------------
// Validation

/// A compiled validator for a schema revision and its `$ref` closure.
pub struct Compiled {
    validator: jsonschema::Validator,
}

/// The revision paths reachable from `root` through `$ref`, given the schema
/// documents already known: those still missing are returned to be fetched.
pub fn closure(root: &str, known: &HashMap<String, Value>) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut seen = BTreeSet::new();
    let mut missing = BTreeSet::new();
    let mut stack = vec![root.to_string()];
    while let Some(p) = stack.pop() {
        if !seen.insert(p.clone()) {
            continue;
        }
        match known.get(&p) {
            None => {
                missing.insert(p);
            }
            Some(doc) => {
                let mut refs = Refs::default();
                let _ = walk(&strip_members(doc), "", true, &mut refs);
                stack.extend(refs.paths);
            }
        }
    }
    (seen, missing)
}

/// Checks that every `$ref` fragment into another schema resolves there
/// (§6.1). `known` holds every document of the closure.
pub fn check_fragments(refs: &Refs, known: &HashMap<String, Value>) -> Result<(), SchemaError> {
    for (path, frag) in &refs.fragments {
        if path.is_empty() {
            continue;
        }
        let Some(doc) = known.get(path) else {
            return Err(SchemaError::Unavailable {
                path: path.clone(),
                message: "not resolved".into(),
            });
        };
        if !fragment_resolves(&strip_members(doc), frag) {
            return Err(SchemaError::invalid(
                "",
                format!("$ref {path}#{frag} names nothing in that schema"),
            ));
        }
    }
    Ok(())
}

/// Compiles `root` with every document of its closure in `known`. Patterns
/// are translated from RE2 (§6.6) for the regex engine.
pub fn compile(root: &str, known: &HashMap<String, Value>) -> Result<Compiled, SchemaError> {
    let docs: HashMap<String, serde_json::Value> = known
        .iter()
        .map(|(k, v)| {
            (
                format!("{BASE}{k}"),
                to_json(&translate_patterns(&strip_members(v))),
            )
        })
        .collect();
    let root_doc =
        docs.get(&format!("{BASE}{root}"))
            .cloned()
            .ok_or_else(|| SchemaError::Unavailable {
                path: root.into(),
                message: "not resolved".into(),
            })?;
    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .with_base_uri(format!("{BASE}{root}"))
        .with_retriever(Known(docs))
        .should_validate_formats(true)
        .should_ignore_unknown_formats(false)
        .with_pattern_options(jsonschema::PatternOptions::regex())
        .with_format("regex", |s: &str| re2(s).is_ok())
        .build(&root_doc)
        .map_err(|e| SchemaError::invalid("", format!("schema {root} doesn't compile: {e}")))?;
    Ok(Compiled { validator })
}

impl Compiled {
    /// Validates the document (without the members step 5 leaves out); the
    /// errors as (JSON Pointer, message), at most 20.
    pub fn validate(&self, doc: &Value) -> Result<(), SchemaError> {
        let instance = to_json(&strip(doc));
        let errors: Vec<(String, String)> = self
            .validator
            .iter_errors(&instance)
            .take(20)
            .map(|e| (e.instance_path().as_str().to_string(), e.to_string()))
            .collect();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(SchemaError::Invalid(errors))
        }
    }
}

struct Known(HashMap<String, serde_json::Value>);

impl jsonschema::Retrieve for Known {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let key = uri
            .as_str()
            .split('#')
            .next()
            .unwrap_or_default()
            .to_string();
        self.0
            .get(&key)
            .cloned()
            .ok_or_else(|| format!("{key} isn't resolved").into())
    }
}

/// Patterns in `pattern` values and `patternProperties` keys, translated
/// from RE2 to the regex crate's syntax. Invalid ones are left as they are
/// (`check_schema` has refused them).
fn translate_patterns(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut out = BTreeMap::new();
            for (k, x) in m {
                let x2 = match (k.as_str(), x) {
                    ("pattern", Value::String(s)) => {
                        Value::String(re2(s).unwrap_or_else(|_| s.clone()))
                    }
                    ("patternProperties", Value::Object(o)) => Value::Object(
                        o.iter()
                            .map(|(pat, sub)| {
                                (
                                    re2(pat).unwrap_or_else(|_| pat.clone()),
                                    translate_patterns(sub),
                                )
                            })
                            .collect(),
                    ),
                    (k, x)
                        if !k.starts_with("x-")
                            && !matches!(k, "enum" | "const" | "default" | "examples") =>
                    {
                        translate_patterns(x)
                    }
                    _ => x.clone(),
                };
                out.insert(k.clone(), x2);
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(translate_patterns).collect()),
        other => other.clone(),
    }
}

/// Our value as serde_json's; integral numbers in i64 as integers.
pub fn to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Number(n) => {
            if n.fract() == 0.0 && n.abs() < 9.007_199_254_740_992e15 {
                serde_json::Value::from(*n as i64)
            } else {
                serde_json::Number::from_f64(*n)
                    .map(serde_json::Value::Number)
                    .unwrap_or(serde_json::Value::Null)
            }
        }
        Value::String(s) => serde_json::Value::String(s.clone()),
        Value::Array(a) => serde_json::Value::Array(a.iter().map(to_json).collect()),
        Value::Object(m) => {
            serde_json::Value::Object(m.iter().map(|(k, x)| (k.clone(), to_json(x))).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    fn v(s: &str) -> Value {
        parse(s.as_bytes()).unwrap()
    }

    // Addendum I.11
    #[test]
    fn i11_regular_expressions() {
        let m = |p: &str, s: &str| regex::Regex::new(&re2(p).unwrap()).unwrap().is_match(s);
        assert!(m(r"^\u00e9$", "é"));
        assert!(!m(r"^\u00e9$", "e"));
        assert!(!m(r"^\u00e9$", r"\u00e9"));
        assert!(m(r"^\ud83d\ude00$", "😀"));
        assert!(m(r"^[\u00e0-\u00ff]+$", "àéÿ"));
        assert!(!m(r"^[\u00e0-\u00ff]+$", "a"));
        assert!(m(r"^\\u0041$", r"\u0041"));
        assert!(!m(r"^\\u0041$", "A"));
        for bad in [r"\ud800", r"\udc00", r"\ud83dA", r"\x{D800}"] {
            assert!(re2(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn re2_spellings() {
        let m = |p: &str, s: &str| regex::Regex::new(&re2(p).unwrap()).unwrap().is_match(s);
        assert!(m(r"^\Qa.b\E$", "a.b"));
        assert!(!m(r"^\Qa.b\E$", "axb"));
        assert!(m(r"^\d+$", "123"));
        assert!(!m(r"^\d+$", "١٢٣")); // RE2's \d is ASCII
        assert!(m(r"^[\d_]+$", "1_2"));
        assert!(re2(r"(a)\1").is_err()); // no backreferences
        assert!(re2(r"a(?=b)").is_err()); // no lookaround
    }

    #[test]
    fn typed_forms() {
        assert_eq!(typed(&v(r#"{"a":1}"#)).unwrap(), Typed::Untyped);
        assert_eq!(
            typed(&v(&format!(r#"{{"$schema":"{DIALECT}"}}"#))).unwrap(),
            Typed::Schema
        );
        let p = "/r/schemas/post/rev/1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll";
        assert_eq!(
            typed(&v(&format!(r#"{{"$schema":"{p}"}}"#))).unwrap(),
            Typed::Instance(p.into())
        );
        assert!(matches!(
            typed(&v(r#"{"$schema":1}"#)),
            Err(SchemaError::Ref(_))
        ));
        assert!(matches!(
            typed(&v(r#"{"$schema":"https://example.com/s"}"#)),
            Err(SchemaError::Ref(_))
        ));
        assert!(matches!(
            typed(&v(r#"{"$schema":"/r/schemas/post/rev/1L2GI"}"#)),
            Err(SchemaError::Ref(_))
        ));
    }

    #[test]
    fn schema_documents() {
        let ok = format!(
            r##"{{"$schema":"{DIALECT}","type":"object","x-index":{{"by":"title"}},
                "properties":{{"title":{{"type":"string","pattern":"^\\u00e9","format":"email"}},
                "n":{{"$ref":"#/$defs/n"}},"o":{{"$ref":"/r/s/other/rev/1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll#/$defs/x"}}}},
                "$defs":{{"n":{{"type":"integer"}}}}}}"##
        );
        let refs = check_schema(&v(&ok)).unwrap();
        assert_eq!(refs.paths.len(), 1);
        for (bad, why) in [
            (r#""$id":"x""#, "invalid"),
            (r#""dependencies":{}"#, "invalid"),
            (r#""frobnicate":1"#, "invalid"),
            (r#""format":"phone""#, "invalid"),
            (r#""pattern":"(a)\\1""#, "invalid"),
            (r#""$ref":"https://example.com/s""#, "ref"),
            (
                r#""$dynamicRef":"/r/s/x/rev/1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll""#,
                "ref",
            ),
            (r##""$ref":"#/$defs/missing""##, "invalid"),
            (r#""properties":{"a":{"$schema":"x"}}"#, "invalid"),
        ] {
            let doc = v(&format!(r#"{{"$schema":"{DIALECT}",{bad}}}"#));
            let r = check_schema(&doc);
            match why {
                "ref" => assert!(matches!(r, Err(SchemaError::Ref(_))), "{bad}: {r:?}"),
                _ => assert!(matches!(r, Err(SchemaError::Invalid(_))), "{bad}: {r:?}"),
            }
        }
    }

    #[test]
    fn validates_across_revisions() {
        let a = "/r/s/post/rev/1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll";
        let b = "/r/s/name/rev/1sywh54kpo3c4ezn2znktvl3avge4zl5d";
        let mut known = HashMap::new();
        known.insert(
            a.to_string(),
            v(&format!(
                r#"{{"$schema":"{DIALECT}","type":"object","required":["title"],
                    "properties":{{"title":{{"$ref":"{b}"}},"slug":{{"type":"string","pattern":"^[\\d-]+$"}}}},
                    "additionalProperties":false}}"#
            )),
        );
        known.insert(
            b.to_string(),
            v(&format!(
                r#"{{"$schema":"{DIALECT}","type":"string","minLength":2}}"#
            )),
        );
        let (all, missing) = closure(a, &known);
        assert!(missing.is_empty());
        assert_eq!(all.len(), 2);
        let c = compile(a, &known).unwrap();
        let ok = v(&format!(
            r#"{{"$schema":"{a}","title":"Hello","slug":"12-3","$nonce":"abcdefghijklmnopqrstuvwxyz"}}"#
        ));
        c.validate(&ok).unwrap();
        let bad = v(&format!(
            r#"{{"$schema":"{a}","title":"H","slug":"x","extra":1}}"#
        ));
        match c.validate(&bad) {
            Err(SchemaError::Invalid(errs)) => {
                let ptrs: Vec<&str> = errs.iter().map(|(p, _)| p.as_str()).collect();
                assert!(ptrs.contains(&"/title"), "{errs:?}");
                assert!(ptrs.contains(&"/slug"), "{errs:?}");
            }
            r => panic!("{r:?}"),
        }
        let mut partial = known.clone();
        partial.remove(b);
        assert_eq!(
            closure(a, &partial).1.into_iter().collect::<Vec<_>>(),
            vec![b.to_string()]
        );
    }
}
