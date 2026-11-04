//! I-JSON input (§3.1) and canonical JSON (RFC 8785, JCS).
//!
//! The parser is strict where §3.1 and Addendum I.1 say so: invalid UTF-8,
//! duplicate member names, lone surrogates, Unicode noncharacters, numbers
//! that overflow a double, and numbers whose canonical form is an integer
//! literal outside ±(2⁵³−1) are refused. Numbers are held as `f64`, which is
//! exactly what JCS serialises.

use std::collections::BTreeMap;
use std::fmt;

/// A JSON value. Objects are keyed by Rust strings (UTF-8 byte order); the
/// canonical serialiser re-sorts members by UTF-16 code units as JCS requires.
#[derive(Clone, Debug)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl PartialEq for Value {
    /// JSON equality as JSON Patch `test` uses it (RFC 6902 §4.6): numbers by
    /// value, objects regardless of member order.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Number(a), Value::Number(b)) => a == b,
            (Value::String(a), Value::String(b)) => a == b,
            (Value::Array(a), Value::Array(b)) => a == b,
            (Value::Object(a), Value::Object(b)) => a == b,
            _ => false,
        }
    }
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_object(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object().and_then(|m| m.get(key))
    }
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }
}

/// Why input isn't I-JSON. Every one of these is a `400` (`bad_input`).
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub offset: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not I-JSON at byte {}: {}", self.offset, self.message)
    }
}

impl std::error::Error for ParseError {}

/// Nesting the parser accepts at all. `nestingDepth` (§6.6) is checked on the
/// resulting document; this only bounds recursion on hostile input.
pub const MAX_PARSE_DEPTH: usize = 512;

/// Largest integer magnitude whose integer-literal canonical form is accepted.
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

pub fn parse(input: &[u8]) -> Result<Value, ParseError> {
    let text = std::str::from_utf8(input).map_err(|e| ParseError {
        offset: e.valid_up_to(),
        message: "invalid UTF-8".into(),
    })?;
    let mut p = Parser {
        s: text.as_bytes(),
        src: text,
        i: 0,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.s.len() {
        return Err(p.err("trailing data"));
    }
    Ok(v)
}

struct Parser<'a> {
    s: &'a [u8],
    src: &'a str,
    i: usize,
}

fn is_noncharacter(c: u32) -> bool {
    (0xFDD0..=0xFDEF).contains(&c) || (c & 0xFFFE) == 0xFFFE
}

impl<'a> Parser<'a> {
    fn err(&self, m: &str) -> ParseError {
        ParseError {
            offset: self.i,
            message: m.into(),
        }
    }

    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn lit(&mut self, word: &str, v: Value) -> Result<Value, ParseError> {
        if self.s[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(self.err("unexpected token"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, ParseError> {
        match self.peek() {
            None => Err(self.err("unexpected end of input")),
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't') => self.lit("true", Value::Bool(true)),
            Some(b'f') => self.lit("false", Value::Bool(false)),
            Some(b'n') => self.lit("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.err("unexpected character")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, ParseError> {
        if depth > MAX_PARSE_DEPTH {
            return Err(self.err("nested too deeply"));
        }
        self.i += 1;
        let mut m = BTreeMap::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Object(m));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("expected a member name"));
            }
            let at = self.i;
            let k = self.string()?;
            self.ws();
            if self.peek() != Some(b':') {
                return Err(self.err("expected ':'"));
            }
            self.i += 1;
            self.ws();
            let v = self.value(depth)?;
            if m.insert(k, v).is_some() {
                return Err(ParseError {
                    offset: at,
                    message: "duplicate member name".into(),
                });
            }
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Object(m));
                }
                _ => return Err(self.err("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, ParseError> {
        if depth > MAX_PARSE_DEPTH {
            return Err(self.err("nested too deeply"));
        }
        self.i += 1;
        let mut a = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Array(a));
        }
        loop {
            self.ws();
            a.push(self.value(depth)?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Array(a));
                }
                _ => return Err(self.err("expected ',' or ']'")),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        if self.i + 4 > self.s.len() {
            return Err(self.err("truncated \\u escape"));
        }
        let h = &self.src[self.i..self.i + 4];
        if !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(self.err("bad \\u escape"));
        }
        self.i += 4;
        Ok(u32::from_str_radix(h, 16).unwrap())
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.i += 1; // opening quote
        let mut out = String::new();
        let mut run = self.i;
        loop {
            let Some(b) = self.peek() else {
                return Err(self.err("unterminated string"));
            };
            match b {
                b'"' => {
                    out.push_str(&self.src[run..self.i]);
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    out.push_str(&self.src[run..self.i]);
                    self.i += 1;
                    let Some(e) = self.peek() else {
                        return Err(self.err("unterminated escape"));
                    };
                    self.i += 1;
                    let c = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if !self.s[self.i..].starts_with(b"\\u") {
                                    return Err(self.err("lone surrogate"));
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(self.err("lone surrogate"));
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err(self.err("lone surrogate"));
                            } else {
                                hi
                            };
                            if is_noncharacter(cp) {
                                return Err(self.err("Unicode noncharacter"));
                            }
                            char::from_u32(cp).unwrap()
                        }
                        _ => return Err(self.err("bad escape")),
                    };
                    out.push(c);
                    run = self.i;
                }
                0..=0x1F => return Err(self.err("control character in string")),
                0x80.. => {
                    // Raw non-ASCII: the input is valid UTF-8, so decode one char.
                    let c = self.src[self.i..].chars().next().unwrap();
                    if is_noncharacter(c as u32) {
                        return Err(self.err("Unicode noncharacter"));
                    }
                    self.i += c.len_utf8();
                }
                _ => self.i += 1,
            }
        }
    }

    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return Err(self.err("bad number")),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("bad number"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("bad number"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        let text = &self.src[start..self.i];
        // Rust's parse is correctly rounded: overflow gives ±inf, underflow ±0.
        let v: f64 = text.parse().map_err(|_| self.err("bad number"))?;
        check_number(v).map_err(|m| ParseError {
            offset: start,
            message: m.into(),
        })?;
        Ok(Value::Number(if v == 0.0 { 0.0 } else { v }))
    }
}

/// §3.1: a number must fit a double, and one whose canonical form is an
/// integer literal (integral, |v| < 10²¹) must be within ±(2⁵³−1).
pub fn check_number(v: f64) -> Result<(), &'static str> {
    if !v.is_finite() {
        return Err("number overflows a double");
    }
    if v.fract() == 0.0 && v.abs() < 1e21 && v.abs() > MAX_SAFE {
        return Err("integer outside ±(2^53-1)");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Canonical form (RFC 8785)

/// `canonical(v)`: JCS, UTF-8.
pub fn canonical(v: &Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    write_canonical(v, &mut out);
    out
}

pub fn canonical_string(v: &Value) -> String {
    // SAFETY-free: JCS output is built from valid UTF-8 pieces only.
    String::from_utf8(canonical(v)).expect("canonical JSON is UTF-8")
}

pub fn write_canonical(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => write_number(*n, out),
        Value::String(s) => write_string(s, out),
        Value::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(x, out);
            }
            out.push(b']');
        }
        Value::Object(m) => {
            out.push(b'{');
            let member = |i: usize, k: &String, x: &Value, out: &mut Vec<u8>| {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                write_canonical(x, out);
            };
            if needs_utf16_sort(m) {
                for (i, (k, x)) in sorted_members(m).into_iter().enumerate() {
                    member(i, k, x, out);
                }
            } else {
                for (i, (k, x)) in m.iter().enumerate() {
                    member(i, k, x, out);
                }
            }
            out.push(b'}');
        }
    }
}

/// Members in JCS order: by UTF-16 code units. UTF-8 byte order agrees with
/// it except where a key holds characters above U+FFFF and in
/// U+E000–U+FFFF at the same position, so the common case needs no re-sort.
pub fn sorted_members(m: &BTreeMap<String, Value>) -> Vec<(&String, &Value)> {
    let mut v: Vec<(&String, &Value)> = m.iter().collect();
    if needs_utf16_sort(m) {
        v.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
    }
    v
}

/// Whether any key holds a character above U+FFFF (a 4-byte UTF-8 sequence).
fn needs_utf16_sort(m: &BTreeMap<String, Value>) -> bool {
    m.keys().any(|k| k.bytes().any(|b| b >= 0xF0))
}

pub fn write_number(n: f64, out: &mut Vec<u8>) {
    if n.fract() == 0.0 && n.abs() <= 9_007_199_254_740_991.0 {
        // Safe integers print as plain digits; skip the shortest-round-trip search.
        let mut buf = [0u8; 20];
        let mut i = buf.len();
        let mut v = n.abs() as u64;
        loop {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        if n < 0.0 {
            out.push(b'-');
        }
        out.extend_from_slice(&buf[i..]);
        return;
    }
    let mut b = ryu_js::Buffer::new();
    out.extend_from_slice(b.format_finite(n).as_bytes());
}

/// Length of a number as canonical JSON.
pub fn number_len(n: f64) -> usize {
    if n.fract() == 0.0 && n.abs() <= 9_007_199_254_740_991.0 {
        let mut v = n.abs() as u64;
        let mut len = usize::from(n < 0.0) + 1;
        while v >= 10 {
            v /= 10;
            len += 1;
        }
        return len;
    }
    ryu_js::Buffer::new().format_finite(n).len()
}

pub fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    let bytes = s.as_bytes();
    let mut run = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let esc: Option<&[u8]> = match b {
            b'"' => Some(b"\\\""),
            b'\\' => Some(b"\\\\"),
            b'\n' => Some(b"\\n"),
            b'\r' => Some(b"\\r"),
            b'\t' => Some(b"\\t"),
            0x08 => Some(b"\\b"),
            0x0C => Some(b"\\f"),
            _ => None,
        };
        if let Some(e) = esc {
            out.extend_from_slice(&bytes[run..i]);
            out.extend_from_slice(e);
            run = i + 1;
        } else if b < 0x20 {
            out.extend_from_slice(&bytes[run..i]);
            const HEX: &[u8; 16] = b"0123456789abcdef";
            out.extend_from_slice(b"\\u00");
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 15) as usize]);
            run = i + 1;
        }
    }
    out.extend_from_slice(&bytes[run..]);
    out.push(b'"');
}

/// Length in bytes of `canonical(v)`, without building it.
pub fn canonical_len(v: &Value) -> usize {
    match v {
        Value::Null => 4,
        Value::Bool(true) => 4,
        Value::Bool(false) => 5,
        Value::Number(n) => number_len(*n),
        Value::String(s) => string_len(s),
        Value::Array(a) => {
            2 + a.len().saturating_sub(1) + a.iter().map(canonical_len).sum::<usize>()
        }
        Value::Object(m) => {
            2 + m.len().saturating_sub(1)
                + m.iter()
                    .map(|(k, x)| string_len(k) + 1 + canonical_len(x))
                    .sum::<usize>()
        }
    }
}

/// Length of a string as canonical JSON, quotes included.
pub fn string_len(s: &str) -> usize {
    2 + s
        .bytes()
        .map(|b| match b {
            b'"' | b'\\' | b'\n' | b'\r' | b'\t' | 0x08 | 0x0C => 2,
            0..=0x1F => 6,
            _ => 1,
        })
        .sum::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(s: &str) -> Result<String, ParseError> {
        parse(s.as_bytes()).map(|v| canonical_string(&v))
    }

    // Addendum I.1
    #[test]
    fn i1_canonical_json() {
        let accept = [
            (r#"{"a":1,"b":2.0}"#, r#"{"a":1,"b":2}"#),
            (r#"{"a":1e2}"#, r#"{"a":100}"#),
            (r#"{"a":9007199254740991}"#, r#"{"a":9007199254740991}"#),
            (r#"{"a":1000000000000000000000}"#, r#"{"a":1e+21}"#),
            (r#"{"a":1e21}"#, r#"{"a":1e+21}"#),
            (r#"{"a":1e300}"#, r#"{"a":1e+300}"#),
            (r#"{"a":0.1}"#, r#"{"a":0.1}"#),
            (r#"{"a":1e-400}"#, r#"{"a":0}"#),
            (r#"{"a":-1e-400}"#, r#"{"a":0}"#),
            (r#"{"b":1,"a":2,"ä":3}"#, r#"{"a":2,"b":1,"ä":3}"#),
        ];
        for (i, o) in accept {
            assert_eq!(canon(i).unwrap(), o, "{i}");
        }
        let reject = [
            r#"{"a":9007199254740992}"#,
            r#"{"a":-9007199254740992}"#,
            r#"{"a":1,"a":2}"#,
            r#""\ud800""#,
            r#""\udc00""#,
            r#""\ud800A""#,
            r#"{"a":1e400}"#,
            r#"{"a":-1e400}"#,
            r#"{"a":1e20}"#,
            r#"{"a":-1e16}"#,
            r#"{"a":9007199254740992.0}"#,
            r#"{"a":9.007199254740992e15}"#,
        ];
        for i in reject {
            assert!(canon(i).is_err(), "{i} should be refused");
        }
    }

    #[test]
    fn i1_noncharacters() {
        for raw in [
            "\u{FDD0}",
            "\u{FDEF}",
            "\u{FFFE}",
            "\u{FFFF}",
            "\u{1FFFE}",
            "\u{10FFFF}",
        ] {
            assert!(
                canon(&format!("\"{raw}\"")).is_err(),
                "raw {:x}",
                raw.chars().next().unwrap() as u32
            );
        }
        for esc in [r#""﷐""#, r#""﷯""#, r#""￾""#, r#""￿""#, r#""🿾""#, r#""􏿿""#] {
            assert!(canon(esc).is_err(), "{esc}");
        }
        for ok in ["\u{FDCF}", "\u{FDF0}", "\u{FFFD}"] {
            assert!(canon(&format!("\"{ok}\"")).is_ok());
        }
        assert_eq!(canon(r#""﷏""#).unwrap(), "\"\u{FDCF}\"");
        // Raw invalid UTF-8.
        assert!(parse(b"\"\xff\"").is_err());
    }

    #[test]
    fn utf16_member_order() {
        // U+1F600 (surrogates D83D DE00) sorts before U+FB01 in UTF-16, after it in UTF-8.
        let v = parse("{\"\u{FB01}\":1,\"\u{1F600}\":2}".as_bytes()).unwrap();
        assert_eq!(canonical_string(&v), "{\"\u{1F600}\":2,\"\u{FB01}\":1}");
    }

    #[test]
    fn escapes_and_lengths() {
        let v = parse(br#"{"s":"a\"b\\c\u0001\u001f\n\/","n":[-0,1.5e-7,123456789012]}"#).unwrap();
        let c = canonical_string(&v);
        assert_eq!(
            c,
            r#"{"n":[0,1.5e-7,123456789012],"s":"a\"b\\c\u0001\u001f\n/"}"#
        );
        assert_eq!(canonical_len(&v), c.len());
    }

    #[test]
    fn grammar() {
        for bad in [
            "",
            "01",
            "1.",
            ".5",
            "+1",
            "[1,]",
            "{\"a\"}",
            "tru",
            "\"\t\"",
            "[1] x",
            "\u{feff}1",
        ] {
            assert!(parse(bad.as_bytes()).is_err(), "{bad:?}");
        }
        let deep = "[".repeat(MAX_PARSE_DEPTH + 1) + &"]".repeat(MAX_PARSE_DEPTH + 1);
        assert!(parse(deep.as_bytes()).is_err());
    }
}
