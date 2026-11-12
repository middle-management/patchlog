//! Grants (Addendum C) as Biscuit v3 tokens (§C.8).
//!
//! Checking a grant is split as §C.2 item 1 orders it:
//!
//! - [`decode`] does everything that needs no key: transport, `grantSize`,
//!   the Biscuit protobuf, every structural rule of §C.8 (one
//!   `grant_block(<canonical JSON>)` fact per block and nothing else,
//!   Ed25519 keys only, version 1 signature payloads, no third-party
//!   blocks), the block forms of §C.1, `rulesPerGrant` and the validity of
//!   each rule (§6.4.2). Its errors are request-shape errors: the server
//!   answers them before it looks up any key, and before the `ns` check.
//! - [`Unverified::verify`] checks the signature chain under the root key
//!   the root block's `kid` names, and the token's proof (sealed tokens are
//!   accepted), and yields a [`Grant`] with its id, revocation ids and
//!   stored form (§C.3, §C.4).
//! - [`Grant::check_times`] is `nbf` ≤ now < `exp` for every block.
//!
//! Biscuit's Datalog is never evaluated, so the protobuf decoder is a small
//! hand-written one for the messages a grant may use, refusing every other
//! field. [`mint`] and [`attenuate`] produce tokens in exactly the form
//! [`decode`] accepts.

use crate::id::Id;
use crate::json::{self, Value};
use crate::names::is_namespace_name;
use crate::rules;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

/// `grantSize` default (§12.2), in decoded bytes.
pub const GRANT_SIZE_DEFAULT: u64 = 8 * 1024;
/// `rulesPerGrant` default (§12.2).
pub const RULES_PER_GRANT_DEFAULT: u64 = 32;

/// Why a grant is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantError {
    /// `413`, `code: "limit"`, `limit: "grantSize"` (decoded bytes, §C.8).
    TooLarge { measured: u64, max: u64 },
    /// `413`, `code: "limit"`, `limit: "rulesPerGrant"` (§12.2).
    TooManyRules { measured: u64, max: u64 },
    /// `401`: no usable grant (§C.2).
    Invalid(String),
}

impl GrantError {
    pub fn status(&self) -> u16 {
        match self {
            GrantError::TooLarge { .. } | GrantError::TooManyRules { .. } => 413,
            GrantError::Invalid(_) => 401,
        }
    }

    /// The limit key of a `413`.
    pub fn limit(&self) -> Option<&'static str> {
        match self {
            GrantError::TooLarge { .. } => Some("grantSize"),
            GrantError::TooManyRules { .. } => Some("rulesPerGrant"),
            GrantError::Invalid(_) => None,
        }
    }
}

impl fmt::Display for GrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GrantError::TooLarge { measured, max } => {
                write!(f, "grant is {measured} bytes, over grantSize {max}")
            }
            GrantError::TooManyRules { measured, max } => {
                write!(f, "grant has {measured} rules, over rulesPerGrant {max}")
            }
            GrantError::Invalid(m) => write!(f, "invalid grant: {m}"),
        }
    }
}

impl std::error::Error for GrantError {}

fn invalid<T>(m: impl Into<String>) -> Result<T, GrantError> {
    Err(GrantError::Invalid(m.into()))
}

// ---------------------------------------------------------------------------
// Decoding

/// One Biscuit block as it appears in the token.
#[derive(Debug, Clone)]
struct RawBlock {
    /// The `SignedBlock` message, byte for byte.
    signed: Vec<u8>,
    /// Its serialized `Block` (the signed Datalog).
    data: Vec<u8>,
    next_key: [u8; 32],
    signature: [u8; 64],
}

#[derive(Debug, Clone)]
enum Proof {
    NextSecret([u8; 32]),
    FinalSignature([u8; 64]),
}

/// A grant whose form has been checked but whose signatures have not.
#[derive(Debug, Clone)]
pub struct Unverified {
    kid: String,
    root: Value,
    narrowing: Vec<Value>,
    blocks: Vec<RawBlock>,
    proof: Proof,
    /// The token's symbol table after its last block (Biscuit's, without
    /// the default symbols).
    symbols: Vec<String>,
}

/// A verified grant.
#[derive(Debug, Clone)]
pub struct Grant {
    /// The root block's `kid`.
    pub kid: String,
    /// The root block.
    pub root: Value,
    /// The narrowing blocks, in order.
    pub narrowing: Vec<Value>,
    /// The grant id, `trunc160(sha256(canonical(root block)))` (§C.3).
    pub id: Id,
    /// The grant id, then each narrowing block's
    /// `trunc160(sha256(its Biscuit signature))` (§C.4).
    pub revocation_ids: Vec<Id>,
    /// The non-bearer stored form (§C.8): the authority block's
    /// `SignedBlock` protobuf, with its signature and next key.
    pub stored: Vec<u8>,
}

/// Step 1 of §C.2 item 1: everything that needs no key, in its order:
/// transport, `grantSize` (`413`), the token's and the blocks' forms
/// (§C.8, §C.1, `401`), `rulesPerGrant` (`413`), then each rule (§6.4.2,
/// `401`). `token` is the `Bearer` value: Biscuit's URL-safe base64, with
/// or without padding and a `biscuit:` prefix.
pub fn decode(
    token: &str,
    grant_size_max: u64,
    rules_per_grant_max: u64,
) -> Result<Unverified, GrantError> {
    let b64 = token.strip_prefix("biscuit:").unwrap_or(token);
    let unpadded = b64.trim_end_matches('=');
    let measured = (unpadded.len() as u64) * 3 / 4;
    if measured > grant_size_max {
        return Err(GrantError::TooLarge {
            measured,
            max: grant_size_max,
        });
    }
    let pad = b64.len() - unpadded.len();
    if pad > 0 && (!b64.len().is_multiple_of(4) || pad > 2) {
        return invalid("not URL-safe base64");
    }
    let Some(bytes) = base64url_decode(unpadded) else {
        return invalid("not URL-safe base64");
    };
    let u = parse_token(&bytes)?;

    // rulesPerGrant, counted over every block, before any rule is checked.
    let blocks = std::iter::once(&u.root).chain(&u.narrowing);
    let measured: u64 = blocks
        .clone()
        .filter_map(|b| b.get("rules")?.as_array())
        .flatten()
        .map(count_rules)
        .sum();
    if measured > rules_per_grant_max {
        return Err(GrantError::TooManyRules {
            measured,
            max: rules_per_grant_max,
        });
    }
    for (i, b) in blocks.enumerate() {
        if let Some(r) = b.get("rules") {
            if let Err(errors) = rules::check(r, "/rules") {
                let (ptr, m) = errors.into_iter().next().unwrap_or_default();
                return invalid(format!("block {i}: invalid rule at {ptr}: {m}"));
            }
        }
    }
    Ok(u)
}

/// Rule forms in one rule, nested ones included (§12.2), whether or not it
/// is valid: `rulesPerGrant` is checked before validity (§C.2).
fn count_rules(r: &Value) -> u64 {
    let Some(m) = r.as_object() else { return 1 };
    if m.contains_key("op") {
        return 1;
    }
    let lists: u64 = ["all", "any", "if", "then"]
        .iter()
        .filter_map(|k| m.get(*k)?.as_array())
        .flatten()
        .map(count_rules)
        .sum();
    1 + lists + m.get("not").map_or(0, count_rules)
}

impl Unverified {
    /// The root block's `kid`, naming the key to verify it with.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The root block.
    pub fn root(&self) -> &Value {
        &self.root
    }

    /// The narrowing blocks, in order.
    pub fn narrowing(&self) -> &[Value] {
        &self.narrowing
    }

    /// Whether the token is sealed (no holder can add a block).
    pub fn is_sealed(&self) -> bool {
        matches!(self.proof, Proof::FinalSignature(_))
    }

    /// The grant id (§C.3), known before verification.
    pub fn id(&self) -> Id {
        grant_id(&self.root)
    }

    /// The revocation ids (§C.4), known before verification: the grant id,
    /// then each narrowing block's `trunc160(sha256(its signature))`.
    pub fn revocation_ids(&self) -> Vec<Id> {
        let mut ids = vec![self.id()];
        ids.extend(
            self.blocks[1..]
                .iter()
                .map(|b| Id::from_digest(&Sha256::digest(b.signature))),
        );
        ids
    }

    /// The non-bearer stored form (§C.8), known before verification.
    pub fn stored(&self) -> &[u8] {
        &self.blocks[0].signed
    }

    /// Verifies the signature chain under `root_key` (the Ed25519 key the
    /// root block's `kid` names): the authority block's signature by it,
    /// every other block's by the previous block's next key, all over
    /// Biscuit's version 1 payload and verified strictly, then the proof:
    /// a sealed token's final signature by the last next key, or an
    /// attenuable token's secret matching it.
    pub fn verify(&self, root_key: &[u8; 32]) -> Result<Grant, GrantError> {
        let mut key = *root_key;
        let mut prev: Option<&[u8; 64]> = None;
        for (i, b) in self.blocks.iter().enumerate() {
            let payload = block_payload_v1(&b.data, &b.next_key, prev);
            if !verify_ed25519(&key, &payload, &b.signature) {
                return invalid(format!("block {i}: bad signature"));
            }
            key = b.next_key;
            prev = Some(&b.signature);
        }
        let last = self.blocks.last().expect("authority block");
        match &self.proof {
            Proof::NextSecret(secret) => {
                if SigningKey::from_bytes(secret).verifying_key().to_bytes() != key {
                    return invalid("proof: the secret isn't the last block's next key");
                }
            }
            Proof::FinalSignature(sig) => {
                if !verify_ed25519(&key, &seal_payload(last), sig) {
                    return invalid("proof: bad seal signature");
                }
            }
        }
        Ok(Grant {
            kid: self.kid.clone(),
            root: self.root.clone(),
            narrowing: self.narrowing.clone(),
            id: self.id(),
            revocation_ids: self.revocation_ids(),
            stored: self.stored().to_vec(),
        })
    }
}

/// `trunc160(sha256(canonical(root block)))` (§C.3).
pub fn grant_id(root: &Value) -> Id {
    Id::from_digest(&Sha256::digest(json::canonical(root)))
}

impl Grant {
    /// `nbf` ≤ `now` < `exp` for every block (§C.2), `now` in milliseconds
    /// since the epoch.
    pub fn check_times(&self, now_ms: i64) -> Result<(), GrantError> {
        check_times(&self.root, &self.narrowing, now_ms)
    }

    /// The principal's delegatees, the narrowing blocks' `via` in block
    /// order (§C.1).
    pub fn via(&self) -> Vec<&str> {
        self.narrowing
            .iter()
            .filter_map(|b| b.get("via")?.as_str())
            .collect()
    }

    /// The earliest `exp` among the blocks, in milliseconds (rounded down).
    pub fn exp_ms(&self) -> i64 {
        std::iter::once(&self.root)
            .chain(&self.narrowing)
            .filter_map(|b| time_ms(b.get("exp")?.as_str()?))
            .min()
            .unwrap_or(i64::MIN)
    }
}

fn check_times(root: &Value, narrowing: &[Value], now_ms: i64) -> Result<(), GrantError> {
    let now = Instant {
        secs: now_ms.div_euclid(1000),
        frac: format!("{:03}", now_ms.rem_euclid(1000))
            .trim_end_matches('0')
            .to_string(),
    };
    for (i, b) in std::iter::once(root).chain(narrowing).enumerate() {
        let at = |k: &str| b.get(k).and_then(Value::as_str).and_then(instant);
        if let Some(nbf) = at("nbf") {
            if now < nbf {
                return invalid(format!("block {i} is not yet valid (nbf)"));
            }
        }
        if let Some(exp) = at("exp") {
            if now >= exp {
                return invalid(format!("block {i} has expired (exp)"));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Biscuit's protobuf messages (schema.proto), read strictly: only the
// fields a grant may use, each singular one at most once, wire types as
// declared; anything else refuses the token.

enum Wire<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

fn varint(b: &[u8], i: &mut usize) -> Option<u64> {
    let mut v: u64 = 0;
    for shift in (0..64).step_by(7) {
        let c = *b.get(*i)?;
        *i += 1;
        if shift == 63 && c > 1 {
            return None;
        }
        v |= u64::from(c & 0x7f) << shift;
        if c < 0x80 {
            return Some(v);
        }
    }
    None
}

/// A message's fields in order, as `(number, value)`.
fn fields<'a>(b: &'a [u8], what: &str) -> Result<Vec<(u64, Wire<'a>)>, GrantError> {
    let bad = || GrantError::Invalid(format!("{what}: malformed protobuf"));
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let key = varint(b, &mut i).ok_or_else(bad)?;
        let (n, wt) = (key >> 3, key & 7);
        if n == 0 {
            return Err(bad());
        }
        let v = match wt {
            0 => Wire::Varint(varint(b, &mut i).ok_or_else(bad)?),
            2 => {
                let len = varint(b, &mut i).ok_or_else(bad)?;
                let end = usize::try_from(len)
                    .ok()
                    .and_then(|l| i.checked_add(l))
                    .filter(|&e| e <= b.len())
                    .ok_or_else(bad)?;
                let s = &b[i..end];
                i = end;
                Wire::Bytes(s)
            }
            _ => return invalid(format!("{what}: field {n} of an unexpected wire type")),
        };
        out.push((n, v));
    }
    Ok(out)
}

/// Collects a message's fields by number, refusing unknown ones, wrong wire
/// types and repeated singular ones.
struct Msg<'a> {
    what: &'a str,
    varints: BTreeMap<u64, Vec<u64>>,
    bytes: BTreeMap<u64, Vec<&'a [u8]>>,
}

impl<'a> Msg<'a> {
    /// `spec` lists `(number, is_bytes, repeated, name)`; a field not listed
    /// is refused with `refuse(number)` if given, else as unknown.
    fn read(
        b: &'a [u8],
        what: &'a str,
        spec: &[(u64, bool, bool, &str)],
        refuse: &dyn Fn(u64) -> Option<String>,
    ) -> Result<Msg<'a>, GrantError> {
        let mut m = Msg {
            what,
            varints: BTreeMap::new(),
            bytes: BTreeMap::new(),
        };
        for (n, v) in fields(b, what)? {
            let Some(&(_, is_bytes, repeated, name)) = spec.iter().find(|s| s.0 == n) else {
                return invalid(
                    refuse(n).unwrap_or_else(|| format!("{what}: unexpected field {n}")),
                );
            };
            let count = match v {
                Wire::Varint(x) if !is_bytes => {
                    let e = m.varints.entry(n).or_default();
                    e.push(x);
                    e.len()
                }
                Wire::Bytes(x) if is_bytes => {
                    let e = m.bytes.entry(n).or_default();
                    e.push(x);
                    e.len()
                }
                _ => return invalid(format!("{what}: {name} has the wrong wire type")),
            };
            if count > 1 && !repeated {
                return invalid(format!("{what}: {name} appears twice"));
            }
        }
        Ok(m)
    }

    fn bytes(&self, n: u64, name: &str) -> Result<&'a [u8], GrantError> {
        match self.bytes.get(&n) {
            Some(v) => Ok(v[0]),
            None => invalid(format!("{}: {name} is missing", self.what)),
        }
    }

    fn opt_bytes(&self, n: u64) -> Option<&'a [u8]> {
        self.bytes.get(&n).map(|v| v[0])
    }

    fn all_bytes(&self, n: u64) -> &[&'a [u8]] {
        self.bytes.get(&n).map_or(&[], Vec::as_slice)
    }

    fn varint(&self, n: u64) -> Option<u64> {
        self.varints.get(&n).map(|v| v[0])
    }
}

const NONE: &dyn Fn(u64) -> Option<String> = &|_| None;

/// Biscuit's default symbol table: indexes 0–27; 28–1023 are reserved.
const DEFAULT_SYMBOLS: [&str; 28] = [
    "read",
    "write",
    "resource",
    "operation",
    "right",
    "time",
    "role",
    "owner",
    "tenant",
    "namespace",
    "user",
    "team",
    "service",
    "admin",
    "email",
    "group",
    "member",
    "ip_address",
    "client",
    "client_ip",
    "domain",
    "path",
    "version",
    "cluster",
    "node",
    "hostname",
    "nonce",
    "query",
];
const SYMBOL_OFFSET: u64 = 1024;
const FACT_NAME: &str = "grant_block";
/// Datalog block versions Biscuit 3 defines: v3.0 to v3.3.
const BLOCK_VERSIONS: std::ops::RangeInclusive<u64> = 3..=6;

fn parse_token(t: &[u8]) -> Result<Unverified, GrantError> {
    // message Biscuit { rootKeyId = 1; authority = 2; blocks = 3; proof = 4 }
    let top = Msg::read(
        t,
        "token",
        &[
            (1, false, false, "rootKeyId"),
            (2, true, false, "authority"),
            (3, true, true, "blocks"),
            (4, true, false, "proof"),
        ],
        NONE,
    )?;
    // rootKeyId is ignored: the root block's kid names the key (§C.8).
    let mut signed = vec![top.bytes(2, "authority")?];
    signed.extend_from_slice(top.all_bytes(3));
    let proof = parse_proof(top.bytes(4, "proof")?)?;

    let mut symbols: Vec<String> = Vec::new();
    let mut blocks = Vec::with_capacity(signed.len());
    let mut values = Vec::with_capacity(signed.len());
    for (i, sb) in signed.into_iter().enumerate() {
        let raw = parse_signed_block(sb, i)?;
        let text = parse_block(&raw.data, i, &mut symbols)?;
        let v = match json::parse(text.as_bytes()) {
            Ok(v) => v,
            Err(e) => return invalid(format!("block {i}: grant_block {e}")),
        };
        if json::canonical(&v) != text.as_bytes() {
            return invalid(format!("block {i}: grant_block isn't canonical JSON"));
        }
        check_block(&v, i)?;
        values.push(v);
        blocks.push(raw);
    }
    let root = values.remove(0);
    let kid = root
        .get("kid")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    Ok(Unverified {
        kid,
        root,
        narrowing: values,
        blocks,
        proof,
        symbols,
    })
}

fn parse_proof(b: &[u8]) -> Result<Proof, GrantError> {
    // message Proof { oneof { nextSecret = 1; finalSignature = 2 } }
    let p = Msg::read(
        b,
        "proof",
        &[
            (1, true, false, "nextSecret"),
            (2, true, false, "finalSignature"),
        ],
        NONE,
    )?;
    match (p.opt_bytes(1), p.opt_bytes(2)) {
        (Some(s), None) => match s.try_into() {
            Ok(s) => Ok(Proof::NextSecret(s)),
            Err(_) => invalid("proof: nextSecret isn't an Ed25519 secret key"),
        },
        (None, Some(s)) => match s.try_into() {
            Ok(s) => Ok(Proof::FinalSignature(s)),
            Err(_) => invalid("proof: finalSignature isn't an Ed25519 signature"),
        },
        _ => invalid("proof: exactly one of nextSecret and finalSignature"),
    }
}

fn parse_signed_block(sb: &[u8], i: usize) -> Result<RawBlock, GrantError> {
    // message SignedBlock { block = 1; nextKey = 2; signature = 3;
    //   externalSignature = 4; version = 5 }
    let what = format!("block {i}");
    let m = Msg::read(
        sb,
        &what,
        &[
            (1, true, false, "block"),
            (2, true, false, "nextKey"),
            (3, true, false, "signature"),
            (5, false, false, "version"),
        ],
        &|n| (n == 4).then(|| format!("block {i}: a third-party block (external signature)")),
    )?;
    if m.varint(5) != Some(1) {
        return invalid(format!(
            "block {i}: signature payload version {}, not 1",
            m.varint(5).unwrap_or(0)
        ));
    }
    let next_key = parse_public_key(m.bytes(2, "nextKey")?, &what)?;
    let Ok(signature) = m.bytes(3, "signature")?.try_into() else {
        return invalid(format!("block {i}: the signature isn't Ed25519"));
    };
    Ok(RawBlock {
        signed: sb.to_vec(),
        data: m.bytes(1, "block")?.to_vec(),
        next_key,
        signature,
    })
}

fn parse_public_key(b: &[u8], what: &str) -> Result<[u8; 32], GrantError> {
    // message PublicKey { algorithm = 1 (Ed25519 = 0); key = 2 }
    let m = Msg::read(
        b,
        what,
        &[(1, false, false, "algorithm"), (2, true, false, "key")],
        NONE,
    )?;
    match m.varint(1) {
        Some(0) => {}
        Some(a) => return invalid(format!("{what}: key algorithm {a}, not Ed25519")),
        None => return invalid(format!("{what}: key algorithm missing")),
    }
    match m.bytes(2, "key")?.try_into() {
        Ok(k) => Ok(k),
        Err(_) => invalid(format!("{what}: not a 32-byte Ed25519 key")),
    }
}

/// Checks one `Block` and returns its `grant_block` string, adding its
/// symbols to the token's table.
fn parse_block(data: &[u8], i: usize, table: &mut Vec<String>) -> Result<String, GrantError> {
    // message Block { symbols = 1; context = 2; version = 3; facts = 4;
    //   rules = 5; checks = 6; scope = 7; publicKeys = 8 }
    let what = format!("block {i}");
    let m = Msg::read(
        data,
        &what,
        &[
            (1, true, true, "symbols"),
            (2, true, false, "context"),
            (3, false, false, "version"),
            (4, true, true, "facts"),
        ],
        &|n| {
            let thing = match n {
                5 => "a rule",
                6 => "a check",
                7 => "a scope",
                8 => "a public key",
                _ => return None,
            };
            Some(format!("block {i}: {thing}, beyond the one fact"))
        },
    )?;
    if m.opt_bytes(2).is_some_and(|c| !c.is_empty()) {
        return invalid(format!("block {i}: a non-empty context"));
    }
    match m.varint(3) {
        Some(v) if BLOCK_VERSIONS.contains(&v) => {}
        v => {
            return invalid(format!(
                "block {i}: Datalog version {}, not 3 to 6",
                v.unwrap_or(0)
            ))
        }
    }
    let first_new = table.len() as u64 + SYMBOL_OFFSET;
    for s in m.all_bytes(1) {
        let Ok(s) = std::str::from_utf8(s) else {
            return invalid(format!("block {i}: a symbol isn't UTF-8"));
        };
        if DEFAULT_SYMBOLS.contains(&s) || table.iter().any(|t| t == s) {
            return invalid(format!("block {i}: symbol {s:?} defined twice"));
        }
        table.push(s.to_string());
    }
    let facts = m.all_bytes(4);
    if facts.len() != 1 {
        return invalid(format!("block {i}: {} facts, not one", facts.len()));
    }
    // message Fact { predicate = 1 }
    let f = Msg::read(facts[0], &what, &[(1, true, false, "predicate")], NONE)?;
    // message Predicate { name = 1; terms = 2 }
    let p = Msg::read(
        f.bytes(1, "predicate")?,
        &what,
        &[(1, false, false, "name"), (2, true, true, "terms")],
        NONE,
    )?;
    let symbol = |n: u64| -> Option<&str> {
        if n < DEFAULT_SYMBOLS.len() as u64 {
            Some(DEFAULT_SYMBOLS[n as usize])
        } else {
            let k = usize::try_from(n.checked_sub(SYMBOL_OFFSET)?).ok()?;
            table.get(k).map(String::as_str)
        }
    };
    let Some(name) = p.varint(1) else {
        return invalid(format!("{what}: predicate name missing"));
    };
    if symbol(name) != Some(FACT_NAME) {
        return invalid(format!("block {i}: a fact other than grant_block"));
    }
    let terms = p.all_bytes(2);
    if terms.len() != 1 {
        return invalid(format!("block {i}: grant_block has {} terms", terms.len()));
    }
    // message Term { oneof { ..., string = 3, ... } }
    let t = Msg::read(terms[0], &what, &[(3, false, false, "string")], &|_| {
        Some(format!("block {i}: grant_block's term isn't a string"))
    })?;
    let Some(s) = t.varint(3) else {
        return invalid(format!("block {i}: grant_block's term isn't a string"));
    };
    let Some(text) = symbol(s) else {
        return invalid(format!("block {i}: unknown symbol {s}"));
    };
    // Every symbol the block adds is used by its one fact.
    for n in first_new..table.len() as u64 + SYMBOL_OFFSET {
        if n != name && n != s {
            return invalid(format!("block {i}: an unused symbol"));
        }
    }
    Ok(text.to_string())
}

// ---------------------------------------------------------------------------
// Block forms (§C.1)

const ROOT_MEMBERS: [&str; 13] = [
    "kid", "sub", "groups", "roles", "attrs", "ns", "can", "nbf", "exp", "at", "rules", "signers",
    "enc",
];
const NARROWING_MEMBERS: [&str; 7] = ["ns", "can", "roles", "nbf", "exp", "rules", "via"];
/// Verbs a block's `can` may list; `"*"` is for keys only (§C.1, §C.4).
pub const VERBS: [&str; 11] = [
    "read", "create", "append", "restore", "delete", "purge", "config", "branch", "purge-ns",
    "export", "prune",
];

/// Checks a block's members against §C.1: block `i` is the root block for
/// `i == 0`, a narrowing block otherwise. Rules are only checked to be an
/// array here; [`decode`] counts and checks them afterwards.
fn check_block(v: &Value, i: usize) -> Result<(), GrantError> {
    let bad = |m: String| GrantError::Invalid(format!("block {i}: {m}"));
    let Some(m) = v.as_object() else {
        return Err(bad("not a JSON object".into()));
    };
    let root = i == 0;
    let allowed: &[&str] = if root {
        &ROOT_MEMBERS
    } else {
        &NARROWING_MEMBERS
    };
    if let Some(k) = m.keys().find(|k| !allowed.contains(&k.as_str())) {
        let kind = if root { "a root" } else { "a narrowing" };
        return Err(bad(format!("{k:?} isn't a member of {kind} block")));
    }
    if root {
        for k in ["kid", "sub", "ns", "exp"] {
            if !m.contains_key(k) {
                return Err(bad(format!("a root block needs {k:?}")));
            }
        }
        if !m.contains_key("can") && !m.contains_key("roles") {
            return Err(bad("a root block without \"can\" needs \"roles\"".into()));
        }
    }
    let strings = |k: &str| -> Result<Option<Vec<&str>>, GrantError> {
        let Some(x) = m.get(k) else { return Ok(None) };
        match x.as_array() {
            Some(a) => match a.iter().map(Value::as_str).collect::<Option<Vec<_>>>() {
                Some(s) => Ok(Some(s)),
                None => Err(bad(format!("{k} is an array of strings"))),
            },
            None => Err(bad(format!("{k} is an array of strings"))),
        }
    };
    for k in ["kid", "sub", "via"] {
        if m.get(k).is_some_and(|x| x.as_str().is_none()) {
            return Err(bad(format!("{k} is a string")));
        }
    }
    strings("groups")?;
    strings("roles")?;
    if let Some(ns) = strings("ns")? {
        if let Some(n) = ns.iter().find(|n| **n != "*" && !is_namespace_name(n)) {
            return Err(bad(format!("ns: {n:?} isn't a namespace name")));
        }
    }
    if let Some(can) = strings("can")? {
        if can.contains(&"*") {
            return Err(bad("\"*\" in can, which only keys may list".into()));
        }
        if let Some(c) = can.iter().find(|c| !VERBS.contains(c)) {
            return Err(bad(format!("can: {c:?} isn't a verb")));
        }
    }
    if m.get("attrs").is_some_and(|a| a.as_object().is_none()) {
        return Err(bad("attrs is an object".into()));
    }
    for k in ["nbf", "exp"] {
        if let Some(t) = m.get(k) {
            if t.as_str().and_then(instant).is_none() {
                return Err(bad(format!("{k} isn't an absolute RFC 3339 time")));
            }
        }
    }
    if let Some(at) = m.get("at") {
        let ok = match at {
            Value::String(s) => Id::parse(s).is_some(),
            Value::Object(o) => {
                o.len() == 2
                    && o.get("ns")
                        .and_then(Value::as_str)
                        .is_some_and(is_namespace_name)
                    && o.get("id")
                        .and_then(Value::as_str)
                        .is_some_and(|s| Id::parse(s).is_some())
            }
            _ => false,
        };
        if !ok {
            return Err(bad("at is an ns_id or { \"ns\", \"id\" }".into()));
        }
    }
    if m.get("rules").is_some_and(|r| r.as_array().is_none()) {
        return Err(bad("rules is an array of rules".into()));
    }
    if let Some(s) = m.get("signers") {
        check_signers(s).map_err(|e| bad(format!("signers: {e}")))?;
    }
    if let Some(e) = m.get("enc") {
        let ok = e.as_object().is_some_and(|o| {
            o.len() == 3
                && o.get("kty").and_then(Value::as_str) == Some("OKP")
                && o.get("crv").and_then(Value::as_str) == Some("X25519")
                && o.get("x")
                    .and_then(Value::as_str)
                    .is_some_and(|x| decode_pub(x).is_some())
        });
        if !ok {
            return Err(bad("enc is an X25519 JWK of only kty, crv and x".into()));
        }
    }
    Ok(())
}

/// `signers: [{ "kid", "alg": "Ed25519", "pub" }]` (§C.3.1).
fn check_signers(s: &Value) -> Result<(), String> {
    let Some(list) = s.as_array() else {
        return Err("an array of signer entries".into());
    };
    let mut kids = Vec::with_capacity(list.len());
    for (j, e) in list.iter().enumerate() {
        let Some(o) = e.as_object() else {
            return Err(format!("entry {j} isn't an object"));
        };
        if let Some(k) = o
            .keys()
            .find(|k| !["kid", "alg", "pub"].contains(&k.as_str()))
        {
            return Err(format!("entry {j} has {k:?}"));
        }
        let Some(kid) = o.get("kid").and_then(Value::as_str) else {
            return Err(format!("entry {j} needs a string kid"));
        };
        if kid.contains(':') {
            return Err(format!("kid {kid:?} contains ':'"));
        }
        if kids.contains(&kid) {
            return Err(format!("kid {kid:?} listed twice"));
        }
        kids.push(kid);
        if o.get("alg").and_then(Value::as_str) != Some("Ed25519") {
            return Err(format!("entry {j}: alg isn't \"Ed25519\""));
        }
        if !o
            .get("pub")
            .and_then(Value::as_str)
            .is_some_and(|p| decode_pub(p).is_some())
        {
            return Err(format!("entry {j}: pub isn't 43 characters of base64url"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Times

/// An RFC 3339 time as seconds since the epoch and its fractional digits
/// without trailing zeros, which then order as decimals do.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Instant {
    secs: i64,
    frac: String,
}

/// Parses an absolute RFC 3339 `date-time` (with `Z` or an offset), in the
/// form the rule language compares (§6.4.2): uppercase `T` and `Z`, no
/// leap second.
fn instant(s: &str) -> Option<Instant> {
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
    Some(Instant {
        secs: days * 86_400 + h * 3600 + mi * 60 + sec - offset,
        frac,
    })
}

/// A grant time (`nbf`, `exp`) in milliseconds since the epoch, rounded
/// down; `None` if it isn't one.
pub fn time_ms(s: &str) -> Option<i64> {
    let t = instant(s)?;
    let ms: i64 = format!("{:0<3}", t.frac)[..3].parse().ok()?;
    t.secs.checked_mul(1000)?.checked_add(ms)
}

// ---------------------------------------------------------------------------
// Signatures

/// Biscuit's block signature payload, version 1.
fn block_payload_v1(data: &[u8], next_key: &[u8; 32], prev: Option<&[u8; 64]>) -> Vec<u8> {
    let mut p = Vec::with_capacity(data.len() + 160);
    p.extend_from_slice(b"\0BLOCK\0\0VERSION\0");
    p.extend_from_slice(&1u32.to_le_bytes());
    p.extend_from_slice(b"\0PAYLOAD\0");
    p.extend_from_slice(data);
    p.extend_from_slice(b"\0ALGORITHM\0");
    p.extend_from_slice(&0u32.to_le_bytes()); // Ed25519
    p.extend_from_slice(b"\0NEXTKEY\0");
    p.extend_from_slice(next_key);
    if let Some(sig) = prev {
        p.extend_from_slice(b"\0PREVSIG\0");
        p.extend_from_slice(sig);
    }
    p
}

/// What a sealed token's final signature covers: the last block's data,
/// its next key's algorithm and bytes, and its signature.
fn seal_payload(last: &RawBlock) -> Vec<u8> {
    let mut p = last.data.clone();
    p.extend_from_slice(&0u32.to_le_bytes());
    p.extend_from_slice(&last.next_key);
    p.extend_from_slice(&last.signature);
    p
}

/// Strict Ed25519 verification (RFC 8032 §5.1.7 with its strict options):
/// canonical encodings of the public key and `R`, `S < L`, and no
/// small-order public key or `R`.
pub fn verify_ed25519(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(public) else {
        return false;
    };
    // Decompression accepts a y ≥ p; strict verification doesn't.
    if vk.to_edwards().compress().to_bytes() != *public {
        return false;
    }
    vk.verify_strict(msg, &Signature::from_bytes(sig)).is_ok()
}

/// The Ed25519 public key of a 32-byte seed.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

// ---------------------------------------------------------------------------
// base64url

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url without padding.
pub fn base64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..=c.len() {
            out.push(B64URL[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// Decodes base64url without padding, strictly: no other characters, and
/// the unused bits of the last character zero.
pub fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 4 == 1 {
        return None;
    }
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32)
    };
    let mut out = Vec::with_capacity(b.len() * 3 / 4);
    for chunk in b.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        let bytes = chunk.len() - 1;
        if n & ((1 << (24 - 8 * bytes)) - 1) != 0 {
            return None;
        }
        out.extend_from_slice(&n.to_be_bytes()[1..=bytes]);
    }
    Some(out)
}

/// A 32-byte key as 43 characters of base64url without padding (a
/// `signers` or key `pub`, an `enc`'s `x`).
pub fn decode_pub(s: &str) -> Option<[u8; 32]> {
    if s.len() != 43 {
        return None;
    }
    base64url_decode(s)?.try_into().ok()
}

/// Biscuit's URL-safe base64, with padding, as Biscuit libraries write it.
fn base64url_padded(bytes: &[u8]) -> String {
    let mut s = base64url(bytes);
    while !s.len().is_multiple_of(4) {
        s.push('=');
    }
    s
}

// ---------------------------------------------------------------------------
// Minting

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push(v as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn put_bytes(out: &mut Vec<u8>, field: u64, bytes: &[u8]) {
    put_varint(out, field << 3 | 2);
    put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn put_uint(out: &mut Vec<u8>, field: u64, v: u64) {
    put_varint(out, field << 3);
    put_varint(out, v);
}

/// A `Block` with the one fact `grant_block(<text>)`, adding its new
/// symbols to `table`.
fn encode_block(text: &str, table: &mut Vec<String>) -> Vec<u8> {
    let mut symbol = |s: &str, new: &mut Vec<String>| -> u64 {
        let k = match table.iter().position(|t| t == s) {
            Some(k) => k,
            None => {
                table.push(s.to_string());
                new.push(s.to_string());
                table.len() - 1
            }
        };
        k as u64 + SYMBOL_OFFSET
    };
    let mut new = Vec::new();
    let name = symbol(FACT_NAME, &mut new);
    let string = symbol(text, &mut new);
    let mut term = Vec::new();
    put_uint(&mut term, 3, string);
    let mut predicate = Vec::new();
    put_uint(&mut predicate, 1, name);
    put_bytes(&mut predicate, 2, &term);
    let mut fact = Vec::new();
    put_bytes(&mut fact, 1, &predicate);
    let mut block = Vec::new();
    for s in &new {
        put_bytes(&mut block, 1, s.as_bytes());
    }
    put_uint(&mut block, 3, 3);
    put_bytes(&mut block, 4, &fact);
    block
}

/// A `SignedBlock` with a version 1 signature by `signer`.
fn sign_block(
    signer: &SigningKey,
    data: Vec<u8>,
    next_key: [u8; 32],
    prev: Option<&[u8; 64]>,
) -> RawBlock {
    let signature = signer
        .sign(&block_payload_v1(&data, &next_key, prev))
        .to_bytes();
    let mut key = Vec::with_capacity(36);
    put_uint(&mut key, 1, 0);
    put_bytes(&mut key, 2, &next_key);
    let mut signed = Vec::new();
    put_bytes(&mut signed, 1, &data);
    put_bytes(&mut signed, 2, &key);
    put_bytes(&mut signed, 3, &signature);
    put_uint(&mut signed, 5, 1);
    RawBlock {
        signed,
        data,
        next_key,
        signature,
    }
}

fn encode_token(blocks: &[RawBlock], secret: &[u8; 32]) -> String {
    let mut t = Vec::new();
    put_bytes(&mut t, 2, &blocks[0].signed);
    for b in &blocks[1..] {
        put_bytes(&mut t, 3, &b.signed);
    }
    let mut proof = Vec::new();
    put_bytes(&mut proof, 1, secret);
    put_bytes(&mut t, 4, &proof);
    base64url_padded(&t)
}

/// Mints a grant: the root block signed by the key of `root_seed`, then
/// each narrowing block, as §C.8 requires. `next_seed(i)` gives the seed of
/// block `i`'s next key (random for real grants; fixed for tests). The
/// result is checked with [`decode`] (without limits), so a block that
/// breaks §C.1 or a rule that isn't valid is refused here.
pub fn mint(
    root_seed: &[u8; 32],
    root: &Value,
    narrowing: &[Value],
    mut next_seed: impl FnMut(usize) -> [u8; 32],
) -> Result<String, GrantError> {
    let mut table = Vec::new();
    let mut blocks: Vec<RawBlock> = Vec::with_capacity(1 + narrowing.len());
    let mut signer = SigningKey::from_bytes(root_seed);
    for (i, b) in std::iter::once(root).chain(narrowing).enumerate() {
        let data = encode_block(&json::canonical_string(b), &mut table);
        let next = SigningKey::from_bytes(&next_seed(i));
        let raw = sign_block(
            &signer,
            data,
            next.verifying_key().to_bytes(),
            blocks.last().map(|b| &b.signature),
        );
        blocks.push(raw);
        signer = next;
    }
    let token = encode_token(&blocks, &signer.to_bytes());
    decode(&token, u64::MAX, u64::MAX)?;
    Ok(token)
}

/// Appends a narrowing block to an attenuable token, as any holder can,
/// with the next key of `next_seed`. Refuses a sealed token and one that
/// [`decode`] refuses; doesn't verify signatures.
pub fn attenuate(token: &str, block: &Value, next_seed: &[u8; 32]) -> Result<String, GrantError> {
    let u = decode(token, u64::MAX, u64::MAX)?;
    let Proof::NextSecret(secret) = u.proof else {
        return invalid("a sealed token can't be attenuated");
    };
    let mut table = u.symbols;
    let mut blocks = u.blocks;
    let data = encode_block(&json::canonical_string(block), &mut table);
    let next = SigningKey::from_bytes(next_seed);
    let raw = sign_block(
        &SigningKey::from_bytes(&secret),
        data,
        next.verifying_key().to_bytes(),
        blocks.last().map(|b| &b.signature),
    );
    blocks.push(raw);
    let token = encode_token(&blocks, next_seed);
    decode(&token, u64::MAX, u64::MAX)?;
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!("../../../../internal/vectors/testdata/biscuit.json");

    fn vectors() -> Value {
        json::parse(VECTORS.as_bytes()).unwrap()
    }

    fn s<'a>(v: &'a Value, k: &str) -> &'a str {
        v.get(k).and_then(Value::as_str).unwrap()
    }

    fn list(d: &Value) -> &[Value] {
        d.get("vectors").and_then(Value::as_array).unwrap()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn seed(n: u8) -> [u8; 32] {
        std::array::from_fn(|k| n + k as u8)
    }

    fn root_key(d: &Value) -> [u8; 32] {
        decode_pub(s(d, "root public key")).unwrap()
    }

    fn v(s: &str) -> Value {
        json::parse(s.as_bytes()).unwrap()
    }

    #[test]
    fn accepted_vectors() {
        let d = vectors();
        let key = root_key(&d);
        let mut n = 0;
        for t in list(&d) {
            if s(t, "verdict") != "accept" {
                continue;
            }
            n += 1;
            let name = s(t, "name");
            let u = decode(s(t, "token"), GRANT_SIZE_DEFAULT, RULES_PER_GRANT_DEFAULT)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(u.kid(), "ops-2026");
            let g = u.verify(&key).unwrap_or_else(|e| panic!("{name}: {e}"));
            let blocks: Vec<String> = std::iter::once(&g.root)
                .chain(&g.narrowing)
                .map(json::canonical_string)
                .collect();
            let want: Vec<&str> = t
                .get("blocks")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|b| b.as_str().unwrap())
                .collect();
            assert_eq!(blocks, want, "{name}");
            let sigs: Vec<String> = u.blocks.iter().map(|b| hex(&b.signature)).collect();
            let want: Vec<&str> = t
                .get("signatures")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|b| b.as_str().unwrap())
                .collect();
            assert_eq!(sigs, want, "{name}");
            assert_eq!(g.id.text(), s(t, "grant id"), "{name}");
            let rev: Vec<String> = g.revocation_ids.iter().map(Id::text).collect();
            let want: Vec<&str> = t
                .get("revocation ids")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|b| b.as_str().unwrap())
                .collect();
            assert_eq!(rev, want, "{name}");
            assert_eq!(hex(&g.stored), s(t, "stored"), "{name}");
            assert_eq!(g.via(), ["svc:reader"]);
            // With the prefix too.
            let p = format!("biscuit:{}", s(t, "token"));
            decode(&p, GRANT_SIZE_DEFAULT, 32)
                .unwrap()
                .verify(&key)
                .unwrap();
            // Under another root key, nothing verifies.
            assert!(u.verify(&public_key(&seed(1))).is_err());
        }
        assert_eq!(n, 2);
    }

    /// Each refused vector fails at the stage its rule implies: at
    /// [`decode`] where the rule needs no key, else at [`Unverified::verify`].
    #[test]
    fn refused_vectors() {
        let d = vectors();
        let key = root_key(&d);
        let mut n = 0;
        for t in list(&d) {
            if s(t, "verdict") == "accept" {
                continue;
            }
            n += 1;
            let name = s(t, "name");
            assert_eq!(s(t, "verdict"), "401", "{name}");
            let at_verify = s(t, "fn").contains("SignedBy");
            let r = decode(s(t, "token"), GRANT_SIZE_DEFAULT, RULES_PER_GRANT_DEFAULT);
            let err = match r {
                Err(e) => {
                    assert!(!at_verify, "{name}: refused at decode: {e}");
                    e
                }
                Ok(u) => {
                    assert!(at_verify, "{name}: decoded");
                    u.verify(&key).expect_err(name)
                }
            };
            assert_eq!(err.status(), 401, "{name}: {err}");
            println!("{name}: {err}");
        }
        assert_eq!(n, 22);
    }

    #[test]
    fn mint_reproduces_i14() {
        let d = vectors();
        let t = &list(&d)[0];
        let blocks: Vec<Value> = t
            .get("blocks")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|b| v(b.as_str().unwrap()))
            .collect();
        let token = mint(&seed(0), &blocks[0], &blocks[1..], |i| {
            seed(0x40 + 0x20 * i as u8)
        })
        .unwrap();
        assert_eq!(token, s(t, "token"));
        // The same through attenuation.
        let one = mint(&seed(0), &blocks[0], &[], |_| seed(0x40)).unwrap();
        assert_eq!(attenuate(&one, &blocks[1], &seed(0x60)).unwrap(), token);
        // I.14's token, wrapped as in the spec.
        let i14 = "EpcCCqoBCgtncmFudF9ibG9jawqMAXsiY2FuIjpbInJlYWQiLCJhcHBlbmQiXSwiZXhwIjoiMjAyNi0xMC0wNVQwMDowMDowMFoiLCJncm91\
cHMiOlsibWF0Y2gtZGVzayJdLCJraWQiOiJvcHMtMjAyNiIsIm5zIjpbIm1hdGNoZXMiXSwicnVsZXMiOltdLCJzdWIiOiJ1c2VyOmJvYiJ9\
GAMiCgoICIAIEgMYgQgSJAgAEiAlQ7kv8QlVEUdq3INp223ckzZloRl43aFATuEGbKlVnRpAWgaUHLoFLrXYHs2MaIetUEXWGK0SK3h0v5xB\
RUsBNE2qQ14tB8LGmoIYtimpZPta1sYSQLSXob_gozBFMAKwBCgBGp8BCjMKI3siY2FuIjpbInJlYWQiXSwidmlhIjoic3ZjOnJlYWRlciJ9\
GAMiCgoICIAIEgMYgggSJAgAEiAXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk_1RpA8F--Z-0pJdeRlyhAqVvLMmB_GniPzob9JmjQ\
7YO0D3Q2C3CKHXITLKHBjp3DfkQNccX2F8XKmGJl-6o7fmuICSgBIiIKIGBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_";
        assert_eq!(token, i14);
        let g = decode(i14, GRANT_SIZE_DEFAULT, RULES_PER_GRANT_DEFAULT)
            .unwrap()
            .verify(&decode_pub("A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg").unwrap())
            .unwrap();
        let rev: Vec<String> = g.revocation_ids.iter().map(Id::text).collect();
        assert_eq!(
            rev,
            [
                "15swdvi5nbnlkv76v7y6k77h52atov6ru",
                "1chpmwycvsbh7sqmzckzhe7hk6obtra72"
            ]
        );
        assert_eq!(
            public_key(&seed(0)),
            decode_pub(s(&d, "root public key")).unwrap()
        );
    }

    #[test]
    fn i4_grant_id() {
        let root = v(
            r#"{"can":["read","append"],"exp":"2026-10-05T00:00:00Z","groups":["match-desk"],"kid":"ops-2026","ns":["matches"],"rules":[],"sub":"user:bob"}"#,
        );
        assert_eq!(grant_id(&root).text(), "15swdvi5nbnlkv76v7y6k77h52atov6ru");
        // I.4's signer key and signature verify strictly.
        let pubkey = decode_pub("RuA-BPBo4NqYkx_g6O3FJZEvHe9xVq-EQmmn3F8mRiM").unwrap();
        let digest: Vec<u8> = (0..32)
            .map(|i| {
                u8::from_str_radix(
                    &"43bba3f8e86bdd96435153ddb0d704cab7e5e9459087f3fd78c157b6a7102c54"
                        [2 * i..2 * i + 2],
                    16,
                )
                .unwrap()
            })
            .collect();
        let sig: [u8; 64] = base64url_decode(
            "Zdm2HSg4Fefj9ZaOYm2nYdW7xyLjKc_6T8CruK76EDEL_H6rnZd_sKdQrlevjtIQDGpiudAJjyHigradmHXXCA",
        )
        .unwrap()
        .try_into()
        .unwrap();
        assert!(verify_ed25519(&pubkey, &digest, &sig));
        assert!(!verify_ed25519(&pubkey, &digest[1..], &sig));
    }

    #[test]
    fn strictness() {
        let sk = seed(7);
        let pk = public_key(&sk);
        let sig = SigningKey::from_bytes(&sk).sign(b"m").to_bytes();
        assert!(verify_ed25519(&pk, b"m", &sig));
        // S + L.
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut bad = sig;
        let mut carry = 0u16;
        for i in 0..32 {
            let x = bad[32 + i] as u16 + L[i] as u16 + carry;
            bad[32 + i] = x as u8;
            carry = x >> 8;
        }
        assert!(!verify_ed25519(&pk, b"m", &bad));
        // A small-order public key (the identity) with a forged signature:
        // R = identity, S = 0 satisfies the cofactorless equation.
        let mut ident = [0u8; 32];
        ident[0] = 1;
        let mut forged = [0u8; 64];
        forged[0] = 1;
        assert!(!verify_ed25519(&ident, b"anything", &forged));
        // A non-canonical encoding of a valid public key: y + p for y = 1
        // isn't representable, but the sign bit on x = 0 is non-canonical.
        let mut neg_ident = ident;
        neg_ident[31] |= 0x80;
        assert!(!verify_ed25519(&neg_ident, b"anything", &forged));
    }

    fn token(root: &str, narrowing: &[&str]) -> Result<String, GrantError> {
        let n: Vec<Value> = narrowing.iter().map(|b| v(b)).collect();
        mint(&seed(0), &v(root), &n, |i| seed(0x40 + 0x20 * i as u8))
    }

    const ROOT: &str =
        r#"{"kid":"k","sub":"user:a","ns":["n"],"can":["read"],"exp":"2026-10-05T00:00:00Z"}"#;

    fn shape_err(root: &str, narrowing: &[&str]) {
        match token(root, narrowing) {
            Err(GrantError::Invalid(_)) => {}
            other => panic!("{root} {narrowing:?}: {other:?}"),
        }
    }

    #[test]
    fn block_forms() {
        token(ROOT, &[]).unwrap();
        token(
            r#"{"kid":"k","sub":"s","ns":["*"],"roles":[],"exp":"2026-10-05T02:00:00+02:00","nbf":"2026-10-04T00:00:00.5Z",
                "groups":["g"],"attrs":{"a":1},"at":{"ns":"cat","id":"15swdvi5nbnlkv76v7y6k77h52atov6ru"},
                "rules":[{"op":"writes","within":["/a"]}],
                "signers":[{"kid":"key-1","alg":"Ed25519","pub":"RuA-BPBo4NqYkx_g6O3FJZEvHe9xVq-EQmmn3F8mRiM"}],
                "enc":{"kty":"OKP","crv":"X25519","x":"RuA-BPBo4NqYkx_g6O3FJZEvHe9xVq-EQmmn3F8mRiM"}}"#,
            &[r#"{"via":"svc:x","ns":[],"can":[],"roles":["r"],"exp":"2026-10-04T12:00:00Z","nbf":"2026-10-04T01:00:00Z","rules":[]}"#, "{}"],
        )
        .unwrap();
        // Root members.
        for k in ["kid", "sub", "ns", "exp"] {
            let mut r = v(ROOT);
            if let Value::Object(m) = &mut r {
                m.remove(k);
            }
            shape_err(&json::canonical_string(&r), &[]);
        }
        shape_err(
            r#"{"kid":"k","sub":"s","ns":["n"],"exp":"2026-10-05T00:00:00Z"}"#,
            &[],
        );
        shape_err(
            r#"{"kid":"k","sub":"s","ns":["n"],"can":["read"],"exp":"2026-10-05T00:00:00Z","via":"x"}"#,
            &[],
        );
        shape_err(
            r#"{"kid":"k","sub":"s","ns":["n"],"can":["*"],"exp":"2026-10-05T00:00:00Z"}"#,
            &[],
        );
        shape_err(
            r#"{"kid":"k","sub":"s","ns":["n"],"can":["write"],"exp":"2026-10-05T00:00:00Z"}"#,
            &[],
        );
        shape_err(
            r#"{"kid":"k","sub":"s","ns":["N"],"can":["read"],"exp":"2026-10-05T00:00:00Z"}"#,
            &[],
        );
        shape_err(
            r#"{"kid":"k","sub":"s","ns":["n"],"can":["read"],"exp":"2026-10-05"}"#,
            &[],
        );
        shape_err(
            r#"{"kid":"k","sub":"s","ns":["n"],"can":["read"],"exp":"2026-10-05T00:00:00"}"#,
            &[],
        );
        shape_err(
            r#"{"kid":"k","sub":"s","ns":["n"],"can":["read"],"exp":"2026-10-05T00:00:00Z","at":"x"}"#,
            &[],
        );
        shape_err(
            r#"{"kid":"k","sub":"s","ns":["n"],"can":["read"],"exp":"2026-10-05T00:00:00Z","attrs":[]}"#,
            &[],
        );
        shape_err(
            r#"{"kid":"k","sub":1,"ns":["n"],"can":["read"],"exp":"2026-10-05T00:00:00Z"}"#,
            &[],
        );
        shape_err(
            r#"{"kid":"k","sub":"s","ns":["n"],"can":["read"],"exp":"2026-10-05T00:00:00Z","rules":{}}"#,
            &[],
        );
        shape_err(
            r#"{"kid":"k","sub":"s","ns":["n"],"can":["read"],"exp":"2026-10-05T00:00:00Z","rules":[{"op":"nope"}]}"#,
            &[],
        );
        shape_err(
            r#"{"kid":"k","sub":"s","ns":["n"],"can":["read"],"exp":"2026-10-05T00:00:00Z","enc":{"kty":"OKP","crv":"X25519","x":"RuA-BPBo4NqYkx_g6O3FJZEvHe9xVq-EQmmn3F8mRiM","use":"enc"}}"#,
            &[],
        );
        shape_err(
            r#"{"kid":"k","sub":"s","ns":["n"],"can":["read"],"exp":"2026-10-05T00:00:00Z","enc":{"kty":"OKP","crv":"Ed25519","x":"RuA-BPBo4NqYkx_g6O3FJZEvHe9xVq-EQmmn3F8mRiM"}}"#,
            &[],
        );
        // Signers.
        let signers = |s: &str| {
            format!(
                r#"{{"kid":"k","sub":"s","ns":["n"],"can":["read"],"exp":"2026-10-05T00:00:00Z","signers":{s}}}"#
            )
        };
        const P: &str = "RuA-BPBo4NqYkx_g6O3FJZEvHe9xVq-EQmmn3F8mRiM";
        token(&signers(&format!(r#"[{{"kid":"a","alg":"Ed25519","pub":"{P}"}},{{"kid":"b","alg":"Ed25519","pub":"{P}"}}]"#)), &[]).unwrap();
        shape_err(
            &signers(&format!(
                r#"[{{"kid":"a","alg":"Ed25519","pub":"{P}"}},{{"kid":"a","alg":"Ed25519","pub":"{P}"}}]"#
            )),
            &[],
        );
        shape_err(
            &signers(&format!(r#"[{{"kid":"a:b","alg":"Ed25519","pub":"{P}"}}]"#)),
            &[],
        );
        shape_err(
            &signers(&format!(r#"[{{"kid":"a","alg":"Ed448","pub":"{P}"}}]"#)),
            &[],
        );
        shape_err(
            &signers(&format!(r#"[{{"kid":"a","alg":"Ed25519","pub":"{P}="}}]"#)),
            &[],
        );
        shape_err(
            &signers(
                r#"[{"kid":"a","alg":"Ed25519","pub":"RuA-BPBo4NqYkx_g6O3FJZEvHe9xVq-EQmmn3F8mRiN"}]"#,
            ),
            &[],
        );
        shape_err(
            &signers(&format!(
                r#"[{{"kid":"a","alg":"Ed25519","pub":"{P}","x":1}}]"#
            )),
            &[],
        );
        // Narrowing blocks.
        for b in [
            r#"{"kid":"k"}"#,
            r#"{"sub":"s"}"#,
            r#"{"signers":[]}"#,
            r#"{"enc":{}}"#,
            r#"{"attrs":{}}"#,
            r#"{"can":["*"]}"#,
            r#"{"via":1}"#,
            "[]",
        ] {
            shape_err(ROOT, &[b]);
        }
    }

    #[test]
    fn limits() {
        let t = token(ROOT, &[]).unwrap();
        let size = base64url_decode(t.trim_end_matches('=')).unwrap().len() as u64;
        decode(&t, size, 0).unwrap();
        assert_eq!(
            decode(&t, size - 1, 0).unwrap_err(),
            GrantError::TooLarge {
                measured: size,
                max: size - 1
            }
        );
        // rulesPerGrant counts nested forms across blocks, before validity.
        let root = r#"{"kid":"k","sub":"s","ns":["n"],"can":["read"],"exp":"2026-10-05T00:00:00Z","rules":[{"not":{"op":"writes","within":["/a"]}}]}"#;
        let t = token(
            root,
            &[r#"{"rules":[{"all":[{"op":"writes","within":["/b"]}]}]}"#],
        )
        .unwrap();
        decode(&t, GRANT_SIZE_DEFAULT, 4).unwrap();
        assert_eq!(
            decode(&t, GRANT_SIZE_DEFAULT, 3).unwrap_err(),
            GrantError::TooManyRules {
                measured: 4,
                max: 3
            }
        );
        // A grant that is too large and malformed is 413 first.
        assert_eq!(decode("!!!!!!!!", 1, 0).unwrap_err().status(), 413);
        assert_eq!(decode("!!!!!!!!", 100, 0).unwrap_err().status(), 401);
    }

    #[test]
    fn invalid_rules_count_before_they_fail() {
        // An invalid rule beyond the limit is 413, within it 401.
        let n = v(r#"{"rules":[{"op":"nope"},{"op":"nope"}]}"#);
        let u = mint(&seed(0), &v(ROOT), &[], |_| seed(0x40)).unwrap();
        // Attenuation validates too, so build the token by hand.
        let d = decode(&u, u64::MAX, u64::MAX).unwrap();
        let Proof::NextSecret(secret) = d.proof else {
            unreachable!()
        };
        let mut table = d.symbols;
        let mut blocks = d.blocks;
        let data = encode_block(&json::canonical_string(&n), &mut table);
        let raw = sign_block(
            &SigningKey::from_bytes(&secret),
            data,
            public_key(&seed(0x60)),
            Some(&blocks[0].signature),
        );
        blocks.push(raw);
        let t = encode_token(&blocks, &seed(0x60));
        assert_eq!(
            decode(&t, GRANT_SIZE_DEFAULT, 1).unwrap_err(),
            GrantError::TooManyRules {
                measured: 2,
                max: 1
            }
        );
        assert_eq!(decode(&t, GRANT_SIZE_DEFAULT, 2).unwrap_err().status(), 401);
    }

    #[test]
    fn times() {
        let t = token(
            r#"{"kid":"k","sub":"s","ns":["n"],"can":["read"],"nbf":"2026-10-04T08:00:00Z","exp":"2026-10-05T00:00:00Z"}"#,
            &[r#"{"exp":"2026-10-04T20:00:00.0005Z"}"#],
        )
        .unwrap();
        let g = decode(&t, GRANT_SIZE_DEFAULT, 32)
            .unwrap()
            .verify(&public_key(&seed(0)))
            .unwrap();
        let nbf = time_ms("2026-10-04T08:00:00Z").unwrap();
        let exp = time_ms("2026-10-04T20:00:00Z").unwrap();
        assert!(g.check_times(nbf - 1).is_err());
        g.check_times(nbf).unwrap();
        // exp is 20:00:00.0005: 20:00:00.000 is before it, .001 isn't.
        g.check_times(exp).unwrap();
        assert!(g.check_times(exp + 1).is_err());
        assert_eq!(g.exp_ms(), exp);
        assert_eq!(time_ms("2026-10-04T22:00:00.5+02:00"), Some(exp + 500));
    }

    #[test]
    fn sealed_and_proof() {
        let d = vectors();
        let key = root_key(&d);
        let sealed = s(&list(&d)[1], "token");
        let u = decode(sealed, GRANT_SIZE_DEFAULT, 32).unwrap();
        assert!(u.is_sealed());
        assert!(attenuate(sealed, &v("{}"), &seed(9)).is_err());
        // An attenuable token whose secret isn't the last next key.
        let u = decode(s(&list(&d)[0], "token"), GRANT_SIZE_DEFAULT, 32).unwrap();
        let mut wrong = u.clone();
        wrong.proof = Proof::NextSecret(seed(1));
        assert!(wrong.verify(&key).is_err());
        u.verify(&key).unwrap();
        // Padding is optional, but must be right when present.
        let unpadded = sealed.trim_end_matches('=');
        decode(unpadded, GRANT_SIZE_DEFAULT, 32)
            .unwrap()
            .verify(&key)
            .unwrap();
        assert!(decode(&format!("{unpadded}=="), GRANT_SIZE_DEFAULT, 32).is_err());
    }

    #[test]
    fn base64url_strict() {
        assert_eq!(base64url(b"\xfb\xff"), "-_8");
        assert_eq!(base64url_decode("-_8").unwrap(), b"\xfb\xff");
        assert!(base64url_decode("-_9").is_none());
        assert!(base64url_decode("A").is_none());
        assert!(base64url_decode("AA+/").is_none());
        assert_eq!(base64url_decode("").unwrap(), b"");
    }

    /// A root-only token whose authority `Block` is the minted one with
    /// `extra` appended, properly signed.
    fn with_extra(extra: &[u8]) -> String {
        let mut data = encode_block(&json::canonical_string(&v(ROOT)), &mut Vec::new());
        data.extend_from_slice(extra);
        let raw = sign_block(
            &SigningKey::from_bytes(&seed(0)),
            data,
            public_key(&seed(0x40)),
            None,
        );
        encode_token(&[raw], &seed(0x40))
    }

    #[test]
    fn block_fields() {
        let key = public_key(&seed(0));
        // An empty context is accepted (biscuit-go writes one).
        let t = with_extra(&[0x12, 0x00]);
        decode(&t, GRANT_SIZE_DEFAULT, 32)
            .unwrap()
            .verify(&key)
            .unwrap();
        // A context twice, a second Datalog version, an unknown field, a
        // fixed64 field: refused.
        for extra in [
            &[0x12, 0x00, 0x12, 0x00][..],
            &[0x18, 0x04],
            &[0x48, 0x01],
            &[0x09, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0x0a],
        ] {
            assert!(
                decode(&with_extra(extra), GRANT_SIZE_DEFAULT, 32).is_err(),
                "{extra:?}"
            );
        }
        // A Datalog version Biscuit 3 doesn't define.
        let mut data = encode_block(&json::canonical_string(&v(ROOT)), &mut Vec::new());
        let at = data.windows(2).position(|w| w == [0x18, 0x03]).unwrap();
        data[at + 1] = 7;
        let raw = sign_block(
            &SigningKey::from_bytes(&seed(0)),
            data,
            public_key(&seed(0x40)),
            None,
        );
        assert!(decode(&encode_token(&[raw], &seed(0x40)), GRANT_SIZE_DEFAULT, 32).is_err());
    }
}
