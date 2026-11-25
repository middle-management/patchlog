//! `patchlog-grant`: make, attenuate and inspect patchlog grants, Biscuit v3
//! tokens in the form of Addendum C §C.8. Native only; not part of the
//! Worker build.
//!
//! ```text
//! patchlog-grant keygen [--seed <64 hex>]
//! patchlog-grant mint --seed <64 hex> --root '<json>' [--block '<json>']...
//! patchlog-grant attenuate --token <token> --block '<json>' [--block '<json>']...
//! patchlog-grant inspect --token <token> [--pub <base64url>]
//! ```

use patchlog_core::grant;
use patchlog_core::json::{self, Value};
use std::collections::BTreeMap;
use std::process::ExitCode;

const USAGE: &str = "usage:
  patchlog-grant keygen [--seed <64 hex>]
      prints { \"seed\": <hex>, \"pub\": <base64url> } (a random seed if none is given)
  patchlog-grant mint --seed <64 hex> --root '<json>' [--block '<json>']...
      prints a grant: the root block signed by the key of --seed, then each
      narrowing block; next keys are random
  patchlog-grant attenuate --token <token> --block '<json>' [--block '<json>']...
      prints the token with the narrowing blocks appended
  patchlog-grant inspect --token <token> [--pub <base64url>]
      prints the blocks, grant id, revocation ids and stored form (base64url);
      with --pub, also verifies the signatures under that root key";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(out) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("patchlog-grant: {e}");
            if e.contains("usage") || e.starts_with("unexpected argument") {
                eprintln!("{USAGE}");
            }
            ExitCode::FAILURE
        }
    }
}

/// `--name value` options, each possibly repeated.
fn options(args: &[String], allowed: &[&str]) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let Some(name) = a.strip_prefix("--").filter(|n| allowed.contains(n)) else {
            return Err(format!("unexpected argument {a:?}"));
        };
        let Some(v) = it.next() else {
            return Err(format!("--{name} needs a value"));
        };
        out.entry(name.to_string()).or_default().push(v.clone());
    }
    Ok(out)
}

fn one<'a>(o: &'a BTreeMap<String, Vec<String>>, name: &str) -> Result<Option<&'a str>, String> {
    match o.get(name).map(Vec::as_slice) {
        None => Ok(None),
        Some([v]) => Ok(Some(v)),
        Some(_) => Err(format!("--{name} given twice")),
    }
}

fn required<'a>(o: &'a BTreeMap<String, Vec<String>>, name: &str) -> Result<&'a str, String> {
    one(o, name)?.ok_or_else(|| format!("--{name} is required"))
}

fn parse_seed(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("--seed is 64 hex digits".into());
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn random_seed() -> Result<[u8; 32], String> {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).map_err(|e| format!("no randomness: {e}"))?;
    Ok(s)
}

fn parse_json(what: &str, s: &str) -> Result<Value, String> {
    json::parse(s.as_bytes()).map_err(|e| format!("{what}: {e}"))
}

fn string(s: impl Into<String>) -> Value {
    Value::String(s.into())
}

fn object(members: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Object(
        members
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

fn run(args: &[String]) -> Result<String, String> {
    let Some((cmd, rest)) = args.split_first() else {
        return Err("usage".into());
    };
    match cmd.as_str() {
        "keygen" => {
            let o = options(rest, &["seed"])?;
            let seed = match one(&o, "seed")? {
                Some(s) => parse_seed(s)?,
                None => random_seed()?,
            };
            let out = object([
                ("seed", string(hex(&seed))),
                ("pub", string(grant::base64url(&grant::public_key(&seed)))),
            ]);
            Ok(json::canonical_string(&out))
        }
        "mint" => {
            let o = options(rest, &["seed", "root", "block"])?;
            let seed = parse_seed(required(&o, "seed")?)?;
            let root = parse_json("--root", required(&o, "root")?)?;
            let blocks = o
                .get("block")
                .into_iter()
                .flatten()
                .map(|b| parse_json("--block", b))
                .collect::<Result<Vec<_>, _>>()?;
            let mut err = None;
            let token = grant::mint(&seed, &root, &blocks, |_| {
                random_seed().unwrap_or_else(|e| {
                    err = Some(e);
                    [0; 32]
                })
            });
            if let Some(e) = err {
                return Err(e);
            }
            token.map_err(|e| e.to_string())
        }
        "attenuate" => {
            let o = options(rest, &["token", "block"])?;
            let mut token = required(&o, "token")?.trim().to_string();
            let blocks = o.get("block").ok_or("--block is required")?;
            for b in blocks {
                let b = parse_json("--block", b)?;
                token = grant::attenuate(&token, &b, &random_seed()?).map_err(|e| e.to_string())?;
            }
            Ok(token)
        }
        "inspect" => {
            let o = options(rest, &["token", "pub"])?;
            let token = required(&o, "token")?.trim();
            let u = grant::decode(token, u64::MAX, u64::MAX).map_err(|e| e.to_string())?;
            let mut out = vec![
                ("kid", string(u.kid())),
                ("root", u.root().clone()),
                ("narrowing", Value::Array(u.narrowing().to_vec())),
                ("id", string(u.id().text())),
                (
                    "revocationIds",
                    Value::Array(
                        u.revocation_ids()
                            .iter()
                            .map(|i| string(i.text()))
                            .collect(),
                    ),
                ),
                ("stored", string(grant::base64url(u.stored()))),
                ("sealed", Value::Bool(u.is_sealed())),
            ];
            if let Some(p) = one(&o, "pub")? {
                let key = grant::decode_pub(p).ok_or("--pub is 43 characters of base64url")?;
                let g = u.verify(&key).map_err(|e| e.to_string())?;
                out.push(("verified", Value::Bool(true)));
                out.push((
                    "via",
                    Value::Array(g.via().into_iter().map(string).collect()),
                ));
            }
            let size = token.strip_prefix("biscuit:").unwrap_or(token);
            let size = size.trim_end_matches('=').len() * 3 / 4;
            out.push(("size", Value::Number(size as f64)));
            Ok(json::canonical_string(&object(out)))
        }
        "help" | "--help" | "-h" => Ok(USAGE.to_string()),
        _ => Err(format!("unknown command {cmd:?}; usage")),
    }
}
