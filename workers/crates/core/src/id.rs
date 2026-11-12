//! Ids (§3.2–§3.5) and blob ids (§3.7).

use sha2::{Digest, Sha256};
use std::fmt;

/// A 160-bit id: SHA-256 truncated to 20 bytes. Text form `"1" + base32lower`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Id(pub [u8; 20]);

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

impl Id {
    pub fn from_digest(d: &[u8]) -> Id {
        let mut b = [0u8; 20];
        b.copy_from_slice(&d[..20]);
        Id(b)
    }

    /// The 33-character text form.
    pub fn text(&self) -> String {
        let mut s = String::with_capacity(33);
        s.push('1');
        // 160 bits are exactly 32 groups of 5: no padding bits.
        let mut acc: u64 = 0;
        let mut bits = 0;
        for &byte in &self.0 {
            acc = (acc << 8) | byte as u64;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                s.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
            }
        }
        s
    }

    /// Parses the text form strictly: `1`, then exactly 32 of `a–z2–7`.
    pub fn parse(s: &str) -> Option<Id> {
        let b = s.as_bytes();
        if b.len() != 33 || b[0] != b'1' {
            return None;
        }
        let mut out = [0u8; 20];
        let mut acc: u64 = 0;
        let mut bits = 0;
        let mut n = 0;
        for &c in &b[1..] {
            let v = match c {
                b'a'..=b'z' => c - b'a',
                b'2'..=b'7' => c - b'2' + 26,
                _ => return None,
            };
            acc = (acc << 5) | v as u64;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out[n] = (acc >> bits) as u8;
                n += 1;
            }
        }
        Some(Id(out))
    }

    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text())
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text())
    }
}

fn chained(parent: Option<&Id>, body: &[u8]) -> Id {
    let mut h = Sha256::new();
    if let Some(p) = parent {
        h.update(p.0);
    }
    h.update([0x0A]);
    h.update(body);
    Id::from_digest(&h.finalize())
}

/// §3.3: `trunc160(sha256(bytes(parent) ‖ 0x0A ‖ canonical(patches)))`.
pub fn revision_id(parent: Option<&Id>, canonical_patches: &[u8]) -> Id {
    chained(parent, canonical_patches)
}

/// §3.4: `trunc160(sha256(bytes(parent) ‖ 0x0A ‖ "tombstone"))`.
pub fn tombstone_id(parent: &Id) -> Id {
    chained(Some(parent), b"tombstone")
}

/// §3.5: `trunc160(sha256(bytes(prev_ns_id) ‖ 0x0A ‖ canonical(entry)))`.
pub fn ns_id(prev: Option<&Id>, canonical_entry: &[u8]) -> Id {
    chained(prev, canonical_entry)
}

/// §3.7, incrementally: feed the blob's bytes as they arrive.
pub struct BlobHasher(Sha256);

impl BlobHasher {
    /// `type` lowercased without parameters; `nonce` empty or 26 base32 characters.
    pub fn new(media_type: &str, nonce: &str) -> BlobHasher {
        let mut h = Sha256::new();
        h.update(b"patchlog-blob-v1\n");
        h.update(media_type.as_bytes());
        h.update([0x0A]);
        h.update(nonce.as_bytes());
        h.update([0x0A]);
        BlobHasher(h)
    }
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
    pub fn finish(self) -> Id {
        Id::from_digest(&self.0.finalize())
    }
}

pub fn blob_id(media_type: &str, nonce: &str, bytes: &[u8]) -> Id {
    let mut h = BlobHasher::new(media_type, nonce);
    h.update(bytes);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::{canonical, parse};

    fn canon(s: &str) -> Vec<u8> {
        canonical(&parse(s.as_bytes()).unwrap())
    }

    // Addendum I.2
    #[test]
    fn i2_ids() {
        let p1 = canon(r#"[{"op":"add","path":"","value":{"title":"Hello","views":0}}]"#);
        let p2 = canon(r#"[{"op":"replace","path":"/views","value":1}]"#);
        let g = revision_id(None, &p1);
        assert_eq!(g.text(), "1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll");
        assert_eq!(g.hex(), "5e8c8d1cecdd67fd2e5a750b07aa0f91fd4ab16b");
        let c = revision_id(Some(&g), &p2);
        assert_eq!(c.text(), "1sywh54kpo3c4ezn2znktvl3avge4zl5d");
        assert_eq!(c.hex(), "962c7ef14f76c5c265bacb553aaf60a989ccafa3");
        let t = tombstone_id(&c);
        assert_eq!(t.text(), "1idx6u2b3z42obqmwsgmlzvrfuutks2bq");
        assert_eq!(t.hex(), "40efea683bcf34e0c1969198bcd625a526a96830");

        let e1 = canon(r#"{"kind":"config","target":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll"}"#);
        let n1 = ns_id(None, &e1);
        assert_eq!(n1.text(), "1vmctae4vewju6nvxi374rkrkmyzpdrif");
        let e2 = canon(
            r#"{"kind":"head","resource":"derby","target":"1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll"}"#,
        );
        assert_eq!(
            ns_id(Some(&n1), &e2).text(),
            "1pa2nh6iw2yd2djqfy2wrszd5kglfpxvm"
        );
    }

    #[test]
    fn i2_text_forms() {
        assert_eq!(
            Id::parse("1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll")
                .unwrap()
                .text(),
            "1l2gi2hhm3vt72ls2oufqpkqpsh6uvmll"
        );
        for bad in [
            "1L2GI2HHM3VT72LS2OUFQPKQPSH6UVMLL",
            "1l2gi2hhm3vt72ls2oufqpkqpsh6uvml",
            "1l2gi2hhm3vt72ls2oufqpkqpsh6uvml1",
            "1l2gi2hhm3vt72ls2oufqpkqpsh6uvmlla",
            "2l2gi2hhm3vt72ls2oufqpkqpsh6uvmll",
            "l2gi2hhm3vt72ls2oufqpkqpsh6uvmll",
            "",
        ] {
            assert!(Id::parse(bad).is_none(), "{bad}");
        }
        let m = Id::parse("1l2gi2hhm3vt72ls2oufqpkqpsh6uvmlm").unwrap();
        assert_eq!(m.0[19], 0x6c);
    }

    // Addendum I.1: noncharacter neighbours that are accepted, as genesis ids.
    #[test]
    fn i1_genesis_ids() {
        for (t, want) in [
            ("\u{FDCF}", "1sxrx3wwzxwyahs7khilka36c6selzwrb"),
            ("\u{FDF0}", "1jkaabmuivygpelkeuncgmiatzunwp5zw"),
            ("\u{FFFD}", "137ielgcxtgdymhcykw5flzgaml4d6kbx"),
        ] {
            let p = canon(&format!(
                r#"[{{"op":"add","path":"","value":{{"t":"{t}"}}}}]"#
            ));
            assert_eq!(revision_id(None, &p).text(), want);
            let esc = format!("\\u{:04x}", t.chars().next().unwrap() as u32);
            let p = canon(&format!(
                r#"[{{"op":"add","path":"","value":{{"t":"{esc}"}}}}]"#
            ));
            assert_eq!(revision_id(None, &p).text(), want);
        }
    }

    // Addendum I.3
    #[test]
    fn i3_blob_ids() {
        let b = b"hello patchlog\n";
        assert_eq!(
            blob_id("text/plain", "", b).text(),
            "1m5jj344d7tz7cicfmq53ayhmwuubpmyt"
        );
        assert_eq!(
            blob_id("text/plain", "aaaaaaaaaaaaaaaaaaaaaaaaaa", b).text(),
            "1hdwkfub2zymqzgc75snybxosfk67633s"
        );
    }
}
