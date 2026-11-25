//! CPU per write and per read of the platform-neutral path, by document size.
//!
//!     cargo run --release -p patchlog-bench
//!     cargo build --release -p patchlog-bench --target wasm32-wasip1 && node bench/wasi.mjs
//!
//! A write here is what the namespace Durable Object does in wasm besides
//! SQLite: read the body (I-JSON, canonical form), hash the id, apply the
//! patch to the cached head document, measure the limits, and every 16th
//! write serialise a snapshot. A read miss of a revision serialises the
//! document and hashes it for `Repr-Digest`.

use patchlog_core::fmt::repr_digest;
use patchlog_core::gate::{apply_and_check, id_for, read_body, WriteKind};
use patchlog_core::json::{canonical, parse, Value};
use patchlog_core::limits::Limits;
use std::time::Instant;

fn doc_of(size: usize) -> Value {
    // A list of small records, like a page of blocks or a catalog.
    let mut items = String::new();
    let mut i = 0;
    while items.len() + 64 < size {
        if i > 0 {
            items.push(',');
        }
        items.push_str(&format!(
            r#"{{"id":"b{i}","kind":"para","text":"lorem ipsum dolor {i}","n":{i}}}"#
        ));
        i += 1;
    }
    parse(format!(r#"{{"title":"bench","items":[{items}]}}"#).as_bytes()).unwrap()
}

fn main() {
    let limits = Limits {
        document_size: 4 << 20,
        ..Limits::default()
    };
    let deployment = limits.clone();
    println!("size\twrite_us\tread_us\tserialise_us\twrites_per_cpu_s");
    for size in [512usize, 16 << 10, 256 << 10, 1 << 20, 3 << 19] {
        let mut doc = doc_of(size);
        let actual = canonical(&doc).len();
        let n_items = doc.get("items").unwrap().as_array().unwrap().len();
        let iters = (200_000_000 / actual.max(20_000)).clamp(20, 20_000);
        let mut parent = None;
        let t = Instant::now();
        for i in 0..iters {
            let body = format!(
                r#"[{{"op":"replace","path":"/items/{}/n","value":{}}}]"#,
                i % n_items,
                i + 1_000_000
            );
            let b = read_body(body.as_bytes(), &deployment).unwrap();
            let _ = id_for(parent.as_ref(), &b);
            let p = apply_and_check(parent.as_ref(), doc, &b, WriteKind::Append, &limits).unwrap();
            if i % 16 == 0 {
                std::hint::black_box(canonical(&p.doc));
            }
            parent = Some(p.id);
            doc = p.doc;
        }
        let write_us = t.elapsed().as_secs_f64() * 1e6 / iters as f64;
        let riters = iters.min(5_000);
        let t = Instant::now();
        for _ in 0..riters {
            let bytes = canonical(&doc);
            std::hint::black_box(repr_digest(&bytes));
        }
        let read_us = t.elapsed().as_secs_f64() * 1e6 / riters as f64;
        let t = Instant::now();
        for _ in 0..riters {
            std::hint::black_box(canonical(&doc));
        }
        let ser_us = t.elapsed().as_secs_f64() * 1e6 / riters as f64;
        println!(
            "{actual}\t{write_us:.1}\t{read_us:.1}\t{ser_us:.1}\t{:.0}",
            1e6 / write_us
        );
    }
}
