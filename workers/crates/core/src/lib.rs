//! Platform-neutral core of patchlog (../docs/SPEC.md): I-JSON input and
//! canonical JSON (§3.1), ids (§3.2–§3.5, §3.7), names (§3.6), JSON Patch
//! with the `writes` of §6.4.1, the limits of §6.6, and the steps of a write
//! that need no storage (§6.2). No I/O, so it builds natively for tests and
//! benchmarks and to wasm32 for the Worker.

pub mod blob;
pub mod fmt;
pub mod gate;
pub mod id;
pub mod json;
pub mod limits;
pub mod names;
pub mod patch;
pub mod rules;
pub mod schema;

pub use id::Id;
pub use json::Value;
