//! # SecCorp scanning engine
//!
//! Platform-independent malware scanning core used by every SecCorp build
//! (Windows, macOS, Android, iOS) and by the command-line tools.
//!
//! Detection layers, from cheapest to most expensive:
//!
//! 1. **Hash signatures** – SHA-256 / SHA-1 / MD5 exact matches (own format,
//!    ClamAV `.hdb/.hsb`, MalwareBazaar exports, plain hash lists).
//! 2. **Body signatures** – byte patterns with wildcards and jumps (ClamAV
//!    `.ndb`), matched in a single pass with Aho-Corasick atoms + lazy
//!    regex verification.
//! 3. **Rules** – a YARA-compatible rule language subset (`.yar`).
//! 4. **Heuristics** – structural analysis of executables, documents,
//!    scripts, archives and file names that produces a risk score.
//!
//! Archives (ZIP/APK/JAR/OOXML, GZIP, TAR) are unpacked recursively in
//! memory with decompression-bomb protection.

pub mod analyzers;
pub mod archive;
pub mod cache;
pub mod config;
pub mod engine;
pub mod error;
pub mod filetype;
pub mod hashing;
pub mod patterns;
pub mod quarantine;
#[cfg(feature = "realtime")]
pub mod realtime;
pub mod report;
pub mod rules;
pub mod scanner;
pub mod sigdb;
pub mod update;
pub mod util;

pub use config::{HeuristicLevel, ScanOptions};
pub use engine::Engine;
pub use error::{Error, Result};
pub use report::{Detection, DetectionKind, FileVerdict, ScanSummary, Severity, Verdict};
pub use scanner::{ScanControl, ScanEvent, ScanProgress};
pub use sigdb::{DbInfo, SignatureDb};

/// Version of the scanning engine (also used for update compatibility checks).
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
