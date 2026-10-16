//! Byte pattern parsing and multi-pattern matching.

pub mod hex;
mod set;

pub use hex::{Atom, HexToken, extract_atom, parse_clamav_hex, parse_yara_hex, tokens_to_regex};
pub use set::{OffsetConstraint, PatternMatches, PatternOptions, PatternSet, PatternSetBuilder, PatternSpec, ScanContext, TargetFilter};
