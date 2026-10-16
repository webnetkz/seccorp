//! Multi-pattern matcher.
//!
//! All patterns of a set are searched in one pass over the data:
//!
//! * literal patterns are fed directly into an Aho-Corasick automaton;
//! * wildcard / jump patterns contribute an *atom* (fixed byte run) to the
//!   automaton; when the atom is found, the full pattern is verified with an
//!   anchored byte regex at the possible start positions only;
//! * patterns without a usable atom fall back to one full regex search;
//! * patterns pinned to a single offset are checked directly.
//!
//! Regexes are compiled lazily on first use, so databases with hundreds of
//! thousands of signatures load quickly.

use super::hex::{Atom, HexToken, as_literal, extract_atom, tokens_to_regex};
use crate::filetype::FileType;
use aho_corasick::{AhoCorasick, MatchKind};
use regex::bytes::{Regex, RegexBuilder};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

/// Maximum anchored verifications per pattern and buffer before switching
/// to a single full search.
const MAX_VERIFICATIONS: u32 = 512;
/// Maximum distance window for anchored verification.
const MAX_WINDOW: usize = 256;

/// Where a match may start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OffsetConstraint {
    #[default]
    Any,
    /// Start within `start ..= start + len`.
    Absolute { start: u64, len: u64 },
    /// Start within `size - back ..= size - back + len`.
    FromEnd { back: u64, len: u64 },
    /// Start within `ep + delta ..= ep + delta + len` (`ep` = entry point file offset).
    EntryPoint { delta: i64, len: u64 },
}

impl OffsetConstraint {
    /// Absolute start window for a buffer, `None` = unconstrained,
    /// `Some(None)` = cannot match in this buffer.
    fn window(&self, ctx: &ScanContext, size: usize) -> Option<Option<(u64, u64)>> {
        let size = size as u64;
        match *self {
            OffsetConstraint::Any => None,
            OffsetConstraint::Absolute { start, len } => Some(Some((start, start.saturating_add(len)))),
            OffsetConstraint::FromEnd { back, len } => Some(size.checked_sub(back).map(|s| (s, s.saturating_add(len)))),
            OffsetConstraint::EntryPoint { delta, len } => Some(ctx.entry_point.and_then(|ep| {
                let s = ep as i64 + delta;
                (s >= 0).then(|| (s as u64, (s as u64).saturating_add(len)))
            })),
        }
    }
}

/// File type filter (mirrors ClamAV target types).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TargetFilter {
    #[default]
    Any,
    Pe,
    Ole2,
    Html,
    Mail,
    Image,
    Elf,
    Text,
    MachO,
    Pdf,
    Java,
}

impl TargetFilter {
    /// Maps a ClamAV target type number. Unsupported targets return `None`.
    pub fn from_clamav(t: u32) -> Option<TargetFilter> {
        Some(match t {
            0 => TargetFilter::Any,
            1 => TargetFilter::Pe,
            2 => TargetFilter::Ole2,
            3 => TargetFilter::Html,
            4 => TargetFilter::Mail,
            5 => TargetFilter::Image,
            6 => TargetFilter::Elf,
            7 => TargetFilter::Text,
            9 => TargetFilter::MachO,
            10 => TargetFilter::Pdf,
            12 => TargetFilter::Java,
            _ => return None,
        })
    }

    pub fn matches(self, ft: FileType) -> bool {
        match self {
            TargetFilter::Any => true,
            TargetFilter::Pe => ft == FileType::Pe,
            TargetFilter::Ole2 => ft == FileType::Ole2,
            TargetFilter::Html => matches!(ft, FileType::Html | FileType::Text | FileType::Script),
            TargetFilter::Mail => matches!(ft, FileType::Text),
            TargetFilter::Image => ft == FileType::Image,
            TargetFilter::Elf => ft == FileType::Elf,
            TargetFilter::Text => ft.is_textual(),
            TargetFilter::MachO => ft == FileType::MachO,
            TargetFilter::Pdf => ft == FileType::Pdf,
            TargetFilter::Java => matches!(ft, FileType::JavaClass | FileType::Zip),
        }
    }

    /// Text targets are matched against a normalized (lower-cased) buffer.
    pub fn is_normalized_text(self) -> bool {
        matches!(self, TargetFilter::Html | TargetFilter::Text | TargetFilter::Mail)
    }
}

/// Per-buffer information used to resolve offsets and filters.
#[derive(Debug, Clone, Copy)]
pub struct ScanContext {
    pub file_type: FileType,
    /// File offset of the executable entry point, when known.
    pub entry_point: Option<u64>,
}

/// Pattern definition passed to the builder.
#[derive(Debug, Clone)]
pub enum PatternSpec {
    Literal {
        bytes: Vec<u8>,
        nocase: bool,
    },
    Hex(Vec<HexToken>),
    /// A regex body in Rust `regex` syntax (YARA regexes are compatible).
    Regex {
        source: String,
        nocase: bool,
        dotall: bool,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct PatternOptions {
    pub constraint: OffsetConstraint,
    pub target: TargetFilter,
    pub fullword: bool,
    /// Stop collecting after this many matches (1 = existence only).
    pub max_matches: u32,
}

impl Default for PatternOptions {
    fn default() -> Self {
        PatternOptions { constraint: OffsetConstraint::Any, target: TargetFilter::Any, fullword: false, max_matches: 1 }
    }
}

enum Kind {
    Literal { len: usize },
    Regex { body: String, flags: &'static str, atom: Option<Atom>, unanchored: OnceLock<Option<Regex>>, anchored: OnceLock<Option<Regex>> },
}

struct Compiled {
    tag: u32,
    kind: Kind,
    opts: PatternOptions,
}

impl Compiled {
    fn regex(&self, anchored: bool) -> Option<&Regex> {
        let Kind::Regex { body, flags, unanchored, anchored: anch, .. } = &self.kind else {
            return None;
        };
        let cell = if anchored { anch } else { unanchored };
        cell.get_or_init(|| {
            let src = if anchored { format!("(?{flags})^(?:{body})") } else { format!("(?{flags}){body}") };
            match RegexBuilder::new(&src).unicode(false).size_limit(64 << 20).dfa_size_limit(8 << 20).build() {
                Ok(r) => Some(r),
                Err(e) => {
                    log::warn!("pattern {} disabled: {e}", self.tag);
                    None
                }
            }
        })
        .as_ref()
    }
}

/// Builder for [`PatternSet`].
#[derive(Default)]
pub struct PatternSetBuilder {
    patterns: Vec<Compiled>,
    literals: Vec<(u32, Vec<u8>, bool)>,
}

impl PatternSetBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Adds a pattern and returns its id within the set.
    pub fn add(&mut self, tag: u32, spec: PatternSpec, opts: PatternOptions) -> Result<u32, String> {
        let kind = match spec {
            PatternSpec::Literal { bytes, nocase } => {
                if bytes.is_empty() {
                    return Err("empty literal".into());
                }
                let len = bytes.len();
                self.patterns.push(Compiled { tag, kind: Kind::Literal { len }, opts });
                let id = (self.patterns.len() - 1) as u32;
                self.literals.push((id, bytes, nocase));
                return Ok(id);
            }
            PatternSpec::Hex(tokens) => {
                if let Some(bytes) = as_literal(&tokens) {
                    return self.add(tag, PatternSpec::Literal { bytes, nocase: false }, opts);
                }
                Kind::Regex {
                    body: tokens_to_regex(&tokens),
                    flags: "s-u",
                    atom: extract_atom(&tokens),
                    unanchored: OnceLock::new(),
                    anchored: OnceLock::new(),
                }
            }
            PatternSpec::Regex { source, nocase, dotall } => {
                // Validate eagerly: user supplied regexes are few.
                let flags = match (nocase, dotall) {
                    (true, true) => "is-u",
                    (true, false) => "i-u",
                    (false, true) => "s-u",
                    (false, false) => "-u",
                };
                RegexBuilder::new(&format!("(?{flags}){source}"))
                    .unicode(false)
                    .size_limit(64 << 20)
                    .build()
                    .map_err(|e| format!("invalid regex: {e}"))?;
                Kind::Regex { body: source, flags, atom: None, unanchored: OnceLock::new(), anchored: OnceLock::new() }
            }
        };
        self.patterns.push(Compiled { tag, kind, opts });
        Ok((self.patterns.len() - 1) as u32)
    }

    pub fn build(self) -> PatternSet {
        PatternSet::from_builder(self)
    }
}

// Literal byte strings are kept aside until build time.
impl PatternSetBuilder {
    #[allow(clippy::type_complexity)]
    fn take_literals(&mut self) -> Vec<(u32, Vec<u8>, bool)> {
        std::mem::take(&mut self.literals)
    }
}

/// Compiled multi-pattern matcher. Cheap to share between threads.
pub struct PatternSet {
    patterns: Vec<Compiled>,
    ac_cs: Option<AhoCorasick>,
    ac_ci: Option<AhoCorasick>,
    users_cs: Vec<Vec<u32>>,
    users_ci: Vec<Vec<u32>>,
    positional: Vec<u32>,
    always: Vec<u32>,
}

impl Default for PatternSet {
    fn default() -> Self {
        PatternSetBuilder::new().build()
    }
}

/// Matches of one scan: pattern id → `(offset, length)` list.
#[derive(Debug, Default)]
pub struct PatternMatches {
    hits: HashMap<u32, Vec<(u64, u32)>>,
}

impl PatternMatches {
    pub fn get(&self, id: u32) -> &[(u64, u32)] {
        self.hits.get(&id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn is_match(&self, id: u32) -> bool {
        self.hits.get(&id).is_some_and(|v| !v.is_empty())
    }

    /// Ids of all matched patterns.
    pub fn matched(&self) -> impl Iterator<Item = u32> + '_ {
        self.hits.iter().filter(|(_, v)| !v.is_empty()).map(|(k, _)| *k)
    }

    pub fn is_empty(&self) -> bool {
        self.matched().next().is_none()
    }
}

#[derive(Default)]
struct PatState {
    hits: Vec<(u64, u32)>,
    full_done: bool,
    verifications: u32,
    checked: Option<HashSet<u64>>,
}

impl PatternSet {
    fn from_builder(mut b: PatternSetBuilder) -> PatternSet {
        let literals = b.take_literals();
        let mut literal_bytes: HashMap<u32, (Vec<u8>, bool)> =
            literals.into_iter().map(|(id, bytes, nocase)| (id, (bytes, nocase))).collect();

        let mut atoms_cs: Vec<Vec<u8>> = Vec::new();
        let mut atoms_ci: Vec<Vec<u8>> = Vec::new();
        let mut index_cs: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut index_ci: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut users_cs: Vec<Vec<u32>> = Vec::new();
        let mut users_ci: Vec<Vec<u32>> = Vec::new();
        let mut positional = Vec::new();
        let mut always = Vec::new();

        let mut register = |bytes: Vec<u8>, nocase: bool, id: u32| {
            let (atoms, index, users) =
                if nocase { (&mut atoms_ci, &mut index_ci, &mut users_ci) } else { (&mut atoms_cs, &mut index_cs, &mut users_cs) };
            let key = if nocase { bytes.to_ascii_lowercase() } else { bytes };
            let slot = *index.entry(key.clone()).or_insert_with(|| {
                atoms.push(key);
                users.push(Vec::new());
                atoms.len() - 1
            });
            users[slot].push(id);
        };

        for (i, p) in b.patterns.iter().enumerate() {
            let id = i as u32;
            let single_position = matches!(
                p.opts.constraint,
                OffsetConstraint::Absolute { len: 0, .. }
                    | OffsetConstraint::FromEnd { len: 0, .. }
                    | OffsetConstraint::EntryPoint { len: 0, .. }
            );
            match &p.kind {
                Kind::Literal { .. } => {
                    let (bytes, nocase) = literal_bytes.remove(&id).expect("literal bytes");
                    if single_position && !nocase {
                        // Store as a 1-token "regex" is unnecessary: positional
                        // check compares bytes directly.
                        positional.push(id);
                        literal_bytes.insert(id, (bytes, nocase));
                    } else {
                        register(bytes, nocase, id);
                    }
                }
                Kind::Regex { atom, .. } => {
                    if single_position {
                        positional.push(id);
                    } else if let Some(a) = atom {
                        register(a.bytes.clone(), false, id);
                    } else {
                        always.push(id);
                    }
                }
            }
        }

        // Positional literals keep their bytes for direct comparison.
        let mut patterns = b.patterns;
        for (id, (bytes, _)) in literal_bytes {
            let p = &mut patterns[id as usize];
            p.kind = Kind::Regex {
                body: tokens_to_regex(&bytes.iter().map(|b| HexToken::Byte(*b)).collect::<Vec<_>>()),
                flags: "s-u",
                atom: None,
                unanchored: OnceLock::new(),
                anchored: OnceLock::new(),
            };
        }

        let build_ac = |atoms: &[Vec<u8>], nocase: bool| -> Option<AhoCorasick> {
            if atoms.is_empty() {
                return None;
            }
            match AhoCorasick::builder().match_kind(MatchKind::Standard).ascii_case_insensitive(nocase).build(atoms) {
                Ok(ac) => Some(ac),
                Err(e) => {
                    log::error!("failed to build pattern automaton: {e}");
                    None
                }
            }
        };

        PatternSet { ac_cs: build_ac(&atoms_cs, false), ac_ci: build_ac(&atoms_ci, true), patterns, users_cs, users_ci, positional, always }
    }

    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Tag supplied when the pattern was added.
    pub fn tag(&self, id: u32) -> u32 {
        self.patterns[id as usize].tag
    }

    /// Searches all patterns in `data`.
    pub fn scan(&self, data: &[u8], ctx: &ScanContext) -> PatternMatches {
        let mut state: HashMap<u32, PatState> = HashMap::new();

        for &id in &self.positional {
            let p = &self.patterns[id as usize];
            if !p.opts.target.matches(ctx.file_type) {
                continue;
            }
            if let Some(Some((pos, _))) = p.opts.constraint.window(ctx, data.len())
                && (pos as usize) < data.len()
            {
                self.verify_at(id, data, pos as usize, ctx, &mut state);
            }
        }

        if let Some(ac) = &self.ac_cs {
            for m in ac.find_overlapping_iter(data) {
                for &id in &self.users_cs[m.pattern().as_usize()] {
                    self.on_atom(id, data, m.start(), m.end(), ctx, &mut state);
                }
            }
        }
        if let Some(ac) = &self.ac_ci {
            for m in ac.find_overlapping_iter(data) {
                for &id in &self.users_ci[m.pattern().as_usize()] {
                    self.on_atom(id, data, m.start(), m.end(), ctx, &mut state);
                }
            }
        }

        for &id in &self.always {
            if self.patterns[id as usize].opts.target.matches(ctx.file_type) {
                self.full_search(id, data, ctx, &mut state);
            }
        }

        PatternMatches { hits: state.into_iter().filter(|(_, s)| !s.hits.is_empty()).map(|(k, s)| (k, s.hits)).collect() }
    }

    fn start_allowed(p: &Compiled, ctx: &ScanContext, size: usize, start: u64) -> bool {
        match p.opts.constraint.window(ctx, size) {
            None => true,
            Some(None) => false,
            Some(Some((lo, hi))) => start >= lo && start <= hi,
        }
    }

    fn fullword_ok(data: &[u8], start: usize, end: usize) -> bool {
        let before = start.checked_sub(1).and_then(|i| data.get(i));
        let after = data.get(end);
        !before.is_some_and(|b| b.is_ascii_alphanumeric()) && !after.is_some_and(|b| b.is_ascii_alphanumeric())
    }

    fn record(p: &Compiled, st: &mut PatState, start: u64, len: u32) {
        if st.hits.len() < p.opts.max_matches as usize && !st.hits.iter().any(|h| h.0 == start) {
            st.hits.push((start, len));
        }
    }

    fn on_atom(&self, id: u32, data: &[u8], astart: usize, aend: usize, ctx: &ScanContext, state: &mut HashMap<u32, PatState>) {
        let p = &self.patterns[id as usize];
        if let Some(st) = state.get(&id)
            && (st.full_done || st.hits.len() >= p.opts.max_matches as usize)
        {
            return;
        }
        if !p.opts.target.matches(ctx.file_type) {
            return;
        }
        match &p.kind {
            Kind::Literal { len } => {
                debug_assert_eq!(aend - astart, *len);
                if p.opts.fullword && !Self::fullword_ok(data, astart, aend) {
                    return;
                }
                if !Self::start_allowed(p, ctx, data.len(), astart as u64) {
                    return;
                }
                let st = state.entry(id).or_default();
                Self::record(p, st, astart as u64, *len as u32);
            }
            Kind::Regex { atom: Some(atom), .. } => {
                let Some(max) = atom.before_max else {
                    self.full_search(id, data, ctx, state);
                    return;
                };
                if astart < atom.before_min {
                    return;
                }
                if max - atom.before_min > MAX_WINDOW {
                    self.full_search(id, data, ctx, state);
                    return;
                }
                let hi = astart - atom.before_min;
                let lo = astart.saturating_sub(max);
                for s in lo..=hi {
                    let st = state.entry(id).or_default();
                    if st.full_done || st.hits.len() >= p.opts.max_matches as usize {
                        return;
                    }
                    if st.verifications >= MAX_VERIFICATIONS {
                        self.full_search(id, data, ctx, state);
                        return;
                    }
                    let checked = st.checked.get_or_insert_with(HashSet::new);
                    if !checked.insert(s as u64) {
                        continue;
                    }
                    if Self::start_allowed(p, ctx, data.len(), s as u64) {
                        self.verify_at(id, data, s, ctx, state);
                    }
                }
            }
            Kind::Regex { atom: None, .. } => self.full_search(id, data, ctx, state),
        }
    }

    fn verify_at(&self, id: u32, data: &[u8], start: usize, _ctx: &ScanContext, state: &mut HashMap<u32, PatState>) {
        let p = &self.patterns[id as usize];
        let st = state.entry(id).or_default();
        st.verifications += 1;
        let Some(re) = p.regex(true) else { return };
        if let Some(m) = re.find(&data[start..]) {
            let end = start + m.end();
            if p.opts.fullword && !Self::fullword_ok(data, start, end) {
                return;
            }
            Self::record(p, st, start as u64, m.len() as u32);
        }
    }

    fn full_search(&self, id: u32, data: &[u8], ctx: &ScanContext, state: &mut HashMap<u32, PatState>) {
        let p = &self.patterns[id as usize];
        let st = state.entry(id).or_default();
        if st.full_done {
            return;
        }
        st.full_done = true;
        st.hits.clear();
        let Some(re) = p.regex(false) else { return };
        for m in re.find_iter(data) {
            if p.opts.fullword && !Self::fullword_ok(data, m.start(), m.end()) {
                continue;
            }
            if !Self::start_allowed(p, ctx, data.len(), m.start() as u64) {
                continue;
            }
            Self::record(p, st, m.start() as u64, m.len() as u32);
            if st.hits.len() >= p.opts.max_matches as usize {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::hex::{parse_clamav_hex, parse_yara_hex};
    use super::*;

    fn ctx() -> ScanContext {
        ScanContext { file_type: FileType::Unknown, entry_point: None }
    }

    #[test]
    fn literal_and_nocase() {
        let mut b = PatternSetBuilder::new();
        let a = b
            .add(
                1,
                PatternSpec::Literal { bytes: b"Hello".to_vec(), nocase: false },
                PatternOptions { max_matches: 10, ..Default::default() },
            )
            .unwrap();
        let c = b.add(2, PatternSpec::Literal { bytes: b"WORLD".to_vec(), nocase: true }, PatternOptions::default()).unwrap();
        let set = b.build();
        let m = set.scan(b"xx Hello world Hello", &ctx());
        assert_eq!(m.get(a), &[(3, 5), (15, 5)]);
        assert!(m.is_match(c));
        assert_eq!(set.tag(c), 2);
    }

    #[test]
    fn hex_with_atom_and_jumps() {
        let mut b = PatternSetBuilder::new();
        let id = b.add(7, PatternSpec::Hex(parse_yara_hex("?? 11 22 33 [1-3] 44").unwrap()), PatternOptions::default()).unwrap();
        let set = b.build();
        assert!(set.scan(&[0, 9, 0x11, 0x22, 0x33, 0, 0, 0x44, 0], &ctx()).is_match(id));
        assert!(!set.scan(&[0, 9, 0x11, 0x22, 0x33, 0, 0, 0, 0, 0x44], &ctx()).is_match(id));
        // Atom at the very start of the buffer: the "??" cannot match before offset 0.
        assert!(!set.scan(&[0x11, 0x22, 0x33, 0, 0x44], &ctx()).is_match(id));
    }

    #[test]
    fn unbounded_jump_uses_full_search() {
        let mut b = PatternSetBuilder::new();
        let id = b.add(1, PatternSpec::Hex(parse_clamav_hex("aabb*ccdd").unwrap()), PatternOptions::default()).unwrap();
        let set = b.build();
        let mut data = vec![0u8; 5000];
        data[10] = 0xaa;
        data[11] = 0xbb;
        data[4000] = 0xcc;
        data[4001] = 0xdd;
        assert!(set.scan(&data, &ctx()).is_match(id));
    }

    #[test]
    fn offset_constraints() {
        let mut b = PatternSetBuilder::new();
        let at0 = b
            .add(
                1,
                PatternSpec::Literal { bytes: b"MZ".to_vec(), nocase: false },
                PatternOptions { constraint: OffsetConstraint::Absolute { start: 0, len: 0 }, ..Default::default() },
            )
            .unwrap();
        let tail = b
            .add(
                2,
                PatternSpec::Hex(parse_clamav_hex("ee??ff").unwrap()),
                PatternOptions { constraint: OffsetConstraint::FromEnd { back: 3, len: 0 }, ..Default::default() },
            )
            .unwrap();
        let range = b
            .add(
                3,
                PatternSpec::Literal { bytes: b"XYZ".to_vec(), nocase: false },
                PatternOptions { constraint: OffsetConstraint::Absolute { start: 4, len: 2 }, ..Default::default() },
            )
            .unwrap();
        let set = b.build();
        let m = set.scan(b"MZ..XYZ.....\xee\x00\xff", &ctx());
        assert!(m.is_match(at0));
        assert!(m.is_match(tail));
        assert!(m.is_match(range));
        let m = set.scan(b".MZ.......XYZ\xee\x00\xff.", &ctx());
        assert!(!m.is_match(at0));
        assert!(!m.is_match(tail));
        assert!(!m.is_match(range));
    }

    #[test]
    fn fullword_and_regex() {
        let mut b = PatternSetBuilder::new();
        let fw = b
            .add(
                1,
                PatternSpec::Literal { bytes: b"cat".to_vec(), nocase: false },
                PatternOptions { fullword: true, max_matches: 10, ..Default::default() },
            )
            .unwrap();
        let rx = b
            .add(
                2,
                PatternSpec::Regex { source: r"id=[0-9]{3,}".into(), nocase: false, dotall: false },
                PatternOptions { max_matches: 10, ..Default::default() },
            )
            .unwrap();
        let set = b.build();
        let m = set.scan(b"concatenate cat; id=12 id=12345", &ctx());
        assert_eq!(m.get(fw), &[(12, 3)]);
        assert_eq!(m.get(rx), &[(23, 8)]);
    }

    #[test]
    fn target_filter() {
        let mut b = PatternSetBuilder::new();
        let id = b
            .add(
                1,
                PatternSpec::Literal { bytes: b"abc".to_vec(), nocase: false },
                PatternOptions { target: TargetFilter::Pe, ..Default::default() },
            )
            .unwrap();
        let set = b.build();
        assert!(!set.scan(b"abc", &ctx()).is_match(id));
        assert!(set.scan(b"abc", &ScanContext { file_type: FileType::Pe, entry_point: None }).is_match(id));
    }
}
