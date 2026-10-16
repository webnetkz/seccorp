//! Hex signature syntax (ClamAV body signatures and YARA hex strings).
//!
//! Both syntaxes are parsed into the same token list, which is then compiled
//! into a byte regex and an Aho-Corasick "atom" (a run of fixed bytes used to
//! find candidate positions quickly).

use std::fmt::Write as _;

/// Upper bound for bounded jumps; larger jumps are treated as unbounded.
const MAX_BOUNDED_JUMP: usize = 16_384;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexToken {
    /// A fixed byte.
    Byte(u8),
    /// Nibble wildcard: a byte `b` matches when `b & mask == value`.
    Masked { value: u8, mask: u8 },
    /// `??` – any single byte.
    Any,
    /// Jump of `min..=max` arbitrary bytes (`max == None` – unbounded).
    Jump { min: usize, max: Option<usize> },
    /// Alternatives `( AA | BB CC )`.
    Alt(Vec<Vec<HexToken>>),
    /// Any byte except the listed ones (`~AA`, `!(AA|BB)`).
    Not(Vec<u8>),
}

impl HexToken {
    /// Length range in bytes `(min, max)`; `max == None` means unbounded.
    pub fn len_range(&self) -> (usize, Option<usize>) {
        match self {
            HexToken::Byte(_) | HexToken::Masked { .. } | HexToken::Any | HexToken::Not(_) => (1, Some(1)),
            HexToken::Jump { min, max } => (*min, *max),
            HexToken::Alt(alts) => {
                let mut lo = usize::MAX;
                let mut hi = Some(0usize);
                for alt in alts {
                    let (a, b) = seq_len(alt);
                    lo = lo.min(a);
                    hi = match (hi, b) {
                        (Some(x), Some(y)) => Some(x.max(y)),
                        _ => None,
                    };
                }
                (if lo == usize::MAX { 0 } else { lo }, hi)
            }
        }
    }
}

/// Length range of a token sequence.
pub fn seq_len(tokens: &[HexToken]) -> (usize, Option<usize>) {
    let mut lo = 0usize;
    let mut hi = Some(0usize);
    for t in tokens {
        let (a, b) = t.len_range();
        lo = lo.saturating_add(a);
        hi = match (hi, b) {
            (Some(x), Some(y)) => x.checked_add(y),
            _ => None,
        };
    }
    (lo, hi)
}

/// Returns `Some(bytes)` when the sequence consists only of fixed bytes.
pub fn as_literal(tokens: &[HexToken]) -> Option<Vec<u8>> {
    tokens
        .iter()
        .map(|t| match t {
            HexToken::Byte(b) => Some(*b),
            _ => None,
        })
        .collect()
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn pair_token(c1: u8, c2: u8) -> Result<HexToken, String> {
    match (c1, c2) {
        (b'?', b'?') => Ok(HexToken::Any),
        (b'?', lo) => {
            let lo = hex_val(lo).ok_or_else(|| format!("invalid hex digit '{}'", lo as char))?;
            Ok(HexToken::Masked { value: lo, mask: 0x0F })
        }
        (hi, b'?') => {
            let hi = hex_val(hi).ok_or_else(|| format!("invalid hex digit '{}'", hi as char))?;
            Ok(HexToken::Masked { value: hi << 4, mask: 0xF0 })
        }
        (hi, lo) => {
            let h = hex_val(hi).ok_or_else(|| format!("invalid hex digit '{}'", hi as char))?;
            let l = hex_val(lo).ok_or_else(|| format!("invalid hex digit '{}'", lo as char))?;
            Ok(HexToken::Byte((h << 4) | l))
        }
    }
}

fn parse_jump(spec: &str, allow_single: bool) -> Result<HexToken, String> {
    let spec = spec.trim();
    let num = |s: &str| -> Result<usize, String> { s.trim().parse::<usize>().map_err(|_| format!("invalid jump '{spec}'")) };
    let (min, max) = if let Some((a, b)) = spec.split_once('-') {
        let min = if a.trim().is_empty() { 0 } else { num(a)? };
        let max = if b.trim().is_empty() { None } else { Some(num(b)?) };
        (min, max)
    } else if allow_single {
        let n = num(spec)?;
        (n, Some(n))
    } else {
        return Err(format!("invalid jump '{spec}'"));
    };
    if let Some(m) = max
        && m < min
    {
        return Err(format!("invalid jump range '{spec}'"));
    }
    let max = match max {
        Some(m) if m > MAX_BOUNDED_JUMP => None,
        other => other,
    };
    Ok(HexToken::Jump { min, max })
}

// ---------------------------------------------------------------------------
// YARA hex strings
// ---------------------------------------------------------------------------

/// Parses the body of a YARA hex string (text between `{` and `}`).
pub fn parse_yara_hex(src: &str) -> Result<Vec<HexToken>, String> {
    let mut p = YaraHexParser { s: src.as_bytes(), i: 0 };
    let tokens = p.parse_seq(false)?;
    p.skip_ws();
    if p.i != p.s.len() {
        return Err(format!("unexpected '{}' in hex string", p.s[p.i] as char));
    }
    if tokens.is_empty() {
        return Err("empty hex string".into());
    }
    Ok(tokens)
}

struct YaraHexParser<'a> {
    s: &'a [u8],
    i: usize,
}

impl YaraHexParser<'_> {
    fn skip_ws(&mut self) {
        loop {
            while self.i < self.s.len() && self.s[self.i].is_ascii_whitespace() {
                self.i += 1;
            }
            if self.s[self.i..].starts_with(b"//") {
                while self.i < self.s.len() && self.s[self.i] != b'\n' {
                    self.i += 1;
                }
                continue;
            }
            if self.s[self.i..].starts_with(b"/*") {
                match self.s[self.i + 2..].windows(2).position(|w| w == b"*/") {
                    Some(p) => self.i += 2 + p + 2,
                    None => self.i = self.s.len(),
                }
                continue;
            }
            break;
        }
    }

    fn next_pair(&mut self) -> Result<(u8, u8), String> {
        let c1 = *self.s.get(self.i).ok_or("truncated hex byte")?;
        let c2 = *self.s.get(self.i + 1).ok_or("truncated hex byte")?;
        self.i += 2;
        Ok((c1, c2))
    }

    fn parse_seq(&mut self, in_alt: bool) -> Result<Vec<HexToken>, String> {
        let mut out = Vec::new();
        loop {
            self.skip_ws();
            let Some(&c) = self.s.get(self.i) else {
                if in_alt {
                    return Err("unclosed '(' in hex string".into());
                }
                break;
            };
            match c {
                b'|' | b')' if in_alt => break,
                b'(' => {
                    self.i += 1;
                    let mut alts = Vec::new();
                    loop {
                        let alt = self.parse_seq(true)?;
                        if alt.is_empty() {
                            return Err("empty alternative in hex string".into());
                        }
                        alts.push(alt);
                        self.skip_ws();
                        match self.s.get(self.i) {
                            Some(b'|') => self.i += 1,
                            Some(b')') => {
                                self.i += 1;
                                break;
                            }
                            _ => return Err("expected '|' or ')' in hex string".into()),
                        }
                    }
                    out.push(HexToken::Alt(alts));
                }
                b'[' => {
                    let end = self.s[self.i..].iter().position(|&b| b == b']').ok_or("unclosed '[' in hex string")?;
                    let spec = std::str::from_utf8(&self.s[self.i + 1..self.i + end]).map_err(|_| "bad jump")?;
                    out.push(parse_jump(spec, true)?);
                    self.i += end + 1;
                }
                b'~' => {
                    self.i += 1;
                    let (c1, c2) = self.next_pair()?;
                    match pair_token(c1, c2)? {
                        HexToken::Byte(b) => out.push(HexToken::Not(vec![b])),
                        _ => return Err("only '~XX' with a fixed byte is supported".into()),
                    }
                }
                c if c == b'?' || c.is_ascii_hexdigit() => {
                    let (c1, c2) = self.next_pair()?;
                    out.push(pair_token(c1, c2)?);
                }
                other => return Err(format!("unexpected '{}' in hex string", other as char)),
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// ClamAV body signatures
// ---------------------------------------------------------------------------

/// Parses a ClamAV body signature (`.ndb` hex field).
pub fn parse_clamav_hex(src: &str) -> Result<Vec<HexToken>, String> {
    let s: Vec<u8> = src.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let tokens = parse_clamav_seq(&s)?;
    if tokens.is_empty() {
        return Err("empty signature".into());
    }
    Ok(tokens)
}

fn find_closing(s: &[u8], open: u8, close: u8) -> Option<usize> {
    let mut depth = 0usize;
    for (i, &b) in s.iter().enumerate() {
        if b == open {
            depth += 1;
        } else if b == close {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

fn split_top_level(s: &[u8], sep: u8) -> Vec<&[u8]> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (i, &b) in s.iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ if b == sep && depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

fn parse_clamav_seq(s: &[u8]) -> Result<Vec<HexToken>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'*' => {
                out.push(HexToken::Jump { min: 0, max: None });
                i += 1;
            }
            b'{' => {
                let end = s[i..].iter().position(|&b| b == b'}').ok_or("unclosed '{'")? + i;
                let spec = std::str::from_utf8(&s[i + 1..end]).map_err(|_| "bad jump")?;
                out.push(parse_jump(spec, true)?);
                i = end + 1;
            }
            b'[' => {
                let end = s[i..].iter().position(|&b| b == b']').ok_or("unclosed '['")? + i;
                let spec = std::str::from_utf8(&s[i + 1..end]).map_err(|_| "bad jump")?;
                out.push(parse_jump(spec, false)?);
                i = end + 1;
            }
            b'!' => {
                if s.get(i + 1) != Some(&b'(') {
                    return Err("'!' must be followed by '('".into());
                }
                let close = find_closing(&s[i + 1..], b'(', b')').ok_or("unclosed '!('")? + i + 1;
                let inner = &s[i + 2..close];
                let mut bytes = Vec::new();
                for alt in split_top_level(inner, b'|') {
                    match parse_clamav_seq(alt)?.as_slice() {
                        [HexToken::Byte(b)] => bytes.push(*b),
                        _ => return Err("negated alternatives must be single bytes".into()),
                    }
                }
                out.push(HexToken::Not(bytes));
                i = close + 1;
            }
            b'(' => {
                let close = find_closing(&s[i..], b'(', b')').ok_or("unclosed '('")? + i;
                let inner = &s[i + 1..close];
                if matches!(inner, b"B" | b"L" | b"W") {
                    return Err("boundary markers are not supported".into());
                }
                let mut alts = Vec::new();
                for alt in split_top_level(inner, b'|') {
                    let toks = parse_clamav_seq(alt)?;
                    if toks.is_empty() {
                        return Err("empty alternative".into());
                    }
                    alts.push(toks);
                }
                out.push(HexToken::Alt(alts));
                i = close + 1;
            }
            c if c == b'?' || c.is_ascii_hexdigit() => {
                let c2 = *s.get(i + 1).ok_or("truncated hex byte")?;
                out.push(pair_token(c, c2)?);
                i += 2;
            }
            other => return Err(format!("unsupported character '{}'", other as char)),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

fn push_byte(out: &mut String, b: u8) {
    let _ = write!(out, "\\x{b:02X}");
}

/// Compiles a token list into a byte-regex body (without flags/anchors).
/// Use with `(?s-u)` so that `.` matches any byte.
pub fn tokens_to_regex(tokens: &[HexToken]) -> String {
    let mut out = String::with_capacity(tokens.len() * 4);
    write_tokens(&mut out, tokens);
    out
}

fn write_tokens(out: &mut String, tokens: &[HexToken]) {
    for t in tokens {
        match t {
            HexToken::Byte(b) => push_byte(out, *b),
            HexToken::Any => out.push('.'),
            HexToken::Masked { value, mask } => {
                if *mask == 0xF0 {
                    out.push('[');
                    push_byte(out, *value);
                    out.push('-');
                    push_byte(out, *value | 0x0F);
                    out.push(']');
                } else {
                    out.push('[');
                    for b in 0u16..=255 {
                        let b = b as u8;
                        if b & mask == *value {
                            push_byte(out, b);
                        }
                    }
                    out.push(']');
                }
            }
            HexToken::Jump { min, max } => match max {
                Some(m) if *m == *min => {
                    if *m > 0 {
                        let _ = write!(out, ".{{{m}}}");
                    }
                }
                Some(m) => {
                    let _ = write!(out, ".{{{min},{m}}}?");
                }
                None => {
                    let _ = write!(out, ".{{{min},}}?");
                }
            },
            HexToken::Alt(alts) => {
                out.push_str("(?:");
                for (i, alt) in alts.iter().enumerate() {
                    if i > 0 {
                        out.push('|');
                    }
                    write_tokens(out, alt);
                }
                out.push(')');
            }
            HexToken::Not(bytes) => {
                out.push_str("[^");
                for b in bytes {
                    push_byte(out, *b);
                }
                out.push(']');
            }
        }
    }
}

/// A run of fixed bytes inside a pattern plus the distance range between the
/// start of the pattern and the start of the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Atom {
    pub bytes: Vec<u8>,
    pub before_min: usize,
    pub before_max: Option<usize>,
}

impl Atom {
    pub fn window(&self) -> Option<usize> {
        self.before_max.map(|m| m - self.before_min)
    }
}

/// Picks the best atom for prefiltering, or `None` when the pattern has no
/// fixed run of at least two bytes.
pub fn extract_atom(tokens: &[HexToken]) -> Option<Atom> {
    const MAX_ATOM: usize = 32;
    let mut candidates: Vec<Atom> = Vec::new();
    let mut lo = 0usize;
    let mut hi = Some(0usize);
    let mut run: Vec<u8> = Vec::new();
    let mut run_lo = 0usize;
    let mut run_hi = Some(0usize);

    let flush = |run: &mut Vec<u8>, run_lo: usize, run_hi: Option<usize>, out: &mut Vec<Atom>| {
        if run.len() >= 2 {
            out.push(Atom { bytes: run[..run.len().min(MAX_ATOM)].to_vec(), before_min: run_lo, before_max: run_hi });
        }
        run.clear();
    };

    for t in tokens {
        match t {
            HexToken::Byte(b) => {
                if run.is_empty() {
                    run_lo = lo;
                    run_hi = hi;
                }
                run.push(*b);
            }
            _ => flush(&mut run, run_lo, run_hi, &mut candidates),
        }
        let (a, b) = t.len_range();
        lo = lo.saturating_add(a);
        hi = match (hi, b) {
            (Some(x), Some(y)) => x.checked_add(y),
            _ => None,
        };
    }
    flush(&mut run, run_lo, run_hi, &mut candidates);

    let best_any = candidates.iter().max_by_key(|a| (a.bytes.len(), std::cmp::Reverse(a.before_min)))?;
    let best_bounded =
        candidates.iter().filter(|a| a.window().is_some_and(|w| w <= 256)).max_by_key(|a| (a.bytes.len(), std::cmp::Reverse(a.before_min)));
    match best_bounded {
        Some(b) if b.bytes.len() >= best_any.bytes.len().min(4) => Some(b.clone()),
        _ => Some(best_any.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::bytes::Regex;

    fn re(tokens: &[HexToken]) -> Regex {
        Regex::new(&format!("(?s-u){}", tokens_to_regex(tokens))).unwrap()
    }

    #[test]
    fn yara_hex_basic() {
        let t = parse_yara_hex("4D 5A ?? [2-4] ( 90 | 91 92 ) A? ?B ~00 // comment\n FF").unwrap();
        assert_eq!(t[0], HexToken::Byte(0x4D));
        assert_eq!(t[2], HexToken::Any);
        assert_eq!(t[3], HexToken::Jump { min: 2, max: Some(4) });
        assert!(matches!(t[4], HexToken::Alt(ref a) if a.len() == 2));
        assert_eq!(t[5], HexToken::Masked { value: 0xA0, mask: 0xF0 });
        assert_eq!(t[6], HexToken::Masked { value: 0x0B, mask: 0x0F });
        assert_eq!(t[7], HexToken::Not(vec![0]));
        let r = re(&t);
        assert!(r.is_match(&[0x4D, 0x5A, 0x00, 1, 2, 0x91, 0x92, 0xA7, 0x3B, 0x01, 0xFF]));
        assert!(!r.is_match(&[0x4D, 0x5A, 0x00, 1, 2, 0x91, 0x92, 0xA7, 0x3B, 0x00, 0xFF]));
    }

    #[test]
    fn clamav_hex_features() {
        let t = parse_clamav_hex("deadbeef*cafe{2-3}(aa|bbcc)!(00|01)??{4}ff").unwrap();
        let r = re(&t);
        let mut d = vec![0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 0xca, 0xfe, 9, 9, 0xbb, 0xcc, 0x05, 0x77];
        d.extend_from_slice(&[0, 0, 0, 0, 0xff]);
        assert!(r.is_match(&d));
        d[13] = 0x01; // negated byte
        assert!(!r.is_match(&d));
        assert!(parse_clamav_hex("aa(B)bb").is_err());
        assert!(parse_clamav_hex("zz").is_err());
    }

    #[test]
    fn atom_selection_prefers_long_bounded_runs() {
        let t = parse_clamav_hex("aabb*0102030405??06").unwrap();
        let a = extract_atom(&t).unwrap();
        assert_eq!(a.bytes, vec![1, 2, 3, 4, 5]);
        assert_eq!(a.before_max, None);
        let t = parse_yara_hex("00 11 22 33 [0-10] 44 55").unwrap();
        let a = extract_atom(&t).unwrap();
        assert_eq!(a.bytes, vec![0, 0x11, 0x22, 0x33]);
        assert_eq!((a.before_min, a.before_max), (0, Some(0)));
        assert!(extract_atom(&parse_yara_hex("?? 11 ?? 22").unwrap()).is_none());
    }

    #[test]
    fn literal_detection() {
        assert_eq!(as_literal(&parse_yara_hex("41 42").unwrap()), Some(vec![0x41, 0x42]));
        assert_eq!(as_literal(&parse_yara_hex("41 ??").unwrap()), None);
    }
}
