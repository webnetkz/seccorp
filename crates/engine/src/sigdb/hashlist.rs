//! Plain hash lists and MalwareBazaar CSV exports.
//!
//! Accepted line formats (comments start with `#`):
//!
//! ```text
//! <hash>
//! <hash> <name...>
//! <hash>,<name>
//! "2026-10-01 10:00:00","<sha256>","<md5>","<sha1>",...,"<signature>",...   (MalwareBazaar CSV)
//! ```
//!
//! MalwareBazaar exports require a free abuse.ch Auth-Key; see the README.

use super::clamav::ImportStats;
use super::hashdb::{ANY_SIZE, HashDbBuilder};
use crate::report::Severity;

fn is_hex_len(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_hash(s: &str) -> bool {
    is_hex_len(s, 64) || is_hex_len(s, 40) || is_hex_len(s, 32)
}

/// Minimal CSV field splitter supporting double-quoted fields.
fn split_csv(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out.into_iter().map(|f| f.trim().to_string()).collect()
}

fn sanitize_name(name: &str) -> String {
    let cleaned: String = name.chars().map(|c| if c.is_alphanumeric() || "._-".contains(c) { c } else { '_' }).take(96).collect();
    cleaned.trim_matches('_').to_string()
}

/// Imports a hash list. `source` is used to name unnamed signatures.
pub fn parse_hash_list(text: &str, source: &str, out: &mut HashDbBuilder) -> ImportStats {
    let mut st = ImportStats::default();
    let mut columns: Option<Vec<String>> = None;
    let source_tag = sanitize_name(source);
    let default_name = if source_tag.is_empty() { "HashList.Generic".to_string() } else { format!("HashList.{source_tag}") };

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix('#') {
            // MalwareBazaar puts the CSV header in a comment line.
            let c = comment.trim();
            if c.contains("sha256_hash") {
                columns = Some(split_csv(c).into_iter().map(|s| s.to_ascii_lowercase()).collect());
            }
            continue;
        }

        if line.contains('"') || line.matches(',').count() >= 2 {
            let fields = split_csv(line);
            let col = |name: &str| -> Option<&str> {
                let cols = columns.as_ref()?;
                let i = cols.iter().position(|c| c == name)?;
                fields.get(i).map(|s| s.as_str())
            };
            let hash = col("sha256_hash")
                .filter(|h| is_hex_len(h, 64))
                .map(str::to_string)
                .or_else(|| fields.iter().find(|f| is_hex_len(f, 64)).cloned())
                .or_else(|| fields.iter().find(|f| is_hash(f)).cloned());
            let Some(hash) = hash else {
                st.skipped += 1;
                continue;
            };
            let family = col("signature").filter(|s| !s.is_empty() && *s != "n/a" && *s != "null");
            let name = match family {
                Some(f) => format!("MalwareBazaar.{}", sanitize_name(f)),
                None if columns.is_some() => "MalwareBazaar.Generic".to_string(),
                None => default_name.clone(),
            };
            match out.add_hex(&hash.to_ascii_lowercase(), ANY_SIZE, &name, Severity::High) {
                Ok(()) => st.added += 1,
                Err(_) => st.skipped += 1,
            }
            continue;
        }

        let mut parts = line.splitn(2, |c: char| c.is_whitespace() || c == ',' || c == ';' || c == '\t');
        let hash = parts.next().unwrap_or("").trim();
        if !is_hash(hash) {
            st.skipped += 1;
            continue;
        }
        let name = parts.next().map(|n| sanitize_name(n.trim())).filter(|n| !n.is_empty()).unwrap_or_else(|| default_name.clone());
        match out.add_hex(&hash.to_ascii_lowercase(), ANY_SIZE, &name, Severity::High) {
            Ok(()) => st.added += 1,
            Err(_) => st.skipped += 1,
        }
    }
    st
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::hash_bytes;

    #[test]
    fn plain_and_named() {
        let h1 = hex::encode(hash_bytes(b"one", false, false).sha256);
        let h2 = hex::encode(hash_bytes(b"two", false, false).sha256);
        let text = format!("# list\n{h1}\n{h2} Family Name\nnot-a-hash\n");
        let mut b = HashDbBuilder::new();
        let st = parse_hash_list(&text, "custom list", &mut b);
        assert_eq!((st.added, st.skipped), (2, 1));
        let db = b.build();
        assert_eq!(db.lookup(&hash_bytes(b"one", false, false), 3).unwrap().name, "HashList.custom_list");
        assert_eq!(db.lookup(&hash_bytes(b"two", false, false), 3).unwrap().name, "Family_Name");
    }

    #[test]
    fn malwarebazaar_csv() {
        let sha = hex::encode(hash_bytes(b"sample", false, false).sha256);
        let text = format!(
            "################\n# \"first_seen_utc\",\"sha256_hash\",\"md5_hash\",\"sha1_hash\",\"reporter\",\"file_name\",\"file_type_guess\",\"mime_type\",\"signature\"\n\"2026-10-01 10:00:00\",\"{sha}\",\"{md5}\",\"{sha1}\",\"someone\",\"a.exe\",\"exe\",\"application/x-dosexec\",\"ExampleFamily\"\n",
            md5 = "0".repeat(32),
            sha1 = "0".repeat(40)
        );
        let mut b = HashDbBuilder::new();
        let st = parse_hash_list(&text, "recent.csv", &mut b);
        assert_eq!(st.added, 1);
        let db = b.build();
        assert_eq!(db.lookup(&hash_bytes(b"sample", false, false), 6).unwrap().name, "MalwareBazaar.ExampleFamily");
    }
}
