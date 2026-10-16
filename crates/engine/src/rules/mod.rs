//! YARA-compatible rule engine (subset).
//!
//! Rules are parsed with [`parser`], their strings are compiled into one
//! shared [`PatternSet`], and conditions are evaluated per file with
//! [`eval`]. A rule that fails to compile is skipped with a warning; it never
//! prevents the rest of the database from loading.

pub mod ast;
pub mod eval;
pub mod lexer;
pub mod parser;

use crate::patterns::{PatternMatches, PatternOptions, PatternSet, PatternSetBuilder, PatternSpec, ScanContext};
use crate::report::Severity;
use ast::{Expr, MetaValue, Rule, StringValue};
use eval::{EvalCtx, eval};
use serde::Serialize;
use std::collections::HashMap;

/// Matches collected per string (YARA collects far more; this is plenty for
/// counting conditions while bounding memory).
const MAX_MATCHES_PER_STRING: u32 = 1000;

struct CompiledRule {
    name: String,
    tags: Vec<String>,
    private: bool,
    global: bool,
    condition: Expr,
    /// Pattern ids for every string (several for `ascii wide` variants).
    string_patterns: Vec<Vec<u32>>,
    severity: Severity,
    threat_name: String,
    description: String,
}

/// A rule that matched a buffer.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleMatch {
    pub rule: String,
    pub tags: Vec<String>,
    pub severity: Severity,
    pub threat_name: String,
    pub description: String,
}

/// A compiled set of rules.
#[derive(Default)]
pub struct RuleSet {
    rules: Vec<CompiledRule>,
    patterns: PatternSet,
    /// Problems found while compiling (skipped rules etc.).
    pub warnings: Vec<String>,
    /// Per source: `(origin, compiled rules, skipped rules)`.
    pub origins: Vec<(String, u64, u64)>,
}

impl RuleSet {
    /// Compiles rule sources. `sources` is a list of `(origin, text)`.
    pub fn compile(sources: &[(String, String)]) -> RuleSet {
        let mut builder = PatternSetBuilder::new();
        let mut rules: Vec<CompiledRule> = Vec::new();
        let mut names: HashMap<String, usize> = HashMap::new();
        let mut warnings = Vec::new();

        let mut origins = Vec::with_capacity(sources.len());
        for (origin, text) in sources {
            let (rules_before, warnings_before) = (rules.len(), warnings.len());
            let mut parser = parser::Parser::new(text, names.clone());
            while let Some(item) = parser.next_rule() {
                let rule = match item {
                    Ok(r) => r,
                    Err(e) => {
                        warnings.push(format!(
                            "{origin}:{}: {}{}",
                            e.line,
                            e.rule.map(|r| format!("rule '{r}': ")).unwrap_or_default(),
                            e.message
                        ));
                        continue;
                    }
                };
                if names.contains_key(&rule.name) {
                    warnings.push(format!("{origin}:{}: duplicate rule '{}' skipped", rule.line, rule.name));
                    continue;
                }
                match compile_rule(&rule, &mut builder, rules.len() as u32) {
                    Ok(compiled) => {
                        names.insert(rule.name.clone(), rules.len());
                        parser.add_known_rule(rule.name.clone(), rules.len());
                        rules.push(compiled);
                    }
                    Err(msg) => warnings.push(format!("{origin}:{}: rule '{}': {msg}", rule.line, rule.name)),
                }
            }
            origins.push((origin.clone(), (rules.len() - rules_before) as u64, (warnings.len() - warnings_before) as u64));
        }

        RuleSet { rules, patterns: builder.build(), warnings, origins }
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Evaluates all rules against `data`.
    pub fn scan(&self, data: &[u8], filesize: u64, ctx: &ScanContext) -> Vec<RuleMatch> {
        if self.rules.is_empty() {
            return Vec::new();
        }
        let matches = self.patterns.scan(data, ctx);
        self.evaluate(&matches, data, filesize, ctx)
    }

    fn evaluate(&self, matches: &PatternMatches, data: &[u8], filesize: u64, ctx: &ScanContext) -> Vec<RuleMatch> {
        let mut results = vec![false; self.rules.len()];
        let mut out = Vec::new();
        let mut hits: Vec<Vec<(u64, u32)>> = Vec::new();

        // Global rules gate everything else.
        let mut globals_ok = true;
        for (i, rule) in self.rules.iter().enumerate() {
            hits.clear();
            for ids in &rule.string_patterns {
                let mut v: Vec<(u64, u32)> = ids.iter().flat_map(|id| matches.get(*id).iter().copied()).collect();
                if ids.len() > 1 {
                    v.sort_unstable();
                    v.dedup_by_key(|h| h.0);
                }
                hits.push(v);
            }
            let cx = EvalCtx { data, filesize, entrypoint: ctx.entry_point, hits: &hits, rule_results: &results[..i] };
            let ok = eval(&rule.condition, &cx).truthy();
            results[i] = ok;
            if rule.global && !ok {
                globals_ok = false;
            }
        }
        if !globals_ok {
            return Vec::new();
        }
        for (i, rule) in self.rules.iter().enumerate() {
            if results[i] && !rule.private && !rule.global {
                out.push(RuleMatch {
                    rule: rule.name.clone(),
                    tags: rule.tags.clone(),
                    severity: rule.severity,
                    threat_name: rule.threat_name.clone(),
                    description: rule.description.clone(),
                });
            }
        }
        out
    }
}

fn compile_rule(rule: &Rule, builder: &mut PatternSetBuilder, tag: u32) -> Result<CompiledRule, String> {
    let mut string_patterns = Vec::with_capacity(rule.strings.len());
    for s in &rule.strings {
        let opts = PatternOptions { max_matches: MAX_MATCHES_PER_STRING, fullword: s.mods.fullword, ..Default::default() };
        let mut ids = Vec::new();
        match &s.value {
            StringValue::Text(text) => {
                let want_ascii = s.mods.ascii || !s.mods.wide;
                if want_ascii {
                    ids.push(builder.add(tag, PatternSpec::Literal { bytes: text.clone(), nocase: s.mods.nocase }, opts)?);
                }
                if s.mods.wide {
                    let wide: Vec<u8> = text.iter().flat_map(|&b| [b, 0]).collect();
                    ids.push(builder.add(tag, PatternSpec::Literal { bytes: wide, nocase: s.mods.nocase }, opts)?);
                }
            }
            StringValue::Hex(tokens) => {
                ids.push(builder.add(tag, PatternSpec::Hex(tokens.clone()), opts)?);
            }
            StringValue::Regex { pattern, nocase, dotall } => {
                ids.push(builder.add(
                    tag,
                    PatternSpec::Regex { source: pattern.clone(), nocase: *nocase || s.mods.nocase, dotall: *dotall },
                    opts,
                )?);
            }
        }
        string_patterns.push(ids);
    }

    let severity = rule
        .meta("severity")
        .and_then(MetaValue::as_str)
        .and_then(Severity::parse)
        .or_else(|| rule.meta("score").and_then(MetaValue::as_int).map(|s| Severity::from_score(s.clamp(0, 100) as u32)))
        .unwrap_or(Severity::High);
    let threat_name = rule
        .meta("threat")
        .or_else(|| rule.meta("malware_name"))
        .and_then(MetaValue::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| rule.name.clone());
    let description = rule.meta("description").and_then(MetaValue::as_str).map(str::to_string).unwrap_or_default();

    Ok(CompiledRule {
        name: rule.name.clone(),
        tags: rule.tags.clone(),
        private: rule.private,
        global: rule.global,
        condition: rule.condition.clone(),
        string_patterns,
        severity,
        threat_name,
        description,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filetype::FileType;

    fn ctx() -> ScanContext {
        ScanContext { file_type: FileType::Unknown, entry_point: None }
    }

    fn compile(src: &str) -> RuleSet {
        RuleSet::compile(&[("test.yar".into(), src.into())])
    }

    fn names(rs: &RuleSet, data: &[u8]) -> Vec<String> {
        let mut v: Vec<String> = rs.scan(data, data.len() as u64, &ctx()).into_iter().map(|m| m.rule).collect();
        v.sort();
        v
    }

    #[test]
    fn basic_conditions() {
        let rs = compile(
            r#"
            rule TextAndHex : demo {
                meta:
                    description = "demo rule"
                    severity = "medium"
                strings:
                    $a = "alpha" nocase
                    $b = { 62 65 74 61 }
                    $c = /gam+a/
                condition:
                    $a and ($b or $c)
            }
            rule Counting { strings: $x = "x" condition: #x >= 3 and @x[1] == 0 and !x[2] == 1 }
            rule Header { condition: uint16(0) == 0x7878 and filesize < 1KB }
            rule Quant { strings: $p1 = "one" $p2 = "two" $p3 = "three" condition: 2 of ($p*) and not all of them }
            rule Percent { strings: $p1 = "one" $p2 = "two" condition: 50% of them }
            rule InRange { strings: $z = "ALPHA" condition: $z in (0..10) }
            private rule Hidden { strings: $h = "beta" condition: $h }
            rule UsesHidden { condition: Hidden and Header }
            "#,
        );
        assert!(rs.warnings.is_empty(), "{:?}", rs.warnings);
        assert_eq!(rs.len(), 8);
        let data = b"xxxALPHA beta one two";
        assert_eq!(names(&rs, data), vec!["Counting", "Header", "InRange", "Percent", "Quant", "TextAndHex", "UsesHidden"]);
        let m = rs.scan(data, data.len() as u64, &ctx());
        let first = m.iter().find(|m| m.rule == "TextAndHex").unwrap();
        assert_eq!(first.severity, Severity::Medium);
        assert_eq!(first.tags, vec!["demo"]);
        assert_eq!(first.description, "demo rule");
        assert!(names(&rs, b"nothing here").is_empty());
    }

    #[test]
    fn wide_and_fullword() {
        let rs = compile(r#"rule W { strings: $a = "abc" wide ascii fullword condition: #a == 2 }"#);
        assert!(rs.warnings.is_empty(), "{:?}", rs.warnings);
        let mut data = b"abc ".to_vec();
        data.extend_from_slice(&[b'a', 0, b'b', 0, b'c', 0]);
        data.extend_from_slice(b" xabcx");
        assert_eq!(names(&rs, &data), vec!["W"]);
    }

    #[test]
    fn bad_rules_are_skipped() {
        let rs = compile(
            r#"
            import "pe"
            rule Good1 { condition: true }
            rule Bad1 { condition: pe.is_dll() }
            rule Bad2 { strings: $a = "x" xor condition: $a }
            rule Bad3 { condition: for any i in (1..2) : (true) }
            rule Bad4 { condition: $missing }
            rule Good2 { strings: $a = "ok" condition: $a and Good1 }
            "#,
        );
        assert_eq!(rs.len(), 2, "{:?}", rs.warnings);
        assert_eq!(rs.warnings.len(), 4, "{:?}", rs.warnings);
        assert_eq!(names(&rs, b"ok"), vec!["Good1", "Good2"]);
    }

    #[test]
    fn global_rules_gate_matches() {
        let rs = compile(
            r#"
            global rule SmallOnly { condition: filesize < 10 }
            rule Any { condition: true }
            "#,
        );
        assert_eq!(names(&rs, b"tiny"), vec!["Any"]);
        assert!(names(&rs, b"this is a long buffer").is_empty());
    }

    #[test]
    fn arithmetic_and_bitwise() {
        let rs = compile(
            r#"rule Math { condition: (filesize * 2 + 1) \ 3 == 3 and (0xF0 | 0x0F) == 255 and (1 << 4) == 16 and -(-2) == 2 and 7 % 4 == 3 }"#,
        );
        assert!(rs.warnings.is_empty(), "{:?}", rs.warnings);
        assert_eq!(names(&rs, b"abcd"), vec!["Math"]);
    }
}
