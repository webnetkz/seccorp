//! Recursive-descent parser for the YARA-compatible rule subset.
//!
//! Supported: `rule` with `private`/`global` flags and tags, `meta`,
//! `strings` (text with `nocase wide ascii fullword private`, hex strings
//! with wildcards/jumps/alternatives, regexes with `i`/`s` flags) and
//! conditions with boolean/arithmetic/bitwise operators, string matches,
//! `at`, `in`, `#`, `@`, `!`, `any|all|none|N|N% of`, `them`, wildcards,
//! `filesize`, `entrypoint`, `uintXX()/intXX()[be]` and references to
//! earlier rules. `import`ed modules and `for` loops are rejected with a clear
//! message so the rest of the file still loads.

use super::ast::*;
use super::lexer::{Lexer, Tok};
use crate::patterns::parse_yara_hex;
use std::collections::{HashMap, VecDeque};

/// A parse error tied to a line.
#[derive(Debug, Clone)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
    /// Name of the rule being parsed, when known.
    pub rule: Option<String>,
}

pub struct Parser<'a> {
    lexer: Lexer<'a>,
    buf: VecDeque<(Tok, usize)>,
    /// Rules that may be referenced from conditions (name → index).
    known_rules: HashMap<String, usize>,
}

const KEYWORDS: &[&str] = &[
    "all",
    "and",
    "any",
    "ascii",
    "at",
    "condition",
    "contains",
    "entrypoint",
    "false",
    "filesize",
    "for",
    "fullword",
    "global",
    "import",
    "in",
    "include",
    "matches",
    "meta",
    "nocase",
    "none",
    "not",
    "of",
    "or",
    "private",
    "rule",
    "strings",
    "them",
    "true",
    "wide",
    "xor",
    "base64",
    "base64wide",
];

impl<'a> Parser<'a> {
    pub fn new(src: &'a str, known_rules: HashMap<String, usize>) -> Self {
        Parser { lexer: Lexer::new(src), buf: VecDeque::new(), known_rules }
    }

    /// Makes a successfully compiled rule referenceable by later rules.
    pub fn add_known_rule(&mut self, name: String, index: usize) {
        self.known_rules.insert(name, index);
    }

    fn fill(&mut self, n: usize) -> Result<(), String> {
        while self.buf.len() < n {
            let line = self.lexer.line;
            let t = self.lexer.next_token()?;
            self.buf.push_back((t, line));
        }
        Ok(())
    }

    fn peek(&mut self) -> Result<&Tok, String> {
        self.fill(1)?;
        Ok(&self.buf[0].0)
    }

    fn peek2(&mut self) -> Result<&Tok, String> {
        self.fill(2)?;
        Ok(&self.buf[1].0)
    }

    fn line(&self) -> usize {
        self.buf.front().map(|t| t.1).unwrap_or(self.lexer.line)
    }

    fn next(&mut self) -> Result<Tok, String> {
        self.fill(1)?;
        Ok(self.buf.pop_front().map(|t| t.0).unwrap_or(Tok::Eof))
    }

    fn expect(&mut self, want: &Tok, what: &str) -> Result<(), String> {
        let t = self.next()?;
        if &t == want { Ok(()) } else { Err(format!("expected {what}, found {t:?}")) }
    }

    fn expect_ident(&mut self, what: &str) -> Result<String, String> {
        match self.next()? {
            Tok::Ident(s) => Ok(s),
            t => Err(format!("expected {what}, found {t:?}")),
        }
    }

    fn is_kw(t: &Tok, kw: &str) -> bool {
        matches!(t, Tok::Ident(s) if s == kw)
    }

    /// Parses the next top-level item. Returns `Ok(None)` at end of input.
    /// On error, the parser skips to the next `rule` keyword so that the
    /// caller can continue with the remaining rules.
    pub fn next_rule(&mut self) -> Option<Result<Rule, ParseError>> {
        loop {
            let tok = match self.peek() {
                Ok(t) => t.clone(),
                Err(e) => return Some(Err(ParseError { line: self.lexer.line, message: e, rule: None })),
            };
            match tok {
                Tok::Eof => return None,
                Tok::Ident(ref s) if s == "import" || s == "include" => {
                    let _ = self.next();
                    let _ = self.next(); // module / file name
                    if s == "include" {
                        return Some(Err(ParseError {
                            line: self.line(),
                            message: "'include' is not supported; place rule files side by side".into(),
                            rule: None,
                        }));
                    }
                    continue;
                }
                _ => {}
            }
            let line = self.line();
            let result = self.parse_rule();
            return Some(result.map_err(|(message, rule)| {
                self.recover();
                ParseError { line, message, rule }
            }));
        }
    }

    fn recover(&mut self) {
        // Skip tokens until the next rule header.
        loop {
            match self.peek() {
                Err(_) => {
                    // Lexer error: drop the rest of the file.
                    self.buf.clear();
                    self.buf.push_back((Tok::Eof, self.lexer.line));
                    return;
                }
                Ok(Tok::Eof) => return,
                Ok(t) if Self::is_kw(t, "rule") || Self::is_kw(t, "private") || Self::is_kw(t, "global") => return,
                Ok(_) => {
                    let _ = self.next();
                }
            }
        }
    }

    fn parse_rule(&mut self) -> Result<Rule, (String, Option<String>)> {
        let mut private = false;
        let mut global = false;
        loop {
            match self.next().map_err(|e| (e, None))? {
                Tok::Ident(s) if s == "private" => private = true,
                Tok::Ident(s) if s == "global" => global = true,
                Tok::Ident(s) if s == "rule" => break,
                t => return Err((format!("expected 'rule', found {t:?}"), None)),
            }
        }
        let line = self.line();
        let name = self.expect_ident("rule name").map_err(|e| (e, None))?;
        let ctx = Some(name.clone());
        if KEYWORDS.contains(&name.as_str()) {
            return Err((format!("'{name}' is a reserved word"), ctx));
        }
        let mut tags = Vec::new();
        if *self.peek().map_err(|e| (e, ctx.clone()))? == Tok::Colon {
            self.next().map_err(|e| (e, ctx.clone()))?;
            while let Tok::Ident(t) = self.peek().map_err(|e| (e, ctx.clone()))?.clone() {
                self.next().map_err(|e| (e, ctx.clone()))?;
                tags.push(t);
            }
        }
        self.expect(&Tok::LBrace, "'{'").map_err(|e| (e, ctx.clone()))?;

        let mut meta = Vec::new();
        let mut strings: Vec<StringDef> = Vec::new();
        let condition = loop {
            let section = self.next().map_err(|e| (e, ctx.clone()))?;
            match section {
                Tok::Ident(s) if s == "meta" => {
                    self.expect(&Tok::Colon, "':'").map_err(|e| (e, ctx.clone()))?;
                    self.parse_meta(&mut meta).map_err(|e| (e, ctx.clone()))?;
                }
                Tok::Ident(s) if s == "strings" => {
                    self.expect(&Tok::Colon, "':'").map_err(|e| (e, ctx.clone()))?;
                    self.parse_strings(&mut strings).map_err(|e| (e, ctx.clone()))?;
                }
                Tok::Ident(s) if s == "condition" => {
                    self.expect(&Tok::Colon, "':'").map_err(|e| (e, ctx.clone()))?;
                    let expr = self.parse_or(&strings).map_err(|e| (e, ctx.clone()))?;
                    self.expect(&Tok::RBrace, "'}' after condition").map_err(|e| (e, ctx.clone()))?;
                    break expr;
                }
                t => return Err((format!("expected 'meta', 'strings' or 'condition', found {t:?}"), ctx)),
            }
        };
        Ok(Rule { name, tags, private, global, meta, strings, condition, line })
    }

    fn parse_meta(&mut self, meta: &mut Vec<(String, MetaValue)>) -> Result<(), String> {
        loop {
            let (Tok::Ident(key), Tok::Assign) = (self.peek()?.clone(), self.peek2()?.clone()) else {
                return Ok(());
            };
            if key == "strings" || key == "condition" {
                return Ok(());
            }
            self.next()?;
            self.next()?;
            let value = match self.next()? {
                Tok::Str(s) => MetaValue::Str(String::from_utf8_lossy(&s).into_owned()),
                Tok::Int(i) => MetaValue::Int(i),
                Tok::Minus => match self.next()? {
                    Tok::Int(i) => MetaValue::Int(-i),
                    t => return Err(format!("invalid meta value {t:?}")),
                },
                Tok::Ident(b) if b == "true" => MetaValue::Bool(true),
                Tok::Ident(b) if b == "false" => MetaValue::Bool(false),
                t => return Err(format!("invalid meta value {t:?}")),
            };
            meta.push((key, value));
        }
    }

    fn parse_strings(&mut self, strings: &mut Vec<StringDef>) -> Result<(), String> {
        let mut anon = 0usize;
        while let Tok::StringId(id) = self.peek()?.clone() {
            self.next()?;
            if id.ends_with('*') {
                return Err(format!("invalid string identifier '${id}'"));
            }
            self.expect(&Tok::Assign, "'='")?;
            let id = if id.is_empty() {
                anon += 1;
                format!("__anon{anon}")
            } else {
                id
            };
            if strings.iter().any(|s| s.id == id) {
                return Err(format!("duplicate string identifier '${id}'"));
            }
            let value = match self.next()? {
                Tok::Str(s) => {
                    if s.is_empty() {
                        return Err(format!("empty string '${id}'"));
                    }
                    StringValue::Text(s)
                }
                Tok::LBrace => {
                    // The lookahead buffer is empty here (we just consumed '{').
                    debug_assert!(self.buf.is_empty());
                    let body = self.lexer.read_hex_body()?;
                    StringValue::Hex(parse_yara_hex(&body).map_err(|e| format!("${id}: {e}"))?)
                }
                Tok::Regex { pattern, nocase, dotall } => StringValue::Regex { pattern, nocase, dotall },
                t => return Err(format!("invalid value for '${id}': {t:?}")),
            };
            let mut mods = Modifiers::default();
            while let Tok::Ident(m) = self.peek()?.clone() {
                match m.as_str() {
                    "nocase" => mods.nocase = true,
                    "wide" => mods.wide = true,
                    "ascii" => mods.ascii = true,
                    "fullword" => mods.fullword = true,
                    "private" => mods.private = true,
                    "xor" | "base64" | "base64wide" => return Err(format!("modifier '{m}' is not supported")),
                    _ => break,
                }
                self.next()?;
            }
            match &value {
                StringValue::Hex(_) if mods.nocase || mods.wide || mods.fullword || mods.ascii => {
                    return Err(format!("${id}: hex strings accept only the 'private' modifier"));
                }
                StringValue::Regex { .. } if mods.wide => {
                    return Err(format!("${id}: 'wide' is not supported for regular expressions"));
                }
                _ => {}
            }
            strings.push(StringDef { id, value, mods });
        }
        Ok(())
    }

    // ---- condition -------------------------------------------------------

    fn parse_or(&mut self, s: &[StringDef]) -> Result<Expr, String> {
        let mut e = self.parse_and(s)?;
        while Self::is_kw(self.peek()?, "or") {
            self.next()?;
            let r = self.parse_and(s)?;
            e = Expr::Or(Box::new(e), Box::new(r));
        }
        Ok(e)
    }

    fn parse_and(&mut self, s: &[StringDef]) -> Result<Expr, String> {
        let mut e = self.parse_not(s)?;
        while Self::is_kw(self.peek()?, "and") {
            self.next()?;
            let r = self.parse_not(s)?;
            e = Expr::And(Box::new(e), Box::new(r));
        }
        Ok(e)
    }

    fn parse_not(&mut self, s: &[StringDef]) -> Result<Expr, String> {
        if Self::is_kw(self.peek()?, "not") {
            self.next()?;
            return Ok(Expr::Not(Box::new(self.parse_not(s)?)));
        }
        self.parse_cmp(s)
    }

    fn parse_cmp(&mut self, s: &[StringDef]) -> Result<Expr, String> {
        let l = self.parse_bitor(s)?;
        let op = match self.peek()? {
            Tok::Eq => CmpOp::Eq,
            Tok::Ne => CmpOp::Ne,
            Tok::Lt => CmpOp::Lt,
            Tok::Le => CmpOp::Le,
            Tok::Gt => CmpOp::Gt,
            Tok::Ge => CmpOp::Ge,
            Tok::Ident(k) if k == "contains" || k == "matches" => {
                return Err(format!("operator '{k}' is not supported"));
            }
            _ => return Ok(l),
        };
        self.next()?;
        let r = self.parse_bitor(s)?;
        Ok(Expr::Cmp(op, Box::new(l), Box::new(r)))
    }

    fn parse_bitor(&mut self, s: &[StringDef]) -> Result<Expr, String> {
        let mut e = self.parse_bitxor(s)?;
        while *self.peek()? == Tok::Pipe {
            self.next()?;
            e = Expr::Bin(BinOp::Or, Box::new(e), Box::new(self.parse_bitxor(s)?));
        }
        Ok(e)
    }

    fn parse_bitxor(&mut self, s: &[StringDef]) -> Result<Expr, String> {
        let mut e = self.parse_bitand(s)?;
        while *self.peek()? == Tok::Caret {
            self.next()?;
            e = Expr::Bin(BinOp::Xor, Box::new(e), Box::new(self.parse_bitand(s)?));
        }
        Ok(e)
    }

    fn parse_bitand(&mut self, s: &[StringDef]) -> Result<Expr, String> {
        let mut e = self.parse_shift(s)?;
        while *self.peek()? == Tok::Amp {
            self.next()?;
            e = Expr::Bin(BinOp::And, Box::new(e), Box::new(self.parse_shift(s)?));
        }
        Ok(e)
    }

    fn parse_shift(&mut self, s: &[StringDef]) -> Result<Expr, String> {
        let mut e = self.parse_add(s)?;
        loop {
            let op = match self.peek()? {
                Tok::Shl => BinOp::Shl,
                Tok::Shr => BinOp::Shr,
                _ => return Ok(e),
            };
            self.next()?;
            e = Expr::Bin(op, Box::new(e), Box::new(self.parse_add(s)?));
        }
    }

    fn parse_add(&mut self, s: &[StringDef]) -> Result<Expr, String> {
        let mut e = self.parse_mul(s)?;
        loop {
            let op = match self.peek()? {
                Tok::Plus => BinOp::Add,
                Tok::Minus => BinOp::Sub,
                _ => return Ok(e),
            };
            self.next()?;
            e = Expr::Bin(op, Box::new(e), Box::new(self.parse_mul(s)?));
        }
    }

    fn parse_mul(&mut self, s: &[StringDef]) -> Result<Expr, String> {
        let mut e = self.parse_unary(s)?;
        loop {
            let op = match self.peek()? {
                Tok::Star => BinOp::Mul,
                Tok::Backslash => BinOp::Div,
                // `N% of` is handled in parse_primary; here '%' is modulo.
                Tok::Percent => BinOp::Mod,
                _ => return Ok(e),
            };
            self.next()?;
            e = Expr::Bin(op, Box::new(e), Box::new(self.parse_unary(s)?));
        }
    }

    fn parse_unary(&mut self, s: &[StringDef]) -> Result<Expr, String> {
        match self.peek()? {
            Tok::Minus => {
                self.next()?;
                Ok(Expr::Neg(Box::new(self.parse_unary(s)?)))
            }
            Tok::Tilde => {
                self.next()?;
                Ok(Expr::BitNot(Box::new(self.parse_unary(s)?)))
            }
            _ => self.parse_primary(s),
        }
    }

    fn string_index(s: &[StringDef], id: &str) -> Result<usize, String> {
        s.iter().position(|d| d.id == id).ok_or_else(|| format!("undefined string '${id}'"))
    }

    fn parse_range(&mut self, s: &[StringDef]) -> Result<(Box<Expr>, Box<Expr>), String> {
        self.expect(&Tok::LParen, "'(' for range")?;
        let lo = self.parse_add(s)?;
        self.expect(&Tok::DotDot, "'..'")?;
        let hi = self.parse_add(s)?;
        self.expect(&Tok::RParen, "')' after range")?;
        Ok((Box::new(lo), Box::new(hi)))
    }

    fn parse_index(&mut self, s: &[StringDef]) -> Result<Box<Expr>, String> {
        if *self.peek()? == Tok::LBracket {
            self.next()?;
            let e = self.parse_add(s)?;
            self.expect(&Tok::RBracket, "']'")?;
            Ok(Box::new(e))
        } else {
            Ok(Box::new(Expr::Int(1)))
        }
    }

    fn parse_string_set(&mut self, s: &[StringDef]) -> Result<Vec<usize>, String> {
        if Self::is_kw(self.peek()?, "them") {
            self.next()?;
            if s.is_empty() {
                return Err("'them' used in a rule without strings".into());
            }
            return Ok((0..s.len()).collect());
        }
        self.expect(&Tok::LParen, "'(' or 'them'")?;
        let mut out = Vec::new();
        loop {
            match self.next()? {
                Tok::StringId(id) => {
                    if let Some(prefix) = id.strip_suffix('*') {
                        let before = out.len();
                        for (i, d) in s.iter().enumerate() {
                            if d.id.starts_with(prefix) && !out.contains(&i) {
                                out.push(i);
                            }
                        }
                        if out.len() == before {
                            return Err(format!("no strings match '${id}'"));
                        }
                    } else {
                        let i = Self::string_index(s, &id)?;
                        if !out.contains(&i) {
                            out.push(i);
                        }
                    }
                }
                t => return Err(format!("expected string identifier, found {t:?}")),
            }
            match self.next()? {
                Tok::Comma => continue,
                Tok::RParen => break,
                t => return Err(format!("expected ',' or ')', found {t:?}")),
            }
        }
        Ok(out)
    }

    fn parse_of(&mut self, quant: Quant, s: &[StringDef]) -> Result<Expr, String> {
        if !Self::is_kw(&self.next()?, "of") {
            return Err("expected 'of'".into());
        }
        let strings = self.parse_string_set(s)?;
        let range = if Self::is_kw(self.peek()?, "in") {
            self.next()?;
            Some(self.parse_range(s)?)
        } else {
            None
        };
        Ok(Expr::Of { quant, strings, range })
    }

    fn parse_primary(&mut self, s: &[StringDef]) -> Result<Expr, String> {
        let tok = self.next()?;
        match tok {
            Tok::LParen => {
                let e = self.parse_or(s)?;
                self.expect(&Tok::RParen, "')'")?;
                Ok(e)
            }
            Tok::Int(n) => {
                if Self::is_kw(self.peek()?, "of") {
                    return self.parse_of(Quant::Count(n), s);
                }
                if *self.peek()? == Tok::Percent && Self::is_kw(self.peek2()?, "of") {
                    self.next()?;
                    return self.parse_of(Quant::Percent(n), s);
                }
                Ok(Expr::Int(n))
            }
            Tok::StringId(id) => {
                if id.is_empty() || id.ends_with('*') {
                    return Err(format!("'${id}' can only be used in a string set"));
                }
                let i = Self::string_index(s, &id)?;
                if Self::is_kw(self.peek()?, "at") {
                    self.next()?;
                    let off = self.parse_add(s)?;
                    return Ok(Expr::StrAt(i, Box::new(off)));
                }
                if Self::is_kw(self.peek()?, "in") {
                    self.next()?;
                    let (lo, hi) = self.parse_range(s)?;
                    return Ok(Expr::StrIn(i, lo, hi));
                }
                Ok(Expr::Str(i))
            }
            Tok::CountId(id) => {
                let i = Self::string_index(s, &id)?;
                if Self::is_kw(self.peek()?, "in") {
                    self.next()?;
                    let (lo, hi) = self.parse_range(s)?;
                    return Ok(Expr::CountIn(i, lo, hi));
                }
                Ok(Expr::Count(i))
            }
            Tok::OffsetId(id) => {
                let i = Self::string_index(s, &id)?;
                Ok(Expr::Offset(i, self.parse_index(s)?))
            }
            Tok::LengthId(id) => {
                let i = Self::string_index(s, &id)?;
                Ok(Expr::Length(i, self.parse_index(s)?))
            }
            Tok::Ident(name) => match name.as_str() {
                "true" => Ok(Expr::Bool(true)),
                "false" => Ok(Expr::Bool(false)),
                "filesize" => Ok(Expr::Filesize),
                "entrypoint" => Ok(Expr::Entrypoint),
                "any" => self.parse_of(Quant::Any, s),
                "all" => self.parse_of(Quant::All, s),
                "none" => self.parse_of(Quant::None, s),
                "for" => Err("'for' loops are not supported".into()),
                _ => {
                    if let Some(kind) = IntKind::from_name(&name) {
                        self.expect(&Tok::LParen, "'('")?;
                        let off = self.parse_add(s)?;
                        self.expect(&Tok::RParen, "')'")?;
                        return Ok(Expr::ReadInt(kind, Box::new(off)));
                    }
                    if *self.peek()? == Tok::Dot {
                        return Err(format!("module '{name}' is not supported"));
                    }
                    match self.known_rules.get(&name) {
                        Some(&idx) => Ok(Expr::RuleRef(idx)),
                        None => Err(format!("unknown identifier '{name}'")),
                    }
                }
            },
            t => Err(format!("unexpected {t:?} in condition")),
        }
    }
}
