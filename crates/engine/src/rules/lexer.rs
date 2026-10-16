//! Tokenizer for the YARA-compatible rule language.

#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    Ident(String),
    /// `$name`, `$` (anonymous) or `$prefix*` (wildcard).
    StringId(String),
    /// `#name`
    CountId(String),
    /// `@name`
    OffsetId(String),
    /// `!name`
    LengthId(String),
    Int(i64),
    Str(Vec<u8>),
    Regex {
        pattern: String,
        nocase: bool,
        dotall: bool,
    },
    LBrace,
    RBrace,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Colon,
    Comma,
    Assign,
    DotDot,
    Dot,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Plus,
    Minus,
    Star,
    Backslash,
    Percent,
    Amp,
    Pipe,
    Caret,
    Tilde,
    Shl,
    Shr,
    Eof,
}

pub struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    pub line: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a str) -> Self {
        Lexer { src: src.as_bytes(), pos: 0, line: 1 }
    }

    fn peek_byte(&self, off: usize) -> Option<u8> {
        self.src.get(self.pos + off).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.src.get(self.pos).copied()?;
        self.pos += 1;
        if b == b'\n' {
            self.line += 1;
        }
        Some(b)
    }

    fn skip_ws_and_comments(&mut self) -> Result<(), String> {
        loop {
            match self.peek_byte(0) {
                Some(b) if b.is_ascii_whitespace() => {
                    self.bump();
                }
                Some(b'/') if self.peek_byte(1) == Some(b'/') => {
                    while let Some(b) = self.peek_byte(0) {
                        if b == b'\n' {
                            break;
                        }
                        self.bump();
                    }
                }
                Some(b'/') if self.peek_byte(1) == Some(b'*') => {
                    self.bump();
                    self.bump();
                    loop {
                        match self.bump() {
                            None => return Err("unterminated comment".into()),
                            Some(b'*') if self.peek_byte(0) == Some(b'/') => {
                                self.bump();
                                break;
                            }
                            _ => {}
                        }
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    fn ident_tail(&mut self) -> String {
        let start = self.pos;
        while let Some(b) = self.peek_byte(0) {
            if b.is_ascii_alphanumeric() || b == b'_' {
                self.bump();
            } else {
                break;
            }
        }
        String::from_utf8_lossy(&self.src[start..self.pos]).into_owned()
    }

    /// Reads the raw body of a hex string. Must be called right after the
    /// opening `{` was returned as [`Tok::LBrace`]; consumes the closing `}`.
    pub fn read_hex_body(&mut self) -> Result<String, String> {
        let start = self.pos;
        loop {
            match self.bump() {
                None => return Err("unterminated hex string".into()),
                Some(b'}') => {
                    return Ok(String::from_utf8_lossy(&self.src[start..self.pos - 1]).into_owned());
                }
                Some(_) => {}
            }
        }
    }

    fn read_string(&mut self) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        loop {
            match self.bump() {
                None | Some(b'\n') => return Err("unterminated string".into()),
                Some(b'"') => return Ok(out),
                Some(b'\\') => match self.bump() {
                    Some(b'"') => out.push(b'"'),
                    Some(b'\\') => out.push(b'\\'),
                    Some(b't') => out.push(b'\t'),
                    Some(b'n') => out.push(b'\n'),
                    Some(b'r') => out.push(b'\r'),
                    Some(b'x') => {
                        let h = self.bump().ok_or("bad \\x escape")?;
                        let l = self.bump().ok_or("bad \\x escape")?;
                        let s = [h, l];
                        let s = std::str::from_utf8(&s).map_err(|_| "bad \\x escape")?;
                        out.push(u8::from_str_radix(s, 16).map_err(|_| "bad \\x escape")?);
                    }
                    other => return Err(format!("unknown escape '\\{}'", other.map(|b| b as char).unwrap_or(' '))),
                },
                Some(b) => out.push(b),
            }
        }
    }

    fn read_regex(&mut self) -> Result<Tok, String> {
        let mut pattern = Vec::new();
        loop {
            match self.bump() {
                None | Some(b'\n') => return Err("unterminated regular expression".into()),
                Some(b'\\') => {
                    let next = self.bump().ok_or("unterminated regular expression")?;
                    if next == b'/' {
                        pattern.push(b'/');
                    } else {
                        pattern.push(b'\\');
                        pattern.push(next);
                    }
                }
                Some(b'/') => break,
                Some(b) => pattern.push(b),
            }
        }
        let mut nocase = false;
        let mut dotall = false;
        while let Some(b) = self.peek_byte(0) {
            match b {
                b'i' => nocase = true,
                b's' => dotall = true,
                _ => break,
            }
            self.bump();
        }
        if pattern.is_empty() {
            return Err("empty regular expression".into());
        }
        Ok(Tok::Regex { pattern: String::from_utf8(pattern).map_err(|_| "regular expression must be UTF-8")?, nocase, dotall })
    }

    fn read_number(&mut self) -> Result<Tok, String> {
        let start = self.pos;
        let value: i64 = if self.peek_byte(0) == Some(b'0') && matches!(self.peek_byte(1), Some(b'x' | b'X')) {
            self.bump();
            self.bump();
            let s = self.pos;
            while self.peek_byte(0).is_some_and(|b| b.is_ascii_hexdigit()) {
                self.bump();
            }
            let txt = std::str::from_utf8(&self.src[s..self.pos]).unwrap_or("");
            i64::from_str_radix(txt, 16).map_err(|_| "invalid hex number")?
        } else {
            while self.peek_byte(0).is_some_and(|b| b.is_ascii_digit()) {
                self.bump();
            }
            let txt = std::str::from_utf8(&self.src[start..self.pos]).unwrap_or("");
            txt.parse().map_err(|_| "invalid number")?
        };
        let mult = match (self.peek_byte(0), self.peek_byte(1)) {
            (Some(b'K'), Some(b'B')) => 1024,
            (Some(b'M'), Some(b'B')) => 1024 * 1024,
            _ => 1,
        };
        if mult > 1 {
            self.bump();
            self.bump();
        }
        Ok(Tok::Int(value.checked_mul(mult).ok_or("number too large")?))
    }

    pub fn next_token(&mut self) -> Result<Tok, String> {
        self.skip_ws_and_comments()?;
        let Some(b) = self.peek_byte(0) else {
            return Ok(Tok::Eof);
        };
        let two = |s: &mut Self, t: Tok| {
            s.bump();
            s.bump();
            Ok(t)
        };
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => Ok(Tok::Ident(self.ident_tail())),
            b'0'..=b'9' => self.read_number(),
            b'$' => {
                self.bump();
                let mut id = self.ident_tail();
                if self.peek_byte(0) == Some(b'*') {
                    self.bump();
                    id.push('*');
                }
                Ok(Tok::StringId(id))
            }
            b'#' => {
                self.bump();
                Ok(Tok::CountId(self.ident_tail()))
            }
            b'@' => {
                self.bump();
                Ok(Tok::OffsetId(self.ident_tail()))
            }
            b'!' if self.peek_byte(1) == Some(b'=') => two(self, Tok::Ne),
            b'!' => {
                self.bump();
                Ok(Tok::LengthId(self.ident_tail()))
            }
            b'"' => {
                self.bump();
                Ok(Tok::Str(self.read_string()?))
            }
            b'/' => {
                self.bump();
                self.read_regex()
            }
            b'{' => {
                self.bump();
                Ok(Tok::LBrace)
            }
            b'}' => {
                self.bump();
                Ok(Tok::RBrace)
            }
            b'(' => {
                self.bump();
                Ok(Tok::LParen)
            }
            b')' => {
                self.bump();
                Ok(Tok::RParen)
            }
            b'[' => {
                self.bump();
                Ok(Tok::LBracket)
            }
            b']' => {
                self.bump();
                Ok(Tok::RBracket)
            }
            b':' => {
                self.bump();
                Ok(Tok::Colon)
            }
            b',' => {
                self.bump();
                Ok(Tok::Comma)
            }
            b'.' if self.peek_byte(1) == Some(b'.') => two(self, Tok::DotDot),
            b'.' => {
                self.bump();
                Ok(Tok::Dot)
            }
            b'=' if self.peek_byte(1) == Some(b'=') => two(self, Tok::Eq),
            b'=' => {
                self.bump();
                Ok(Tok::Assign)
            }
            b'<' if self.peek_byte(1) == Some(b'=') => two(self, Tok::Le),
            b'<' if self.peek_byte(1) == Some(b'<') => two(self, Tok::Shl),
            b'<' => {
                self.bump();
                Ok(Tok::Lt)
            }
            b'>' if self.peek_byte(1) == Some(b'=') => two(self, Tok::Ge),
            b'>' if self.peek_byte(1) == Some(b'>') => two(self, Tok::Shr),
            b'>' => {
                self.bump();
                Ok(Tok::Gt)
            }
            b'+' => {
                self.bump();
                Ok(Tok::Plus)
            }
            b'-' => {
                self.bump();
                Ok(Tok::Minus)
            }
            b'*' => {
                self.bump();
                Ok(Tok::Star)
            }
            b'\\' => {
                self.bump();
                Ok(Tok::Backslash)
            }
            b'%' => {
                self.bump();
                Ok(Tok::Percent)
            }
            b'&' => {
                self.bump();
                Ok(Tok::Amp)
            }
            b'|' => {
                self.bump();
                Ok(Tok::Pipe)
            }
            b'^' => {
                self.bump();
                Ok(Tok::Caret)
            }
            b'~' => {
                self.bump();
                Ok(Tok::Tilde)
            }
            other => Err(format!("unexpected character '{}'", other as char)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens() {
        let mut lx = Lexer::new(r#"rule a { strings: $x = "a\x41\"" nocase $r = /ab\/c/is condition: #x > 2 and filesize < 2KB } // c"#);
        let mut toks = Vec::new();
        loop {
            let t = lx.next_token().unwrap();
            if t == Tok::Eof {
                break;
            }
            toks.push(t);
        }
        assert!(toks.contains(&Tok::Str(b"aA\"".to_vec())));
        assert!(toks.contains(&Tok::Regex { pattern: "ab/c".into(), nocase: true, dotall: true }));
        assert!(toks.contains(&Tok::CountId("x".into())));
        assert!(toks.contains(&Tok::Int(2048)));
    }
}
