//! Syntax tree of the rule language.

use crate::patterns::HexToken;

#[derive(Debug, Clone, PartialEq)]
pub enum MetaValue {
    Str(String),
    Int(i64),
    Bool(bool),
}

impl MetaValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            MetaValue::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            MetaValue::Int(i) => Some(*i),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Modifiers {
    pub nocase: bool,
    pub wide: bool,
    pub ascii: bool,
    pub fullword: bool,
    pub private: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StringValue {
    Text(Vec<u8>),
    Hex(Vec<HexToken>),
    Regex { pattern: String, nocase: bool, dotall: bool },
}

#[derive(Debug, Clone, PartialEq)]
pub struct StringDef {
    /// Identifier without `$` (anonymous strings get a generated name).
    pub id: String,
    pub value: StringValue,
    pub mods: Modifiers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntKind {
    U8,
    U16,
    U32,
    I8,
    I16,
    I32,
    U16Be,
    U32Be,
    I16Be,
    I32Be,
}

impl IntKind {
    pub fn from_name(name: &str) -> Option<IntKind> {
        Some(match name {
            "uint8" => IntKind::U8,
            "uint16" => IntKind::U16,
            "uint32" => IntKind::U32,
            "int8" => IntKind::I8,
            "int16" => IntKind::I16,
            "int32" => IntKind::I32,
            "uint8be" => IntKind::U8,
            "uint16be" => IntKind::U16Be,
            "uint32be" => IntKind::U32Be,
            "int8be" => IntKind::I8,
            "int16be" => IntKind::I16Be,
            "int32be" => IntKind::I32Be,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    And,
    Or,
    Xor,
    Shl,
    Shr,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Quant {
    Any,
    All,
    None,
    Count(i64),
    Percent(i64),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Bool(bool),
    Int(i64),
    Filesize,
    Entrypoint,
    /// `$a`
    Str(usize),
    /// `$a at <expr>`
    StrAt(usize, Box<Expr>),
    /// `$a in (<lo>..<hi>)`
    StrIn(usize, Box<Expr>, Box<Expr>),
    /// `#a`
    Count(usize),
    /// `#a in (<lo>..<hi>)`
    CountIn(usize, Box<Expr>, Box<Expr>),
    /// `@a[i]`
    Offset(usize, Box<Expr>),
    /// `!a[i]`
    Length(usize, Box<Expr>),
    /// `<quant> of (<strings>) [in (<lo>..<hi>)]`
    Of {
        quant: Quant,
        strings: Vec<usize>,
        range: Option<(Box<Expr>, Box<Expr>)>,
    },
    /// `uint32(<offset>)` and friends.
    ReadInt(IntKind, Box<Expr>),
    /// Reference to a previously defined rule.
    RuleRef(usize),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Cmp(CmpOp, Box<Expr>, Box<Expr>),
    Bin(BinOp, Box<Expr>, Box<Expr>),
    Neg(Box<Expr>),
    BitNot(Box<Expr>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub name: String,
    pub tags: Vec<String>,
    pub private: bool,
    pub global: bool,
    pub meta: Vec<(String, MetaValue)>,
    pub strings: Vec<StringDef>,
    pub condition: Expr,
    pub line: usize,
}

impl Rule {
    pub fn meta(&self, key: &str) -> Option<&MetaValue> {
        self.meta.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v)
    }
}
