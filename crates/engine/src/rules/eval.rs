//! Condition evaluation.

use super::ast::*;
use crate::util::{be_u16, be_u32, le_u16, le_u32};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Val {
    Int(i64),
    Bool(bool),
    Undef,
}

impl Val {
    pub fn truthy(self) -> bool {
        match self {
            Val::Bool(b) => b,
            Val::Int(i) => i != 0,
            Val::Undef => false,
        }
    }

    fn int(self) -> Option<i64> {
        match self {
            Val::Int(i) => Some(i),
            Val::Bool(b) => Some(b as i64),
            Val::Undef => None,
        }
    }
}

pub struct EvalCtx<'a> {
    /// Analysed content (may be shorter than the file).
    pub data: &'a [u8],
    pub filesize: u64,
    pub entrypoint: Option<u64>,
    /// Matches for each string of the rule: `(offset, length)`.
    pub hits: &'a [Vec<(u64, u32)>],
    /// Results of rules evaluated earlier.
    pub rule_results: &'a [bool],
}

pub fn eval(e: &Expr, cx: &EvalCtx) -> Val {
    match e {
        Expr::Bool(b) => Val::Bool(*b),
        Expr::Int(i) => Val::Int(*i),
        Expr::Filesize => Val::Int(cx.filesize as i64),
        Expr::Entrypoint => cx.entrypoint.map(|v| Val::Int(v as i64)).unwrap_or(Val::Undef),
        Expr::Str(i) => Val::Bool(!cx.hits[*i].is_empty()),
        Expr::StrAt(i, off) => match eval(off, cx).int() {
            Some(o) => Val::Bool(cx.hits[*i].iter().any(|h| h.0 as i64 == o)),
            None => Val::Undef,
        },
        Expr::StrIn(i, lo, hi) => match (eval(lo, cx).int(), eval(hi, cx).int()) {
            (Some(lo), Some(hi)) => Val::Bool(cx.hits[*i].iter().any(|h| (h.0 as i64) >= lo && (h.0 as i64) <= hi)),
            _ => Val::Undef,
        },
        Expr::Count(i) => Val::Int(cx.hits[*i].len() as i64),
        Expr::CountIn(i, lo, hi) => match (eval(lo, cx).int(), eval(hi, cx).int()) {
            (Some(lo), Some(hi)) => Val::Int(cx.hits[*i].iter().filter(|h| (h.0 as i64) >= lo && (h.0 as i64) <= hi).count() as i64),
            _ => Val::Undef,
        },
        Expr::Offset(i, idx) => nth_hit(cx, *i, idx).map(|h| Val::Int(h.0 as i64)).unwrap_or(Val::Undef),
        Expr::Length(i, idx) => nth_hit(cx, *i, idx).map(|h| Val::Int(h.1 as i64)).unwrap_or(Val::Undef),
        Expr::Of { quant, strings, range } => {
            let window = match range {
                Some((lo, hi)) => match (eval(lo, cx).int(), eval(hi, cx).int()) {
                    (Some(lo), Some(hi)) => Some((lo, hi)),
                    _ => return Val::Undef,
                },
                None => None,
            };
            let matched = strings
                .iter()
                .filter(|&&i| match window {
                    None => !cx.hits[i].is_empty(),
                    Some((lo, hi)) => cx.hits[i].iter().any(|h| (h.0 as i64) >= lo && (h.0 as i64) <= hi),
                })
                .count() as i64;
            let total = strings.len() as i64;
            Val::Bool(match quant {
                Quant::Any => matched >= 1,
                Quant::All => matched == total,
                Quant::None => matched == 0,
                Quant::Count(n) => matched >= *n,
                Quant::Percent(p) => total > 0 && matched * 100 >= p * total,
            })
        }
        Expr::ReadInt(kind, off) => {
            let Some(o) = eval(off, cx).int() else { return Val::Undef };
            if o < 0 {
                return Val::Undef;
            }
            read_int(cx.data, o as usize, *kind).map(Val::Int).unwrap_or(Val::Undef)
        }
        Expr::RuleRef(i) => Val::Bool(cx.rule_results.get(*i).copied().unwrap_or(false)),
        Expr::Not(x) => match eval(x, cx) {
            Val::Undef => Val::Undef,
            v => Val::Bool(!v.truthy()),
        },
        Expr::And(a, b) => {
            if !eval(a, cx).truthy() {
                return Val::Bool(false);
            }
            Val::Bool(eval(b, cx).truthy())
        }
        Expr::Or(a, b) => {
            if eval(a, cx).truthy() {
                return Val::Bool(true);
            }
            Val::Bool(eval(b, cx).truthy())
        }
        Expr::Cmp(op, a, b) => match (eval(a, cx).int(), eval(b, cx).int()) {
            (Some(x), Some(y)) => Val::Bool(match op {
                CmpOp::Eq => x == y,
                CmpOp::Ne => x != y,
                CmpOp::Lt => x < y,
                CmpOp::Le => x <= y,
                CmpOp::Gt => x > y,
                CmpOp::Ge => x >= y,
            }),
            _ => Val::Undef,
        },
        Expr::Bin(op, a, b) => match (eval(a, cx).int(), eval(b, cx).int()) {
            (Some(x), Some(y)) => match op {
                BinOp::Add => Val::Int(x.wrapping_add(y)),
                BinOp::Sub => Val::Int(x.wrapping_sub(y)),
                BinOp::Mul => Val::Int(x.wrapping_mul(y)),
                BinOp::Div => x.checked_div(y).map(Val::Int).unwrap_or(Val::Undef),
                BinOp::Mod => x.checked_rem(y).map(Val::Int).unwrap_or(Val::Undef),
                BinOp::And => Val::Int(x & y),
                BinOp::Or => Val::Int(x | y),
                BinOp::Xor => Val::Int(x ^ y),
                BinOp::Shl => Val::Int(if (0..64).contains(&y) { x.wrapping_shl(y as u32) } else { 0 }),
                BinOp::Shr => Val::Int(if (0..64).contains(&y) { x.wrapping_shr(y as u32) } else { 0 }),
            },
            _ => Val::Undef,
        },
        Expr::Neg(x) => eval(x, cx).int().map(|v| Val::Int(v.wrapping_neg())).unwrap_or(Val::Undef),
        Expr::BitNot(x) => eval(x, cx).int().map(|v| Val::Int(!v)).unwrap_or(Val::Undef),
    }
}

fn nth_hit<'a>(cx: &'a EvalCtx, i: usize, idx: &Expr) -> Option<&'a (u64, u32)> {
    let n = eval(idx, cx).int()?;
    if n < 1 {
        return None;
    }
    cx.hits[i].get((n - 1) as usize)
}

fn read_int(data: &[u8], off: usize, kind: IntKind) -> Option<i64> {
    Some(match kind {
        IntKind::U8 => *data.get(off)? as i64,
        IntKind::I8 => *data.get(off)? as i8 as i64,
        IntKind::U16 => le_u16(data, off)? as i64,
        IntKind::I16 => le_u16(data, off)? as i16 as i64,
        IntKind::U32 => le_u32(data, off)? as i64,
        IntKind::I32 => le_u32(data, off)? as i32 as i64,
        IntKind::U16Be => be_u16(data, off)? as i64,
        IntKind::I16Be => be_u16(data, off)? as i16 as i64,
        IntKind::U32Be => be_u32(data, off)? as i64,
        IntKind::I32Be => be_u32(data, off)? as i32 as i64,
    })
}
