//! Bounded, source-preserving words for static inspection and completion. This is not the risk
//! parser: it never classifies permission or executes expansion. Unsupported syntax stays visible.

const MAX_BYTES: usize = 200 * 1024;
const MAX_TOKENS: usize = 4096;

#[derive(Clone, Debug)]
pub(crate) struct Word<'a> {
    pub raw: &'a str,
    pub start: usize,
    pub end: usize,
    pub line: u32,
}

impl Word<'_> {
    /// Quote removal for literal command names/arguments only. No expansion, including ~.
    pub fn literal(&self) -> Option<String> {
        let mut out = String::new();
        let mut chars = self.raw.chars().peekable();
        let mut quote = None;
        while let Some(c) = chars.next() {
            match (quote, c) {
                (Some('\''), '\'') | (Some('"'), '"') => quote = None,
                (Some('\''), _) => out.push(c),
                (_, '\\') => {
                    let next = chars.next()?;
                    if next != '\n' {
                        if quote == Some('"') && !"$`\"\\".contains(next) { out.push('\\'); }
                        out.push(next);
                    }
                }
                (_, '$' | '`') => return None,
                (None, '\'' | '"') => quote = Some(c),
                (None, '*' | '?' | '[' | '~') => return None,
                _ => out.push(c),
            }
        }
        quote.is_none().then_some(out)
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Token<'a> {
    Word(Word<'a>),
    Op(&'a str, u32),
}

pub(crate) struct Tokens<'a> {
    pub tokens: Vec<Token<'a>>,
    pub error: Option<(u32, &'static str)>,
}

/// Keeps raw quote/expansion boundaries. Incomplete words are returned for completion; inspection
/// must respect `error` and must never treat a partial word as an analyzed statement.
pub(crate) fn scan(src: &str) -> Tokens<'_> {
    if src.len() > MAX_BYTES {
        return Tokens { tokens: Vec::new(), error: Some((1, "script exceeds the inspection size limit")) };
    }
    let chars: Vec<(usize, char)> = src.char_indices().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    let mut line = 1;
    let byte = |i: usize| chars.get(i).map_or(src.len(), |(b, _)| *b);
    while i < chars.len() {
        if tokens.len() >= MAX_TOKENS {
            return Tokens { tokens, error: Some((line, "script exceeds the inspection token limit")) };
        }
        let c = chars[i].1;
        if c == ' ' || c == '\t' || c == '\r' { i += 1; continue; }
        if c == '#' {
            while i < chars.len() && chars[i].1 != '\n' { i += 1; }
            continue;
        }
        if ";\n|&<>(){}".contains(c) {
            let begin = i;
            let at = line;
            i += 1;
            if i < chars.len() && (matches!(c, '|' | '&' | '<' | '>') && chars[i].1 == c || c == ';' && chars[i].1 == ';') { i += 1; }
            tokens.push(Token::Op(&src[byte(begin)..byte(i)], at));
            if c == '\n' { line += 1; }
            continue;
        }
        let begin = i;
        let at = line;
        let mut quote = None;
        let mut incomplete = None;
        while i < chars.len() {
            let c = chars[i].1;
            if quote.is_none() && (c.is_ascii_whitespace() || ";|&<>(){}".contains(c)) { break; }
            if c == '\n' { line += 1; }
            if quote == Some('\'') {
                if c == '\'' { quote = None; }
                i += 1;
                continue;
            }
            if c == '\\' {
                i += 1;
                if i < chars.len() {
                    if chars[i].1 == '\n' { line += 1; }
                    i += 1;
                } else { incomplete = Some("unfinished escape"); }
                continue;
            }
            if c == '\'' && quote.is_none() { quote = Some(c); i += 1; continue; }
            if c == '"' { quote = if quote.is_none() { Some(c) } else { None }; i += 1; continue; }
            if c == '`' || c == '$' && chars.get(i + 1).is_some_and(|(_, c)| matches!(c, '(' | '{')) {
                let backtick = c == '`';
                let open = if backtick { '`' } else { chars[i + 1].1 };
                let close = match open { '(' => ')', '{' => '}', _ => '`' };
                i += if backtick { 1 } else { 2 };
                let mut depth = 1;
                let mut inner_quote = None;
                while i < chars.len() && depth > 0 {
                    let c = chars[i].1;
                    if c == '\n' { line += 1; }
                    if c == '\\' && inner_quote != Some('\'') {
                        i += 1;
                        if chars.get(i).is_some_and(|(_, c)| *c == '\n') { line += 1; }
                    } else if inner_quote.is_some() {
                        if inner_quote == Some(c) { inner_quote = None; }
                    } else if c == close {
                        depth -= 1;
                    } else if !backtick && c == open {
                        depth += 1;
                    } else if matches!(c, '\'' | '"') {
                        inner_quote = Some(c);
                    }
                    i += 1;
                }
                if depth > 0 { incomplete = Some("unfinished substitution"); }
                continue;
            }
            i += 1;
        }
        tokens.push(Token::Word(Word { raw: &src[byte(begin)..byte(i)], start: byte(begin), end: byte(i), line: at }));
        if let Some(reason) = incomplete.or(quote.map(|_| "unfinished quote")) {
            return Tokens { tokens, error: Some((at, reason)) };
        }
    }
    Tokens { tokens, error: None }
}
