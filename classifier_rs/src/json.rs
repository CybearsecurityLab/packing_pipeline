use std::borrow::Cow;

pub enum V<'a> {
    Null,
    Bool(bool),
    Int(i128),
    Big,
    Float,
    Str(Cow<'a, str>),
    Arr(Vec<V<'a>>),
    Obj(Vec<(Cow<'a, str>, V<'a>)>),
}

impl<'a> V<'a> {
    pub fn get(&self, key: &str) -> Option<&V<'a>> {
        match self {
            V::Obj(items) => items.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

const MAX_DEPTH: u32 = 64;

struct P<'a> {
    b: &'a [u8],
    i: usize,
    depth: u32,
}

impl<'a> P<'a> {
    #[inline]
    fn ws(&mut self) {
        while self.i < self.b.len() {
            match self.b[self.i] {
                b' ' | b'\t' | b'\n' | b'\r' => self.i += 1,
                _ => break,
            }
        }
    }

    #[inline]
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn value(&mut self) -> Option<V<'a>> {
        self.ws();
        match self.peek()? {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => self.string().map(V::Str),
            b't' => self.literal(b"true", V::Bool(true)),
            b'f' => self.literal(b"false", V::Bool(false)),
            b'n' => self.literal(b"null", V::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }

    fn literal(&mut self, text: &[u8], v: V<'a>) -> Option<V<'a>> {
        if self.b.len() >= self.i + text.len() && &self.b[self.i..self.i + text.len()] == text {
            self.i += text.len();
            Some(v)
        } else {
            None
        }
    }

    fn object(&mut self) -> Option<V<'a>> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return None;
        }
        self.i += 1;
        let mut items = Vec::new();
        self.ws();
        if self.peek()? == b'}' {
            self.i += 1;
            self.depth -= 1;
            return Some(V::Obj(items));
        }
        loop {
            self.ws();
            if self.peek()? != b'"' {
                return None;
            }
            let key = self.string()?;
            self.ws();
            if self.peek()? != b':' {
                return None;
            }
            self.i += 1;
            let value = self.value()?;
            items.push((key, value));
            self.ws();
            match self.peek()? {
                b',' => self.i += 1,
                b'}' => {
                    self.i += 1;
                    break;
                }
                _ => return None,
            }
        }
        self.depth -= 1;
        Some(V::Obj(items))
    }

    fn array(&mut self) -> Option<V<'a>> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return None;
        }
        self.i += 1;
        let mut items = Vec::new();
        self.ws();
        if self.peek()? == b']' {
            self.i += 1;
            self.depth -= 1;
            return Some(V::Arr(items));
        }
        loop {
            let value = self.value()?;
            items.push(value);
            self.ws();
            match self.peek()? {
                b',' => self.i += 1,
                b']' => {
                    self.i += 1;
                    break;
                }
                _ => return None,
            }
        }
        self.depth -= 1;
        Some(V::Arr(items))
    }

    fn hex4(&mut self) -> Option<u32> {
        if self.i + 4 > self.b.len() {
            return None;
        }
        let mut v = 0u32;
        for k in 0..4 {
            let c = self.b[self.i + k];
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return None,
            };
            v = v * 16 + d as u32;
        }
        self.i += 4;
        Some(v)
    }

    fn string(&mut self) -> Option<Cow<'a, str>> {
        self.i += 1;
        let start = self.i;
        let mut non_ascii = false;
        loop {
            let c = *self.b.get(self.i)?;
            if c == b'"' {
                let raw = &self.b[start..self.i];
                self.i += 1;
                let s = if non_ascii {
                    std::str::from_utf8(raw).ok()?
                } else {
                    unsafe { std::str::from_utf8_unchecked(raw) }
                };
                return Some(Cow::Borrowed(s));
            }
            if c == b'\\' {
                break;
            }
            if c < 0x20 {
                return None;
            }
            if c >= 0x80 {
                non_ascii = true;
            }
            self.i += 1;
        }
        let mut out: Vec<u8> = self.b[start..self.i].to_vec();
        loop {
            let c = *self.b.get(self.i)?;
            if c == b'"' {
                self.i += 1;
                return String::from_utf8(out).ok().map(Cow::Owned);
            }
            if c < 0x20 {
                return None;
            }
            if c != b'\\' {
                out.push(c);
                self.i += 1;
                continue;
            }
            self.i += 1;
            let e = *self.b.get(self.i)?;
            self.i += 1;
            match e {
                b'"' => out.push(b'"'),
                b'\\' => out.push(b'\\'),
                b'/' => out.push(b'/'),
                b'b' => out.push(8),
                b'f' => out.push(12),
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                b'u' => {
                    let hi = self.hex4()?;
                    let cp = if (0xD800..0xDC00).contains(&hi) {
                        if self.b.get(self.i) != Some(&b'\\') || self.b.get(self.i + 1) != Some(&b'u') {
                            return None;
                        }
                        self.i += 2;
                        let lo = self.hex4()?;
                        if !(0xDC00..0xE000).contains(&lo) {
                            return None;
                        }
                        0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                    } else if (0xDC00..0xE000).contains(&hi) {
                        return None;
                    } else {
                        hi
                    };
                    let ch = char::from_u32(cp)?;
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                _ => return None,
            }
        }
    }

    fn number(&mut self) -> Option<V<'a>> {
        let negative = self.b[self.i] == b'-';
        if negative {
            self.i += 1;
        }
        let digits_start = self.i;
        match self.peek()? {
            b'0' => self.i += 1,
            b'1'..=b'9' => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return None,
        }
        let digits_end = self.i;
        let mut float = false;
        if self.peek() == Some(b'.') {
            self.i += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return None;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
            float = true;
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.i += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return None;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
            float = true;
        }
        let digits = &self.b[digits_start..digits_end];
        if digits.len() > 100 {
            return None;
        }
        if float {
            return Some(V::Float);
        }
        if digits.len() > 38 {
            return Some(V::Big);
        }
        let mut v: i128 = 0;
        for &d in digits {
            v = v * 10 + (d - b'0') as i128;
        }
        Some(V::Int(if negative { -v } else { v }))
    }
}

pub trait Fields<'a> {
    fn field(&self, key: &str) -> Option<&V<'a>>;
}

impl<'a> Fields<'a> for V<'a> {
    #[inline]
    fn field(&self, key: &str) -> Option<&V<'a>> {
        self.get(key)
    }
}

pub const SLOTS: usize = 19;

#[inline(always)]
pub fn slot(key: &str) -> Option<usize> {
    Some(match key {
        "seq" => 0,
        "event" => 1,
        "action" => 2,
        "pid" => 3,
        "reason" => 4,
        "after_cutoff" => 5,
        "job_matches" => 6,
        "parent_pid" => 7,
        "role" => 8,
        "tid" => 9,
        "file_id" => 10,
        "file_offset" => 11,
        "size" => 12,
        "address" => 13,
        "target_pid" => 14,
        "invalidated_physical_spans" => 15,
        "physical_spans" => 16,
        "physical_address" => 17,
        "source_layer" => 18,
        _ => return None,
    })
}

pub struct Event<'a> {
    pub slots: [Option<V<'a>>; SLOTS],
}

impl<'a> Fields<'a> for Event<'a> {
    #[inline(always)]
    fn field(&self, key: &str) -> Option<&V<'a>> {
        match slot(key) {
            Some(i) => self.slots[i].as_ref(),
            None => None,
        }
    }
}

pub fn parse_event(line: &[u8]) -> Option<Event<'_>> {
    let mut p = P { b: line, i: 0, depth: 0 };
    p.ws();
    if p.peek()? != b'{' {
        return None;
    }
    let mut event = Event { slots: std::array::from_fn(|_| None) };
    p.depth = 1;
    p.i += 1;
    p.ws();
    if p.peek()? == b'}' {
        p.i += 1;
    } else {
        loop {
            p.ws();
            if p.peek()? != b'"' {
                return None;
            }
            let key = p.string()?;
            p.ws();
            if p.peek()? != b':' {
                return None;
            }
            p.i += 1;
            let value = p.value()?;
            if let Some(i) = slot(&key) {
                event.slots[i] = Some(value);
            }
            p.ws();
            match p.peek()? {
                b',' => p.i += 1,
                b'}' => {
                    p.i += 1;
                    break;
                }
                _ => return None,
            }
        }
    }
    p.ws();
    if p.i != line.len() {
        return None;
    }
    Some(event)
}
