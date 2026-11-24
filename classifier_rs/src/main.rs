mod json;

use json::{Event, Fields, V};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::hash::{BuildHasherDefault, Hasher};
use std::io::{BufRead, BufReader, Write};

#[derive(Default, Clone, Copy)]
pub struct Fx(u64);

impl Hasher for Fx {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u64(b as u64);
        }
    }
    #[inline]
    fn write_u8(&mut self, x: u8) {
        self.write_u64(x as u64);
    }
    #[inline]
    fn write_u32(&mut self, x: u32) {
        self.write_u64(x as u64);
    }
    #[inline]
    fn write_i64(&mut self, x: i64) {
        self.write_u64(x as u64);
    }
    #[inline]
    fn write_usize(&mut self, x: usize) {
        self.write_u64(x as u64);
    }
    #[inline]
    fn write_u64(&mut self, x: u64) {
        self.0 = (self.0.rotate_left(26) ^ x).wrapping_mul(0xf135_7aea_2e62_a9c5);
    }
    #[inline]
    fn finish(&self) -> u64 {
        self.0.rotate_left(26)
    }
}

type B = BuildHasherDefault<Fx>;
type Map<K, T> = HashMap<K, T, B>;
type Set<K> = HashSet<K, B>;


const U: u8 = b'U';
const R: u8 = b'R';
const W: u8 = b'W';
const X: u8 = b'X';
const O: u8 = b'O';

pub enum Stop {
    Fallback(&'static str),
    Unknown,
    NonMonotonic,
    Value(&'static str),
    Key(&'static str),
}

type Res<T> = Result<T, Stop>;

#[inline]
fn opt<'b, 'a, E: Fields<'a>>(e: &'b E, k: &str) -> Option<&'b V<'a>> {
    e.field(k)
}

#[inline]
fn req<'b, 'a, E: Fields<'a>>(e: &'b E, k: &'static str) -> Res<&'b V<'a>> {
    e.field(k).ok_or(Stop::Key(k))
}

#[inline]
fn int(v: &V) -> Res<i128> {
    match v {
        V::Int(i) => Ok(*i),
        _ => Err(Stop::Fallback("non-integer value in an int() field")),
    }
}

fn base0(s: &str) -> Option<i128> {
    let b = s.as_bytes();
    if b.is_empty() {
        return None;
    }
    let (radix, digits) = if b.len() >= 2 && b[0] == b'0' && matches!(b[1], b'x' | b'X') {
        (16, &b[2..])
    } else if b.len() >= 2 && b[0] == b'0' && matches!(b[1], b'o' | b'O') {
        (8, &b[2..])
    } else if b.len() >= 2 && b[0] == b'0' && matches!(b[1], b'b' | b'B') {
        (2, &b[2..])
    } else if b[0] == b'0' {
        if b.iter().all(|&c| c == b'0') {
            return Some(0);
        }
        return None;
    } else {
        (10, b)
    };
    if digits.is_empty() || digits.len() > 30 {
        return None;
    }
    let mut v: i128 = 0;
    for &c in digits {
        let d = (c as char).to_digit(radix)? as i128;
        v = v * radix as i128 + d;
    }
    Some(v)
}

#[inline]
fn number(v: &V) -> Res<i128> {
    match v {
        V::Int(i) => Ok(*i),
        V::Str(s) => base0(s).ok_or(Stop::Fallback("unsupported string in number() field")),
        _ => Err(Stop::Fallback("unsupported value in number() field")),
    }
}

#[inline]
fn small(x: i128) -> Res<i64> {
    if (-(1i128 << 62)..=(1i128 << 62)).contains(&x) {
        Ok(x as i64)
    } else {
        Err(Stop::Fallback("integer outside the supported range"))
    }
}

#[inline]
fn span_u64(base: i128, len: i128) -> Res<u64> {
    if base < 0 || base > u64::MAX as i128 || (len > 0 && base + len - 1 > u64::MAX as i128) {
        Err(Stop::Fallback("address outside the u64 range"))
    } else {
        Ok(base as u64)
    }
}

#[inline]
fn event_size(e: &Event) -> Res<i128> {
    let size = match opt(e, "size") {
        None => 1,
        Some(v) => int(v)?,
    };
    if !(0..=(1i128 << 32)).contains(&size) {
        return Err(Stop::Fallback("event size outside the supported range"));
    }
    Ok(size)
}

const NONE: i32 = i32::MIN;
const LAYER_LIMIT: i32 = 1 << 30;
const F_EXEC: u8 = 1;
const F_RS: u8 = 2;
const F_LISTED: u8 = 4;
const F_NF: u8 = 8;

type SKey = (u32, i32, u64);

#[derive(Clone, Copy)]
struct Ent {
    layer: i32,
    state: u8,
    flags: u8,
}

#[derive(Default)]
enum Layers {
    #[default]
    Zero,
    One(Ent),
    Many(Box<Vec<Ent>>),
}

impl Layers {
    #[inline]
    fn as_slice(&self) -> &[Ent] {
        match self {
            Layers::Zero => &[],
            Layers::One(e) => std::slice::from_ref(e),
            Layers::Many(v) => v,
        }
    }

    #[inline]
    fn find(&self, layer: i32) -> Option<&Ent> {
        self.as_slice().iter().find(|e| e.layer == layer)
    }

    #[inline]
    fn find_mut(&mut self, layer: i32) -> Option<&mut Ent> {
        match self {
            Layers::Zero => None,
            Layers::One(e) => {
                if e.layer == layer {
                    Some(e)
                } else {
                    None
                }
            }
            Layers::Many(v) => v.iter_mut().find(|e| e.layer == layer),
        }
    }

    #[inline]
    fn upsert(&mut self, layer: i32) -> (&mut Ent, bool) {
        let existed = self.find(layer).is_some();
        if !existed {
            let fresh = Ent { layer, state: 0, flags: 0 };
            match self {
                Layers::Zero => *self = Layers::One(fresh),
                Layers::One(e) => {
                    let first = *e;
                    *self = Layers::Many(Box::new(vec![first, fresh]));
                }
                Layers::Many(v) => v.push(fresh),
            }
        }
        (self.find_mut(layer).unwrap(), existed)
    }
}

const FEW: usize = 16;

enum Tiny<T: Copy + Eq + std::hash::Hash> {
    Zero,
    One(T),
    Few(Box<Vec<T>>),
    Lots(Box<Set<T>>),
}

impl<T: Copy + Eq + std::hash::Hash> Default for Tiny<T> {
    fn default() -> Self {
        Tiny::Zero
    }
}

impl<T: Copy + Eq + std::hash::Hash> Tiny<T> {
    #[inline]
    fn insert(&mut self, v: T) {
        match self {
            Tiny::Zero => *self = Tiny::One(v),
            Tiny::One(x) => {
                if *x != v {
                    let first = *x;
                    *self = Tiny::Few(Box::new(vec![first, v]));
                }
            }
            Tiny::Few(items) => {
                if !items.contains(&v) {
                    if items.len() < FEW {
                        items.push(v);
                    } else {
                        let mut set: Set<T> = items.iter().copied().collect();
                        set.insert(v);
                        *self = Tiny::Lots(Box::new(set));
                    }
                }
            }
            Tiny::Lots(set) => {
                set.insert(v);
            }
        }
    }

    #[inline]
    fn is_empty(&self) -> bool {
        matches!(self, Tiny::Zero)
    }

    #[inline]
    fn for_each(&self, mut f: impl FnMut(T)) {
        match self {
            Tiny::Zero => {}
            Tiny::One(x) => f(*x),
            Tiny::Few(items) => items.iter().for_each(|&x| f(x)),
            Tiny::Lots(set) => set.iter().for_each(|&x| f(x)),
        }
    }

    #[inline]
    fn any(&self, mut f: impl FnMut(T) -> bool) -> bool {
        match self {
            Tiny::Zero => false,
            Tiny::One(x) => f(*x),
            Tiny::Few(items) => items.iter().any(|&x| f(x)),
            Tiny::Lots(set) => set.iter().any(|&x| f(x)),
        }
    }
}

#[derive(Default)]
struct MemRec {
    wl: i32,
    writers: Tiny<u32>,
    layers: Layers,
}

impl MemRec {
    fn new() -> Self {
        MemRec { wl: NONE, writers: Tiny::Zero, layers: Layers::Zero }
    }
}

struct PhysRec {
    wl: i32,
    writers: Tiny<u32>,
    locations: Tiny<SKey>,
}

impl PhysRec {
    fn new() -> Self {
        PhysRec { wl: NONE, writers: Tiny::Zero, locations: Tiny::Zero }
    }
}

struct FileRec {
    layer: i32,
    writers: Tiny<u32>,
    version: u64,
}

#[derive(Default)]
struct Ctx {
    frame: i64,
    new_frame: Vec<u64>,
    resettable: Vec<u64>,
}

#[inline]
fn or_minus_one(v: i32) -> i32 {
    if v == NONE {
        -1
    } else {
        v
    }
}

#[inline]
fn layer_of(v: i128) -> Res<i32> {
    if (-(LAYER_LIMIT as i128)..=(LAYER_LIMIT as i128)).contains(&v) {
        Ok(v as i32)
    } else {
        Err(Stop::Fallback("layer outside the supported range"))
    }
}

fn ranges(mut addresses: Vec<u64>) -> Vec<(u64, u64)> {
    addresses.sort_unstable();
    addresses.dedup();
    let mut out: Vec<(u64, u64)> = Vec::new();
    for a in addresses {
        match out.last_mut() {
            Some(last) if last.1 + 1 == a => last.1 = a,
            _ => out.push((a, a)),
        }
    }
    out
}

#[derive(Default)]
struct St {
    pid_ids: Map<i64, u32>,
    pid_values: Vec<i64>,
    mem: Map<(u32, u64), MemRec>,
    phys: Map<u64, PhysRec>,
    files: Map<(u32, u64), FileRec>,
    ctx: Map<(u32, i32), Ctx>,
    block_ids: Map<SKey, u32>,
    blocks: Vec<SKey>,
    packer: Vec<bool>,
    unique: Set<(u32, u64, i64)>,
    sequence: Vec<u32>,
    frame_written: Map<(u32, i32, i64), Vec<(u64, u64)>>,
    frame_blocks: Map<(u32, i32, i64), u64>,
    repacked: Set<SKey>,
    last_block: Map<(u32, i64), u32>,
    threads: Set<(u32, i64)>,
    interactions: Set<(u32, u32)>,
    root_pid: Option<i64>,
    last_sequence: i128,
    cross_process_activity: bool,
    mapped_applied: Map<(u32, u64), ((u32, u64), u64)>,
    file_ids: HashMap<String, u32>,
    file_int_ids: Map<i128, u32>,
    pks: Vec<Option<u64>>,
    affected: Vec<SKey>,
    sources: Vec<u32>,
    internal_error: bool,
}

impl St {
    fn pid(&mut self, value: i64) -> u32 {
        if let Some(&id) = self.pid_ids.get(&value) {
            return id;
        }
        let id = self.pid_values.len() as u32;
        self.pid_values.push(value);
        self.pid_ids.insert(value, id);
        id
    }

    fn block(&mut self, key: SKey) -> u32 {
        if let Some(&id) = self.block_ids.get(&key) {
            return id;
        }
        let id = self.blocks.len() as u32;
        self.blocks.push(key);
        self.packer.push(false);
        self.block_ids.insert(key, id);
        id
    }

    fn intern(&mut self, s: &str) -> u32 {
        if let Some(&id) = self.file_ids.get(s) {
            return id;
        }
        let id = self.file_ids.len() as u32;
        self.file_ids.insert(s.to_string(), id);
        id
    }

    fn file_key(&mut self, v: &V) -> Res<u32> {
        match v {
            V::Str(s) => Ok(self.intern(s)),
            V::Int(i) => {
                if let Some(&id) = self.file_int_ids.get(i) {
                    return Ok(id);
                }
                let id = self.intern(&i.to_string());
                self.file_int_ids.insert(*i, id);
                Ok(id)
            }
            V::Bool(true) => Ok(self.intern("True")),
            V::Bool(false) => Ok(self.intern("False")),
            V::Null => Ok(self.intern("None")),
            _ => Err(Stop::Fallback("unsupported file_id value")),
        }
    }

    fn physical_keys(&mut self, e: &Event, size: usize) -> Res<()> {
        self.pks.clear();
        let spans = match opt(e, "physical_spans") {
            None | Some(V::Null) => None,
            Some(V::Arr(items)) => Some(items),
            Some(_) => return Err(Stop::Fallback("unsupported physical_spans value")),
        };
        match spans {
            None => match opt(e, "physical_address") {
                None | Some(V::Null) => self.pks.resize(size, None),
                Some(base) => {
                    let base = number(base)?;
                    let base = span_u64(base, size as i128)?;
                    for offset in 0..size as u64 {
                        self.pks.push(Some(base + offset));
                    }
                }
            },
            Some(items) => {
                self.pks.resize(size, None);
                for span in items {
                    if !matches!(span, V::Obj(_)) {
                        return Err(Stop::Fallback("unsupported physical span value"));
                    }
                    let offset = int(req(span, "offset")?)?;
                    let span_size = int(req(span, "size")?)?;
                    let address = number(req(span, "address")?)?;
                    if offset < 0 || span_size <= 0 || offset + span_size > size as i128 {
                        return Err(Stop::Value("physical span lies outside its event"));
                    }
                    let address = span_u64(address, span_size)?;
                    for relative in 0..span_size as u64 {
                        let index = offset as usize + relative as usize;
                        if self.pks[index].is_some() {
                            return Err(Stop::Value("physical spans overlap"));
                        }
                        self.pks[index] = Some(address + relative);
                    }
                }
                if self.pks.iter().any(|v| v.is_none()) {
                    return Err(Stop::Value("physical spans do not cover the complete event"));
                }
            }
        }
        Ok(())
    }

    fn invalidated_physical_keys(&mut self, e: &Event, size: usize) -> Res<()> {
        self.pks.clear();
        self.pks.resize(size, None);
        let items = match opt(e, "invalidated_physical_spans") {
            None => return Ok(()),
            Some(V::Arr(items)) => items,
            Some(_) => return Err(Stop::Fallback("unsupported invalidated_physical_spans value")),
        };
        for span in items {
            if !matches!(span, V::Obj(_)) {
                return Err(Stop::Fallback("unsupported invalidated physical span value"));
            }
            let offset = int(req(span, "offset")?)?;
            let span_size = int(req(span, "size")?)?;
            let address = number(req(span, "address")?)?;
            if offset < 0 || span_size <= 0 || offset + span_size > size as i128 {
                return Err(Stop::Value("invalidated physical span lies outside its event"));
            }
            let address = span_u64(address, span_size)?;
            for relative in 0..span_size as u64 {
                let index = offset as usize + relative as usize;
                if self.pks[index].is_some() {
                    return Err(Stop::Value("invalidated physical spans overlap"));
                }
                self.pks[index] = Some(address + relative);
            }
        }
        Ok(())
    }

    fn mark_written(&mut self, key: SKey, invalidation: bool) {
        let rec = self.mem.entry((key.0, key.2)).or_insert_with(MemRec::new);
        let (ent, existed) = rec.layers.upsert(key.1);
        if invalidation && !existed {
            self.internal_error = true;
        }
        let current = if existed { ent.state } else { O };
        if current == U {
            ent.state = R;
            self.repacked.insert(key);
        } else if current != R {
            ent.state = W;
            ent.flags &= !F_RS;
        }
        if ent.flags & F_NF == 0 {
            ent.flags |= F_NF;
            self.ctx.entry((key.0, key.1)).or_default().new_frame.push(key.2);
        }
    }

    fn record_written_byte(
        &mut self,
        target_pid: u32,
        address: u64,
        physical_key: Option<u64>,
        source_layer: i32,
        sources: &[u32],
    ) {
        for &s in sources {
            let source_pid = self.blocks[s as usize].0;
            if source_pid != target_pid {
                self.interactions.insert((source_pid, target_pid));
            }
        }
        let mut affected = std::mem::take(&mut self.affected);
        affected.clear();
        let rec = self.mem.entry((target_pid, address)).or_insert_with(MemRec::new);
        let mut highest = or_minus_one(rec.wl);
        if let Some(pk) = physical_key {
            if let Some(p) = self.phys.get(&pk) {
                let physical_layer = or_minus_one(p.wl);
                if physical_layer > highest {
                    highest = physical_layer;
                }
            }
        }
        if source_layer > highest {
            highest = source_layer;
        }
        rec.wl = highest;
        for &s in sources {
            rec.writers.insert(s);
        }
        affected.extend(rec.layers.as_slice().iter().map(|e| (target_pid, e.layer, address)));
        affected.push((target_pid, highest + 1, address));
        if let Some(pk) = physical_key {
            let p = self.phys.entry(pk).or_insert_with(PhysRec::new);
            p.wl = highest;
            for &s in sources {
                p.writers.insert(s);
            }
            p.locations.for_each(|k| affected.push(k));
        }
        for &key in &affected {
            self.mark_written(key, false);
        }
        self.affected = affected;
    }

    fn executed_at(&self, key: SKey) -> bool {
        self.mem.get(&(key.0, key.2)).map_or(false, |rec| {
            rec.layers.as_slice().iter().any(|e| e.layer == key.1 && e.flags & F_EXEC != 0)
        })
    }

    fn invalidate_byte(&mut self, target_pid: u32, address: u64, physical_key: Option<u64>, source: Option<u32>) {
        let mut affected = std::mem::take(&mut self.affected);
        affected.clear();
        if let Some(rec) = self.mem.get(&(target_pid, address)) {
            affected.extend(rec.layers.as_slice().iter().map(|e| (target_pid, e.layer, address)));
        }
        if let Some(pk) = physical_key {
            if let Some(p) = self.phys.get(&pk) {
                p.locations.for_each(|k| affected.push(k));
            }
        }
        let source_layer = source.map(|s| self.blocks[s as usize].1);
        for &key in &affected {
            self.mark_written(key, true);
            if let (Some(s), Some(sl)) = (source, source_layer) {
                if key.1 != sl && self.executed_at(key) {
                    self.packer[s as usize] = true;
                }
            }
        }
        self.affected = affected;
        if let Some(rec) = self.mem.get_mut(&(target_pid, address)) {
            rec.wl = NONE;
            rec.writers = Tiny::Zero;
        }
        if let Some(pk) = physical_key {
            self.phys.remove(&pk);
        }
    }

    fn event(&mut self, e: &Event) -> Res<()> {
        if let Some(seq) = opt(e, "seq") {
            let sequence = int(seq)?;
            if sequence <= self.last_sequence {
                return Err(Stop::NonMonotonic);
            }
            self.last_sequence = sequence;
        }
        let kind: &str = match opt(e, "event") {
            Some(V::Str(s)) => s,
            Some(V::Arr(_)) | Some(V::Obj(_)) => return Err(Stop::Fallback("unhashable event kind")),
            _ => return Err(Stop::Unknown),
        };
        if kind == "marker" {
            let action = match opt(e, "action") {
                None => 0,
                Some(v) => int(v)?,
            };
            if action == 1 {
                self.root_pid = Some(small(int(req(e, "pid")?)?)?);
            }
        } else if kind == "root_image" {
            self.root_pid = Some(small(int(req(e, "pid")?)?)?);
        }
        if kind == "process" {
            let is_root_marker = matches!(opt(e, "reason"), Some(V::Str(s)) if s == "root_marker");
            if !is_root_marker {
                self.cross_process_activity = true;
            }
        } else if kind == "descendant_debug" && matches!(opt(e, "after_cutoff"), Some(V::Bool(true))) {
            let job = matches!(opt(e, "job_matches"), Some(V::Bool(true)));
            let parent = if job {
                false
            } else if let Some(root) = self.root_pid {
                match opt(e, "parent_pid") {
                    Some(V::Int(i)) => *i == root as i128,
                    Some(V::Bool(b)) => (*b as i128) == root as i128,
                    Some(V::Float) => return Err(Stop::Fallback("float parent_pid")),
                    _ => false,
                }
            } else {
                false
            };
            if job || parent {
                self.cross_process_activity = true;
            }
        }
        match kind {
            "process" | "prestart_exec" | "root_image" | "sample_start" | "trace_start" | "marker"
            | "register_handles" | "exception_dispatch" | "exception_recovered" | "descendant_debug"
            | "root_debug" | "summary" | "evasion_check" => return Ok(()),
            "exec" | "write" | "invalidate" | "unmap" | "free" | "file_write" | "file_read" => {}
            _ => return Err(Stop::Unknown),
        }
        if matches!(opt(e, "role"), Some(V::Str(s)) if s == "system") {
            return Ok(());
        }
        let pid_value = small(int(req(e, "pid")?)?)?;
        let tid = small(int(req(e, "tid")?)?)?;
        let pid = self.pid(pid_value);
        if kind == "file_write" {
            let source = match self.last_block.get(&(pid, tid)) {
                None => return Ok(()),
                Some(&s) => s,
            };
            let source_layer = self.blocks[source as usize].1;
            let file_id = self.file_key(req(e, "file_id")?)?;
            let file_offset = number(req(e, "file_offset")?)?;
            let size = event_size(e)?;
            let file_offset = span_u64(file_offset, size)?;
            for offset in 0..size as u64 {
                let rec = self
                    .files
                    .entry((file_id, file_offset + offset))
                    .or_insert_with(|| FileRec { layer: -1, writers: Tiny::Zero, version: 0 });
                if source_layer > rec.layer {
                    rec.layer = source_layer;
                }
                rec.writers.insert(source);
                rec.version += 1;
            }
            return Ok(());
        }
        let address = number(req(e, "address")?)?;
        let size = event_size(e)?;
        self.threads.insert((pid, tid));
        let address = span_u64(address, size)?;
        let n = size as usize;

        if kind == "invalidate" || kind == "unmap" || kind == "free" {
            let target_pid = match opt(e, "target_pid") {
                None => pid,
                Some(v) => {
                    let value = small(int(v)?)?;
                    self.pid(value)
                }
            };
            let source = self.last_block.get(&(pid, tid)).copied();
            self.invalidated_physical_keys(e, n)?;
            let pks = std::mem::take(&mut self.pks);
            for offset in 0..n {
                self.invalidate_byte(target_pid, address + offset as u64, pks[offset], source);
            }
            self.pks = pks;
            return Ok(());
        }

        self.physical_keys(e, n)?;

        if kind == "file_read" {
            let target_pid = match opt(e, "target_pid") {
                None => pid,
                Some(v) => {
                    let value = small(int(v)?)?;
                    self.pid(value)
                }
            };
            let file_id = self.file_key(req(e, "file_id")?)?;
            let file_offset = number(req(e, "file_offset")?)?;
            let file_offset = span_u64(file_offset, size)?;
            let pks = std::mem::take(&mut self.pks);
            let mut sources = std::mem::take(&mut self.sources);
            for offset in 0..n {
                let file_key = (file_id, file_offset + offset as u64);
                let layer = match self.files.get(&file_key) {
                    Some(rec) => {
                        sources.clear();
                        rec.writers.for_each(|s| sources.push(s));
                        rec.layer
                    }
                    None => continue,
                };
                self.record_written_byte(target_pid, address + offset as u64, pks[offset], layer, &sources);
            }
            self.sources = sources;
            self.pks = pks;
            return Ok(());
        }

        if kind == "write" {
            let target_pid = match opt(e, "target_pid") {
                None => pid,
                Some(v) => {
                    let value = small(int(v)?)?;
                    self.pid(value)
                }
            };
            let source = self.last_block.get(&(pid, tid)).copied();
            let source_layer = match opt(e, "source_layer") {
                None => source.map_or(0, |s| self.blocks[s as usize].1),
                Some(v) => layer_of(int(v)?)?,
            };
            let sources: Vec<u32> = source.into_iter().collect();
            let pks = std::mem::take(&mut self.pks);
            for offset in 0..n {
                self.record_written_byte(target_pid, address + offset as u64, pks[offset], source_layer, &sources);
            }
            self.pks = pks;
            return Ok(());
        }

        let pks = std::mem::take(&mut self.pks);
        let result = self.exec(e, pid, tid, address, size, &pks);
        self.pks = pks;
        result
    }

    fn exec(&mut self, e: &Event, pid: u32, tid: i64, address: u64, size: i128, pks: &[Option<u64>]) -> Res<()> {
        let n = size as usize;
        match opt(e, "file_id") {
            None | Some(V::Null) => {}
            Some(fid) => {
                let file_id = self.file_key(fid)?;
                let file_offset = number(req(e, "file_offset")?)?;
                let file_offset = span_u64(file_offset, size)?;
                let mut sources = std::mem::take(&mut self.sources);
                for offset in 0..n {
                    let file_key = (file_id, file_offset + offset as u64);
                    let (layer, version) = match self.files.get(&file_key) {
                        Some(rec) => {
                            sources.clear();
                            rec.writers.for_each(|s| sources.push(s));
                            (rec.layer, rec.version)
                        }
                        None => continue,
                    };
                    let applied = (file_key, version);
                    let memory_key = (pid, address + offset as u64);
                    if self.mapped_applied.get(&memory_key) != Some(&applied) {
                        self.mapped_applied.insert(memory_key, applied);
                        self.record_written_byte(pid, address + offset as u64, pks[offset], layer, &sources);
                    }
                }
                self.sources = sources;
            }
        }
        let mut layer: i32 = 0;
        {
            let blocks = &self.blocks;
            for offset in 0..n {
                let virt = self.mem.get(&(pid, address + offset as u64)).map_or(-1, |r| or_minus_one(r.wl));
                let mut phys = -1;
                if let Some(pk) = pks[offset] {
                    if let Some(p) = self.phys.get(&pk) {
                        if p.writers.any(|s| blocks[s as usize].0 != pid) {
                            phys = or_minus_one(p.wl);
                        }
                    }
                }
                let byte_layer = virt.max(phys) + 1;
                if offset == 0 || byte_layer > layer {
                    layer = byte_layer;
                }
            }
        }
        if layer >= LAYER_LIMIT {
            return Err(Stop::Fallback("layer outside the supported range"));
        }
        let layer_key = (pid, layer);
        let mut starts_frame = false;
        for offset in 0..n {
            if let Some(rec) = self.mem.get(&(pid, address + offset as u64)) {
                if let Some(ent) = rec.layers.find(layer) {
                    if (ent.state == W || ent.state == R) && ent.flags & F_NF != 0 {
                        starts_frame = true;
                        break;
                    }
                }
            }
        }
        if starts_frame {
            let ctx = self.ctx.entry(layer_key).or_default();
            ctx.frame += 1;
            let number = ctx.frame;
            let written = std::mem::take(&mut ctx.new_frame);
            let mut resettable = std::mem::take(&mut ctx.resettable);
            for &a in &written {
                if let Some(ent) = self.mem.get_mut(&(pid, a)).and_then(|r| r.layers.find_mut(layer)) {
                    ent.flags &= !F_NF;
                }
            }
            for &a in &resettable {
                if let Some(ent) = self.mem.get_mut(&(pid, a)).and_then(|r| r.layers.find_mut(layer)) {
                    ent.flags &= !F_LISTED;
                    if ent.flags & F_RS != 0 {
                        ent.flags &= !F_RS;
                        if ent.state == U || ent.state == R {
                            ent.state = W;
                        } else if ent.state == X {
                            ent.state = O;
                        }
                    }
                }
            }
            resettable.clear();
            self.ctx.get_mut(&layer_key).unwrap().resettable = resettable;
            self.frame_written.insert((pid, layer, number), ranges(written));
        }
        let frame = self.ctx.get(&layer_key).map_or(0, |c| c.frame);
        let block = self.block((pid, layer, address));
        self.unique.insert((block, size as u64, frame));
        if self.sequence.last() != Some(&block) {
            self.sequence.push(block);
        }
        self.last_block.insert((pid, tid), block);
        *self.frame_blocks.entry((pid, layer, frame)).or_insert(0) += 1;
        let ctx = self.ctx.entry(layer_key).or_default();
        let blocks = &self.blocks;
        let packer = &mut self.packer;
        let interactions = &mut self.interactions;
        for offset in 0..n {
            let a = address + offset as u64;
            let physical_key = pks[offset];
            let rec = self.mem.entry((pid, a)).or_insert_with(MemRec::new);
            rec.writers.for_each(|s| {
                let source_pid = blocks[s as usize].0;
                if source_pid != pid {
                    interactions.insert((source_pid, pid));
                }
                packer[s as usize] = true;
            });
            let mut cross = false;
            if let Some(pk) = physical_key {
                if let Some(p) = self.phys.get(&pk) {
                    p.writers.for_each(|s| {
                        let source_pid = blocks[s as usize].0;
                        if source_pid != pid {
                            cross = true;
                            interactions.insert((source_pid, pid));
                            packer[s as usize] = true;
                        }
                    });
                }
            }
            let value = if rec.wl != NONE || cross { U } else { X };
            let (ent, _) = rec.layers.upsert(layer);
            ent.state = value;
            ent.flags |= F_EXEC | F_RS;
            if ent.flags & F_LISTED == 0 {
                ent.flags |= F_LISTED;
                ctx.resettable.push(a);
            }
            if let Some(pk) = physical_key {
                self.phys.entry(pk).or_insert_with(PhysRec::new).locations.insert((pid, layer, a));
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<String, &'static str> {
        if self.internal_error {
            return Err("internal state invariant violated");
        }
        {
            let blocks = &self.blocks;
            let packer = &mut self.packer;
            for rec in self.mem.values() {
                if rec.writers.is_empty() {
                    continue;
                }
                let layers = rec.layers.as_slice();
                rec.writers.for_each(|s| {
                    let source_layer = blocks[s as usize].1;
                    if layers.iter().any(|e| e.flags & F_EXEC != 0 && e.layer != source_layer) {
                        packer[s as usize] = true;
                    }
                });
            }
        }
        let root = match self.root_pid {
            Some(r) => Some(self.pid(r)),
            None => self.sequence.first().map(|&b| self.blocks[b as usize].0),
        };
        let pid_count = self.pid_values.len();
        let mut relevant = vec![false; pid_count];
        let mut relevant_pids: u64 = 0;
        if let Some(root) = root {
            relevant[root as usize] = true;
            relevant_pids = 1;
            let mut adjacency: Vec<Vec<u32>> = vec![Vec::new(); pid_count];
            for &(left, right) in &self.interactions {
                adjacency[left as usize].push(right);
                adjacency[right as usize].push(left);
            }
            let mut stack = vec![root];
            while let Some(p) = stack.pop() {
                for &q in &adjacency[p as usize] {
                    if !relevant[q as usize] {
                        relevant[q as usize] = true;
                        relevant_pids += 1;
                        stack.push(q);
                    }
                }
            }
        }
        let strict = &self.packer;

        let mut packer_pages: Map<(u32, i32), Set<u64>> = Map::default();
        for (id, &(pid, layer, address)) in self.blocks.iter().enumerate() {
            if strict[id] && relevant[pid as usize] {
                packer_pages.entry((pid, layer)).or_default().insert(address / 4096);
            }
        }
        let mut candidate = vec![false; self.blocks.len()];
        for (id, &(pid, layer, address)) in self.blocks.iter().enumerate() {
            if !relevant[pid as usize] || strict[id] {
                continue;
            }
            let page = address / 4096;
            let too_close = packer_pages.get(&(pid, layer)).map_or(false, |pages| {
                let low = page.saturating_sub(9);
                (low..=page + 9).any(|p| pages.contains(&p))
            });
            candidate[id] = !too_close;
        }
        let mut candidate_lists: Map<(u32, i32), Vec<u64>> = Map::default();
        let mut candidate_frames: Set<(u32, i32, i64)> = Set::default();
        for &(block, size, frame) in &self.unique {
            if !candidate[block as usize] {
                continue;
            }
            let (pid, layer, address) = self.blocks[block as usize];
            let list = candidate_lists.entry((pid, layer)).or_default();
            for byte in address..address + size {
                list.push(byte);
            }
            candidate_frames.insert((pid, layer, frame));
        }
        let mut total_candidate: u64 = 0;
        for list in candidate_lists.values_mut() {
            list.sort_unstable();
            list.dedup();
            total_candidate += list.len() as u64;
        }

        let mut relevant_count: u64 = 0;
        let mut relevant_max_layer: i64 = -1;
        let mut forward: u64 = 0;
        let mut backward: u64 = 0;
        let mut transitions: u64 = 0;
        let mut packer_to_app: u64 = 0;
        let mut app_to_packer: u64 = 0;
        let mut previous: Option<(i32, bool)> = None;
        for &b in &self.sequence {
            let (pid, layer, _) = self.blocks[b as usize];
            if !relevant[pid as usize] {
                continue;
            }
            relevant_count += 1;
            if layer as i64 > relevant_max_layer {
                relevant_max_layer = layer as i64;
            }
            let app = candidate[b as usize];
            if let Some((prev_layer, prev_app)) = previous {
                if prev_layer != layer {
                    transitions += 1;
                    if layer > prev_layer {
                        forward += 1;
                    } else {
                        backward += 1;
                    }
                }
                if prev_app != app {
                    if app {
                        packer_to_app += 1;
                    } else {
                        app_to_packer += 1;
                    }
                }
            }
            previous = Some((layer, app));
        }
        let raw_linear = backward == 0 && transitions as i128 == relevant_max_layer.max(0) as i128;
        let mut topology_tail = false;
        if relevant_count > 0 && relevant_max_layer >= 1 {
            let mut reached_tail = false;
            let mut chain_ok = true;
            let mut chain_len: i64 = 0;
            let mut clean = true;
            let mut prev_layer: Option<i64> = None;
            for &b in &self.sequence {
                let (pid, layer, _) = self.blocks[b as usize];
                if !relevant[pid as usize] {
                    continue;
                }
                let layer = layer as i64;
                if !reached_tail {
                    if let Some(pl) = prev_layer {
                        if pl != layer {
                            if pl != chain_len || layer != chain_len + 1 {
                                chain_ok = false;
                            }
                            chain_len += 1;
                        }
                    }
                    prev_layer = Some(layer);
                    if layer == relevant_max_layer {
                        reached_tail = true;
                    }
                }
                if reached_tail && strict[b as usize] {
                    clean = false;
                    break;
                }
            }
            topology_tail = chain_ok && chain_len == relevant_max_layer && clean;
        }
        let linear = raw_linear || topology_tail;
        let all_code_packer = relevant_count > 0 && total_candidate == 0;
        let tail = (packer_to_app == 1 && app_to_packer == 0) || topology_tail;
        let interleaved = !tail && !all_code_packer;

        struct Regions {
            region_of: Vec<u32>,
            region_len: Vec<u64>,
            first: Vec<Option<i64>>,
            multi: Vec<bool>,
        }
        let mut regions: Map<(u32, i32), Regions> = Map::default();
        for (k, bytes) in &candidate_lists {
            if bytes.is_empty() {
                continue;
            }
            let mut region_of: Vec<u32> = Vec::with_capacity(bytes.len());
            let mut region_len: Vec<u64> = Vec::new();
            for (i, &b) in bytes.iter().enumerate() {
                if i == 0 || b - bytes[i - 1] > 10 * 4096 {
                    region_len.push(0);
                }
                let r = region_len.len() - 1;
                region_len[r] += 1;
                region_of.push(r as u32);
            }
            let count = region_len.len();
            regions.insert(*k, Regions { region_of, region_len, first: vec![None; count], multi: vec![false; count] });
        }
        for (&(fp, fl, frame), written) in &self.frame_written {
            let (Some(reg), Some(bytes)) = (regions.get_mut(&(fp, fl)), candidate_lists.get(&(fp, fl))) else {
                continue;
            };
            for &(start, last) in written {
                let mut idx = bytes.partition_point(|&b| b < start);
                while idx < bytes.len() && bytes[idx] <= last {
                    let r = reg.region_of[idx] as usize;
                    match reg.first[r] {
                        None => reg.first[r] = Some(frame),
                        Some(f) if f != frame => reg.multi[r] = true,
                        _ => {}
                    }
                    idx += 1;
                }
            }
        }
        let mut candidate_multiframe: u64 = 0;
        for reg in regions.values() {
            for r in 0..reg.region_len.len() {
                if reg.multi[r] {
                    candidate_multiframe += reg.region_len[r];
                }
            }
        }

        let mut executed_pages: Set<(u32, i32, u64)> = Set::default();
        for &(block, size, _) in &self.unique {
            let (pid, layer, address) = self.blocks[block as usize];
            let low = (address as i128) >> 12;
            let high = (address as i128 + size as i128 - 1) >> 12;
            let mut p = low;
            while p <= high {
                executed_pages.insert((pid, layer, p as u64));
                p += 1;
            }
        }
        let mut frames: Vec<(i64, i32, i64, u32)> =
            candidate_frames.iter().map(|&(p, l, f)| (self.pid_values[p as usize], l, f, p)).collect();
        frames.sort_unstable();
        let mut sizes: Vec<u64> = Vec::with_capacity(frames.len());
        let mut basic_blocks: Vec<u64> = Vec::with_capacity(frames.len());
        for &(_, layer, frame, pid) in &frames {
            let mut count: u64 = 0;
            if let Some(written) = self.frame_written.get(&(pid, layer, frame)) {
                for &(start, last) in written {
                    let mut page = start >> 12;
                    loop {
                        let page_start = page << 12;
                        let lo = start.max(page_start);
                        let hi = last.min(page_start | 0xfff);
                        if executed_pages.contains(&(pid, layer, page)) {
                            count += hi - lo + 1;
                        }
                        if page >= last >> 12 {
                            break;
                        }
                        page += 1;
                    }
                }
            }
            sizes.push(count);
            basic_blocks.push(*self.frame_blocks.get(&(pid, layer, frame)).unwrap_or(&0));
        }
        let repacked_candidate = self
            .repacked
            .iter()
            .filter(|k| candidate_lists.get(&(k.0, k.1)).map_or(false, |v| v.binary_search(&k.2).is_ok()))
            .count();
        let threads = self.threads.iter().filter(|(p, _)| relevant[*p as usize]).count();
        let layers = if relevant_count > 0 { relevant_max_layer + 1 } else { 0 };
        let cross = self.cross_process_activity || !self.interactions.is_empty();

        let mut out = String::new();
        out.push_str("{\"status\":\"ok\"");
        let mut field = |name: &str, value: String| {
            out.push_str(",\"");
            out.push_str(name);
            out.push_str("\":");
            out.push_str(&value);
        };
        let list = |v: &[u64]| {
            let parts: Vec<String> = v.iter().map(|x| x.to_string()).collect();
            format!("[{}]", parts.join(","))
        };
        field("layers", layers.to_string());
        field("processes", relevant_pids.to_string());
        field("threads", threads.to_string());
        field("forward_transitions", forward.to_string());
        field("backward_transitions", backward.to_string());
        field("original_code_frames", frames.len().to_string());
        field("candidate_code_bytes", total_candidate.to_string());
        field("candidate_multiframe_bytes", candidate_multiframe.to_string());
        field("repacked_original_bytes", repacked_candidate.to_string());
        field("tail_transition", tail.to_string());
        field("interleaved", interleaved.to_string());
        field("frame_sizes", list(&sizes));
        field("frame_basic_blocks", list(&basic_blocks));
        field("all_code_flagged_packer", all_code_packer.to_string());
        field("cross_process_activity", cross.to_string());
        field("linear_transition_model", linear.to_string());
        field("packer_to_application_transitions", packer_to_app.to_string());
        field("application_to_packer_transitions", app_to_packer.to_string());
        Ok(out)
    }
}

fn emit(s: &str) {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = lock.write_all(s.as_bytes());
    let _ = lock.write_all(b"\n");
    let _ = lock.flush();
}

fn stop_json(kind: &str, line_no: u64, offset: u64, detail: &str) -> String {
    format!(
        "{{\"status\":\"{}\",\"line_no\":{},\"offset\":{},\"detail\":\"{}\"}}",
        kind, line_no, offset, detail
    )
}

const DIRECT_CHUNK: usize = 8 << 20;
const O_DIRECT: i32 = 0o40000;

struct AlignedBuf {
    ptr: *mut u8,
    layout: std::alloc::Layout,
}

impl AlignedBuf {
    fn new(size: usize) -> Self {
        let layout = std::alloc::Layout::from_size_align(size, 4096).unwrap();
        let ptr = unsafe { std::alloc::alloc(layout) };
        assert!(!ptr.is_null());
        AlignedBuf { ptr, layout }
    }

    fn slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.layout.size()) }
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.ptr, self.layout) }
    }
}

struct TraceReader {
    path: String,
    file: File,
    direct: bool,
    buf: AlignedBuf,
    start: usize,
    end: usize,
    offset: u64,
}

impl TraceReader {
    fn open(path: &str) -> std::io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let (file, direct) = match std::fs::OpenOptions::new().read(true).custom_flags(O_DIRECT).open(path) {
            Ok(f) => (f, true),
            Err(_) => (File::open(path)?, false),
        };
        Ok(TraceReader { path: path.to_string(), file, direct, buf: AlignedBuf::new(DIRECT_CHUNK), start: 0, end: 0, offset: 0 })
    }

    fn fill(&mut self) -> std::io::Result<()> {
        use std::io::{Read, Seek, SeekFrom};
        loop {
            let result = self.file.read(self.buf.slice());
            match result {
                Ok(n) => {
                    self.start = 0;
                    self.end = n;
                    self.offset += n as u64;
                    if self.direct && n % 4096 != 0 {
                        let mut file = File::open(&self.path)?;
                        file.seek(SeekFrom::Start(self.offset))?;
                        self.file = file;
                        self.direct = false;
                    }
                    return Ok(());
                }
                Err(e) if self.direct && e.raw_os_error() == Some(22) => {
                    let mut file = File::open(&self.path)?;
                    file.seek(SeekFrom::Start(self.offset))?;
                    self.file = file;
                    self.direct = false;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}

impl std::io::Read for TraceReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.start == self.end {
            self.fill()?;
        }
        let n = out.len().min(self.end - self.start);
        out[..n].copy_from_slice(&self.buf.slice()[self.start..self.start + n]);
        self.start += n;
        Ok(n)
    }
}

fn run(path: &str) -> String {
    let file = match TraceReader::open(path) {
        Ok(f) => f,
        Err(_) => return stop_json("fallback", 0, 0, "cannot open trace"),
    };
    let mut reader = BufReader::with_capacity(1 << 20, file);
    let mut st = St { last_sequence: -1, ..Default::default() };
    let mut buf: Vec<u8> = Vec::with_capacity(1 << 16);
    let mut offset: u64 = 0;
    let mut line_no: u64 = 0;
    let mut unparsed_final: Option<(u64, u64)> = None;
    loop {
        buf.clear();
        let n = match reader.read_until(b'\n', &mut buf) {
            Ok(n) => n,
            Err(_) => return stop_json("fallback", line_no, offset, "read error"),
        };
        if n == 0 {
            break;
        }
        line_no += 1;
        let line_offset = offset;
        offset += n as u64;
        let is_final = match reader.fill_buf() {
            Ok(rest) => rest.is_empty(),
            Err(_) => return stop_json("fallback", line_no, offset, "read error"),
        };
        if buf.iter().all(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)) {
            continue;
        }
        let event = match json::parse_event(&buf) {
            Some(e) => e,
            None => {
                if is_final {
                    unparsed_final = Some((line_no, line_offset));
                    break;
                }
                return stop_json("json_error", line_no, line_offset, "");
            }
        };
        match st.event(&event) {
            Ok(()) => {}
            Err(Stop::Fallback(reason)) => return stop_json("fallback", line_no, line_offset, reason),
            Err(Stop::Unknown) => return stop_json("unknown_event", line_no, line_offset, ""),
            Err(Stop::NonMonotonic) => return stop_json("non_monotonic", line_no, line_offset, ""),
            Err(Stop::Value(m)) => return stop_json("value_error", line_no, line_offset, m),
            Err(Stop::Key(k)) => return stop_json("key_error", line_no, line_offset, k),
        }
    }
    let mut out = match st.finish() {
        Ok(out) => out,
        Err(reason) => return stop_json("fallback", line_no, offset, reason),
    };
    match unparsed_final {
        Some((l, o)) => out.push_str(&format!(",\"unparsed_final\":{{\"line_no\":{},\"offset\":{}}}}}", l, o)),
        None => out.push_str(",\"unparsed_final\":null}"),
    }
    out
}

extern "C" {
    fn mallopt(param: i32, value: i32) -> i32;
}

fn main() {
    unsafe {
        mallopt(-1, i32::MAX);
        mallopt(-3, 32 << 20);
        mallopt(-2, 16 << 20);
    }
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: paper_core TRACE.jsonl");
        std::process::exit(2);
    }
    let out = run(&args[1]);
    emit(&out);
}
