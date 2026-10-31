//! Offline Windows registry hives (regf), pure Rust.
//!
//! Paths use backslashes relative to the hive root, e.g. `Policies\Microsoft\Windows\DataCollection`
//! inside SOFTWARE. Lookups are case-insensitive like Windows.
//!
//! The hive is kept in memory and written back by `commit`. Layout: a 4096-byte base block, then
//! hive bins ("hbin", multiples of 4096 bytes) holding cells. A cell starts with a signed 32-bit
//! size (negative = allocated); cell offsets are relative to the end of the base block.
//! Writing reuses free cells (first fit, split, coalescing) and appends new bins when needed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};

/// A key handle: the cell offset of its key node.
pub type NodeH = usize;
/// A value handle: the cell offset of its value node.
pub type ValueH = usize;

pub const REG_NONE: u32 = 0;
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_QWORD: u32 = 11;

const BASE: usize = 4096;
const BIN: usize = 4096;
const NONE: u32 = u32::MAX;
/// Values above this size are stored as "db" big data in segments of this size.
const BIG_SEGMENT: usize = 16344;
const KEY_COMP_NAME: u16 = 0x20;
const VALUE_COMP_NAME: u16 = 1;
const INLINE: u32 = 0x8000_0000;

#[derive(Debug, Clone, PartialEq)]
pub struct RegData {
    pub kind: u32,
    pub data: Vec<u8>,
}

impl RegData {
    pub fn dword(v: u32) -> Self {
        RegData { kind: REG_DWORD, data: v.to_le_bytes().to_vec() }
    }
    pub fn sz(s: &str) -> Self {
        RegData { kind: REG_SZ, data: utf16z(s) }
    }
    pub fn as_dword(&self) -> Option<u32> {
        (self.kind == REG_DWORD && self.data.len() >= 4).then(|| u32::from_le_bytes(self.data[..4].try_into().unwrap()))
    }
    pub fn as_string(&self) -> Option<String> {
        matches!(self.kind, REG_SZ | REG_EXPAND_SZ).then(|| from_utf16(&self.data))
    }
    pub fn as_multi(&self) -> Option<Vec<String>> {
        (self.kind == REG_MULTI_SZ).then(|| {
            let units: Vec<u16> = self.data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            units.split(|&u| u == 0).filter(|s| !s.is_empty()).map(String::from_utf16_lossy).collect()
        })
    }
}

pub fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16().chain(std::iter::once(0)).flat_map(u16::to_le_bytes).collect()
}

pub fn from_utf16(b: &[u8]) -> String {
    let units: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
    String::from_utf16_lossy(&units)
}

fn le16(b: &[u8], o: usize) -> Result<u16> {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).ok_or_else(|| anyhow!("truncated cell"))
}

fn le32(b: &[u8], o: usize) -> Result<u32> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap())).ok_or_else(|| anyhow!("truncated cell"))
}

fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

fn filetime_now() -> u64 {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    d.as_secs() * 10_000_000 + u64::from(d.subsec_nanos() / 100) + 116_444_736_000_000_000
}

/// Decodes a stored name: Latin-1 when compressed, else UTF-16LE.
fn decode_name(b: &[u8], compressed: bool, strict: bool) -> Result<String> {
    if compressed {
        return Ok(b.iter().map(|&c| char::from(c)).collect());
    }
    let units: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    if strict {
        String::from_utf16(&units).map_err(|_| anyhow!("name is not valid UTF-16"))
    } else {
        Ok(String::from_utf16_lossy(&units))
    }
}

/// Encodes a name like Windows: compressed (one byte per character) if every character fits.
fn encode_name(s: &str) -> (Vec<u8>, bool) {
    if s.chars().all(|c| (c as u32) <= 0xFF) {
        (s.chars().map(|c| c as u8).collect(), true)
    } else {
        (s.encode_utf16().flat_map(u16::to_le_bytes).collect(), false)
    }
}

/// Upper-cased UTF-16 code units, the order and hash basis of subkey lists. Like Windows, each
/// code unit is mapped on its own (surrogates stay unchanged).
fn upcase(s: &str) -> Vec<u16> {
    s.encode_utf16()
        .map(|unit| {
            let Some(c) = char::from_u32(u32::from(unit)) else { return unit };
            let mut up = c.to_uppercase();
            match (up.next(), up.next()) {
                (Some(u), None) if u.len_utf16() == 1 => u as u32 as u16,
                _ => unit,
            }
        })
        .collect()
}

fn name_len_units(s: &str) -> u32 {
    s.encode_utf16().count() as u32
}

fn lh_hash(up: &[u16]) -> u32 {
    up.iter().fold(0u32, |h, &u| h.wrapping_mul(37).wrapping_add(u32::from(u)))
}

fn lf_hint(name: &str) -> u32 {
    let mut b = [0u8; 4];
    for (i, c) in name.chars().take(4).enumerate() {
        // A prefix that does not fit one byte per character gets no hint.
        let Ok(byte) = u8::try_from(c as u32) else { return 0 };
        b[i] = byte;
    }
    u32::from_le_bytes(b)
}

pub struct Hive {
    data: Vec<u8>,
    path: PathBuf,
    writable: bool,
    dirty: bool,
    root: u32,
    /// Free cells (offset → size); only maintained for writable hives.
    free: BTreeMap<u32, u32>,
    /// Hive bins as (offset, size), sorted.
    bins: Vec<(u32, u32)>,
}

/// Cells and security references collected before a destructive change.
#[derive(Default)]
struct Garbage {
    cells: Vec<u32>,
    security: Vec<u32>,
}

impl Hive {
    /// Opens a hive file. Refuses dirty hives (unequal sequence numbers): their pending
    /// transaction logs would have to be replayed first.
    pub fn open(path: &Path, write: bool) -> Result<Self> {
        let data = std::fs::read(path).map_err(|e| anyhow!("cannot read hive {}: {e}", path.display()))?;
        if data.len() < BASE || &data[..4] != b"regf" {
            bail!("{} is not a registry hive", path.display());
        }
        let (s1, s2) = (le32(&data, 4)?, le32(&data, 8)?);
        if s1 != s2 {
            bail!("hive {} is dirty (sequence {s1} != {s2}); its transaction log is not replayed", path.display());
        }
        let bins_size = le32(&data, 0x28)? as usize;
        if bins_size % BIN != 0 || BASE + bins_size > data.len() {
            bail!("hive {} has an invalid hive bin size {bins_size}", path.display());
        }
        let root = le32(&data, 0x24)?;
        let mut h = Hive { data, path: path.to_path_buf(), writable: write, dirty: false, root, free: BTreeMap::new(), bins: Vec::new() };
        h.nk(root).with_context(|| format!("hive {} has no valid root key", path.display()))?;
        if write {
            h.scan_bins().with_context(|| format!("hive {} cannot be opened for writing", path.display()))?;
        }
        Ok(h)
    }

    fn bins_size(&self) -> usize {
        u32::from_le_bytes(self.data[0x28..0x2C].try_into().unwrap()) as usize
    }

    /// Indexes all hive bins and free cells; fails on any inconsistency.
    fn scan_bins(&mut self) -> Result<()> {
        let size = self.bins_size();
        let mut off = 0usize;
        while off < size {
            let abs = BASE + off;
            if &self.data[abs..abs + 4] != b"hbin" {
                bail!("missing hbin signature at offset {off:#x}");
            }
            let len = le32(&self.data, abs + 8)? as usize;
            if len < BIN || len % BIN != 0 || off + len > size {
                bail!("invalid hbin size {len:#x} at offset {off:#x}");
            }
            let mut c = off + 32;
            while c < off + len {
                let s = i32::from_le_bytes(self.data[BASE + c..BASE + c + 4].try_into().unwrap());
                let l = s.unsigned_abs() as usize;
                if l < 8 || l % 8 != 0 || c + l > off + len {
                    bail!("invalid cell size {s} at offset {c:#x}");
                }
                if s > 0 {
                    self.free.insert(c as u32, l as u32);
                }
                c += l;
            }
            self.bins.push((off as u32, len as u32));
            off += len;
        }
        Ok(())
    }

    // ---- cells ----

    /// Payload of an allocated cell.
    fn cell(&self, off: u32) -> Result<&[u8]> {
        let (s, l) = self.cell_bounds(off)?;
        Ok(&self.data[s..l])
    }

    fn cell_mut(&mut self, off: u32) -> Result<&mut [u8]> {
        let (s, l) = self.cell_bounds(off)?;
        Ok(&mut self.data[s..l])
    }

    fn cell_bounds(&self, off: u32) -> Result<(usize, usize)> {
        let limit = BASE + self.bins_size();
        let abs = BASE + off as usize;
        if off == NONE || off % 8 != 0 || abs + 4 > limit {
            bail!("invalid cell offset {off:#x}");
        }
        let s = i32::from_le_bytes(self.data[abs..abs + 4].try_into().unwrap());
        if s >= 0 {
            bail!("cell {off:#x} is not allocated");
        }
        let len = s.unsigned_abs() as usize;
        if len < 8 || abs + len > limit {
            bail!("cell {off:#x} has an invalid size");
        }
        Ok((abs + 4, abs + len))
    }

    fn set_cell_size(&mut self, off: u32, size: i32) {
        let abs = BASE + off as usize;
        self.data[abs..abs + 4].copy_from_slice(&size.to_le_bytes());
    }

    fn bin_of(&self, off: u32) -> (u32, u32) {
        let i = self.bins.partition_point(|b| b.0 <= off);
        let b = self.bins[i.saturating_sub(1)];
        (b.0, b.0 + b.1)
    }

    fn alloc(&mut self, payload: usize) -> Result<u32> {
        let need = (payload + 4 + 7) & !7;
        if need > i32::MAX as usize {
            bail!("cell too large");
        }
        let found = self.free.iter().find(|&(_, &s)| s as usize >= need).map(|(&o, &s)| (o, s));
        let (off, size) = match found {
            Some((o, s)) => {
                self.free.remove(&o);
                (o, s as usize)
            }
            None => self.grow(need)?,
        };
        let mut used = size;
        if size - need >= 8 {
            let rest = off + need as u32;
            self.set_cell_size(rest, (size - need) as i32);
            self.free.insert(rest, (size - need) as u32);
            used = need;
        }
        self.set_cell_size(off, -(used as i32));
        let abs = BASE + off as usize;
        self.data[abs + 4..abs + used].fill(0);
        Ok(off)
    }

    fn alloc_write(&mut self, payload: &[u8]) -> Result<u32> {
        let off = self.alloc(payload.len())?;
        let abs = BASE + off as usize + 4;
        self.data[abs..abs + payload.len()].copy_from_slice(payload);
        Ok(off)
    }

    /// Appends a hive bin that can hold a cell of `need` bytes; returns its free cell.
    fn grow(&mut self, need: usize) -> Result<(u32, usize)> {
        let len = (need + 32).div_ceil(BIN) * BIN;
        let off = self.bins_size();
        let abs = BASE + off;
        if self.data.len() < abs + len {
            self.data.resize(abs + len, 0);
        }
        self.data[abs..abs + len].fill(0);
        self.data[abs..abs + 4].copy_from_slice(b"hbin");
        put32(&mut self.data, abs + 4, off as u32);
        put32(&mut self.data, abs + 8, len as u32);
        self.data[abs + 20..abs + 28].copy_from_slice(&filetime_now().to_le_bytes());
        let new_size = u32::try_from(off + len).map_err(|_| anyhow!("hive too large"))?;
        put32(&mut self.data, 0x28, new_size);
        self.bins.push((off as u32, len as u32));
        let cell = off as u32 + 32;
        self.set_cell_size(cell, (len - 32) as i32);
        Ok((cell, len - 32))
    }

    fn free_cell(&mut self, off: u32) {
        let abs = BASE + off as usize;
        let s = i32::from_le_bytes(self.data[abs..abs + 4].try_into().unwrap());
        if s >= 0 {
            return;
        }
        let (bin_start, bin_end) = self.bin_of(off);
        let (mut start, mut len) = (off, s.unsigned_abs());
        self.set_cell_size(off, len as i32);
        if off + len < bin_end {
            if let Some(n) = self.free.remove(&(off + len)) {
                len += n;
            }
        }
        if let Some((&p, &pl)) = self.free.range(..off).next_back() {
            if p >= bin_start && p + pl == off {
                self.free.remove(&p);
                start = p;
                len += pl;
            }
        }
        self.set_cell_size(start, len as i32);
        self.free.insert(start, len);
    }

    fn writable(&self) -> Result<()> {
        if !self.writable {
            bail!("hive {} is open read-only", self.path.display());
        }
        Ok(())
    }

    // ---- key nodes ----

    fn nk(&self, off: u32) -> Result<&[u8]> {
        let p = self.cell(off)?;
        if p.len() < 76 || &p[..2] != b"nk" {
            bail!("cell {off:#x} is not a key node");
        }
        Ok(p)
    }

    fn nk_name(&self, off: u32) -> Result<String> {
        let p = self.nk(off)?;
        let len = usize::from(le16(p, 72)?);
        let b = p.get(76..76 + len).ok_or_else(|| anyhow!("key name exceeds its cell"))?;
        decode_name(b, le16(p, 2)? & KEY_COMP_NAME != 0, false)
    }

    fn nk_field(&self, off: u32, field: usize) -> Result<u32> {
        le32(self.nk(off)?, field)
    }

    fn set_nk_field(&mut self, off: u32, field: usize, v: u32) -> Result<()> {
        self.nk(off)?;
        put32(self.cell_mut(off)?, field, v);
        Ok(())
    }

    fn handle(node: NodeH) -> Result<u32> {
        u32::try_from(node).map_err(|_| anyhow!("invalid key handle"))
    }

    /// Subkey node offsets in list order.
    fn child_offsets(&self, node: u32) -> Result<Vec<u32>> {
        let p = self.nk(node)?;
        let (count, list) = (le32(p, 20)?, le32(p, 28)?);
        let mut out = Vec::with_capacity(count as usize);
        if count != 0 && list != NONE {
            self.list_entries(list, &mut out, true)?;
        }
        Ok(out)
    }

    fn list_entries(&self, list: u32, out: &mut Vec<u32>, allow_ri: bool) -> Result<()> {
        let p = self.cell(list)?;
        let n = usize::from(le16(p, 2)?);
        let stride = match &p[..2] {
            b"lf" | b"lh" => 8,
            b"li" | b"ri" => 4,
            s => bail!("unknown subkey list type {:?} at {list:#x}", String::from_utf8_lossy(s)),
        };
        if 4 + n * stride > p.len() {
            bail!("subkey list {list:#x} exceeds its cell");
        }
        for i in 0..n {
            let e = le32(p, 4 + i * stride)?;
            if &p[..2] == b"ri" {
                if !allow_ri {
                    bail!("nested ri list at {list:#x}");
                }
                self.list_entries(e, out, false)?;
            } else {
                out.push(e);
            }
        }
        Ok(())
    }

    // ---- values ----

    fn value_offsets(&self, node: u32) -> Result<Vec<u32>> {
        let p = self.nk(node)?;
        let (count, list) = (le32(p, 36)? as usize, le32(p, 40)?);
        if count == 0 || list == NONE {
            return Ok(Vec::new());
        }
        let l = self.cell(list)?;
        if count * 4 > l.len() {
            bail!("value list {list:#x} exceeds its cell");
        }
        (0..count).map(|i| le32(l, i * 4)).collect()
    }

    fn vk(&self, off: u32) -> Result<&[u8]> {
        let p = self.cell(off)?;
        if p.len() < 20 || &p[..2] != b"vk" {
            bail!("cell {off:#x} is not a value node");
        }
        Ok(p)
    }

    fn vk_name(&self, off: u32, strict: bool) -> Result<String> {
        let p = self.vk(off)?;
        let len = usize::from(le16(p, 2)?);
        let b = p.get(20..20 + len).ok_or_else(|| anyhow!("value name exceeds its cell"))?;
        decode_name(b, le16(p, 16)? & VALUE_COMP_NAME != 0, strict)
    }

    fn vk_data(&self, off: u32) -> Result<RegData> {
        let p = self.vk(off)?;
        let (size, doff, kind) = (le32(p, 4)?, le32(p, 8)?, le32(p, 12)?);
        if size & INLINE != 0 {
            let len = (size & !INLINE) as usize;
            if len > 4 {
                bail!("inline value data of {len} bytes");
            }
            return Ok(RegData { kind, data: p[8..8 + len].to_vec() });
        }
        let len = size as usize;
        if len == 0 {
            return Ok(RegData { kind, data: Vec::new() });
        }
        let c = self.cell(doff)?;
        if len <= c.len() {
            return Ok(RegData { kind, data: c[..len].to_vec() });
        }
        if len > BIG_SEGMENT && c.len() >= 8 && &c[..2] == b"db" {
            let (n, list) = (usize::from(le16(c, 2)?), le32(c, 4)?);
            let segs = self.cell(list)?;
            if n * 4 > segs.len() {
                bail!("big data segment list exceeds its cell");
            }
            let mut data = Vec::with_capacity(len);
            for i in 0..n {
                let s = self.cell(le32(segs, i * 4)?)?;
                let take = (len - data.len()).min(BIG_SEGMENT).min(s.len());
                data.extend_from_slice(&s[..take]);
                if data.len() == len {
                    break;
                }
            }
            if data.len() != len {
                bail!("big data value is shorter than declared");
            }
            return Ok(RegData { kind, data });
        }
        bail!("value data length {len} exceeds its cell")
    }

    /// Cells owned by one value node (the node, its data, big data structures).
    fn value_garbage(&self, off: u32, g: &mut Garbage) -> Result<()> {
        let p = self.vk(off)?;
        let (size, doff) = (le32(p, 4)?, le32(p, 8)?);
        g.cells.push(off);
        if size & INLINE != 0 || size == 0 || doff == NONE {
            return Ok(());
        }
        let c = self.cell(doff)?;
        if size as usize > c.len() && size as usize > BIG_SEGMENT && c.len() >= 8 && &c[..2] == b"db" {
            let (n, list) = (usize::from(le16(c, 2)?), le32(c, 4)?);
            let segs = self.cell(list)?;
            for i in 0..n {
                g.cells.push(le32(segs, i * 4)?);
            }
            g.cells.push(list);
        }
        g.cells.push(doff);
        Ok(())
    }

    /// Stores value data; returns the (size, offset) fields of a value node.
    fn store_data(&mut self, data: &[u8]) -> Result<(u32, u32)> {
        let len = data.len();
        if len <= 4 {
            let mut b = [0u8; 4];
            b[..len].copy_from_slice(data);
            return Ok((len as u32 | INLINE, u32::from_le_bytes(b)));
        }
        let size = u32::try_from(len).ok().filter(|s| s & INLINE == 0).ok_or_else(|| anyhow!("value data too large"))?;
        // Segmented big data exists from hive format 1.4 on; older hives use one cell.
        if len <= BIG_SEGMENT || le32(&self.data, 0x18)? < 4 {
            return Ok((size, self.alloc_write(data)?));
        }
        let segs: Vec<u32> = data.chunks(BIG_SEGMENT).map(|c| self.alloc_write(c)).collect::<Result<_>>()?;
        let n = u16::try_from(segs.len()).map_err(|_| anyhow!("value data too large"))?;
        let list = self.alloc_write(&segs.iter().flat_map(|s| s.to_le_bytes()).collect::<Vec<_>>())?;
        let mut db = vec![0u8; 12];
        db[..2].copy_from_slice(b"db");
        put16(&mut db, 2, n);
        put32(&mut db, 4, list);
        Ok((size, self.alloc_write(&db)?))
    }

    // ---- public API: navigation ----

    pub fn root(&self) -> NodeH {
        self.root as NodeH
    }

    pub fn name(&self, node: NodeH) -> String {
        Self::handle(node).and_then(|n| self.nk_name(n)).unwrap_or_default()
    }

    pub fn children(&self, node: NodeH) -> Vec<(String, NodeH)> {
        let Ok(n) = Self::handle(node) else { return Vec::new() };
        self.child_offsets(n).unwrap_or_default().into_iter().map(|c| (self.nk_name(c).unwrap_or_default(), c as NodeH)).collect()
    }

    pub fn child(&self, node: NodeH, name: &str) -> Result<Option<NodeH>> {
        let want = upcase(name);
        for c in self.child_offsets(Self::handle(node)?)? {
            let p = self.nk(c)?;
            let len = usize::from(le16(p, 72)?);
            let raw = p.get(76..76 + len).ok_or_else(|| anyhow!("key name exceeds its cell"))?;
            if Self::name_matches(raw, le16(p, 2)? & KEY_COMP_NAME != 0, &want) {
                return Ok(Some(c as NodeH));
            }
        }
        Ok(None)
    }

    pub fn parent(&self, node: NodeH) -> Option<NodeH> {
        let n = Self::handle(node).ok()?;
        if n == self.root {
            return None;
        }
        let p = self.nk_field(n, 16).ok()?;
        self.nk(p).is_ok().then_some(p as NodeH)
    }

    /// Resolves a backslash separated key path.
    pub fn key(&self, path: &str) -> Result<Option<NodeH>> {
        let mut n = self.root();
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            match self.child(n, part)? {
                Some(c) => n = c,
                None => return Ok(None),
            }
        }
        Ok(Some(n))
    }

    // ---- public API: values ----

    pub fn values(&self, node: NodeH) -> Vec<(String, RegData)> {
        let Ok(n) = Self::handle(node) else { return Vec::new() };
        self.value_offsets(n)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| Some((self.vk_name(v, false).ok()?, self.vk_data(v).ok()?)))
            .collect()
    }

    fn find_value(&self, node: u32, name: &str) -> Result<Option<(usize, u32)>> {
        let want = upcase(name);
        for (i, v) in self.value_offsets(node)?.into_iter().enumerate() {
            let p = self.vk(v)?;
            let len = usize::from(le16(p, 2)?);
            let raw = p.get(20..20 + len).ok_or_else(|| anyhow!("value name exceeds its cell"))?;
            if Self::name_matches(raw, le16(p, 16)? & VALUE_COMP_NAME != 0, &want) {
                return Ok(Some((i, v)));
            }
        }
        Ok(None)
    }

    pub fn value(&self, node: NodeH, name: &str) -> Result<Option<RegData>> {
        match self.find_value(Self::handle(node)?, name)? {
            Some((_, v)) => self.vk_data(v).map(Some),
            None => Ok(None),
        }
    }

    /// Reads `name` under `path`; None if the key or value is missing.
    pub fn get(&self, path: &str, name: &str) -> Result<Option<RegData>> {
        match self.key(path)? {
            Some(n) => self.value(n, name),
            None => Ok(None),
        }
    }

    /// All values of `node`; fails instead of skipping values that cannot be read.
    pub fn values_strict(&self, node: NodeH) -> Result<Vec<(String, RegData)>> {
        let n = Self::handle(node)?;
        let offs = self.value_offsets(n).with_context(|| format!("cannot enumerate the values of key {}", self.name(node)))?;
        offs.into_iter()
            .map(|v| {
                let k = self.vk_name(v, true).with_context(|| format!("cannot read a value name in key {}", self.name(node)))?;
                let d = self.vk_data(v).with_context(|| format!("cannot read value {k:?} in key {}", self.name(node)))?;
                Ok((k, d))
            })
            .collect()
    }

    // ---- public API: changes ----

    /// Resolves a key path, creating missing keys.
    pub fn create_key(&mut self, path: &str) -> Result<NodeH> {
        let mut n = self.root();
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            n = match self.child(n, part)? {
                Some(c) => c,
                None => self.add_child(Self::handle(n)?, part).with_context(|| format!("cannot create key {part} in {path}"))? as NodeH,
            };
        }
        Ok(n)
    }

    fn add_child(&mut self, parent: u32, name: &str) -> Result<u32> {
        self.writable()?;
        let units = name_len_units(name);
        if name.is_empty() || units > 255 {
            bail!("invalid key name {name:?}");
        }
        let security = self.nk_field(parent, 44)?;
        let (nb, compressed) = encode_name(name);
        let mut nk = vec![0u8; 76 + nb.len()];
        nk[..2].copy_from_slice(b"nk");
        put16(&mut nk, 2, if compressed { KEY_COMP_NAME } else { 0 });
        nk[4..12].copy_from_slice(&filetime_now().to_le_bytes());
        put32(&mut nk, 16, parent);
        for f in [28, 32, 40, 48] {
            put32(&mut nk, f, NONE);
        }
        put32(&mut nk, 44, security);
        put16(&mut nk, 72, nb.len() as u16);
        nk[76..].copy_from_slice(&nb);
        if security != NONE {
            let sk = self.cell(security)?;
            if sk.len() < 20 || &sk[..2] != b"sk" {
                bail!("parent security cell {security:#x} is not a security node");
            }
        }
        let off = self.alloc_write(&nk)?;
        if security != NONE {
            let sk = self.cell_mut(security)?;
            let rc = le32(sk, 12)?;
            put32(sk, 12, rc + 1);
        }
        self.insert_subkey(parent, off, name)?;
        self.dirty = true;
        Ok(off)
    }

    fn key_order(&self, a: &[u16], b: u32) -> Result<std::cmp::Ordering> {
        Ok(a.cmp(&upcase(&self.nk_name(b)?)))
    }

    fn insert_subkey(&mut self, parent: u32, child: u32, name: &str) -> Result<()> {
        let (count, list) = (self.nk_field(parent, 20)?, self.nk_field(parent, 28)?);
        let up = upcase(name);
        if count == 0 || list == NONE {
            let mut l = vec![0u8; 12];
            l[..2].copy_from_slice(b"lh");
            put16(&mut l, 2, 1);
            put32(&mut l, 4, child);
            put32(&mut l, 8, lh_hash(&up));
            // A stale list pointer with a zero count is ignored, not freed.
            let new = self.alloc_write(&l)?;
            self.set_nk_field(parent, 28, new)?;
        } else if &self.cell(list)?[..2] == b"ri" {
            let mut leaves = Vec::new();
            let p = self.cell(list)?;
            for i in 0..usize::from(le16(p, 2)?) {
                leaves.push(le32(p, 4 + i * 4)?);
            }
            if leaves.is_empty() {
                bail!("empty ri list at {list:#x}");
            }
            let mut idx = leaves.len() - 1;
            for (i, &leaf) in leaves.iter().enumerate() {
                let mut e = Vec::new();
                self.list_entries(leaf, &mut e, false)?;
                if let Some(&last) = e.last() {
                    if self.key_order(&up, last)?.is_le() {
                        idx = i;
                        break;
                    }
                }
            }
            let new = self.leaf_insert(leaves[idx], child, name, &up)?;
            put32(self.cell_mut(list)?, 4 + idx * 4, new);
        } else {
            let new = self.leaf_insert(list, child, name, &up)?;
            self.set_nk_field(parent, 28, new)?;
        }
        self.set_nk_field(parent, 20, count + 1)?;
        let p = self.cell_mut(parent)?;
        let max = le16(p, 52)?;
        let want = (name_len_units(name) * 2) as u16;
        if want > max {
            put16(p, 52, want);
        }
        Ok(())
    }

    /// Copies a leaf list with `child` inserted in sorted position; frees the old list.
    fn leaf_insert(&mut self, list: u32, child: u32, name: &str, up: &[u16]) -> Result<u32> {
        let old = self.cell(list)?.to_vec();
        let kind: [u8; 2] = old[..2].try_into().unwrap();
        let n = usize::from(le16(&old, 2)?);
        let stride = if &kind == b"li" { 4 } else { 8 };
        if n >= 0xFFFF {
            bail!("subkey list is full");
        }
        // Binary search for the first entry that sorts after the new name.
        let (mut lo, mut hi) = (0usize, n);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let e = le32(&old, 4 + mid * stride)?;
            match self.key_order(up, e)? {
                std::cmp::Ordering::Greater => lo = mid + 1,
                std::cmp::Ordering::Equal => bail!("key {name} already exists"),
                std::cmp::Ordering::Less => hi = mid,
            }
        }
        let mut new = Vec::with_capacity(4 + (n + 1) * stride);
        new.extend_from_slice(&kind);
        new.extend_from_slice(&((n + 1) as u16).to_le_bytes());
        new.extend_from_slice(&old[4..4 + lo * stride]);
        new.extend_from_slice(&child.to_le_bytes());
        match &kind {
            b"lh" => new.extend_from_slice(&lh_hash(up).to_le_bytes()),
            b"lf" => new.extend_from_slice(&lf_hint(name).to_le_bytes()),
            _ => {}
        }
        new.extend_from_slice(&old[4 + lo * stride..4 + n * stride]);
        let off = self.alloc_write(&new)?;
        self.free_cell(list);
        Ok(off)
    }

    /// Frees collected cells once each (a cell merged into a free neighbour must not be freed again).
    fn free_all(&mut self, mut cells: Vec<u32>) {
        cells.sort_unstable();
        cells.dedup();
        for c in cells {
            self.free_cell(c);
        }
    }

    /// Compares a stored key or value name with upper-cased `want` without allocating for misses.
    fn name_matches(raw: &[u8], compressed: bool, want: &[u16]) -> bool {
        let units = if compressed { raw.len() } else { raw.len() / 2 };
        units == want.len() && decode_name(raw, compressed, false).is_ok_and(|n| upcase(&n) == want)
    }

    fn list_garbage(&self, list: u32, g: &mut Garbage) -> Result<()> {
        let p = self.cell(list)?;
        if &p[..2] == b"ri" {
            for i in 0..usize::from(le16(p, 2)?) {
                g.cells.push(le32(p, 4 + i * 4)?);
            }
        }
        g.cells.push(list);
        Ok(())
    }

    /// Adds or replaces one value, creating the key path as needed.
    pub fn set(&mut self, path: &str, name: &str, data: &RegData) -> Result<()> {
        self.writable()?;
        let node = Self::handle(self.create_key(path)?)?;
        self.set_value(node, name, data).with_context(|| format!("cannot set {path}\\{name}"))?;
        let back = self.value(node as NodeH, name)?;
        if back.as_ref() != Some(data) {
            bail!("read-back of {path}\\{name} differs");
        }
        Ok(())
    }

    fn set_value(&mut self, node: u32, name: &str, data: &RegData) -> Result<()> {
        if name_len_units(name) > 16383 {
            bail!("value name too long");
        }
        let existing = self.find_value(node, name)?;
        let mut old = Garbage::default();
        if let Some((_, v)) = existing {
            self.value_garbage(v, &mut old)?;
        }
        let (size, doff) = self.store_data(&data.data)?;
        let (nb, compressed) = encode_name(name);
        let mut vk = vec![0u8; 20 + nb.len()];
        vk[..2].copy_from_slice(b"vk");
        put16(&mut vk, 2, nb.len() as u16);
        put32(&mut vk, 4, size);
        put32(&mut vk, 8, doff);
        put32(&mut vk, 12, data.kind);
        put16(&mut vk, 16, if compressed { VALUE_COMP_NAME } else { 0 });
        vk[20..].copy_from_slice(&nb);
        let voff = self.alloc_write(&vk)?;
        match existing {
            Some((i, _)) => {
                let list = self.nk_field(node, 40)?;
                put32(self.cell_mut(list)?, i * 4, voff);
                self.free_all(old.cells);
            }
            None => {
                let mut offs = self.value_offsets(node)?;
                // A stale list pointer with a zero count is not owned and must not be freed.
                let old_list = if offs.is_empty() { NONE } else { self.nk_field(node, 40)? };
                offs.push(voff);
                let new = self.alloc_write(&offs.iter().flat_map(|o| o.to_le_bytes()).collect::<Vec<_>>())?;
                if old_list != NONE {
                    self.free_cell(old_list);
                }
                self.set_nk_field(node, 40, new)?;
                self.set_nk_field(node, 36, offs.len() as u32)?;
            }
        }
        let p = self.cell_mut(node)?;
        let (mn, md) = (le32(p, 60)?, le32(p, 64)?);
        put32(p, 60, mn.max(name_len_units(name) * 2));
        put32(p, 64, md.max(data.data.len() as u32));
        self.dirty = true;
        Ok(())
    }

    /// Removes one value; returns false if it did not exist.
    pub fn delete_value(&mut self, path: &str, name: &str) -> Result<bool> {
        let Some(node) = self.key(path)? else { return Ok(false) };
        let want = upcase(name);
        Ok(self.retain_values(node, |k, _| upcase(k) != want)? > 0)
    }

    /// Keeps only the values of `node` for which `keep` returns true; returns how many were removed.
    /// Reads all values first (fails if any value cannot be read) before changing anything.
    pub fn retain_values(&mut self, node: NodeH, mut keep: impl FnMut(&str, &RegData) -> bool) -> Result<usize> {
        self.writable()?;
        let n = Self::handle(node)?;
        let all = self.values_strict(node)?;
        let offs = self.value_offsets(n)?;
        let mut kept = Vec::new();
        let mut g = Garbage::default();
        for ((k, d), v) in all.iter().zip(&offs) {
            if keep(k, d) {
                kept.push(*v);
            } else {
                self.value_garbage(*v, &mut g)?;
            }
        }
        let removed = offs.len() - kept.len();
        if removed == 0 {
            return Ok(0);
        }
        let list = self.nk_field(n, 40)?;
        if kept.is_empty() {
            self.free_cell(list);
            self.set_nk_field(n, 40, NONE)?;
        } else {
            let l = self.cell_mut(list)?;
            for (i, v) in kept.iter().enumerate() {
                put32(l, i * 4, *v);
            }
        }
        self.set_nk_field(n, 36, kept.len() as u32)?;
        self.free_all(g.cells);
        self.dirty = true;
        Ok(removed)
    }

    /// Collects every cell of a key subtree (keys, values, lists, class names, security refs).
    fn tree_garbage(&self, node: u32, g: &mut Garbage, depth: usize) -> Result<()> {
        if depth > 512 {
            bail!("key nesting too deep");
        }
        for c in self.child_offsets(node)? {
            self.tree_garbage(c, g, depth + 1)?;
        }
        for v in self.value_offsets(node)? {
            self.value_garbage(v, g)?;
        }
        let p = self.nk(node)?;
        let (sc, sl, vc, vl, sec, class) = (le32(p, 20)?, le32(p, 28)?, le32(p, 36)?, le32(p, 40)?, le32(p, 44)?, le32(p, 48)?);
        if vc != 0 && vl != NONE {
            g.cells.push(vl);
        }
        if sc != 0 && sl != NONE {
            self.list_garbage(sl, g)?;
        }
        if class != NONE && le16(p, 74)? != 0 {
            self.cell(class)?;
            g.cells.push(class);
        }
        if sec != NONE {
            g.security.push(sec);
        }
        g.cells.push(node);
        Ok(())
    }

    /// Checks that releasing `refs` (with repetitions) succeeds, before anything is changed.
    fn check_security_release(&self, refs: &[u32]) -> Result<()> {
        let mut uses: BTreeMap<u32, u32> = BTreeMap::new();
        for &sk in refs {
            *uses.entry(sk).or_default() += 1;
        }
        for (&sk, &n) in &uses {
            let p = self.cell(sk)?;
            if p.len() < 20 || &p[..2] != b"sk" {
                bail!("cell {sk:#x} is not a security node");
            }
            let (flink, blink, rc) = (le32(p, 4)?, le32(p, 8)?, le32(p, 12)?);
            if rc < n {
                bail!("security node {sk:#x} has refcount {rc} but {n} users are deleted");
            }
            if rc == n {
                if flink == sk || blink == sk {
                    bail!("refusing to free the last security descriptor");
                }
                // Neighbours that are freed too stay valid sk cells until their own (later)
                // release, and each release relinks the current neighbours, so the ring stays intact.
                for nb in [flink, blink] {
                    let q = self.cell(nb)?;
                    if q.len() < 20 || &q[..2] != b"sk" {
                        bail!("security list neighbour {nb:#x} is not a security node");
                    }
                }
            }
        }
        Ok(())
    }

    fn release_security(&mut self, sk: u32) -> Result<()> {
        let p = self.cell(sk)?;
        if p.len() < 20 || &p[..2] != b"sk" {
            bail!("cell {sk:#x} is not a security node");
        }
        let (flink, blink, rc) = (le32(p, 4)?, le32(p, 8)?, le32(p, 12)?);
        if rc > 1 {
            put32(self.cell_mut(sk)?, 12, rc - 1);
            return Ok(());
        }
        if flink == sk || blink == sk {
            bail!("refusing to free the last security descriptor");
        }
        put32(self.cell_mut(blink)?, 4, flink);
        put32(self.cell_mut(flink)?, 8, blink);
        self.free_cell(sk);
        Ok(())
    }

    /// Removes `child` from the subkey list of `parent` (in place).
    fn remove_subkey(&mut self, parent: u32, child: u32) -> Result<()> {
        let (count, list) = (self.nk_field(parent, 20)?, self.nk_field(parent, 28)?);
        if count == 0 || list == NONE {
            bail!("key {child:#x} is not listed in its parent");
        }
        let p = self.cell(list)?;
        if &p[..2] == b"ri" {
            let n = usize::from(le16(p, 2)?);
            let leaves: Vec<u32> = (0..n).map(|i| le32(p, 4 + i * 4)).collect::<Result<_>>()?;
            let mut done = false;
            for (i, leaf) in leaves.into_iter().enumerate() {
                if self.leaf_remove(leaf, child)? {
                    if le16(self.cell(leaf)?, 2)? == 0 {
                        self.free_cell(leaf);
                        let l = self.cell_mut(list)?;
                        l.copy_within(4 + (i + 1) * 4..4 + n * 4, 4 + i * 4);
                        put16(l, 2, (n - 1) as u16);
                        if n == 1 {
                            self.free_cell(list);
                            self.set_nk_field(parent, 28, NONE)?;
                        }
                    }
                    done = true;
                    break;
                }
            }
            if !done {
                bail!("key {child:#x} is not listed in its parent");
            }
        } else {
            if !self.leaf_remove(list, child)? {
                bail!("key {child:#x} is not listed in its parent");
            }
            if le16(self.cell(list)?, 2)? == 0 {
                self.free_cell(list);
                self.set_nk_field(parent, 28, NONE)?;
            }
        }
        self.set_nk_field(parent, 20, count - 1)
    }

    fn leaf_remove(&mut self, list: u32, child: u32) -> Result<bool> {
        let p = self.cell(list)?;
        let n = usize::from(le16(p, 2)?);
        let stride = match &p[..2] {
            b"lf" | b"lh" => 8,
            b"li" => 4,
            _ => bail!("unexpected subkey list type at {list:#x}"),
        };
        if 4 + n * stride > p.len() {
            bail!("subkey list {list:#x} exceeds its cell");
        }
        let Some(i) = (0..n).find(|&i| le32(p, 4 + i * stride).ok() == Some(child)) else { return Ok(false) };
        let l = self.cell_mut(list)?;
        l.copy_within(4 + (i + 1) * stride..4 + n * stride, 4 + i * stride);
        put16(l, 2, (n - 1) as u16);
        Ok(true)
    }

    /// Deletes a key (by handle) with all subkeys. The handle and those of its subkeys become invalid.
    pub fn delete_node(&mut self, node: NodeH) -> Result<()> {
        self.writable()?;
        let n = Self::handle(node)?;
        if n == self.root {
            bail!("refusing to delete the hive root");
        }
        let name = self.name(node);
        let mut g = Garbage::default();
        self.tree_garbage(n, &mut g, 0).with_context(|| format!("cannot delete key {name}"))?;
        self.check_security_release(&g.security).with_context(|| format!("cannot delete key {name}"))?;
        let parent = self.nk_field(n, 16)?;
        self.remove_subkey(parent, n).with_context(|| format!("cannot delete key {name}"))?;
        for sk in g.security {
            self.release_security(sk)?;
        }
        self.free_all(g.cells);
        self.dirty = true;
        Ok(())
    }

    /// True if the key has neither values nor subkeys.
    pub fn is_empty_key(&self, node: NodeH) -> Result<bool> {
        let n = Self::handle(node)?;
        Ok(self.value_offsets(n)?.is_empty() && self.child_offsets(n)?.is_empty())
    }

    /// Deletes a key and all subkeys; returns false if it did not exist.
    pub fn delete_key(&mut self, path: &str) -> Result<bool> {
        let Some(node) = self.key(path)? else { return Ok(false) };
        self.delete_node(node).with_context(|| format!("cannot delete key {path}"))?;
        Ok(true)
    }

    /// Writes changes back to the hive file. The contents are replaced in place, which keeps the
    /// file's identity.
    pub fn commit(&mut self) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let seq = le32(&self.data, 4)?.wrapping_add(1);
        put32(&mut self.data, 4, seq);
        put32(&mut self.data, 8, seq);
        self.data[12..20].copy_from_slice(&filetime_now().to_le_bytes());
        let mut sum = (0..127).fold(0u32, |x, i| x ^ u32::from_le_bytes(self.data[i * 4..i * 4 + 4].try_into().unwrap()));
        if sum == u32::MAX {
            sum = u32::MAX - 1;
        } else if sum == 0 {
            sum = 1;
        }
        put32(&mut self.data, 0x1FC, sum);
        self.write_in_place().map_err(|e| anyhow!("cannot write hive {}: {e}", self.path.display()))?;
        self.dirty = false;
        Ok(())
    }
}

impl Hive {
    /// Writes a complete copy next to the hive first (so a full disk fails before the original is
    /// touched), then overwrites the original in place and syncs it.
    fn write_in_place(&self) -> std::io::Result<()> {
        use std::io::Write;
        let tmp = self.path.with_extension("lean11-new");
        std::fs::write(&tmp, &self.data)?;
        let mut f = std::fs::OpenOptions::new().write(true).open(&self.path)?;
        f.write_all(&self.data)?;
        f.set_len(self.data.len() as u64)?;
        f.sync_all()?;
        std::fs::remove_file(&tmp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_roundtrip() {
        let d = RegData::sz("Grüße");
        assert_eq!(d.as_string().unwrap(), "Grüße");
        assert_eq!(RegData::dword(4).as_dword(), Some(4));
    }

    /// A minimal valid hive: base block, one bin with a security node and the root key.
    fn empty_hive(path: &Path) {
        let mut d = vec![0u8; BASE + BIN];
        d[..4].copy_from_slice(b"regf");
        for (o, v) in [(4, 1), (8, 1), (0x14, 1), (0x18, 5), (0x20, 1), (0x28, BIN as u32), (0x2C, 1)] {
            put32(&mut d, o, v);
        }
        d[BASE..BASE + 4].copy_from_slice(b"hbin");
        put32(&mut d, BASE + 8, BIN as u32);
        // sk at 0x20: 20 bytes header + 20 bytes descriptor (revision 1, self-relative, no ACLs)
        let sk = 0x20usize;
        let sk_len = 48i32;
        d[BASE + sk..BASE + sk + 4].copy_from_slice(&(-sk_len).to_le_bytes());
        let p = BASE + sk + 4;
        d[p..p + 2].copy_from_slice(b"sk");
        put32(&mut d, p + 4, sk as u32);
        put32(&mut d, p + 8, sk as u32);
        put32(&mut d, p + 12, 1);
        put32(&mut d, p + 16, 20);
        d[p + 20] = 1;
        put16(&mut d, p + 22, 0x8000);
        // root nk
        let nk = sk + sk_len as usize;
        let name = b"ROOT";
        let nk_len = ((4 + 76 + name.len() + 7) & !7) as i32;
        d[BASE + nk..BASE + nk + 4].copy_from_slice(&(-nk_len).to_le_bytes());
        let p = BASE + nk + 4;
        d[p..p + 2].copy_from_slice(b"nk");
        put16(&mut d, p + 2, 0x2C);
        for f in [16, 28, 32, 40, 48] {
            put32(&mut d, p + f, NONE);
        }
        put32(&mut d, p + 44, sk as u32);
        put16(&mut d, p + 72, name.len() as u16);
        d[p + 76..p + 76 + name.len()].copy_from_slice(name);
        let free = nk + nk_len as usize;
        d[BASE + free..BASE + free + 4].copy_from_slice(&((BIN - free) as i32).to_le_bytes());
        put32(&mut d, 0x24, nk as u32);
        std::fs::write(path, d).unwrap();
    }

    #[test]
    fn synthetic_edit_roundtrip() {
        let dir = std::env::temp_dir().join(format!("lean11-hive-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hive");
        empty_hive(&path);
        let big: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        {
            let mut h = Hive::open(&path, true).unwrap();
            for name in ["Zeta", "alpha", "Mid", "beta", "Ünïcode", "日本"] {
                h.set(&format!(r"Software\{name}"), "V", &RegData::dword(7)).unwrap();
            }
            for i in 0..300 {
                h.set(&format!(r"Software\Many\K{i:04}"), "", &RegData::sz("x")).unwrap();
            }
            h.set(r"Software\alpha", "Big", &RegData { kind: REG_BINARY, data: big.clone() }).unwrap();
            h.set(r"Software\alpha", "Empty", &RegData { kind: REG_BINARY, data: vec![] }).unwrap();
            h.set(r"Software\alpha", "Text", &RegData::sz("hallo welt, ein längerer Text")).unwrap();
            h.set(r"Software\alpha", "Text", &RegData::sz("ersetzt")).unwrap();
            h.commit().unwrap();
        }
        let mut h = Hive::open(&path, true).unwrap();
        let names: Vec<String> = h.children(h.key("software").unwrap().unwrap()).into_iter().map(|c| c.0).collect();
        assert_eq!(names, ["alpha", "beta", "Many", "Mid", "Zeta", "Ünïcode", "日本"]);
        assert_eq!(h.get(r"SOFTWARE\ALPHA", "big").unwrap().unwrap().data, big);
        assert_eq!(h.get(r"Software\alpha", "Text").unwrap().unwrap().as_string().unwrap(), "ersetzt");
        assert_eq!(h.get(r"Software\alpha", "Empty").unwrap().unwrap().data, Vec::<u8>::new());
        assert_eq!(h.children(h.key(r"Software\Many").unwrap().unwrap()).len(), 300);
        assert!(h.delete_value(r"Software\alpha", "BIG").unwrap());
        assert!(!h.delete_value(r"Software\alpha", "BIG").unwrap());
        assert!(h.delete_key(r"Software\Many").unwrap());
        assert!(h.delete_key(r"Software\Zeta").unwrap());
        assert!(h.delete_node(h.root()).is_err());
        h.commit().unwrap();
        drop(h);
        let h = Hive::open(&path, false).unwrap();
        let names: Vec<String> = h.children(h.key("Software").unwrap().unwrap()).into_iter().map(|c| c.0).collect();
        assert_eq!(names, ["alpha", "beta", "Mid", "Ünïcode", "日本"]);
        assert_eq!(h.values(h.key(r"Software\alpha").unwrap().unwrap()).len(), 3);
        // root security descriptor: refcount back to root + 5 keys + Software
        let sk = le32(h.nk(h.root).unwrap(), 44).unwrap();
        assert_eq!(le32(h.cell(sk).unwrap(), 12).unwrap(), 7);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Needs a real hive: LEAN11_TEST_HIVE=/path/to/SOFTWARE (a copy, it is modified).
    #[test]
    fn real_hive_edit() {
        let Ok(p) = std::env::var("LEAN11_TEST_HIVE") else { return };
        let path = PathBuf::from(p);
        let mut h = Hive::open(&path, true).unwrap();
        h.set(r"Policies\Microsoft\Windows\T11Test", "Answer", &RegData::dword(42)).unwrap();
        h.set(r"Policies\Microsoft\Windows\T11Test", "Text", &RegData::sz("hallo")).unwrap();
        h.commit().unwrap();
        drop(h);
        let mut h = Hive::open(&path, true).unwrap();
        assert_eq!(h.get(r"policies\microsoft\windows\t11test", "answer").unwrap().unwrap().as_dword(), Some(42));
        assert!(h.delete_value(r"Policies\Microsoft\Windows\T11Test", "Text").unwrap());
        assert!(h.delete_key(r"Policies\Microsoft\Windows\T11Test").unwrap());
        h.commit().unwrap();
        drop(h);
        let h = Hive::open(&path, false).unwrap();
        assert!(h.key(r"Policies\Microsoft\Windows\T11Test").unwrap().is_none());
    }
}
