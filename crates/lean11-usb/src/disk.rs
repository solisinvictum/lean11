//! Byte-addressed access to a disk or image through 1 MiB blocks: raw devices (Windows physical drives,
//! macOS raw disks, Linux with O_DIRECT) only accept sector-aligned transfers from aligned buffers, and
//! FAT writes are small. Blocks are cached and written back in order (`sync`, `into_inner`; `flush` keeps them).
//!
//! On a freshly partitioned target (`fresh`) a block that was never written in this session is not read
//! but starts as zeros: everything the file system later reads it wrote itself, and the rest is free
//! space. That avoids reading back old stick contents before overwriting them.

use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom, Write};

pub const BLOCK: usize = 1 << 20;
const ALIGN: usize = 4096;
const CACHE_BLOCKS: usize = 32;

/// A buffer whose data starts at a 4096-byte boundary.
struct ABuf {
    v: Vec<u8>,
    off: usize,
}

impl ABuf {
    fn new(len: usize) -> Self {
        let v = vec![0u8; len + ALIGN];
        let off = (ALIGN - (v.as_ptr() as usize % ALIGN)) % ALIGN;
        ABuf { v, off }
    }
    fn get(&self) -> &[u8] {
        &self.v[self.off..self.off + BLOCK]
    }
    fn get_mut(&mut self) -> &mut [u8] {
        &mut self.v[self.off..self.off + BLOCK]
    }
}

struct Slot {
    buf: ABuf,
    dirty: bool,
    used: u64,
}

pub struct CachedDisk<F: Read + Write + Seek> {
    inner: F,
    len: u64,
    pos: u64,
    fresh: bool,
    written: Vec<u64>,
    slots: HashMap<u64, Slot>,
    tick: u64,
    /// bytes written back to the target
    pub flushed: u64,
}

impl<F: Read + Write + Seek> CachedDisk<F> {
    /// `len` must be a multiple of 512 (the size of the device or image).
    pub fn new(inner: F, len: u64, fresh: bool) -> Self {
        let blocks = len.div_ceil(BLOCK as u64);
        CachedDisk { inner, len, pos: 0, fresh, written: vec![0; blocks.div_ceil(64) as usize], slots: HashMap::new(), tick: 0, flushed: 0 }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn block_len(&self, idx: u64) -> usize {
        (self.len - idx * BLOCK as u64).min(BLOCK as u64) as usize
    }

    fn was_written(&self, idx: u64) -> bool {
        self.written[(idx / 64) as usize] & (1 << (idx % 64)) != 0
    }

    fn write_back(&mut self, idx: u64) -> io::Result<()> {
        let n = self.block_len(idx);
        let Some(slot) = self.slots.get_mut(&idx) else { return Ok(()) };
        if !slot.dirty {
            return Ok(());
        }
        // whole sectors only: n is a multiple of 512 because len is
        self.inner.seek(SeekFrom::Start(idx * BLOCK as u64))?;
        self.inner.write_all(&slot.buf.get()[..n])?;
        slot.dirty = false;
        self.flushed += n as u64;
        self.written[(idx / 64) as usize] |= 1 << (idx % 64);
        Ok(())
    }

    fn slot(&mut self, idx: u64) -> io::Result<&mut Slot> {
        self.tick += 1;
        if !self.slots.contains_key(&idx) {
            if self.slots.len() >= CACHE_BLOCKS {
                // evict the least recently used block (written back first)
                let victim = *self.slots.iter().min_by_key(|(_, s)| s.used).map(|(k, _)| k).expect("cache not empty");
                self.write_back(victim)?;
                self.slots.remove(&victim);
            }
            let mut buf = ABuf::new(BLOCK);
            let n = self.block_len(idx);
            if !self.fresh || self.was_written(idx) {
                self.inner.seek(SeekFrom::Start(idx * BLOCK as u64))?;
                self.inner.read_exact(&mut buf.get_mut()[..n])?;
            }
            self.slots.insert(idx, Slot { buf, dirty: false, used: 0 });
        }
        let tick = self.tick;
        let s = self.slots.get_mut(&idx).expect("just inserted");
        s.used = tick;
        Ok(s)
    }

    /// Writes all dirty blocks back in disk order and flushes the target.
    pub fn sync(&mut self) -> io::Result<()> {
        let mut dirty: Vec<u64> = self.slots.iter().filter(|(_, s)| s.dirty).map(|(k, _)| *k).collect();
        dirty.sort_unstable();
        for idx in dirty {
            self.write_back(idx)?;
        }
        self.inner.flush()
    }

    /// Writes everything back and returns the target.
    pub fn into_inner(mut self) -> io::Result<F> {
        self.sync()?;
        let CachedDisk { inner, .. } = self;
        Ok(inner)
    }

    pub fn inner_mut(&mut self) -> &mut F {
        &mut self.inner
    }
}

impl<F: Read + Write + Seek> Read for CachedDisk<F> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || out.is_empty() {
            return Ok(0);
        }
        let idx = self.pos / BLOCK as u64;
        let off = (self.pos % BLOCK as u64) as usize;
        let n = out.len().min(self.block_len(idx) - off);
        let s = self.slot(idx)?;
        out[..n].copy_from_slice(&s.buf.get()[off..off + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl<F: Read + Write + Seek> Write for CachedDisk<F> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        if self.pos >= self.len {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "write beyond the end of the target"));
        }
        let idx = self.pos / BLOCK as u64;
        let off = (self.pos % BLOCK as u64) as usize;
        let n = data.len().min(self.block_len(idx) - off);
        let s = self.slot(idx)?;
        s.buf.get_mut()[off..off + n].copy_from_slice(&data[..n]);
        s.dirty = true;
        self.pos += n as u64;
        Ok(n)
    }

    /// Keeps the cache: the file system flushes after every file, and writing the FAT and directory blocks
    /// back each time multiplied the writes (a 1 MiB block per small file; unbuffered raw devices on macOS
    /// and Windows show it). Blocks go back on eviction and with `sync` / `into_inner`, which every
    /// writer calls at the end.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<F: Read + Write + Seek> Seek for CachedDisk<F> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let p = match to {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => self.len as i128 + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if p < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before the start"));
        }
        self.pos = p as u64;
        Ok(self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// flush keeps the blocks (the file system flushes after every file); sync writes each dirty block once
    #[test]
    fn flush_keeps_the_cache() {
        let len = 8 * BLOCK as u64;
        let mut d = CachedDisk::new(Cursor::new(vec![0u8; len as usize]), len, true);
        for i in 0..100u64 {
            d.seek(SeekFrom::Start(i * 512)).unwrap();
            d.write_all(b"fat entry").unwrap();
            d.flush().unwrap();
        }
        assert_eq!(d.flushed, 0);
        d.sync().unwrap();
        assert_eq!(d.flushed, BLOCK as u64);
    }

    #[test]
    fn writes_back_and_reads_again() {
        let len = 5 * BLOCK as u64 + 4096;
        let mut d = CachedDisk::new(Cursor::new(vec![0xAAu8; len as usize]), len, true);
        d.seek(SeekFrom::Start(BLOCK as u64 - 3)).unwrap();
        d.write_all(b"abcdef").unwrap();
        d.seek(SeekFrom::Start(len - 10)).unwrap();
        d.write_all(b"0123456789").unwrap();
        assert!(d.write(b"x").is_err());
        d.seek(SeekFrom::Start(BLOCK as u64 - 3)).unwrap();
        let mut b = [0u8; 6];
        d.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"abcdef");
        d.sync().unwrap();
        let v = d.inner.into_inner();
        assert_eq!(&v[BLOCK - 3..BLOCK + 3], b"abcdef");
        // fresh: untouched bytes of a written block are zeros, unwritten blocks stay as they were
        assert_eq!(v[BLOCK - 4], 0);
        assert_eq!(v[2 * BLOCK + 5], 0xAA);
        assert_eq!(&v[len as usize - 10..], b"0123456789");
    }

    #[test]
    fn eviction_keeps_data() {
        let len = (CACHE_BLOCKS as u64 + 8) * BLOCK as u64;
        let mut d = CachedDisk::new(Cursor::new(vec![0u8; len as usize]), len, true);
        for i in 0..CACHE_BLOCKS as u64 + 8 {
            d.seek(SeekFrom::Start(i * BLOCK as u64 + 7)).unwrap();
            d.write_all(&[i as u8 + 1; 3]).unwrap();
        }
        // block 0 was evicted and written; reading it must come back from the target, not zeros
        d.seek(SeekFrom::Start(7)).unwrap();
        let mut b = [0u8; 3];
        d.read_exact(&mut b).unwrap();
        assert_eq!(b, [1, 1, 1]);
    }
}
