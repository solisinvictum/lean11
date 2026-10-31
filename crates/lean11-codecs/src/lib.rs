//! wimlib's XPRESS, LZX and LZMS compressors (generated in `generated/`, see README) behind a safe API.

#[allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut,
    unused_variables,
    unused_unsafe,
    unused_parens,
    clashing_extern_declarations,
    unpredictable_function_pointer_comparisons,
    static_mut_refs,
    unsafe_op_in_unsafe_fn,
    clippy::all
)]
mod generated {
    pub mod compress_common;
    pub mod decompress_common;
    pub mod divsufsort;
    pub mod lcpit_matchfinder;
    pub mod lzms_common;
    pub mod lzms_compress;
    pub mod lzms_decompress;
    pub mod lzx_common;
    pub mod lzx_compress;
    pub mod lzx_decompress;
    pub mod xpress_compress;
    pub mod xpress_decompress;
}

use generated::lzx_decompress::decompressor_ops;

/// One decompressor instance (not shared between threads).
pub struct Decompressor {
    ops: *const decompressor_ops,
    ctx: *mut core::ffi::c_void,
    max_block: usize,
}

unsafe impl Send for Decompressor {}

impl Decompressor {
    /// `max_block`: largest uncompressed chunk passed to `decompress`.
    pub fn new(kind: Kind, max_block: usize) -> Option<Self> {
        unsafe {
            let ops: *const decompressor_ops = match kind {
                Kind::Lzx => &raw const generated::lzx_decompress::lzx_decompressor_ops,
                Kind::Lzms => (&raw const generated::lzms_decompress::lzms_decompressor_ops).cast(),
                Kind::Xpress => (&raw const generated::xpress_decompress::xpress_decompressor_ops).cast(),
            };
            let mut ctx = core::ptr::null_mut();
            let r = ((*ops).create_decompressor?)(max_block, &mut ctx);
            (r == 0).then_some(Decompressor { ops, ctx, max_block })
        }
    }

    /// Decompresses `input` into exactly `output.len()` bytes; false on corrupt data.
    pub fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> bool {
        if output.len() > self.max_block {
            return false;
        }
        let Some(f) = (unsafe { (*self.ops).decompress }) else { return false };
        unsafe { f(input.as_ptr().cast(), input.len(), output.as_mut_ptr().cast(), output.len(), self.ctx) == 0 }
    }
}

impl Drop for Decompressor {
    fn drop(&mut self) {
        unsafe {
            if let Some(f) = (*self.ops).free_decompressor {
                f(self.ctx);
            }
        }
    }
}

use generated::lzms_compress::compressor_ops;

/// Codec of a compressor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Xpress,
    Lzx,
    Lzms,
}

/// wimlib's default compression level.
pub const DEFAULT_LEVEL: u32 = 50;
/// wimlib's level for `--compress=maximum` (LZX).
pub const MAXIMUM_LEVEL: u32 = 100;

/// One compressor instance. It keeps large work buffers; use one per thread.
pub struct Compressor {
    ops: *const compressor_ops,
    ctx: *mut core::ffi::c_void,
    max_block: usize,
}

// The instance owns its buffers; the static operation tables are read-only.
unsafe impl Send for Compressor {}

impl Compressor {
    /// `max_block`: largest input passed to `compress`; `level`: wimlib compression level.
    pub fn new(kind: Kind, max_block: usize, level: u32) -> Option<Self> {
        unsafe {
            let ops: *const compressor_ops = match kind {
                Kind::Lzms => &raw const generated::lzms_compress::lzms_compressor_ops,
                Kind::Lzx => (&raw const generated::lzx_compress::lzx_compressor_ops).cast(),
                Kind::Xpress => (&raw const generated::xpress_compress::xpress_compressor_ops).cast(),
            };
            let mut ctx = core::ptr::null_mut();
            let r = ((*ops).create_compressor?)(max_block, level, false, &mut ctx);
            (r == 0 && !ctx.is_null()).then_some(Compressor { ops, ctx, max_block })
        }
    }

    /// Memory a compressor needs, in bytes (for sizing thread pools).
    pub fn needed_memory(kind: Kind, max_block: usize, level: u32) -> u64 {
        unsafe {
            let ops: *const compressor_ops = match kind {
                Kind::Lzms => &raw const generated::lzms_compress::lzms_compressor_ops,
                Kind::Lzx => (&raw const generated::lzx_compress::lzx_compressor_ops).cast(),
                Kind::Xpress => (&raw const generated::xpress_compress::xpress_compressor_ops).cast(),
            };
            (*ops).get_needed_memory.map_or(0, |f| f(max_block, level, false))
        }
    }

    /// Compresses `input` into fewer than `input.len()` bytes; `None` if it does not shrink.
    pub fn compress(&mut self, input: &[u8]) -> Option<Vec<u8>> {
        if input.is_empty() || input.len() > self.max_block {
            return None;
        }
        let capacity = input.len() - 1;
        let mut out = vec![0u8; capacity.max(1)];
        let n = unsafe { ((*self.ops).compress?)(input.as_ptr().cast(), input.len(), out.as_mut_ptr().cast(), capacity, self.ctx) };
        (n != 0).then(|| {
            out.truncate(n);
            out
        })
    }
}

impl Drop for Compressor {
    fn drop(&mut self) {
        unsafe {
            if let Some(f) = (*self.ops).free_compressor {
                f(self.ctx);
            }
        }
    }
}

/// Memory helpers of wimlib's util.c used by the generated code.
mod alloc_shim {
    use core::ffi::c_void;
    unsafe extern "C" {
        fn malloc(size: usize) -> *mut c_void;
        fn free(p: *mut c_void);
    }
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn wimlib_malloc(size: usize) -> *mut c_void {
        unsafe { malloc(size.max(1)) }
    }
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn wimlib_free_memory(p: *mut c_void) {
        unsafe { free(p) }
    }
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn wimlib_aligned_malloc(size: usize, alignment: usize) -> *mut c_void {
        let word = core::mem::size_of::<*mut c_void>();
        unsafe {
            let raw = malloc(word + alignment - 1 + size);
            if raw.is_null() {
                return raw;
            }
            let p = ((raw as usize + word + alignment - 1) & !(alignment - 1)) as *mut *mut c_void;
            *p.sub(1) = raw;
            p.cast()
        }
    }
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn wimlib_aligned_free(p: *mut c_void) {
        if !p.is_null() {
            unsafe { free(*(p as *mut *mut c_void).sub(1)) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        let mut v = Vec::new();
        let mut x = 12345u32;
        for i in 0..400_000u32 {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            v.extend_from_slice(format!("line {} value {}\n", i % 977, (x >> 16) % 100).as_bytes());
            if i % 7 == 0 {
                v.extend_from_slice(&(i * 4).to_le_bytes());
            }
        }
        v
    }

    #[test]
    fn roundtrip_with_independent_decoders() {
        let data = sample();
        for (kind, chunk) in [(Kind::Xpress, 32768usize), (Kind::Lzx, 32768), (Kind::Lzms, 1 << 20)] {
            let mut c = Compressor::new(kind, chunk, DEFAULT_LEVEL).unwrap();
            let (mut inb, mut outb) = (0, 0);
            for ch in data.chunks(chunk) {
                let z = c.compress(ch).expect("text must shrink");
                let mut own = vec![0u8; ch.len()];
                assert!(Decompressor::new(kind, chunk).unwrap().decompress(&z, &mut own), "{kind:?} own decoder");
                assert_eq!(own, ch, "{kind:?} own roundtrip");
                let mut back = vec![0u8; ch.len()];
                match kind {
                    Kind::Xpress => ms_compress::decompress_xpress(&z, &mut back).map(drop).unwrap(),
                    Kind::Lzx => ms_compress::lzx::decompress_lzx(&z, &mut back, chunk).unwrap(),
                    Kind::Lzms => ms_compress::lzms::decompress_lzms(&z, &mut back).unwrap(),
                }
                assert_eq!(back, ch, "{kind:?} roundtrip");
                inb += ch.len();
                outb += z.len();
            }
            assert!(outb * 3 < inb, "{kind:?} ratio {outb}/{inb}");
        }
        assert!(Compressor::needed_memory(Kind::Lzms, 1 << 26, DEFAULT_LEVEL) > 1 << 26);
    }
}
