# lean11-codecs

wimlib's compressors for XPRESS, LZX and LZMS (`src/generated/`), translated from wimlib 1.14.5 to Rust with
c2rust by `scripts/codecs/transpile.sh`, plus a safe wrapper (`Compressor`). The output is byte for byte
identical to wimlib's (checked chunk by chunk against libwim on real Windows files), so lean11 writes the
same WIM/ESD data as wimlib and DISM-compatible ratios (LZMS 0.220, LZX 0.297 on Windows system files).

The generated files are not edited by hand; fixes go into the script. Licenses: `lzms_*`, `lzx_*` and
`xpress_compress` are LGPL-2.1-or-later (Eric Biggers), `lcpit_matchfinder` and `compress_common` MIT
(Eric Biggers), `divsufsort` MIT (Yuta Mori). The translation targets aarch64 C semantics so that only
wimlib's portable code paths are used; it runs on x86_64 and aarch64 alike.

Note: `xpress_free_compressor` compares function pointers to decide whether near-optimal buffers exist;
that mode is only used from compression level 60, lean11 uses 50.
