//! Writes a small tree (nested dirs, unicode names, empty file, a file larger than one extent
//! chunk is too big for a test, so several blocks) and reads it back with the UDF reader.

use std::fs;
use std::path::PathBuf;

fn tmpdir(name: &str) -> PathBuf {
    let base = std::env::var("CARGO_TARGET_TMPDIR").map(PathBuf::from).unwrap_or_else(|_| std::env::temp_dir());
    let d = base.join(format!("lean11-iso-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn write_then_read_back() {
    let src = tmpdir("src");
    fs::create_dir_all(src.join("boot")).unwrap();
    fs::create_dir_all(src.join("efi/microsoft/boot")).unwrap();
    fs::create_dir_all(src.join("sources/de-DE")).unwrap();
    fs::create_dir_all(src.join("leer")).unwrap();
    fs::write(src.join("boot/etfsboot.com"), vec![0xEBu8; 4096]).unwrap();
    fs::write(src.join("efi/microsoft/boot/efisys.bin"), vec![0x55u8; 1474560]).unwrap();
    fs::write(src.join("sources/de-DE/Größenänderung€.txt"), "unicode").unwrap();
    fs::write(src.join("empty.txt"), "").unwrap();
    let big: Vec<u8> = (0..5_000_003u32).map(|i| (i * 7 % 251) as u8).collect();
    fs::write(src.join("sources/big.bin"), &big).unwrap();

    let out = tmpdir("out").join("t.iso");
    let opts = lean11_iso::WriteOptions {
        label: "LEAN11_TEST".into(),
        bios_image: Some("boot/etfsboot.com".into()),
        uefi_image: Some("efi/microsoft/boot/efisys.bin".into()),
    };
    lean11_iso::write_iso(&src, &out, &opts, &mut |_, _| {}).unwrap();

    let r = lean11_iso::UdfReader::open(&out).unwrap();
    let all = r.walk().unwrap();
    let paths: Vec<&str> = all.iter().map(|e| e.path.as_str()).collect();
    for p in ["boot", "boot/etfsboot.com", "efi/microsoft/boot/efisys.bin", "empty.txt", "leer", "sources/big.bin", "sources/de-DE/Größenänderung€.txt"] {
        assert!(paths.contains(&p), "{p} missing in {paths:?}");
    }
    let e = r.find("sources/big.bin").unwrap().unwrap();
    assert_eq!(r.read_file(&e).unwrap(), big);
    assert_eq!(r.read_range(&e, 4_999_990, 100).unwrap(), big[4_999_990..].to_vec());
    let u = r.find("sources/de-de/größenänderung€.txt").unwrap();
    assert!(u.is_none() || r.read_file(&u.unwrap()).unwrap() == b"unicode");
    assert_eq!(r.find("empty.txt").unwrap().unwrap().size, 0);
    assert_eq!(r.label().unwrap(), "LEAN11_TEST");

    // El Torito: boot catalog at sector 22 points into the UDF file data
    let cat = lean11_iso::reader::read_at(&out, 22 * 2048, 128).unwrap();
    assert_eq!((cat[0], cat[30], cat[31]), (1, 0x55, 0xAA));
    let sum = cat[..32].chunks_exact(2).fold(0u16, |a, c| a.wrapping_add(u16::from_le_bytes([c[0], c[1]])));
    assert_eq!(sum, 0, "validation entry checksum");
    let bios_lba = u32::from_le_bytes(cat[40..44].try_into().unwrap()) as u64;
    assert_eq!(lean11_iso::reader::read_at(&out, bios_lba * 2048, 4).unwrap(), vec![0xEB; 4]);
    assert_eq!((cat[64], cat[65]), (0x91, 0xEF));
    let uefi_lba = u32::from_le_bytes(cat[104..108].try_into().unwrap()) as u64;
    assert_eq!(lean11_iso::reader::read_at(&out, uefi_lba * 2048, 4).unwrap(), vec![0x55; 4]);
    fs::remove_dir_all(&src).ok();
    fs::remove_file(&out).ok();
}
