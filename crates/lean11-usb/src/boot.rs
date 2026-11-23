//! Legacy BIOS boot code, taken at run time from `boot\bootsect.exe` of the Windows media being written
//! (lean11 ships no Microsoft code). bootsect.exe embeds its boot records as raw 512-byte blocks:
//! the NT6 MBR (the one with the TPM measurement, "TCPA") and the FAT32 boot record that loads BOOTMGR:
//! sector 0 with the code, an FSInfo template, then the second part of the code, which sector 0 reads
//! from sector 12 of the partition (hidden sectors + 0x0C). They are found by their signatures, not by
//! offsets, so other builds of bootsect.exe work too.

/// Boot code for an MBR disk with one FAT32 partition booting BOOTMGR.
#[derive(Clone)]
pub struct BootCode {
    /// MBR bootstrap code (the first 440 bytes; disk signature and partition table are ours).
    pub mbr: [u8; 440],
    /// FAT32 boot sector 0 (BPB area replaced when installed).
    pub vbr0: [u8; 512],
    /// Second part of the FAT32 boot code (goes to sector 12 of the partition).
    pub vbr2: [u8; 512],
}

fn find(hay: &[u8], needle: &[u8]) -> impl Iterator<Item = usize> {
    hay.windows(needle.len()).enumerate().filter(move |(_, w)| *w == needle).map(|(i, _)| i)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Finds the NT6 boot records in the bytes of bootsect.exe.
pub fn from_bootsect(exe: &[u8]) -> Option<BootCode> {
    let sig = |b: &[u8]| b.len() >= 512 && b[510] == 0x55 && b[511] == 0xaa;
    // MBR: "xor ax,ax; mov ss,ax; mov sp,7c00" with the NT6 strings and the TPM call
    let mbr = find(exe, b"\x33\xc0\x8e\xd0\xbc\x00\x7c").find_map(|p| {
        let b = exe.get(p..p + 512)?;
        (sig(b) && contains(b, b"TCPA") && contains(b, b"Invalid partition table")).then(|| b[..440].try_into().ok())?
    })?;
    // FAT32 boot record: jmp 0x5A, FAT32 file system type, loads BOOTMGR, then FSInfo template and sector 2
    let (vbr0, vbr2) = find(exe, b"\xeb\x58\x90").find_map(|p| {
        let s0 = exe.get(p..p + 512)?;
        let s1 = exe.get(p + 512..p + 1024)?;
        let s2 = exe.get(p + 1024..p + 1536)?;
        let ok = sig(s0) && &s0[0x52..0x5a] == b"FAT32   " && contains(s0, b"BOOTMGR") && &s1[..4] == b"RRaA" && sig(s2);
        ok.then(|| (s0.try_into().ok(), s2.try_into().ok()))
    })?;
    Some(BootCode { mbr, vbr0: vbr0?, vbr2: vbr2? })
}

/// FAT32 boot sector 0 with our BPB (from the freshly formatted volume) and the NT6 code around it.
pub fn patch_vbr(code: &BootCode, formatted: &[u8; 512], hidden_sectors: u32) -> [u8; 512] {
    let mut out = code.vbr0;
    // bytes 3..0x5A: OEM name, BPB and extended BPB of the new volume
    out[3..0x5a].copy_from_slice(&formatted[3..0x5a]);
    // the code reads the volume relative to the partition start and boots from the first hard disk
    out[0x1c..0x20].copy_from_slice(&hidden_sectors.to_le_bytes());
    out[0x40] = 0x80;
    out[510] = 0x55;
    out[511] = 0xaa;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic bootsect.exe: some padding, an old MBR, the NT6 MBR, the FAT32 record.
    fn fake_exe() -> Vec<u8> {
        let mut v = vec![0u8; 0x160];
        let mut old = vec![0u8; 512];
        old[..7].copy_from_slice(b"\x33\xc0\x8e\xd0\xbc\x00\x7c");
        old[100..123].copy_from_slice(b"Invalid partition table");
        old[510] = 0x55;
        old[511] = 0xaa;
        v.extend_from_slice(&old);
        let mut mbr = old.clone();
        mbr[200..204].copy_from_slice(b"TCPA");
        mbr[439] = 0x42;
        v.extend_from_slice(&mbr);
        let mut s0 = vec![0u8; 512];
        s0[..3].copy_from_slice(b"\xeb\x58\x90");
        s0[0x52..0x5a].copy_from_slice(b"FAT32   ");
        s0[0x170..0x177].copy_from_slice(b"BOOTMGR");
        s0[0x100] = 0x99;
        s0[510] = 0x55;
        s0[511] = 0xaa;
        let mut s1 = vec![0u8; 512];
        s1[..4].copy_from_slice(b"RRaA");
        let mut s2 = vec![0u8; 512];
        s2[0] = 0x77;
        s2[510] = 0x55;
        s2[511] = 0xaa;
        v.extend(s0.iter().chain(&s1).chain(&s2));
        v
    }

    #[test]
    fn finds_nt6_records() {
        let c = from_bootsect(&fake_exe()).expect("boot code");
        assert_eq!(c.mbr[439], 0x42, "the NT6 MBR (with TCPA), not the old one");
        assert_eq!(c.vbr0[0x100], 0x99);
        assert_eq!(c.vbr2[0], 0x77);
        assert!(from_bootsect(&[0u8; 4096]).is_none());
    }

    #[test]
    fn vbr_keeps_bpb() {
        let c = from_bootsect(&fake_exe()).unwrap();
        let mut f = [0u8; 512];
        f[3..11].copy_from_slice(b"MSWIN4.1");
        f[0x0b] = 0x00;
        f[0x0c] = 0x02;
        f[0x52..0x5a].copy_from_slice(b"FAT32   ");
        let v = patch_vbr(&c, &f, 2048);
        assert_eq!(&v[..3], b"\xeb\x58\x90");
        assert_eq!(&v[3..11], b"MSWIN4.1");
        assert_eq!(u32::from_le_bytes(v[0x1c..0x20].try_into().unwrap()), 2048);
        assert_eq!(v[0x40], 0x80);
        assert_eq!(v[0x100], 0x99);
        assert_eq!(&v[510..], &[0x55, 0xaa]);
    }
}
