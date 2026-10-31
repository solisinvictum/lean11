//! Shared UDF (ECMA-167 / OSTA UDF 1.02) primitives: descriptor tags, CRC, timestamps, strings.

pub const SECTOR: usize = 2048;

pub const TAG_PVD: u16 = 1;
pub const TAG_AVDP: u16 = 2;
pub const TAG_IUVD: u16 = 4;
pub const TAG_PD: u16 = 5;
pub const TAG_LVD: u16 = 6;
pub const TAG_USD: u16 = 7;
pub const TAG_TD: u16 = 8;
pub const TAG_LVID: u16 = 9;
pub const TAG_FSD: u16 = 256;
pub const TAG_FID: u16 = 257;
pub const TAG_FE: u16 = 261;
pub const TAG_EFE: u16 = 266;

/// CRC-ITU-T (x^16 + x^12 + x^5 + 1), initial value 0, as used by ECMA-167 descriptor tags.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

/// Fills in a descriptor tag at the start of `buf` (ECMA-167 3/7.2).
/// `body_len` is the number of bytes after the 16-byte tag covered by the CRC.
pub fn finish_tag(buf: &mut [u8], id: u16, location: u32, body_len: usize) {
    buf[0..2].copy_from_slice(&id.to_le_bytes());
    buf[2..4].copy_from_slice(&2u16.to_le_bytes()); // descriptor version 2 (NSR02)
    buf[5] = 0;
    buf[6..8].copy_from_slice(&0u16.to_le_bytes()); // serial number
    let crc = crc16(&buf[16..16 + body_len]);
    buf[8..10].copy_from_slice(&crc.to_le_bytes());
    buf[10..12].copy_from_slice(&(body_len as u16).to_le_bytes());
    buf[12..16].copy_from_slice(&location.to_le_bytes());
    let sum = buf[0..16].iter().enumerate().filter(|(i, _)| *i != 4).fold(0u8, |a, (_, b)| a.wrapping_add(*b));
    buf[4] = sum;
}

/// Checks tag checksum and CRC; returns the tag identifier.
pub fn check_tag(buf: &[u8]) -> Option<u16> {
    if buf.len() < 16 {
        return None;
    }
    let sum = buf[0..16].iter().enumerate().filter(|(i, _)| *i != 4).fold(0u8, |a, (_, b)| a.wrapping_add(*b));
    if sum != buf[4] {
        return None;
    }
    let len = u16::from_le_bytes([buf[10], buf[11]]) as usize;
    if 16 + len <= buf.len() && crc16(&buf[16..16 + len]) != u16::from_le_bytes([buf[8], buf[9]]) {
        return None;
    }
    Some(u16::from_le_bytes([buf[0], buf[1]]))
}

pub fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
pub fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
pub fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
pub fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
pub fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
pub fn put64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

/// Broken-down UTC time.
#[derive(Debug, Clone, Copy)]
pub struct Time {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl Time {
    pub fn from_unix(secs: i64) -> Self {
        let days = secs.div_euclid(86400);
        let rem = secs.rem_euclid(86400);
        // civil_from_days (Howard Hinnant)
        let z = days + 719468;
        let era = z.div_euclid(146097);
        let doe = z - era * 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        Time {
            year: y as u16,
            month: m as u8,
            day: d as u8,
            hour: (rem / 3600) as u8,
            minute: (rem / 60 % 60) as u8,
            second: (rem % 60) as u8,
        }
    }

    pub fn now() -> Self {
        let secs = std::env::var("SOURCE_DATE_EPOCH").ok().and_then(|s| s.parse().ok()).unwrap_or_else(|| {
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
        });
        Self::from_unix(secs)
    }

    /// ECMA-167 1/7.3 timestamp (12 bytes), UTC.
    pub fn udf(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        put16(&mut b, 0, 0x1000); // type 1 (local time), offset 0 minutes
        put16(&mut b, 2, self.year);
        b[4] = self.month;
        b[5] = self.day;
        b[6] = self.hour;
        b[7] = self.minute;
        b[8] = self.second;
        b
    }

    /// ISO 9660 8.4.26.1 date (17 bytes, digits).
    pub fn iso_long(&self) -> [u8; 17] {
        let s = format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}00",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        );
        let mut b = [0u8; 17];
        b[..16].copy_from_slice(s.as_bytes());
        b
    }

    /// ISO 9660 9.1.5 recording date (7 bytes).
    pub fn iso_short(&self) -> [u8; 7] {
        [(self.year - 1900) as u8, self.month, self.day, self.hour, self.minute, self.second, 0]
    }
}

/// OSTA CS0 charspec ("OSTA Compressed Unicode").
pub fn charspec() -> [u8; 64] {
    let mut b = [0u8; 64];
    b[1..24].copy_from_slice(b"OSTA Compressed Unicode");
    b
}

/// Encodes a name as OSTA compressed unicode (compression id 8 if all chars < 256, else 16).
pub fn cs0_encode(s: &str) -> Vec<u8> {
    let units: Vec<u16> = s.encode_utf16().collect();
    if units.iter().all(|&u| u < 256) {
        let mut v = vec![8u8];
        v.extend(units.iter().map(|&u| u as u8));
        v
    } else {
        let mut v = vec![16u8];
        for u in units {
            v.extend_from_slice(&u.to_be_bytes());
        }
        v
    }
}

pub fn cs0_decode(b: &[u8]) -> String {
    match b.first() {
        Some(8) => b[1..].iter().map(|&c| c as char).collect(),
        Some(16) => {
            let units: Vec<u16> = b[1..].chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&units)
        }
        _ => String::new(),
    }
}

/// Fixed-size dstring: CS0 bytes, zero padded, last byte = used length.
pub fn dstring(s: &str, size: usize) -> Vec<u8> {
    let mut v = vec![0u8; size];
    if s.is_empty() {
        return v;
    }
    let mut enc = cs0_encode(s);
    let max = size - 1;
    if enc.len() > max {
        let unit = if enc[0] == 16 { 2 } else { 1 };
        enc.truncate(1 + (max - 1) / unit * unit);
    }
    v[..enc.len()].copy_from_slice(&enc);
    v[size - 1] = enc.len() as u8;
    v
}

/// Entity identifier (regid, 32 bytes).
pub fn regid(ident: &[u8], suffix: &[u8]) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[1..1 + ident.len()].copy_from_slice(ident);
    b[24..24 + suffix.len()].copy_from_slice(suffix);
    b
}

/// UDF revision suffix for domain identifiers: revision 1.02, no flags.
pub const DOMAIN_SUFFIX: [u8; 3] = [0x02, 0x01, 0x00];
pub const UDF_REV: [u8; 2] = [0x02, 0x01];
/// Implementation identifier suffix: OS class 4 (UNIX), OS identifier 0.
pub const IMPL_SUFFIX: [u8; 2] = [0x04, 0x00];
pub const IMPL_ID: &[u8] = b"*lean11";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_known_value() {
        // CRC-16/XMODEM of "123456789" is 0x31C3.
        assert_eq!(crc16(b"123456789"), 0x31C3);
    }

    #[test]
    fn tag_roundtrip() {
        let mut b = vec![0u8; 512];
        b[100] = 7;
        finish_tag(&mut b, TAG_PVD, 257, 496);
        assert_eq!(check_tag(&b), Some(TAG_PVD));
        b[200] = 1;
        assert_eq!(check_tag(&b), None);
    }

    #[test]
    fn cs0() {
        assert_eq!(cs0_encode("boot"), b"\x08boot");
        assert_eq!(cs0_decode(&cs0_encode("Ärger€")), "Ärger€");
        let d = dstring("CCCOMA_X64FRE_DE-DE_DV9", 32);
        assert_eq!(d[31] as usize, 24);
    }

    #[test]
    fn unix_time() {
        let t = Time::from_unix(1_792_800_000);
        assert_eq!((t.year, t.month, t.day), (2026, 10, 24));
    }
}
