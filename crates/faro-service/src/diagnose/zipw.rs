//! A minimal zip writer: stored (uncompressed) entries only.
//!
//! A problem report is a few text files, so compression buys nothing worth
//! a dependency. The archive is the plain PKZIP layout (local headers, the
//! central directory, an end record) with CRC-32 checksums, names in UTF-8,
//! and no zip64: everything is far below 4 GiB and 65,535 entries.
//! Windows' Explorer, `tar`, `Expand-Archive` and `unzip` all read it.

use std::io;

/// One file: its path inside the archive (forward slashes) and its bytes.
pub struct Entry<'a> {
    pub name: &'a str,
    pub data: &'a [u8],
}

/// `(date, time)` in MS-DOS format for a UTC time in milliseconds since
/// the Unix epoch. DOS time starts in 1980 and has 2-second steps.
pub fn dos_datetime(ms: i64) -> (u16, u16) {
    let secs = ms.div_euclid(1000).max(0);
    let days = secs / 86_400;
    let t = secs % 86_400;
    let (y, mo, d) = super::civil(days);
    if y < 1980 {
        return (1 | (1 << 5), 0);
    }
    let y = (y - 1980).min(127) as u16;
    let date = (y << 9) | ((mo as u16) << 5) | d as u16;
    let time =
        (((t / 3600) as u16) << 11) | ((((t / 60) % 60) as u16) << 5) | ((t % 60 / 2) as u16);
    (date, time)
}

fn too_big() -> io::Error {
    io::Error::other("the report is too large for a zip file")
}

/// The archive holding `entries`, all stamped `(date, time)` (see
/// [`dos_datetime`]).
pub fn stored_zip(entries: &[Entry<'_>], stamp: (u16, u16)) -> io::Result<Vec<u8>> {
    let (date, time) = stamp;
    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();
    let count = u16::try_from(entries.len()).map_err(|_| too_big())?;
    for e in entries {
        let name = e.name.as_bytes();
        let name_len = u16::try_from(name.len()).map_err(|_| too_big())?;
        let size = u32::try_from(e.data.len()).map_err(|_| too_big())?;
        let offset = u32::try_from(out.len()).map_err(|_| too_big())?;
        let crc = crc32fast::hash(e.data);
        // Local file header.
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0x0800u16.to_le_bytes()); // flags: UTF-8 names
        out.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        out.extend_from_slice(&time.to_le_bytes());
        out.extend_from_slice(&date.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes()); // compressed
        out.extend_from_slice(&size.to_le_bytes()); // uncompressed
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra length
        out.extend_from_slice(name);
        out.extend_from_slice(e.data);
        // Central directory header.
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0x0800u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&time.to_le_bytes());
        central.extend_from_slice(&date.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&name_len.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra
        central.extend_from_slice(&0u16.to_le_bytes()); // comment
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        central.extend_from_slice(&0u32.to_le_bytes()); // external attributes
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name);
    }
    let cd_offset = u32::try_from(out.len()).map_err(|_| too_big())?;
    let cd_size = u32::try_from(central.len()).map_err(|_| too_big())?;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // this disk
    out.extend_from_slice(&0u16.to_le_bytes()); // central directory's disk
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length
    u32::try_from(out.len()).map_err(|_| too_big())?;
    Ok(out)
}

/// Read back an archive made by [`stored_zip`], checking every CRC.
/// For tests: `(name, bytes)` per entry.
#[cfg(test)]
pub fn read_stored(zip: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let u16_at = |o: usize| u16::from_le_bytes([zip[o], zip[o + 1]]) as usize;
    let u32_at = |o: usize| u32::from_le_bytes([zip[o], zip[o + 1], zip[o + 2], zip[o + 3]]);
    let eocd = zip.len().checked_sub(22).ok_or("too short")?;
    if u32_at(eocd) != 0x0605_4b50 {
        return Err("no end record".into());
    }
    let count = u16_at(eocd + 10);
    let mut p = u32_at(eocd + 16) as usize;
    let mut out = Vec::new();
    for _ in 0..count {
        if u32_at(p) != 0x0201_4b50 {
            return Err("bad central header".into());
        }
        let (method, crc) = (u16_at(p + 10), u32_at(p + 16));
        let (size, name_len) = (u32_at(p + 24) as usize, u16_at(p + 28));
        let local = u32_at(p + 42) as usize;
        let name = String::from_utf8(zip[p + 46..p + 46 + name_len].to_vec())
            .map_err(|e| e.to_string())?;
        if method != 0 || u32_at(local) != 0x0403_4b50 {
            return Err("bad local header".into());
        }
        let data_at = local + 30 + u16_at(local + 26) + u16_at(local + 28);
        let data = zip[data_at..data_at + size].to_vec();
        if crc32fast::hash(&data) != crc {
            return Err(format!("{name}: bad CRC"));
        }
        out.push((name, data));
        p += 46 + name_len + u16_at(p + 30) + u16_at(p + 32);
    }
    Ok(out)
}
