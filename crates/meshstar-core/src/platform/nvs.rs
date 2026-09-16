//! Minimal read-only parser of the ESP-IDF NVS partition format.
//!
//! Lets a MeshStar firmware read values written by another firmware (for
//! example the original MeshStar's `ed25519_pk` / `ed25519_sk` keys in the
//! `meshstar` namespace) without linking ESP-IDF. Format (ESP-IDF
//! `nvs_flash`, "NVS Partition Structure"): 4096-byte pages, a 32-byte page
//! header, a 32-byte entry state bitmap and 126 entries of 32 bytes:
//!
//! ```text
//! ns u8 | type u8 | span u8 | chunk u8 | crc32 u32 | key[16] | data[8]
//! ```
//!
//! Namespace names are entries with `ns == 0`, type U8, whose data byte is
//! the namespace id. Blobs: legacy `0x41` (data follows in `span - 1`
//! entries), or `0x42` chunks assembled through a `0x48` index entry.
//! Entries are only considered when their state bits say "written" (0b10).

use alloc::string::String;
use alloc::vec::Vec;

const PAGE: usize = 4096;
const ENTRY: usize = 32;
const ENTRIES_PER_PAGE: usize = 126;

const T_U8: u8 = 0x01;
const T_I8: u8 = 0x11;
const T_U16: u8 = 0x02;
const T_I16: u8 = 0x12;
const T_U32: u8 = 0x04;
const T_I32: u8 = 0x14;
const T_U64: u8 = 0x08;
const T_I64: u8 = 0x18;
const T_STR: u8 = 0x21;
const T_BLOB: u8 = 0x41;
const T_BLOB_DATA: u8 = 0x42;
const T_BLOB_IDX: u8 = 0x48;

/// A decoded value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NvsValue {
    U64(u64),
    I64(i64),
    Str(String),
    Blob(Vec<u8>),
}

/// One key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NvsEntry {
    pub namespace: String,
    pub key: String,
    pub value: NvsValue,
}

fn key_of(e: &[u8]) -> String {
    let k = &e[8..24];
    let end = k.iter().position(|&b| b == 0).unwrap_or(16);
    String::from_utf8_lossy(&k[..end]).into_owned()
}

/// Parse a raw NVS partition image. Never panics on malformed input.
pub fn parse(image: &[u8]) -> Vec<NvsEntry> {
    let mut namespaces: Vec<(u8, String)> = Vec::new();
    let mut raw: Vec<(u8, String, u8, u8, Vec<u8>, [u8; 8])> = Vec::new(); // ns, key, type, chunk, payload(after entry), data
    for page in image.chunks(PAGE) {
        if page.len() < 64 {
            continue;
        }
        let state = u32::from_le_bytes([page[0], page[1], page[2], page[3]]);
        // 0xFFFFFFFF = uninitialised page
        if state == 0xFFFF_FFFF {
            continue;
        }
        let bitmap = &page[32..64];
        let mut i = 0;
        while i < ENTRIES_PER_PAGE {
            let st = (bitmap[i / 4] >> ((i % 4) * 2)) & 0b11;
            let off = 64 + i * ENTRY;
            if off + ENTRY > page.len() {
                break;
            }
            let e = &page[off..off + ENTRY];
            let span = e[2].max(1) as usize;
            if st != 0b10 {
                i += 1;
                continue;
            }
            let ns = e[0];
            let ty = e[1];
            let chunk = e[3];
            let key = key_of(e);
            let mut data = [0u8; 8];
            data.copy_from_slice(&e[24..32]);
            let payload: Vec<u8> = if span > 1 {
                let start = off + ENTRY;
                let end = (start + (span - 1) * ENTRY).min(page.len());
                page[start..end].to_vec()
            } else {
                Vec::new()
            };
            if ns == 0 && ty == T_U8 {
                namespaces.push((data[0], key));
            } else {
                raw.push((ns, key, ty, chunk, payload, data));
            }
            i += span;
        }
    }
    let ns_name = |id: u8| namespaces.iter().find(|(n, _)| *n == id).map(|(_, s)| s.clone()).unwrap_or_else(|| alloc::format!("ns{}", id));
    let mut out = Vec::new();
    for (ns, key, ty, _chunk, payload, data) in &raw {
        let value = match *ty {
            T_U8 => NvsValue::U64(data[0] as u64),
            T_I8 => NvsValue::I64(data[0] as i8 as i64),
            T_U16 => NvsValue::U64(u16::from_le_bytes([data[0], data[1]]) as u64),
            T_I16 => NvsValue::I64(i16::from_le_bytes([data[0], data[1]]) as i64),
            T_U32 => NvsValue::U64(u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64),
            T_I32 => NvsValue::I64(i32::from_le_bytes([data[0], data[1], data[2], data[3]]) as i64),
            T_U64 => NvsValue::U64(u64::from_le_bytes(*data)),
            T_I64 => NvsValue::I64(i64::from_le_bytes(*data)),
            T_STR | T_BLOB => {
                let size = u16::from_le_bytes([data[0], data[1]]) as usize;
                let bytes = payload.get(..size.min(payload.len())).unwrap_or(&[]).to_vec();
                if *ty == T_STR {
                    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                    NvsValue::Str(String::from_utf8_lossy(&bytes[..end]).into_owned())
                } else {
                    NvsValue::Blob(bytes)
                }
            }
            T_BLOB_IDX => {
                // data: size u32, chunk_count u8, chunk_start u8
                let size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
                let count = data[4] as usize;
                let start = data[5];
                let mut blob = Vec::with_capacity(size);
                for c in 0..count {
                    let want = start.wrapping_add(c as u8);
                    if let Some((_, _, _, _, p, d)) = raw.iter().find(|(n2, k2, t2, ch, _, _)| n2 == ns && k2 == key && *t2 == T_BLOB_DATA && *ch == want) {
                        let sz = u16::from_le_bytes([d[0], d[1]]) as usize;
                        blob.extend_from_slice(p.get(..sz.min(p.len())).unwrap_or(&[]));
                    }
                }
                blob.truncate(size);
                NvsValue::Blob(blob)
            }
            T_BLOB_DATA => continue, // assembled through the index entry
            _ => continue,
        };
        out.push(NvsEntry { namespace: ns_name(*ns), key: key.clone(), value });
    }
    out
}

/// Convenience: find a blob by namespace and key.
pub fn blob<'a>(entries: &'a [NvsEntry], namespace: &str, key: &str) -> Option<&'a [u8]> {
    entries.iter().find(|e| e.namespace == namespace && e.key == key).and_then(|e| match &e.value {
        NvsValue::Blob(b) => Some(b.as_slice()),
        _ => None,
    })
}

/// Recover a MeshStar identity seed from an NVS image written by the
/// original firmware (`meshstar/ed25519_sk`, 32-byte seed or 64-byte
/// libsodium secret key whose first half is the seed). The public key, if
/// present, must match.
pub fn original_identity_seed(image: &[u8]) -> Option<[u8; 32]> {
    let entries = parse(image);
    let sk = blob(&entries, "meshstar", "ed25519_sk")?;
    if sk.len() < 32 {
        return None;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&sk[..32]);
    let id = crate::identity::Identity::from_seed(&seed);
    if let Some(pk) = blob(&entries, "meshstar", "ed25519_pk") {
        if pk.len() == 32 && pk != id.public().public_key_bytes() {
            // 64-byte libsodium format stores pk in the second half
            if sk.len() >= 64 && &sk[32..64] == pk {
                return Some(seed);
            }
            return None;
        }
    }
    Some(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a one-page NVS image with a namespace and a few entries.
    fn image() -> Vec<u8> {
        let mut page = alloc::vec![0xFFu8; PAGE];
        page[0..4].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes()); // active page
        let mut idx = 0usize;
        let mut put = |page: &mut Vec<u8>, ns: u8, ty: u8, key: &str, data: [u8; 8], payload: &[u8]| {
            let span = 1 + payload.len().div_ceil(ENTRY);
            let off = 64 + idx * ENTRY;
            page[off] = ns;
            page[off + 1] = ty;
            page[off + 2] = span as u8;
            page[off + 3] = 0xFF;
            page[off + 8..off + 24].fill(0);
            page[off + 8..off + 8 + key.len()].copy_from_slice(key.as_bytes());
            page[off + 24..off + 32].copy_from_slice(&data);
            page[off + 32..off + 32 + payload.len()].copy_from_slice(payload);
            for k in 0..span {
                let i = idx + k;
                page[32 + i / 4] &= !(0b11 << ((i % 4) * 2));
                page[32 + i / 4] |= 0b10 << ((i % 4) * 2);
            }
            idx += span;
        };
        put(&mut page, 0, T_U8, "meshstar", [1, 0, 0, 0, 0, 0, 0, 0], &[]);
        put(&mut page, 1, T_U32, "region", 7u32.to_le_bytes().iter().chain([0u8; 4].iter()).copied().collect::<Vec<u8>>().try_into().unwrap(), &[]);
        let seed = [9u8; 32];
        let id = crate::identity::Identity::from_seed(&seed);
        let mut d = [0u8; 8];
        d[0..2].copy_from_slice(&32u16.to_le_bytes());
        put(&mut page, 1, T_BLOB, "ed25519_sk", d, &seed);
        put(&mut page, 1, T_BLOB, "ed25519_pk", d, &id.public().public_key_bytes());
        let mut ds = [0u8; 8];
        ds[0..2].copy_from_slice(&6u16.to_le_bytes());
        put(&mut page, 1, T_STR, "name", ds, b"hello\0");
        page
    }

    #[test]
    fn parses_namespaces_blobs_and_scalars() {
        let img = image();
        let e = parse(&img);
        assert!(e.iter().any(|x| x.namespace == "meshstar" && x.key == "region" && x.value == NvsValue::U64(7)));
        assert!(e.iter().any(|x| x.key == "name" && x.value == NvsValue::Str("hello".into())));
        assert_eq!(blob(&e, "meshstar", "ed25519_sk").map(|b| b.len()), Some(32));
        assert_eq!(original_identity_seed(&img), Some([9u8; 32]));
        // garbage never panics
        let junk: Vec<u8> = (0..20_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        let _ = parse(&junk);
        assert!(original_identity_seed(&junk).is_none());
        assert!(parse(&[]).is_empty());
    }

    /// Runs only when the real dump is present (it is not committed).
    #[test]
    fn recovers_the_original_identity_from_the_dump() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../firmware-dump/nvs.bin");
        let Ok(img) = std::fs::read(path) else { return };
        let entries = parse(&img);
        assert!(entries.iter().any(|e| e.namespace == "meshstar"), "no meshstar namespace found");
        let seed = original_identity_seed(&img).expect("original ed25519 identity");
        let id = crate::identity::Identity::from_seed(&seed);
        // do not print secrets; the address is public
        std::eprintln!("original node address: {}", id.address());
        assert!(!id.address().is_null());
    }
}
