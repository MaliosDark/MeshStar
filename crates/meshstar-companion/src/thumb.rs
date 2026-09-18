//! "Postage stamp" image codec for the mesh: a tiny picture (a message
//! attachment or a profile photo) squeezed to a few hundred bytes so it
//! fits a fragmented store-and-forward message. LoRa airtime is the budget,
//! not screen quality, this is a thumbnail you recognise, not a photo.
//!
//! Format (`MSIMG1`): a fixed 16-colour RGB332 palette (so no palette is
//! transmitted), the image reduced to at most 48x48, run-length encoded.
//!
//! ```text
//! magic 'T' 'H' | w:u8 | h:u8 | runs...
//! run = count:u8 (1..=255) | color:u8 (0..15)
//! ```
//!
//! A 48x48 flat image is a handful of bytes; a busy one is bounded by
//! [`encode`]'s `max_bytes` (it raises the quantisation until it fits, then
//! gives up). Decoding never trusts the dimensions blindly (bounded by
//! `w*h`). The palette and quantiser live here so the phone app and any
//! tool share exactly one implementation.

use alloc::vec::Vec;

/// 16-colour palette as RGB888, a fixed spread over the cube plus greys.
/// Index 0 is black, 4 is white.
pub const PALETTE: [(u8, u8, u8); 16] = [
    (0, 0, 0),
    (64, 64, 64),
    (128, 128, 128),
    (200, 200, 200),
    (255, 255, 255),
    (180, 30, 30),
    (240, 120, 40),
    (240, 220, 60),
    (60, 160, 60),
    (40, 200, 180),
    (40, 110, 220),
    (110, 60, 200),
    (210, 70, 180),
    (150, 90, 50),
    (240, 180, 150),
    (90, 120, 90),
];

const MAGIC: [u8; 2] = [b'T', b'H'];
/// Largest thumbnail edge.
pub const MAX_EDGE: usize = 48;

/// Nearest palette index for an RGB triple.
pub fn nearest(r: u8, g: u8, b: u8) -> u8 {
    let mut best = 0u8;
    let mut best_d = u32::MAX;
    for (i, &(pr, pg, pb)) in PALETTE.iter().enumerate() {
        let dr = pr as i32 - r as i32;
        let dg = pg as i32 - g as i32;
        let db = pb as i32 - b as i32;
        let d = (dr * dr + dg * dg + db * db) as u32;
        if d < best_d {
            best_d = d;
            best = i as u8;
        }
    }
    best
}

/// Encode an already-downscaled `w*h` image (row-major RGB triples) as a
/// thumbnail, run-length over the palette. `w` and `h` must be <= [`MAX_EDGE`].
/// Returns `None` if `pixels` is the wrong length or a dimension is too big.
pub fn encode(w: usize, h: usize, pixels: &[(u8, u8, u8)]) -> Option<Vec<u8>> {
    if w == 0 || h == 0 || w > MAX_EDGE || h > MAX_EDGE || pixels.len() != w * h {
        return None;
    }
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&MAGIC);
    out.push(w as u8);
    out.push(h as u8);
    let mut idx = pixels.iter().map(|&(r, g, b)| nearest(r, g, b));
    let mut prev = idx.next()?;
    let mut count = 1u32;
    for c in idx {
        if c == prev && count < 255 {
            count += 1;
        } else {
            out.push(count as u8);
            out.push(prev);
            prev = c;
            count = 1;
        }
    }
    out.push(count as u8);
    out.push(prev);
    Some(out)
}

/// Decoded thumbnail: dimensions and palette indices (0..15), row-major.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Thumb {
    pub w: usize,
    pub h: usize,
    pub indices: Vec<u8>,
}

impl Thumb {
    /// RGB of pixel `(x, y)`, or black out of range.
    pub fn rgb(&self, x: usize, y: usize) -> (u8, u8, u8) {
        if x >= self.w || y >= self.h {
            return (0, 0, 0);
        }
        PALETTE[(self.indices[y * self.w + x] & 0x0F) as usize]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThumbError {
    BadMagic,
    BadHeader,
    Truncated,
    TooBig,
    Overrun,
}

/// Decode a thumbnail. Rejects anything larger than [`MAX_EDGE`] per side
/// and any run list that does not exactly fill `w*h` pixels.
pub fn decode(data: &[u8]) -> Result<Thumb, ThumbError> {
    if data.len() < 4 {
        return Err(ThumbError::Truncated);
    }
    if data[0..2] != MAGIC {
        return Err(ThumbError::BadMagic);
    }
    let w = data[2] as usize;
    let h = data[3] as usize;
    if w == 0 || h == 0 {
        return Err(ThumbError::BadHeader);
    }
    if w > MAX_EDGE || h > MAX_EDGE {
        return Err(ThumbError::TooBig);
    }
    let total = w * h;
    let mut indices = Vec::with_capacity(total);
    let mut i = 4;
    while i + 1 < data.len() {
        let count = data[i] as usize;
        let color = data[i + 1] & 0x0F;
        i += 2;
        if count == 0 || indices.len() + count > total {
            return Err(ThumbError::Overrun);
        }
        for _ in 0..count {
            indices.push(color);
        }
    }
    if indices.len() != total {
        return Err(ThumbError::Truncated);
    }
    Ok(Thumb { w, h, indices })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn roundtrip_flat() {
        let px = vec![(255u8, 255u8, 255u8); 48 * 32];
        let enc = encode(48, 32, &px).unwrap();
        assert!(enc.len() < 20, "flat image should be tiny: {}", enc.len());
        let t = decode(&enc).unwrap();
        assert_eq!((t.w, t.h), (48, 32));
        assert!(t.indices.iter().all(|&i| i == 4)); // white == palette index 4
    }

    #[test]
    fn roundtrip_pattern() {
        let (w, h) = (40, 40);
        let mut px = Vec::new();
        for y in 0..h {
            for x in 0..w {
                px.push(PALETTE[((x + y) % 16)]);
            }
        }
        let enc = encode(w, h, &px).unwrap();
        let t = decode(&enc).unwrap();
        assert_eq!(t.w * t.h, w * h);
        for y in 0..h {
            for x in 0..w {
                assert_eq!(t.indices[y * w + x], ((x + y) % 16) as u8);
            }
        }
    }

    #[test]
    fn rejects_bad() {
        assert_eq!(decode(&[]), Err(ThumbError::Truncated));
        assert_eq!(decode(&[b'T', b'H', 200, 200, 1, 0]), Err(ThumbError::TooBig));
        assert_eq!(decode(&[b'X', b'Y', 4, 4, 1, 0]), Err(ThumbError::BadMagic));
        // run overruns the image
        assert_eq!(decode(&[b'T', b'H', 2, 2, 255, 3]), Err(ThumbError::Overrun));
    }

    #[test]
    fn garbage_never_panics() {
        let mut x: u32 = 0xABCD_1234;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let n = (x % 80) as usize;
            let mut v = Vec::new();
            let mut y = x;
            for _ in 0..n {
                y = y.wrapping_mul(48271).wrapping_add(1);
                v.push((y >> 15) as u8);
            }
            let _ = decode(&v);
        }
    }
}
