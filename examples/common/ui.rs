//! Device UI for 128x64 SSD1306 OLEDs: a pixel framebuffer driver, a 5x7
//! font (plus 2x scaling), small icons, and the screens described in
//! `docs/UI.md`. The look borrows the inverted status bar and signal/battery
//! icons from Meshtastic and the contact/message lists from MeshCore; what is
//! MeshStar's own is that every list mixes the three networks, each entry
//! tagged with its protocol badge and an honest security label.
//!
//! One button drives everything: short press moves the cursor (and past the
//! last entry, to the next screen of the ring Home > Chats > Networks >
//! Signal > Node > Settings), long press acts on the selected entry.
//!
//! The screens read a [`UiModel`] that the firmware keeps up to date from
//! `Node` events and the compatibility layer, so the code here has no radio
//! or protocol logic.

use core::fmt::Write;

use embedded_hal::i2c::I2c;
use meshstar_core::identity::Address;
use meshstar_core::node::{Node, Protection};
use meshstar_core::protocol::Role;
use meshstar_core::radio::RadioStats;
use meshstar_protocols::model::{ContentType, IdentityRef, ProtocolId, SecurityLevel, UnifiedMessage};

pub const WIDTH: usize = 128;
pub const HEIGHT: usize = 64;
const PAGES: usize = HEIGHT / 8;

/// 5x7 glyphs, ASCII 32..=126, column-major (bit 0 = top row).
static FONT: [[u8; 5]; 95] = [
    [0x00, 0x00, 0x00, 0x00, 0x00], // ' '
    [0x00, 0x00, 0x5f, 0x00, 0x00], // '!'
    [0x00, 0x07, 0x00, 0x07, 0x00], // '"'
    [0x14, 0x7f, 0x14, 0x7f, 0x14], // '#'
    [0x24, 0x2a, 0x7f, 0x2a, 0x12], // '$'
    [0x23, 0x13, 0x08, 0x64, 0x62], // '%'
    [0x36, 0x49, 0x55, 0x22, 0x50], // '&'
    [0x00, 0x05, 0x03, 0x00, 0x00], // '\''
    [0x00, 0x1c, 0x22, 0x41, 0x00], // '('
    [0x00, 0x41, 0x22, 0x1c, 0x00], // ')'
    [0x14, 0x08, 0x3e, 0x08, 0x14], // '*'
    [0x08, 0x08, 0x3e, 0x08, 0x08], // '+'
    [0x00, 0x50, 0x30, 0x00, 0x00], // ','
    [0x08, 0x08, 0x08, 0x08, 0x08], // '-'
    [0x00, 0x60, 0x60, 0x00, 0x00], // '.'
    [0x20, 0x10, 0x08, 0x04, 0x02], // '/'
    [0x3e, 0x51, 0x49, 0x45, 0x3e], // '0'
    [0x00, 0x42, 0x7f, 0x40, 0x00], // '1'
    [0x42, 0x61, 0x51, 0x49, 0x46], // '2'
    [0x21, 0x41, 0x45, 0x4b, 0x31], // '3'
    [0x18, 0x14, 0x12, 0x7f, 0x10], // '4'
    [0x27, 0x45, 0x45, 0x45, 0x39], // '5'
    [0x3c, 0x4a, 0x49, 0x49, 0x30], // '6'
    [0x01, 0x71, 0x09, 0x05, 0x03], // '7'
    [0x36, 0x49, 0x49, 0x49, 0x36], // '8'
    [0x06, 0x49, 0x49, 0x29, 0x1e], // '9'
    [0x00, 0x36, 0x36, 0x00, 0x00], // ':'
    [0x00, 0x56, 0x36, 0x00, 0x00], // ';'
    [0x08, 0x14, 0x22, 0x41, 0x00], // '<'
    [0x14, 0x14, 0x14, 0x14, 0x14], // '='
    [0x00, 0x41, 0x22, 0x14, 0x08], // '>'
    [0x02, 0x01, 0x51, 0x09, 0x06], // '?'
    [0x32, 0x49, 0x79, 0x41, 0x3e], // '@'
    [0x7e, 0x11, 0x11, 0x11, 0x7e], // 'A'
    [0x7f, 0x49, 0x49, 0x49, 0x36], // 'B'
    [0x3e, 0x41, 0x41, 0x41, 0x22], // 'C'
    [0x7f, 0x41, 0x41, 0x22, 0x1c], // 'D'
    [0x7f, 0x49, 0x49, 0x49, 0x41], // 'E'
    [0x7f, 0x09, 0x09, 0x09, 0x01], // 'F'
    [0x3e, 0x41, 0x49, 0x49, 0x7a], // 'G'
    [0x7f, 0x08, 0x08, 0x08, 0x7f], // 'H'
    [0x00, 0x41, 0x7f, 0x41, 0x00], // 'I'
    [0x20, 0x40, 0x41, 0x3f, 0x01], // 'J'
    [0x7f, 0x08, 0x14, 0x22, 0x41], // 'K'
    [0x7f, 0x40, 0x40, 0x40, 0x40], // 'L'
    [0x7f, 0x02, 0x0c, 0x02, 0x7f], // 'M'
    [0x7f, 0x04, 0x08, 0x10, 0x7f], // 'N'
    [0x3e, 0x41, 0x41, 0x41, 0x3e], // 'O'
    [0x7f, 0x09, 0x09, 0x09, 0x06], // 'P'
    [0x3e, 0x41, 0x51, 0x21, 0x5e], // 'Q'
    [0x7f, 0x09, 0x19, 0x29, 0x46], // 'R'
    [0x46, 0x49, 0x49, 0x49, 0x31], // 'S'
    [0x01, 0x01, 0x7f, 0x01, 0x01], // 'T'
    [0x3f, 0x40, 0x40, 0x40, 0x3f], // 'U'
    [0x1f, 0x20, 0x40, 0x20, 0x1f], // 'V'
    [0x3f, 0x40, 0x38, 0x40, 0x3f], // 'W'
    [0x63, 0x14, 0x08, 0x14, 0x63], // 'X'
    [0x07, 0x08, 0x70, 0x08, 0x07], // 'Y'
    [0x61, 0x51, 0x49, 0x45, 0x43], // 'Z'
    [0x00, 0x7f, 0x41, 0x41, 0x00], // '['
    [0x02, 0x04, 0x08, 0x10, 0x20], // '\\'
    [0x00, 0x41, 0x41, 0x7f, 0x00], // ']'
    [0x04, 0x02, 0x01, 0x02, 0x04], // '^'
    [0x40, 0x40, 0x40, 0x40, 0x40], // '_'
    [0x00, 0x01, 0x02, 0x04, 0x00], // '`'
    [0x20, 0x54, 0x54, 0x54, 0x78], // 'a'
    [0x7f, 0x48, 0x44, 0x44, 0x38], // 'b'
    [0x38, 0x44, 0x44, 0x44, 0x20], // 'c'
    [0x38, 0x44, 0x44, 0x48, 0x7f], // 'd'
    [0x38, 0x54, 0x54, 0x54, 0x18], // 'e'
    [0x08, 0x7e, 0x09, 0x01, 0x02], // 'f'
    [0x0c, 0x52, 0x52, 0x52, 0x3e], // 'g'
    [0x7f, 0x08, 0x04, 0x04, 0x78], // 'h'
    [0x00, 0x44, 0x7d, 0x40, 0x00], // 'i'
    [0x20, 0x40, 0x44, 0x3d, 0x00], // 'j'
    [0x7f, 0x10, 0x28, 0x44, 0x00], // 'k'
    [0x00, 0x41, 0x7f, 0x40, 0x00], // 'l'
    [0x7c, 0x04, 0x18, 0x04, 0x78], // 'm'
    [0x7c, 0x08, 0x04, 0x04, 0x78], // 'n'
    [0x38, 0x44, 0x44, 0x44, 0x38], // 'o'
    [0x7c, 0x14, 0x14, 0x14, 0x08], // 'p'
    [0x08, 0x14, 0x14, 0x18, 0x7c], // 'q'
    [0x7c, 0x08, 0x04, 0x04, 0x08], // 'r'
    [0x48, 0x54, 0x54, 0x54, 0x20], // 's'
    [0x04, 0x3f, 0x44, 0x40, 0x20], // 't'
    [0x3c, 0x40, 0x40, 0x20, 0x7c], // 'u'
    [0x1c, 0x20, 0x40, 0x20, 0x1c], // 'v'
    [0x3c, 0x40, 0x30, 0x40, 0x3c], // 'w'
    [0x44, 0x28, 0x10, 0x28, 0x44], // 'x'
    [0x0c, 0x50, 0x50, 0x50, 0x3c], // 'y'
    [0x44, 0x64, 0x54, 0x4c, 0x44], // 'z'
    [0x00, 0x08, 0x36, 0x41, 0x00], // '{'
    [0x00, 0x00, 0x7f, 0x00, 0x00], // '|'
    [0x00, 0x41, 0x36, 0x08, 0x00], // '}'
    [0x10, 0x08, 0x08, 0x10, 0x08], // '~'
];

// ---------------------------------------------------------------- icons

/// Row bitmaps, bit 7 = leftmost pixel, one byte per row.
const ICON_STAR: [u8; 7] = [0x10, 0x10, 0xFE, 0x7C, 0x38, 0x6C, 0x44];
/// 12x12 star for the splash screen.
const LOGO_STAR: [u16; 12] = [0x060, 0x060, 0x0F0, 0x0F0, 0xFFF, 0x7FE, 0x3FC, 0x1F8, 0x1F8, 0x3CC, 0x786, 0xC03];
const ICON_LOCK: [u8; 7] = [0x70, 0x88, 0x88, 0xF8, 0xF8, 0xD8, 0xF8];
const ICON_LOCK_OPEN: [u8; 7] = [0x70, 0x88, 0x08, 0xF8, 0xF8, 0xD8, 0xF8];
const ICON_BRIDGE: [u8; 7] = [0x20, 0x7E, 0x20, 0x00, 0x08, 0xFC, 0x08];
const ICON_MOON: [u8; 7] = [0x38, 0x60, 0xC0, 0xC0, 0xC0, 0x60, 0x38];
const ICON_ANCHOR: [u8; 7] = [0x20, 0x50, 0x20, 0xF8, 0x20, 0xA8, 0x70];
const ICON_ANTENNA: [u8; 7] = [0x88, 0x50, 0x20, 0x20, 0x20, 0x20, 0x20];
const ICON_MAIL_W: usize = 9;
const ICON_MAIL: [u16; 7] = [0x1FF, 0x101, 0x183, 0x145, 0x129, 0x111, 0x1FF];

// ---------------------------------------------------------------- driver

pub struct Ssd1306<I> {
    i2c: I,
    addr: u8,
    buf: [u8; WIDTH * PAGES],
    dirty: [bool; PAGES],
}

impl<I: I2c> Ssd1306<I> {
    pub fn new(i2c: I, addr: u8) -> Self {
        Self { i2c, addr, buf: [0; WIDTH * PAGES], dirty: [true; PAGES] }
    }

    fn cmd(&mut self, c: &[u8]) -> Result<(), I::Error> {
        let mut b = [0u8; 8];
        b[0] = 0x00;
        let n = c.len().min(7);
        b[1..1 + n].copy_from_slice(&c[..n]);
        self.i2c.write(self.addr, &b[..1 + n])
    }

    /// Init sequence (datasheet 128x64, charge pump on).
    pub fn init(&mut self) -> Result<(), I::Error> {
        for c in [&[0xAEu8][..], &[0xD5, 0x80], &[0xA8, 0x3F], &[0xD3, 0x00], &[0x40], &[0x8D, 0x14], &[0x20, 0x02], &[0xA1], &[0xC8], &[0xDA, 0x12], &[0x81, 0xCF], &[0xD9, 0xF1], &[0xDB, 0x40], &[0xA4], &[0xA6], &[0x2E], &[0xAF]] {
            self.cmd(c)?;
        }
        self.clear();
        self.flush()
    }

    /// Display on/off (contents are kept).
    pub fn power(&mut self, on: bool) -> Result<(), I::Error> {
        self.cmd(&[if on { 0xAF } else { 0xAE }])
    }

    pub fn clear(&mut self) {
        self.buf.fill(0);
        self.dirty.fill(true);
    }

    /// Write dirty pages only.
    pub fn flush(&mut self) -> Result<(), I::Error> {
        for p in 0..PAGES {
            if !self.dirty[p] {
                continue;
            }
            self.cmd(&[0xB0 | p as u8, 0x00, 0x10])?;
            let mut chunk = [0x40u8; 1 + WIDTH];
            chunk[1..].copy_from_slice(&self.buf[p * WIDTH..(p + 1) * WIDTH]);
            self.i2c.write(self.addr, &chunk)?;
            self.dirty[p] = false;
        }
        Ok(())
    }

    #[inline]
    pub fn pixel(&mut self, x: i32, y: i32, on: bool) {
        if x < 0 || y < 0 || x >= WIDTH as i32 || y >= HEIGHT as i32 {
            return;
        }
        let (x, y) = (x as usize, y as usize);
        let i = (y / 8) * WIDTH + x;
        let m = 1 << (y % 8);
        if on {
            self.buf[i] |= m;
        } else {
            self.buf[i] &= !m;
        }
        self.dirty[y / 8] = true;
    }

    pub fn fill_rect(&mut self, x: i32, y: i32, w: i32, h: i32, on: bool) {
        for yy in y..y + h {
            for xx in x..x + w {
                self.pixel(xx, yy, on);
            }
        }
    }

    pub fn rect(&mut self, x: i32, y: i32, w: i32, h: i32) {
        self.hline(x, y, w);
        self.hline(x, y + h - 1, w);
        self.vline(x, y, h);
        self.vline(x + w - 1, y, h);
    }

    pub fn hline(&mut self, x: i32, y: i32, w: i32) {
        for xx in x..x + w {
            self.pixel(xx, y, true);
        }
    }

    pub fn vline(&mut self, x: i32, y: i32, h: i32) {
        for yy in y..y + h {
            self.pixel(x, yy, true);
        }
    }

    /// XOR a rectangle (used for the cursor and inverted bars).
    pub fn invert_rect(&mut self, x: i32, y: i32, w: i32, h: i32) {
        for yy in y.max(0)..(y + h).min(HEIGHT as i32) {
            for xx in x.max(0)..(x + w).min(WIDTH as i32) {
                let i = (yy as usize / 8) * WIDTH + xx as usize;
                self.buf[i] ^= 1 << (yy % 8);
            }
            self.dirty[yy as usize / 8] = true;
        }
    }

    /// Draw a glyph with its top-left corner at (x, y), scaled by `s`.
    fn glyph(&mut self, x: i32, y: i32, ch: u8, s: i32, on: bool) {
        let g = FONT.get(ch.saturating_sub(32) as usize).copied().unwrap_or([0x7f; 5]);
        for (i, col) in g.iter().enumerate() {
            for b in 0..7 {
                if col & (1 << b) != 0 {
                    self.fill_rect(x + i as i32 * s, y + b * s, s, s, on);
                }
            }
        }
    }

    /// Text with the top-left corner at (x, y). Returns the x after the text.
    pub fn text(&mut self, x: i32, y: i32, s: &str) -> i32 {
        self.text_on(x, y, s, true)
    }

    pub fn text_on(&mut self, x: i32, y: i32, s: &str, on: bool) -> i32 {
        let mut cx = x;
        for ch in s.bytes() {
            if cx >= WIDTH as i32 {
                break;
            }
            self.glyph(cx, y, ch, 1, on);
            cx += 6;
        }
        cx
    }

    /// Double-size text (10x14 per glyph, 12 px pitch).
    pub fn text_2x(&mut self, x: i32, y: i32, s: &str) -> i32 {
        let mut cx = x;
        for ch in s.bytes() {
            if cx >= WIDTH as i32 {
                break;
            }
            self.glyph(cx, y, ch, 2, true);
            cx += 12;
        }
        cx
    }

    /// Text right-aligned so that it ends at `right`.
    pub fn text_right(&mut self, right: i32, y: i32, s: &str) -> i32 {
        let x = right - 6 * s.len() as i32 + 1;
        self.text(x, y, s)
    }

    pub fn icon8(&mut self, x: i32, y: i32, rows: &[u8], on: bool) {
        for (r, bits) in rows.iter().enumerate() {
            for c in 0..8 {
                if bits & (0x80 >> c) != 0 {
                    self.pixel(x + c, y + r as i32, on);
                }
            }
        }
    }

    pub fn icon16(&mut self, x: i32, y: i32, rows: &[u16], w: usize, on: bool) {
        for (r, bits) in rows.iter().enumerate() {
            for c in 0..w {
                if bits & (1 << (w - 1 - c)) != 0 {
                    self.pixel(x + c as i32, y + r as i32, on);
                }
            }
        }
    }

    /// Meshtastic-style signal bars (4 bars, 9x7) for an RSSI in dBm.
    pub fn bars(&mut self, x: i32, y: i32, rssi: i16, on: bool) {
        let level = if rssi == 0 { 0 } else if rssi > -80 { 4 } else if rssi > -95 { 3 } else if rssi > -110 { 2 } else { 1 };
        for b in 0..4 {
            let h = 1 + 2 * b;
            if b < level {
                self.fill_rect(x + b * 2 + (b.max(0)), y + 7 - h, 2, h, on);
            } else {
                self.fill_rect(x + b * 2 + b, y + 6, 2, 1, on);
            }
        }
    }

    /// Battery outline 12x7 with a fill proportional to `percent`.
    pub fn battery(&mut self, x: i32, y: i32, percent: Option<u8>, on: bool) {
        self.fill_rect(x, y, 11, 7, on);
        self.fill_rect(x + 1, y + 1, 9, 5, !on);
        self.fill_rect(x + 11, y + 2, 1, 3, on);
        match percent {
            Some(p) => {
                let w = (p as i32 * 9 + 50) / 100;
                self.fill_rect(x + 1, y + 1, w.min(9), 5, on);
            }
            None => {
                // No gauge: a small "?" inside.
                self.fill_rect(x + 5, y + 2, 1, 2, on);
                self.fill_rect(x + 5, y + 5, 1, 1, on);
            }
        }
    }

    /// Protocol badge (7x9): a star for MeshStar, an inverted box with a
    /// letter for foreign networks.
    pub fn badge(&mut self, x: i32, y: i32, p: Proto, on: bool) {
        match p {
            Proto::Star => self.icon8(x, y + 1, &ICON_STAR, on),
            Proto::Meshtastic | Proto::MeshCore | Proto::Unknown => {
                self.fill_rect(x, y, 7, 9, on);
                self.glyph(x + 1, y + 1, p.letter(), 1, !on);
            }
        }
    }
}

// ---------------------------------------------------------------- model

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Star,
    Meshtastic,
    MeshCore,
    Unknown,
}

impl Proto {
    pub fn from_id(p: ProtocolId) -> Self {
        match p {
            ProtocolId::MeshStar => Self::Star,
            ProtocolId::Meshtastic => Self::Meshtastic,
            ProtocolId::MeshCore => Self::MeshCore,
            _ => Self::Unknown,
        }
    }
    pub fn letter(self) -> u8 {
        match self {
            Self::Star => b'*',
            Self::Meshtastic => b'M',
            Self::MeshCore => b'C',
            Self::Unknown => b'?',
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Star => "MeshStar",
            Self::Meshtastic => "Meshtastic",
            Self::MeshCore => "MeshCore",
            Self::Unknown => "unknown",
        }
    }
}

/// Security label shown next to nodes and messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sec {
    /// Noise XX session established.
    E2e,
    /// Sealed envelope.
    Envelope,
    /// Network group key.
    Group,
    /// Foreign shared channel key.
    Channel,
    /// Foreign direct message with per-node keys.
    Direct,
    /// Crossed a gateway.
    Bridged,
    /// Plaintext.
    Plain,
    /// Encrypted, no key.
    Opaque,
    /// Nothing exchanged yet.
    None,
}

impl Sec {
    pub fn from_level(l: &SecurityLevel) -> Self {
        match l {
            SecurityLevel::MeshStarE2E => Self::E2e,
            SecurityLevel::MeshStarEnvelope => Self::Envelope,
            SecurityLevel::MeshStarGroup => Self::Group,
            SecurityLevel::Plaintext => Self::Plain,
            SecurityLevel::ForeignSharedKey { .. } => Self::Channel,
            SecurityLevel::ForeignDirect { .. } => Self::Direct,
            SecurityLevel::Undecryptable { .. } => Self::Opaque,
            SecurityLevel::Bridged { .. } => Self::Bridged,
        }
    }
    pub fn from_protection(p: Protection) -> Self {
        match p {
            Protection::Session => Self::E2e,
            Protection::Envelope => Self::Envelope,
            Protection::Group => Self::Group,
            Protection::Plaintext => Self::Plain,
        }
    }
    /// Three-character label.
    pub fn short(self) -> &'static str {
        match self {
            Self::E2e => "E2E",
            Self::Envelope => "ENV",
            Self::Group => "GRP",
            Self::Channel => "CH",
            Self::Direct => "DM",
            Self::Bridged => "BR",
            Self::Plain => "TXT",
            Self::Opaque => "?",
            Self::None => "--",
        }
    }
    pub fn long(self) -> &'static str {
        match self {
            Self::E2e => "E2E, fwd secrecy",
            Self::Envelope => "Sealed envelope",
            Self::Group => "Network group key",
            Self::Channel => "Shared channel key",
            Self::Direct => "Direct, node keys",
            Self::Bridged => "Bridged, gateway",
            Self::Plain => "PLAINTEXT",
            Self::Opaque => "Encrypted, no key",
            Self::None => "No session yet",
        }
    }
    /// Whether to draw a closed lock, an open lock or nothing.
    fn lock(self) -> Option<bool> {
        match self {
            Self::E2e | Self::Envelope | Self::Direct => Some(true),
            Self::Group | Self::Channel | Self::Bridged | Self::Opaque => Some(false),
            Self::Plain | Self::None => None,
        }
    }
}

pub type Name = heapless::String<12>;

#[derive(Clone, Debug)]
pub struct UiNode {
    pub proto: Proto,
    pub key: IdentityRef,
    pub name: Name,
    pub rssi: i16,
    pub sec: Sec,
    pub hops: u8,
    pub sleeping: bool,
    pub anchor: bool,
    pub last_seen: u64,
}

#[derive(Clone, Debug)]
pub struct UiMsg {
    pub proto: Proto,
    pub from: Name,
    pub channel: Name,
    pub text: heapless::String<96>,
    pub sec: Sec,
    pub rssi: i16,
    pub hops: u8,
    pub at: u64,
    pub unread: bool,
}

#[derive(Clone, Debug)]
pub struct UiNet {
    pub proto: Proto,
    pub name: Name,
    pub nodes: u8,
    pub rssi: i16,
    pub frames: u32,
    pub last_seen: u64,
}

/// Everything the screens show. Filled by the firmware.
pub struct UiModel {
    pub name: Name,
    pub short_id: heapless::String<10>,
    pub role: Role,
    pub nodes: heapless::Vec<UiNode, 16>,
    pub msgs: heapless::Vec<UiMsg, 8>,
    pub nets: heapless::Vec<UiNet, 4>,
    pub compat: Option<Proto>,
    pub bridge: bool,
    pub battery_mv: Option<u32>,
    pub rssi_hist: [i16; 56],
    pub hist_len: usize,
    last_rx_frames: u32,
    pub screen_on: bool,
    pub last_activity: u64,
    pub screen_timeout_s: u32,
}

impl UiModel {
    pub fn new(name: &str, addr: Address, role: Role) -> Self {
        let mut short_id = heapless::String::new();
        let s = u32::from_be_bytes([addr.0[4], addr.0[5], addr.0[6], addr.0[7]]);
        let _ = write!(short_id, "{:04X}.{:04X}", s >> 16, s & 0xFFFF);
        let mut nets = heapless::Vec::new();
        let _ = nets.push(UiNet { proto: Proto::Star, name: Name::try_from("MeshStar").unwrap_or_default(), nodes: 0, rssi: 0, frames: 0, last_seen: 0 });
        Self { name: name.chars().take(12).collect(), short_id, role, nodes: heapless::Vec::new(), msgs: heapless::Vec::new(), nets, compat: None, bridge: false, battery_mv: None, rssi_hist: [0; 56], hist_len: 0, last_rx_frames: 0, screen_on: true, last_activity: 0, screen_timeout_s: 0 }
    }

    pub fn unread(&self) -> usize {
        self.msgs.iter().filter(|m| m.unread).count()
    }

    pub fn battery_percent(&self) -> Option<u8> {
        self.battery_mv.map(|mv| ((mv.clamp(3300, 4150) - 3300) * 100 / 850) as u8)
    }

    fn short_addr(a: &Address) -> Name {
        let mut n = Name::new();
        let _ = write!(n, "{:02X}{:02X}.{:02X}{:02X}", a.0[4], a.0[5], a.0[6], a.0[7]);
        n
    }

    fn short_ref(r: &IdentityRef) -> Name {
        match r {
            IdentityRef::MeshStar(a) => Self::short_addr(a),
            IdentityRef::Meshtastic(n) => {
                let mut s = Name::new();
                let _ = write!(s, "!{:08x}", n);
                s
            }
            IdentityRef::MeshCore(_) => {
                // `meshcore:<hex>` -> first 8 hex digits of the key / hash.
                r.canonical().trim_start_matches("meshcore:").chars().take(8).collect()
            }
            IdentityRef::Broadcast(_) => Name::try_from("broadcast").unwrap_or_default(),
        }
    }

    /// Refresh the MeshStar entries from the node's tables.
    pub fn sync_native(&mut self, node: &Node, now: u64) {
        self.role = node.role();
        self.nodes.retain(|n| n.proto != Proto::Star);
        let sessions = node.sessions();
        let mut count = 0u8;
        for nb in node.neighbors().iter() {
            let key = IdentityRef::MeshStar(nb.addr);
            let sec = if sessions.contains_key(&nb.addr) { Sec::E2e } else { Sec::None };
            let sleeping = nb.role == Role::Leaf && nb.awake_until.map(|u| u < now).unwrap_or(true);
            let e = UiNode { proto: Proto::Star, key, name: Self::short_addr(&nb.addr), rssi: nb.rssi_dbm as i16, sec, hops: 1, sleeping, anchor: nb.role == Role::Anchor, last_seen: nb.last_seen };
            count = count.saturating_add(1);
            if self.nodes.push(e).is_err() {
                break;
            }
        }
        for z in node.zone().iter().filter(|z| z.distance > 1) {
            let key = IdentityRef::MeshStar(z.addr);
            let sec = if sessions.contains_key(&z.addr) { Sec::E2e } else { Sec::None };
            let e = UiNode { proto: Proto::Star, key, name: Self::short_addr(&z.addr), rssi: 0, sec, hops: z.distance, sleeping: false, anchor: false, last_seen: now };
            count = count.saturating_add(1);
            if self.nodes.push(e).is_err() {
                break;
            }
        }
        if let Some(n) = self.nets.iter_mut().find(|n| n.proto == Proto::Star) {
            n.nodes = count;
            n.frames = node.counters().rx_packets as u32;
            if count > 0 {
                n.last_seen = now;
            }
        }
        self.sort_nodes();
    }

    fn sort_nodes(&mut self) {
        // Strongest signal first, unknown (multi-hop) last.
        let mut v: heapless::Vec<UiNode, 16> = heapless::Vec::new();
        let mut items: alloc::vec::Vec<UiNode> = self.nodes.iter().cloned().collect();
        items.sort_by_key(|n| if n.rssi == 0 { 0 } else { n.rssi as i32 + 300 });
        items.reverse();
        for n in items {
            let _ = v.push(n);
        }
        self.nodes = v;
    }

    /// A MeshStar message arrived.
    pub fn push_native(&mut self, from: Address, text: &str, protection: Protection, rssi: i16, hops: u8, now: u64) {
        self.push_msg(UiMsg { proto: Proto::Star, from: Self::short_addr(&from), channel: Name::try_from("direct").unwrap_or_default(), text: text.chars().take(96).collect(), sec: Sec::from_protection(protection), rssi, hops, at: now, unread: true });
    }

    /// A frame decoded by the compatibility layer.
    pub fn observe_foreign(&mut self, m: &UnifiedMessage, rssi: i16, now: u64) {
        let proto = Proto::from_id(m.protocol);
        let name: Name = m.meta("long_name").or(m.meta("name")).or(m.meta("sender_name")).map(|s| s.chars().take(12).collect()).unwrap_or_else(|| Self::short_ref(&m.source));
        let sec = Sec::from_level(&m.security);
        if !m.source.is_broadcast() {
            if let Some(n) = self.nodes.iter_mut().find(|n| n.key == m.source) {
                n.rssi = rssi;
                n.last_seen = now;
                if m.meta("long_name").or(m.meta("name")).or(m.meta("sender_name")).is_some() {
                    n.name = name.clone();
                }
                if sec != Sec::Opaque || n.sec == Sec::None {
                    n.sec = sec;
                }
            } else {
                let e = UiNode { proto, key: m.source.clone(), name: name.clone(), rssi, sec, hops: m.hops.hops_travelled.unwrap_or(0), sleeping: false, anchor: false, last_seen: now };
                if self.nodes.is_full() {
                    // Drop the oldest foreign entry.
                    if let Some(i) = self.nodes.iter().enumerate().filter(|(_, n)| n.proto != Proto::Star).min_by_key(|(_, n)| n.last_seen).map(|(i, _)| i) {
                        self.nodes.swap_remove(i);
                    }
                }
                let _ = self.nodes.push(e);
            }
            self.sort_nodes();
        }
        // One entry per foreign network, named after the channel we decode.
        let chan: Name = m.channel.as_deref().unwrap_or(proto.name()).chars().take(12).collect();
        let nodes = self.nodes.iter().filter(|x| x.proto == proto).count() as u8;
        if let Some(n) = self.nets.iter_mut().find(|n| n.proto == proto) {
            n.frames += 1;
            n.rssi = rssi;
            n.last_seen = now;
            n.nodes = nodes;
            if m.channel.is_some() {
                n.name = chan.clone();
            }
        } else {
            let _ = self.nets.push(UiNet { proto, name: chan.clone(), nodes, rssi, frames: 1, last_seen: now });
        }
        if m.content_type == ContentType::Text {
            if let Some(t) = m.text_payload() {
                self.push_msg(UiMsg { proto, from: name, channel: chan, text: t.chars().take(96).collect(), sec, rssi, hops: m.hops.hops_travelled.unwrap_or(0), at: now, unread: true });
            }
        }
    }

    fn push_msg(&mut self, m: UiMsg) {
        if self.msgs.is_full() {
            self.msgs.pop();
        }
        let _ = self.msgs.insert(0, m);
    }

    /// Record the RSSI of each new frame for the sparkline.
    pub fn sample_signal(&mut self, radio: &RadioStats) {
        if radio.rx_frames == self.last_rx_frames {
            return;
        }
        self.last_rx_frames = radio.rx_frames;
        if self.hist_len < self.rssi_hist.len() {
            self.rssi_hist[self.hist_len] = radio.last_rssi_dbm;
            self.hist_len += 1;
        } else {
            self.rssi_hist.rotate_left(1);
            self.rssi_hist[self.rssi_hist.len() - 1] = radio.last_rssi_dbm;
        }
    }
}

// ---------------------------------------------------------------- input

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Press {
    Short,
    Long,
}

/// Debounced single-button decoder: short on release, long once after
/// 600 ms held.
pub struct Button {
    down_since: Option<u64>,
    long_fired: bool,
}

impl Button {
    pub const LONG_MS: u64 = 600;
    pub fn new() -> Self {
        Self { down_since: None, long_fired: false }
    }
    pub fn update(&mut self, down: bool, now: u64) -> Option<Press> {
        match (down, self.down_since) {
            (true, None) => {
                self.down_since = Some(now);
                self.long_fired = false;
                None
            }
            (true, Some(t)) => {
                if !self.long_fired && now.saturating_sub(t) >= Self::LONG_MS {
                    self.long_fired = true;
                    Some(Press::Long)
                } else {
                    None
                }
            }
            (false, Some(t)) => {
                self.down_since = None;
                if !self.long_fired && now.saturating_sub(t) >= 30 {
                    Some(Press::Short)
                } else {
                    None
                }
            }
            (false, None) => None,
        }
    }
}

impl Default for Button {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------- screens

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    Home,
    Chats,
    Networks,
    Signal,
    Node,
    Settings,
}

impl Screen {
    const RING: [Screen; 6] = [Screen::Home, Screen::Chats, Screen::Networks, Screen::Signal, Screen::Node, Screen::Settings];
    fn next(self) -> Self {
        let i = Self::RING.iter().position(|s| *s == self).unwrap_or(0);
        Self::RING[(i + 1) % Self::RING.len()]
    }
    fn index(self) -> usize {
        Self::RING.iter().position(|s| *s == self).unwrap_or(0)
    }
}

/// What the firmware should do after a long press.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    None,
    /// Cycle compat mode off -> MeshCore -> Meshtastic -> off.
    CycleCompat,
    /// Send a compat advert / node info now.
    Advert,
    /// Turn the screen off (any press turns it back on).
    ScreenOff,
    Reboot,
}

const SETTINGS: [&str; 5] = ["Compat", "Advert now", "Screen off", "Role", "Reboot"];

pub struct Ui {
    pub screen: Screen,
    cursor: usize,
    detail: bool,
    frame: u32,
}

impl Ui {
    pub fn new() -> Self {
        Self { screen: Screen::Home, cursor: 0, detail: false, frame: 0 }
    }

    fn items(&self, m: &UiModel) -> usize {
        match self.screen {
            Screen::Home => m.nodes.len(),
            Screen::Chats => m.msgs.len(),
            Screen::Networks => m.nets.len(),
            Screen::Signal | Screen::Node => 0,
            Screen::Settings => SETTINGS.len(),
        }
    }

    /// Feed a button press; returns the action the firmware must perform.
    pub fn press(&mut self, p: Press, m: &mut UiModel) -> Action {
        if self.detail {
            // Any press leaves a detail view.
            self.detail = false;
            return Action::None;
        }
        match p {
            Press::Short => {
                self.cursor += 1;
                if self.cursor >= self.items(m) {
                    self.cursor = 0;
                    self.screen = self.screen.next();
                }
                Action::None
            }
            Press::Long => match self.screen {
                Screen::Home => {
                    if !m.nodes.is_empty() {
                        self.detail = true;
                    }
                    Action::None
                }
                Screen::Chats => {
                    if let Some(msg) = m.msgs.get_mut(self.cursor) {
                        msg.unread = false;
                        self.detail = true;
                    }
                    Action::None
                }
                Screen::Networks => Action::CycleCompat,
                Screen::Signal | Screen::Node => Action::None,
                Screen::Settings => match self.cursor {
                    0 => Action::CycleCompat,
                    1 => Action::Advert,
                    2 => Action::ScreenOff,
                    4 => Action::Reboot,
                    _ => Action::None,
                },
            },
        }
    }

    /// Draw the current screen.
    pub fn render<I: I2c>(&mut self, d: &mut Ssd1306<I>, m: &UiModel, radio: &RadioStats, uptime_s: u64, now: u64) {
        self.frame = self.frame.wrapping_add(1);
        d.clear();
        self.header(d, m);
        if self.detail {
            match self.screen {
                Screen::Home => self.node_card(d, m, now),
                Screen::Chats => self.message(d, m, now),
                _ => self.detail = false,
            }
        } else {
            match self.screen {
                Screen::Home => self.home(d, m, now),
                Screen::Chats => self.chats(d, m, now),
                Screen::Networks => self.networks(d, m, now),
                Screen::Signal => self.signal(d, m, radio),
                Screen::Node => self.node(d, m, uptime_s),
                Screen::Settings => self.settings(d, m),
            }
        }
        // Ring position: a thin scrollbar at the right edge.
        let track = HEIGHT as i32 - 13;
        let thumb = track / Screen::RING.len() as i32;
        d.vline(WIDTH as i32 - 1, 13, track);
        d.fill_rect(WIDTH as i32 - 2, 13 + thumb * self.screen.index() as i32, 2, thumb, true);
        let _ = d.flush();
    }

    /// Inverted status bar: badge + name, role, compat, unread, nodes, battery.
    fn header<I: I2c>(&self, d: &mut Ssd1306<I>, m: &UiModel) {
        d.fill_rect(0, 0, WIDTH as i32, 11, true);
        d.icon8(1, 2, &ICON_STAR, false);
        let mut x = d.text_on(10, 2, &m.name, false) + 4;
        let role = match m.role {
            Role::Anchor => "A",
            Role::Leaf => "L",
            Role::Normal => "N",
        };
        x = d.text_on(x, 2, role, false) + 3;
        if let Some(c) = m.compat {
            d.fill_rect(x, 1, 7, 9, false);
            d.glyph(x + 1, 2, c.letter(), 1, true);
            x += 9;
        }
        if m.bridge {
            d.icon8(x, 2, &ICON_BRIDGE, false);
            x += 9;
        }
        let _ = x;
        // Right side, laid out from the edge inwards.
        let mut r = WIDTH as i32 - 1;
        d.battery(r - 12, 2, m.battery_percent(), false);
        r -= 15;
        let n = alloc::format!("{}", m.nodes.len());
        r = d.text_right(r, 2, &n) - 6 * n.len() as i32 - 1;
        d.icon8(r - 7, 2, &ICON_ANTENNA, false);
        r -= 10;
        let unread = m.unread();
        if unread > 0 {
            let u = alloc::format!("{}", unread);
            r = d.text_right(r, 2, &u) - 6 * u.len() as i32 - 1;
            d.icon16(r - ICON_MAIL_W as i32, 2, &ICON_MAIL, ICON_MAIL_W, false);
        }
    }

    fn row_y(i: usize) -> i32 {
        13 + 10 * i as i32
    }

    /// Which list window to show so that the cursor is visible.
    fn window(&self, len: usize, rows: usize) -> usize {
        if self.cursor >= rows {
            (self.cursor + 1 - rows).min(len.saturating_sub(rows))
        } else {
            0
        }
    }

    fn sec_tag<I: I2c>(d: &mut Ssd1306<I>, x: i32, y: i32, sec: Sec) {
        match sec.lock() {
            Some(true) => d.icon8(x, y, &ICON_LOCK, true),
            Some(false) => d.icon8(x, y, &ICON_LOCK_OPEN, true),
            None => {}
        }
        d.text(x + 6, y, sec.short());
    }

    fn age(now: u64, at: u64) -> heapless::String<8> {
        let s = now.saturating_sub(at) / 1000;
        let mut o = heapless::String::new();
        let _ = if s < 60 { write!(o, "{}s", s) } else if s < 3600 { write!(o, "{}m", s / 60) } else { write!(o, "{}h", s / 3600) };
        o
    }

    fn home<I: I2c>(&self, d: &mut Ssd1306<I>, m: &UiModel, now: u64) {
        if m.nodes.is_empty() {
            d.text(4, 22, "Listening...");
            d.text(4, 34, "no nodes heard yet");
            return;
        }
        let start = self.window(m.nodes.len(), 5);
        for (i, n) in m.nodes.iter().enumerate().skip(start).take(5) {
            let y = Self::row_y(i - start);
            d.badge(1, y, n.proto, true);
            let name: heapless::String<9> = n.name.chars().take(9).collect();
            d.text(10, y + 1, &name);
            if n.sleeping {
                d.icon8(66, y + 1, &ICON_MOON, true);
            } else if n.rssi != 0 {
                d.bars(66, y + 1, n.rssi, true);
                let r = alloc::format!("{}", n.rssi);
                d.text(78, y + 1, &r);
            } else {
                let h = alloc::format!("{}hop", n.hops);
                d.text(66, y + 1, &h);
            }
            if n.anchor {
                d.icon8(112, y + 1, &ICON_ANCHOR, true);
            } else {
                Self::sec_tag(d, 101, y + 1, n.sec);
            }
            if i == self.cursor {
                d.invert_rect(0, y, WIDTH as i32 - 3, 10);
            }
        }
        let _ = now;
    }

    fn node_card<I: I2c>(&self, d: &mut Ssd1306<I>, m: &UiModel, now: u64) {
        let Some(n) = m.nodes.get(self.cursor) else { return };
        d.badge(1, 13, n.proto, true);
        d.text(10, 14, &n.name);
        d.text_right(WIDTH as i32 - 4, 14, &Self::age(now, n.last_seen));
        let kind = alloc::format!("{}{}", n.proto.name(), if n.anchor { " anchor" } else if n.sleeping { " leaf, asleep" } else { "" });
        d.text(4, 24, &kind);
        let sig = if n.rssi != 0 { alloc::format!("{} dBm, {} hop", n.rssi, n.hops) } else { alloc::format!("{} hops away", n.hops) };
        d.text(4, 34, &sig);
        if n.rssi != 0 {
            d.bars(100, 34, n.rssi, true);
        }
        Self::sec_tag(d, 4, 46, n.sec);
        d.text(4, 55, n.sec.long());
    }

    fn chats<I: I2c>(&self, d: &mut Ssd1306<I>, m: &UiModel, now: u64) {
        if m.msgs.is_empty() {
            d.text(4, 22, "No messages yet.");
            d.text(4, 34, "Hold to open one.");
            return;
        }
        let start = self.window(m.msgs.len(), 5);
        for (i, msg) in m.msgs.iter().enumerate().skip(start).take(5) {
            let y = Self::row_y(i - start);
            d.badge(1, y, msg.proto, true);
            let from: heapless::String<7> = msg.from.chars().take(7).collect();
            let x = d.text(10, y + 1, &from);
            let width = ((104 - x) / 6).max(0) as usize;
            let text: heapless::String<16> = msg.text.chars().take(width).collect();
            d.text(x + 4, y + 1, &text);
            d.text_right(WIDTH as i32 - 4, y + 1, &Self::age(now, msg.at));
            if msg.unread {
                d.fill_rect(WIDTH as i32 - 5, y + 3, 2, 2, true);
            }
            if i == self.cursor {
                d.invert_rect(0, y, WIDTH as i32 - 3, 10);
            }
        }
    }

    fn message<I: I2c>(&self, d: &mut Ssd1306<I>, m: &UiModel, now: u64) {
        let Some(msg) = m.msgs.get(self.cursor) else { return };
        d.badge(1, 13, msg.proto, true);
        d.text(10, 14, &msg.from);
        d.text_right(WIDTH as i32 - 4, 14, &Self::age(now, msg.at));
        // Up to three lines of text, wrapped at 20 columns.
        let mut y = 24;
        let mut line = heapless::String::<21>::new();
        for w in msg.text.split(' ') {
            if line.len() + w.len() + usize::from(!line.is_empty()) > 20 {
                d.text(4, y, &line);
                y += 9;
                line.clear();
                if y > 42 {
                    break;
                }
            }
            if !line.is_empty() {
                let _ = line.push(' ');
            }
            let _ = line.push_str(&w.chars().take(20).collect::<heapless::String<21>>());
        }
        if !line.is_empty() && y <= 42 {
            d.text(4, y, &line);
        }
        Self::sec_tag(d, 4, 54, msg.sec);
        let meta = alloc::format!("{}dBm {}h", msg.rssi, msg.hops);
        d.text_right(WIDTH as i32 - 4, 54, &meta);
    }

    fn networks<I: I2c>(&self, d: &mut Ssd1306<I>, m: &UiModel, now: u64) {
        let start = self.window(m.nets.len(), 4);
        for (i, n) in m.nets.iter().enumerate().skip(start).take(4) {
            let y = Self::row_y(i - start);
            d.badge(1, y, n.proto, true);
            let name: heapless::String<9> = n.name.chars().take(9).collect();
            d.text(10, y + 1, &name);
            let cnt = alloc::format!("{}", n.nodes);
            d.icon8(66, y + 1, &ICON_ANTENNA, true);
            d.text(74, y + 1, &cnt);
            if n.rssi != 0 {
                d.bars(88, y + 1, n.rssi, true);
                let r = alloc::format!("{}", n.rssi);
                d.text_right(WIDTH as i32 - 4, y + 1, &r);
            } else if n.last_seen == 0 {
                d.text_right(WIDTH as i32 - 4, y + 1, "--");
            }
            if i == self.cursor {
                d.invert_rect(0, y, WIDTH as i32 - 3, 10);
            }
        }
        let status = match m.compat {
            None => alloc::string::String::from("scan: MeshStar only"),
            Some(p) => alloc::format!("compat: {}", p.name()),
        };
        d.text(4, 54, &status);
        // Blink a dot while listening.
        if self.frame % 4 < 2 {
            d.fill_rect(WIDTH as i32 - 8, 56, 3, 3, true);
        }
        let _ = now;
    }

    fn signal<I: I2c>(&self, d: &mut Ssd1306<I>, m: &UiModel, radio: &RadioStats) {
        let rssi = alloc::format!("{}", radio.last_rssi_dbm);
        let x = d.text_2x(2, 14, &rssi);
        d.text(x + 2, 21, "dBm");
        d.bars(2, 32, radio.last_rssi_dbm, true);
        let snr = alloc::format!("snr {:+.1}", radio.last_snr_db);
        d.text(14, 32, &snr);
        let l1 = alloc::format!("rx {} tx {}", radio.rx_frames, radio.tx_frames);
        d.text(2, 43, &l1);
        let l2 = alloc::format!("crc {} air {}s", radio.rx_crc_errors, radio.tx_airtime_ms / 1000);
        d.text(2, 53, &l2);
        // Sparkline of the last frames' RSSI, -130..-30 dBm over 30 px.
        let (gx, gy, gw, gh) = (70, 14, 54, 30);
        d.rect(gx - 1, gy - 1, gw + 2, gh + 2);
        for (i, r) in m.rssi_hist[..m.hist_len].iter().enumerate() {
            let v = (*r as i32).clamp(-130, -30) + 130;
            let h = v * gh / 100;
            d.vline(gx + i as i32, gy + gh - h, h.max(1));
        }
        d.text(gx, gy + gh + 3, "last frames");
    }

    fn node<I: I2c>(&self, d: &mut Ssd1306<I>, m: &UiModel, uptime_s: u64) {
        d.icon8(2, 14, &ICON_STAR, true);
        d.text(12, 14, &m.name);
        d.text_right(WIDTH as i32 - 4, 14, m.role.name());
        let id = alloc::format!("ID {}", m.short_id);
        d.text(2, 24, &id);
        let net = m.nets.iter().find(|n| n.proto == Proto::Star);
        let l = alloc::format!("zone {} nodes, {} msgs", net.map(|n| n.nodes).unwrap_or(0), m.msgs.len());
        d.text(2, 34, &l);
        let bat = match m.battery_mv {
            Some(mv) => alloc::format!("bat {}.{:02}V {}%", mv / 1000, (mv % 1000) / 10, m.battery_percent().unwrap_or(0)),
            None => alloc::string::String::from("bat: no gauge"),
        };
        d.text(2, 44, &bat);
        let up = alloc::format!("up {:02}:{:02}:{:02}", uptime_s / 3600, (uptime_s / 60) % 60, uptime_s % 60);
        d.text(2, 54, &up);
    }

    fn settings<I: I2c>(&self, d: &mut Ssd1306<I>, m: &UiModel) {
        for (i, name) in SETTINGS.iter().enumerate() {
            let y = Self::row_y(i);
            d.text(4, y + 1, name);
            let value = match i {
                0 => alloc::string::String::from(m.compat.map(|p| p.name()).unwrap_or("off")),
                1 => alloc::string::String::from(if m.compat.is_some() { "hold" } else { "n/a" }),
                2 => alloc::string::String::from("hold"),
                3 => alloc::string::String::from(m.role.name()),
                _ => alloc::string::String::from("hold"),
            };
            d.text_right(WIDTH as i32 - 4, y + 1, &value);
            if i == self.cursor {
                d.invert_rect(0, y, WIDTH as i32 - 3, 10);
            }
        }
    }
}

impl Default for Ui {
    fn default() -> Self {
        Self::new()
    }
}

/// Boot screen: logo, name, id and version.
pub fn splash<I: I2c>(d: &mut Ssd1306<I>, name: &str, short_id: &str, version: &str) {
    d.clear();
    // The 12x12 star at 2x on the left, name and id on the right.
    for (r, bits) in LOGO_STAR.iter().enumerate() {
        for c in 0..12 {
            if bits & (0x800 >> c) != 0 {
                d.fill_rect(2 + c * 2, 10 + r as i32 * 2, 2, 2, true);
            }
        }
    }
    d.text_2x(30, 8, "MeshStar");
    d.text(30, 26, name);
    d.text(30, 36, short_id);
    d.hline(0, 48, WIDTH as i32);
    d.text(4, 53, version);
    let _ = d.flush();
}
