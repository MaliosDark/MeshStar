//! Minimal SSD1306 (128x64, I2C) driver in page mode plus a 5x7 font and
//! the status screens of a MeshStar node. Shared by the ESP32 examples.
//! Modelled on the original firmware's OLED UI (SIGNAL / NODES / CONFIG /
//! MESSAGES pages, `ID: XXXX.XXXX`, `Role: ANCHOR n:3`).

use core::fmt::Write;

use embedded_hal::i2c::I2c;
use meshstar_core::node::Node;
use meshstar_core::radio::RadioStats;

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

    /// Draw text at column `x` (pixels) on text row `row` (0..=7).
    pub fn text(&mut self, x: usize, row: usize, s: &str) {
        if row >= PAGES {
            return;
        }
        let mut cx = x;
        for ch in s.bytes() {
            if cx + 6 > WIDTH {
                break;
            }
            let g = FONT.get(ch.saturating_sub(32) as usize).copied().unwrap_or([0x7f; 5]);
            for (i, col) in g.iter().enumerate() {
                self.buf[row * WIDTH + cx + i] = *col;
            }
            self.buf[row * WIDTH + cx + 5] = 0;
            cx += 6;
        }
        self.dirty[row] = true;
    }

    pub fn hline(&mut self, row: usize) {
        for x in 0..WIDTH {
            self.buf[row * WIDTH + x] |= 0x80;
        }
        self.dirty[row] = true;
    }
}

/// Which page is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    Status,
    Signal,
    Nodes,
    Radio,
}

impl Page {
    pub fn next(self) -> Self {
        match self {
            Self::Status => Self::Signal,
            Self::Signal => Self::Nodes,
            Self::Nodes => Self::Radio,
            Self::Radio => Self::Status,
        }
    }
}

/// Fixed-capacity line buffer for formatting without allocation.
struct Line(heapless::String<32>);
impl Line {
    fn new() -> Self {
        Self(heapless::String::new())
    }
    fn fmt(mut self, args: core::fmt::Arguments) -> Self {
        let _ = self.0.write_fmt(args);
        self
    }
}

/// Render one page of node state.
pub fn render<I: I2c>(d: &mut Ssd1306<I>, page: Page, node: &mut Node, radio: &RadioStats, battery_mv: Option<u32>, uptime_s: u64) {
    d.clear();
    let a = node.address();
    let short = u32::from_be_bytes([a.0[4], a.0[5], a.0[6], a.0[7]]);
    match page {
        Page::Status => {
            d.text(0, 0, "MeshStar");
            d.text(0, 1, &Line::new().fmt(format_args!("ID: {:04X}.{:04X}", short >> 16, short & 0xFFFF)).0);
            d.text(0, 2, &Line::new().fmt(format_args!("Role: {:<7} n:{}", node.role().name(), node.neighbors().len())).0);
            d.text(0, 3, &Line::new().fmt(format_args!("Nodes: {:<3} Sess: {}", node.zone().len(), node.sessions().len())).0);
            let c = node.counters();
            d.text(0, 4, &Line::new().fmt(format_args!("RX: {:<6} TX: {}", c.rx_packets, c.tx_packets)).0);
            match battery_mv {
                Some(mv) => d.text(0, 5, &Line::new().fmt(format_args!("Bat: {}.{:02}V", mv / 1000, (mv % 1000) / 10)).0),
                None => d.text(0, 5, "Bat: --  (no bat)"),
            }
            d.text(0, 6, &Line::new().fmt(format_args!("Up: {:02}:{:02}:{:02}", uptime_s / 3600, (uptime_s / 60) % 60, uptime_s % 60)).0);
            d.text(0, 7, "> next");
        }
        Page::Signal => {
            d.text(0, 0, "SIGNAL");
            d.text(0, 1, &Line::new().fmt(format_args!("RSSI: {} dBm", radio.last_rssi_dbm)).0);
            d.text(0, 2, &Line::new().fmt(format_args!("SNR:  {:+.1} dB", radio.last_snr_db)).0);
            d.text(0, 3, &Line::new().fmt(format_args!("RX: {:<6} TX: {}", radio.rx_frames, radio.tx_frames)).0);
            d.text(0, 4, &Line::new().fmt(format_args!("CRC err: {}", radio.rx_crc_errors)).0);
            d.text(0, 5, &Line::new().fmt(format_args!("Air TX: {}s", radio.tx_airtime_ms / 1000)).0);
            d.text(0, 7, "> next");
        }
        Page::Nodes => {
            d.text(0, 0, "NODES");
            let mut row = 1;
            for n in node.neighbors().iter().take(6) {
                let s = u32::from_be_bytes([n.addr.0[4], n.addr.0[5], n.addr.0[6], n.addr.0[7]]);
                d.text(0, row, &Line::new().fmt(format_args!("{:04X}.{:04X} {} {:>4}", s >> 16, s & 0xFFFF, &n.role.name()[..1], n.rssi_dbm as i32)).0);
                row += 1;
            }
            if row == 1 {
                d.text(0, 2, "No nodes heard yet.");
            }
            let more = node.neighbors().len().saturating_sub(6);
            if more > 0 {
                d.text(0, 7, &Line::new().fmt(format_args!("+{} more  > next", more)).0);
            } else {
                d.text(0, 7, "> next");
            }
        }
        Page::Radio => {
            let p = node.config().profile;
            d.text(0, 0, "RADIO");
            d.text(0, 1, &Line::new().fmt(format_args!("{}.{:03}MHz", p.frequency_hz / 1_000_000, (p.frequency_hz / 1000) % 1000)).0);
            d.text(0, 2, &Line::new().fmt(format_args!("SF{} BW{}k CR4/{}", p.spreading_factor, p.bandwidth_hz / 1000, p.coding_rate)).0);
            d.text(0, 3, &Line::new().fmt(format_args!("Pwr {} dBm sync {:02X}", p.tx_power_dbm, p.sync_word)).0);
            let dg = node.diagnostics();
            d.text(0, 4, &Line::new().fmt(format_args!("Duty: {}.{}%", dg.airtime_permille / 10, dg.airtime_permille % 10)).0);
            d.text(0, 5, &Line::new().fmt(format_args!("Queue {} relays {}", dg.tx_queue, dg.pending_relays)).0);
            d.text(0, 7, "> next");
        }
    }
    d.hline(0);
    let _ = d.flush();
}
