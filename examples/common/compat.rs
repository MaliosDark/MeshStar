//! On-device compatibility mode: tune the radio to a foreign profile and run
//! the adapter layer on received frames; transmit foreign frames.

use alloc::string::String;
use alloc::vec::Vec;

use meshstar_core::radio::{LoRaProfile, RxMeta};
use meshstar_protocols::adapter::ProtocolContext;
use meshstar_protocols::detector::Detector;
use meshstar_protocols::model::{IdentityRef, ProtocolId, UnifiedMessage};
use meshstar_protocols::{meshcore, meshtastic};

pub struct Compat {
    pub mode: Option<ProtocolId>,
    pub detector: Detector,
    pub ctx: ProtocolContext,
    pub seen: u32,
    meshcore_id: meshstar_protocols::adapter::LocalProtocolIdentity,
    meshtastic_id: meshstar_protocols::adapter::LocalProtocolIdentity,
}

impl Compat {
    pub fn new(seed: &[u8; 32], name: &str) -> Self {
        let mut ctx = ProtocolContext::new(0, 1_700_000_000, LoRaProfile::MESHSTAR_EU868);
        ctx.channels.push(meshcore::public_channel());
        ctx.channels.push(meshtastic::default_channel_key());
        let meshcore_id = meshcore::local_identity_from_seed(seed, name);
        // Meshtastic node number: low 32 bits of the seed-derived address.
        let addr = meshstar_core::identity::Identity::from_seed(seed).address();
        let num = u32::from_be_bytes([addr.0[4], addr.0[5], addr.0[6], addr.0[7]]);
        let meshtastic_id = meshstar_protocols::adapter::LocalProtocolIdentity { protocol: ProtocolId::Meshtastic, id: IdentityRef::Meshtastic(num), display_name: String::from(name), short_name: name.chars().take(4).collect(), secret: Vec::new() };
        ctx.local = Some(meshcore_id.clone());
        Self { mode: None, detector: Detector::with_all(None, None), ctx, seen: 0, meshcore_id, meshtastic_id }
    }

    fn select_identity(&mut self, mode: ProtocolId) {
        self.ctx.local = Some(match mode {
            ProtocolId::Meshtastic => self.meshtastic_id.clone(),
            _ => self.meshcore_id.clone(),
        });
    }

    /// Profile to tune the radio to for `mode`.
    pub fn profile(mode: ProtocolId) -> LoRaProfile {
        match mode {
            ProtocolId::MeshCore => meshcore::profiles::eu_uk_sf8(),
            ProtocolId::Meshtastic => meshtastic::profiles::preset("LongFast", meshstar_protocols::profiles::Region::Eu868).unwrap_or(LoRaProfile::MESHSTAR_EU868),
            _ => LoRaProfile::MESHSTAR_EU868,
        }
    }

    /// Classify and decode a received frame; returns a one-line summary.
    pub fn on_rx(&mut self, frame: &[u8], meta: &RxMeta, now: u64, random: [u8; 32]) -> String {
        self.ctx.now_ms = now;
        self.ctx.random = random;
        self.seen += 1;
        let (d, r) = self.detector.classify(frame, meta, &self.ctx);
        match r {
            Some(Ok(m)) => alloc::format!("[{} {}] {} -> {} {:?} {} | {}", d.protocol, d.score, m.source, m.destination, m.content_type, m.text_payload().map(|t| alloc::format!("{:?}", t)).unwrap_or_default(), m.security.label()),
            Some(Err(e)) => alloc::format!("[{} {}] decode error {}", d.protocol, d.score, e),
            None => alloc::format!("[unknown {} probable {:?}] {} bytes", d.score, d.probable, frame.len()),
        }
    }

    /// Encode a public-channel text for `mode`.
    pub fn encode_text(&mut self, mode: ProtocolId, text: &str, now: u64, random: [u8; 32]) -> Result<Vec<u8>, String> {
        self.ctx.now_ms = now;
        self.ctx.unix_time_s = 1_700_000_000 + (now / 1000) as u32;
        self.ctx.random = random;
        self.ctx.profile = Self::profile(mode);
        self.select_identity(mode);
        let adapter = self.detector.adapter(mode).ok_or_else(|| String::from("no adapter"))?;
        let src = self.ctx.local.as_ref().map(|l| l.id.clone()).unwrap_or(IdentityRef::Broadcast(mode));
        let mut m = UnifiedMessage::text(src, IdentityRef::Broadcast(mode), mode, text);
        m.channel = Some(match mode {
            ProtocolId::MeshCore => "Public".into(),
            _ => "LongFast".into(),
        });
        adapter.encode(&m, &self.ctx).map(|f| f.bytes).map_err(|e| alloc::format!("{}", e))
    }

    /// Frames the adapter wants to send periodically (adverts / node info).
    pub fn periodic(&mut self, mode: ProtocolId, now: u64, random: [u8; 32]) -> Vec<Vec<u8>> {
        self.ctx.now_ms = now;
        self.ctx.unix_time_s = 1_700_000_000 + (now / 1000) as u32;
        self.ctx.random = random;
        self.ctx.profile = Self::profile(mode);
        self.select_identity(mode);
        match self.detector.adapter_mut(mode) {
            Some(a) => a.periodic(&self.ctx).into_iter().map(|f| f.bytes).collect(),
            None => Vec::new(),
        }
    }
}
