//! ROUTE_REQUEST / ROUTE_REPLY / ROUTE_ERROR payload codecs.
//!
//! ```text
//! ROUTE_REQUEST  (dst = BROADCAST, relayed selectively)
//!   target (8) | cost u16 | flags u8
//! ROUTE_REPLY    (unicast to the request origin along the reverse path)
//!   target (8) | req_id u32 | hops_to_target u8 | cost u16 | flags u8 | [target pubkey 32]
//! ROUTE_ERROR    (unicast to the source of the packet that could not be forwarded)
//!   count u8 | unreachable (8) ...
//! ```

use alloc::vec::Vec;

use crate::identity::Address;
use crate::protocol::{Error, Result};

pub mod rreq_flags {
    /// An ANCHOR may answer on behalf of the target (sleeping LEAF).
    pub const PROXY_OK: u8 = 1 << 0;
    /// Origin wants the target's public key in the reply (for envelopes).
    pub const WANT_KEY: u8 = 1 << 1;
}

pub mod rrep_flags {
    /// The replier is an ANCHOR answering for the target.
    pub const PROXY: u8 = 1 << 0;
    pub const HAS_KEY: u8 = 1 << 1;
    /// The target is a LEAF (sleeping or not).
    pub const TARGET_LEAF: u8 = 1 << 2;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteRequest {
    pub target: Address,
    pub cost: u16,
    pub flags: u8,
}

impl RouteRequest {
    pub const LEN: usize = 11;

    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(Self::LEN);
        v.extend_from_slice(&self.target.0);
        v.extend_from_slice(&self.cost.to_be_bytes());
        v.push(self.flags);
        v
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != Self::LEN {
            return Err(Error::Truncated);
        }
        let target = Address::from_bytes(&b[..8])?;
        if target.is_null() || target.is_broadcast() {
            return Err(Error::BadField);
        }
        Ok(Self { target, cost: u16::from_be_bytes([b[8], b[9]]), flags: b[10] })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteReply {
    pub target: Address,
    pub req_id: u32,
    pub hops_to_target: u8,
    pub cost: u16,
    pub flags: u8,
    pub target_key: Option<[u8; 32]>,
}

impl RouteReply {
    pub const MIN_LEN: usize = 16;

    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(Self::MIN_LEN + 32);
        v.extend_from_slice(&self.target.0);
        v.extend_from_slice(&self.req_id.to_be_bytes());
        v.push(self.hops_to_target);
        v.extend_from_slice(&self.cost.to_be_bytes());
        let mut flags = self.flags & !rrep_flags::HAS_KEY;
        if self.target_key.is_some() {
            flags |= rrep_flags::HAS_KEY;
        }
        v.push(flags);
        if let Some(k) = &self.target_key {
            v.extend_from_slice(k);
        }
        v
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() < Self::MIN_LEN {
            return Err(Error::Truncated);
        }
        let target = Address::from_bytes(&b[..8])?;
        if target.is_null() || target.is_broadcast() {
            return Err(Error::BadField);
        }
        let req_id = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
        let hops_to_target = b[12];
        let cost = u16::from_be_bytes([b[13], b[14]]);
        let flags = b[15];
        let target_key = if flags & rrep_flags::HAS_KEY != 0 {
            if b.len() != Self::MIN_LEN + 32 {
                return Err(Error::Truncated);
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&b[16..48]);
            Some(k)
        } else {
            if b.len() != Self::MIN_LEN {
                return Err(Error::BadField);
            }
            None
        };
        Ok(Self { target, req_id, hops_to_target, cost, flags, target_key })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteError {
    pub unreachable: Vec<Address>,
}

impl RouteError {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + 8 * self.unreachable.len());
        v.push(self.unreachable.len().min(16) as u8);
        for a in self.unreachable.iter().take(16) {
            v.extend_from_slice(&a.0);
        }
        v
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.is_empty() {
            return Err(Error::Truncated);
        }
        let n = b[0] as usize;
        if n == 0 || n > 16 || b.len() != 1 + 8 * n {
            return Err(Error::BadField);
        }
        let mut unreachable = Vec::with_capacity(n);
        for i in 0..n {
            let a = Address::from_bytes(&b[1 + 8 * i..9 + 8 * i])?;
            if a.is_null() || a.is_broadcast() {
                return Err(Error::BadField);
            }
            unreachable.push(a);
        }
        Ok(Self { unreachable })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips() {
        let q = RouteRequest { target: Address([3; 8]), cost: 1234, flags: rreq_flags::PROXY_OK };
        assert_eq!(RouteRequest::decode(&q.encode()).unwrap(), q);
        assert!(RouteRequest::decode(&q.encode()[..5]).is_err());
        let r = RouteReply { target: Address([3; 8]), req_id: 99, hops_to_target: 4, cost: 400, flags: rrep_flags::PROXY, target_key: Some([7; 32]) };
        let d = RouteReply::decode(&r.encode()).unwrap();
        assert_eq!(d.target_key, r.target_key);
        assert!(d.flags & rrep_flags::HAS_KEY != 0);
        let r2 = RouteReply { target_key: None, ..r.clone() };
        assert_eq!(RouteReply::decode(&r2.encode()).unwrap().target_key, None);
        let mut bad = r2.encode();
        bad.push(1);
        assert!(RouteReply::decode(&bad).is_err());
        let e = RouteError { unreachable: alloc::vec![Address([1; 8]), Address([2; 8])] };
        assert_eq!(RouteError::decode(&e.encode()).unwrap(), e);
        assert!(RouteError::decode(&[0]).is_err());
        assert!(RouteError::decode(&[1, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }
}
