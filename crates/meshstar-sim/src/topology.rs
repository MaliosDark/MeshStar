//! Node placement, roles, mobility and outages.

use meshstar_core::protocol::Role;
use rand_core::RngCore;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Shape {
    Grid,
    Random,
    Clustered,
    Line,
    Ring,
}

impl Shape {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "grid" => Some(Self::Grid),
            "random" => Some(Self::Random),
            "clustered" | "clusters" => Some(Self::Clustered),
            "line" | "chain" => Some(Self::Line),
            "ring" => Some(Self::Ring),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TopologyParams {
    pub shape: Shape,
    pub nodes: usize,
    pub width_m: f32,
    pub height_m: f32,
    /// Spacing for grid/line/ring (metres between neighbours).
    pub spacing_m: f32,
    pub clusters: usize,
    pub cluster_radius_m: f32,
    pub anchor_fraction: f32,
    pub leaf_fraction: f32,
    /// If set, the area is rescaled at start-up so that the average node
    /// hears about this many others, using the link model's nominal range.
    pub target_degree: Option<f32>,
}

impl TopologyParams {
    /// Random placement sized so that the average node sees about
    /// `target_degree` others (with the default link model, ~1.8 km range).
    pub fn random(nodes: usize, target_degree: f32) -> Self {
        let range = 1_800.0f32;
        let area_per_node = std::f32::consts::PI * range * range / target_degree.max(1.0);
        let side = (area_per_node * nodes as f32).sqrt();
        Self { shape: Shape::Random, nodes, width_m: side, height_m: side, spacing_m: 1_200.0, clusters: 4, cluster_radius_m: 1_500.0, anchor_fraction: 0.1, leaf_fraction: 0.2, target_degree: Some(target_degree) }
    }

    pub fn grid(nodes: usize, spacing_m: f32) -> Self {
        let side = (nodes as f32).sqrt().ceil();
        Self { shape: Shape::Grid, nodes, width_m: side * spacing_m, height_m: side * spacing_m, spacing_m, clusters: 1, cluster_radius_m: 0.0, anchor_fraction: 0.1, leaf_fraction: 0.2, target_degree: None }
    }
}

/// A placed node.
#[derive(Clone, Copy, Debug)]
pub struct Placement {
    pub x: f32,
    pub y: f32,
    pub role: Role,
}

pub struct Topology;

impl Topology {
    pub fn build(p: &TopologyParams, rng: &mut impl RngCore) -> Vec<Placement> {
        let n = p.nodes.max(1);
        let mut out = Vec::with_capacity(n);
        let unit = |rng: &mut dyn RngCore| (rng.next_u32() % 100_000) as f32 / 100_000.0;
        match p.shape {
            Shape::Grid => {
                let side = (n as f32).sqrt().ceil() as usize;
                for i in 0..n {
                    let gx = (i % side) as f32 * p.spacing_m;
                    let gy = (i / side) as f32 * p.spacing_m;
                    // small jitter avoids perfectly symmetric ties
                    let jx = (unit(rng) - 0.5) * p.spacing_m * 0.1;
                    let jy = (unit(rng) - 0.5) * p.spacing_m * 0.1;
                    out.push(Placement { x: gx + jx, y: gy + jy, role: Role::Normal });
                }
            }
            Shape::Random => {
                for _ in 0..n {
                    out.push(Placement { x: unit(rng) * p.width_m, y: unit(rng) * p.height_m, role: Role::Normal });
                }
            }
            Shape::Clustered => {
                let k = p.clusters.max(1);
                let centers: Vec<(f32, f32)> = (0..k).map(|_| (unit(rng) * p.width_m, unit(rng) * p.height_m)).collect();
                for i in 0..n {
                    let c = centers[i % k];
                    let a = unit(rng) * std::f32::consts::TAU;
                    let r = unit(rng).sqrt() * p.cluster_radius_m;
                    out.push(Placement { x: c.0 + a.cos() * r, y: c.1 + a.sin() * r, role: Role::Normal });
                }
            }
            Shape::Line => {
                for i in 0..n {
                    out.push(Placement { x: i as f32 * p.spacing_m, y: (unit(rng) - 0.5) * p.spacing_m * 0.2, role: Role::Normal });
                }
            }
            Shape::Ring => {
                let r = p.spacing_m * n as f32 / std::f32::consts::TAU;
                for i in 0..n {
                    let a = i as f32 / n as f32 * std::f32::consts::TAU;
                    out.push(Placement { x: r + a.cos() * r, y: r + a.sin() * r, role: Role::Normal });
                }
            }
        }
        // Roles: anchors spread evenly, leaves after them.
        let anchors = ((n as f32) * p.anchor_fraction).round() as usize;
        let leaves = ((n as f32) * p.leaf_fraction).round() as usize;
        if anchors > 0 {
            let stride = n / anchors.max(1);
            for a in 0..anchors {
                let i = (a * stride.max(1)) % n;
                out[i].role = Role::Anchor;
            }
        }
        let mut assigned = 0;
        let mut i = 1;
        while assigned < leaves && i < n {
            if out[i].role == Role::Normal {
                out[i].role = Role::Leaf;
                assigned += 1;
            }
            i += 1;
        }
        out
    }
}

/// Random waypoint mobility.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MobilityParams {
    pub mobile_fraction: f32,
    pub speed_mps: f32,
    pub reach_update_ms: u64,
}

impl Default for MobilityParams {
    fn default() -> Self {
        Self { mobile_fraction: 0.2, speed_mps: 1.4, reach_update_ms: 5_000 }
    }
}

/// Random node outages (power loss, reboot, out of range).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OutageParams {
    pub outages_per_node_hour: f32,
    pub outage_duration_s: u32,
}

impl Default for OutageParams {
    fn default() -> Self {
        Self { outages_per_node_hour: 2.0, outage_duration_s: 120 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::SeedableRng;

    #[test]
    fn roles_and_counts() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        for shape in [Shape::Grid, Shape::Random, Shape::Clustered, Shape::Line, Shape::Ring] {
            let mut p = TopologyParams::random(100, 6.0);
            p.shape = shape;
            let t = Topology::build(&p, &mut rng);
            assert_eq!(t.len(), 100);
            assert_eq!(t.iter().filter(|x| x.role == Role::Anchor).count(), 10);
            assert_eq!(t.iter().filter(|x| x.role == Role::Leaf).count(), 20);
        }
    }
}
