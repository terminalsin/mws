//! Static IP addresses: two IPv4 addresses (and two IPv6 addresses for dual
//! stack) per accelerator, one from each of Global Accelerator's network
//! zones, unique across every account; and IPv4 CIDR arithmetic.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use rand::Rng;

/// The anycast ranges Global Accelerator assigns from, one per network
/// zone.
const IPV4_POOLS: [(Ipv4Addr, u8); 2] = [(Ipv4Addr::new(75, 2, 0, 0), 17), (Ipv4Addr::new(99, 83, 128, 0), 17)];
const IPV6_POOLS: [u16; 2] = [0xa400, 0xa800];

/// A free IPv4 address in network zone `zone` (0 or 1).
pub fn allocate_ipv4(zone: usize, used: &BTreeSet<String>) -> String {
    let (base, prefix) = IPV4_POOLS[zone % 2];
    let size = 1u32 << (32 - prefix);
    let mut rng = rand::thread_rng();
    loop {
        // Skip the network and broadcast-looking ends of each /24.
        let offset = rng.gen_range(1..size - 1);
        let ip = Ipv4Addr::from(u32::from(base) + offset);
        let last = ip.octets()[3];
        if last == 0 || last == 255 {
            continue;
        }
        let s = ip.to_string();
        if !used.contains(&s) {
            return s;
        }
    }
}

pub fn allocate_ipv6(zone: usize, used: &BTreeSet<String>) -> String {
    let mut rng = rand::thread_rng();
    loop {
        let ip = Ipv6Addr::new(
            0x2600,
            0x9000,
            IPV6_POOLS[zone % 2] | rng.gen_range(0..0x400),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen_range(1..u16::MAX),
        );
        let s = ip.to_string();
        if !used.contains(&s) {
            return s;
        }
    }
}

/// An IPv4 CIDR block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub network: u32,
    pub prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Self> {
        let (ip, prefix) = s.split_once('/')?;
        let ip: Ipv4Addr = ip.parse().ok()?;
        let prefix: u8 = prefix.parse().ok().filter(|p| *p <= 32)?;
        let network = u32::from(ip);
        let mask = Self::mask(prefix);
        (network & mask == network).then_some(Self { network, prefix })
    }

    fn mask(prefix: u8) -> u32 {
        if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        }
    }

    pub fn size(&self) -> u64 {
        1u64 << (32 - self.prefix)
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & Self::mask(self.prefix) == self.network
    }

    pub fn overlaps(&self, other: &Cidr) -> bool {
        let p = self.prefix.min(other.prefix);
        self.network & Self::mask(p) == other.network & Self::mask(p)
    }

    /// The address at `index` from the start of the block.
    pub fn nth(&self, index: u64) -> Ipv4Addr {
        Ipv4Addr::from(self.network.wrapping_add(index as u32))
    }

    pub fn index_of(&self, ip: Ipv4Addr) -> Option<u64> {
        self.contains(ip).then(|| u64::from(u32::from(ip) - self.network))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_math() {
        let c = Cidr::parse("10.0.1.0/24").unwrap();
        assert_eq!(c.size(), 256);
        assert!(c.contains("10.0.1.77".parse().unwrap()));
        assert!(!c.contains("10.0.2.1".parse().unwrap()));
        assert_eq!(c.nth(5).to_string(), "10.0.1.5");
        assert!(Cidr::parse("10.0.1.1/24").is_none());
        assert!(c.overlaps(&Cidr::parse("10.0.0.0/16").unwrap()));
    }

    #[test]
    fn allocations_are_unique_and_in_pool() {
        let mut used = BTreeSet::new();
        for zone in [0, 1] {
            for _ in 0..50 {
                let ip = allocate_ipv4(zone, &used);
                assert!(used.insert(ip.clone()));
                let pool = if zone == 0 { "75.2." } else { "99.83." };
                assert!(ip.starts_with(pool), "{ip}");
            }
        }
        assert!(allocate_ipv6(0, &used).starts_with("2600:9000:a"));
    }
}
