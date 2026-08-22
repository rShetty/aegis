//! Client-IP resolution and trusted-proxy handling (#7).
//!
//! `source_ip` in `egress_log` must be the *real* client address, not a
//! constant. The rules are deliberately strict:
//!
//! - The direct socket peer (`ConnectInfo`) is always the ground truth.
//! - `X-Forwarded-For` is consulted **only** when the direct peer itself is a
//!   configured trusted proxy (`[server] trusted_proxies`). Any other caller
//!   can set that header freely, so honoring it would let anyone forge the
//!   audit trail's source_ip.
//! - Within a trusted chain, the client is the rightmost entry that is NOT a
//!   trusted proxy (standard XFF semantics). If every entry is trusted (or the
//!   header is absent/malformed), we fall back conservatively: leftmost entry
//!   when the chain parsed cleanly, otherwise the direct peer.

use std::net::IpAddr;

/// One allowlist entry: an exact IP or a CIDR range (`10.0.0.0/8`, `fd00::/8`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedProxy {
    Exact(IpAddr),
    Cidr(IpAddr, u8),
}

impl TrustedProxy {
    /// Parse an entry; `None` when it is neither a valid IP nor a valid CIDR
    /// (with a prefix length appropriate to the address family).
    pub fn parse(entry: &str) -> Option<Self> {
        let entry = entry.trim();
        if entry.is_empty() {
            return None;
        }
        if let Some((ip_part, len_part)) = entry.split_once('/') {
            let ip: IpAddr = ip_part.trim().parse().ok()?;
            let len: u8 = len_part.trim().parse().ok()?;
            let max_bits = match ip {
                IpAddr::V4(_) => 32u8,
                IpAddr::V6(_) => 128u8,
            };
            if len > max_bits {
                return None;
            }
            Some(TrustedProxy::Cidr(ip, len))
        } else {
            entry.parse::<IpAddr>().ok().map(TrustedProxy::Exact)
        }
    }

    /// Whether `ip` falls inside this entry.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match self {
            TrustedProxy::Exact(expected) => *expected == ip,
            TrustedProxy::Cidr(base, prefix) => match (base, ip) {
                (IpAddr::V4(b), IpAddr::V4(c)) => cidr_match(&b.octets(), &c.octets(), *prefix),
                (IpAddr::V6(b), IpAddr::V6(c)) => cidr_match(&b.octets(), &c.octets(), *prefix),
                _ => false, // family mismatch can never match
            },
        }
    }
}

/// Compare the leading `prefix` bits of two equal-length byte arrays.
fn cidr_match(base: &[u8], candidate: &[u8], prefix: u8) -> bool {
    debug_assert_eq!(base.len(), candidate.len());
    if prefix == 0 {
        return true;
    }
    let prefix = prefix as usize;
    if prefix > base.len() * 8 {
        return false;
    }
    let full_bytes = prefix / 8;
    let rem_bits = prefix % 8;
    if base[..full_bytes] != candidate[..full_bytes] {
        return false;
    }
    if rem_bits == 0 {
        return true;
    }
    let mask = !(u8::MAX >> rem_bits); // keep the top `rem_bits` bits
    (base[full_bytes] & mask) == (candidate[full_bytes] & mask)
}

/// The parsed `[server] trusted_proxies` allowlist.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies {
    entries: Vec<TrustedProxy>,
}

impl TrustedProxies {
    /// Build the allowlist from raw config strings. Invalid entries are
    /// skipped here; `Config::validate` rejects them loudly at startup, so in
    /// production this never silently drops anything an operator asked for.
    pub fn from_config(entries: &[String]) -> Self {
        TrustedProxies {
            entries: entries
                .iter()
                .filter_map(|e| TrustedProxy::parse(e))
                .collect(),
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.entries.iter().any(|e| e.contains(ip))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Resolve the true client IP for a request (#7).
///
/// `peer` is the direct socket peer; `forwarded_for` is the raw
/// `X-Forwarded-For` header value, if any. See the module docs for the trust
/// rules. Returns the IP as a string for direct storage in `egress_log`.
pub fn resolve_client_ip(
    peer: IpAddr,
    forwarded_for: Option<&str>,
    trusted: &TrustedProxies,
) -> String {
    // Only a trusted proxy may speak for someone else. Everyone else's
    // X-Forwarded-For is attacker-controlled noise.
    if !trusted.contains(peer) {
        return peer.to_string();
    }
    let Some(header) = forwarded_for else {
        return peer.to_string();
    };

    // Every entry must parse as a bare IP; anything else (obfuscated chains,
    // hostnames, injected garbage) makes the whole header untrustworthy.
    let Ok(chain) = header
        .split(',')
        .map(|part| part.trim().parse::<IpAddr>())
        .collect::<Result<Vec<IpAddr>, _>>()
    else {
        return peer.to_string();
    };
    if chain.is_empty() {
        return peer.to_string();
    }

    // Rightmost-to-leftmost: the client is the first hop that is NOT one of
    // our own trusted proxies.
    for ip in chain.iter().rev() {
        if !trusted.contains(*ip) {
            return ip.to_string();
        }
    }
    // Entire chain is trusted proxies (proxy-of-proxy deployment): the
    // leftmost entry is the original client as reported by the innermost
    // proxy.
    chain[0].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(entries: &[&str]) -> TrustedProxies {
        TrustedProxies {
            entries: entries
                .iter()
                .map(|e| TrustedProxy::parse(e).unwrap())
                .collect(),
        }
    }

    // ---------------- TrustedProxy parsing ----------------

    #[test]
    fn parse_accepts_ips_and_cidrs() {
        assert_eq!(
            TrustedProxy::parse("10.0.0.1"),
            Some(TrustedProxy::Exact("10.0.0.1".parse().unwrap()))
        );
        assert_eq!(
            TrustedProxy::parse("10.0.0.0/8"),
            Some(TrustedProxy::Cidr("10.0.0.0".parse().unwrap(), 8))
        );
        assert_eq!(
            TrustedProxy::parse("fd00::/8"),
            Some(TrustedProxy::Cidr("fd00::".parse().unwrap(), 8))
        );
        assert!(TrustedProxy::parse("").is_none());
        assert!(TrustedProxy::parse("not-an-ip").is_none());
        assert!(
            TrustedProxy::parse("10.0.0.0/33").is_none(),
            "v4 prefix too long"
        );
        assert!(
            TrustedProxy::parse("fd00::/129").is_none(),
            "v6 prefix too long"
        );
        assert!(TrustedProxy::parse("10.0.0.0/-1").is_none());
        assert!(TrustedProxy::parse("10.0.0.0/eight").is_none());
    }

    #[test]
    fn cidr_contains_respects_prefix_boundaries() {
        let range = TrustedProxy::parse("10.0.0.0/8").unwrap();
        assert!(range.contains("10.1.2.3".parse().unwrap()));
        assert!(range.contains("10.0.0.0".parse().unwrap()));
        assert!(!range.contains("11.0.0.0".parse().unwrap()));

        let slash31 = TrustedProxy::parse("192.168.1.4/31").unwrap();
        assert!(slash31.contains("192.168.1.4".parse().unwrap()));
        assert!(slash31.contains("192.168.1.5".parse().unwrap()));
        assert!(!slash31.contains("192.168.1.6".parse().unwrap()));

        let v6 = TrustedProxy::parse("fd00::/8").unwrap();
        assert!(v6.contains("fd12::1".parse().unwrap()));
        assert!(!v6.contains("fe80::1".parse().unwrap()));
        assert!(!v6.contains("10.0.0.1".parse().unwrap()), "family mismatch");

        // Host bits set in the base are masked out correctly.
        let sloppy = TrustedProxy::parse("10.1.2.3/24").unwrap();
        assert!(sloppy.contains("10.1.2.254".parse().unwrap()));
        assert!(!sloppy.contains("10.1.3.0".parse().unwrap()));

        // /0 matches everything in-family.
        let zero_v4 = TrustedProxy::parse("0.0.0.0/0").unwrap();
        assert!(zero_v4.contains("203.0.113.9".parse().unwrap()));
    }

    // ---------------- resolve_client_ip ----------------

    #[test]
    fn untrusted_peer_header_is_ignored() {
        let trusted = ips(&["10.0.0.9"]);
        // Direct client (no proxy in front) tries to forge a Google IP.
        assert_eq!(
            resolve_client_ip(
                "203.0.113.7".parse().unwrap(),
                Some("198.51.100.1"),
                &trusted
            ),
            "203.0.113.7",
            "peer is not a trusted proxy; its header must be ignored"
        );
    }

    #[test]
    fn trusted_proxy_forwarded_value_is_used() {
        let trusted = ips(&["127.0.0.1"]);
        assert_eq!(
            resolve_client_ip(
                "127.0.0.1".parse().unwrap(),
                Some("198.51.100.23"),
                &trusted
            ),
            "198.51.100.23"
        );
    }

    #[test]
    fn rightmost_untrusted_entry_wins_in_chains() {
        let trusted = ips(&["10.0.0.0/8"]);
        // outer LB (10.0.0.1) -> inner proxy (10.0.0.2) -> client
        assert_eq!(
            resolve_client_ip(
                "10.0.0.1".parse().unwrap(),
                Some("198.51.100.9, 10.0.0.2"),
                &trusted
            ),
            "198.51.100.9"
        );
        // Spoofed prefix prepended by the client is skipped past: the
        // rightmost non-trusted hop is the real edge.
        assert_eq!(
            resolve_client_ip(
                "10.0.0.1".parse().unwrap(),
                Some("1.2.3.4, 198.51.100.9, 10.0.0.2"),
                &trusted
            ),
            "198.51.100.9"
        );
    }

    #[test]
    fn fully_trusted_chain_falls_back_to_leftmost() {
        let trusted = ips(&["10.0.0.0/8"]);
        assert_eq!(
            resolve_client_ip(
                "10.0.0.1".parse().unwrap(),
                Some("10.0.0.2, 10.0.0.3"),
                &trusted
            ),
            "10.0.0.2"
        );
    }

    #[test]
    fn missing_or_malformed_header_falls_back_to_peer() {
        let trusted = ips(&["127.0.0.1"]);
        assert_eq!(
            resolve_client_ip("127.0.0.1".parse().unwrap(), None, &trusted),
            "127.0.0.1"
        );
        assert_eq!(
            resolve_client_ip("127.0.0.1".parse().unwrap(), Some(""), &trusted),
            "127.0.0.1"
        );
        // Garbage entry: refuse to guess from the header entirely.
        assert_eq!(
            resolve_client_ip(
                "127.0.0.1".parse().unwrap(),
                Some("not-an-ip, 198.51.100.9"),
                &trusted
            ),
            "127.0.0.1"
        );
        // Entry with a sneaky port suffix is not a bare IP: rejected whole.
        assert_eq!(
            resolve_client_ip(
                "127.0.0.1".parse().unwrap(),
                Some("198.51.100.9:8080"),
                &trusted
            ),
            "127.0.0.1"
        );
    }

    #[test]
    fn empty_allowlist_never_trusts_anyone() {
        let trusted = TrustedProxies::default();
        assert!(trusted.is_empty());
        assert_eq!(
            resolve_client_ip("127.0.0.1".parse().unwrap(), Some("8.8.8.8"), &trusted),
            "127.0.0.1"
        );
    }

    // ---------------- migration smoke for the module ----------------

    #[test]
    fn from_config_skips_invalid_entries() {
        let proxies =
            TrustedProxies::from_config(&["10.0.0.0/8".to_string(), "garbage".to_string()]);
        assert!(proxies.contains("10.20.30.40".parse().unwrap()));
        assert!(!proxies.contains("192.168.0.1".parse().unwrap()));
    }
}
