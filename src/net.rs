//! Transport policy: which Dokploy URLs may receive the API key.
//!
//! The API key travels in a request header, so plain HTTP is only acceptable
//! inside a private network. Even with `security.allow_http = true`, an `http://`
//! URL whose host is not private (by name or by address) is rejected.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::{Host, Url};

/// Hostnames that only exist inside private networks or the local machine.
const PRIVATE_SUFFIXES: [&str; 4] = [".internal", ".local", ".lan", ".home.arpa"];

/// True when `url` points to a host that is private by name or address.
pub fn is_private_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(name)) => {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            name == "localhost" || PRIVATE_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
        }
        Some(Host::Ipv4(ip)) => is_private_ipv4(ip),
        Some(Host::Ipv6(ip)) => is_private_ipv6(ip),
        None => false,
    }
}

/// True when an already-resolved address is private. Used by `doctor` to warn
/// when a private-looking name resolves to a public address.
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_private_ipv4(ip),
        IpAddr::V6(ip) => is_private_ipv6(ip),
    }
}

fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    ip.is_loopback()
        || ip.is_private() // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local() // 169.254/16
        || (a == 100 && (64..=127).contains(&b)) // 100.64/10: CGNAT, Tailscale
}

fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    ip.is_loopback()
        || (first & 0xfe00) == 0xfc00 // fc00::/7 unique local
        || (first & 0xffc0) == 0xfe80 // fe80::/10 link local
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private(url: &str) -> bool {
        is_private_host(&Url::parse(url).unwrap())
    }

    #[test]
    fn private_names_and_ranges_are_private() {
        for url in [
            "http://dokploy.acme.internal",
            "http://panel.local:3000",
            "http://localhost",
            "http://127.0.0.1",
            "http://10.0.0.5",
            "http://172.20.1.1",
            "http://192.168.1.10",
            "http://100.64.12.34",
            "http://[::1]",
            "http://[fd00::1]",
        ] {
            assert!(private(url), "{url} should be private");
        }
    }

    #[test]
    fn public_hosts_are_not_private() {
        for url in [
            "http://dokploy.example.com",
            "http://internal.example.com",
            "http://8.8.8.8",
            "http://172.32.0.1",
            "http://100.128.0.1",
            "http://[2001:db8::1]",
        ] {
            assert!(!private(url), "{url} should be public");
        }
    }
}
