use ipnet::IpNet;
use std::net::IpAddr;

pub fn trusted_peer(peer: IpAddr, ranges: &[IpNet]) -> bool {
    ranges.iter().any(|range| range.contains(&peer))
}

/// Walk from the observed peer toward the caller. Never trust the leftmost
/// address merely because an intervening proxy is trusted. Ambiguity fails closed.
pub fn forwarded_client(peer: IpAddr, chain: Option<&str>, ranges: &[IpNet]) -> IpAddr {
    if !trusted_peer(peer, ranges) {
        return peer;
    }
    let Some(chain) = chain.filter(|value| value.len() <= 4096) else {
        return peer;
    };
    let parsed: Result<Vec<IpAddr>, _> = chain.split(',').map(|v| v.trim().parse()).collect();
    let Ok(addresses) = parsed else { return peer };
    let mut current = peer;
    for address in addresses.into_iter().rev() {
        if !trusted_peer(current, ranges) {
            break;
        }
        current = address;
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chain_stops_at_untrusted_hop_and_rejects_malformed_input() {
        let peer = "192.0.2.5".parse().unwrap();
        let ranges = vec!["192.0.2.0/24".parse().unwrap()];
        assert_eq!(
            forwarded_client(peer, Some("203.0.113.9, 198.51.100.8"), &ranges),
            "198.51.100.8".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            forwarded_client(peer, Some("bad, 198.51.100.8"), &ranges),
            peer
        );
        assert_eq!(forwarded_client(peer, None, &ranges), peer);
        assert_eq!(forwarded_client(peer, Some("198.51.100.8"), &[]), peer);
    }
}
