//! Best-effort IPv4 → country (ISO-3166 alpha-2) lookup for peer rows.
//!
//! The UI shows a national flag before every peer address; this module is
//! the offline, no_std source for that mapping (an online geo API would be
//! slow, rate-limited and often unreachable from CN networks).
//!
//! Data: IP2Location LITE DB1 (CC-BY-SA 4.0, https://lite.ip2location.com),
//! aggregated to /16 granularity by address-coverage majority. The table is
//! sorted by prefix for binary search. Private / unallocated ranges map to
//! the empty code `[0, 0]` and render without a flag.
//!
//! **IPv6**: supported through an optional (start, end, country) range table
//! generated from IP2Location LITE DB11 (IPv6 edition) by
//! `tools/gen_geo_ipv6.py`. Until that data is generated, every IPv6 address
//! resolves to unknown — geolocation is never fabricated. Callers already
//! fall back to "no flag".
//!
//! Attribution (required by the CC-BY-SA 4.0 data license):
//!   This product includes IP2Location LITE data available from
//!   <https://lite.ip2location.com> under CC BY-SA 4.0.
//
// The generator spells country codes as `[b'X', b'Y']`, which trips
// `clippy::byte_char_slices` on every one of the ~56k entries; the generated
// module opts out (the suggested `*b"XY"` is byte-identical).
#[allow(clippy::byte_char_slices)]
mod geo_data {
    include!("geo_table.inc");
}

use geo_data::IPV4_COUNTRY;

// The (start, end, country) IPv6 range table, sorted by start for binary
// search. Empty until `tools/gen_geo_ipv6.py` is run against an IP2Location
// LITE DB11 CSV — see that script for the one-line invocation.
mod geo_ipv6_data {
    include!("geo_ipv6_table.inc");
}

use geo_ipv6_data::IPV6_COUNTRY;

/// Look up the ISO-3166 alpha-2 country code for an IPv4 address, or
/// `[0, 0]` when unknown (private / unallocated ranges).
pub fn ipv4_country(ip: [u8; 4]) -> [u8; 2] {
    let prefix = ((ip[0] as u16) << 8) | ip[1] as u16;
    match IPV4_COUNTRY.binary_search_by_key(&prefix, |e| e.0) {
        Ok(i) => IPV4_COUNTRY[i].1,
        Err(_) => [0, 0],
    }
}

/// Look up the ISO-3166 alpha-2 country code for an IPv6 address, or
/// `[0, 0]` when unknown (private / unallocated ranges, or the IPv6 table
/// has not been generated yet).
pub fn ipv6_country(ip: [u8; 16]) -> [u8; 2] {
    lookup_ipv6(IPV6_COUNTRY, ip)
}

/// Binary search over a sorted `(start, end, cc)` IPv6 range table.
/// `[u8; 16]` compares lexicographically, which for big-endian IPv6 bytes
/// is numeric order. Finds the last range with `start <= ip`, then checks
/// the inclusive `end`. O(log n), no allocation.
fn lookup_ipv6(table: &[([u8; 16], [u8; 16], [u8; 2])], ip: [u8; 16]) -> [u8; 2] {
    let mut lo = 0usize;
    let mut hi = table.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        if table[mid].0 <= ip {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo == 0 {
        return [0, 0];
    }

    let (_, end, cc) = table[lo - 1];
    if ip <= end {
        cc
    } else {
        [0, 0]
    }
}

/// The country code as a printable string ("" when unknown).
pub fn ipv4_country_str(ip: [u8; 4]) -> alloc::string::String {
    let c = ipv4_country(ip);
    if c == [0, 0] {
        alloc::string::String::new()
    } else {
        alloc::string::String::from_utf8_lossy(&c).into_owned()
    }
}

/// The country code as a printable string
pub fn ipv6_country_str(ip: [u8; 16]) -> alloc::string::String {
    let c = ipv6_country(ip);
    if c == [0, 0] {
        alloc::string::String::new()
    } else {
        alloc::string::String::from_utf8_lossy(&c).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_blocks_resolve() {
        // 1.3.x.x is CN in the IP2Location LITE DB1 data.
        assert_eq!(ipv4_country([1, 3, 0, 1]), *b"CN");
        assert_eq!(ipv4_country_str([1, 3, 0, 1]), "CN");
    }

    #[test]
    fn private_ranges_map_to_unknown() {
        assert_eq!(ipv4_country([10, 0, 0, 1]), [0, 0]);
        assert_eq!(ipv4_country([192, 168, 1, 1]), [0, 0]);
        assert_eq!(ipv4_country([127, 0, 0, 1]), [0, 0]);
        assert_eq!(ipv4_country([169, 254, 1, 1]), [0, 0]);
        assert_eq!(ipv4_country_str([10, 0, 0, 1]), "");
    }

    #[test]
    fn table_is_sorted_for_binary_search() {
        for w in IPV4_COUNTRY.windows(2) {
            assert!(w[0].0 < w[1].0, "prefixes must be strictly sorted");
        }
    }

    #[test]
    fn ipv6_lookup_algorithm() {
        // Mini table — TEST data only; the production table is generated
        // from IP2Location LITE DB11 by tools/gen_geo_ipv6.py. `ZZ` is a
        // reserved, never-allocated code (ISO-3166) so it cannot collide
        // with real data.
        let t: [([u8; 16], [u8; 16], [u8; 2]); 2] = [
            (
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                [
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
                ],
                *b"ZZ",
            ),
            (
                [0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                [
                    0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
                ],
                *b"US",
            ),
        ];
        // inside first range (start inclusive)
        assert_eq!(
            lookup_ipv6(
                &t,
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
            ),
            *b"ZZ"
        );
        // exact end boundary (end inclusive)
        assert_eq!(
            lookup_ipv6(
                &t,
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]
            ),
            *b"ZZ"
        );
        // inside second range
        assert_eq!(
            lookup_ipv6(
                &t,
                [0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            ),
            *b"US"
        );
        // gap between the two ranges
        assert_eq!(
            lookup_ipv6(
                &t,
                [0x20, 0x01, 0x0d, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            ),
            [0, 0]
        );
        // below the first range
        assert_eq!(
            lookup_ipv6(&t, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            [0, 0]
        );
        // above the last range
        assert_eq!(
            lookup_ipv6(
                &t,
                [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff
                ]
            ),
            [0, 0]
        );
        // empty table (data not generated yet)
        assert_eq!(
            lookup_ipv6(&[], [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            [0, 0]
        );
    }

    #[test]
    fn ipv6_is_unknown_until_a_dataset_exists() {
        // With the generated table absent, even public ranges resolve to
        // unknown — never a fabricated country.
        assert_eq!(
            ipv6_country([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            [0, 0]
        );
        assert_eq!(
            ipv6_country_str([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            ""
        );
    }
}
