//! Unified download-link parsing. [`parse_link`] turns every mainstream
//! URL format into a typed [`DownloadLink`]: magnet, eD2k, Xunlei, QQDL,
//! FlashGet, IPFS/IPNS, Kad, HTTP(S)/FTP, Baidu & Xunlei Netdisk (the two
//! Netdisks require host credentials). [`ContentId`] gives cross-format
//! content addressing so receipts can attest any source.

use crate::crypto::base32;
use crate::crypto::base58;
use crate::crypto::base64::{self, Variant};
use crate::crypto::{Md4, Sha1, Sha256};
use crate::error::{Error, Result};
use crate::magnet::Magnet;
use crate::platform::NetAddr;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

/// A cross-format content identity (digest family + expected size).
///
/// Used to verify bytes obtained from direct/eD2k sources and to anchor
/// provable-download receipts for non-BitTorrent transfers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentId {
    /// SHA-1 digest (20 bytes) and expected size.
    Sha1([u8; 20], u64),
    /// MD4 digest (16 bytes, eMule file hash) and expected size.
    Md4([u8; 16], u64),
    /// SHA-256 digest (32 bytes) and expected size.
    Sha256([u8; 32], u64),
}

impl ContentId {
    /// Human-readable family name.
    pub fn family(&self) -> &'static str {
        match self {
            ContentId::Sha1(..) => "sha1",
            ContentId::Md4(..) => "md4",
            ContentId::Sha256(..) => "sha256",
        }
    }

    /// Expected content size in bytes.
    pub fn size(&self) -> u64 {
        match self {
            ContentId::Sha1(_, s) | ContentId::Md4(_, s) | ContentId::Sha256(_, s) => *s,
        }
    }

    /// The raw digest bytes.
    pub fn digest(&self) -> &[u8] {
        match self {
            ContentId::Sha1(d, _) => d,
            ContentId::Md4(d, _) => d,
            ContentId::Sha256(d, _) => d,
        }
    }

    /// Verify `data` against this identity (digest + size).
    pub fn verify(&self, data: &[u8]) -> bool {
        if data.len() as u64 != self.size() {
            return false;
        }
        match self {
            ContentId::Sha1(d, _) => &Sha1::digest(data) == d,
            ContentId::Md4(d, _) => &Md4::digest(data) == d,
            ContentId::Sha256(d, _) => &Sha256::digest(data) == d,
        }
    }

    /// Compute the identity of `data` in the given family.
    pub fn digest_of(family: ContentFamily, data: &[u8]) -> ContentId {
        let size = data.len() as u64;
        match family {
            ContentFamily::Sha1 => ContentId::Sha1(Sha1::digest(data), size),
            ContentFamily::Md4 => ContentId::Md4(Md4::digest(data), size),
            ContentFamily::Sha256 => ContentId::Sha256(Sha256::digest(data), size),
        }
    }

    /// 32-byte receipt anchor (digest left-aligned, zero-padded).
    pub fn to_root(&self) -> [u8; 32] {
        let mut root = [0u8; 32];
        let d = self.digest();
        root[..d.len()].copy_from_slice(d);
        root
    }
}

/// Hash family selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentFamily {
    /// SHA-1.
    Sha1,
    /// MD4 (eMule).
    Md4,
    /// SHA-256.
    Sha256,
}

/// A direct HTTP(S)/FTP source, optionally content-addressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlSource {
    /// The URL to fetch.
    pub url: String,
    /// Optional expected identity (verified after download).
    pub expected: Option<ContentId>,
}

/// An eD2k (eMule) file description from `ed2k://|file|…|/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed2kFile {
    /// File name.
    pub name: String,
    /// File size in bytes.
    pub size: u64,
    /// MD4 content hash (16 bytes).
    pub hash: [u8; 16],
    /// Optional AICH root hash (SHA-1, 20 bytes; `|h=`).
    pub aich: Option<[u8; 20]>,
    /// Optional eD2k server endpoints (`|s=host:port`).
    pub servers: Vec<String>,
}

impl Ed2kFile {
    /// This file as a content identity (MD4 + size).
    pub fn as_content_id(&self) -> ContentId {
        ContentId::Md4(self.hash, self.size)
    }
}

/// A Baidu Netdisk share link.
///
/// Baidu does not allow anonymous downloads; the host must inject an
/// authenticated HTTP client (cookies) to fetch the actual file. The core
/// models the link so UIs and bridges can display and queue it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaiduPanLink {
    /// The original share URL.
    pub url: String,
    /// Share code from `/s/<code>` (new-style shares).
    pub share_code: Option<String>,
    /// Extraction code (`pwd`/`提取码`), if any.
    pub extract_code: Option<String>,
}

/// A Xunlei Netdisk share link (`pan.xunlei.com`).
///
/// Like Baidu, Xunlei Netdisk requires an authenticated host session; the
/// core models the link for display/queuing and leaves fetching to a host
/// with credentials injected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XunleiPanLink {
    /// The original share URL.
    pub url: String,
    /// Share code from `/s/<code>` (new-style shares).
    pub share_code: Option<String>,
    /// Extraction code, if any.
    pub extract_code: Option<String>,
}

/// An eMule Kademlia node link (`kad://`).
///
/// The id part is hex or base32; an optional `@host:port` / `|host:port`
/// suffix carries a node endpoint. Only numeric endpoints are resolved
/// (the core has no DNS); host-name endpoints are rejected rather than
/// silently dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KadLink {
    /// Decoded node id (eMule Kad uses 16 bytes; up to 20 accepted).
    pub node_id: Vec<u8>,
    /// Optional numeric endpoint.
    pub addr: Option<NetAddr>,
}

/// An IPFS content link (`ipfs://`) or IPNS name (`ipns://`).
///
/// Supports CIDv0 (`Qm…`, base58, SHA-256) and CIDv1 (multibase `b`/`B`
/// base32 or `z` base58, varint version/codec/multihash). IPNS names are
/// not content-addressed — they must be resolved (e.g. via a gateway or
/// the IPFS DHT) before verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpfsLink {
    /// The CID string (without scheme/prefix).
    pub cid: String,
    /// CID version (0 or 1).
    pub version: u8,
    /// CIDv1 codec varint (0x70 = dag-pb, 0x55 = raw, 0x01 = cbor, …).
    pub codec: u64,
    /// Multihash function code (0x12 = sha2-256, 0x00 = identity, …).
    pub mh_code: u64,
    /// Raw multihash digest bytes.
    pub digest: Vec<u8>,
    /// Optional sub-path after the CID (`/ipfs/<cid>/docs/x.md`).
    pub sub_path: Option<String>,
    /// True when this is an IPNS name (must be resolved first).
    pub is_ipns: bool,
}

impl IpfsLink {
    /// Build a gateway URL for this content (`{gateway}/ipfs/<cid>[path]`
    /// or `…/ipns/<name>[path]`).
    pub fn gateway_url(&self, gateway: &str) -> String {
        let ns = if self.is_ipns { "ipns" } else { "ipfs" };
        let mut u = format!("{gateway}/{ns}/{}", self.cid);
        if let Some(p) = &self.sub_path {
            u.push('/');
            u.push_str(p);
        }
        u
    }
}

/// Every download format the core understands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadLink {
    /// BitTorrent magnet (BEP-9).
    BitTorrent(Magnet),
    /// eMule/eD2k file.
    Ed2k(Ed2kFile),
    /// Plain HTTP(S)/FTP direct link.
    Url(UrlSource),
    /// Xunlei `thunder://` (Base64-wrapped URL).
    Thunder(UrlSource),
    /// QQ Xuanfeng `qqdl://` (Base64 URL).
    Qqdl(UrlSource),
    /// FlashGet `flashget://`.
    Flashget(UrlSource),
    /// Baidu Netdisk share (needs host credentials).
    BaiduPan(BaiduPanLink),
    /// Xunlei Netdisk share (needs host credentials).
    XunleiPan(XunleiPanLink),
    /// eMule Kademlia node.
    Kad(KadLink),
    /// IPFS content (CID) or IPNS name.
    Ipfs(IpfsLink),
}

impl DownloadLink {
    /// Parse any supported URI.
    pub fn parse(uri: &str) -> Result<DownloadLink> {
        parse_link(uri)
    }

    /// A human-readable type tag.
    pub fn kind(&self) -> &'static str {
        match self {
            DownloadLink::BitTorrent(_) => "bittorrent",
            DownloadLink::Ed2k(_) => "ed2k",
            DownloadLink::Url(_) => "url",
            DownloadLink::Thunder(_) => "thunder",
            DownloadLink::Qqdl(_) => "qqdl",
            DownloadLink::Flashget(_) => "flashget",
            DownloadLink::BaiduPan(_) => "baidupan",
            DownloadLink::XunleiPan(_) => "xunleipan",
            DownloadLink::Kad(_) => "kad",
            DownloadLink::Ipfs(_) => "ipfs",
        }
    }

    /// Content identity for non-BitTorrent sources (if known).
    pub fn content_id(&self) -> Option<ContentId> {
        match self {
            DownloadLink::Ed2k(f) => Some(f.as_content_id()),
            DownloadLink::Url(u)
            | DownloadLink::Thunder(u)
            | DownloadLink::Qqdl(u)
            | DownloadLink::Flashget(u) => u.expected,
            _ => None,
        }
    }
}

/// Parse a unified download link.
pub fn parse_link(uri: &str) -> Result<DownloadLink> {
    let (scheme, rest) = scheme_of(uri).ok_or(Error::InvalidInput)?;
    let rest = rest.trim_start_matches('/');
    match scheme {
        "magnet" => Ok(DownloadLink::BitTorrent(Magnet::parse(uri)?)),
        "ed2k" => parse_ed2k(rest).map(DownloadLink::Ed2k),
        "thunder" => parse_thunder(rest).map(DownloadLink::Thunder),
        "qqdl" => parse_wrapped_base64(rest, false).map(DownloadLink::Qqdl),
        "flashget" => parse_flashget(rest).map(DownloadLink::Flashget),
        "kad" => parse_kad(rest).map(DownloadLink::Kad),
        "ipfs" => parse_ipfs(rest, false).map(DownloadLink::Ipfs),
        "ipns" => parse_ipfs(rest, true).map(DownloadLink::Ipfs),
        "http" | "https" => {
            let host = url_host(uri);
            if host.is_some_and(is_baidu_host) {
                let (u, s, e) = parse_pan_link(uri);
                Ok(DownloadLink::BaiduPan(BaiduPanLink {
                    url: u,
                    share_code: s,
                    extract_code: e,
                }))
            } else if host.is_some_and(is_xunlei_pan_host) {
                let (u, s, e) = parse_pan_link(uri);
                Ok(DownloadLink::XunleiPan(XunleiPanLink {
                    url: u,
                    share_code: s,
                    extract_code: e,
                }))
            } else {
                Ok(DownloadLink::Url(UrlSource {
                    url: uri.to_string(),
                    expected: None,
                }))
            }
        }
        "ftp" => Ok(DownloadLink::Url(UrlSource {
            url: uri.to_string(),
            expected: None,
        })),
        _ => Err(Error::InvalidInput),
    }
}

/// Split `scheme:` (ASCII case-insensitive) from the rest.
fn scheme_of(uri: &str) -> Option<(&str, &str)> {
    let colon = uri.find(':')?;
    let scheme = &uri[..colon];
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return None;
    }
    Some((scheme, &uri[colon + 1..]))
}

/// Parse `ed2k://|file|<name>|<size>|<md4>|/…`.
fn parse_ed2k(rest: &str) -> Result<Ed2kFile> {
    let parts: Vec<&str> = rest.split('|').collect();
    // parts[0] is empty because the URI starts with `|`.
    if parts.len() < 5 || parts.get(1).copied() != Some("file") {
        return Err(Error::InvalidInput);
    }
    let name = parts[2];
    let size: u64 = parts[3].parse().map_err(|_| Error::InvalidInput)?;
    let hash = hex_to_16(parts[4]).ok_or(Error::InvalidInput)?;
    let mut aich = None;
    let mut servers = Vec::new();
    // trailing segments: `|/`, `|h=<hex>`, `|s=<host:port>`
    for seg in &parts[5..] {
        if seg.is_empty() || *seg == "/" {
            continue;
        }
        if let Some(h) = seg.strip_prefix("h=") {
            if h.len() == 40 {
                if let Some(d) = hex_to_n::<20>(h) {
                    aich = Some(d);
                }
            }
        } else if let Some(s) = seg.strip_prefix("s=") {
            if !s.is_empty() {
                servers.push(String::from(s));
            }
        }
    }
    Ok(Ed2kFile {
        name: String::from(name),
        size,
        hash,
        aich,
        servers,
    })
}

/// Parse `thunder://<base64>` → `AA<url>ZZ`.
fn parse_thunder(rest: &str) -> Result<UrlSource> {
    let raw = base64::decode(rest, Variant::Standard).ok_or(Error::InvalidInput)?;
    let s = String::from_utf8_lossy(&raw).into_owned();
    let inner = if s.starts_with("AA") && s.ends_with("ZZ") && s.len() >= 4 {
        &s[2..s.len() - 2]
    } else {
        s.as_str()
    };
    if inner.is_empty() {
        return Err(Error::InvalidInput);
    }
    Ok(UrlSource {
        url: String::from(inner),
        expected: None,
    })
}

/// Parse `qqdl://<base64>` (URL directly Base64-encoded, no wrapper) or, when
/// `unwrap_aa_zz` is set, also strip an `AA…ZZ` wrapper (FlashGet legacy).
fn parse_wrapped_base64(rest: &str, unwrap_aa_zz: bool) -> Result<UrlSource> {
    let raw = base64::decode(rest, Variant::Standard).ok_or(Error::InvalidInput)?;
    let s = String::from_utf8_lossy(&raw).into_owned();
    let inner = if unwrap_aa_zz && s.starts_with("AA") && s.ends_with("ZZ") && s.len() >= 4 {
        &s[2..s.len() - 2]
    } else {
        s.as_str()
    };
    if inner.is_empty() {
        return Err(Error::InvalidInput);
    }
    Ok(UrlSource {
        url: String::from(inner),
        expected: None,
    })
}

/// Parse `flashget://[FLASHGET]<base64>[/FLASHGET]`.
fn parse_flashget(rest: &str) -> Result<UrlSource> {
    let mut b64 = rest;
    if let Some(stripped) = rest.strip_prefix("[FLASHGET]") {
        b64 = stripped;
    }
    if let Some(stripped) = b64.strip_suffix("[/FLASHGET]") {
        b64 = stripped;
    }
    parse_wrapped_base64(b64, true)
}

fn is_baidu_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("pan.baidu.com")
        || host.eq_ignore_ascii_case("xpan.baidu.com")
        || host.eq_ignore_ascii_case("yun.baidu.com")
        || host.ends_with(".pan.baidu.com")
}

fn is_xunlei_pan_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("pan.xunlei.com")
        || host.eq_ignore_ascii_case("xlpan.com")
        || host.eq_ignore_ascii_case("pan.xunlei.net")
        || host.ends_with(".pan.xunlei.com")
}

/// Extract the host portion of a URL (`scheme://host[:port][/…]`).
fn url_host(url: &str) -> Option<&str> {
    let after = url.find("://")? + 3;
    let rest = &url[after..];
    let end = rest
        .find(|c| ['/', '?', '#'].contains(&c))
        .unwrap_or(rest.len());
    let hostport = &rest[..end];
    // strip :port
    let host = hostport.split(':').next().unwrap_or(hostport);
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Parse a share URL into `(url, share_code, extract_code)`.
fn parse_pan_link(url: &str) -> (String, Option<String>, Option<String>) {
    let share_code = url
        .split("/s/")
        .nth(1)
        .map(|rest| {
            let code = rest
                .split(['/', '?'])
                .next()
                .unwrap_or("")
                .trim_end_matches('/');
            String::from(code)
        })
        .filter(|c| !c.is_empty());
    let extract_code = query_param(url, "pwd")
        .or_else(|| query_param(url, "提取码"))
        .or_else(|| query_param(url, "extract"));
    (String::from(url), share_code, extract_code)
}

/// Parse `kad://<id>[@host:port | |host:port]`.
fn parse_kad(rest: &str) -> Result<KadLink> {
    let (id_part, addr_part) = if let Some((l, r)) = rest.split_once('@') {
        (l, Some(r))
    } else if let Some((l, r)) = rest.split_once('|') {
        (l, Some(r))
    } else {
        (rest, None)
    };
    let id_part = id_part.trim();
    let node_id = if !id_part.is_empty()
        && id_part.len() % 2 == 0
        && id_part.bytes().all(|b| b.is_ascii_hexdigit())
    {
        hex_to_bytes(id_part).ok_or(Error::InvalidInput)?
    } else {
        base32::decode(id_part).ok_or(Error::InvalidInput)?
    };
    if node_id.is_empty() || node_id.len() > 20 {
        return Err(Error::InvalidInput);
    }
    let addr = match addr_part {
        Some(hp) => parse_host_port(hp.trim())?,
        None => None,
    };
    Ok(KadLink { node_id, addr })
}

/// Parse a `host:port` / `[ipv6]:port` endpoint into a [`NetAddr`].
/// Host names are rejected (no DNS in the core); returns `Ok(None)` for an
/// empty string.
fn parse_host_port(hp: &str) -> Result<Option<NetAddr>> {
    if hp.is_empty() {
        return Ok(None);
    }
    if let Some(inner) = hp.strip_prefix('[') {
        // [ipv6]:port
        let end = inner.find(']').ok_or(Error::InvalidInput)?;
        let host = &inner[..end];
        let rest = &inner[end + 1..];
        let port = rest
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .ok_or(Error::InvalidInput)?;
        let mut bytes = [0u8; 16];
        if parse_ipv6(host, &mut bytes) {
            return Ok(Some(NetAddr::V6(bytes, port)));
        }
        return Err(Error::InvalidInput);
    }
    let (host, port) = hp.rsplit_once(':').ok_or(Error::InvalidInput)?;
    let port: u16 = port.parse().map_err(|_| Error::InvalidInput)?;
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() == 4 {
        let mut o = [0u8; 4];
        for (i, part) in parts.iter().enumerate() {
            let n: u8 = part.parse().map_err(|_| Error::InvalidInput)?;
            o[i] = n;
        }
        return Ok(Some(NetAddr::V4(o, port)));
    }
    Err(Error::InvalidInput) // host name without DNS support
}

/// Parse an IPv6 address into 16 bytes (full or `::`-compressed groups).
fn parse_ipv6(s: &str, out: &mut [u8; 16]) -> bool {
    let mut groups: Vec<u16> = Vec::new();
    if let Some((l, r)) = s.split_once("::") {
        for g in l.split(':').filter(|x| !x.is_empty()) {
            match u16::from_str_radix(g, 16) {
                Ok(v) => groups.push(v),
                Err(_) => return false,
            }
        }
        while groups.len() < 8 - r.split(':').filter(|x| !x.is_empty()).count() {
            groups.push(0);
        }
        for g in r.split(':').filter(|x| !x.is_empty()) {
            match u16::from_str_radix(g, 16) {
                Ok(v) => groups.push(v),
                Err(_) => return false,
            }
        }
    } else {
        for g in s.split(':') {
            match u16::from_str_radix(g, 16) {
                Ok(v) => groups.push(v),
                Err(_) => return false,
            }
        }
    }
    if groups.len() != 8 {
        return false;
    }
    for (i, g) in groups.iter().enumerate() {
        out[i * 2] = (g >> 8) as u8;
        out[i * 2 + 1] = *g as u8;
    }
    true
}

/// Parse `ipfs://` / `ipns://` payloads.
fn parse_ipfs(rest: &str, is_ipns: bool) -> Result<IpfsLink> {
    let mut cid_part = rest;
    if !is_ipns {
        if let Some(p) = rest.strip_prefix("ipfs/") {
            cid_part = p;
        }
    } else if let Some(p) = rest.strip_prefix("ipns/") {
        cid_part = p;
    }
    let sub_path = match cid_part.split_once('/') {
        Some((c, sp)) => {
            cid_part = c;
            Some(String::from(sp))
        }
        None => None,
    };
    let (version, codec, mh_code, digest) = match parse_cid(cid_part) {
        Some(v) => v,
        // IPNS names may also be DNSLink domains (not CIDs).
        None if is_ipns && is_valid_ipns_name(cid_part) => (0, 0, 0, Vec::new()),
        None => return Err(Error::InvalidInput),
    };
    Ok(IpfsLink {
        cid: String::from(cid_part),
        version,
        codec,
        mh_code,
        digest,
        sub_path,
        is_ipns,
    })
}

/// Decode a CID string into `(version, codec, mh_code, digest)`.
fn parse_cid(cid: &str) -> Option<(u8, u64, u64, Vec<u8>)> {
    // CIDv0: base58 `Qm…` = 0x12 0x20 + 32-byte SHA-256.
    if cid.starts_with("Qm") {
        let bytes = base58::decode(cid)?;
        if bytes.len() == 34 && bytes[0] == 0x12 && bytes[1] == 0x20 {
            return Some((0, 0x70, 0x12, bytes[2..].to_vec()));
        }
        return None;
    }
    // CIDv1: multibase prefix.
    let b = cid.as_bytes();
    if b.is_empty() {
        return None;
    }
    let bytes = match b[0] {
        b'b' | b'B' => base32::decode(&cid[1..])?,
        b'z' => base58::decode(&cid[1..])?,
        _ => return None, // base36 (`k`) and others unsupported
    };
    let mut pos = 0usize;
    let (version, n1) = read_varint(&bytes, pos)?;
    pos += n1;
    let (codec, n2) = read_varint(&bytes, pos)?;
    pos += n2;
    if version != 1 {
        return None;
    }
    let (mh_code, n3) = read_varint(&bytes, pos)?;
    pos += n3;
    let (mh_len, n4) = read_varint(&bytes, pos)?;
    pos += n4;
    let digest = bytes.get(pos..pos + mh_len as usize)?.to_vec();
    Some((1, codec, mh_code, digest))
}

/// Read a LEB128 varint at `start`; returns `(value, bytes_consumed)`.
fn read_varint(b: &[u8], start: usize) -> Option<(u64, usize)> {
    let mut val: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in b.iter().enumerate().skip(start) {
        if i - start >= 10 {
            return None;
        }
        val |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((val, i + 1 - start));
        }
        shift += 7;
    }
    None
}

/// A conservative DNSLink / IPNS-name sanity check (no path separators,
/// spaces or control bytes; 1..=253 chars).
fn is_valid_ipns_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..b.len()).step_by(2) {
        out.push((hexval(b[i])? << 4) | hexval(b[i + 1])?);
    }
    Some(out)
}

/// Read a query parameter (percent-decoded) from a URL.
fn query_param(url: &str, key: &str) -> Option<String> {
    let q = url.find('?')?;
    for part in url[q + 1..].split('&') {
        let (k, v) = part.split_once('=')?;
        if k == key {
            let dec = crate::magnet::percent_decode(v);
            return Some(String::from_utf8_lossy(&dec).into_owned());
        }
    }
    None
}

fn hex_to_16(s: &str) -> Option<[u8; 16]> {
    hex_to_n::<16>(s)
}

fn hex_to_n<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let b = s.as_bytes();
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = (hexval(b[i * 2])? << 4) | hexval(b[i * 2 + 1])?;
    }
    Some(out)
}

fn hexval(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magnet_link() {
        let l = parse_link("magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=x")
            .unwrap();
        assert_eq!(l.kind(), "bittorrent");
        assert!(matches!(l, DownloadLink::BitTorrent(_)));
    }

    #[test]
    fn ed2k_single_file() {
        // MD4("abc") = a448017aaf21d8525fc10ae87aa6729d
        let l = parse_link("ed2k://|file|hello.bin|3|a448017aaf21d8525fc10ae87aa6729d|/").unwrap();
        match l {
            DownloadLink::Ed2k(f) => {
                assert_eq!(f.name, "hello.bin");
                assert_eq!(f.size, 3);
                assert_eq!(f.hash, Md4::digest(b"abc"));
                assert_eq!(f.servers.len(), 0);
            }
            other => panic!("expected ed2k, got {other:?}"),
        }
    }

    #[test]
    fn ed2k_with_servers_and_aich() {
        let l = parse_link(
            "ed2k://|file|movie.mkv|1024|0123456789abcdef0123456789abcdef|/|s=ed2k.example.com:4661|s=backup.example.net:4662|/",
        )
        .unwrap();
        match l {
            DownloadLink::Ed2k(f) => {
                assert_eq!(f.servers.len(), 2);
                assert_eq!(f.servers[0], "ed2k.example.com:4661");
                assert!(f.aich.is_none());
            }
            other => panic!("expected ed2k, got {other:?}"),
        }
    }

    #[test]
    fn ed2k_rejects_bad_hash() {
        assert!(parse_link("ed2k://|file|a|1|xyz|/").is_err());
        assert!(parse_link("ed2k://|file|a|nope|0123456789abcdef0123456789abcdef|/").is_err());
    }

    #[test]
    fn thunder_unwraps_aa_zz() {
        // base64("AAhttp://example.com/f.rarZZ")
        let l = parse_link("thunder://QUFodHRwOi8vZXhhbXBsZS5jb20vZi5yYXJaWg==").unwrap();
        match l {
            DownloadLink::Thunder(u) => assert_eq!(u.url, "http://example.com/f.rar"),
            other => panic!("expected thunder, got {other:?}"),
        }
    }

    #[test]
    fn qqdl_direct() {
        // base64("http://example.com/f.rar")
        let l = parse_link("qqdl://aHR0cDovL2V4YW1wbGUuY29tL2YucmFy").unwrap();
        match l {
            DownloadLink::Qqdl(u) => assert_eq!(u.url, "http://example.com/f.rar"),
            other => panic!("expected qqdl, got {other:?}"),
        }
    }

    #[test]
    fn flashget_tagged() {
        // base64("AAhttp://example.com/f.rarZZ")
        let l =
            parse_link("flashget://[FLASHGET]QUFodHRwOi8vZXhhbXBsZS5jb20vZi5yYXJaWg==[/FLASHGET]")
                .unwrap();
        match l {
            DownloadLink::Flashget(u) => assert_eq!(u.url, "http://example.com/f.rar"),
            other => panic!("expected flashget, got {other:?}"),
        }
    }

    #[test]
    fn direct_http_and_ftp() {
        let l = parse_link("https://cdn.example.com/a.bin").unwrap();
        match l {
            DownloadLink::Url(u) => assert_eq!(u.url, "https://cdn.example.com/a.bin"),
            other => panic!("expected url, got {other:?}"),
        }
        assert!(matches!(
            parse_link("ftp://mirror.example.com/x.iso").unwrap(),
            DownloadLink::Url(_)
        ));
    }

    #[test]
    fn baidu_share() {
        let l = parse_link("https://pan.baidu.com/s/1abcDEF123?pwd=uvw4").unwrap();
        match l {
            DownloadLink::BaiduPan(b) => {
                assert_eq!(b.share_code.as_deref(), Some("1abcDEF123"));
                assert_eq!(b.extract_code.as_deref(), Some("uvw4"));
            }
            other => panic!("expected baidupan, got {other:?}"),
        }
    }

    #[test]
    fn unknown_scheme_rejected() {
        assert!(parse_link("gopher://example.com").is_err());
        assert!(parse_link("not a uri").is_err());
    }

    #[test]
    fn content_id_verify() {
        let data = b"the quick brown fox";
        let id = ContentId::digest_of(ContentFamily::Sha256, data);
        assert!(id.verify(data));
        assert!(!id.verify(b"tampered"));
        // size mismatch
        let id2 = ContentId::Sha256([0u8; 32], data.len() as u64 + 1);
        assert!(!id2.verify(data));
        // root is left-aligned 32 bytes
        let root = id.to_root();
        assert_eq!(&root[..32], id.digest());
    }

    #[test]
    fn ed2k_content_id() {
        let f = Ed2kFile {
            name: String::from("abc"),
            size: 3,
            hash: Md4::digest(b"abc"),
            aich: None,
            servers: Vec::new(),
        };
        assert!(f.as_content_id().verify(b"abc"));
    }

    #[test]
    fn kad_hex_id_and_endpoint() {
        let l = parse_link("kad://00112233445566778899aabbccddeeff").unwrap();
        match l {
            DownloadLink::Kad(k) => {
                assert_eq!(k.node_id.len(), 16);
                assert_eq!(k.node_id[0], 0x00);
                assert_eq!(k.node_id[15], 0xff);
                assert!(k.addr.is_none());
            }
            other => panic!("expected kad, got {other:?}"),
        }
        let l = parse_link("kad://00112233445566778899aabbccddeeff@127.0.0.1:4661").unwrap();
        match l {
            DownloadLink::Kad(k) => match k.addr {
                Some(NetAddr::V4(ip, port)) => {
                    assert_eq!(ip, [127, 0, 0, 1]);
                    assert_eq!(port, 4661);
                }
                other => panic!("expected v4 addr, got {other:?}"),
            },
            other => panic!("expected kad, got {other:?}"),
        }
    }

    #[test]
    fn kad_base32_id() {
        let id = [0xABu8; 16];
        let b32 = crate::crypto::base32_encode(&id);
        let l = parse_link(&format!("kad://{b32}|10.0.0.9:6881")).unwrap();
        match l {
            DownloadLink::Kad(k) => {
                assert_eq!(k.node_id, id);
                assert_eq!(k.addr, Some(NetAddr::V4([10, 0, 0, 9], 6881)));
            }
            other => panic!("expected kad, got {other:?}"),
        }
    }

    #[test]
    fn ipfs_cidv0() {
        // Construct CIDv0: base58(0x12 0x20 + 32 bytes).
        let mut mh = vec![0x12u8, 0x20];
        mh.extend_from_slice(&[7u8; 32]);
        let cid = crate::crypto::base58_encode(&mh);
        assert!(cid.starts_with("Qm"));
        let l = parse_link(&format!("ipfs://{cid}")).unwrap();
        match l {
            DownloadLink::Ipfs(i) => {
                assert_eq!(i.version, 0);
                assert_eq!(i.mh_code, 0x12);
                assert_eq!(i.digest, vec![7u8; 32]);
                assert!(!i.is_ipns);
                // gateway URL builds correctly
                let gu = i.gateway_url("https://ipfs.io");
                assert!(gu.starts_with("https://ipfs.io/ipfs/"));
            }
            other => panic!("expected ipfs, got {other:?}"),
        }
    }

    #[test]
    fn ipfs_cidv1_base32() {
        // CIDv1: version=1, codec=0x70 (dag-pb), multihash sha2-256.
        let mut bytes = vec![1u8, 0x70, 0x12, 0x20];
        bytes.extend_from_slice(&[9u8; 32]);
        let cid = format!("b{}", crate::crypto::base32_encode(&bytes));
        let l = parse_link(&format!("ipfs://{cid}/docs/x.md")).unwrap();
        match l {
            DownloadLink::Ipfs(i) => {
                assert_eq!(i.version, 1);
                assert_eq!(i.codec, 0x70);
                assert_eq!(i.mh_code, 0x12);
                assert_eq!(i.digest, vec![9u8; 32]);
                assert_eq!(i.sub_path.as_deref(), Some("docs/x.md"));
            }
            other => panic!("expected ipfs, got {other:?}"),
        }
    }

    #[test]
    fn ipns_parsed() {
        let l = parse_link("ipns://docs.ipfs.tech/").unwrap();
        match l {
            DownloadLink::Ipfs(i) => assert!(i.is_ipns),
            other => panic!("expected ipfs, got {other:?}"),
        }
    }

    #[test]
    fn xunlei_pan() {
        let l = parse_link("https://pan.xunlei.com/s/AbCdEfGh?pwd=1234").unwrap();
        match l {
            DownloadLink::XunleiPan(p) => {
                assert_eq!(p.share_code.as_deref(), Some("AbCdEfGh"));
                assert_eq!(p.extract_code.as_deref(), Some("1234"));
            }
            other => panic!("expected xunleipan, got {other:?}"),
        }
    }

    #[test]
    fn ipfs_rejects_garbage() {
        assert!(parse_link("ipfs://QmNOTVALID").is_err());
        assert!(parse_link("kad://zz").is_err()); // bad hex/base32 id
    }
}
