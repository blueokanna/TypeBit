//! Port mapping for the listen port: **NAT-PMP (RFC 6886)** with **UPnP IGD**
//! (SSDP discovery + SOAP control) fallback. Allocation-bounded codecs plus
//! a time-driven state machine pumped once per tick; transport via the
//! [`Host`] seam. NAT-PMP needs no HTTP; UPnP needs
//! [`Host::http_post`]/[`Host::local_ip`] (a platform may leave them
//! unsupported → clear failure, not guessing). Replies arrive as unicast
//! UDP on the engine socket, routed here by [`PortMapManager::handle_datagram`].

use crate::error::{Error, Result};
use crate::platform::{Host, NetAddr};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// NAT-PMP (RFC 6886) well-known port.
pub const NAT_PMP_PORT: u16 = 5351;
/// SSDP multicast group for UPnP device discovery.
pub const SSDP_ADDR: NetAddr = NetAddr::V4([239, 255, 255, 250], 1900);
/// NAT-PMP protocol version (RFC 6886 §1.1).
const NAT_PMP_VERSION: u8 = 0;
/// NAT-PMP opcode: request the gateway's public address.
pub const NAT_PMP_PUBLIC_ADDR: u8 = 0;
/// NAT-PMP opcode: add/update a UDP mapping.
pub const NAT_PMP_MAP_UDP: u8 = 1;
/// NAT-PMP opcode: add/update a TCP mapping.
pub const NAT_PMP_MAP_TCP: u8 = 2;
/// NAT-PMP result code: success.
pub const NAT_PMP_OK: u16 = 0;
/// NAT-PMP result code: the device does not support NAT-PMP.
pub const NAT_PMP_UNSUPPORTED: u16 = 1;
/// Upper bound on accepted SSDP / XML / SOAP payloads (hostile-input bound).
const MAX_SSDP_SIZE: usize = 16 * 1024;
const MAX_XML_SCAN: usize = 256 * 1024;

// ---------------------------------------------------------------------------
// NAT-PMP codec (RFC 6886)
// ---------------------------------------------------------------------------

/// A NAT-PMP request (12 bytes on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatPmpRequest {
    /// Opcode: [`NAT_PMP_PUBLIC_ADDR`], [`NAT_PMP_MAP_UDP`], [`NAT_PMP_MAP_TCP`].
    pub opcode: u8,
    /// Internal port (mapping opcodes only).
    pub internal_port: u16,
    /// Requested external port (0 = gateway-chosen).
    pub external_port: u16,
    /// Lease lifetime in seconds (0 = delete).
    pub lifetime_sec: u32,
}

impl NatPmpRequest {
    /// Request the gateway's public address.
    pub fn public_addr() -> Self {
        NatPmpRequest {
            opcode: NAT_PMP_PUBLIC_ADDR,
            internal_port: 0,
            external_port: 0,
            lifetime_sec: 0,
        }
    }

    /// Add/update (or with `lifetime_sec == 0`, delete) a mapping.
    pub fn map(opcode: u8, internal_port: u16, external_port: u16, lifetime_sec: u32) -> Self {
        debug_assert!(opcode == NAT_PMP_MAP_UDP || opcode == NAT_PMP_MAP_TCP);
        NatPmpRequest {
            opcode,
            internal_port,
            external_port,
            lifetime_sec,
        }
    }

    /// Encode the 12-byte RFC 6886 request.
    pub fn encode(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0] = NAT_PMP_VERSION;
        out[1] = self.opcode;
        out[4..6].copy_from_slice(&self.internal_port.to_be_bytes());
        out[6..8].copy_from_slice(&self.external_port.to_be_bytes());
        out[8..12].copy_from_slice(&self.lifetime_sec.to_be_bytes());
        out
    }
}

/// A parsed NAT-PMP response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatPmpResponse {
    /// Echoed opcode.
    pub opcode: u8,
    /// Result code ([`NAT_PMP_OK`], [`NAT_PMP_UNSUPPORTED`], …).
    pub result: u16,
    /// Seconds since the gateway epoch.
    pub epoch_sec: u32,
    /// Gateway public address (opcode 0 replies).
    pub public_ip: Option<[u8; 4]>,
    /// Internal port echoed back (mapping replies).
    pub internal_port: Option<u16>,
    /// External port granted (mapping replies).
    pub external_port: Option<u16>,
    /// Lease granted in seconds (mapping replies).
    pub lifetime_sec: Option<u32>,
}

impl NatPmpResponse {
    /// Parse a reply. Rejects wrong version, unknown opcodes and truncated
    /// frames.
    pub fn parse(data: &[u8]) -> Result<NatPmpResponse> {
        // version(1) opcode(1) result(2) epoch(4)
        //   public addr reply: + ip(4)                        → 12 bytes
        //   mapping reply:     + internal(2) ext(2) life(4)   → 16 bytes
        if data.len() < 8 || data[0] != NAT_PMP_VERSION {
            return Err(Error::Protocol);
        }
        let opcode = data[1];
        let result = u16::from_be_bytes([data[2], data[3]]);
        let epoch = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        match opcode {
            NAT_PMP_PUBLIC_ADDR => {
                if data.len() != 12 {
                    return Err(Error::Protocol);
                }
                Ok(NatPmpResponse {
                    opcode,
                    result,
                    epoch_sec: epoch,
                    public_ip: Some([data[8], data[9], data[10], data[11]]),
                    internal_port: None,
                    external_port: None,
                    lifetime_sec: None,
                })
            }
            NAT_PMP_MAP_UDP | NAT_PMP_MAP_TCP => {
                if data.len() != 16 {
                    return Err(Error::Protocol);
                }
                Ok(NatPmpResponse {
                    opcode,
                    result,
                    epoch_sec: epoch,
                    public_ip: None,
                    internal_port: Some(u16::from_be_bytes([data[8], data[9]])),
                    external_port: Some(u16::from_be_bytes([data[10], data[11]])),
                    lifetime_sec: Some(u32::from_be_bytes([
                        data[12], data[13], data[14], data[15],
                    ])),
                })
            }
            _ => Err(Error::Protocol),
        }
    }
}

// ---------------------------------------------------------------------------
// UPnP IGD: SSDP discovery + device description + SOAP control
// ---------------------------------------------------------------------------

/// Build the SSDP M-SEARCH discovery datagram (UPnP §1.3.2).
pub fn build_m_search() -> Vec<u8> {
    let mut out = Vec::with_capacity(192);
    out.extend_from_slice(b"M-SEARCH * HTTP/1.1\r\n");
    out.extend_from_slice(b"HOST: 239.255.255.250:1900\r\n");
    out.extend_from_slice(b"MAN: \"ssdp:discover\"\r\n");
    out.extend_from_slice(b"MX: 2\r\n");
    out.extend_from_slice(b"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n");
    out.extend_from_slice(b"\r\n");
    out
}

/// A parsed SSDP device advertisement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsdpResponse {
    /// `LOCATION` header: the device description URL.
    pub location: String,
}

/// Parse an SSDP M-SEARCH response (HTTP over UDP). Bounded and tolerant
/// of header casing/whitespace.
pub fn parse_ssdp_response(data: &[u8]) -> Option<SsdpResponse> {
    if data.len() > MAX_SSDP_SIZE {
        return None;
    }
    let text = core::str::from_utf8(data).ok()?;
    if !text.starts_with("HTTP/") {
        return None;
    }
    let location = header_value(text, "location")?;
    Some(SsdpResponse { location })
}

/// Case-insensitive HTTP header lookup over CRLF lines.
fn header_value(text: &str, name: &str) -> Option<String> {
    for line in text.split("\r\n") {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case(name) {
            return Some(v.trim().to_string());
        }
    }
    None
}

/// Join a (possibly relative) UPnP control URL onto the device-description
/// URL.
pub fn join_url(base: &str, rel: &str) -> String {
    if rel.starts_with("http://") || rel.starts_with("https://") {
        return rel.to_string();
    }
    if let Some(idx) = base.rfind('/') {
        let mut out = String::from(&base[..idx]);
        if !rel.starts_with('/') {
            out.push('/');
        }
        out.push_str(rel);
        out
    } else {
        rel.to_string()
    }
}

/// Extract the WAN IP/PPP connection service's `<controlURL>` from an IGD
/// device description. Uses a bounded, defensive tag scan — UPnP XML here
/// is trivial and does not need a full parser.
pub fn find_wan_control_url(xml: &[u8]) -> Option<String> {
    let max = xml.len().min(MAX_XML_SCAN);
    let s = core::str::from_utf8(&xml[..max]).ok()?;
    for st in [
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
    ] {
        if let Some(idx) = s.find(st) {
            if let Some(url) = control_url_after(&s[idx..]) {
                return Some(url);
            }
        }
    }
    None
}

/// First `<controlURL>…</controlURL>` after a service-type marker.
fn control_url_after(s: &str) -> Option<String> {
    let start = s.find("<controlURL>")?;
    let rest = &s[start + "<controlURL>".len()..];
    let end = rest.find("</controlURL>")?;
    let url = rest[..end].trim();
    if url.is_empty() {
        None
    } else {
        Some(url.to_string())
    }
}

/// Which SOAP action a response is expected to confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoapAction {
    /// `AddPortMapping`.
    Add,
    /// `DeletePortMapping`.
    Delete,
}

/// Build the SOAP `AddPortMapping` request body.
pub fn build_soap_add_mapping(
    protocol: &str,
    internal_port: u16,
    external_port: u16,
    lease_sec: u32,
    description: &str,
    internal_client: &str,
) -> Vec<u8> {
    let mut body = String::from(
        "<?xml version=\"1.0\"?>\r\n\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
         <s:Body><u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">",
    );
    body.push_str("<NewRemoteHost></NewRemoteHost>");
    body.push_str("<NewExternalPort>");
    body.push_str(&external_port.to_string());
    body.push_str("</NewExternalPort>");
    body.push_str("<NewProtocol>");
    body.push_str(protocol);
    body.push_str("</NewProtocol>");
    body.push_str("<NewInternalPort>");
    body.push_str(&internal_port.to_string());
    body.push_str("</NewInternalPort>");
    body.push_str("<NewInternalClient>");
    body.push_str(internal_client);
    body.push_str("</NewInternalClient>");
    body.push_str("<NewEnabled>1</NewEnabled>");
    body.push_str("<NewPortMappingDescription>");
    body.push_str(description);
    body.push_str("</NewPortMappingDescription>");
    body.push_str("<NewLeaseDuration>");
    body.push_str(&lease_sec.to_string());
    body.push_str("</NewLeaseDuration>");
    body.push_str("</u:AddPortMapping></s:Body></s:Envelope>\r\n");
    body.into_bytes()
}

/// Build the SOAP `DeletePortMapping` request body.
pub fn build_soap_delete_mapping(protocol: &str, external_port: u16) -> Vec<u8> {
    let mut body = String::from(
        "<?xml version=\"1.0\"?>\r\n\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
         <s:Body><u:DeletePortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">",
    );
    body.push_str("<NewRemoteHost></NewRemoteHost>");
    body.push_str("<NewExternalPort>");
    body.push_str(&external_port.to_string());
    body.push_str("</NewExternalPort>");
    body.push_str("<NewProtocol>");
    body.push_str(protocol);
    body.push_str("</NewProtocol>");
    body.push_str("</u:DeletePortMapping></s:Body></s:Envelope>\r\n");
    body.into_bytes()
}

/// Whether a SOAP response confirms the requested action (and carries no
/// fault). Tolerant substring matching mirrors what real clients do.
pub fn soap_succeeded(response: &[u8], action: SoapAction) -> bool {
    let text = match core::str::from_utf8(response) {
        Ok(t) => t,
        Err(_) => return false,
    };
    if text.contains("<s:Fault") || text.contains("<soap:Fault") {
        return false;
    }
    match action {
        SoapAction::Add => text.contains("<u:AddPortMappingResponse"),
        SoapAction::Delete => text.contains("<u:DeletePortMappingResponse"),
    }
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// Lifecycle of the port mapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortMapPhase {
    /// Not started.
    Idle,
    /// NAT-PMP public-address probe in flight.
    NatPmpProbe,
    /// NAT-PMP mapping request in flight.
    NatPmpMapping,
    /// SSDP M-SEARCH in flight.
    UpnpDiscover,
    /// Fetching the IGD device description.
    UpnpFetching,
    /// Sending the SOAP AddPortMapping.
    UpnpMapping,
    /// A mapping is live; refreshing on lease expiry.
    Mapped,
    /// Deleting the mapping.
    Unmapping,
    /// Unmapped / finished.
    Done,
    /// All methods failed (retried after backoff).
    Failed,
}

impl PortMapPhase {
    /// Stable numeric code for events / FFI.
    pub fn code(self) -> u8 {
        match self {
            PortMapPhase::Idle => 0,
            PortMapPhase::NatPmpProbe => 1,
            PortMapPhase::NatPmpMapping => 2,
            PortMapPhase::UpnpDiscover => 3,
            PortMapPhase::UpnpFetching => 4,
            PortMapPhase::UpnpMapping => 5,
            PortMapPhase::Mapped => 6,
            PortMapPhase::Unmapping => 7,
            PortMapPhase::Done => 8,
            PortMapPhase::Failed => 9,
        }
    }
}

/// Which transport protocol a mapping is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapProtocol {
    /// UDP (also used by the DHT/tracker socket).
    Udp,
    /// TCP (peer connections).
    Tcp,
}

impl MapProtocol {
    fn nat_pmp_opcode(self) -> u8 {
        match self {
            MapProtocol::Udp => NAT_PMP_MAP_UDP,
            MapProtocol::Tcp => NAT_PMP_MAP_TCP,
        }
    }

    fn upnp_name(self) -> &'static str {
        match self {
            MapProtocol::Udp => "UDP",
            MapProtocol::Tcp => "TCP",
        }
    }
}

/// Configuration for the port mapper.
#[derive(Debug, Clone)]
pub struct PortMapConfig {
    /// Master switch (engine sets it from its own config).
    pub enabled: bool,
    /// Internal UDP port to map (usually the listen port).
    pub udp_port: u16,
    /// Internal TCP port to map (usually the listen port).
    pub tcp_port: u16,
    /// Requested lease (seconds); the gateway may grant less.
    pub lease_sec: u32,
    /// Per-step network timeout (ms).
    pub step_timeout_ms: u64,
    /// Backoff before retrying after a failed cycle (ms).
    pub retry_interval_ms: u64,
    /// Human-readable mapping description shown in router UIs.
    pub description: String,
}

impl Default for PortMapConfig {
    fn default() -> Self {
        PortMapConfig {
            enabled: false,
            udp_port: 0,
            tcp_port: 0,
            lease_sec: 3600,
            step_timeout_ms: 3000,
            retry_interval_ms: 300_000,
            description: String::from("TypeBit"),
        }
    }
}

/// Live status of the port mapper (events / host inspection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMapStatus {
    /// Current phase.
    pub phase: PortMapPhase,
    /// Protocol of the mapping being established/maintained.
    pub protocol: Option<MapProtocol>,
    /// External port granted by the gateway, when known.
    pub external_port: Option<u16>,
    /// Short error description when `phase == Failed`.
    pub error: Option<String>,
}

/// Refresh the mapping at half the lease, clamped to [60 s, 1 h].
fn refresh_interval(lease_sec: u32) -> u64 {
    let half = (lease_sec as u64) / 2;
    half.clamp(60, 3600) * 1000
}

/// Port mapper driven by [`PortMapManager::tick`].
pub struct PortMapManager {
    cfg: PortMapConfig,
    phase: PortMapPhase,
    protocol: Option<MapProtocol>,
    gateway: Option<NetAddr>,
    /// Timestamp of the in-flight request (None = nothing outstanding).
    sent_at: Option<u64>,
    external_port: Option<u16>,
    /// UPnP device description URL.
    location: Option<String>,
    /// Full SOAP control URL.
    control_url: Option<String>,
    /// Whether the live mapping was established via UPnP (vs NAT-PMP).
    using_upnp: bool,
    next: u64,
    error: Option<String>,
}

impl PortMapManager {
    /// Create a manager. The engine calls [`PortMapManager::start`] once
    /// its UDP socket is open.
    pub fn new(cfg: PortMapConfig) -> Self {
        PortMapManager {
            cfg,
            phase: PortMapPhase::Idle,
            protocol: None,
            gateway: None,
            sent_at: None,
            external_port: None,
            location: None,
            control_url: None,
            using_upnp: false,
            next: 0,
            error: None,
        }
    }

    /// Begin mapping. No-op unless idle or after a finished cycle.
    pub fn start(&mut self, now: u64) {
        if self.phase != PortMapPhase::Idle && self.phase != PortMapPhase::Done {
            return;
        }
        self.protocol = Some(MapProtocol::Udp);
        self.external_port = None;
        self.location = None;
        self.control_url = None;
        self.error = None;
        self.sent_at = None;
        self.next = now;
        self.phase = PortMapPhase::NatPmpProbe;
    }

    /// Whether a mapping is currently live.
    pub fn is_mapped(&self) -> bool {
        self.phase == PortMapPhase::Mapped
    }

    /// Live status snapshot.
    pub fn status(&self) -> PortMapStatus {
        PortMapStatus {
            phase: self.phase,
            protocol: self.protocol,
            external_port: self.external_port,
            error: self.error.clone(),
        }
    }

    /// Best-effort removal of the current mapping.
    pub fn unmap(&mut self, now: u64) {
        if self.phase == PortMapPhase::Mapped {
            self.phase = PortMapPhase::Unmapping;
            self.sent_at = None;
            self.next = now;
        }
    }

    /// Advance the state machine. Call once per engine tick. Network
    /// failures are absorbed into the `Failed` state (best-effort feature).
    pub fn tick<H: Host>(&mut self, host: &mut H, now: u64) {
        if !self.cfg.enabled {
            return;
        }
        if now < self.next {
            return;
        }
        match self.phase {
            PortMapPhase::Idle => {}
            PortMapPhase::NatPmpProbe => {
                if self.sent_at.is_none() {
                    match self.gateway(host) {
                        Some(gw) => {
                            let req = NatPmpRequest::public_addr();
                            let target = with_port(gw, NAT_PMP_PORT);
                            match host.udp_send(&target, &req.encode()) {
                                Ok(()) => {
                                    self.sent_at = Some(now);
                                    self.next = now + self.cfg.step_timeout_ms;
                                }
                                Err(_) => self.enter_upnp_discover(now, "nat-pmp send failed"),
                            }
                        }
                        None => self.enter_upnp_discover(now, "no default gateway"),
                    }
                } else {
                    // probe timed out → fall back to UPnP
                    self.sent_at = None;
                    self.enter_upnp_discover(now, "nat-pmp probe timeout");
                }
            }
            PortMapPhase::NatPmpMapping => {
                if self.sent_at.is_none() {
                    match (self.gateway(host), self.protocol) {
                        (Some(gw), Some(proto)) => {
                            let port = self.port_for(proto);
                            let req = NatPmpRequest::map(
                                proto.nat_pmp_opcode(),
                                port,
                                port,
                                self.cfg.lease_sec,
                            );
                            let target = with_port(gw, NAT_PMP_PORT);
                            match host.udp_send(&target, &req.encode()) {
                                Ok(()) => {
                                    self.sent_at = Some(now);
                                    self.next = now + self.cfg.step_timeout_ms;
                                }
                                Err(_) => {
                                    self.enter_upnp_discover(now, "nat-pmp map send failed");
                                }
                            }
                        }
                        _ => self.enter_upnp_discover(now, "no gateway for mapping"),
                    }
                } else {
                    // mapping timed out → try UPnP
                    self.sent_at = None;
                    self.enter_upnp_discover(now, "nat-pmp mapping timeout");
                }
            }
            PortMapPhase::UpnpDiscover => {
                if self.sent_at.is_none() {
                    match host.udp_multicast_send(&SSDP_ADDR, &build_m_search()) {
                        Ok(()) => {
                            self.sent_at = Some(now);
                            self.next = now + self.cfg.step_timeout_ms;
                        }
                        Err(_) => self.fail("upnp multicast send failed"),
                    }
                } else {
                    self.sent_at = None;
                    self.fail("upnp discovery timeout");
                }
            }
            PortMapPhase::UpnpFetching => self.step_upnp_fetch(host, now),
            PortMapPhase::UpnpMapping => self.step_upnp_map(host, now),
            PortMapPhase::Mapped => {
                // lease about to expire → renew through the active method
                self.sent_at = None;
                self.next = now;
                if self.using_upnp {
                    self.phase = PortMapPhase::UpnpMapping;
                } else {
                    self.phase = PortMapPhase::NatPmpMapping;
                }
            }
            PortMapPhase::Unmapping => {
                let _ = self.send_delete(host);
                self.phase = PortMapPhase::Done;
                self.next = now;
            }
            PortMapPhase::Done | PortMapPhase::Failed => {
                // periodic retry (long backoff, no hammering)
                self.phase = PortMapPhase::NatPmpProbe;
                self.sent_at = None;
                self.next = now + self.cfg.retry_interval_ms;
            }
        }
    }

    /// Route an inbound UDP datagram. Returns `true` when consumed (a
    /// NAT-PMP reply or an SSDP discovery response).
    pub fn handle_datagram(&mut self, addr: &NetAddr, data: &[u8], now: u64) -> bool {
        if data.len() >= 8 && data[0] == NAT_PMP_VERSION && addr.port() == NAT_PMP_PORT {
            return self.on_nat_pmp_reply(data, now);
        }
        if data.len() >= 5 && data.starts_with(b"HTTP/") {
            if let Some(ssdp) = parse_ssdp_response(data) {
                return self.on_ssdp(ssdp, now);
            }
        }
        false
    }

    // -- steps --

    fn gateway<H: Host>(&mut self, host: &H) -> Option<NetAddr> {
        if self.gateway.is_none() {
            self.gateway = host.default_gateway();
        }
        self.gateway
    }

    fn port_for(&self, proto: MapProtocol) -> u16 {
        match proto {
            MapProtocol::Udp => self.cfg.udp_port,
            MapProtocol::Tcp => self.cfg.tcp_port,
        }
    }

    fn enter_upnp_discover(&mut self, now: u64, why: &str) {
        self.error = Some(String::from(why));
        self.phase = PortMapPhase::UpnpDiscover;
        self.sent_at = None;
        self.next = now;
    }

    fn fail(&mut self, why: &str) {
        self.error = Some(String::from(why));
        self.phase = PortMapPhase::Failed;
        self.sent_at = None;
        self.next = 0; // retry path in tick arms the backoff
    }

    fn step_upnp_fetch<H: Host>(&mut self, host: &mut H, now: u64) {
        let loc = match &self.location {
            Some(l) => l.clone(),
            None => {
                self.fail("upnp: missing location");
                return;
            }
        };
        let mut xml = Vec::new();
        match host.http_get(&loc, self.cfg.step_timeout_ms, &mut xml) {
            Ok(()) => match find_wan_control_url(&xml) {
                Some(rel) => {
                    self.control_url = Some(join_url(&loc, &rel));
                    self.phase = PortMapPhase::UpnpMapping;
                    self.next = now;
                }
                None => self.fail("upnp: no WAN IP connection service"),
            },
            Err(_) => self.fail("upnp: device description fetch failed"),
        }
    }

    fn step_upnp_map<H: Host>(&mut self, host: &mut H, now: u64) {
        let (url, proto, port, local) = match (
            &self.control_url,
            self.protocol,
            self.port_for(self.protocol.unwrap_or(MapProtocol::Udp)),
            host.local_ip(),
        ) {
            (Some(u), Some(p), port, Some(local)) => (u.clone(), p, port, local),
            (_, _, _, None) => {
                self.fail("upnp: host cannot report LAN IP");
                return;
            }
            _ => {
                self.fail("upnp: missing control URL");
                return;
            }
        };
        let client = local.to_alloc_string();
        let body = build_soap_add_mapping(
            proto.upnp_name(),
            port,
            port,
            self.cfg.lease_sec,
            &self.cfg.description,
            &client,
        );
        let mut resp = Vec::new();
        match host.http_post(&url, &body, self.cfg.step_timeout_ms, &mut resp) {
            Ok(()) => {
                if soap_succeeded(&resp, SoapAction::Add) {
                    self.error = None;
                    self.using_upnp = true;
                    self.external_port = Some(port);
                    self.phase = PortMapPhase::Mapped;
                    self.next = now + refresh_interval(self.cfg.lease_sec);
                } else {
                    self.fail("upnp: AddPortMapping rejected");
                }
            }
            Err(Error::NotSupported) => self.fail("upnp: host lacks http_post"),
            Err(_) => self.fail("upnp: AddPortMapping request failed"),
        }
    }

    /// Best-effort delete of the live mapping (used by `unmap`).
    fn send_delete<H: Host>(&mut self, host: &mut H) -> Result<()> {
        let proto = self.protocol.unwrap_or(MapProtocol::Udp);
        let port = self.port_for(proto);
        if self.using_upnp {
            let url = match &self.control_url {
                Some(u) => u.clone(),
                None => return Err(Error::NotFound),
            };
            let body = build_soap_delete_mapping(proto.upnp_name(), port);
            let mut resp = Vec::new();
            match host.http_post(&url, &body, self.cfg.step_timeout_ms, &mut resp) {
                Ok(()) => {
                    let _ = soap_succeeded(&resp, SoapAction::Delete);
                    Ok(())
                }
                Err(_) => Err(Error::Io),
            }
        } else {
            let gw = match self.gateway(host) {
                Some(g) => g,
                None => return Err(Error::NotFound),
            };
            let req = NatPmpRequest::map(proto.nat_pmp_opcode(), port, port, 0);
            host.udp_send(&with_port(gw, NAT_PMP_PORT), &req.encode())
        }
    }

    // -- inbound handling --

    fn on_nat_pmp_reply(&mut self, data: &[u8], now: u64) -> bool {
        let resp = match NatPmpResponse::parse(data) {
            Ok(r) => r,
            Err(_) => return false,
        };
        match resp.opcode {
            NAT_PMP_PUBLIC_ADDR => {
                if self.phase != PortMapPhase::NatPmpProbe {
                    return false;
                }
                if resp.result == NAT_PMP_OK {
                    self.phase = PortMapPhase::NatPmpMapping;
                    self.sent_at = None;
                    self.next = now;
                } else {
                    // unsupported or other error → try UPnP
                    self.enter_upnp_discover(now, "nat-pmp unsupported");
                }
                true
            }
            NAT_PMP_MAP_UDP | NAT_PMP_MAP_TCP => {
                if self.phase != PortMapPhase::NatPmpMapping
                    || resp.opcode != self.protocol.map(|p| p.nat_pmp_opcode()).unwrap_or(0xFF)
                {
                    return false;
                }
                if resp.result == NAT_PMP_OK {
                    self.error = None;
                    self.external_port = resp.external_port.or(Some(
                        self.port_for(self.protocol.unwrap_or(MapProtocol::Udp)),
                    ));
                    self.using_upnp = false;
                    self.phase = PortMapPhase::Mapped;
                    self.sent_at = None;
                    self.next = now + refresh_interval(self.cfg.lease_sec);
                } else if resp.result == NAT_PMP_UNSUPPORTED {
                    self.enter_upnp_discover(now, "nat-pmp mapping unsupported");
                } else {
                    self.fail("nat-pmp mapping rejected");
                }
                true
            }
            _ => false,
        }
    }

    fn on_ssdp(&mut self, ssdp: SsdpResponse, now: u64) -> bool {
        if self.phase != PortMapPhase::UpnpDiscover {
            return false;
        }
        self.location = Some(ssdp.location);
        self.phase = PortMapPhase::UpnpFetching;
        self.sent_at = None;
        self.next = now;
        true
    }
}

fn with_port(a: NetAddr, port: u16) -> NetAddr {
    match a {
        NetAddr::V4(ip, _) => NetAddr::V4(ip, port),
        NetAddr::V6(ip, _) => NetAddr::V6(ip, port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{ConnId, DiskId, LogLevel};

    // -- codecs --

    #[test]
    fn nat_pmp_request_encoding() {
        let req = NatPmpRequest::public_addr();
        assert_eq!(req.encode(), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let map = NatPmpRequest::map(NAT_PMP_MAP_UDP, 6881, 6881, 3600);
        let b = map.encode();
        assert_eq!(&b[..4], &[0, 1, 0, 0]);
        assert_eq!(&b[4..6], &0x1AE1u16.to_be_bytes()); // 6881
        assert_eq!(&b[8..12], &3600u32.to_be_bytes());
        // lifetime 0 = delete
        let del = NatPmpRequest::map(NAT_PMP_MAP_TCP, 6881, 6881, 0);
        assert_eq!(&del.encode()[8..12], &[0, 0, 0, 0]);
    }

    #[test]
    fn nat_pmp_response_parsing() {
        // public address reply: v0 op0 result0 epoch123 ip 203.0.113.9
        let mut b = [0u8; 12];
        b[1] = 0;
        b[4..8].copy_from_slice(&123u32.to_be_bytes());
        b[8..12].copy_from_slice(&[203, 0, 113, 9]);
        let r = NatPmpResponse::parse(&b).unwrap();
        assert_eq!(r.opcode, 0);
        assert_eq!(r.result, 0);
        assert_eq!(r.epoch_sec, 123);
        assert_eq!(r.public_ip, Some([203, 0, 113, 9]));
        // mapping reply: 16 bytes
        let mut m = [0u8; 16];
        m[1] = NAT_PMP_MAP_UDP;
        m[8..10].copy_from_slice(&6881u16.to_be_bytes());
        m[10..12].copy_from_slice(&6881u16.to_be_bytes());
        m[12..16].copy_from_slice(&3600u32.to_be_bytes());
        let r = NatPmpResponse::parse(&m).unwrap();
        assert_eq!(r.internal_port, Some(6881));
        assert_eq!(r.external_port, Some(6881));
        assert_eq!(r.lifetime_sec, Some(3600));
        // reject truncation and wrong version
        assert!(NatPmpResponse::parse(&b[..8]).is_err());
        let mut bad = b;
        bad[0] = 1;
        assert!(NatPmpResponse::parse(&bad).is_err());
    }

    #[test]
    fn ssdp_build_and_parse() {
        let m = build_m_search();
        let text = core::str::from_utf8(&m).unwrap();
        assert!(text.contains("M-SEARCH * HTTP/1.1"));
        assert!(text.contains("239.255.255.250:1900"));
        assert!(text.contains("InternetGatewayDevice:1"));
        let resp = "HTTP/1.1 200 OK\r\n\
                    CACHE-CONTROL: max-age=1800\r\n\
                    LOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n\
                    ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
        let s = parse_ssdp_response(resp.as_bytes()).unwrap();
        assert_eq!(s.location, "http://192.168.1.1:5000/rootDesc.xml");
        assert!(parse_ssdp_response(b"garbage").is_none());
    }

    #[test]
    fn wan_control_url_extraction() {
        let xml = br#"<?xml version="1.0"?>
        <root>
          <device>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <controlURL>/upnp/control/WANIPConn1</controlURL>
                <eventSubURL>/upnp/event/WANIPConn1</eventSubURL>
              </service>
            </serviceList>
          </device>
        </root>"#;
        assert_eq!(
            find_wan_control_url(xml),
            Some(String::from("/upnp/control/WANIPConn1"))
        );
        assert_eq!(
            join_url(
                "http://192.168.1.1:5000/rootDesc.xml",
                "/upnp/control/WANIPConn1"
            ),
            "http://192.168.1.1:5000/upnp/control/WANIPConn1"
        );
        assert_eq!(
            join_url("http://192.168.1.1/desc.xml", "control?1"),
            "http://192.168.1.1/control?1"
        );
        assert!(find_wan_control_url(b"<root></root>").is_none());
    }

    #[test]
    fn soap_bodies_and_result() {
        let add = build_soap_add_mapping("TCP", 6881, 6881, 3600, "TypeBit", "192.168.1.10");
        let t = core::str::from_utf8(&add).unwrap();
        assert!(t.contains("<u:AddPortMapping"));
        assert!(t.contains("<NewExternalPort>6881</NewExternalPort>"));
        assert!(t.contains("<NewInternalClient>192.168.1.10</NewInternalClient>"));
        let ok = br#"<s:Envelope><s:Body><u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"></u:AddPortMappingResponse></s:Body></s:Envelope>"#;
        assert!(soap_succeeded(ok, SoapAction::Add));
        assert!(!soap_succeeded(ok, SoapAction::Delete));
        let fault = br#"<s:Envelope><s:Body><s:Fault><faultstring>UPnPError</faultstring></s:Fault></s:Body></s:Envelope>"#;
        assert!(!soap_succeeded(fault, SoapAction::Add));
    }

    // -- state machine with a scripted host --

    struct ScriptedHost {
        now: u64,
        gateway: Option<NetAddr>,
        local: Option<NetAddr>,
        sent: Vec<(NetAddr, Vec<u8>)>,
        xml: Option<Vec<u8>>,
        post_resp: Option<Vec<u8>>,
    }

    impl ScriptedHost {
        fn new(gw: [u8; 4]) -> Self {
            ScriptedHost {
                now: 0,
                gateway: Some(NetAddr::V4(gw, 0)),
                local: Some(NetAddr::V4([192, 168, 1, 10], 0)),
                sent: Vec::new(),
                xml: None,
                post_resp: None,
            }
        }
    }

    impl Host for ScriptedHost {
        fn now_ms(&self) -> u64 {
            self.now
        }
        fn fill_random(&mut self, _buf: &mut [u8]) {}
        fn log(&mut self, _level: LogLevel, _msg: &str) {}
        fn http_get(&mut self, _url: &str, _timeout_ms: u64, out: &mut Vec<u8>) -> Result<()> {
            match &self.xml {
                Some(x) => {
                    out.extend_from_slice(x);
                    Ok(())
                }
                None => Err(Error::Io),
            }
        }
        fn http_post(
            &mut self,
            _url: &str,
            _body: &[u8],
            _timeout_ms: u64,
            out: &mut Vec<u8>,
        ) -> Result<()> {
            match &self.post_resp {
                Some(r) => {
                    out.extend_from_slice(r);
                    Ok(())
                }
                None => Err(Error::NotSupported),
            }
        }
        fn default_gateway(&self) -> Option<NetAddr> {
            self.gateway
        }
        fn local_ip(&self) -> Option<NetAddr> {
            self.local
        }
        fn tcp_connect(&mut self, _a: &NetAddr) -> Result<ConnId> {
            Err(Error::NotSupported)
        }
        fn tcp_connect_done(&mut self, _id: ConnId) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn tcp_send(&mut self, _id: ConnId, _d: &[u8]) -> Result<usize> {
            Err(Error::NotSupported)
        }
        fn tcp_recv(&mut self, _id: ConnId, _b: &mut [u8]) -> Result<usize> {
            Err(Error::NotSupported)
        }
        fn tcp_close(&mut self, _id: ConnId) {}
        fn udp_open(&mut self, _port: u16) -> Result<()> {
            Ok(())
        }
        fn udp_send(&mut self, addr: &NetAddr, data: &[u8]) -> Result<()> {
            self.sent.push((*addr, data.to_vec()));
            Ok(())
        }
        fn udp_recv(&mut self, _buf: &mut [u8]) -> Result<(NetAddr, usize)> {
            Err(Error::WouldBlock)
        }
        fn disk_open(&mut self, _p: &str) -> Result<DiskId> {
            Err(Error::NotSupported)
        }
        fn disk_read(&mut self, _id: DiskId, _o: u64, _b: &mut [u8]) -> Result<usize> {
            Err(Error::NotSupported)
        }
        fn disk_write(&mut self, _id: DiskId, _o: u64, _d: &[u8]) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn disk_prealloc(&mut self, _id: DiskId, _s: u64) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn disk_flush(&mut self, _id: DiskId) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn disk_close(&mut self, _id: DiskId) {}
    }

    fn nat_pmp_map_reply(opcode: u8, result: u16) -> Vec<u8> {
        let mut m = [0u8; 16];
        m[0] = 0;
        m[1] = opcode;
        m[2..4].copy_from_slice(&result.to_be_bytes());
        m[8..10].copy_from_slice(&6881u16.to_be_bytes());
        m[10..12].copy_from_slice(&6881u16.to_be_bytes());
        m[12..16].copy_from_slice(&3600u32.to_be_bytes());
        m.to_vec()
    }

    #[test]
    fn nat_pmp_flow_reaches_mapped() {
        let mut host = ScriptedHost::new([192, 168, 1, 1]);
        let cfg = PortMapConfig {
            enabled: true,
            udp_port: 6881,
            tcp_port: 6881,
            ..Default::default()
        };
        let mut pm = PortMapManager::new(cfg);
        pm.start(0);
        pm.tick(&mut host, 0);
        // probe sent to gateway:5351
        assert_eq!(host.sent.len(), 1);
        let (target, req) = &host.sent[0];
        assert_eq!(target.port(), NAT_PMP_PORT);
        assert_eq!(req[0], 0);
        assert_eq!(req[1], NAT_PMP_PUBLIC_ADDR);
        // gateway replies with public address
        let mut pub_reply = [0u8; 12];
        pub_reply[8..12].copy_from_slice(&[203, 0, 113, 9]);
        assert!(pm.handle_datagram(&NetAddr::V4([192, 168, 1, 1], 5351), &pub_reply, 10));
        // map request is queued on the next tick
        pm.tick(&mut host, 10);
        assert_eq!(host.sent.len(), 2);
        let (_, req) = &host.sent[1];
        assert_eq!(req[1], NAT_PMP_MAP_UDP);
        // gateway grants the mapping
        let reply = nat_pmp_map_reply(NAT_PMP_MAP_UDP, NAT_PMP_OK);
        assert!(pm.handle_datagram(&NetAddr::V4([192, 168, 1, 1], 5351), &reply, 20));
        assert!(pm.is_mapped());
        assert_eq!(pm.status().external_port, Some(6881));
    }

    #[test]
    fn mapping_refreshes_before_lease_expiry() {
        let mut host = ScriptedHost::new([192, 168, 1, 1]);
        let cfg = PortMapConfig {
            enabled: true,
            udp_port: 6881,
            tcp_port: 6881,
            lease_sec: 120, // refresh at half = 60 s
            ..Default::default()
        };
        let mut pm = PortMapManager::new(cfg);
        pm.start(0);
        pm.tick(&mut host, 0);
        let mut pub_reply = [0u8; 12];
        pub_reply[8..12].copy_from_slice(&[203, 0, 113, 9]);
        pm.handle_datagram(&NetAddr::V4([192, 168, 1, 1], 5351), &pub_reply, 10);
        pm.tick(&mut host, 10);
        let reply = nat_pmp_map_reply(NAT_PMP_MAP_UDP, NAT_PMP_OK);
        pm.handle_datagram(&NetAddr::V4([192, 168, 1, 1], 5351), &reply, 20);
        assert!(pm.is_mapped());
        // at refresh time the renewing map request is issued on the next tick
        let sent_before = host.sent.len();
        pm.tick(&mut host, 20 + 60_000);
        pm.tick(&mut host, 20 + 60_000);
        assert_eq!(host.sent.len(), sent_before + 1);
        assert_eq!(host.sent[sent_before].1[1], NAT_PMP_MAP_UDP);
    }

    #[test]
    fn nat_pmp_unsupported_falls_back_to_upnp() {
        let mut host = ScriptedHost::new([192, 168, 1, 1]);
        host.xml = Some(
            br#"<root><device><serviceList><service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <controlURL>/ctl</controlURL></service></serviceList></device></root>"#
                .to_vec(),
        );
        host.post_resp = Some(
            br#"<s:Envelope><s:Body><u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/></s:Body></s:Envelope>"#
                .to_vec(),
        );
        let cfg = PortMapConfig {
            enabled: true,
            udp_port: 6881,
            tcp_port: 6881,
            ..Default::default()
        };
        let mut pm = PortMapManager::new(cfg);
        pm.start(0);
        pm.tick(&mut host, 0);
        // unsupported result to the probe
        let mut bad = [0u8; 12];
        bad[1] = 0;
        bad[2..4].copy_from_slice(&1u16.to_be_bytes()); // UNSUPPORTED
        assert!(pm.handle_datagram(&NetAddr::V4([192, 168, 1, 1], 5351), &bad, 10));
        // now SSDP discovery
        pm.tick(&mut host, 10);
        let ssdp = "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n\r\n";
        assert!(pm.handle_datagram(&NetAddr::V4([192, 168, 1, 1], 1900), ssdp.as_bytes(), 20));
        // fetch description, then the SOAP AddPortMapping, on subsequent ticks
        pm.tick(&mut host, 20);
        pm.tick(&mut host, 20);
        assert!(pm.is_mapped());
        assert!(pm.status().error.is_none());
    }

    #[test]
    fn upnp_timeout_fails_then_retries() {
        let mut host = ScriptedHost::new([0, 0, 0, 0]);
        host.gateway = None; // no gateway → straight to UPnP discovery
        let cfg = PortMapConfig {
            enabled: true,
            udp_port: 6881,
            tcp_port: 6881,
            retry_interval_ms: 1000,
            step_timeout_ms: 500,
            ..Default::default()
        };
        let mut pm = PortMapManager::new(cfg);
        pm.start(0);
        // no gateway → straight to UPnP discovery; next tick sends M-SEARCH
        pm.tick(&mut host, 0);
        pm.tick(&mut host, 0);
        assert_eq!(pm.status().phase, PortMapPhase::UpnpDiscover);
        // no SSDP response → timeout → Failed
        pm.tick(&mut host, 501);
        assert_eq!(pm.status().phase, PortMapPhase::Failed);
        // backoff elapses → retry: probe phase, then no-gateway → UPnP again
        pm.tick(&mut host, 1502);
        assert_eq!(pm.status().phase, PortMapPhase::NatPmpProbe);
        pm.tick(&mut host, 2502);
        assert_eq!(pm.status().phase, PortMapPhase::UpnpDiscover);
    }
}
