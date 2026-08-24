//! Unified error type for the TypeBit core.
//!
//! Kept dependency-free (`no_std`), `Copy` where possible so it can flow
//! through hot paths without allocation, and `Display`-capable for logging.

use alloc::string::String;
use core::fmt;

/// Error taxonomy of the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// Generic invalid input / malformed data.
    InvalidInput,
    /// Bencode syntax or structure error.
    Bencode,
    /// Metainfo / torrent file structure error.
    MetaInfo,
    /// Magnet URI error.
    Magnet,
    /// Peer-wire handshake failure.
    Handshake,
    /// Peer-wire protocol violation.
    Protocol,
    /// Piece hash mismatch (v1 SHA-1 / v2 SHA-256).
    HashMismatch,
    /// Tracker error (HTTP status or bencoded failure reason).
    Tracker,
    /// DHT / KRPC protocol error.
    Dht,
    /// Cryptographic operation failed (signature verify, key decode, …).
    Crypto,
    /// Receipt construction or verification failed.
    Receipt,
    /// Underlying I/O failed.
    Io,
    /// Resource limit hit (cache full, pipeline full, …).
    Full,
    /// Operation requires the `std` feature of the host.
    NotSupported,
    /// Transient "would block" for non-blocking transports.
    WouldBlock,
    /// Timed out.
    Timeout,
    /// Connection or entity not found.
    NotFound,
    /// Message too large for a bounded buffer.
    TooLarge,
    /// Overlong nesting / recursion limit exceeded.
    Depth,
    /// Internal invariant violation (a bug; not hostile input).
    Internal,
    /// Value out of supported range.
    Range,
}

impl Error {
    /// Short human-readable tag used in logs.
    pub fn tag(&self) -> &'static str {
        match self {
            Error::InvalidInput => "invalid_input",
            Error::Bencode => "bencode",
            Error::MetaInfo => "metainfo",
            Error::Magnet => "magnet",
            Error::Handshake => "handshake",
            Error::Protocol => "protocol",
            Error::HashMismatch => "hash_mismatch",
            Error::Tracker => "tracker",
            Error::Dht => "dht",
            Error::Crypto => "crypto",
            Error::Receipt => "receipt",
            Error::Io => "io",
            Error::Full => "full",
            Error::NotSupported => "not_supported",
            Error::WouldBlock => "would_block",
            Error::Timeout => "timeout",
            Error::NotFound => "not_found",
            Error::TooLarge => "too_large",
            Error::Depth => "depth",
            Error::Internal => "internal",
            Error::Range => "range",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Result alias used throughout the core.
pub type Result<T> = core::result::Result<T, Error>;

/// Error carrying a message, used where diagnostics matter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgError {
    /// Kind of error.
    pub kind: Error,
    /// Additional detail.
    pub msg: String,
}

impl MsgError {
    /// Construct a message error.
    pub fn new(kind: Error, msg: impl Into<String>) -> Self {
        Self {
            kind,
            msg: msg.into(),
        }
    }
    /// Short-hand for `InvalidInput`.
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::new(Error::InvalidInput, msg)
    }
    /// Short-hand for `Protocol`.
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::new(Error::Protocol, msg)
    }
}

impl From<MsgError> for Error {
    fn from(e: MsgError) -> Self {
        e.kind
    }
}

impl fmt::Display for MsgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.msg)
    }
}
