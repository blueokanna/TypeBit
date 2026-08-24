//! TypeBit std host: implements [`typebit_core::Host`] on top of the OS
//! (blocking sockets in non-blocking mode, files, `SystemTime`) and a
//! runnable example client.

pub mod host;

pub use host::StdHost;
