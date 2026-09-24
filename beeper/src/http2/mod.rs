//! HTTP/2 parsing.
//!
//! HTTP/2 does not spell its header fields out on the wire. HPACK either
//! replaces a field with an index into the static or the dynamic table, or
//! Huffman encodes it. [`Parser`] therefore matches the Huffman encoded field
//! name against its DFA and mirrors the peer's dynamic table in a BPF map, so
//! that indexed fields can be resolved in the kernel as well.

use std::net::SocketAddr;

mod action;
mod hpack;
mod parser;
pub use parser::{AttachedParser, Parser, ip4_addr, ip4_conn};

impl From<SocketAddr> for ip4_addr {
    /// Converts `addr` into the address the BPF programs key their per
    /// connection state with.
    ///
    /// # Panics
    ///
    /// Panics if `addr` is an IPv6 address, which Beeper does not support yet.
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr) => ip4_addr {
                ip4: u32::from_ne_bytes(addr.ip().octets()),
                port: addr.port() as u32,
            },
            SocketAddr::V6(_) => panic!("ip4_addr does not support IPv6 addresses"),
        }
    }
}
