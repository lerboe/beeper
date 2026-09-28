//! HTTP/2 parsing.
//!
//! [`Parser`] compiles the configured patterns into a DFA whose edges
//! are injected into the BPF parser program. The kernel walks the message
//! byte by byte, follows the edges and runs each action it encounters.
//!
//! Note that [`Parser`] operates directly on the Huffman-encoded bytes,
//! and manages a copy of the dynamic table for each connection.

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
