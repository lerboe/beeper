//! HTTP/2 parsing.
//!
//! [`Parser`] compiles the configured patterns into a DFA whose edges
//! are injected into the BPF parser program. The kernel walks the message
//! byte by byte, follows the edges and runs each action it encounters.
//!
//! Note that [`Parser`] operates directly on the Huffman-encoded bytes,
//! and manages a copy of the dynamic table for each connection.
//!
//! # Examples
//!
//! Captures the `User-Agent` header and passes its match ID to the target
//! program through the read-only data of its skeleton, before the program
//! is loaded:
//!
//! ```no_run
//! # fn main() -> Result<(), beeper::Error> {
//! # struct Rodata { user_agent_mid: u8 }
//! # let mut rodata = Rodata { user_agent_mid: 0 };
//! # let prog_fd = 0;
//! use beeper::{MessageBuffer, http2};
//! use http::header::USER_AGENT;
//!
//! let mut parser = http2::Parser::new();
//! let user_agent_mid = parser.capture_hdr(&USER_AGENT)?;
//!
//! // e.g. open_skel.maps.rodata_data.as_mut().unwrap()
//! rodata.user_agent_mid = user_agent_mid.into();
//!
//! let parser = parser
//!     .parse_fn("parse_http2", MessageBuffer::Msg)
//!     .extract_fn("extract_http2_match", MessageBuffer::Msg)
//!     .get_dynamic_table_entry("get_dt_entry")
//!     .attach(prog_fd)?;
//! # Ok(())
//! # }
//! ```
//!
//! The target program declares the stub and calls it with that match ID
//! to get the captured value:
//!
//! ```c
//! #include "beeper/http2.h"
//!
//! volatile const u8 user_agent_mid;
//!
//! BEEPER_HTTP2_PARSE_MSG(parse_http2)
//! BEEPER_EXTRACT_MATCH_MSG(extract_http2_match)
//!
//! SEC("sk_msg")
//! int msg_verdict(struct sk_msg_md *msg) {
//!     struct http_parse_res pres = { 0 };
//!     struct http2_frame frame = { 0 };
//!     if (parse_http2(msg, &pres, &frame) < 0) return SK_PASS;
//!
//!     struct bytes user_agent = { 0 };
//!     if (extract_http2_match(msg, &pres, user_agent_mid, &user_agent) == 0) {
//!         // user_agent.ptr points to the user_agent.len bytes of the value
//!     }
//!
//!     return SK_PASS;
//! }
//! ```

use std::net::SocketAddr;

mod action;
mod hpack;
mod parser;
pub use parser::{AttachedParser, DynamicTableInfo, Parser};
use parser::ip4_addr;

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
