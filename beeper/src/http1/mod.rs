//! HTTP/1.1 parsing.
//!
//! [`Parser`] compiles the configured patterns into a DFA whose edges
//! are injected into the BPF parser program. The kernel walks the message
//! byte by byte, follows the edges and runs each action it encounters.
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
//! use beeper::{MessageBuffer, http1};
//! use http::header::USER_AGENT;
//!
//! let mut parser = http1::Parser::new();
//! let user_agent_mid = parser.capture_hdr(&USER_AGENT)?;
//!
//! // e.g. open_skel.maps.rodata_data.as_mut().unwrap()
//! rodata.user_agent_mid = user_agent_mid.into();
//!
//! let parser = parser
//!     .parse_fn("parse_http1", MessageBuffer::Msg)
//!     .extract_fn("extract_http1_match", MessageBuffer::Msg)
//!     .attach(prog_fd)?;
//! # Ok(())
//! # }
//! ```
//!
//! The target program declares the stub and calls it with that match ID
//! to get the captured value:
//!
//! ```c
//! #include "beeper/http1.h"
//!
//! volatile const u8 user_agent_mid;
//!
//! BEEPER_HTTP1_PARSE_MSG(parse_http1)
//! BEEPER_EXTRACT_MATCH_MSG(extract_http1_match)
//!
//! SEC("sk_msg")
//! int msg_verdict(struct sk_msg_md *msg) {
//!     struct http_parse_res pres = { 0 };
//!     if (parse_http1(msg, &pres) < 0) return SK_PASS;
//!
//!     struct bytes user_agent = { 0 };
//!     if (extract_http1_match(msg, &pres, user_agent_mid, &user_agent) == 0) {
//!         // user_agent.ptr points to the user_agent.len bytes of the value
//!     }
//!
//!     return SK_PASS;
//! }
//! ```

mod action;
mod parser;

pub use parser::AttachedParser;
pub use parser::Parser;
