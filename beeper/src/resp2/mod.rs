//! RESP2 parsing.
//!
//! RESP2 is the protocol Redis clients speak. A command is an array of bulk
//! strings, each of which is prefixed with its length:
//!
//! ```text
//! *3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n
//! ```
//!
//! A reply is a single value of one of these types, or an array of them:
//!
//! ```text
//! +OK\r\n  -ERR ...\r\n  :1\r\n  $5\r\nvalue\r\n  $-1\r\n
//! ```
//!
//! [`Parser`] compiles the shape of commands and replies into a DFA whose transition
//! table is injected into the BPF parser program. The kernel side walks the
//! array and the length of every bulk string, skips the string itself and
//! captures the ones it was configured to. Their contents are never walked, so
//! they may hold any byte, CRLF included. An array holds up to [`MAX_ARGS`]
//! elements of any of the types above; an array nested in another one is not
//! parsed.

mod parser;

pub use crate::dfa::parser::AttachedParser;
pub use parser::{MAX_ARGS, Parser, Resp2};
