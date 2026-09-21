//! Application-layer parsing in eBPF.
//!
//! Beeper compiles a set of header patterns into a DFA, injects that DFA into
//! a pre-compiled BPF parser program and attaches the parser to another BPF
//! program with `freplace`. Messages are therefore parsed in the kernel, as
//! part of the program that uses the parser, and never have to be copied to
//! user space.
//!
//! The target program declares the functions it wants Beeper to provide with
//! the `BEEPER_*` macros of `beeper.h` and then names them in the [`h1`] or
//! [`h2`] builder:
//!
//! ```no_run
//! # fn main() -> anyhow::Result<()> {
//! # let prog_fd = 0;
//! use beeper::{MessageBuffer, h1, pseudo_header::PATH};
//!
//! let mut parser = h1::Parser::new();
//! let path = parser.capture_hdr(&PATH)?;
//!
//! let parser = parser
//!     .parse_fn("parse_h1", MessageBuffer::Msg)
//!     .extract_fn("extract_h1_match", MessageBuffer::Msg)
//!     .attach(prog_fd)?;
//! # Ok(())
//! # }
//! ```
//!
//! The value returned by `attach` owns the links to the attached programs, so
//! the parser stays in place until it is dropped.

pub(crate) use dfa::Dfa;
use httlib_huffman::EncoderError;
use std::fmt::Display;

mod dfa;

#[cfg(feature = "build")]
pub mod build;

#[cfg(feature = "h1")]
pub mod h1;

#[cfg(feature = "h2")]
pub mod h2;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MessageBuffer {
    Skb,
    Msg,
    DynPtr,
}

/// The ways configuring a parser can fail.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// The parser is already configured with as many captures as the parser
    /// program has room for. The limit is carried along.
    MatchLimitExceeded(usize),

    /// A header name could not be Huffman encoded, so there is no way to match
    /// it on the wire.
    InvalidEncoding(EncoderError),
}

impl std::error::Error for Error {}

impl From<EncoderError> for Error {
    fn from(err: EncoderError) -> Error {
        Error::InvalidEncoding(err)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::MatchLimitExceeded(limit) => {
                write!(f, "a parser captures at most {limit} ranges")
            }
            Error::InvalidEncoding(err) => {
                write!(f, "the header name cannot be Huffman encoded: {err}")
            }
        }
    }
}

/// One of the fields of a request or status line.
///
/// HTTP/2 carries them as pseudo-headers, HTTP/1.x as part of the first line
/// of a message. A `PseudoHeaderName` is spelled the way HTTP/2 puts it on the
/// wire, with the leading colon that tells it apart from a header field of the
/// same name, and addresses the same field in either protocol. The constants
/// of [`pseudo_header`] name the ones a parser understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PseudoHeaderName(&'static str);

impl PseudoHeaderName {
    /// Returns the field as HTTP/2 spells it, e.g. `:path`.
    pub const fn as_str(&self) -> &'static str {
        self.0
    }
}

impl AsRef<str> for PseudoHeaderName {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl AsRef<[u8]> for PseudoHeaderName {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// The names Beeper uses to address the fields of a request or status line,
/// see [`PseudoHeaderName`].
pub mod pseudo_header {
    use super::PseudoHeaderName;

    /// The method of a request, e.g. `GET`.
    pub const METHOD: PseudoHeaderName = PseudoHeaderName(":method");
    /// The path a request is addressed to, e.g. `/index.html`.
    pub const PATH: PseudoHeaderName = PseudoHeaderName(":path");
    /// The status code of a response, e.g. `200`.
    pub const STATUS: PseudoHeaderName = PseudoHeaderName(":status");
    /// The authority of a request, e.g. `example.com`.
    pub const AUTHORITY: PseudoHeaderName = PseudoHeaderName(":authority");
    /// The scheme of a request, e.g. `example.com`.
    pub const SCHEME: PseudoHeaderName = PseudoHeaderName(":scheme");
}

/// Identifies a state of the DFA.
///
/// State 0 is the state a message is parsed from, state 1 the one input that
/// matches no pattern leads back to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct StateId(u16);

/// Identifies a captured range in the parse result.
///
/// It is the index the target program passes to the functions replaced with
/// `Parser::matched_fn` and `Parser::extract_fn`. Captures are
/// numbered in the order in which they are configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MatchId(u8);

impl From<MatchId> for u8 {
    fn from(id: MatchId) -> u8 {
        id.0
    }
}
