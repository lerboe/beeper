//! HTTP/1.1 parsing.
//!
//! [`Parser`] compiles the configured patterns into a DFA whose edges
//! are injected into the BPF parser program. The kernel walks the message
//! byte by byte, follows the edges and runs each action it encounters.

mod action;
mod parser;

pub use parser::AttachedParser;
pub use parser::Parser;
