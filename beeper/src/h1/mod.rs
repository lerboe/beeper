//! HTTP/1.x parsing.
//!
//! [`Parser`] compiles the configured patterns into a DFA whose transition
//! table is injected into the BPF parser program. The kernel side walks a
//! message byte by byte, follows the table and runs the action of every state it
//! enters, which is what turns a pattern into a captured range.

mod parser;

pub use parser::AttachedParser;
pub use parser::Parser;
