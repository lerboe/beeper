//! The DFA actions for [`http2::Parser`].
//!
//! The actions reside on the edge of the DFA and are executed by the eBPF
//! runtime when it consumes the input associated with that edge.
//!
//! The state ids and action kinds below must stay in sync with the `S_*` and
//! `HTTP2A_*` constants of http2/parser.bpf.c.

use crate::{MatchId, StateId, http2::parser::types::http2_action};

/// Fallback state when no header field matched.
pub const S_DEAD: StateId = StateId(2);

/// State marking the first byte of a field.
pub const S_FIELD: StateId = StateId(3);

/// State marking the first byte of a field length.
pub const S_KEY_LEN: StateId = StateId(4);

/// State marking the first byte of a field value.
pub const S_VAL_LEN: StateId = StateId(5);

/// The root of the trie of the field names to capture, as they read Huffman
/// coded.
pub const S_NAME: StateId = StateId(6);

/// Continuation of the index of an indexed field.
pub const S_IDX7_CONT: StateId = StateId(7);

/// Continuation of the name index of a field that is added to the dynamic
/// table.
pub const S_IDX6_CONT: StateId = StateId(8);

/// Continuation of the name index of a field that is not.
pub const S_IDX4_CONT: StateId = StateId(9);

/// Continuation of a dynamic table size update.
pub const S_STG_CONT: StateId = StateId(10);

/// Continuation of the length of a field name.
pub const S_KEY_LEN_CONT: StateId = StateId(11);

/// Continuation of the length of a Huffman coded field name.
pub const S_KEY_LEN_CONT_HUFF: StateId = StateId(12);

/// Continuation of the length of a field value.
pub const S_VAL_LEN_CONT: StateId = StateId(13);

/// Continuation of the length of a Huffman coded field value.
pub const S_VAL_LEN_CONT_HUFF: StateId = StateId(14);

/// The root of the trie of the field names to capture, as they read when they
/// are not Huffman coded.
pub const S_NAME_PLAIN: StateId = StateId(15);

/// Number of reserved states (see definitions above).
pub const S_RESERVED: u16 = 16;

/// Boolean indicating that the string is Huffman-encoded.
pub const F_HUFF: u8 = 1 << 0;

/// Boolean indicating that the string should be cached in the
/// dynamic table.
pub const F_ADD_DT: u8 = 1 << 1;

/// Boolean indicating that the integer continues in the next
/// byte.
pub const F_CONT: u8 = 1 << 2;

/// The different kinds of [`Action`]s.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Kind {
    /// Indexed header field representation
    Indexed = 1,

    /// Literal header field -- indexed name.
    IdxName,

    /// Literal header field -- new name.
    LitName,

    /// The length of a field name.
    KeyLen,

    /// The length of a field value.
    ValLen,

    /// A dynamic table size update.
    TableSize,

    /// The first byte of an integer that does not fit into the prefix of that
    /// byte, carrying the prefix maximum the integer is counted from.
    IntStart,

    /// A byte of such an integer that is not its last one either.
    IntCont,

    /// The name of the field being read just matched a pattern.
    Capture,

    /// The representation is malformed.
    Err,
}

/// The DFA actions for [`http2::Parser`], wrapped for convenience
/// in an struct for usage in [`Dfa`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Action {
    pub kind: Kind,
    pub val: u16,
    pub flags: u8,
}

impl Action {
    /// Returns the action of an edge of `kind` carrying `val`.
    pub const fn new(kind: Kind, val: u16, flags: u8) -> Action {
        Action { kind, val, flags }
    }

    /// Returns the action capturing the value of the field whose name the
    /// DFA just matched, identified by the match id `mid`.
    pub const fn capture(mid: MatchId) -> Action {
        Action::new(Kind::Capture, mid.0 as u16, 0)
    }
}

impl From<Action> for http2_action {
    /// Converts the Rust-based [`Action`] into the eBPF-based `http2_action`.
    fn from(value: Action) -> Self {
        http2_action {
            val: value.val,
            kind: value.kind as u8,
            flags: value.flags,
        }
    }
}
