//! The shape of an HPACK header field representation, compiled into
//! transitions.
//!
//! A field is a sequence of integers and strings, and which one comes next is
//! decided by the bytes read so far, so it can be walked with the same
//! automaton as the field names themselves. Section 6 of RFC 7541 spells the
//! representations out.
//!
//! The value an integer carries lives on the transition rather than in the
//! state it leads to, which is what keeps the automaton small: every index a
//! representation can carry is a transition of its own, but all of them lead to
//! the same handful of states.
//!
//! The state ids and action kinds below must stay in sync with the `S_*` and
//! `H2A_*` constants of h2/parser.bpf.c.

use crate::{MatchId, StateId, h2::parser::types::h2_action};

/// A field name that matched no pattern.
pub const S_DEAD: StateId = StateId(2);

/// At the first byte of a field representation.
pub const S_FIELD: StateId = StateId(3);

/// At the first byte of the length of a field name.
pub const S_KEY_LEN: StateId = StateId(4);

/// At the first byte of the length of a field value.
pub const S_VAL_LEN: StateId = StateId(5);

/// The root of the trie of the field names to capture.
pub const S_NAME: StateId = StateId(6);

/// The continuation of the index of an indexed field.
pub const S_IDX7_CONT: StateId = StateId(7);

/// The continuation of the name index of a field that is added to the dynamic
/// table.
pub const S_IDX6_CONT: StateId = StateId(8);

/// The continuation of the name index of a field that is not.
pub const S_IDX4_CONT: StateId = StateId(9);

/// The continuation of a dynamic table size update.
pub const S_STG_CONT: StateId = StateId(10);

/// The continuation of the length of a field name.
pub const S_KEY_LEN_CONT: StateId = StateId(11);

/// The continuation of the length of a Huffman coded field name.
pub const S_KEY_LEN_CONT_HUFF: StateId = StateId(12);

/// The continuation of the length of a field value.
pub const S_VAL_LEN_CONT: StateId = StateId(13);

/// The continuation of the length of a Huffman coded field value.
pub const S_VAL_LEN_CONT_HUFF: StateId = StateId(14);

/// The number of state ids the ones above reserve.
pub const S_RESERVED: u16 = 15;

/// The string the action describes is Huffman coded.
pub const F_HUFF: u8 = 1 << 0;

/// The field the action describes is added to the dynamic table.
pub const F_ADD_DT: u8 = 1 << 1;

/// The integer the action describes is spread over several bytes, so the parser
/// takes it from its accumulator rather than from [`Action::val`].
pub const F_CONT: u8 = 1 << 2;

/// What the parser does upon taking a transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Kind {
    /// A field spelled out by nothing but an index, which addresses the entry
    /// both its name and its value are read from.
    Indexed = 1,

    /// A field whose name is an index and whose value is spelled out.
    IdxName,

    /// A field whose name is spelled out as well.
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

/// A single action of the automaton, as the BPF parser reads it.
///
/// `val` is an index, a length or a table size, depending on `kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Action {
    pub kind: Kind,
    pub val: u16,
    pub flags: u8,
}

impl Action {
    /// Returns the action of a transition of `kind` carrying `val`.
    pub const fn new(kind: Kind, val: u16, flags: u8) -> Action {
        Action { kind, val, flags }
    }

    /// Returns the action capturing the value of the field whose name the
    /// automaton just matched, under the id `cid`.
    pub const fn capture(mid: MatchId) -> Action {
        Action::new(Kind::Capture, mid.0, 0)
    }
}

impl From<Action> for h2_action {
    fn from(value: Action) -> Self {
        h2_action {
            val: value.val,
            kind: value.kind as u8,
            flags: value.flags,
        }
    }
}
