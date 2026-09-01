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

use std::collections::HashMap;

/// A field name that matched no pattern.
const S_DEAD: u16 = 2;

/// At the first byte of a field representation.
const S_FIELD: u16 = 3;

/// At the first byte of the length of a field name.
const S_KEY_LEN: u16 = 4;

/// At the first byte of the length of a field value.
const S_VAL_LEN: u16 = 5;

/// The root of the trie of the field names to capture.
pub(super) const S_NAME: u16 = 6;

/// The continuation of the index of an indexed field.
const S_IDX7_CONT: u16 = 7;

/// The continuation of the name index of a field that is added to the dynamic
/// table.
const S_IDX6_CONT: u16 = 8;

/// The continuation of the name index of a field that is not.
const S_IDX4_CONT: u16 = 9;

/// The continuation of a dynamic table size update.
const S_STG_CONT: u16 = 10;

/// The continuation of the length of a field name.
const S_KEY_LEN_CONT: u16 = 11;

/// The continuation of the length of a Huffman coded field name.
const S_KEY_LEN_CONT_HUFF: u16 = 12;

/// The continuation of the length of a field value.
const S_VAL_LEN_CONT: u16 = 13;

/// The continuation of the length of a Huffman coded field value.
const S_VAL_LEN_CONT_HUFF: u16 = 14;

/// The number of state ids the ones above reserve.
pub(super) const S_RESERVED: u16 = 15;

/// The string the action describes is Huffman coded.
const F_HUFF: u8 = 1 << 0;

/// The field the action describes is added to the dynamic table.
const F_ADD_DT: u8 = 1 << 1;

/// The integer the action describes is spread over several bytes, so the parser
/// takes it from its accumulator rather than from [`Action::val`].
const F_CONT: u8 = 1 << 2;

/// What the parser does upon taking a transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum Kind {
    /// Nothing.
    None,

    /// A field spelled out by nothing but an index, which addresses the entry
    /// both its name and its value are read from.
    Indexed,

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

impl Kind {
    /// Returns the number the BPF parser identifies the kind by.
    fn id(self) -> u8 {
        match self {
            Kind::None => 0,
            Kind::Indexed => 1,
            Kind::IdxName => 2,
            Kind::LitName => 3,
            Kind::KeyLen => 4,
            Kind::ValLen => 5,
            Kind::TableSize => 6,
            Kind::IntStart => 7,
            Kind::IntCont => 8,
            Kind::Capture => 9,
            Kind::Err => 10,
        }
    }
}

/// A single action of the automaton, as the BPF parser reads it.
///
/// `val` is an index, a length or a table size, depending on `kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct Action {
    pub kind: Kind,
    pub val: u16,
    pub flags: u8,
}

impl Action {
    /// The action of a transition that does nothing.
    pub const NONE: Action = Action {
        kind: Kind::None,
        val: 0,
        flags: 0,
    };

    /// Returns the action of a transition of `kind` carrying `val`.
    const fn new(kind: Kind, val: u16, flags: u8) -> Action {
        Action { kind, val, flags }
    }

    /// Returns the action capturing the value of the field whose name the
    /// automaton just matched, under the id `cid`.
    pub const fn capture(cid: u16) -> Action {
        Action::new(Kind::Capture, cid, 0)
    }

    /// Returns the kind and flags the BPF parser reads the action with.
    pub fn encode(&self) -> (u8, u8) {
        (self.kind.id(), self.flags)
    }
}

/// A single transition, as the BPF parser reads it out of its table.
#[derive(Clone, Copy, Debug)]
pub(super) struct Edge {
    pub from: u16,
    pub input: u8,
    pub to: u16,

    /// The index of the entry of the action table the transition carries.
    pub action: u16,
}

/// The transitions and actions the BPF parser is injected with.
///
/// Actions are interned, so the transitions of an index and those of a length
/// only take up as many entries as there are distinct values they can carry.
pub(super) struct Table {
    edges: Vec<Edge>,
    actions: Vec<Action>,
    interned: HashMap<Action, u16>,
}

impl Table {
    /// Creates a table holding the transitions of every representation of RFC
    /// 7541, ready to take the field name patterns.
    pub fn new() -> Table {
        let mut table = Table {
            edges: Vec::new(),
            actions: Vec::new(),
            interned: HashMap::new(),
        };

        let none = table.intern(Action::NONE);
        assert_eq!(none, 0, "the action of a transition that has none is 0");

        table.push_field_row();
        table.push_length_rows();
        table.push_continuation_rows();

        table
    }

    /// Returns the transitions of the automaton.
    pub fn edges(&self) -> &[Edge] {
        &self.edges
    }

    /// Returns the actions the transitions carry, indexed by [`Edge::action`].
    pub fn actions(&self) -> &[Action] {
        &self.actions
    }

    /// Returns the index of the entry `action` is held under, adding it if the
    /// table does not carry it yet.
    fn intern(&mut self, action: Action) -> u16 {
        if let Some(idx) = self.interned.get(&action) {
            return *idx;
        }

        let idx = self.actions.len() as u16;
        self.actions.push(action);
        let _ = self.interned.insert(action, idx);

        idx
    }

    /// Appends the transition `input` takes from `from` to `to`.
    pub fn push_edge(&mut self, from: u16, input: u8, to: u16, action: Action) {
        let action = self.intern(action);
        self.edges.push(Edge {
            from,
            input,
            to,
            action,
        });
    }

    /// Appends the transitions of the first byte of a representation, see
    /// section 6 of RFC 7541.
    fn push_field_row(&mut self) {
        // an indexed field, 7 bit prefix. The index 0 is not used
        self.push_edge(S_FIELD, 0x80, S_DEAD, Action::new(Kind::Err, 0, 0));
        for idx in 1..0x7F {
            let input = 0x80 | idx as u8;
            self.push_edge(S_FIELD, input, S_FIELD, Action::new(Kind::Indexed, idx, 0));
        }
        self.push_edge(S_FIELD, 0xFF, S_IDX7_CONT, Action::new(Kind::IntStart, 0x7F, 0));

        // a literal field that is added to the dynamic table, 6 bit prefix
        self.push_edge(
            S_FIELD,
            0x40,
            S_KEY_LEN,
            Action::new(Kind::LitName, 0, F_ADD_DT),
        );
        for idx in 1..0x3F {
            let input = 0x40 | idx as u8;
            let action = Action::new(Kind::IdxName, idx, F_ADD_DT);
            self.push_edge(S_FIELD, input, S_VAL_LEN, action);
        }
        self.push_edge(S_FIELD, 0x7F, S_IDX6_CONT, Action::new(Kind::IntStart, 0x3F, 0));

        // a dynamic table size update, 5 bit prefix
        for size in 0..0x1F {
            let input = 0x20 | size as u8;
            self.push_edge(S_FIELD, input, S_FIELD, Action::new(Kind::TableSize, size, 0));
        }
        self.push_edge(S_FIELD, 0x3F, S_STG_CONT, Action::new(Kind::IntStart, 0x1F, 0));

        // a literal field that is not, either because it is never to be indexed
        // or because it is only not indexed here, 4 bit prefix. Beeper reads
        // both the same way
        for base in [0x00u8, 0x10] {
            self.push_edge(S_FIELD, base, S_KEY_LEN, Action::new(Kind::LitName, 0, 0));
            for idx in 1..0x0F {
                let input = base | idx as u8;
                let action = Action::new(Kind::IdxName, idx, 0);
                self.push_edge(S_FIELD, input, S_VAL_LEN, action);
            }
            let input = base | 0x0F;
            self.push_edge(S_FIELD, input, S_IDX4_CONT, Action::new(Kind::IntStart, 0x0F, 0));
        }
    }

    /// Appends the transitions of the byte announcing the length of a name and
    /// of the one announcing the length of a value, see section 5.2 of RFC
    /// 7541. Both carry the Huffman bit in their top bit and a 7 bit prefix.
    fn push_length_rows(&mut self) {
        let rows = [
            (
                S_KEY_LEN,
                Kind::KeyLen,
                S_NAME,
                S_KEY_LEN_CONT,
                S_KEY_LEN_CONT_HUFF,
            ),
            (
                S_VAL_LEN,
                Kind::ValLen,
                S_FIELD,
                S_VAL_LEN_CONT,
                S_VAL_LEN_CONT_HUFF,
            ),
        ];

        for (from, kind, to, cont, cont_huff) in rows {
            for (base, flags, cont) in [(0x00u8, 0, cont), (0x80u8, F_HUFF, cont_huff)] {
                for len in 0..0x7F {
                    let input = base | len as u8;
                    self.push_edge(from, input, to, Action::new(kind, len, flags));
                }

                let input = base | 0x7F;
                self.push_edge(from, input, cont, Action::new(Kind::IntStart, 0x7F, 0));
            }
        }
    }

    /// Appends the transitions of the bytes an integer that did not fit into
    /// the prefix of its first byte is spread over, see section 5.1 of RFC
    /// 7541. The top bit of every one of them says whether another follows.
    fn push_continuation_rows(&mut self) {
        let rows = [
            (S_IDX7_CONT, Kind::Indexed, S_FIELD, 0),
            (S_IDX6_CONT, Kind::IdxName, S_VAL_LEN, F_ADD_DT),
            (S_IDX4_CONT, Kind::IdxName, S_VAL_LEN, 0),
            (S_STG_CONT, Kind::TableSize, S_FIELD, 0),
            (S_KEY_LEN_CONT, Kind::KeyLen, S_NAME, 0),
            (S_KEY_LEN_CONT_HUFF, Kind::KeyLen, S_NAME, F_HUFF),
            (S_VAL_LEN_CONT, Kind::ValLen, S_FIELD, 0),
            (S_VAL_LEN_CONT_HUFF, Kind::ValLen, S_FIELD, F_HUFF),
        ];

        for (from, kind, to, flags) in rows {
            for input in 0..0x80u8 {
                let action = Action::new(kind, 0, flags | F_CONT);
                self.push_edge(from, input, to, action);
                self.push_edge(from, 0x80 | input, from, Action::new(Kind::IntCont, 0, 0));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Returns the states the structure is walked with. `S_DEAD` and `S_NAME`
    /// are left out, as the patterns are what gives those their transitions.
    fn structure_states() -> Vec<u16> {
        (S_FIELD..S_RESERVED).filter(|s| *s != S_NAME).collect()
    }

    #[test]
    fn every_structure_state_has_a_transition_for_every_byte() {
        let table = Table::new();

        for state in structure_states() {
            let inputs: HashSet<u8> = table
                .edges()
                .iter()
                .filter(|edge| edge.from == state)
                .map(|edge| edge.input)
                .collect();

            assert_eq!(inputs.len(), 256, "state {state} does not read every byte");
        }
    }

    #[test]
    fn no_state_reads_a_byte_twice() {
        let table = Table::new();
        let mut seen = HashSet::new();

        for edge in table.edges() {
            assert!(
                seen.insert((edge.from, edge.input)),
                "state {} reads {:#04x} twice",
                edge.from,
                edge.input
            );
        }
    }

    #[test]
    fn no_transition_leads_to_a_state_without_transitions() {
        let table = Table::new();
        let from: HashSet<u16> = table.edges().iter().map(|edge| edge.from).collect();

        for edge in table.edges() {
            assert!(
                edge.to == S_DEAD || edge.to == S_NAME || from.contains(&edge.to),
                "state {} leads nowhere",
                edge.to
            );
        }
    }

    #[test]
    fn the_action_of_a_transition_without_one_is_zero() {
        let table = Table::new();
        assert_eq!(table.actions()[0], Action::NONE);
    }

    #[test]
    fn actions_are_interned() {
        let table = Table::new();
        let unique: HashSet<Action> = table.actions().iter().copied().collect();

        assert_eq!(unique.len(), table.actions().len());
    }
}
