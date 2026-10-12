//! The DFA of the DNS message format of
//! [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035#section-4).
//!
//! A message is a header followed by entries whose layout the DFA walks byte by
//! byte: names, label by label, and fields of a fixed width. Which entry comes
//! next, and how long a label, an RDATA or a TLV value is, follows from counts
//! and lengths the message carries. The runtime keeps track of them, guided by
//! the actions of the edges, and moves the DFA to the next entry.

use crate::{Dfa, StateId, dfa::Input, dns::action::*};

/// The record types whose RDATA the DFA walks, along with the address types
/// whose RDATA length it checks.
#[derive(Clone, Copy)]
enum Rdata {
    /// The RDATA is opaque.
    Opaque,

    /// The RDATA is a single name: NS, MD, MF, CNAME, MB, MG, MR and PTR.
    Name,

    /// A preference followed by a name.
    Mx,

    /// Two names.
    Minfo,

    /// Two names followed by five 32 bit fields.
    Soa,

    /// An IPv4 address, for the class IN.
    A,

    /// An IPv6 address, for the class IN.
    Aaaa,

    /// A sequence of TLVs.
    Opt,
}

/// The record types, by the lower byte of their type, whose upper one is 0.
const TYPES: [(u8, Rdata); 14] = [
    (1, Rdata::A),
    (2, Rdata::Name),
    (3, Rdata::Name),
    (4, Rdata::Name),
    (5, Rdata::Name),
    (6, Rdata::Soa),
    (7, Rdata::Name),
    (8, Rdata::Name),
    (9, Rdata::Name),
    (12, Rdata::Name),
    (14, Rdata::Minfo),
    (15, Rdata::Mx),
    (28, Rdata::Aaaa),
    (41, Rdata::Opt),
];

/// The class IN.
const CLASS_IN: u8 = 1;

/// The number of 32 bit fields that end the RDATA of an SOA record.
const SOA_FIELDS_LEN: usize = 5 * 4;

/// Collects the edges of the DFA while handing out the ids of its states.
struct Grammar {
    edges: Vec<(StateId, Input, StateId, Option<Action>)>,
    num_states: u16,
}

impl Grammar {
    fn new() -> Grammar {
        Grammar {
            edges: Vec::new(),
            num_states: S_RESERVED,
        }
    }

    /// Returns an unused state id.
    fn state(&mut self) -> StateId {
        let id = StateId(self.num_states);
        self.num_states += 1;
        id
    }

    fn edge(&mut self, from: StateId, input: u8, to: StateId, action: Option<Action>) {
        self.edges.push((from, Input::from(input), to, action));
    }

    /// Inserts an edge for every byte.
    fn any(&mut self, from: StateId, to: StateId, action: Option<Action>) {
        for input in 0..=u8::MAX {
            self.edge(from, input, to, action);
        }
    }

    /// Inserts the states of a name that starts in `start` and is followed by
    /// `next` (see
    /// [Section 4.1.4 of RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4)).
    /// `flags` go onto the transitions that end the name.
    ///
    /// The runtime skips the bytes of a label, so the DFA stays in `start` until
    /// the name ends in the root label or in a compression pointer.
    fn name_at(&mut self, start: StateId, next: StateId, flags: u8) {
        let ptr_lo = self.state();

        self.edge(start, 0, next, Some(Action::new(Kind::Root, 0, flags)));
        for len in 1..=0x3F {
            self.edge(
                start,
                len,
                start,
                Some(Action::new(Kind::Label, len as u16, 0)),
            );
        }

        // the `01` prefix of extended labels (RFC 6891 5) and the reserved `10`
        for input in 0x40..0xC0 {
            self.edge(start, input, StateId(0), Some(Action::new(Kind::Err, 0, 0)));
        }

        for input in 0xC0..=0xFF {
            let action = Action::new(Kind::PtrHi, (input & 0x3F) as u16, 0);
            self.edge(start, input, ptr_lo, Some(action));
        }

        self.any(ptr_lo, next, Some(Action::new(Kind::PtrLo, 0, flags)));
    }

    /// Same as [`Grammar::name_at`], in a state of its own.
    fn name(&mut self, next: StateId, flags: u8) -> StateId {
        let start = self.state();
        self.name_at(start, next, flags);
        start
    }

    /// Inserts the states of `len` bytes followed by `next`, the last one
    /// carrying `last`. The bytes before it carry `each`. Returns the state of
    /// each byte, in order.
    fn bytes(
        &mut self,
        len: usize,
        next: StateId,
        each: Option<Action>,
        last: Option<Action>,
    ) -> Vec<StateId> {
        let states: Vec<_> = (0..len).map(|_| self.state()).collect();
        for (i, from) in states.iter().enumerate() {
            let (to, action) = match states.get(i + 1) {
                Some(to) => (*to, each),
                None => (next, last),
            };
            self.any(*from, to, action);
        }

        states
    }

    /// Inserts the states of the `len` bytes of `field`, followed by `next`.
    /// Returns the state of each byte, in order.
    fn field(&mut self, len: usize, field: Field, flags: u8, next: StateId) -> Vec<StateId> {
        let acc = Some(Action::new(Kind::Acc, 0, 0));
        self.bytes(len, next, acc, Some(Action::store(field, flags)))
    }

    /// Inserts the states of the TTL, the RDATA length and the RDATA of a
    /// record of `rdata`, and returns the first state of the TTL.
    fn ttl_onward(&mut self, rdata: Rdata) -> StateId {
        let (rdlen, rdata) = match rdata {
            Rdata::Opaque => (Field::RdLenSkip, S_SKIP),
            Rdata::A => (Field::RdLenA, S_SKIP),
            Rdata::Aaaa => (Field::RdLenAaaa, S_SKIP),
            Rdata::Name => (Field::RdLen, self.name(S_SKIP, F_END)),
            Rdata::Mx => {
                let exchange = self.name(S_SKIP, F_END);
                (Field::RdLen, self.bytes(2, exchange, None, None)[0])
            }
            Rdata::Minfo => {
                let emailbx = self.name(S_SKIP, F_END);
                (Field::RdLen, self.name(emailbx, 0))
            }
            Rdata::Soa => {
                let end = Some(Action::new(Kind::Acc, 0, F_END));
                let fields = self.bytes(SOA_FIELDS_LEN, S_SKIP, None, end)[0];
                let rname = self.name(fields, 0);
                (Field::RdLen, self.name(rname, 0))
            }
            Rdata::Opt => (Field::RdLenTlv, S_TLV),
        };

        let rdlen = self.field(2, rdlen, 0, rdata)[0];
        self.field(4, Field::Ttl, 0, rdlen)[0]
    }

    /// Inserts the states of the class of an address record, whose RDATA
    /// length is only checked for the class IN, as the format of an address
    /// depends on the class. Any other class leads on to the states of an
    /// opaque record, `opaque_class` and `opaque_ttl`.
    fn address_class(
        &mut self,
        rdata: Rdata,
        opaque_class: &[StateId],
        opaque_ttl: StateId,
    ) -> StateId {
        let ttl = self.ttl_onward(rdata);

        let class = self.state();
        let class_lo = self.state();
        let acc = Some(Action::new(Kind::Acc, 0, 0));
        let store = Some(Action::store(Field::Class, 0));

        for input in 0..=u8::MAX {
            let to = if input == 0 {
                class_lo
            } else {
                opaque_class[1]
            };
            self.edge(class, input, to, acc);

            let to = if input == CLASS_IN { ttl } else { opaque_ttl };
            self.edge(class_lo, input, to, store);
        }

        class
    }

    fn into_dfa(self) -> Dfa<Action> {
        let mut dfa = Dfa::with_reserved_states(self.num_states);
        for (from, input, to, action) in self.edges {
            dfa.insert_edge(from, input, to, action);
        }
        dfa
    }
}

/// Builds the states and edges of a DNS message into a DFA.
pub fn dfa() -> Dfa<Action> {
    let mut g = Grammar::new();

    // the header, see section 4.1.1 of RFC 1035
    for k in 0..12u16 {
        let from = StateId(S_HDR.0 + k);
        let to = if k < 11 { StateId(from.0 + 1) } else { S_SKIP };
        g.any(from, to, Some(Action::new(Kind::Hdr, k, 0)));
    }

    // a question, see section 4.1.2 of RFC 1035
    let qclass = g.field(2, Field::QClass, F_END, S_SKIP)[0];
    let qtype = g.field(2, Field::QType, 0, qclass)[0];
    g.name_at(S_QNAME, qtype, 0);

    // a resource record, see section 4.1.3 of RFC 1035. The type picks how
    // the rest of it is laid out
    let opaque_ttl = g.ttl_onward(Rdata::Opaque);
    let opaque_class = g.field(2, Field::Class, 0, opaque_ttl);
    let mut classes = Vec::new();
    for (lo, rdata) in TYPES {
        let class = match rdata {
            Rdata::A | Rdata::Aaaa => g.address_class(rdata, &opaque_class, opaque_ttl),
            _ => {
                let ttl = g.ttl_onward(rdata);
                g.field(2, Field::Class, 0, ttl)[0]
            }
        };
        classes.push((lo, class));
    }

    let type_hi = g.state();
    let type_lo_zero = g.state();
    let type_lo = g.state();
    let acc = Some(Action::new(Kind::Acc, 0, 0));
    let store = Some(Action::store(Field::Type, 0));

    g.edge(type_hi, 0, type_lo_zero, acc);
    for input in 1..=u8::MAX {
        g.edge(type_hi, input, type_lo, acc);
    }

    g.any(type_lo, opaque_class[0], store);
    for input in 0..=u8::MAX {
        let class = classes
            .iter()
            .find(|(lo, _)| *lo == input)
            .map_or(opaque_class[0], |(_, class)| *class);
        g.edge(type_lo_zero, input, class, store);
    }

    g.name_at(S_RRNAME, type_hi, 0);

    // a TLV of an OPT record (RFC 6891 6.1.2) or a DSO message (RFC 8490 5.4).
    // The runtime skips its value, after which the next one starts
    let tlv_len = g.field(2, Field::TlvLen, 0, S_TLV)[0];
    let tlv_code_lo = g.bytes(1, tlv_len, None, None)[0];
    g.any(S_TLV, tlv_code_lo, None);

    g.into_dfa()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    type Edges = HashMap<(StateId, Input), (StateId, Option<Action>)>;

    fn edges() -> Edges {
        dfa()
            .iter_transitions()
            .map(|(from, input, to, action)| ((from, input), (to, action)))
            .collect()
    }

    /// Follows `input` from `state`, and returns the state it ends in along
    /// with the action of every edge it took. The bytes a [`Kind::Label`]
    /// announces are skipped, as the runtime does.
    fn walk(edges: &Edges, mut state: StateId, input: &[u8]) -> (StateId, Vec<Option<Action>>) {
        let mut actions = Vec::new();
        let mut i = 0;
        while i < input.len() {
            let (to, action) = edges[&(state, Input::from(input[i]))];
            if let Some(Action {
                kind: Kind::Label,
                val,
                ..
            }) = action
            {
                i += val as usize;
            }

            actions.push(action);
            state = to;
            i += 1;
        }

        (state, actions)
    }

    fn kinds(actions: &[Option<Action>]) -> Vec<Option<Kind>> {
        actions.iter().map(|a| a.map(|a| a.kind)).collect()
    }

    #[test]
    fn the_dfa_fits_the_parser() {
        let dfa = dfa();
        // MAX_STATES and MAX_ACTIONS of dns/parser.bpf.c, the latter of which
        // reserves an action for edges without one
        assert!(dfa.num_states() <= 256, "{} states", dfa.num_states());

        let mut actions: Vec<_> = dfa.iter_transitions().filter_map(|t| t.3).collect();
        actions.sort_by_key(|a| (a.kind as u8, a.val, a.flags));
        actions.dedup();
        assert!(actions.len() < 256, "{} actions", actions.len());
    }

    #[test]
    fn every_state_reads_every_byte() {
        let edges = edges();
        let mut states: Vec<_> = edges.keys().map(|(from, _)| *from).collect();
        states.sort_by_key(|s| s.0);
        states.dedup();

        for state in states {
            for input in 0..=u8::MAX {
                assert!(
                    edges.contains_key(&(state, Input::from(input))),
                    "{state:?} has no edge for {input}"
                );
            }
        }

        // the runtime moves on from these on its own
        assert!(!edges.contains_key(&(S_SKIP, 0)));
    }

    #[test]
    fn read_the_header() {
        let (state, actions) = walk(&edges(), S_HDR, &[0xAB; 12]);
        assert_eq!(state, S_SKIP);
        for (k, action) in actions.iter().enumerate() {
            assert_eq!(*action, Some(Action::new(Kind::Hdr, k as u16, 0)));
        }
    }

    #[test]
    fn read_a_question() {
        let edges = edges();
        let question = [3, b'w', b'w', b'w', 0, 0, 1, 0, 1];
        let (state, actions) = walk(&edges, S_QNAME, &question);

        assert_eq!(state, S_SKIP);
        assert_eq!(
            actions,
            [
                Some(Action::new(Kind::Label, 3, 0)),
                Some(Action::new(Kind::Root, 0, 0)),
                Some(Action::new(Kind::Acc, 0, 0)),
                Some(Action::store(Field::QType, 0)),
                Some(Action::new(Kind::Acc, 0, 0)),
                Some(Action::store(Field::QClass, F_END)),
            ]
        );
    }

    #[test]
    fn read_compression_pointers_and_reject_reserved_labels() {
        let edges = edges();

        let (_, actions) = walk(&edges, S_QNAME, &[1, b'a', 0xC1, 0x02]);
        assert_eq!(
            actions,
            [
                Some(Action::new(Kind::Label, 1, 0)),
                Some(Action::new(Kind::PtrHi, 1, 0)),
                Some(Action::new(Kind::PtrLo, 0, 0)),
            ]
        );

        for prefix in [0x40, 0x7F, 0x80, 0xBF] {
            let (_, actions) = walk(&edges, S_RRNAME, &[prefix]);
            assert_eq!(kinds(&actions), [Some(Kind::Err)]);
        }
    }

    /// The owner, type and class of a record, followed by its TTL and RDATA
    /// length, up to the action the RDATA length is stored with.
    fn rdlen_field(edges: &Edges, rtype: u16, class: u16) -> (StateId, Option<Action>) {
        let mut record = vec![0];
        record.extend(rtype.to_be_bytes());
        record.extend(class.to_be_bytes());
        record.extend([0, 0, 0, 0, 0, 4]);

        let (state, actions) = walk(edges, S_RRNAME, &record);
        (state, *actions.last().unwrap())
    }

    #[test]
    fn dispatch_on_the_type_of_a_record() {
        let edges = edges();
        let rdlen = |field| Some(Action::store(field, 0));

        assert_eq!(rdlen_field(&edges, 1, 1), (S_SKIP, rdlen(Field::RdLenA)));
        assert_eq!(
            rdlen_field(&edges, 28, 1),
            (S_SKIP, rdlen(Field::RdLenAaaa))
        );
        assert_eq!(
            rdlen_field(&edges, 41, 1232),
            (S_TLV, rdlen(Field::RdLenTlv))
        );
        assert_eq!(
            rdlen_field(&edges, 16, 1),
            (S_SKIP, rdlen(Field::RdLenSkip))
        );
        assert_eq!(
            rdlen_field(&edges, 0x0101, 1),
            (S_SKIP, rdlen(Field::RdLenSkip))
        );

        // the format of an address depends on the class
        assert_eq!(rdlen_field(&edges, 1, 3), (S_SKIP, rdlen(Field::RdLenSkip)));
        assert_eq!(
            rdlen_field(&edges, 1, 0x0101),
            (S_SKIP, rdlen(Field::RdLenSkip))
        );

        // the RDATA of these holds names the DFA walks
        for rtype in [2, 5, 6, 12, 14, 15] {
            let (state, action) = rdlen_field(&edges, rtype, 1);
            assert_eq!(action, rdlen(Field::RdLen), "type {rtype}");
            assert!(![S_SKIP, S_TLV].contains(&state), "type {rtype}");
        }
    }

    #[test]
    fn read_the_rdata_of_an_mx_record() {
        let edges = edges();
        let (state, _) = rdlen_field(&edges, 15, 1);

        let (state, actions) = walk(&edges, state, &[0, 10, 4, b'm', b'a', b'i', b'l', 0xC0, 12]);
        assert_eq!(state, S_SKIP);
        assert_eq!(
            kinds(&actions),
            [
                None,
                None,
                Some(Kind::Label),
                Some(Kind::PtrHi),
                Some(Kind::PtrLo)
            ]
        );
        assert_eq!(actions.last().unwrap().unwrap().flags, F_END);
    }

    #[test]
    fn read_tlvs() {
        let (state, actions) = walk(&edges(), S_TLV, &[0, 10, 0, 8]);
        assert_eq!(state, S_TLV);
        assert_eq!(
            actions,
            [
                None,
                None,
                Some(Action::new(Kind::Acc, 0, 0)),
                Some(Action::store(Field::TlvLen, 0)),
            ]
        );
    }
}
