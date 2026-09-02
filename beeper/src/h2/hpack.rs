use crate::{Dfa, h2::action::*};
use std::collections::HashMap;

/// Builds the transitions of every field representation of RFC 7541 into
/// `dfa`, which has to have been created with [`S_RESERVED`] states reserved
/// for them.
pub(super) fn insert_representations(dfa: &mut Dfa<Action>) {
    insert_field_row(dfa);
    insert_length_rows(dfa);
    insert_continuation_rows(dfa);
}

/// Inserts the transitions of the first byte of a representation, see section 6
/// of RFC 7541.
fn insert_field_row(dfa: &mut Dfa<Action>) {
    let mut edge = |input: u8, to, action| dfa.insert_edge(S_FIELD, input, to, Some(action));

    // an indexed field, 7 bit prefix. The index 0 is not used
    edge(0x80, S_DEAD, Action::new(Kind::Err, 0, 0));
    for idx in 1..0x7F {
        edge(
            0x80 | idx as u8,
            S_FIELD,
            Action::new(Kind::Indexed, idx, 0),
        );
    }
    edge(0xFF, S_IDX7_CONT, Action::new(Kind::IntStart, 0x7F, 0));

    // a literal field that is added to the dynamic table, 6 bit prefix
    edge(0x40, S_KEY_LEN, Action::new(Kind::LitName, 0, F_ADD_DT));
    for idx in 1..0x3F {
        let action = Action::new(Kind::IdxName, idx, F_ADD_DT);
        edge(0x40 | idx as u8, S_VAL_LEN, action);
    }
    edge(0x7F, S_IDX6_CONT, Action::new(Kind::IntStart, 0x3F, 0));

    // a dynamic table size update, 5 bit prefix
    for size in 0..0x1F {
        edge(
            0x20 | size as u8,
            S_FIELD,
            Action::new(Kind::TableSize, size, 0),
        );
    }
    edge(0x3F, S_STG_CONT, Action::new(Kind::IntStart, 0x1F, 0));

    // a literal field that is not, either because it is never to be indexed or
    // because it is only not indexed here, 4 bit prefix. Beeper reads both the
    // same way
    for base in [0x00u8, 0x10] {
        edge(base, S_KEY_LEN, Action::new(Kind::LitName, 0, 0));
        for idx in 1..0x0F {
            edge(
                base | idx as u8,
                S_VAL_LEN,
                Action::new(Kind::IdxName, idx, 0),
            );
        }
        edge(
            base | 0x0F,
            S_IDX4_CONT,
            Action::new(Kind::IntStart, 0x0F, 0),
        );
    }
}

/// Inserts the transitions of the byte announcing the length of a name and of
/// the one announcing the length of a value, see section 5.2 of RFC 7541. Both
/// carry the Huffman bit in their top bit and a 7 bit prefix.
fn insert_length_rows(dfa: &mut Dfa<Action>) {
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
                let action = Action::new(kind, len, flags);
                dfa.insert_edge(from, base | len as u8, to, Some(action));
            }

            let action = Action::new(Kind::IntStart, 0x7F, 0);
            dfa.insert_edge(from, base | 0x7F, cont, Some(action));
        }
    }
}

/// Inserts the transitions of the bytes an integer that did not fit into the
/// prefix of its first byte is spread over, see section 5.1 of RFC 7541. The
/// top bit of every one of them says whether another follows.
fn insert_continuation_rows(dfa: &mut Dfa<Action>) {
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
            dfa.insert_edge(from, input, to, Some(action));

            let action = Action::new(Kind::IntCont, 0, 0);
            dfa.insert_edge(from, 0x80 | input, from, Some(action));
        }
    }
}

/// Returns the HPACK static table, split by whether an entry predefines a
/// value or not.
///
/// The first map goes from a field name to its index, the second from a field
/// name to the index of each of the values that are predefined for it. See
/// appendix A of RFC 7541.
pub fn create_header_maps() -> (
    HashMap<String, usize>,
    HashMap<String, HashMap<String, usize>>,
) {
    // HashMap for headers without values (header_name -> index)
    let mut headers_without_values = HashMap::new();

    // HashMap for headers with values (header_name -> (header_value -> index))
    let mut headers_with_values: HashMap<String, HashMap<String, usize>> = HashMap::new();

    // Headers without values
    headers_without_values.insert("authority".to_string(), 1);
    headers_without_values.insert("accept-charset".to_string(), 15);
    headers_without_values.insert("accept-language".to_string(), 17);
    headers_without_values.insert("accept-ranges".to_string(), 18);
    headers_without_values.insert("accept".to_string(), 19);
    headers_without_values.insert("access-control-allow-origin".to_string(), 20);
    headers_without_values.insert("age".to_string(), 21);
    headers_without_values.insert("allow".to_string(), 22);
    headers_without_values.insert("authorization".to_string(), 23);
    headers_without_values.insert("cache-control".to_string(), 24);
    headers_without_values.insert("content-disposition".to_string(), 25);
    headers_without_values.insert("content-encoding".to_string(), 26);
    headers_without_values.insert("content-language".to_string(), 27);
    headers_without_values.insert("content-length".to_string(), 28);
    headers_without_values.insert("content-location".to_string(), 29);
    headers_without_values.insert("content-range".to_string(), 30);
    headers_without_values.insert("content-type".to_string(), 31);
    headers_without_values.insert("cookie".to_string(), 32);
    headers_without_values.insert("date".to_string(), 33);
    headers_without_values.insert("etag".to_string(), 34);
    headers_without_values.insert("expect".to_string(), 35);
    headers_without_values.insert("expires".to_string(), 36);
    headers_without_values.insert("from".to_string(), 37);
    headers_without_values.insert("host".to_string(), 38);
    headers_without_values.insert("if-match".to_string(), 39);
    headers_without_values.insert("if-modified-since".to_string(), 40);
    headers_without_values.insert("if-none-match".to_string(), 41);
    headers_without_values.insert("if-range".to_string(), 42);
    headers_without_values.insert("if-unmodified-since".to_string(), 43);
    headers_without_values.insert("last-modified".to_string(), 44);
    headers_without_values.insert("link".to_string(), 45);
    headers_without_values.insert("location".to_string(), 46);
    headers_without_values.insert("max-forwards".to_string(), 47);
    headers_without_values.insert("proxy-authenticate".to_string(), 48);
    headers_without_values.insert("proxy-authorization".to_string(), 49);
    headers_without_values.insert("range".to_string(), 50);
    headers_without_values.insert("referer".to_string(), 51);
    headers_without_values.insert("refresh".to_string(), 52);
    headers_without_values.insert("retry-after".to_string(), 53);
    headers_without_values.insert("server".to_string(), 54);
    headers_without_values.insert("set-cookie".to_string(), 55);
    headers_without_values.insert("strict-transport-security".to_string(), 56);
    headers_without_values.insert("transfer-encoding".to_string(), 57);
    headers_without_values.insert("user-agent".to_string(), 58);
    headers_without_values.insert("vary".to_string(), 59);
    headers_without_values.insert("via".to_string(), 60);
    headers_without_values.insert("www-authenticate".to_string(), 61);

    // Headers with values
    // :method
    let mut method_map = HashMap::new();
    method_map.insert("GET".to_string(), 2);
    method_map.insert("POST".to_string(), 3);
    headers_with_values.insert("method".to_string(), method_map);

    // :path
    let mut path_map = HashMap::new();
    path_map.insert("/".to_string(), 4);
    path_map.insert("/index.html".to_string(), 5);
    headers_with_values.insert("path".to_string(), path_map);

    // :scheme
    let mut scheme_map = HashMap::new();
    scheme_map.insert("http".to_string(), 6);
    scheme_map.insert("https".to_string(), 7);
    headers_with_values.insert("scheme".to_string(), scheme_map);

    // :status
    let mut status_map = HashMap::new();
    status_map.insert("200".to_string(), 8);
    status_map.insert("204".to_string(), 9);
    status_map.insert("206".to_string(), 10);
    status_map.insert("304".to_string(), 11);
    status_map.insert("400".to_string(), 12);
    status_map.insert("404".to_string(), 13);
    status_map.insert("500".to_string(), 14);
    headers_with_values.insert("status".to_string(), status_map);

    // accept-encoding
    let mut accept_encoding_map = HashMap::new();
    accept_encoding_map.insert("gzip, deflate".to_string(), 16);
    headers_with_values.insert("accept-encoding".to_string(), accept_encoding_map);

    (headers_without_values, headers_with_values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StateId;
    use std::collections::HashSet;

    /// Returns a DFA holding nothing but the representations.
    fn representations() -> Dfa<Action> {
        let mut dfa = Dfa::with_reserved_states(S_RESERVED);
        insert_representations(&mut dfa);

        dfa
    }

    /// Returns the states a representation is walked with. `S_DEAD` and
    /// `S_NAME` are left out, as it is the patterns that give those their
    /// transitions.
    fn representation_states() -> Vec<StateId> {
        (S_FIELD.0..S_RESERVED)
            .map(StateId)
            .filter(|state| *state != S_NAME)
            .collect()
    }

    #[test]
    fn every_representation_state_reads_every_byte() {
        let dfa = representations();

        for state in representation_states() {
            let inputs: HashSet<u8> = dfa
                .iter_transitions()
                .filter(|(from, ..)| *from == state)
                .map(|(_, input, _, _)| input)
                .collect();

            assert_eq!(
                inputs.len(),
                256,
                "state {state:?} does not read every byte"
            );
        }
    }

    #[test]
    fn no_transition_leads_to_a_state_without_transitions() {
        let dfa = representations();
        let from: HashSet<StateId> = dfa.iter_transitions().map(|(from, ..)| from).collect();

        for (_, _, to, _) in dfa.iter_transitions() {
            assert!(
                to == S_DEAD || to == S_NAME || from.contains(&to),
                "state {to:?} leads nowhere"
            );
        }
    }

    #[test]
    fn every_representation_transition_carries_an_action_of_its_own() {
        let dfa = representations();
        let states = representation_states();

        for (from, input, _, action) in dfa.iter_transitions() {
            if !states.contains(&from) {
                continue;
            }

            assert!(
                action.is_some(),
                "the transition {input:#04x} takes out of {from:?} carries no action"
            );
        }
    }

    #[test]
    fn a_pattern_captures_where_it_ends() {
        let mut dfa = representations();
        dfa.start_pattern(S_NAME)
            .push_bytes(b"beep")
            .with(Action::capture(0));

        let captures: Vec<StateId> = dfa
            .iter_transitions()
            .filter(|(_, _, _, action)| action.is_some_and(|action| action.kind == Kind::Capture))
            .map(|(from, ..)| from)
            .collect();

        assert_eq!(
            captures.len(),
            1,
            "the capture is not on the last transition alone"
        );
    }
}
