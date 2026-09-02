use crate::StateId;
use std::{collections::HashMap, fmt::Debug, ops::RangeBounds};
use tracing::trace;

/// The state a message is parsed from. Only patterns that must appear at the
/// very beginning of a message are anchored here.
pub const INIT_STATE: StateId = StateId(0);

/// The state input that matches no pattern leads back to. Patterns that may
/// appear anywhere in the header block are anchored here.
pub const ANY_STATE: StateId = StateId(1);

/// The input a state matches any byte with. The parser only follows it if the
/// state has no transition for the byte it read.
const ANY_INPUT: u8 = '*' as u8;

/// A single transition of a [`Dfa`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Edge<A: PartialEq + Eq> {
    /// The state the transition leads to.
    to: StateId,

    /// The action it carries, if it carries one of its own rather than the one
    /// of the state it leads to.
    action: Option<A>,
}

/// Builds a single pattern into a [`Dfa`].
///
/// The builder walks the DFA from the state the pattern is anchored at,
/// inserting states and edges as it goes. Patterns share their states, so
/// pushing an input another pattern already pushed reuses its state instead of
/// creating a new one.
pub struct DfaBuilder<'a, A: Copy + Debug + PartialEq + Eq> {
    dfa: &'a mut Dfa<A>,

    /// The state the pattern has been built up to.
    state: StateId,

    /// Strings that may appear before the next input. They are only built into
    /// the DFA once that input is known, as each of them has to lead back to
    /// the state it branched off of.
    optional_prefixes: Vec<(String, bool)>,

    /// All edges that lead into [`DfaBuilder::state`].
    last_edges: Vec<(StateId, u8, bool)>,
}

impl<A: Copy + Debug + PartialEq + Eq> DfaBuilder<'_, A> {
    fn new(dfa: &mut Dfa<A>, state: StateId) -> DfaBuilder<'_, A> {
        DfaBuilder {
            dfa,
            state,
            optional_prefixes: Vec::new(),
            last_edges: Vec::new(),
        }
    }

    /// Attaches `action` to every transition that leads into the state the
    /// pattern has been built up to.
    pub fn with(&mut self, action: A) -> &mut Self {
        trace!("with; state={:?}, action={:?}", self.state, action);

        // an optional prefix loops back into the current state, so it is one of
        // the routes into it and has to carry the action too
        self.push_optional_prefixes();

        for (from, input, case_sensitive) in self.last_edges.clone() {
            if case_sensitive {
                self.dfa.add_action(from, input, action);
            } else {
                self.dfa
                    .add_action(from, input.to_ascii_lowercase(), action);
                self.dfa
                    .add_action(from, input.to_ascii_uppercase(), action);
            }
        }

        self
    }

    /// Builds the optional prefixes that were pushed since the last input, each
    /// of them leading back into the state the pattern has been built up to.
    fn push_optional_prefixes(&mut self) {
        let start = self.state;
        while let Some((optional, case_sensitive)) = self.optional_prefixes.pop() {
            let mut from = start;
            for (i, b) in optional.as_bytes().iter().enumerate() {
                let to = if i == optional.len() - 1 {
                    self.last_edges.push((from, *b, case_sensitive));
                    Some(start)
                } else {
                    None
                };

                from = self.push_edge_from(from, *b, to, case_sensitive);
            }
        }
    }

    /// Appends a single input to the pattern, first building the optional
    /// prefixes that were pushed since the last input.
    fn push_edge(&mut self, input: u8, to: Option<StateId>, case_sensitive: bool) {
        self.push_optional_prefixes();

        trace!(
            "push_edge; state={:?}, input={}, to={:?}",
            self.state,
            (input as char).escape_debug(),
            to
        );

        let start = self.state;
        self.state = self.push_edge_from(start, input, to, case_sensitive);
        self.last_edges = vec![(start, input, case_sensitive)];
    }

    /// Inserts an edge for both the lower and the upper case of `input`,
    /// carrying `action`, and returns the state they lead to. If `to` is
    /// `None`, the edge leads to the state the DFA already has for `input`, or
    /// to a new one.
    fn push_edge_from(
        &mut self,
        from: StateId,
        input: u8,
        to: Option<StateId>,
        case_sensitive: bool,
    ) -> StateId {
        let to = to.unwrap_or(self.dfa.next_state(&from, &input));

        self.dfa.insert_edge(from, input, to, None);
        if !case_sensitive {
            let other_case = if input.is_ascii_lowercase() {
                input.to_ascii_uppercase()
            } else {
                input.to_ascii_lowercase()
            };
            if other_case != input {
                self.dfa.insert_edge(from, other_case, to, None);
            }
        }

        to
    }

    /// Appends `input` to the pattern, one edge per character. Characters are
    /// matched case sensitively.
    pub fn push(&mut self, input: &str) -> &mut Self {
        self.push_inner(input.as_bytes(), true)
    }

    /// Same as [`push`], but accepts raw bytes.
    pub fn push_bytes(&mut self, input: &[u8]) -> &mut Self {
        self.push_inner(input, true)
    }

    /// Same as [`push`], but characters are matched case insensitively.
    pub fn push_ci(&mut self, input: &str) -> &mut Self {
        self.push_inner(input.as_bytes(), false)
    }

    pub fn push_inner(&mut self, input: &[u8], case_sensitive: bool) -> &mut Self {
        for b in input {
            self.push_edge(*b, None, case_sensitive);
        }
        self
    }

    /// Pushes the [`ANY_INPUT`] character onto the [`Dfa`]. `range`
    /// specifies the min and max amount of times any character may
    /// appear in the matched string.
    pub fn push_any<R: RangeBounds<usize>>(&mut self, range: R) -> &mut Self {
        let min_len = match range.start_bound() {
            std::ops::Bound::Excluded(n) => *&n.saturating_sub(1),
            std::ops::Bound::Included(n) => *n,
            std::ops::Bound::Unbounded => 0,
        };

        let max_len = match range.end_bound() {
            std::ops::Bound::Excluded(n) => *&n.saturating_sub(1),
            std::ops::Bound::Included(n) => *n,
            std::ops::Bound::Unbounded => min_len,
        };

        trace!(
            "push_any; state={:?}, min_len={:?}, max_len={:?}",
            self.state, min_len, max_len
        );

        for _ in 0..min_len {
            self.push_edge(ANY_INPUT, None, true);
        }

        // the following transitions are optional and must point to `self.state`
        for i in 1..max_len - min_len {
            let prefix = ANY_INPUT.to_string().repeat(i);
            self.optional_prefixes.push((prefix, true));
        }

        // the loop leads back into the state the repetition ends in, so it is
        // one of the routes into it
        if matches!(range.end_bound(), std::ops::Bound::Unbounded) {
            self.push_edge_from(self.state, ANY_INPUT, Some(self.state), true);
            self.last_edges.push((self.state, ANY_INPUT, true));
        }

        self
    }

    /// Same as [`push_options`], but case insensitive.
    pub fn push_options_ci(&mut self, inputs: &[&str]) -> &mut Self {
        self.push_options_inner(inputs, false)
    }

    pub fn push_options_inner(&mut self, inputs: &[&str], case_sensitive: bool) -> &mut Self {
        let Some(longest) = inputs.iter().copied().max_by_key(|input| input.len()) else {
            return self;
        };

        // the longest option is pushed normally, its final state is the one
        // all the other options have to end in as well
        let start = self.state;
        self.push_inner(longest.as_bytes(), case_sensitive);
        let final_state = self.state;

        // every option ends in the same state, so every one of them is a route
        // into it
        let mut last_edges = std::mem::take(&mut self.last_edges);

        trace!(
            "push_options; state={:?}, longest={}, final_state={:?}",
            start,
            longest.escape_debug(),
            final_state
        );

        for input in inputs.iter().copied().filter(|input| *input != longest) {
            assert!(!input.is_empty(), "Cannot push an empty option");

            self.state = start;
            for (i, b) in input.as_bytes().iter().enumerate() {
                let to = if i == input.len() - 1 {
                    Some(final_state)
                } else {
                    None
                };
                self.push_edge(*b, to, case_sensitive);
            }

            last_edges.append(&mut self.last_edges);
        }

        self.last_edges = last_edges;

        self
    }

    /// Appends `input` to the pattern, but allows it to be skipped.
    pub fn push_optional(&mut self, input: &str) -> &mut Self {
        self.optional_prefixes.push((input.to_string(), true));
        self
    }

    /// Matches the given input string but sets the final state
    /// to the state the DFA would be in if it started from [`ANY_STATE`].
    pub fn restart_with(&mut self, input: &str) {
        let final_state = input.as_bytes().iter().fold(ANY_STATE, |state, b| {
            // next state only inserts a state, we also have to ensure an edge exists
            let next = self.dfa.next_state(&state, &b);
            self.push_edge_from(state, *b, Some(next), false);
            next
        });

        trace!(
            "restart_with; input={}, final_state={:?}",
            input.escape_debug(),
            final_state
        );

        for (i, b) in input.as_bytes().iter().enumerate() {
            let to = if i == input.len() - 1 {
                Some(final_state)
            } else {
                None
            };
            self.push_edge(*b, to, false);
        }
    }
}

type EdgeMap<A> = HashMap<StateId, HashMap<u8, Edge<A>>>;

/// The DFA the patterns of a [`Parser`](super::Parser) are compiled into.
///
/// It is injected into the BPF parser program as a table of transitions,
/// indexed by state and input byte, which is why states are shared between
/// patterns wherever possible. A transition names the action it carries by the
/// index it is held under in [`Dfa::actions`], so that an action can say more
/// than the 16 bits of a transition have room for.
pub(crate) struct Dfa<A: Copy + Debug + PartialEq + Eq> {
    /// The number of states, including [`INIT_STATE`] and [`ANY_STATE`].
    num_states: u16,

    /// The transitions of the DFA, keyed by state and input.
    edges: EdgeMap<A>,
}

impl<A: Copy + Debug + PartialEq + Eq> Dfa<A> {
    /// Creates a DFA that holds nothing but [`INIT_STATE`] and [`ANY_STATE`].
    pub fn new() -> Dfa<A> {
        Dfa::with_reserved_states(2)
    }

    /// Creates a DFA that leaves the first `reserved` state ids to the caller.
    pub fn with_reserved_states(reserved: u16) -> Dfa<A> {
        Dfa {
            num_states: reserved.max(2),
            edges: HashMap::new(),
        }
    }

    /// Returns the number of states the DFA has, the reserved ones included.
    pub fn num_states(&self) -> u16 {
        self.num_states
    }

    /// Returns the number of edges the DFA has.
    pub fn num_edges(&self) -> usize {
        self.edges.len()
    }

    /// Starts a new pattern anchored at `state`, which the caller has to have
    /// reserved with [`Dfa::with_reserved_states`].
    pub fn start_pattern<'a>(&'a mut self, state: StateId) -> DfaBuilder<'a, A> {
        trace!("start_pattern; state={:?}", state);
        DfaBuilder::new(self, state)
    }

    /// Returns an unused state id.
    fn new_state(&mut self) -> StateId {
        let id = StateId(self.num_states);
        self.num_states = self.num_states.strict_add(1);
        id
    }

    /// Queries the edges to retrieve the next state from given state and
    /// input character. Creates a new state if none exists.
    fn next_state(&mut self, from: &StateId, input: &u8) -> StateId {
        self.edges
            .get(from)
            .and_then(|es| es.get(input).map(|edge| edge.to))
            .unwrap_or_else(|| self.new_state())
    }

    /// Inserts an edge from `from` to `to`, matching `input`.
    ///
    /// `action` is the action the edge carries itself, which a parser whose
    /// transitions mean more than the state they lead to needs; an edge without
    /// one runs the action of `to`.
    ///
    /// # Panics
    ///
    /// Panics if `from` already has an edge for `input` that leads somewhere
    /// else, as that would make the automaton non-deterministic, or if it
    /// carries an action `action` cannot be combined with.
    pub fn insert_edge(&mut self, from: StateId, input: u8, to: StateId, action: Option<A>) {
        let edges = self.edges.entry(from).or_default();
        let Some(old) = edges.get_mut(&input) else {
            let _ = edges.insert(input, Edge { to, action });
            return;
        };

        assert!(
            old.to == to,
            "Cannot create a transition from {from:?} to {:?} and {to:?}",
            old.to
        );

        // patterns share their transitions wherever they run alongside each
        // other, so one walking over a transition another already laid down
        // leaves the action on it alone
        match (old.action, action) {
            (_, None) => {}
            (None, Some(action)) => old.action = Some(action),
            (Some(old_action), Some(action)) => assert!(
                old_action == action,
                "Cannot {action:?} and {old_action:?} on the same transition"
            ),
        }
    }

    /// Adds an action to an existing edge.
    ///
    /// # Panics
    ///
    /// Panics if the edge does not exist, or already has an action assigned.
    fn add_action(&mut self, from: StateId, input: u8, action: A) {
        let Some(edges) = self.edges.get_mut(&from) else {
            panic!("State not found");
        };

        let Some(edge) = edges.get_mut(&input) else {
            panic!("Edge not found");
        };

        edge.action = Some(action);
    }

    /// Returns an iterator over the transitions of the DFA, each paired with
    /// the id of the action it carries: its own if it has one, and the one of
    /// the state it leads to otherwise.
    pub fn iter_transitions(&self) -> impl Iterator<Item = (StateId, u8, StateId, Option<A>)> + '_ {
        self.edges.iter().flat_map(move |(from, edges)| {
            edges
                .iter()
                .map(move |(input, edge)| (*from, *input, edge.to, edge.action))
        })
    }
}
