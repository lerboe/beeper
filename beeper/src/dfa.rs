use crate::{Action, CaptureId, MatchId, StateId};
use std::{collections::HashMap, ops::RangeBounds};
use tracing::trace;

/// The state a message is parsed from. Only patterns that must appear at the
/// very beginning of a message are anchored here.
const INIT_STATE: StateId = StateId(0);

/// The state input that matches no pattern leads back to. Patterns that may
/// appear anywhere in the header block are anchored here.
const ANY_STATE: StateId = StateId(1);

/// The input a state matches any byte with. The parser only follows it if the
/// state has no transition for the byte it read.
const ANY_INPUT: char = '*';

/// Builds a single pattern into a [`Dfa`].
///
/// The builder walks the DFA from the state the pattern is anchored at,
/// inserting states and edges as it goes. Patterns share their states, so
/// pushing an input another pattern already pushed reuses its state instead of
/// creating a new one.
pub struct DfaBuilder<'a> {
    dfa: &'a mut Dfa,

    /// The state the pattern has been built up to.
    state: StateId,

    /// Strings that may appear before the next input. They are only built into
    /// the DFA once that input is known, as each of them has to lead back to
    /// the state it branched off of.
    optional_prefixes: Vec<(String, bool)>,

    /// The capture the next input starts, if any.
    start_capture: Option<CaptureId>,

    /// The capture [`DfaBuilder::end_capturing`] closes, if a capture is open.
    end_capture: Option<CaptureId>,
}

impl DfaBuilder<'_> {
    fn new(dfa: &mut Dfa, state: StateId) -> DfaBuilder<'_> {
        DfaBuilder {
            dfa,
            state,
            optional_prefixes: Vec::new(),
            start_capture: None,
            end_capture: None,
        }
    }

    /// Appends a single input to the pattern, first building the optional
    /// prefixes that were pushed since the last input and starting a capture if
    /// one is pending.
    fn push_edge(&mut self, input: char, to: Option<StateId>, case_sensitive: bool) {
        let start = self.state;
        while let Some((optional, case_sensitive)) = self.optional_prefixes.pop() {
            let mut from = start;
            for (i, c) in optional.char_indices() {
                let to = if i == optional.len() - 1 {
                    Some(start)
                } else {
                    None
                };
                from = self.push_edge_from(from, c, to, case_sensitive);
            }
        }

        if let Some(id) = self.start_capture.take() {
            trace!("start_capturing; state={:?}, cid={:?} ", self.state, id);

            // [`INIT_STATE`] is never entered, so a capture anchored there cannot
            // run an action. It doesn't have to: its start index is 0, which is
            // what the parser initializes every capture to.
            if self.state != INIT_STATE {
                self.dfa.add_action(self.state, Action::StartCapture(id));
            }
            self.end_capture = Some(id);
        }

        trace!(
            "push_edge; state={:?}, input={}, to={:?}",
            self.state,
            input.escape_debug(),
            to
        );

        self.state = self.push_edge_from(start, input, to, case_sensitive);
    }

    /// Inserts an edge for both the lower and the upper case of `input` and
    /// returns the state they lead to. If `to` is `None`, the edge leads to the
    /// state the DFA already has for `input`, or to a new one.
    fn push_edge_from(
        &mut self,
        from: StateId,
        input: char,
        to: Option<StateId>,
        case_sensitive: bool,
    ) -> StateId {
        let to = to.unwrap_or(self.dfa.next_state(&from, &input));

        self.dfa.insert_edge(from, input, to);
        if !case_sensitive {
            let other_case = if input.is_lowercase() {
                input.to_ascii_uppercase()
            } else {
                input.to_ascii_lowercase()
            };
            if other_case != input {
                self.dfa.insert_edge(from, other_case, to);
            }
        }

        to
    }

    /// Appends `input` to the pattern, one edge per character. Characters are
    /// matched case sensitively.
    pub fn push(&mut self, input: &str) -> &mut Self {
        self.push_inner(input, true)
    }

    /// Same as [`push`], but characters are matched case insensitively.
    pub fn push_ci(&mut self, input: &str) -> &mut Self {
        self.push_inner(input, false)
    }

    pub fn push_inner(&mut self, input: &str, case_sensitive: bool) -> &mut Self {
        for c in input.chars() {
            self.push_edge(c, None, case_sensitive);
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

        if matches!(range.end_bound(), std::ops::Bound::Unbounded) {
            self.push_edge_from(self.state, ANY_INPUT, Some(self.state), true);
        }

        self
    }

    /// Pushes one branch per input onto the [`Dfa`]. One of the branches
    /// must be matched case sensitively for the [`Dfa`] to reach a final state.
    pub fn push_options(&mut self, inputs: &[&str]) -> &mut Self {
        self.push_options_inner(inputs, true)
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
        self.push_inner(longest, case_sensitive);
        let final_state = self.state;

        trace!(
            "push_options; state={:?}, longest={}, final_state={:?}",
            start,
            longest.escape_debug(),
            final_state
        );

        for input in inputs.iter().copied().filter(|input| *input != longest) {
            assert!(!input.is_empty(), "Cannot push an empty option");

            self.state = start;
            for (i, c) in input.char_indices() {
                let to = if i == input.len() - 1 {
                    Some(final_state)
                } else {
                    None
                };
                self.push_edge(c, to, case_sensitive);
            }
        }

        self
    }

    /// Appends `input` to the pattern, but allows it to be skipped.
    pub fn push_optional(&mut self, input: &str) -> &mut Self {
        self.optional_prefixes.push((input.to_string(), true));
        self
    }

    /// Same as [`push_optional`], but case-insensitive.
    pub fn push_optional_ci(&mut self, input: &str) -> &mut Self {
        self.optional_prefixes.push((input.to_string(), false));
        self
    }

    /// Starts capturing at the next input pushed onto the pattern.
    ///
    /// # Panics
    ///
    /// Panics if a capture has already been started but not yet pushed.
    pub fn start_capturing(&mut self) -> &mut Self {
        assert!(self.start_capture.is_none());
        let cid = self.dfa.new_capture();

        self.start_capture = Some(cid);

        self
    }

    /// Ends the open capture at the last input pushed onto the pattern and
    /// turns the captured range into a match.
    ///
    /// # Panics
    ///
    /// Panics if no capture has been started.
    pub fn end_capturing(&mut self) -> &mut Self {
        let cid = self.end_capture.take().expect("No capture started");
        let mid = self.dfa.new_match();
        trace!(
            "end_capturing; state={:?}, cid={:?} mid={:?}",
            self.state, cid, mid
        );

        self.dfa
            .add_action(self.state, Action::EndCapture(cid, mid));

        self
    }

    /// Matches the given input string but sets the final state
    /// to the state the DFA would be in if it started from [`ANY_STATE`].
    pub fn restart_with(&mut self, input: &str) {
        let final_state = input.chars().fold(ANY_STATE, |state, c| {
            // next state only inserts a state, we also have to ensure an edge exists
            let next = self.dfa.next_state(&state, &c);
            self.push_edge_from(state, c, Some(next), false);
            next
        });

        trace!(
            "restart_with; input={}, final_state={:?}",
            input.escape_debug(),
            final_state
        );

        for (i, c) in input.char_indices() {
            let to = if i == input.len() - 1 {
                Some(final_state)
            } else {
                None
            };
            self.push_edge(c, to, false);
        }
    }

    /// Terminates parsing once the pattern has been matched.
    pub fn done(&mut self) {
        self.dfa.add_action(self.state, Action::Done);
    }
}

type EdgeMap = HashMap<StateId, HashMap<char, StateId>>;
type ActionMap = HashMap<StateId, Action>;

/// The DFA the patterns of a [`Parser`](super::Parser) are compiled into.
///
/// It is injected into the BPF parser program as a table of transitions,
/// indexed by state and input byte, which is why states are shared between
/// patterns wherever possible.
pub(crate) struct Dfa {
    /// The number of captures handed out so far.
    num_captures: u16,

    /// The number of matches handed out so far.
    num_matches: u16,

    /// The number of states, including [`INIT_STATE`] and [`ANY_STATE`].
    num_states: u16,

    /// The transitions of the DFA, keyed by state and input.
    edges: EdgeMap,

    /// The action a state runs when it is entered.
    actions: ActionMap,
}

impl Dfa {
    /// Creates a DFA that holds nothing but [`INIT_STATE`] and [`ANY_STATE`].
    pub fn new() -> Dfa {
        Dfa {
            num_captures: 0,
            num_matches: 0,
            num_states: 2,
            edges: HashMap::new(),
            actions: HashMap::new(),
        }
    }

    /// Starts a new pattern.
    ///
    /// A `status_line` pattern is anchored at [`INIT_STATE`] and therefore only
    /// matches at the very beginning of a message, any other pattern is
    /// anchored at [`ANY_STATE`] and may match anywhere in the header block.
    pub fn start_pattern<'a>(&'a mut self, status_line: bool) -> DfaBuilder<'a> {
        trace!("start_pattern; status_line={:?}", status_line);
        let state = if status_line { INIT_STATE } else { ANY_STATE };
        DfaBuilder::new(self, state)
    }

    /// Returns an unused state id.
    fn new_state(&mut self) -> StateId {
        let id = StateId(self.num_states);
        self.num_states += 1;
        id
    }

    /// Returns an unused capture id.
    fn new_capture(&mut self) -> CaptureId {
        let id = CaptureId(self.num_captures);
        self.num_captures += 1;
        id
    }

    /// Returns an unused match id.
    fn new_match(&mut self) -> MatchId {
        let id = MatchId(self.num_matches);
        self.num_matches += 1;
        id
    }

    /// Queries the edges to retrieve the next state from given state and
    /// input character. Creates a new state if none exists.
    fn next_state(&mut self, from: &StateId, input: &char) -> StateId {
        self.edges
            .get(from)
            .and_then(|es| es.get(input).map(|to| *to))
            .unwrap_or_else(|| self.new_state())
    }

    /// Inserts an edge from `from` to `to`, matching `input`.
    ///
    /// # Panics
    ///
    /// Panics if `from` already has an edge for `input` that leads somewhere
    /// else, as that would make the automaton non-deterministic.
    fn insert_edge(&mut self, from: StateId, input: char, to: StateId) {
        if let Some(to_old) = self.edges.entry(from).or_default().insert(input, to) {
            assert!(
                to_old == to,
                "Cannot create a transition from {from:?} to {to_old:?} and {to:?}"
            );
        }
    }

    /// Attaches `action` to `state`, combining it with the action the state
    /// already carries.
    ///
    /// # Panics
    ///
    /// Panics if the two actions cannot be combined, see [`Action::push`].
    fn add_action(&mut self, state: StateId, action: Action) {
        let action = match self.actions.get(&state) {
            Some(action_old) => action_old
                .push(action)
                .unwrap_or_else(|err| panic!("Cannot add {action:?} to {state:?}: {err}")),
            None => action,
        };

        self.actions.insert(state, action);
    }

    /// Returns an iterator over the edges of the DFA, each paired with the
    /// action of the state it leads to.
    pub fn iter_transitions<'a>(
        &'a self,
    ) -> impl Iterator<Item = (&'a StateId, &'a StateId, &'a char, Option<Action>)> {
        self.edges.iter().flat_map(move |(from, edges)| {
            edges.iter().map(move |(input, to)| {
                let action = self.actions.get(to).copied();
                (from, to, input, action)
            })
        })
    }
}
