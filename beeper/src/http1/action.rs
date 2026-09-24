//! What the HTTP/1.x parser does upon taking a transition.
//!
//! The kinds and flags below must stay in sync with the `HTTP1A_*` and `HTTP1F_*`
//! constants of http1/parser.bpf.c.

use crate::{MatchId, http1::parser::types::http1_action};

/// The parser does nothing.
const HTTP1A_NONE: u8 = 0;

/// A capture starts at the byte behind the transition.
const HTTP1A_START_CAPTURE: u8 = 1;

/// The open capture ends at the byte the transition read.
const HTTP1A_END_CAPTURE: u8 = 2;

/// Parsing is complete, the rest of the message is not a header anymore.
const HTTP1F_DONE: u8 = 1 << 0;

/// The action a transition of the HTTP/1.x parser carries.
///
/// A transition either opens or closes a capture, and may on top of that end
/// the parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// Starts capturing a range, which begins at the byte behind the
    /// transition and is identified by the capture id.
    StartCapture(MatchId),

    /// Ends the capture the first id names at the byte the transition read, and
    /// reports the range it covers under the match id the second one names.
    EndCapture(MatchId),

    /// Terminates parsing.
    Done,

    /// Ends capturing a range and terminates parsing.
    EndCaptureAndDone(MatchId),
}

impl From<Action> for http1_action {
    fn from(value: Action) -> Self {
        let (kind, flags, mid) = match value {
            Action::Done => (HTTP1A_NONE, HTTP1F_DONE, 0),
            Action::StartCapture(mid) => (HTTP1A_START_CAPTURE, 0, mid.0),
            Action::EndCapture(mid) => (HTTP1A_END_CAPTURE, 0, mid.0),
            Action::EndCaptureAndDone(mid) => (HTTP1A_END_CAPTURE, HTTP1F_DONE, mid.0),
        };

        http1_action { kind, flags, mid }
    }
}
