//! The DFA actions for [`http1::parser`].
//!
//! The actions reside on the edge of the DFA and are executed by the eBPF
//! runtime when it consumes the input associated with that edge.
//!
//! The kinds and flags below must stay in sync with the `HTTP1A_*` and `HTTP1F_*`
//! constants of http1/parser.bpf.c.

use crate::{MatchId, http1::parser::types::http1_action};

/// No-op action. The default.
const HTTP1A_NONE: u8 = 0;

/// Start capturing with the next byte.
const HTTP1A_START_CAPTURE: u8 = 1;

/// End capturing with the next byte.
const HTTP1A_END_CAPTURE: u8 = 2;

/// Terminate parsing and skipping the remainder of the message.
const HTTP1F_DONE: u8 = 1 << 0;

/// The DFA actions for [`http1::parser`], wrapped for convenience
/// in an enum for usage in [`Dfa`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// Starts capturing a range starting from the next byte. The
    /// resulting range is identified by the [`MatchId`].
    StartCapture(MatchId),

    /// Ends capturing a range ending with the next byte. The
    /// resulting range is identified by the [`MatchId`].
    EndCapture(MatchId),

    /// Terminates parsing and skips the remainder of the message.
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
