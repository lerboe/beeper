//! What a DFA parser does upon taking a transition.
//!
//! The kinds and flags below must stay in sync with the `DFAA_*` and `DFAF_*`
//! constants of dfa/parser.bpf.h.

use crate::MatchId;

/// The parser does nothing.
const DFAA_NONE: u8 = 0;

/// A capture starts at the byte behind the transition.
const DFAA_START_CAPTURE: u8 = 1;

/// The open capture ends at the byte the transition read.
const DFAA_END_CAPTURE: u8 = 2;

/// The byte the transition read is the next decimal digit of a length.
const DFAA_LEN_DIGIT: u8 = 3;

/// The bytes behind the transition are skipped, as many as the length read so
/// far says.
const DFAA_SKIP: u8 = 4;

/// Parsing is complete, the rest of the message is not to be parsed.
const DFAF_DONE: u8 = 1 << 0;

/// The bytes a [`DFAA_SKIP`] skips are captured.
const DFAF_CAPTURE: u8 = 1 << 1;

/// The action a transition of a DFA parser carries.
///
/// A transition either opens or closes a capture, reads a length or skips as
/// many bytes as it says, and may on top of that end the parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// Starts capturing a range, which begins at the byte behind the
    /// transition and is identified by the capture id.
    StartCapture(MatchId),

    /// Ends the capture the id names at the byte the transition read.
    EndCapture(MatchId),

    /// Terminates parsing.
    Done,

    /// Ends capturing a range and terminates parsing.
    EndCaptureAndDone(MatchId),

    /// Reads the byte of the transition as the next decimal digit of a length.
    LenDigit,

    /// Skips as many bytes behind the transition as the length read so far
    /// says, without walking the DFA over them, and captures them under the
    /// match id if there is one.
    Skip(Option<MatchId>),
}

impl Action {
    /// Returns the kind, the flags and the match id the parser program encodes
    /// the action with.
    pub(crate) fn encode(self) -> (u8, u8, u8) {
        match self {
            Action::Done => (DFAA_NONE, DFAF_DONE, 0),
            Action::StartCapture(mid) => (DFAA_START_CAPTURE, 0, mid.0),
            Action::EndCapture(mid) => (DFAA_END_CAPTURE, 0, mid.0),
            Action::EndCaptureAndDone(mid) => (DFAA_END_CAPTURE, DFAF_DONE, mid.0),
            Action::LenDigit => (DFAA_LEN_DIGIT, 0, 0),
            Action::Skip(None) => (DFAA_SKIP, 0, 0),
            Action::Skip(Some(mid)) => (DFAA_SKIP, DFAF_CAPTURE, mid.0),
        }
    }
}
