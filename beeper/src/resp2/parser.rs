use crate::{
    Error, MatchId, StateId,
    dfa::{
        INIT_STATE,
        action::Action,
        parser::{self as dfa_parser, AttachedParser, load_parser_program},
    },
};

// the skeleton refers to libbpf by the name of the crate xbpf wraps
use xbpf::libbpf as libbpf_rs;

const CRLF: &str = "\r\n";

/// The number of arguments a command may have, the command's name included,
/// for the parser to parse it.
pub const MAX_ARGS: usize = 8;

/// What a [`Parser`] keeps track of while it is being configured.
#[derive(Default)]
pub struct Resp2 {
    /// The match id of every argument captured so far, by its position in the
    /// command.
    args: [Option<MatchId>; MAX_ARGS],

    /// The match id of the payload of a reply, if it is captured.
    reply: Option<MatchId>,
}

/// A parser for RESP2 commands and replies.
///
/// The builder methods configure which arguments and replies the parser
/// captures and which functions of the target program it replaces. Nothing is loaded into
/// the kernel until [`Parser::attach`] is called.
pub type Parser = dfa_parser::Parser<Resp2>;

xbpf::include_bpf!("resp2/parser");
load_parser_program!("RESP2");

impl Parser {
    /// Configures the parser to capture an argument of a command.
    ///
    /// Arguments are addressed by their position in the command, whatever the
    /// command is: the name of the command is argument 0, the key of a `GET`
    /// or a `SET` argument 1 and the value of a `SET` argument 2. A command
    /// that has no argument at `idx` captures nothing for it.
    ///
    /// # Arguments
    ///
    /// * `idx` - The position of the argument in the command
    ///
    /// # Errors
    ///
    /// Returns an error if `idx` is not below [`MAX_ARGS`], or if the parser
    /// already captures as many arguments as the parser program has room for.
    ///
    /// # Returns
    ///
    /// The match ID that can be used in eBPF to extract the captured value. An
    /// argument that is already captured keeps the ID it was given the first
    /// time, rather than being captured a second time under a new one.
    pub fn capture_arg(&mut self, idx: usize) -> Result<MatchId, Error> {
        if idx >= MAX_ARGS {
            return Err(Error::ArgLimitExceeded(MAX_ARGS));
        }

        if let Some(mid) = self.proto.args[idx] {
            return Ok(mid);
        }

        let mid = self.new_match()?;
        self.proto.args[idx] = Some(mid);

        Ok(mid)
    }

    /// Configures the parser to capture the payload of a reply.
    ///
    /// The payload is what a simple string (`+OK`), an error (`-ERR ...`), an
    /// integer (`:1`) or a bulk string (`$5\r\nvalue`) carries, without its
    /// type, its length or its CRLF. The type is the first byte of the
    /// message. A null bulk string (`$-1`) captures nothing.
    ///
    /// A reply that is an array is walked like a command, so its elements are
    /// captured with [`Parser::capture_arg`].
    ///
    /// # Errors
    ///
    /// Returns an error if the parser already captures as many ranges as the
    /// parser program has room for.
    ///
    /// # Returns
    ///
    /// The match ID that can be used in eBPF to extract the captured value. It
    /// is the same every time the method is called.
    pub fn capture_reply(&mut self) -> Result<MatchId, Error> {
        if let Some(mid) = self.proto.reply {
            return Ok(mid);
        }

        let mid = self.new_match()?;
        self.proto.reply = Some(mid);

        Ok(mid)
    }

    /// Configures the parser to walk a reply that is a single element, or no
    /// element at all, and to stop behind it. See [`Parser::match_commands`]
    /// for the ones that are arrays.
    fn match_replies(&mut self) {
        self.push_element(INIT_STATE, self.proto.reply, true);

        // a null array and an empty array carry nothing. Their `-` and `0`
        // are spelled out, as the length of an array is
        for empty in ["*-1", "*0"] {
            self.dfa
                .start_pattern(INIT_STATE)
                .push(empty)
                .push(CRLF)
                .with(Action::Done);
        }
    }

    /// Configures the parser to walk an array of up to [`MAX_ARGS`] elements,
    /// be it a command or a reply, and to stop behind its last one, so that
    /// the next one of a pipeline is left to a parse of its own.
    ///
    /// The DFA cannot count, so there is a pattern for every number of
    /// elements, and one for every element of it.
    fn match_commands(&mut self) {
        let args = self.proto.args;
        for n in 1..=MAX_ARGS {
            let mut pattern = self.dfa.start_pattern(INIT_STATE);
            pattern.push("*").push(&n.to_string()).push(CRLF);

            let mut slot = pattern.state();
            for (i, arg) in args[..n].iter().enumerate() {
                slot = self.push_element(slot, *arg, i == n - 1);
            }
        }
    }

    /// Configures the parser to walk an element that begins in `slot`: a
    /// bulk string, a null bulk string, a simple string, an error or an
    /// integer. Its payload is captured under `mid`, if there is one, and with
    /// `done` the parse ends behind it.
    ///
    /// The length of a bulk string is read by the parser program, which skips
    /// the string rather than walking it. The payload of the other elements is
    /// not prefixed with its length, so it runs up to the CRLF.
    ///
    /// # Returns
    ///
    /// The state behind the element, which every kind of it leads into.
    fn push_element(&mut self, slot: StateId, mid: Option<MatchId>, done: bool) -> StateId {
        let mut pattern = self.dfa.start_pattern(slot);
        pattern
            .push("$")
            .push_any(1..)
            .with(Action::LenDigit)
            .push(CRLF)
            .with(Action::Skip(mid))
            .push(CRLF);
        if done {
            pattern.with(Action::Done);
        }

        let next = pattern.state();

        // the `-` is no digit, but spelled out, which the length above only
        // reads if nothing else matches
        let mut pattern = self.dfa.start_pattern(slot);
        pattern.push("$-1").push_to(CRLF, next);
        if done {
            pattern.with(Action::Done);
        }

        let mut pattern = self.dfa.start_pattern(slot);
        pattern.push_options_ci(&["+", "-", ":"]);
        if let Some(mid) = mid {
            pattern.with(Action::StartCapture(mid));
        }

        pattern.push_any(1..);
        if let Some(mid) = mid {
            pattern.with(Action::EndCapture(mid));
        }

        pattern.push_to(CRLF, next);
        if done {
            pattern.with(Action::Done);
        }

        next
    }

    /// Loads the configured parser and attaches it to the target program.
    ///
    /// Every function configured with [`Parser::parse_fn`],
    /// [`Parser::matched_fn`] or [`Parser::extract_fn`] is replaced in the
    /// target program, the remaining parser programs are left unloaded. The
    /// parser always stops behind the first command or reply of a message,
    /// and reports the number of bytes it takes up.
    ///
    /// # Arguments
    ///
    /// * `target` - The file descriptor of the target program to attach to
    ///
    /// # Errors
    ///
    /// Returns an error if the parser cannot be loaded, or if one of the
    /// functions it should replace does not exist in the target program with a
    /// matching signature.
    pub fn attach(mut self, target: i32) -> Result<AttachedParser, Error> {
        self.match_commands();
        self.match_replies();
        load(&self, target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dfa::{ANY_INPUT, ANY_STATE, parser::MAX_MATCHES};
    use std::collections::HashMap;

    /// Walks the DFA of `parser` over `msg` the way dfa/parser.bpf.h does, and
    /// returns the number of bytes it consumed along with the range captured
    /// for each match id, or `None` if it was not done by the end of `msg`.
    fn walk(parser: &Parser, msg: &[u8]) -> Option<(usize, HashMap<MatchId, Vec<u8>>)> {
        let trans: HashMap<_, _> = parser
            .dfa
            .iter_transitions()
            .map(|(from, input, to, action)| ((from, input), (to, action)))
            .collect();
        let next = |s, c: u8| {
            trans
                .get(&(s, c as u16))
                .or_else(|| trans.get(&(s, ANY_INPUT)))
                .copied()
        };

        let (mut s, mut len, mut skip) = (INIT_STATE, 0usize, 0usize);
        let (mut ms, mut starts) = (HashMap::new(), HashMap::new());
        for (i, &c) in msg.iter().enumerate() {
            if skip > 0 {
                skip -= 1;
                continue;
            }

            let (to, action) = next(s, c)
                .or_else(|| next(ANY_STATE, c))
                .unwrap_or((ANY_STATE, None));
            s = to;

            match action {
                Some(Action::LenDigit) if !c.is_ascii_digit() => {
                    (s, len) = (ANY_STATE, 0);
                }
                Some(Action::LenDigit) => len = len * 10 + (c - b'0') as usize,
                Some(Action::Skip(mid)) => {
                    skip = std::mem::take(&mut len);
                    if let Some(mid) = mid {
                        ms.insert(mid, msg[i + 1..i + 1 + skip].to_vec());
                    }
                }
                Some(Action::StartCapture(mid)) => _ = starts.insert(mid, i + 1),
                Some(Action::EndCapture(mid)) => {
                    _ = ms.insert(mid, msg[starts[&mid]..=i].to_vec());
                }
                Some(Action::Done) => return Some((i + 1, ms)),
                None => {}
                Some(action) => panic!("unexpected action {action:?}"),
            }
        }

        None
    }

    /// Encodes `args` as the array of bulk strings a client sends.
    fn cmd(args: &[&[u8]]) -> Vec<u8> {
        let mut msg = format!("*{}\r\n", args.len()).into_bytes();
        for arg in args {
            msg.extend(format!("${}\r\n", arg.len()).bytes());
            msg.extend(*arg);
            msg.extend(b"\r\n");
        }
        msg
    }

    /// Returns a parser capturing the first three arguments, ready to attach.
    fn parser() -> (Parser, [MatchId; 3]) {
        let mut parser = Parser::new();
        let mids = [0, 1, 2].map(|i| parser.capture_arg(i).expect("capture argument"));
        parser.match_commands();
        parser.match_replies();
        (parser, mids)
    }

    /// Returns a parser capturing the payload of a reply, ready to attach.
    fn reply_parser() -> (Parser, MatchId) {
        let mut parser = Parser::new();
        let mid = parser.capture_reply().expect("capture reply");
        parser.match_commands();
        parser.match_replies();
        (parser, mid)
    }

    #[test]
    fn capture_the_payload_of_every_reply_that_carries_one() {
        let (parser, mid) = reply_parser();
        let replies: [(&[u8], &[u8]); 5] = [
            (b"+OK\r\n", b"OK"),
            (b"-ERR unknown command\r\n", b"ERR unknown command"),
            (b":-42\r\n", b"-42"),
            (b"$5\r\nva\r\nl\r\n", b"va\r\nl"),
            (b"$0\r\n\r\n", b""),
        ];

        for (reply, payload) in replies {
            let (len, ms) = walk(&parser, reply).expect("done");
            assert_eq!(len, reply.len());
            assert_eq!(ms[&mid], payload, "{}", String::from_utf8_lossy(reply));
        }
    }

    #[test]
    fn walk_replies_that_carry_nothing() {
        let (parser, mid) = reply_parser();
        for reply in [b"$-1\r\n".as_slice(), b"*-1\r\n", b"*0\r\n"] {
            let (len, ms) = walk(&parser, reply).expect("done");
            assert_eq!(len, reply.len());
            assert!(!ms.contains_key(&mid));
        }
    }

    #[test]
    fn stop_behind_the_first_reply_of_a_pipeline() {
        let (parser, mid) = reply_parser();
        let (len, ms) = walk(&parser, b"+OK\r\n$5\r\nvalue\r\n").expect("done");
        assert_eq!(len, 5);
        assert_eq!(ms[&mid], b"OK");
    }

    #[test]
    fn capture_the_elements_of_an_array_reply_as_arguments() {
        let (parser, mids) = parser();
        let (_, ms) = walk(&parser, &cmd(&[b"a", b"b"])).expect("done");
        assert_eq!(ms[&mids[0]], b"a");
        assert_eq!(ms[&mids[1]], b"b");
    }

    #[test]
    fn walk_a_command_and_capture_its_arguments() {
        let (parser, mids) = parser();
        let msg = cmd(&[b"SET", b"key", b"value"]);

        let (len, ms) = walk(&parser, &msg).expect("done");
        assert_eq!(len, msg.len());
        assert_eq!(ms[&mids[0]], b"SET");
        assert_eq!(ms[&mids[1]], b"key");
        assert_eq!(ms[&mids[2]], b"value");
    }

    #[test]
    fn stop_behind_the_first_command_of_a_pipeline() {
        let (parser, mids) = parser();
        let get = cmd(&[b"GET", b"key"]);
        let msg = [get.clone(), cmd(&[b"SET", b"key", b"value"])].concat();

        let (len, ms) = walk(&parser, &msg).expect("done");
        assert_eq!(len, get.len());
        assert_eq!(ms[&mids[1]], b"key");
        assert!(!ms.contains_key(&mids[2]));
    }

    #[test]
    fn skip_arguments_that_hold_any_byte() {
        let (parser, mids) = parser();
        let value = b"\r\n*1\r\n$0\r\n\r\n";
        let msg = cmd(&[b"SET", b"", value]);

        let (len, ms) = walk(&parser, &msg).expect("done");
        assert_eq!(len, msg.len());
        assert_eq!(ms[&mids[1]], b"");
        assert_eq!(ms[&mids[2]], value);
    }

    #[test]
    fn walk_commands_of_up_to_max_args_arguments() {
        let (parser, _) = parser();
        for n in 1..=MAX_ARGS {
            let args = vec![b"arg".as_slice(); n];
            let msg = cmd(&args);
            assert_eq!(walk(&parser, &msg).map(|(len, _)| len), Some(msg.len()));
        }

        let args = vec![b"arg".as_slice(); MAX_ARGS + 1];
        assert_eq!(walk(&parser, &cmd(&args)), None);
    }

    #[test]
    fn capture_the_elements_of_an_array_reply_of_any_simple_kind() {
        let (parser, mids) = parser();
        let reply = b"*3\r\n+OK\r\n-ERR no\r\n:1\r\n";

        let (len, ms) = walk(&parser, reply).expect("done");
        assert_eq!(len, reply.len());
        assert_eq!(ms[&mids[0]], b"OK");
        assert_eq!(ms[&mids[1]], b"ERR no");
        assert_eq!(ms[&mids[2]], b"1");
    }

    #[test]
    fn capture_nothing_for_a_null_element() {
        let (parser, mids) = parser();
        let reply = b"*3\r\n$1\r\na\r\n$-1\r\n$1\r\nc\r\n";

        let (len, ms) = walk(&parser, reply).expect("done");
        assert_eq!(len, reply.len());
        assert_eq!(ms[&mids[0]], b"a");
        assert!(!ms.contains_key(&mids[1]));
        assert_eq!(ms[&mids[2]], b"c");
    }

    #[test]
    fn ignore_a_nested_array() {
        let (parser, _) = parser();
        assert_eq!(walk(&parser, b"*1\r\n*1\r\n:1\r\n"), None);
    }

    #[test]
    fn ignore_a_command_whose_length_is_no_number() {
        let (parser, _) = parser();
        assert_eq!(walk(&parser, b"*1\r\n$x\r\n"), None);
    }

    #[test]
    fn ignore_an_inline_command() {
        let (parser, _) = parser();
        assert_eq!(walk(&parser, b"SET key value\r\n"), None);
    }

    #[test]
    fn a_parser_captures_at_most_max_args_arguments() {
        let mut parser = Parser::new();
        for i in 0..MAX_ARGS {
            let mid = parser.capture_arg(i).expect("capture argument");
            assert_eq!(u8::from(mid) as usize, i);
        }

        assert!(matches!(
            parser.capture_arg(MAX_ARGS),
            Err(Error::ArgLimitExceeded(limit)) if limit == MAX_ARGS
        ));
    }

    #[test]
    fn the_same_argument_is_captured_under_one_match_id() {
        let mut parser = Parser::new();
        let first = parser.capture_arg(1).expect("capture argument");
        let second = parser.capture_arg(1).expect("capture argument again");

        assert_eq!(first, second);
    }

    #[test]
    fn the_commands_fit_into_the_parser_program() {
        // must stay in sync with `MAX_STATES` of dfa/parser.bpf.h
        const MAX_STATES: u16 = 512;

        let mut parser = Parser::new();
        for i in 0..MAX_ARGS.min(MAX_MATCHES as usize) {
            parser.capture_arg(i).expect("capture argument");
        }
        parser.capture_reply().expect("capture reply");
        parser.match_commands();
        parser.match_replies();

        let num_states = parser.dfa.num_states();
        assert!(num_states <= MAX_STATES, "{num_states} states");
    }
}
