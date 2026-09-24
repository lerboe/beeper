use crate::{
    Error, MatchId,
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
}

/// A parser for RESP2 commands.
///
/// The builder methods configure which arguments the parser captures and
/// which functions of the target program it replaces. Nothing is loaded into
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

    /// Configures the parser to walk a command of up to [`MAX_ARGS`] arguments
    /// and to stop behind its last one, so that the next command of a
    /// pipeline is left to a parse of its own.
    ///
    /// The DFA cannot count, so there is a pattern for every number of
    /// arguments. The length of a bulk string is read by the parser program
    /// instead, which skips the string rather than walking it, and captures it
    /// on the way if it was asked to.
    fn match_commands(&mut self) {
        let args = self.proto.args;
        for n in 1..=MAX_ARGS {
            let mut pattern = self.dfa.start_pattern(INIT_STATE);
            pattern.push("*").push(&n.to_string()).push(CRLF);

            for arg in &args[..n] {
                pattern
                    .push("$")
                    .push_any(1..)
                    .with(Action::LenDigit)
                    .push(CRLF)
                    .with(Action::Skip(*arg))
                    .push(CRLF);
            }

            pattern.with(Action::Done);
        }
    }

    /// Loads the configured parser and attaches it to the target program.
    ///
    /// Every function configured with [`Parser::parse_fn`],
    /// [`Parser::matched_fn`] or [`Parser::extract_fn`] is replaced in the
    /// target program, the remaining parser programs are left unloaded. The
    /// parser always stops behind the first command of a message, and reports
    /// the number of bytes it takes up.
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
        let mut ms = HashMap::new();
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
        (parser, mids)
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
    fn ignore_a_command_whose_length_is_no_number() {
        let (parser, _) = parser();
        assert_eq!(walk(&parser, b"*1\r\n$-1\r\n"), None);
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
        parser.match_commands();

        assert!(parser.dfa.num_states() <= MAX_STATES);
    }
}
