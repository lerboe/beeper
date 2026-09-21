#![allow(unused_imports)]
use crate::{
    Dfa, Error, MatchId, MessageBuffer,
    dfa::{ANY_STATE, INIT_STATE, fmt_input},
    h1::action::Action,
    pseudo_header::{METHOD, PATH, STATUS},
};
use anyhow::{Result, bail};
use http::HeaderName;
use std::{collections::HashMap, mem::MaybeUninit};
use tracing::{Level, debug, trace, warn};
use types::*;
use xbpf::libbpf::{
    self as libbpf_rs, Link, MapCore, OpenObject,
    skel::{OpenSkel, Skel, SkelBuilder},
};

const CR: &str = "\r";
const LF: &str = "\n";

/// The number of ranges a parser can be configured to capture. Must stay in
/// sync with `MAX_MATCHES` of beeper.h.
const MAX_MATCHES: u8 = 32;

/// A parser for HTTP/1.x messages.
///
/// The builder methods configure which fields the parser captures and which
/// functions of the target program it replaces. Nothing is loaded into the
/// kernel until [`Parser::attach`] is called.
pub struct Parser {
    /// The patterns configured so far, compiled into a DFA.
    dfa: Dfa<Action>,

    /// The number of matches occuring in the patterns.
    num_matches: u8,

    /// The parse function name for each message buffer.
    parse_fns: HashMap<MessageBuffer, String>,

    /// The matched function name. It is agnostic to the message buffer.
    matched_fn: Option<String>,

    /// The extract function name for each message buffer.
    extract_fns: HashMap<MessageBuffer, String>,

    /// The match id of every header captured so far, lowercased as the parser
    /// matches it, so that a header asked for twice is captured once.
    captures: HashMap<String, MatchId>,
}

xbpf::include_bpf!("h1/parser");

#[allow(dead_code)]
impl Parser {
    /// Creates a new HTTP/1.1 parser.
    ///
    /// Additional configuration must be done through the builder methods before calling `attach`.
    pub fn new() -> Parser {
        Parser {
            dfa: Dfa::new(),
            num_matches: 0,
            parse_fns: HashMap::new(),
            matched_fn: None,
            extract_fns: HashMap::new(),
            captures: HashMap::new(),
        }
    }

    /// Specifies the function template in the target program to be replaced with an HTTP/1.1
    /// parser. The function will not be replaced until `attach` is called.
    ///
    /// # Arguments
    ///
    /// * `parse_fn` - The name of the function to replace in the target program
    /// * `msg_buf` - The type of buffer to parse
    pub fn parse_fn<S: ToString>(mut self, parse_fn: S, msg_buf: MessageBuffer) -> Parser {
        self.parse_fns.insert(msg_buf, parse_fn.to_string());
        self
    }

    /// Specifies the function template in the target program to be called when a pattern match
    /// is completed. The function will not be replaced until `attach` is called.
    ///
    /// # Arguments
    ///
    /// * `matched_fn` - The name of the matched callback function in the target program
    pub fn matched_fn<S: ToString>(mut self, matched_fn: S) -> Parser {
        self.matched_fn = Some(matched_fn.to_string());
        self
    }

    /// Specifies the function template in the target program to be called when extracting
    /// matched content. The function will not be replaced until `attach` is called.
    ///
    /// # Arguments
    ///
    /// * `extract_fn` - The name of the extract callback function in the target program
    /// * `msg_buf` - The type of buffer to extract the match from
    pub fn extract_fn<S: ToString>(mut self, extract_fn: S, msg_buf: MessageBuffer) -> Parser {
        self.extract_fns.insert(msg_buf, extract_fn.to_string());
        self
    }

    /// Returns an unused match id.
    ///
    /// # Errors
    ///
    /// Returns an error if the parser is already configured with
    /// [`MAX_MATCHES`] matches, as the parser program has no room to tell one
    /// more apart from them.
    fn new_match(&mut self) -> Result<MatchId, Error> {
        if self.num_matches >= MAX_MATCHES {
            return Err(Error::MatchLimitExceeded(MAX_MATCHES as usize));
        }

        let id = MatchId(self.num_matches);
        self.num_matches += 1;
        Ok(id)
    }

    /// Configures the parser to capture the value of a header field.
    ///
    /// The field is matched case insensitively and its value is captured up to
    /// the end of the line, without the optional whitespace that may follow the
    /// colon. [`METHOD`], [`PATH`] and [`STATUS`] are not header fields in
    /// HTTP/1.x and are captured from the request or status line instead.
    ///
    /// # Arguments
    ///
    /// * `name` - The header name whose value to capture, matched case
    ///   insensitively. A [`PseudoHeader`] names a field of the request or
    ///   status line.
    ///
    /// # Errors
    ///
    /// Returns an error if the parser already captures as many fields as the
    /// parser program has room for.
    ///
    /// # Returns
    ///
    /// The match ID that can be used in eBPF to extract the captured value. A
    /// header that is already captured keeps the ID it was given the first
    /// time, rather than being captured a second time under a new one.
    pub fn capture_hdr<H: AsRef<str>>(&mut self, name: H) -> Result<MatchId, Error> {
        let name = name.as_ref().to_lowercase();
        if let Some(&mid) = self.captures.get(&name) {
            return Ok(mid);
        }

        let mid = self.capture_new_hdr(&name)?;
        self.captures.insert(name, mid);

        Ok(mid)
    }

    /// Configures the parser to capture the value of a header field it does
    /// not capture yet, see [`Parser::capture_hdr`].
    fn capture_new_hdr(&mut self, name: &str) -> Result<MatchId, Error> {
        if name == METHOD.as_str() || name == PATH.as_str() {
            return self.capture_status_line_hdr(name);
        } else if name == STATUS.as_str() {
            return self.capture_status_code();
        }

        let mid = self.new_match()?;
        let mut pattern = self.dfa.start_pattern(ANY_STATE);
        pattern
            .push(LF)
            .push_ci(name)
            .push_optional("\t", true)
            .push_optional(" ", true)
            .push_ci(":")
            .push_optional("\t", true)
            .push_optional(" ", true)
            .with(Action::StartCapture(mid));

        // the value begins here, and it may be empty
        let value = pattern.state();
        pattern
            .push_any(1..)
            .with(Action::EndCapture(mid))
            .push_optional(CR, false)
            .restart_with(LF);

        // an empty value ends its line where it would have begun, and there is
        // nothing in it to capture
        self.dfa
            .start_pattern(value)
            .push_optional(CR, false)
            .restart_with(LF);

        Ok(mid)
    }

    /// Configures the parser to match an HTTP/2 preface in an HTTP/1.1 connection.
    ///
    /// This method sets up pattern matching for the HTTP/2 connection preface
    /// (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`), which is used to upgrade from HTTP/1.1 to HTTP/2.
    ///
    /// The preface is captured as a match, so the target program can detect the
    /// upgrade and switch to an HTTP/2 parser for the rest of the connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the parser already captures as many fields as the
    /// parser program has room for.
    ///
    /// # Returns
    ///
    /// The match ID that can be used in eBPF to extract the captured value.
    pub fn match_h2_preface(&mut self) -> Result<MatchId, Error> {
        let mid = self.new_match()?;
        self.dfa
            .start_pattern(INIT_STATE)
            .with(Action::StartCapture(mid))
            .push(&format!(
                "PRI * HTTP/2.0{}{}{}{}SM{}{}{}{}",
                CR, LF, CR, LF, CR, LF, CR, LF
            ))
            .with(Action::EndCaptureAndDone(mid));

        Ok(mid)
    }

    /// Configures the parser to stop at the empty line that ends the header
    /// block, so that it never walks into the body of a message.
    fn done_on_hdr_end(mut self) -> Parser {
        self.dfa
            .start_pattern(ANY_STATE)
            .push_optional(CR, false)
            .push(LF)
            .push_optional(CR, false)
            .push(LF)
            .with(Action::Done);

        self
    }

    /// Configures the parser to match the request line and capture the field
    /// `name` addresses.
    ///
    /// # Panics
    ///
    /// Panics if `name` is neither [`METHOD`] nor [`PATH`].
    ///
    /// # Errors
    ///
    /// Returns an error if the parser already captures as many fields as the
    /// parser program has room for.
    ///
    /// # Returns
    ///
    /// The match ID that can be used in eBPF to extract the captured value.
    fn capture_status_line_hdr(&mut self, name: &str) -> Result<MatchId, Error> {
        let methods = [
            "POST", "GET", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE",
        ];

        let mid = self.new_match()?;
        if name == METHOD.as_str() {
            self.dfa
                .start_pattern(INIT_STATE)
                .with(Action::StartCapture(mid))
                .push_options_ci(&methods)
                .with(Action::EndCapture(mid))
                .push(" ")
                .push_any(1..)
                .push_ci(" HTTP/1.1")
                .push_optional(CR, false)
                .restart_with(LF);
        } else if name == PATH.as_str() {
            self.dfa
                .start_pattern(INIT_STATE)
                .push_options_ci(&methods)
                .push(" ")
                .with(Action::StartCapture(mid))
                .push_any(1..)
                .with(Action::EndCapture(mid))
                .push_ci(" HTTP/1.1")
                .push_optional(CR, false)
                .restart_with(LF);
        } else {
            panic!(
                "capture_status_line_hdr called with unsupported header name: {}",
                name
            );
        }

        Ok(mid)
    }

    /// Configures the parser to match the status line of a response and capture
    /// its status code.
    ///
    /// # Errors
    ///
    /// Returns an error if the parser already captures as many fields as the
    /// parser program has room for.
    ///
    /// # Returns
    ///
    /// The match ID that can be used in eBPF to extract the captured value.
    fn capture_status_code(&mut self) -> Result<MatchId, Error> {
        let mid = self.new_match()?;
        self.dfa
            .start_pattern(INIT_STATE)
            .push_ci("HTTP/1.1 ")
            .with(Action::StartCapture(mid))
            .push_any(3..=3)
            .with(Action::EndCapture(mid))
            .push_any(1..)
            .push_optional(CR, false)
            .restart_with(LF);

        Ok(mid)
    }

    /// Loads the configured parser and attaches it to the target program.
    ///
    /// Every function configured with [`Parser::parse_fn`],
    /// [`Parser::matched_fn`] or [`Parser::extract_fn`] is replaced in the
    /// target program, the remaining parser programs are left
    /// unloaded. The parser always stops at the end of the header block, no
    /// matter which patterns were configured.
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
    pub fn attach(self, target: i32) -> Result<AttachedParser> {
        let parser = self.done_on_hdr_end();

        let skel_builder = ParserSkelBuilder::default();
        let mut open_obj: MaybeUninit<OpenObject> = MaybeUninit::uninit();
        let mut open_skel = skel_builder.open(&mut open_obj)?;
        if tracing::event_enabled!(target: "bpf", Level::TRACE) {
            open_skel.progs.parse_msg.set_log_level(1);
            open_skel.progs.parse_skb.set_log_level(1);
            open_skel.progs.parse_buf.set_log_level(1);
        }

        // only the programs the parser was configured with are loaded
        for mut prog in open_skel.open_object_mut().progs_mut() {
            prog.set_autoload(false);
        }

        for (msg_buf, func) in &parser.parse_fns {
            let prog = match msg_buf {
                MessageBuffer::Msg => &mut open_skel.progs.parse_msg,
                MessageBuffer::Skb => &mut open_skel.progs.parse_skb,
                MessageBuffer::DynPtr => &mut open_skel.progs.parse_buf,
            };
            prog.set_autoload(true);
            prog.set_attach_target(target, Some(func.clone()))?;
        }

        if let Some(func) = &parser.matched_fn {
            let prog = &mut open_skel.progs.matched;
            prog.set_autoload(true);
            prog.set_attach_target(target, Some(func.clone()))?;
        }

        for (msg_buf, func) in &parser.extract_fns {
            let prog = match msg_buf {
                MessageBuffer::Msg => &mut open_skel.progs.extract_match_msg,
                MessageBuffer::Skb => &mut open_skel.progs.extract_match_skb,
                MessageBuffer::DynPtr => {
                    bail!(
                        "the parser extracts a match from a msg or an skb, not from a {msg_buf:?}"
                    )
                }
            };
            prog.set_autoload(true);
            prog.set_attach_target(target, Some(func.clone()))?;
        }

        parser.inject(&mut open_skel)?;

        let skel = open_skel.load()?;
        xbpf::tracing::try_init(skel.object())?;

        let mut links = Vec::new();

        for msg_buf in parser.parse_fns.keys() {
            links.push(match msg_buf {
                MessageBuffer::Msg => skel.progs.parse_msg.attach()?,
                MessageBuffer::Skb => skel.progs.parse_skb.attach()?,
                MessageBuffer::DynPtr => skel.progs.parse_buf.attach()?,
            });
        }

        if parser.matched_fn.is_some() {
            links.push(skel.progs.matched.attach()?);
        }

        for msg_buf in parser.extract_fns.keys() {
            links.push(match msg_buf {
                MessageBuffer::Msg => skel.progs.extract_match_msg.attach()?,
                MessageBuffer::Skb => skel.progs.extract_match_skb.attach()?,
                MessageBuffer::DynPtr => {
                    bail!(
                        "the parser extracts a match from a msg or an skb, not from a {msg_buf:?}"
                    )
                }
            });
        }

        debug!("Beeper http/1 attached");

        Ok(AttachedParser { links })
    }

    /// Writes the transition table of the DFA into the read-only data of the
    /// parser program. This has to happen before the program is loaded, as the
    /// kernel freezes the section afterwards.
    fn inject(&self, skel: &mut OpenParserSkel) -> Result<()> {
        let Some(data) = skel.maps.rodata_data.as_mut() else {
            bail!("the parser program has no read-only data to inject into");
        };

        let num_states = self.dfa.num_states() as usize;
        if num_states > data.s2ts.len() {
            bail!(
                "the patterns take {num_states} states, the parser holds {}",
                data.s2ts.len()
            );
        }

        // action index 0 is reserved for the noop action
        let mut action_idx = HashMap::new();
        action_idx.insert(None, 0usize);

        for (from, input, to, action) in self.dfa.iter_transitions() {
            let new_action_idx = action_idx.len();
            let action = *action_idx.entry(action).or_insert(new_action_idx);
            if action >= data.a2as.len() {
                bail!(
                    "the patterns take more actions than the {} the parser holds",
                    data.a2as.len()
                );
            }

            let action = action as u16;
            let input = input as usize;
            if input >= data.s2ts[0].len() {
                bail!("the patterns read inputs the parser has no column for: {input}");
            }

            trace!(
                "inject; from={} to={} input={} action={}",
                from.0,
                to.0,
                fmt_input(input as u16),
                action
            );

            data.s2ts[from.0 as usize][input] = trans {
                state: to.0,
                action,
            };
        }

        for (action, i) in action_idx {
            let Some(action) = action else { continue };
            data.a2as[i] = action.into();
        }

        Ok(())
    }
}

/// A [`Parser`] attached to a target program.
///
/// It owns the links of the attached programs, so the target program keeps its
/// parser for as long as this value is alive.
pub struct AttachedParser {
    #[allow(dead_code)]
    links: Vec<Link>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(i: u8) -> HeaderName {
        HeaderName::from_bytes(format!("x-{i}").as_bytes()).unwrap()
    }

    #[test]
    fn a_parser_captures_at_most_max_matches_ranges() {
        let mut parser = Parser::new();
        for i in 0..MAX_MATCHES {
            let mid = parser.capture_hdr(&hdr(i)).expect("capture header");
            assert_eq!(u8::from(mid), i);
        }

        assert_eq!(
            parser.capture_hdr(&hdr(MAX_MATCHES)),
            Err(Error::MatchLimitExceeded(MAX_MATCHES as usize))
        );
    }

    #[test]
    fn the_same_header_is_captured_under_one_match_id() {
        // the status line fields are each captured by a path of their own
        let names: [&dyn AsRef<str>; 4] = [&hdr(0), &METHOD, &PATH, &STATUS];
        for name in names {
            let name = name.as_ref();
            let mut parser = Parser::new();
            let first = parser.capture_hdr(name).expect("capture header");
            let second = parser.capture_hdr(name).expect("capture header again");

            assert_eq!(
                first, second,
                "capturing {name} twice handed out two ids for one range"
            );
        }
    }
}
