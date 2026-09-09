#![allow(unused_imports)]
use crate::{
    Dfa, MatchId, StateId, autoload_and_attach, bench,
    dfa::{ANY_INPUT, ANY_STATE, INIT_STATE, Input, fmt_input},
    h1::action::Action,
    header::{METHOD, PATH, STATUS},
};
use anyhow::{Result, bail};
use http::HeaderName;
use std::{
    cmp::Reverse,
    collections::{HashMap, HashSet},
    mem::MaybeUninit,
    time::Duration,
};
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
const MAX_MATCHES: u16 = 32;

/// A parser for HTTP/1.x messages.
///
/// The builder methods configure which fields the parser captures and which
/// functions of the target program it replaces. Nothing is loaded into the
/// kernel until [`Parser::attach`] is called.
pub struct Parser {
    /// The patterns configured so far, compiled into a DFA.
    dfa: Dfa<Action>,

    /// The number of matches occuring in the patterns.
    num_matches: u16,

    parse_msg_fn: Option<String>,
    parse_buf_fn: Option<String>,
    parse_skb_fn: Option<String>,
    extract_fn: Option<String>,
    matched_fn: Option<String>,
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
            parse_msg_fn: None,
            parse_buf_fn: None,
            parse_skb_fn: None,
            extract_fn: None,
            matched_fn: None,
        }
    }

    /// Specifies the function template in the target program to be replaced with an HTTP/1.1
    /// parser. The function will not be replaced until `attach` is called.
    ///
    /// # Arguments
    ///
    /// * `parse_fn` - The name of the function to replace in the target program
    pub fn replace_parse_msg<S: ToString>(mut self, parse_fn: S) -> Parser {
        self.parse_msg_fn = Some(parse_fn.to_string());
        self
    }

    /// Specifies the function template in the target program to be replaced with a parser
    /// reading from a `sk_buff`. The function will not be replaced until `attach` is called.
    ///
    /// # Arguments
    ///
    /// * `parse_fn` - The name of the function to replace in the target program
    pub fn replace_parse_skb<S: ToString>(mut self, parse_fn: S) -> Parser {
        self.parse_skb_fn = Some(parse_fn.to_string());
        self
    }

    /// Specifies the function template in the target program to be replaced with a parser
    /// reading from a dynptr. The function will not be replaced until `attach` is called.
    ///
    /// # Arguments
    ///
    /// * `parse_fn` - The name of the function to replace in the target program
    pub fn replace_parse_buf<S: ToString>(mut self, parse_fn: S) -> Parser {
        self.parse_buf_fn = Some(parse_fn.to_string());
        self
    }

    /// Specifies the function template in the target program to be called when a pattern match
    /// is completed. The function will not be replaced until `attach` is called.
    ///
    /// # Arguments
    ///
    /// * `matched_fn` - The name of the matched callback function in the target program
    pub fn replace_matched<S: ToString>(mut self, matched_fn: S) -> Parser {
        self.matched_fn = Some(matched_fn.to_string());
        self
    }

    /// Specifies the function template in the target program to be called when extracting
    /// matched content. The function will not be replaced until `attach` is called.
    ///
    /// # Arguments
    ///
    /// * `extract_fn` - The name of the extract callback function in the target program
    pub fn replace_extract<S: ToString>(mut self, extract_fn: S) -> Parser {
        self.extract_fn = Some(extract_fn.to_string());
        self
    }

    /// Returns an unused match id.
    ///
    /// # Panics
    ///
    /// Panics if the parser is already configured with [`MAX_MATCHES`] matches,
    /// as the parser program has no room to tell one more apart from them.
    fn new_match(&mut self) -> MatchId {
        assert!(
            self.num_matches < MAX_MATCHES,
            "a parser captures at most {MAX_MATCHES} ranges"
        );

        let id = MatchId(self.num_matches);
        self.num_matches += 1;
        id
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
    /// * `name` - The header name whose value to capture
    pub fn capture_hdr(mut self, name: &HeaderName) -> Parser {
        if name == &METHOD || name == &PATH {
            return self.capture_status_line_hdr(name);
        } else if name == &STATUS {
            return self.capture_status_code();
        }

        let mid = self.new_match();
        let mut pattern = self.dfa.start_pattern(ANY_STATE);
        pattern
            .push(LF)
            .push_ci(name.as_str())
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

        self
    }

    /// Configures the parser to match an HTTP/2 preface in an HTTP/1.1 connection.
    ///
    /// This method sets up pattern matching for the HTTP/2 connection preface
    /// (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`), which is used to upgrade from HTTP/1.1 to HTTP/2.
    ///
    /// The preface is captured as a match, so the target program can detect the
    /// upgrade and switch to an HTTP/2 parser for the rest of the connection.
    pub fn match_h2_preface(mut self) -> Parser {
        let mid = self.new_match();
        self.dfa
            .start_pattern(INIT_STATE)
            .with(Action::StartCapture(mid))
            .push(&format!(
                "PRI * HTTP/2.0{}{}{}{}SM{}{}{}{}",
                CR, LF, CR, LF, CR, LF, CR, LF
            ))
            .with(Action::EndCaptureAndDone(mid));

        self
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
    fn capture_status_line_hdr(mut self, name: &HeaderName) -> Parser {
        let methods = [
            "POST", "GET", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE",
        ];

        if name == &METHOD {
            let mid = self.new_match();
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
        } else if name == &PATH {
            let mid = self.new_match();
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

        self
    }

    /// Configures the parser to match the status line of a response and capture
    /// its status code.
    fn capture_status_code(mut self) -> Parser {
        let mid = self.new_match();

        self.dfa
            .start_pattern(INIT_STATE)
            .push_ci("HTTP/1.1 ")
            .with(Action::StartCapture(mid))
            .push_any(3..=3)
            .with(Action::EndCapture(mid))
            .push_any(1..)
            .push_optional(CR, false)
            .restart_with(LF);

        self
    }

    /// Loads the configured parser and attaches it to the target program.
    ///
    /// Every function configured with one of the `replace_*` methods is
    /// replaced in the target program, the remaining parser programs are left
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
    pub fn attach<'obj>(self, target: i32) -> Result<AttachedParser> {
        let parser = self.done_on_hdr_end();

        let skel_builder = ParserSkelBuilder::default();
        let mut open_obj: MaybeUninit<OpenObject> = MaybeUninit::uninit();
        let mut open_skel = skel_builder.open(&mut open_obj)?;
        if tracing::event_enabled!(target: "bpf", Level::TRACE) {
            open_skel.progs.parse_msg.set_log_level(1);
            open_skel.progs.parse_skb.set_log_level(1);
            open_skel.progs.parse_buf.set_log_level(1);
        }

        let progs = vec![
            (&mut open_skel.progs.parse_msg, parser.parse_msg_fn.clone()),
            (&mut open_skel.progs.parse_skb, parser.parse_skb_fn.clone()),
            (&mut open_skel.progs.parse_buf, parser.parse_buf_fn.clone()),
            (&mut open_skel.progs.matched, parser.matched_fn.clone()),
            (
                &mut open_skel.progs.extract_match,
                parser.extract_fn.clone(),
            ),
        ];

        for (prog, func) in progs {
            autoload_and_attach(prog, target, func)?;
        }

        open_skel.progs.bench.set_autoload(false);

        parser.inject(&mut open_skel)?;

        let skel = open_skel.load()?;
        xbpf::tracing::try_init(skel.object())?;

        let mut links = Vec::new();
        if parser.parse_msg_fn.is_some() {
            links.push(skel.progs.parse_msg.attach()?);
        }
        if parser.parse_skb_fn.is_some() {
            links.push(skel.progs.parse_skb.attach()?);
        }
        if parser.parse_buf_fn.is_some() {
            links.push(skel.progs.parse_buf.attach()?);
        }

        if parser.matched_fn.is_some() {
            links.push(skel.progs.matched.attach()?);
        }

        if parser.extract_fn.is_some() {
            links.push(skel.progs.extract_match.attach()?);
        }

        debug!("Beeper http/1 attached");

        anyhow::Ok(AttachedParser { links })
    }

    /// Loads the configured parser on its own and times it over `buf`.
    ///
    /// Nothing is attached to a target program: the parser walks `buf` `n`
    /// times inside a single `BPF_PROG_TEST_RUN`, so what is measured is the
    /// parse and not the syscall around it. Loading a program is privileged, so
    /// this only works as root.
    ///
    /// # Arguments
    ///
    /// * `buf` - The message to parse, at most [`bench::BUF_LEN`] bytes of it
    /// * `n` - How often to parse it
    ///
    /// # Errors
    ///
    /// Returns an error if the parser cannot be loaded, if `buf` is longer than
    /// the parser can read, or if the parse fails.
    pub fn bench(self, buf: &[u8], n: u32) -> Result<Duration> {
        let parser = self.done_on_hdr_end();

        let skel_builder = ParserSkelBuilder::default();
        let mut open_obj: MaybeUninit<OpenObject> = MaybeUninit::uninit();
        let mut open_skel = skel_builder.open(&mut open_obj)?;

        for prog in [
            &mut open_skel.progs.parse_msg,
            &mut open_skel.progs.parse_skb,
            &mut open_skel.progs.parse_buf,
            &mut open_skel.progs.matched,
            &mut open_skel.progs.extract_match,
        ] {
            prog.set_autoload(false);
        }

        parser.inject(&mut open_skel)?;

        let skel = open_skel.load()?;

        bench::run(&skel.progs.bench, buf, n)
    }

    /// Writes the transition table of the DFA into the read-only data of the
    /// parser program. This has to happen before the program is loaded, as the
    /// kernel freezes the section afterwards.
    ///
    /// The table is written sparsely: a state only takes up the columns it has
    /// a transition for, and the rows are laid over each other wherever they
    /// leave those free. See `s2es` of the parser program.
    fn inject(&self, skel: &mut OpenParserSkel) -> Result<()> {
        let Some(data) = skel.maps.rodata_data.as_mut() else {
            bail!("the parser program has no read-only data to inject into");
        };

        // action index 0 is reserved for the noop action
        let mut action_idx = HashMap::new();
        action_idx.insert(None, 0usize);

        let mut rows: Vec<Row> = vec![Vec::new(); self.dfa.num_states() as usize];

        for (from, input, to, action) in self.dfa.iter_transitions() {
            let new_action_idx = action_idx.len();
            let action = *action_idx.entry(action).or_insert(new_action_idx);
            if action >= data.a2as.len() {
                bail!(
                    "the patterns take more actions than the {} the parser holds",
                    data.a2as.len()
                );
            }

            if input > ANY_INPUT {
                bail!("the patterns read inputs the parser has no column for: {input}");
            }

            trace!(
                "inject; from={} to={} input={} action={}",
                from.0,
                to.0,
                fmt_input(input),
                action
            );

            rows[from.0 as usize].push((input, to, action as u16));
        }

        let offs = pack(&rows, data.s2es.len())?;
        if offs[ANY_STATE.0 as usize] != ANY_ROW {
            bail!("the state matching no pattern was laid down out of place");
        }

        for (from, row) in rows.iter().enumerate() {
            for (input, to, action) in row {
                let off = offs[from];
                data.s2es[off + *input as usize] = edge(off, offs[to.0 as usize], *action);
            }
        }

        data.s_init = offs[INIT_STATE.0 as usize] as u16;

        for (action, i) in action_idx {
            let Some(action) = action else { continue };
            data.a2as[i] = action.into();
        }

        Ok(())
    }
}

/// The row [`ANY_STATE`] is laid down at. The parser program compares against
/// it on every byte, so it is fixed rather than left to [`pack`]. Must stay in
/// sync with `s_any` of the parser program.
const ANY_ROW: usize = 1;

/// The widest row [`edge`] has room to name. Must stay in sync with
/// `E_ROW_MASK` of the parser program.
const MAX_ROW: usize = 0xFFF;

/// The transitions a single state takes, as the input they match, the state
/// they lead to and the index of the action they carry.
type Row = Vec<(Input, StateId, u16)>;

/// Packs a transition into the word the parser program reads it back out of:
/// the row it leaves, the row it leads to and the index of the action it
/// carries. Must stay in sync with the `E_*` macros of the parser program.
fn edge(row: usize, to: usize, action: u16) -> u32 {
    row as u32 | (to as u32) << 12 | u32::from(action) << 24
}

/// Lays the rows of `rows` into a table of `len` slots, overlapping them
/// wherever they leave each other's columns free, and returns the offset every
/// state was laid down at.
///
/// The offsets are distinct even for a state without transitions, as an offset
/// is what the parser program tells states apart by.
///
/// # Errors
///
/// Returns an error if the rows do not fit into `len` slots.
fn pack(rows: &[Row], len: usize) -> Result<Vec<usize>> {
    let len = len.min(MAX_ROW + 1);

    // `ANY_STATE` goes down first, so that it lands on `ANY_ROW`, and the
    // widest row after it: a narrow one is easier to fit into what the wide
    // ones leave free than the other way around
    let mut order: Vec<usize> = (0..rows.len()).collect();
    let any = ANY_STATE.0 as usize;
    order.sort_by_key(|state| (*state != any, Reverse(rows[*state].len()), *state));

    let mut offs = vec![0; rows.len()];
    let mut taken = vec![false; len];
    let mut used = HashSet::new();

    // offset 0 is left out: it is what a free slot names as its row, which
    // also puts `ANY_STATE` on `ANY_ROW`
    for state in order {
        let fits = |off: &usize| {
            !used.contains(off)
                && rows[state]
                    .iter()
                    .all(|(input, _, _)| taken.get(off + *input as usize).is_some_and(|t| !t))
        };

        let Some(off) = (1..len).find(fits) else {
            bail!("the patterns take more transitions than the {len} the parser holds");
        };

        for (input, _, _) in &rows[state] {
            taken[off + *input as usize] = true;
        }

        used.insert(off);
        offs[state] = off;
    }

    Ok(offs)
}

/// A [`Parser`] attached to a target program.
///
/// It owns the links of the attached programs, so the target program keeps its
/// parser for as long as this value is alive.
pub struct AttachedParser {
    #[allow(dead_code)]
    links: Vec<Link>,
}
