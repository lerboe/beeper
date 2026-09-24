//! The builder every DFA parser shares, whatever protocol its patterns spell.
//!
//! A protocol is a [`Parser`] with the patterns of that protocol on top, e.g.
//! [`crate::http1::Parser`]. Each one compiles its own copy of the parser
//! program, dfa/parser.bpf.h, and loads it with [`load_parser_program`].

use crate::{Dfa, Error, MatchId, MessageBuffer, dfa::action::Action};
use std::collections::HashMap;
use xbpf::libbpf::Link;

/// The number of ranges a parser can be configured to capture. Must stay in
/// sync with `MAX_MATCHES` of beeper/beeper.h.
pub(crate) const MAX_MATCHES: u8 = 32;

/// A parser whose patterns are compiled into a DFA.
///
/// The builder methods configure which fields the parser captures and which
/// functions of the target program it replaces. Nothing is loaded into the
/// kernel until the parser is attached. `P` holds what the protocol it parses
/// keeps track of while it is being configured.
pub struct Parser<P> {
    /// The patterns configured so far, compiled into a DFA.
    pub(crate) dfa: Dfa<Action>,

    /// The number of matches occuring in the patterns.
    num_matches: u8,

    /// The parse function name for each message buffer.
    pub(crate) parse_fns: HashMap<MessageBuffer, String>,

    /// The matched function name. It is agnostic to the message buffer.
    pub(crate) matched_fn: Option<String>,

    /// The extract function name for each message buffer.
    pub(crate) extract_fns: HashMap<MessageBuffer, String>,

    /// What the protocol keeps track of.
    pub(crate) proto: P,
}

impl<P: Default> Parser<P> {
    /// Creates a new parser.
    ///
    /// Additional configuration must be done through the builder methods before calling `attach`.
    pub fn new() -> Self {
        Parser {
            dfa: Dfa::new(),
            num_matches: 0,
            parse_fns: HashMap::new(),
            matched_fn: None,
            extract_fns: HashMap::new(),
            proto: P::default(),
        }
    }
}

impl<P: Default> Default for Parser<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P> Parser<P> {
    /// Specifies the function template in the target program to be replaced with the
    /// parser. The function will not be replaced until `attach` is called.
    ///
    /// # Arguments
    ///
    /// * `parse_fn` - The name of the function to replace in the target program
    /// * `msg_buf` - The type of buffer to parse
    pub fn parse_fn<S: ToString>(mut self, parse_fn: S, msg_buf: MessageBuffer) -> Self {
        self.parse_fns.insert(msg_buf, parse_fn.to_string());
        self
    }

    /// Specifies the function template in the target program to be called when a pattern match
    /// is completed. The function will not be replaced until `attach` is called.
    ///
    /// # Arguments
    ///
    /// * `matched_fn` - The name of the matched callback function in the target program
    pub fn matched_fn<S: ToString>(mut self, matched_fn: S) -> Self {
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
    pub fn extract_fn<S: ToString>(mut self, extract_fn: S, msg_buf: MessageBuffer) -> Self {
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
    pub(crate) fn new_match(&mut self) -> Result<MatchId, Error> {
        if self.num_matches >= MAX_MATCHES {
            return Err(Error::MatchLimitExceeded(MAX_MATCHES as usize));
        }

        let id = MatchId(self.num_matches);
        self.num_matches += 1;
        Ok(id)
    }
}

/// A [`Parser`] attached to a target program.
///
/// It owns the links of the attached programs, so the target program keeps its
/// parser for as long as this value is alive.
pub struct AttachedParser {
    #[allow(dead_code)]
    pub(crate) links: Vec<Link>,
}

/// Defines `load`, which loads the parser program of the calling module for a
/// [`Parser`] and attaches it to a target program.
///
/// Every protocol compiles its own copy of dfa/parser.bpf.h, as the programs
/// have to name the struct the protocol reports its results in, so the
/// skeletons differ in type but not in shape. The macro is expanded right
/// behind `xbpf::include_bpf!` of that copy.
macro_rules! load_parser_program {
    ($proto:literal) => {
        impl From<$crate::dfa::action::Action> for types::dfa_action {
            fn from(action: $crate::dfa::action::Action) -> Self {
                let (kind, flags, mid) = action.encode();
                types::dfa_action { kind, flags, mid }
            }
        }

        /// Loads the parser program for `parser` and attaches it to the target
        /// program.
        ///
        /// Every function configured with `parse_fn`, `matched_fn` or
        /// `extract_fn` is replaced in the target program, the remaining parser
        /// programs are left unloaded.
        ///
        /// # Errors
        ///
        /// Returns an error if the parser cannot be loaded, or if one of the
        /// functions it should replace does not exist in the target program
        /// with a matching signature.
        fn load<P>(
            parser: &$crate::dfa::parser::Parser<P>,
            target: i32,
        ) -> Result<$crate::dfa::parser::AttachedParser, $crate::Error> {
            use $crate::MessageBuffer;
            use xbpf::libbpf::skel::{OpenSkel, Skel, SkelBuilder};

            let skel_builder = ParserSkelBuilder::default();
            let mut open_obj = std::mem::MaybeUninit::uninit();
            let mut open_skel = skel_builder.open(&mut open_obj)?;
            if tracing::event_enabled!(target: "bpf", tracing::Level::TRACE) {
                open_skel.progs.parse_msg.set_log_level(1);
                open_skel.progs.parse_skb.set_log_level(1);
            }

            // only the programs the parser was configured with are loaded
            for mut prog in open_skel.open_object_mut().progs_mut() {
                prog.set_autoload(false);
            }

            for (msg_buf, func) in &parser.parse_fns {
                let prog = match msg_buf {
                    MessageBuffer::Msg => &mut open_skel.progs.parse_msg,
                    MessageBuffer::Skb => &mut open_skel.progs.parse_skb,
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
                };
                prog.set_autoload(true);
                prog.set_attach_target(target, Some(func.clone()))?;
            }

            inject(parser, &mut open_skel)?;

            let skel = open_skel.load()?;
            xbpf::tracing::try_init(skel.object())?;

            let mut links = Vec::new();

            for msg_buf in parser.parse_fns.keys() {
                links.push(match msg_buf {
                    MessageBuffer::Msg => skel.progs.parse_msg.attach()?,
                    MessageBuffer::Skb => skel.progs.parse_skb.attach()?,
                });
            }

            if parser.matched_fn.is_some() {
                links.push(skel.progs.matched.attach()?);
            }

            for msg_buf in parser.extract_fns.keys() {
                links.push(match msg_buf {
                    MessageBuffer::Msg => skel.progs.extract_match_msg.attach()?,
                    MessageBuffer::Skb => skel.progs.extract_match_skb.attach()?,
                });
            }

            tracing::debug!("Beeper {} attached", $proto);

            Ok($crate::dfa::parser::AttachedParser { links })
        }

        /// Writes the transition table of the DFA into the read-only data of
        /// the parser program. This has to happen before the program is
        /// loaded, as the kernel freezes the section afterwards.
        fn inject<P>(
            parser: &$crate::dfa::parser::Parser<P>,
            skel: &mut OpenParserSkel,
        ) -> Result<(), $crate::Error> {
            use $crate::{Error, dfa::fmt_input};
            use std::collections::HashMap;

            let Some(data) = skel.maps.rodata_data.as_mut() else {
                panic!("the parser program has no read-only data to inject into");
            };

            let num_states = parser.dfa.num_states() as usize;
            if num_states > data.s2ts.len() {
                tracing::warn!(
                    "the patterns take {num_states} states, the parser holds {}",
                    data.s2ts.len()
                );
                return Err(Error::ParserExceedsStateLimit);
            }

            // action index 0 is reserved for the noop action
            let mut action_idx = HashMap::new();
            action_idx.insert(None, 0usize);

            for (from, input, to, action) in parser.dfa.iter_transitions() {
                let new_action_idx = action_idx.len();
                let action = *action_idx.entry(action).or_insert(new_action_idx);
                if action >= data.a2as.len() {
                    tracing::warn!(
                        "the patterns take more actions than the {} the parser holds",
                        data.a2as.len()
                    );
                    return Err(Error::ParserExceedsStateLimit);
                }

                let action = action as u16;
                let input = input as usize;
                if input >= data.s2ts[0].len() {
                    tracing::warn!("the patterns read inputs the parser has no column for: {input}");
                    return Err(Error::ParserExceedsStateLimit);
                }

                tracing::trace!(
                    "inject; from={} to={} input={} action={}",
                    from.0,
                    to.0,
                    fmt_input(input as u16),
                    action
                );

                data.s2ts[from.0 as usize][input] = types::trans {
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
    };
}

pub(crate) use load_parser_program;
