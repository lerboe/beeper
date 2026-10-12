use crate::{
    Dfa, Error, MessageBuffer,
    dns::{action::Action, grammar},
};
use std::{collections::HashMap, mem::MaybeUninit};
use tracing::{Level, debug, warn};
use types::*;
use xbpf::libbpf_rs::{
    Link, OpenObject,
    skel::{OpenSkel, Skel, SkelBuilder},
};

xbpf::include_bpf!("dns/parser");

/// A parser for DNS messages.
///
/// The builder methods configure which functions of the target program the
/// parser replaces. Nothing is loaded into the kernel until
/// [`Parser::attach`] is called.
pub struct Parser {
    /// The message format, compiled into a DFA.
    dfa: Dfa<Action>,

    /// The parse function name for each message buffer.
    parse_fns: HashMap<MessageBuffer, String>,

    /// The record extraction function name for each message buffer.
    extract_rr_fns: HashMap<MessageBuffer, String>,

    /// The name extraction function name for each message buffer.
    extract_name_fns: HashMap<MessageBuffer, String>,
}

impl Parser {
    /// Creates a new DNS parser.
    ///
    /// Additional configuration must be done through the builder methods before calling `attach`.
    pub fn new() -> Parser {
        Parser {
            dfa: grammar::dfa(),
            parse_fns: HashMap::new(),
            extract_rr_fns: HashMap::new(),
            extract_name_fns: HashMap::new(),
        }
    }

    /// Specifies the function template in the target program to be replaced with the DNS
    /// parser, declared with `BEEPER_DNS_PARSE_MSG` or `BEEPER_DNS_PARSE_SKB`. The function
    /// will not be replaced until `attach` is called.
    pub fn parse_fn<S: ToString>(mut self, parse_fn: S, msg_buf: MessageBuffer) -> Parser {
        self.parse_fns.insert(msg_buf, parse_fn.to_string());
        self
    }

    /// Specifies the function template in the target program to be replaced with the record
    /// extraction, declared with `BEEPER_DNS_EXTRACT_RR_MSG` or `BEEPER_DNS_EXTRACT_RR_SKB`.
    /// The function will not be replaced until `attach` is called.
    pub fn extract_rr_fn<S: ToString>(
        mut self,
        extract_rr_fn: S,
        msg_buf: MessageBuffer,
    ) -> Parser {
        self.extract_rr_fns
            .insert(msg_buf, extract_rr_fn.to_string());
        self
    }

    /// Specifies the function template in the target program to be replaced with the name
    /// extraction, declared with `BEEPER_DNS_EXTRACT_NAME_MSG` or
    /// `BEEPER_DNS_EXTRACT_NAME_SKB`. The function will not be replaced until `attach` is
    /// called.
    pub fn extract_name_fn<S: ToString>(
        mut self,
        extract_name_fn: S,
        msg_buf: MessageBuffer,
    ) -> Parser {
        self.extract_name_fns
            .insert(msg_buf, extract_name_fn.to_string());
        self
    }

    /// Loads the configured parser and attaches it to the target program.
    ///
    /// Every function configured with [`Parser::parse_fn`], [`Parser::extract_rr_fn`] or
    /// [`Parser::extract_name_fn`] is replaced in the target program, the remaining parser
    /// programs are left unloaded.
    ///
    /// # Errors
    ///
    /// Returns an error if the parser cannot be loaded, or if one of the
    /// functions it should replace does not exist in the target program with a
    /// matching signature.
    pub fn attach(self, target: i32) -> Result<AttachedParser, Error> {
        let skel_builder = ParserSkelBuilder::default();
        let mut open_obj: MaybeUninit<OpenObject> = MaybeUninit::uninit();
        let mut open_skel = skel_builder.open(&mut open_obj)?;

        // only the programs the parser was configured with are loaded
        for mut prog in open_skel.open_object_mut().progs_mut() {
            prog.set_autoload(false);
            if tracing::event_enabled!(target: "bpf", Level::TRACE) {
                prog.set_log_level(1);
            }
        }

        let progs = &mut open_skel.progs;
        let configured = [
            (&self.parse_fns, MessageBuffer::Msg, &mut progs.parse_msg),
            (&self.parse_fns, MessageBuffer::Skb, &mut progs.parse_skb),
            (
                &self.extract_rr_fns,
                MessageBuffer::Msg,
                &mut progs.extract_rr_msg,
            ),
            (
                &self.extract_rr_fns,
                MessageBuffer::Skb,
                &mut progs.extract_rr_skb,
            ),
            (
                &self.extract_name_fns,
                MessageBuffer::Msg,
                &mut progs.extract_name_msg,
            ),
            (
                &self.extract_name_fns,
                MessageBuffer::Skb,
                &mut progs.extract_name_skb,
            ),
        ];

        for (fns, msg_buf, prog) in configured {
            if let Some(func) = fns.get(&msg_buf) {
                prog.set_autoload(true);
                prog.set_attach_target(target, Some(func.clone()))?;
            }
        }

        self.inject(&mut open_skel)?;

        let skel = open_skel.load()?;
        xbpf::tracing::try_init(skel.object())?;

        let progs = &skel.progs;
        let loaded = [
            (&self.parse_fns, MessageBuffer::Msg, &progs.parse_msg),
            (&self.parse_fns, MessageBuffer::Skb, &progs.parse_skb),
            (
                &self.extract_rr_fns,
                MessageBuffer::Msg,
                &progs.extract_rr_msg,
            ),
            (
                &self.extract_rr_fns,
                MessageBuffer::Skb,
                &progs.extract_rr_skb,
            ),
            (
                &self.extract_name_fns,
                MessageBuffer::Msg,
                &progs.extract_name_msg,
            ),
            (
                &self.extract_name_fns,
                MessageBuffer::Skb,
                &progs.extract_name_skb,
            ),
        ];

        let mut links = Vec::new();
        for (fns, msg_buf, prog) in loaded {
            if fns.contains_key(&msg_buf) {
                links.push(prog.attach()?);
            }
        }

        debug!("Beeper DNS attached");

        Ok(AttachedParser { links })
    }
}

impl Parser {
    /// Writes the DFA into the read-only data of the parser program. This has
    /// to happen before the program is loaded, as the kernel freezes the
    /// section afterwards.
    ///
    /// # Errors
    ///
    /// Returns an error if the DFA exceeds the eBPF limits on the number of
    /// states or actions.
    fn inject(&self, skel: &mut OpenParserSkel) -> Result<(), Error> {
        let Some(data) = skel.maps.rodata_data.as_mut() else {
            panic!("the parser program has no read-only data to inject into");
        };

        let num_states = self.dfa.num_states() as usize;
        if num_states > data.s2ts.len() {
            warn!(
                "the DFA takes {num_states} states, the parser holds {}",
                data.s2ts.len()
            );
            return Err(Error::ParserExceedsStateLimit);
        }

        // action index 0 is reserved for the noop action
        let mut action_idx = HashMap::new();
        action_idx.insert(None, 0usize);

        for (from, input, to, action) in self.dfa.iter_transitions() {
            let new_action_idx = action_idx.len();
            let action = *action_idx.entry(action).or_insert(new_action_idx);
            if action >= data.a2as.len() {
                warn!(
                    "the DFA takes more actions than the {} the parser holds",
                    data.a2as.len()
                );
                return Err(Error::ParserExceedsStateLimit);
            }

            data.s2ts[from.0 as usize][input as usize] = trans {
                state: to.0,
                action: action as u16,
            };
        }

        for (action, i) in action_idx {
            let Some(action) = action else { continue };
            data.a2as[i] = action.into();
        }

        Ok(())
    }
}

impl Default for Parser {
    fn default() -> Self {
        Parser::new()
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
