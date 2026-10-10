use crate::{Error, MessageBuffer};
use std::{collections::HashMap, mem::MaybeUninit};
use tracing::{Level, debug};
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
#[derive(Default)]
pub struct Parser {
    /// The parse function name for each message buffer.
    parse_fns: HashMap<MessageBuffer, String>,

    /// The record iterator function name for each message buffer.
    next_rr_fns: HashMap<MessageBuffer, String>,

    /// The name extraction function name for each message buffer.
    extract_name_fns: HashMap<MessageBuffer, String>,
}

impl Parser {
    /// Creates a new DNS parser.
    ///
    /// Additional configuration must be done through the builder methods before calling `attach`.
    pub fn new() -> Parser {
        Parser::default()
    }

    /// Specifies the function template in the target program to be replaced with the DNS
    /// parser, declared with `BEEPER_DNS_PARSE_MSG` or `BEEPER_DNS_PARSE_SKB`. The function
    /// will not be replaced until `attach` is called.
    pub fn parse_fn<S: ToString>(mut self, parse_fn: S, msg_buf: MessageBuffer) -> Parser {
        self.parse_fns.insert(msg_buf, parse_fn.to_string());
        self
    }

    /// Specifies the function template in the target program to be replaced with the record
    /// iterator, declared with `BEEPER_DNS_NEXT_RR_MSG` or `BEEPER_DNS_NEXT_RR_SKB`. The
    /// function will not be replaced until `attach` is called.
    pub fn next_rr_fn<S: ToString>(mut self, next_rr_fn: S, msg_buf: MessageBuffer) -> Parser {
        self.next_rr_fns.insert(msg_buf, next_rr_fn.to_string());
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
    /// Every function configured with [`Parser::parse_fn`], [`Parser::next_rr_fn`] or
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
                &self.next_rr_fns,
                MessageBuffer::Msg,
                &mut progs.next_rr_msg,
            ),
            (
                &self.next_rr_fns,
                MessageBuffer::Skb,
                &mut progs.next_rr_skb,
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

        let skel = open_skel.load()?;
        xbpf::tracing::try_init(skel.object())?;

        let progs = &skel.progs;
        let loaded = [
            (&self.parse_fns, MessageBuffer::Msg, &progs.parse_msg),
            (&self.parse_fns, MessageBuffer::Skb, &progs.parse_skb),
            (&self.next_rr_fns, MessageBuffer::Msg, &progs.next_rr_msg),
            (&self.next_rr_fns, MessageBuffer::Skb, &progs.next_rr_skb),
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

/// A [`Parser`] attached to a target program.
///
/// It owns the links of the attached programs, so the target program keeps its
/// parser for as long as this value is alive.
pub struct AttachedParser {
    #[allow(dead_code)]
    links: Vec<Link>,
}
