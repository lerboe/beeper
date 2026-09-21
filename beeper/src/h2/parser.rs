#![allow(unused_imports)]
use crate::{
    Dfa, Error, MatchId, MessageBuffer,
    h2::{action::*, hpack},
};
use anyhow::{Result, bail};
use as_bytes::AsBytes;
use httlib_huffman as huffman;
use http::HeaderName;
use plain::Plain;
use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use tracing::{Level, debug, warn};
use types::*;
pub use types::{ip4_addr, ip4_conn};
use xbpf::libbpf::{
    self as libbpf_rs, ErrorKind, Link, MapCore, MapFlags, MapHandle, OpenObject,
    skel::{OpenSkel, Skel, SkelBuilder},
};

extern crate plain;

/// The number of ranges a parser can be configured to capture. Must stay in
/// sync with `MAX_MATCHES` of beeper.h.
const MAX_MATCHES: u8 = 32;

/// The index the first entry of a dynamic table is stored under. Must stay in
/// sync with `DYNAMIC_TABLE_BASE` of h2/parser.bpf.c.
const DYNAMIC_TABLE_BASE: u32 = 62;

/// A parser for HTTP/2 messages.
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

    /// The function name to retrieve dynamic table entries.
    get_dynamic_table_entry_fn: Option<String>,

    /// The match id of every header captured so far, keyed by the name as it
    /// travels the wire, so that a header asked for twice is captured once.
    captures: HashMap<Vec<u8>, MatchId>,
}

xbpf::include_bpf!("h2/parser");

#[allow(dead_code)]
impl Parser {
    /// Creates a new HTTP/2 parser.
    ///
    /// Additional configuration must be done through the builder methods before calling `attach`.
    pub fn new() -> Parser {
        let dfa = hpack::dfa();

        Parser {
            dfa,
            num_matches: 0,
            parse_fns: HashMap::new(),
            matched_fn: None,
            extract_fns: HashMap::new(),
            get_dynamic_table_entry_fn: None,
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

    /// Specifies the function template in the target program to be replaced with a reader of the
    /// connection's dynamic table (`BEEPER_H2_GET_DT_ENTRY`). The function will not be replaced
    /// until `attach` is called.
    ///
    /// # Arguments
    ///
    /// * `get_dynamic_table_entry_fn` - The name of the dynamic table entry reader function in the target program
    pub fn get_dynamic_table_entry<S: ToString>(mut self, get_dynamic_table_entry_fn: S) -> Parser {
        self.get_dynamic_table_entry_fn = Some(get_dynamic_table_entry_fn.to_string());
        self
    }

    /// Configures the parser to capture the value of a header field.
    ///
    /// The field name is matched in its Huffman encoded form, which is how
    /// HPACK puts it on the wire. Fields the peer replaced with an index into
    /// the static or the dynamic table are matched against the entry the index
    /// resolves to. A [`PseudoHeader`] carries the leading colon HTTP/2 spells
    /// it with, see [`crate::PseudoHeader`].
    ///
    /// # Arguments
    ///
    /// * `name` - The header name whose value to capture, as it travels the
    ///   wire
    ///
    /// # Errors
    ///
    /// Returns an error if `name` cannot be Huffman encoded, or if the parser
    /// already captures as many fields as the parser program has room for.
    ///
    /// # Returns
    ///
    /// The match ID that can be used in eBPF to extract the captured value. A
    /// header that is already captured keeps the ID it was given the first
    /// time, rather than being captured a second time under a new one.
    pub fn capture_hdr<H: AsRef<[u8]>>(&mut self, name: H) -> Result<MatchId, Error> {
        let name = name.as_ref();
        if let Some(&mid) = self.captures.get(name) {
            return Ok(mid);
        }

        let mut name_encoded = Vec::new();
        huffman::encode(name, &mut name_encoded)?;

        let mid = self.new_match()?;
        self.dfa
            .start_pattern(S_NAME)
            .push_bytes(&name_encoded)
            .with(Action::capture(mid));

        self.captures.insert(name.to_vec(), mid);

        Ok(mid)
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

    /// Fills `static_table` with the Huffman encoded entries of the HPACK
    /// static table and freezes it, so that the parser can resolve the fields a
    /// peer refers to by index.
    ///
    /// # Errors
    ///
    /// Returns an error if an entry cannot be encoded or written to the map.
    fn populate_static_table(&self, static_table: &MapHandle) -> Result<()> {
        let insert = |idx: u32, key: &str, val: Option<&str>| {
            let mut hf_key = Vec::new();
            huffman::encode(key.as_bytes(), &mut hf_key)?;

            let mut hf_val = Vec::new();
            if let Some(val) = val {
                huffman::encode(val.as_bytes(), &mut hf_val)?;
            }

            let key_len = hf_key.len() as u8;
            let val_len = hf_val.len() as u8;
            hf_key.resize(128, 0);
            hf_val.resize(128, 0);

            let hf = header_field {
                key: hf_key.try_into().unwrap(),
                key_len,
                val: hf_val.try_into().unwrap(),
                val_len,
                // the static table is written out Huffman coded above
                key_huff: 1,
                val_huff: 1,
            };

            let idx = unsafe { idx.as_bytes() };
            let hf = unsafe { hf.as_bytes() };

            static_table.update(&idx, &hf, MapFlags::ANY)?;

            anyhow::Ok(())
        };

        let (st_keys, st_hfs) = hpack::create_header_maps();
        for (key, vals) in st_hfs.iter() {
            for (val, idx) in vals.iter() {
                insert(*idx as u32, key, Some(val))?;
            }
        }

        for (key, idx) in st_keys.iter() {
            insert(*idx as u32, key, None)?;
        }

        static_table.freeze()?;

        Ok(())
    }

    /// Loads the configured parser and attaches it to the target program.
    /// Every function configured with [`Parser::parse_fn`],
    /// [`Parser::matched_fn`], [`Parser::extract_fn`] or
    /// [`Parser::get_dynamic_table_entry`] is replaced in the target program,
    /// the remaining parser programs are left unloaded. Loading the parser also
    /// populates the HPACK static table.
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

        for (msg_buf, func) in &self.parse_fns {
            let prog = match msg_buf {
                MessageBuffer::Msg => &mut open_skel.progs.parse_msg,
                MessageBuffer::Skb => &mut open_skel.progs.parse_skb,
                MessageBuffer::DynPtr => &mut open_skel.progs.parse_buf,
            };
            prog.set_autoload(true);
            prog.set_attach_target(target, Some(func.clone()))?;
        }

        if let Some(func) = &self.matched_fn {
            let prog = &mut open_skel.progs.matched;
            prog.set_autoload(true);
            prog.set_attach_target(target, Some(func.clone()))?;
        }

        for (msg_buf, func) in &self.extract_fns {
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

        if let Some(func) = &self.get_dynamic_table_entry_fn {
            let prog = &mut open_skel.progs.get_dt_entry;
            prog.set_autoload(true);
            prog.set_attach_target(target, Some(func.clone()))?;
        }

        self.inject(&mut open_skel)?;

        let skel = open_skel.load()?;
        xbpf::tracing::try_init(skel.object())?;

        let mut links = Vec::new();

        for msg_buf in self.parse_fns.keys() {
            links.push(match msg_buf {
                MessageBuffer::Msg => skel.progs.parse_msg.attach()?,
                MessageBuffer::Skb => skel.progs.parse_skb.attach()?,
                MessageBuffer::DynPtr => skel.progs.parse_buf.attach()?,
            });
        }

        if self.matched_fn.is_some() {
            links.push(skel.progs.matched.attach()?);
        }

        for msg_buf in self.extract_fns.keys() {
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

        if self.get_dynamic_table_entry_fn.is_some() {
            links.push(skel.progs.get_dt_entry.attach()?);
        }

        let id = skel.maps.static_table.info()?.info.id;
        let static_table = MapHandle::from_map_id(id)?;
        self.populate_static_table(&static_table)?;

        debug!("Beeper http/2 attached");

        let dynamic_table_info = MapHandle::try_from(&skel.maps.dynamic_table_info)?;
        let dynamic_table = MapHandle::try_from(&skel.maps.dynamic_table)?;
        let continued_blocks = MapHandle::try_from(&skel.maps.continued_blocks)?;
        Ok(AttachedParser {
            dynamic_table_info,
            dynamic_table,
            continued_blocks,
            links,
        })
    }

    /// Writes the transition table of the DFA and the actions its transitions
    /// carry into the read-only data of the parser program. This has to happen
    /// before the program is loaded, as the kernel freezes the section
    /// afterwards.
    ///
    /// # Errors
    ///
    /// Returns an error if the patterns do not fit into the tables the parser
    /// program reserves for them.
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

            let input = input as usize;
            if input >= data.s2ts[0].len() {
                bail!("the patterns read inputs the parser has no column for: {input}");
            }

            data.s2ts[from.0 as usize][input] = trans {
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

/// A [`Parser`] attached to a target program.
///
/// It owns the links of the attached programs, so the target program keeps its
/// parser for as long as this value is alive.
pub struct AttachedParser {
    /// The map holding the state of the dynamic table of every connection the
    /// parser has seen a header block on.
    dynamic_table_info: MapHandle,

    /// The entries of those dynamic tables.
    dynamic_table: MapHandle,

    /// The header blocks that carry on into a CONTINUATION frame.
    continued_blocks: MapHandle,

    #[allow(dead_code)]
    links: Vec<Link>,
}

/// The state of the dynamic table the parser mirrors for a connection.
///
/// This is mostly useful to assert that the kernel side stayed in sync with the
/// peer's own table.
#[repr(C)]
#[derive(Default, Clone)]
pub struct DynamicTableInfo {
    /// The number of entries currently in the table.
    pub count: u32,

    /// The size of those entries, as defined by section 4.1 of RFC 7541.
    pub size: u32,

    /// The maximum size the peer announced, either as the initial value or with
    /// a `SETTINGS_HEADER_TABLE_SIZE` setting.
    pub max_size: u32,

    /// The number of entries evicted so far. Together with `count` it turns an
    /// HPACK index into an index into the table.
    pub deleted: u32,

    /// Whether the table has drifted from the peer's and can no longer be
    /// trusted.
    ///
    /// It drifts when a header block is split over a HEADERS frame and the
    /// CONTINUATION frames following it in the middle of a field, see section
    /// 6.10 of RFC 9113: the parser cannot address the half of the field that
    /// is in the frame before, so the entry the peer adds is one it cannot
    /// mirror. A table that has drifted is neither added to nor resolved from.
    pub dirty: u32,
}

unsafe impl Plain for DynamicTableInfo {}

impl AttachedParser {
    /// Returns the state of the dynamic table the parser keeps for the
    /// connection between `local` and `remote`.
    ///
    /// # Errors
    ///
    /// Returns an error if the parser has not seen a header block on that
    /// connection yet, or if the map cannot be read.
    ///
    /// # Panics
    ///
    /// Panics if either address is an IPv6 address.
    pub fn dynamic_table_info(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<DynamicTableInfo> {
        let conn = ip4_conn {
            local: local.into(),
            remote: remote.into(),
        };

        let key = unsafe { conn.as_bytes() };
        let val = self.dynamic_table_info.lookup(key, MapFlags::empty())?;
        let Some(val) = val else {
            bail!("no dynamic table info for connection");
        };

        let info: Result<&DynamicTableInfo, _> = plain::from_bytes(&val);
        match info {
            Ok(info) => Ok(info.clone()),
            Err(e) => bail!("failed to parse dynamic table info: {:?}", e),
        }
    }
    pub fn forget_conn(&self, local: SocketAddr, remote: SocketAddr) -> Result<()> {
        let conn = ip4_conn {
            local: local.into(),
            remote: remote.into(),
        };
        let key = unsafe { conn.as_bytes() };

        if let Some(val) = self.dynamic_table_info.lookup(key, MapFlags::empty())? {
            let info: &DynamicTableInfo = match plain::from_bytes(&val) {
                Ok(info) => info,
                Err(e) => bail!("failed to parse dynamic table info: {:?}", e),
            };

            // entries are stored under the running count of the ones added, the
            // evicted ones below `deleted` are already gone
            let first = DYNAMIC_TABLE_BASE + info.deleted;
            for idx in first..first + info.count {
                let entry = dynamic_table_key { conn, idx };
                delete_if_present(&self.dynamic_table, unsafe { entry.as_bytes() })?;
            }

            delete_if_present(&self.dynamic_table_info, key)?;
        }

        delete_if_present(&self.continued_blocks, key)?;

        Ok(())
    }
}

fn delete_if_present(map: &MapHandle, key: &[u8]) -> Result<()> {
    match map.delete(key) {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pseudo_header::{METHOD, PATH, STATUS};

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
        // a pseudo-header is matched under the colon spelled name
        let names: [&dyn AsRef<[u8]>; 4] = [&hdr(0), &METHOD, &PATH, &STATUS];
        for name in names {
            let name = name.as_ref();
            let mut parser = Parser::new();
            let first = parser.capture_hdr(name).expect("capture header");
            let second = parser.capture_hdr(name).expect("capture header again");

            assert_eq!(
                first,
                second,
                "capturing {} twice handed out two ids for one range",
                String::from_utf8_lossy(name)
            );
        }
    }
}
