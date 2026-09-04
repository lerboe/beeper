#![allow(unused_imports)]
use crate::{
    Dfa, MatchId, autoload_and_attach,
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
    self as libbpf_rs, Link, MapCore, MapFlags, MapHandle, OpenObject,
    skel::{OpenSkel, Skel, SkelBuilder},
};

extern crate plain;

/// The number of ranges a parser can be configured to capture. Must stay in
/// sync with `MAX_MATCHES` of beeper.h.
const MAX_MATCHES: u16 = 32;

/// A parser for HTTP/2 messages.
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
    get_dynamic_table_entry_fn: Option<String>,
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
            parse_msg_fn: None,
            parse_buf_fn: None,
            parse_skb_fn: None,
            extract_fn: None,
            matched_fn: None,
            get_dynamic_table_entry_fn: None,
        }
    }

    /// Specifies the function template in the target program to be replaced with an HTTP/2
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

    /// Specifies the function template in the target program to be replaced with a reader of the
    /// connection's dynamic table (`BEEPER_H2_GET_DT_ENTRY`). The function will not be replaced
    /// until `attach` is called.
    ///
    /// # Arguments
    ///
    /// * `get_dynamic_table_entry_fn` - The name of the dynamic table entry reader function in the target program
    pub fn replace_get_dynamic_table_entry<S: ToString>(
        mut self,
        get_dynamic_table_entry_fn: S,
    ) -> Parser {
        self.get_dynamic_table_entry_fn = Some(get_dynamic_table_entry_fn.to_string());
        self
    }

    /// Configures the parser to capture the value of a header field.
    ///
    /// The field name is matched in its Huffman encoded form, which is how
    /// HPACK puts it on the wire. Fields the peer replaced with an index into
    /// the static or the dynamic table are matched against the entry the index
    /// resolves to. Pseudo-headers are addressed without their leading colon,
    /// see [`crate::header`].
    ///
    /// # Arguments
    ///
    /// * `name` - The header name whose value to capture
    ///
    /// # Errors
    ///
    /// Returns an error if `name` cannot be Huffman encoded, or if the parser
    /// already captures as many fields as the parser program has room for.
    pub fn capture_hdr(mut self, name: &HeaderName) -> Result<Parser> {
        if self.num_matches >= MAX_MATCHES {
            bail!("a parser captures at most {MAX_MATCHES} fields");
        }

        let mut name_encoded = Vec::new();
        huffman::encode(name.as_str().as_bytes(), &mut name_encoded)?;

        let mid = self.new_match();
        self.dfa
            .start_pattern(S_NAME)
            .push_bytes(&name_encoded)
            .with(Action::capture(mid));

        Ok(self)
    }

    /// Returns an unused match id.
    fn new_match(&mut self) -> MatchId {
        let id = MatchId(self.num_matches);
        self.num_matches += 1;
        id
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
    ///
    /// Every function configured with one of the `replace_*` methods is
    /// replaced in the target program, the remaining parser programs are left
    /// unloaded. Loading the parser also populates the HPACK static table.
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
        let skel_builder = ParserSkelBuilder::default();
        let mut open_obj: MaybeUninit<OpenObject> = MaybeUninit::uninit();
        let mut open_skel = skel_builder.open(&mut open_obj)?;
        if tracing::event_enabled!(Level::TRACE) {
            open_skel.progs.parse_msg.set_log_level(1);
            open_skel.progs.parse_skb.set_log_level(1);
            open_skel.progs.parse_buf.set_log_level(1);
        }

        let progs = vec![
            (&mut open_skel.progs.parse_msg, self.parse_msg_fn.clone()),
            (&mut open_skel.progs.parse_skb, self.parse_skb_fn.clone()),
            (&mut open_skel.progs.parse_buf, self.parse_buf_fn.clone()),
            (&mut open_skel.progs.matched, self.matched_fn.clone()),
            (&mut open_skel.progs.extract_match, self.extract_fn.clone()),
            (
                &mut open_skel.progs.get_dt_entry,
                self.get_dynamic_table_entry_fn.clone(),
            ),
        ];

        for (prog, func) in progs {
            autoload_and_attach(prog, target, func)?;
        }

        self.inject(&mut open_skel)?;

        let skel = open_skel.load()?;
        xbpf::tracing::try_init(skel.object())?;

        let mut links = Vec::new();
        if self.parse_msg_fn.is_some() {
            links.push(skel.progs.parse_msg.attach()?);
        }
        if self.parse_skb_fn.is_some() {
            links.push(skel.progs.parse_skb.attach()?);
        }
        if self.parse_buf_fn.is_some() {
            links.push(skel.progs.parse_buf.attach()?);
        }
        if self.matched_fn.is_some() {
            links.push(skel.progs.matched.attach()?);
        }
        if self.extract_fn.is_some() {
            links.push(skel.progs.extract_match.attach()?);
        }
        if self.get_dynamic_table_entry_fn.is_some() {
            links.push(skel.progs.get_dt_entry.attach()?);
        }

        let id = skel.maps.static_table.info()?.info.id;
        let static_table = MapHandle::from_map_id(id)?;
        self.populate_static_table(&static_table)?;

        debug!("Beeper http/2 attached");

        let id = skel.maps.dynamic_table_info.info()?.info.id;
        Ok(AttachedParser {
            dynamic_table_info: MapHandle::from_map_id(id)?,
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
}
