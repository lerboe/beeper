//! A BPF program the integration tests attach a parser to.
//!
//! It parses every message on a connection to the server under test and stores
//! the captured ranges in a map, so that a test can assert on them from user
//! space.

#![allow(unused_imports)]

use anyhow::Result;
use as_bytes::AsBytes;
use beeper::{MatchId, MessageBuffer, http2::Parser};
use std::{
    io::{Error, ErrorKind},
    mem::MaybeUninit,
    net::{SocketAddr, ToSocketAddrs},
    ops::{Deref, DerefMut},
    os::{
        fd::{AsFd, AsRawFd, IntoRawFd},
        unix::fs::OpenOptionsExt,
    },
    sync::mpsc::{self, Receiver},
    time::Duration,
};
use tracing::{Level, debug, info, warn};
use types::*;
use xbpf::libbpf_rs::{
    Link, MapCore, MapFlags, MapHandle, MapType, ProgramInput, RingBuffer, RingBufferBuilder,
    skel::{OpenSkel, Skel, SkelBuilder},
};

xbpf::include_bpf!("prog");

/// The direction of the messages to parse. Requests travel downstream to the
/// server, responses upstream to the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// The requests the server receives.
    Downstream,

    /// The responses the server sends.
    Upstream,

    /// Both of them. They overwrite each other's matches, so they are only
    /// told apart in what [`TestProgram::results`] reports.
    Both,
}

/// The hook the program parses messages at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hook {
    /// `sk_msg`, as the messages are sent.
    Msg,

    /// `sk_skb`, as the messages arrive.
    Skb,
}

impl Hook {
    pub fn to_string(&self) -> &str {
        match self {
            Hook::Msg => "msg",
            Hook::Skb => "skb",
        }
    }
}

impl From<Hook> for MessageBuffer {
    fn from(hook: Hook) -> Self {
        match hook {
            Hook::Msg => MessageBuffer::Msg,
            Hook::Skb => MessageBuffer::Skb,
        }
    }
}

/// The test program, attached to a socket map and a cgroup.
///
/// It stays attached until it is dropped.
pub struct TestProgram<'obj> {
    skel: ProgSkel<'obj>,
    hook: Hook,
    #[allow(dead_code)]
    sockops: Link,
}

unsafe impl<'obj> Send for TestProgram<'obj> {}

unsafe impl<'obj> Sync for TestProgram<'obj> {}

impl<'obj> TestProgram<'obj> {
    /// Loads the test program and attaches it to every socket connected to
    /// `address`, parsing the messages travelling in `direction`.
    ///
    /// # Errors
    ///
    /// Returns an error if `address` is not an IPv4 address, or if the program
    /// cannot be loaded or attached.
    pub fn attach<A: ToSocketAddrs>(
        address: A,
        open_obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
        direction: Direction,
    ) -> Result<Self> {
        Self::attach_to(address, open_obj, direction, Hook::Msg)
    }

    pub fn attach_to<A: ToSocketAddrs>(
        address: A,
        open_obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
        direction: Direction,
        hook: Hook,
    ) -> Result<Self> {
        let address = address
            .to_socket_addrs()?
            .next()
            .expect("Failed to parse address");

        let skel_builder = ProgSkelBuilder::default();
        let mut open_skel = skel_builder.open(open_obj)?;
        if tracing::event_enabled!(Level::TRACE) {
            open_skel.progs.msg_verdict.set_log_level(1);
            open_skel.progs.skb_parser.set_log_level(1);
            open_skel.progs.skb_verdict.set_log_level(1);
        }

        let ip4 = match address {
            SocketAddr::V4(addr) => Ok(u32::from_ne_bytes(addr.ip().octets())),
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                "Unsupported address family",
            )),
        }?;

        open_skel.maps.rodata_data.as_mut().unwrap().ip4 = ip4;
        open_skel.maps.rodata_data.as_mut().unwrap().port = address.port() as u32;
        open_skel.maps.rodata_data.as_mut().unwrap().http_parse_resp =
            direction == Direction::Upstream;
        open_skel.maps.rodata_data.as_mut().unwrap().http_parse_both = direction == Direction::Both;
        open_skel.maps.rodata_data.as_mut().unwrap().hook_skb = hook == Hook::Skb;

        let skel = open_skel.load()?;
        let sock_map_fd = skel.maps.sock_map.as_fd().as_raw_fd();

        _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();
        xbpf::tracing::try_init(skel.object())?;

        let cgroup_fd = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open("/sys/fs/cgroup")?
            .into_raw_fd();

        let sockops = skel.progs.monitor_sockets.attach_cgroup(cgroup_fd)?;
        match hook {
            Hook::Msg => skel.progs.msg_verdict.attach_sockmap(sock_map_fd)?,
            Hook::Skb => {
                skel.progs.skb_parser.attach_sockmap(sock_map_fd)?;
                skel.progs.skb_verdict.attach_sockmap(sock_map_fd)?;
            }
        }

        debug!("Test program attached");

        Ok(Self {
            sockops,
            skel,
            hook,
        })
    }

    /// Returns the number of connections that were upgraded to HTTP/2, i.e. the
    /// number of times the program matched the HTTP/2 preface.
    pub fn num_upgraded_conns(&self) -> Result<u32> {
        let func = &self.skel.progs.get_num_upgraded_conns;
        let input = ProgramInput::default();

        Ok(func.test_run(input)?.return_value)
    }

    /// Returns the range captured for the match `mid` in the last parsed
    /// message, or `None` if the parser did not capture one.
    pub fn get_match(&self, mid: MatchId) -> Result<Option<Vec<u8>>> {
        let id = self.skel.maps.matches.info()?.info.id;
        let map = MapHandle::from_map_id(id)?;

        let key = u8::from(mid) as u32;
        let key = unsafe { key.as_bytes() };
        let val = map.lookup(&key, MapFlags::empty())?;

        if let Some(val) = val {
            let val = val.iter().take_while(|&k| *k != 0).cloned().collect();
            Ok(Some(val))
        } else {
            Ok(None)
        }
    }

    /// Returns the match ids the parser reported a capture for in the last
    /// message it parsed, one bit per id.
    pub fn last_matches(&self) -> u32 {
        self.skel.maps.bss_data.as_ref().unwrap().last_matches
    }

    pub fn last_dt_counts(&self) -> (u32, u32) {
        let bss = self.skel.maps.bss_data.as_ref().unwrap();
        (bss.last_dt_count_before, bss.last_dt_count)
    }

    /// Returns what the program parses from now on, as it parses it: every
    /// HTTP/2 header frame, and the opening and closing of every connection to
    /// the server, in the order they happened.
    ///
    /// A connection's frames are all reported before both of its ends are
    /// reported closed, so a reader that waits for that does not miss any.
    ///
    /// # Errors
    ///
    /// Returns an error if the ring buffer the program writes to cannot be
    /// opened.
    pub fn results(&self) -> Result<Receiver<ParseResult>> {
        let id = self.skel.maps.results.info()?.info.id;
        let map = MapHandle::from_map_id(id)?;
        let (tx, rx) = mpsc::channel();

        let mut builder = RingBufferBuilder::new();
        builder.add(&map, move |data: &[u8]| match ParseResult::read(data) {
            // the receiver is gone, which stops the polling below
            Some(res) => tx.send(res).map_or(-1, |_| 0),
            None => {
                warn!("Dropping a result of {}B", data.len());
                0
            }
        })?;
        let ring_buf = builder.build()?;

        // a ring buffer is not `Send`, but it is only ever used by the thread
        // it is handed to, along with the map it reads
        struct Polled {
            ring_buf: RingBuffer<'static>,
            _map: MapHandle,
        }
        unsafe impl Send for Polled {}
        let polled = Polled {
            ring_buf,
            _map: map,
        };

        std::thread::spawn(move || {
            let polled = polled;
            while polled.ring_buf.poll(Duration::from_millis(100)).is_ok() {}
        });

        Ok(rx)
    }

    /// Makes [`TestProgram::results`] report a [`ParseResult::Mark`], after
    /// everything that was reported before this call.
    ///
    /// # Errors
    ///
    /// Returns an error if the program that writes it cannot be run.
    pub fn mark_results(&self) -> Result<()> {
        self.skel
            .progs
            .mark_results
            .test_run(ProgramInput::default())?;
        Ok(())
    }

    /// Returns the file descriptor of the program a parser attaches to.
    pub fn prog_fd(&self) -> i32 {
        match self.hook {
            Hook::Msg => self.skel.progs.msg_verdict.as_fd().as_raw_fd(),
            Hook::Skb => self.skel.progs.skb_verdict.as_fd().as_raw_fd(),
        }
    }
}

/// The number of match ids a parser hands out at most.
pub const MAX_MATCHES: usize = 32;

/// The number of bytes of a captured value [`TestProgram::results`] reports.
pub const RESULT_VAL_LEN: usize = 128;

/// The layout of `struct parse_result` of the program.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawParseResult {
    kind: u32,
    client_port: u32,
    upstream: u32,
    ret: i32,
    sid: u32,
    frame_type: u32,
    flags: u32,
    captured: u32,
    lens: [u32; MAX_MATCHES],
    vals: [[u8; RESULT_VAL_LEN]; MAX_MATCHES],
}

/// A value the parser captured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capture {
    /// The length of the value, as it was sent.
    pub len: u32,

    /// The first [`RESULT_VAL_LEN`] bytes of the value, as it was sent, i.e.
    /// Huffman coded if that is how it was sent.
    pub head: Vec<u8>,
}

/// An HTTP/2 header frame the program parsed.
#[derive(Clone, Debug)]
pub struct Frame {
    /// The port of the client end of the connection it was sent on.
    pub client_port: u16,

    /// Whether it is a response.
    pub upstream: bool,

    /// What the parser returned for it, negative if it failed to parse it.
    pub ret: i32,

    pub sid: u32,
    pub frame_type: u8,
    pub flags: u8,

    /// What the parser captured, indexed by match id.
    pub captures: Vec<Option<Capture>>,
}

/// What the program reports through [`TestProgram::results`].
#[derive(Clone, Debug)]
pub enum ParseResult {
    /// An end of a connection to the server was established. `server` tells
    /// the server's end from the client's.
    Open { client_port: u16, server: bool },

    /// An end of a connection was closed.
    Close { client_port: u16, server: bool },

    /// A header frame was parsed.
    Frame(Frame),

    /// What [`TestProgram::mark_results`] asked for.
    Mark,
}

impl ParseResult {
    /// Reads a result off the ring buffer, or returns `None` if `data` is not
    /// one.
    fn read(data: &[u8]) -> Option<Self> {
        if data.len() < std::mem::size_of::<RawParseResult>() {
            return None;
        }

        let raw = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const RawParseResult) };
        let client_port = raw.client_port as u16;
        let server = raw.upstream != 0;

        match raw.kind {
            0 => Some(ParseResult::Open {
                client_port,
                server,
            }),
            1 => Some(ParseResult::Close {
                client_port,
                server,
            }),
            3 => Some(ParseResult::Mark),
            2 => {
                // only the values `captured` names were written
                let captures = (0..MAX_MATCHES)
                    .map(|i| {
                        (raw.captured & (1 << i) != 0).then(|| {
                            let len = raw.lens[i];
                            let head = raw.vals[i][..(len as usize).min(RESULT_VAL_LEN)].to_vec();
                            Capture { len, head }
                        })
                    })
                    .collect();

                Some(ParseResult::Frame(Frame {
                    client_port,
                    upstream: server,
                    ret: raw.ret,
                    sid: raw.sid,
                    frame_type: raw.frame_type as u8,
                    flags: raw.flags as u8,
                    captures,
                }))
            }
            _ => None,
        }
    }
}
