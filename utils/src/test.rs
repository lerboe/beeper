//! A BPF program the integration tests attach a parser to.
//!
//! It parses every message on a connection to the server under test and stores
//! the captured ranges in a map, so that a test can assert on them from user
//! space.

#![allow(unused_imports)]

use anyhow::Result;
use as_bytes::AsBytes;
use beeper::{MatchId, MessageBuffer, h2::Parser};
use std::{
    io::{Error, ErrorKind},
    mem::MaybeUninit,
    net::{SocketAddr, ToSocketAddrs},
    ops::{Deref, DerefMut},
    os::{
        fd::{AsFd, AsRawFd, IntoRawFd},
        unix::fs::OpenOptionsExt,
    },
};
use tracing::{Level, debug, info, warn};
use types::*;
use xbpf::libbpf::{
    self as libbpf_rs, Link, MapCore, MapFlags, MapHandle, MapType, ProgramInput,
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
}

/// The hook the program parses messages at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hook {
    /// `sk_msg`, as the messages are sent.
    Msg,

    /// `sk_skb`, as the messages arrive.
    Skb,

    /// A buffer handed over as a dynptr, parsed on demand rather than on a
    /// socket. See [`TestProgram::parse_h1_buf`].
    Buf,
}

impl Hook {
    pub fn to_string(&self) -> &str {
        match self {
            Hook::Msg => "msg",
            Hook::Skb => "skb",
            Hook::Buf => "buf",
        }
    }
}

impl From<Hook> for MessageBuffer {
    fn from(hook: Hook) -> Self {
        match hook {
            Hook::Msg => MessageBuffer::Msg,
            Hook::Skb => MessageBuffer::Skb,
            Hook::Buf => MessageBuffer::DynPtr,
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
        open_skel.maps.rodata_data.as_mut().unwrap().parse_resp = direction == Direction::Upstream;
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
            // a buffer arrives at no socket, the test hands it over itself
            Hook::Buf => {}
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

    /// Parses `buf` with the HTTP/1.x parser attached at [`Hook::Buf`] and
    /// returns what it reported.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer does not fit, or if the program that
    /// hands it over cannot be run.
    pub fn parse_h1_buf(&self, buf: &[u8]) -> Result<i32> {
        self.parse_buf(buf, None)
    }

    /// Same as [`TestProgram::parse_h1_buf`], for the HTTP/2 parser. The
    /// buffer is parsed as the connection between `local` and `remote`, which
    /// is what the parser keys its dynamic table with.
    pub fn parse_h2_buf(&self, buf: &[u8], local: SocketAddr, remote: SocketAddr) -> Result<i32> {
        self.parse_buf(buf, Some((local, remote)))
    }

    /// Hands `buf` to the buffer parsers, as HTTP/2 if `conn` names the
    /// connection it belongs to and as HTTP/1.x otherwise.
    fn parse_buf(&self, buf: &[u8], conn: Option<(SocketAddr, SocketAddr)>) -> Result<i32> {
        let mut args = buf_args {
            len: buf.len() as u32,
            is_h2: MaybeUninit::new(conn.is_some()),
            ..Default::default()
        };

        if buf.len() > args.data.len() {
            return Err(Error::new(ErrorKind::InvalidInput, "buffer does not fit").into());
        }
        args.data[..buf.len()].copy_from_slice(buf);

        if let Some((local, remote)) = conn {
            args.conn = ip4_conn {
                local: ip4_addr(local),
                remote: ip4_addr(remote),
            };
        }

        let key = 0u32;
        self.skel.maps.buf_input.update(
            unsafe { key.as_bytes() },
            unsafe { args.as_bytes() },
            MapFlags::ANY,
        )?;

        let input = ProgramInput::default();
        Ok(self
            .skel
            .progs
            .parse_buf_input
            .test_run(input)?
            .return_value as i32)
    }

    /// Returns the file descriptor of the program a parser attaches to.
    pub fn prog_fd(&self) -> i32 {
        match self.hook {
            Hook::Msg => self.skel.progs.msg_verdict.as_fd().as_raw_fd(),
            Hook::Skb => self.skel.progs.skb_verdict.as_fd().as_raw_fd(),
            Hook::Buf => self.skel.progs.parse_buf_input.as_fd().as_raw_fd(),
        }
    }
}

/// Converts `addr` into the address the BPF programs key a connection with.
///
/// # Panics
///
/// Panics if `addr` is an IPv6 address, which beeper does not support.
fn ip4_addr(addr: SocketAddr) -> types::ip4_addr {
    match addr {
        SocketAddr::V4(addr) => types::ip4_addr {
            ip4: u32::from_ne_bytes(addr.ip().octets()),
            port: addr.port() as u32,
        },
        SocketAddr::V6(_) => panic!("ip4_addr does not support IPv6 addresses"),
    }
}
