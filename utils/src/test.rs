//! A BPF program the integration tests attach a parser to.
//!
//! It parses every message on a connection to the server under test and stores
//! the captured ranges in a map, so that a test can assert on them from user
//! space.

#![allow(unused_imports)]

use anyhow::Result;
use as_bytes::AsBytes;
use beeper::h2::Parser;
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

/// The test program, attached to a socket map and a cgroup.
///
/// It stays attached until it is dropped.
pub struct TestProgram<'obj> {
    skel: ProgSkel<'obj>,
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
        let address = address
            .to_socket_addrs()?
            .next()
            .expect("Failed to parse address");

        let skel_builder = ProgSkelBuilder::default();
        let mut open_skel = skel_builder.open(open_obj)?;
        if tracing::event_enabled!(Level::TRACE) {
            open_skel.progs.msg_verdict.set_log_level(1);
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
        skel.progs.msg_verdict.attach_sockmap(sock_map_fd)?;

        debug!("Test program attached");

        Ok(Self { sockops, skel })
    }

    /// Returns the number of connections that were upgraded to HTTP/2, i.e. the
    /// number of times the program matched the HTTP/2 preface.
    pub fn num_upgraded_conns(&self) -> Result<u32> {
        let func = &self.skel.progs.get_num_upgraded_conns;
        let input = ProgramInput::default();

        Ok(func.test_run(input)?.return_value)
    }

    /// Returns the range captured for the match `idx` in the last parsed
    /// message, or `None` if the parser did not capture one.
    pub fn get_match(&self, idx: usize) -> Result<Option<Vec<u8>>> {
        let id = self.skel.maps.matches.info()?.info.id;
        let map = MapHandle::from_map_id(id)?;

        let key = idx as u32;
        let key = unsafe { key.as_bytes() };
        let val = map.lookup(&key, MapFlags::empty())?;

        if let Some(val) = val {
            let val = val.iter().take_while(|&k| *k != 0).cloned().collect();
            Ok(Some(val))
        } else {
            Ok(None)
        }
    }

    /// Returns the file descriptor of the program a parser attaches to.
    pub fn prog_fd(&self) -> i32 {
        self.skel.progs.msg_verdict.as_fd().as_raw_fd()
    }
}
