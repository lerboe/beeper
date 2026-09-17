//! Loads the eBPF monitor and attaches the beeper parsers it logs traffic
//! with.
#![allow(unused_imports)]
use anyhow::Result;
use beeper::{h1, h2, header::PATH, header::STATUS};
use http::header::ACCEPT_LANGUAGE;
use std::{
    io::{Error, ErrorKind},
    mem::MaybeUninit,
    net::{SocketAddr, ToSocketAddrs},
    os::{
        fd::{AsFd, AsRawFd, IntoRawFd},
        unix::fs::OpenOptionsExt,
    },
};
use xbpf::libbpf::{
    self as libbpf_rs, Link, MapCore,
    skel::{OpenSkel, Skel, SkelBuilder},
};

xbpf::include_bpf!("monitor");

/// Logs every request and response of the server at the address it is
/// attached to.
///
/// Stays attached for as long as the returned value is alive.
pub struct Monitor<'obj> {
    #[allow(dead_code)]
    skel: MonitorSkel<'obj>,
    #[allow(dead_code)]
    sockops: Link,
    #[allow(dead_code)]
    h1: h1::AttachedParser,
    #[allow(dead_code)]
    h2: h2::AttachedParser,
}

impl<'obj> Monitor<'obj> {
    /// Loads the monitor and attaches it, along with its parsers, to every
    /// socket of the server at `addr`.
    pub fn attach<A: ToSocketAddrs>(
        addr: A,
        open_obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        let addr = addr.to_socket_addrs()?.next().expect("no address");

        let skel_builder = MonitorSkelBuilder::default();
        let mut open_skel = skel_builder.open(open_obj)?;

        let ip4 = match addr {
            SocketAddr::V4(addr) => Ok(u32::from_ne_bytes(addr.ip().octets())),
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                "Unsupported address family",
            )),
        }?;

        open_skel.maps.rodata_data.as_mut().unwrap().ip4 = ip4;
        open_skel.maps.rodata_data.as_mut().unwrap().port = addr.port() as u32;

        let skel = open_skel.load()?;
        xbpf::tracing::try_init(skel.object())?;

        let sock_map_fd = skel.maps.sock_map.as_fd().as_raw_fd();
        let cgroup_fd = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open("/sys/fs/cgroup")?
            .into_raw_fd();

        let sockops = skel.progs.monitor_sockets.attach_cgroup(cgroup_fd)?;
        skel.progs.msg_verdict.attach_sockmap(sock_map_fd)?;

        let prog_fd = skel.progs.msg_verdict.as_fd().as_raw_fd();

        let h1 = h1::Parser::new()
            .match_h2_preface()
            .capture_hdr(&PATH)
            .capture_hdr(&ACCEPT_LANGUAGE)
            .capture_hdr(&STATUS)
            .replace_parse_msg("parse_h1")
            .replace_matched("matched_h1")
            .replace_extract("extract_h1_match")
            .attach(prog_fd)?;

        let h2 = h2::Parser::new()
            .replace_parse_msg("parse_h2")
            .attach(prog_fd)?;

        tracing::debug!("Monitor attached");

        Ok(Self {
            skel,
            sockops,
            h1,
            h2,
        })
    }
}
