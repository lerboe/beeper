//! Loads the eBPF monitor and attaches the beeper parsers it logs traffic
//! with.
#![allow(unused_imports)]
use anyhow::Result;
use beeper::{
    MessageBuffer, http1, http2,
    pseudo_header::{PATH, STATUS},
};
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
    http1: http1::AttachedParser,
    #[allow(dead_code)]
    http2: http2::AttachedParser,
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

        let mut h1 = http1::Parser::new();
        let preface_mid = h1.match_http2_preface()?;
        let path_mid = h1.capture_hdr(&PATH)?;
        let lang_mid = h1.capture_hdr(&ACCEPT_LANGUAGE)?;
        let status_mid = h1.capture_hdr(&STATUS)?;

        let rodata = open_skel.maps.rodata_data.as_mut().unwrap();
        rodata.ip4 = ip4;
        rodata.port = addr.port() as u32;
        rodata.h1_preface_mid = preface_mid.into();
        rodata.h1_path_mid = path_mid.into();
        rodata.h1_accept_language_mid = lang_mid.into();
        rodata.h1_status_mid = status_mid.into();

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

        let h1 = h1
            .parse_fn("parse_http1", MessageBuffer::Msg)
            .matched_fn("matched_http1")
            .extract_fn("extract_http1_match", MessageBuffer::Msg)
            .attach(prog_fd)?;

        let h2 = http2::Parser::new()
            .parse_fn("parse_http2", MessageBuffer::Msg)
            .attach(prog_fd)?;

        tracing::debug!("Monitor attached");

        Ok(Self {
            skel,
            sockops,
            http1: h1,
            http2: h2,
        })
    }
}
