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
};
use tracing::{Level, debug, info, warn};
use types::*;
use xbpf::libbpf_rs::{
    Link, MapCore, MapFlags, MapHandle, MapType, ProgramInput,
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
        Self::attach_with(address, open_obj, direction, hook, false)
    }

    /// Same as [`TestProgram::attach_to`], for a connection that carries DNS
    /// over TCP. The program parses the messages travelling downstream with
    /// the DNS parser, see [`TestProgram::last_dns`].
    pub fn attach_dns<A: ToSocketAddrs>(
        address: A,
        open_obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
        hook: Hook,
    ) -> Result<Self> {
        Self::attach_with(address, open_obj, Direction::Downstream, hook, true)
    }

    fn attach_with<A: ToSocketAddrs>(
        address: A,
        open_obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
        direction: Direction,
        hook: Hook,
        dns: bool,
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
        open_skel.maps.rodata_data.as_mut().unwrap().hook_skb = hook == Hook::Skb;
        open_skel.maps.rodata_data.as_mut().unwrap().dns = dns;

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

    /// Returns what the DNS parser made of the last message it parsed.
    pub fn last_dns(&self) -> DnsMsg {
        let bss = self.skel.maps.bss_data.as_ref().unwrap();
        let name =
            |buf: &dns_name_buf| String::from_utf8_lossy(&buf.buf[..buf.len as usize]).into_owned();

        let res = &bss.dns_res;
        DnsMsg {
            ret: bss.dns_ret,
            num_msgs: bss.dns_num_msgs,
            base: res.base,
            len: res.len,
            id: res.hdr.id,
            flags: res.hdr.flags,
            counts: [
                res.hdr.qdcount,
                res.hdr.ancount,
                res.hdr.nscount,
                res.hdr.arcount,
            ],
            rcode: res.rcode,
            res_flags: res.flags,
            qname: (bss.dns_qname_ret >= 0 && res.hdr.qdcount > 0).then(|| name(&bss.dns_qname)),
            qtype: res.q.qtype,
            qclass: res.q.qclass,
            edns_udp_size: res.edns.udp_size,
            edns_version: res.edns.version,
            edns_ext_rcode: res.edns.ext_rcode,
            edns_flags: res.edns.flags,
            edns_rdlen: res.edns.rdlen,
            tsig_off: res.tsig_off,
            rrs: (0..bss.dns_num_rrs as usize)
                .map(|i| {
                    let rr = &bss.dns_rrs[i];
                    DnsRr {
                        owner: name(&bss.dns_rr_names[i]),
                        rtype: rr.r#type,
                        class: rr.class,
                        ttl: rr.ttl,
                        rdlen: rr.rdlen,
                        rdata_off: rr.rdata_off,
                        section: rr.section,
                    }
                })
                .collect(),
        }
    }

    /// Returns the file descriptor of the program a parser attaches to.
    pub fn prog_fd(&self) -> i32 {
        match self.hook {
            Hook::Msg => self.skel.progs.msg_verdict.as_fd().as_raw_fd(),
            Hook::Skb => self.skel.progs.skb_verdict.as_fd().as_raw_fd(),
        }
    }
}

/// What the DNS parser made of a message, see [`TestProgram::last_dns`].
#[derive(Debug, Clone, Default)]
pub struct DnsMsg {
    /// What the parse function returned.
    pub ret: i32,
    /// The number of messages that were parsed so far.
    pub num_msgs: u32,
    /// The offset of the header in the buffer the parser parsed.
    pub base: u16,
    pub len: u16,
    pub id: u16,
    pub flags: u16,
    /// QDCOUNT, ANCOUNT, NSCOUNT and ARCOUNT.
    pub counts: [u16; 4],
    pub rcode: u16,
    /// The `DNS_RES_*` flags.
    pub res_flags: u16,
    /// The question name, dotted and lowercased.
    pub qname: Option<String>,
    pub qtype: u16,
    pub qclass: u16,
    pub edns_udp_size: u16,
    pub edns_version: u8,
    pub edns_ext_rcode: u8,
    pub edns_flags: u16,
    pub edns_rdlen: u16,
    /// The offset of the TSIG record in the buffer, if there is one.
    pub tsig_off: u16,
    /// The first records of the message.
    pub rrs: Vec<DnsRr>,
}

/// A record of a [`DnsMsg`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRr {
    /// The owner name, dotted and lowercased.
    pub owner: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdlen: u16,
    /// The offset of the RDATA in the buffer the parser parsed.
    pub rdata_off: u16,
    pub section: u8,
}
