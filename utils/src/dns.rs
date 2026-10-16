//! A BPF program the DNS tests attach a parser to.
//!
//! It runs with `BPF_PROG_TEST_RUN` on a message handed in from user space and
//! stores what the parser made of it in its globals, so that a test can assert
//! on them.

use anyhow::Result;
use std::{
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd},
};
use xbpf::libbpf_rs::{
    ProgramInput,
    skel::{OpenSkel, SkelBuilder},
};

xbpf::include_bpf!("dns");

/// The length of the Ethernet header the test program skips.
pub const ETH_HLEN: usize = 14;

/// What a run of the test program left behind.
pub struct Run {
    pub ret: i32,
    pub res: types::dns_parse_res,
    pub qname_ret: i32,
    pub qname: Vec<u8>,
    pub rr_ret: i32,
    pub rrs: Vec<(types::dns_rr, i32, Vec<u8>)>,
}

pub struct DnsProgram<'obj> {
    skel: DnsSkel<'obj>,
}

impl<'obj> DnsProgram<'obj> {
    pub fn load(open_obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>) -> Result<Self> {
        let open_skel = DnsSkelBuilder::default().open(open_obj)?;
        let skel = open_skel.load()?;
        Ok(Self { skel })
    }

    /// Returns the file descriptor of the program a parser attaches to.
    pub fn prog_fd(&self) -> i32 {
        self.skel.progs.run.as_fd().as_raw_fd()
    }

    /// Parses `payload` as a UDP payload.
    pub fn udp(&mut self, payload: &[u8]) -> Run {
        self.run(payload, 0, 0)
    }

    /// Runs the parser on `payload`, preceded by an Ethernet header.
    pub fn run(&mut self, payload: &[u8], flags: u32, name_flags: u32) -> Run {
        self.run_at(payload, 0, flags, name_flags)
    }

    /// Runs the parser on the message at `off` of `payload`, which is preceded
    /// by an Ethernet header.
    pub fn run_at(&mut self, payload: &[u8], off: usize, flags: u32, name_flags: u32) -> Run {
        let bss = self.skel.maps.bss_data.as_deref_mut().expect("bss");
        // SAFETY: the globals of the program are plain data, all zeros is valid
        unsafe { std::ptr::write_bytes(bss as *mut types::bss, 0, 1) };
        bss.test_off = (ETH_HLEN + off) as u32;
        bss.test_flags = flags;
        bss.test_name_flags = name_flags;

        let mut data = vec![0; ETH_HLEN];
        data.extend_from_slice(payload);

        let input = ProgramInput {
            data_in: Some(&data),
            ..Default::default()
        };
        self.skel.progs.run.test_run(input).expect("test run");

        let bss = self.skel.maps.bss_data.as_deref().expect("bss");
        let name_of = |buf: &types::dns_name_buf| buf.buf[..buf.len as usize].to_vec();
        let rrs = (0..bss.test_num_rrs as usize)
            .map(|i| {
                (
                    bss.test_rrs[i],
                    bss.test_rr_name_ret[i],
                    name_of(&bss.test_rr_names[i]),
                )
            })
            .collect();

        Run {
            ret: bss.test_ret,
            res: bss.test_res,
            qname_ret: bss.test_qname_ret,
            qname: name_of(&bss.test_qname),
            rr_ret: bss.test_rr_ret,
            rrs,
        }
    }
}
