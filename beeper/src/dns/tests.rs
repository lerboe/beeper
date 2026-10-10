//! Runs the parser on handcrafted messages with `BPF_PROG_TEST_RUN`, which
//! needs neither a socket nor a target program to attach to.

use std::mem::MaybeUninit;
use xbpf::libbpf_rs::{
    OpenObject, ProgramInput,
    skel::{OpenSkel, SkelBuilder},
};

mod prog {
    xbpf::include_bpf!("dns/test");
}

use prog::{TestSkel, TestSkelBuilder, types};

// Must stay in sync with beeper/dns.h.
const DNS_PARSE_TCP: u32 = 1 << 0;
const DNS_RES_EDNS: u16 = 1 << 0;
const DNS_RES_TSIG: u16 = 1 << 1;
const DNS_RES_PARTIAL: u16 = 1 << 2;
const DNS_RES_TRAILING: u16 = 1 << 3;
const DNS_NAME_DOTTED: u32 = 1 << 0;
const DNS_NAME_LOWER: u32 = 1 << 1;
const DNS_ERR_INCOMPLETE: i32 = -1;
const DNS_ERR_FORMAT: i32 = -2;
const DNS_ERR_LIMIT: i32 = -3;
const DNS_ERR_END: i32 = -4;

const FLAG_QR: u16 = 1 << 15;
const FLAG_TC: u16 = 1 << 9;
const OPCODE_UPDATE: u16 = 5 << 11;
const OPCODE_DSO: u16 = 6 << 11;

const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_MX: u16 = 15;
const TYPE_OPT: u16 = 41;
const TYPE_TSIG: u16 = 250;
const CLASS_IN: u16 = 1;
const CLASS_ANY: u16 = 255;

/// The length of the Ethernet header the test program skips.
const ETH_HLEN: usize = 14;

/// Encodes `name` in the uncompressed wire format.
fn name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// A compression pointer to `off`, counted from the start of the header.
fn ptr(off: u16) -> Vec<u8> {
    (0xC000 | off).to_be_bytes().to_vec()
}

/// Builds a message octet by octet.
#[derive(Default, Clone)]
struct Msg(Vec<u8>);

impl Msg {
    fn header(id: u16, flags: u16, counts: [u16; 4]) -> Msg {
        let mut msg = Msg::default();
        msg.u16(id).u16(flags);
        for count in counts {
            msg.u16(count);
        }
        msg
    }

    fn u16(&mut self, v: u16) -> &mut Msg {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    fn u32(&mut self, v: u32) -> &mut Msg {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    fn raw(&mut self, v: &[u8]) -> &mut Msg {
        self.0.extend_from_slice(v);
        self
    }

    fn question(&mut self, owner: &[u8], qtype: u16, qclass: u16) -> &mut Msg {
        self.raw(owner).u16(qtype).u16(qclass)
    }

    fn rr(&mut self, owner: &[u8], rtype: u16, class: u16, ttl: u32, rdata: &[u8]) -> &mut Msg {
        self.raw(owner)
            .u16(rtype)
            .u16(class)
            .u32(ttl)
            .u16(rdata.len() as u16)
            .raw(rdata)
    }

    fn tcp(&self) -> Vec<u8> {
        let mut out = (self.0.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&self.0);
        out
    }
}

/// What a run of the test program left behind.
struct Run {
    ret: i32,
    res: types::dns_parse_res,
    qname_ret: i32,
    qname: Vec<u8>,
    rr_ret: i32,
    rrs: Vec<(types::dns_rr, i32, Vec<u8>)>,
}

struct Harness<'obj> {
    skel: TestSkel<'obj>,
}

impl<'obj> Harness<'obj> {
    fn new(open_obj: &'obj mut MaybeUninit<OpenObject>) -> Harness<'obj> {
        let open_skel = TestSkelBuilder::default().open(open_obj).expect("open");
        let skel = open_skel.load().expect("load");
        Harness { skel }
    }

    /// Parses `payload` as a UDP payload.
    fn udp(&mut self, payload: &[u8]) -> Run {
        self.run(payload, 0, 0)
    }

    /// Runs the parser on `payload`, preceded by an Ethernet header.
    fn run(&mut self, payload: &[u8], flags: u32, name_flags: u32) -> Run {
        self.run_at(payload, 0, flags, name_flags)
    }

    /// Runs the parser on the message at `off` of `payload`, which is preceded
    /// by an Ethernet header.
    fn run_at(&mut self, payload: &[u8], off: usize, flags: u32, name_flags: u32) -> Run {
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

/// Converts an offset relative to the message into one relative to the
/// buffer the program parsed.
fn abs(off: usize) -> u16 {
    (ETH_HLEN + off) as u16
}

fn query(qname: &str) -> Msg {
    let mut msg = Msg::header(0x1234, 0x0100, [1, 0, 0, 0]);
    msg.question(&name(qname), TYPE_A, CLASS_IN);
    msg
}

#[test]
fn parse_a_query() {
    let mut open_obj = MaybeUninit::uninit();
    let mut h = Harness::new(&mut open_obj);

    let msg = query("www.Example.com");
    let run = h.udp(&msg.0);

    assert_eq!(run.ret, msg.0.len() as i32);
    assert_eq!(run.res.base, abs(0));
    assert_eq!(run.res.len as usize, msg.0.len());
    assert_eq!(run.res.hdr.id, 0x1234);
    assert_eq!(run.res.hdr.flags, 0x0100);
    assert_eq!(run.res.hdr.qdcount, 1);
    assert_eq!(run.res.q.name.off, abs(12));
    assert_eq!(run.res.q.name.len, 17);
    assert_eq!(run.res.q.qtype, TYPE_A);
    assert_eq!(run.res.q.qclass, CLASS_IN);
    assert_eq!(run.res.flags, 0);
    assert_eq!(run.qname_ret, 17);
    assert_eq!(run.qname, name("www.Example.com"));
    assert_eq!(run.rr_ret, DNS_ERR_END);
    assert!(run.rrs.is_empty());
}

#[test]
fn extract_a_name_dotted_and_lowercased() {
    let mut open_obj = MaybeUninit::uninit();
    let mut h = Harness::new(&mut open_obj);

    let msg = query("www.Example.COM");
    let run = h.run(&msg.0, 0, DNS_NAME_DOTTED | DNS_NAME_LOWER);
    assert_eq!(run.qname, b"www.example.com");
    assert_eq!(run.qname_ret, 15);

    let msg = query(".");
    let run = h.run(&msg.0, 0, DNS_NAME_DOTTED);
    assert_eq!(run.ret, msg.0.len() as i32);
    assert_eq!(run.qname, b".");

    let run = h.run(&msg.0, 0, 0);
    assert_eq!(run.qname, [0]);
}

#[test]
fn follow_compression_pointers() {
    let mut open_obj = MaybeUninit::uninit();
    let mut h = Harness::new(&mut open_obj);

    // www.example.com CNAME web.example.com, web.example.com A 192.0.2.1
    let mut msg = Msg::header(1, FLAG_QR | 0x0180, [1, 2, 0, 0]);
    msg.question(&name("www.example.com"), TYPE_A, CLASS_IN);
    let web = msg.0.len();
    let mut cname = vec![3];
    cname.extend_from_slice(b"web");
    cname.extend(ptr(16)); // example.com of the question
    msg.rr(&ptr(12), TYPE_CNAME, CLASS_IN, 300, &cname);
    let web_off = web + 12; // owner, type, class, ttl, rdlength
    msg.rr(
        &ptr(web_off as u16),
        TYPE_A,
        CLASS_IN,
        0x8000_0000,
        &[192, 0, 2, 1],
    );

    let run = h.run(&msg.0, 0, DNS_NAME_DOTTED);
    assert_eq!(run.ret, msg.0.len() as i32);
    assert_eq!(run.res.sec_off[1], abs(web));
    assert_eq!(run.rr_ret, DNS_ERR_END);
    assert_eq!(run.rrs.len(), 2);

    let (rr, ret, owner) = &run.rrs[0];
    assert_eq!(rr.r#type, TYPE_CNAME);
    assert_eq!(rr.section, 1);
    assert_eq!(rr.ttl, 300);
    assert_eq!(rr.name.len, 2);
    assert_eq!(*ret, 15);
    assert_eq!(owner, b"www.example.com");

    // RFC 8767: a TTL with the high-order bit set is positive
    let (rr, _, owner) = &run.rrs[1];
    assert_eq!(rr.r#type, TYPE_A);
    assert_eq!(rr.ttl, 0x8000_0000);
    assert_eq!(rr.rdlen, 4);
    assert_eq!(rr.rdata_off as usize, ETH_HLEN + msg.0.len() - 4);
    assert_eq!(owner, b"web.example.com");
}

#[test]
fn reject_pointers_that_do_not_lead_backwards() {
    let mut open_obj = MaybeUninit::uninit();
    let mut h = Harness::new(&mut open_obj);

    // a pointer to itself
    let mut msg = Msg::header(1, 0, [1, 0, 0, 0]);
    msg.question(&ptr(12), TYPE_A, CLASS_IN);
    assert_eq!(h.udp(&msg.0).ret, DNS_ERR_FORMAT);

    // a pointer into its own labels
    let mut owner = name("a");
    owner.pop();
    owner.extend(ptr(12));
    let mut msg = Msg::header(1, 0, [1, 0, 0, 0]);
    msg.question(&owner, TYPE_A, CLASS_IN);
    assert_eq!(h.udp(&msg.0).ret, DNS_ERR_FORMAT);

    // a pointer forwards
    let mut msg = Msg::header(1, FLAG_QR, [1, 1, 0, 0]);
    msg.question(&ptr(40), TYPE_A, CLASS_IN);
    msg.rr(&name("a"), TYPE_A, CLASS_IN, 0, &[1, 2, 3, 4]);
    assert_eq!(h.udp(&msg.0).ret, DNS_ERR_FORMAT);

    // a pointer into the header
    let mut msg = Msg::header(1, 0, [1, 0, 0, 0]);
    msg.question(&ptr(2), TYPE_A, CLASS_IN);
    assert_eq!(h.udp(&msg.0).ret, DNS_ERR_FORMAT);

    // two pointers pointing at each other, through the RDATA of a CNAME
    let mut msg = Msg::header(1, FLAG_QR, [0, 2, 0, 0]);
    msg.rr(&name("a"), TYPE_CNAME, CLASS_IN, 0, &ptr(31));
    msg.rr(&ptr(25), TYPE_A, CLASS_IN, 0, &[1, 2, 3, 4]);
    assert_eq!(h.udp(&msg.0).ret, DNS_ERR_FORMAT);
}

#[test]
fn follow_a_chain_of_pointers() {
    let mut open_obj = MaybeUninit::uninit();
    let mut h = Harness::new(&mut open_obj);

    // every NS points at the previous one, the first one at the question
    let mut msg = Msg::header(1, FLAG_QR, [1, 0, 8, 0]);
    msg.question(&name("example.com"), TYPE_NS, CLASS_IN);
    let mut target = 12;
    for _ in 0..8 {
        let off = msg.0.len() as u16;
        msg.rr(&ptr(12), TYPE_NS, CLASS_IN, 60, &ptr(target));
        target = off + 12;
    }

    let run = h.run(&msg.0, 0, DNS_NAME_DOTTED);
    assert_eq!(run.ret, msg.0.len() as i32);
    assert_eq!(run.rrs.len(), 8);
    assert!(
        run.rrs
            .iter()
            .all(|(rr, _, owner)| rr.section == 2 && owner == b"example.com")
    );
}

#[test]
fn reject_extended_and_reserved_labels() {
    let mut open_obj = MaybeUninit::uninit();
    let mut h = Harness::new(&mut open_obj);

    // RFC 2673 binary label, RFC 6891 5
    let mut msg = Msg::header(1, 0, [1, 0, 0, 0]);
    msg.question(&[0x41, 0x08, 0xFF, 0x00], TYPE_A, CLASS_IN);
    assert_eq!(h.udp(&msg.0).ret, DNS_ERR_FORMAT);

    let mut msg = Msg::header(1, 0, [1, 0, 0, 0]);
    msg.question(&[0x80, 0x00], TYPE_A, CLASS_IN);
    assert_eq!(h.udp(&msg.0).ret, DNS_ERR_FORMAT);
}

#[test]
fn limit_the_length_of_labels_and_names() {
    let mut open_obj = MaybeUninit::uninit();
    let mut h = Harness::new(&mut open_obj);

    let label63 = "a".repeat(63);
    let longest = format!("{label63}.{label63}.{label63}.{}", "b".repeat(61));
    assert_eq!(name(&longest).len(), 255);

    let run = h.udp(&query(&longest).0);
    assert!(run.ret > 0);
    assert_eq!(run.qname_ret, 255);
    assert_eq!(run.qname, name(&longest));

    let too_long = format!("{longest}b");
    assert_eq!(h.udp(&query(&too_long).0).ret, DNS_ERR_FORMAT);

    // a label of 64 octets starts with the `01` prefix
    let label64 = "a".repeat(64);
    assert_eq!(h.udp(&query(&label64).0).ret, DNS_ERR_FORMAT);
}

#[test]
fn parse_messages_framed_for_tcp() {
    let mut open_obj = MaybeUninit::uninit();
    let mut h = Harness::new(&mut open_obj);

    let first = query("a.example");
    let second = query("b.example");
    let mut stream = first.tcp();
    stream.extend(second.tcp());

    let run = h.run(&stream, DNS_PARSE_TCP, DNS_NAME_DOTTED);
    assert_eq!(run.ret as usize, 2 + first.0.len());
    assert_eq!(run.res.base, abs(2));
    assert_eq!(run.qname, b"a.example");

    // the second message, as a program walking the buffer would parse it
    let run = h.run_at(&stream, 2 + first.0.len(), DNS_PARSE_TCP, DNS_NAME_DOTTED);
    assert_eq!(run.ret as usize, 2 + second.0.len());
    assert_eq!(run.res.base, abs(4 + first.0.len()));
    assert_eq!(run.qname, b"b.example");

    // a zero length is too short for a header
    assert_eq!(h.run(&[0; 16], DNS_PARSE_TCP, 0).ret, DNS_ERR_FORMAT);

    // a message that is not complete yet announces how long it is
    let partial = &stream[..first.0.len()];
    let run = h.run(partial, DNS_PARSE_TCP, 0);
    assert_eq!(run.ret, DNS_ERR_INCOMPLETE);
    assert_eq!(run.res.len as usize, first.0.len());

    let run = h.run(&stream[..1], DNS_PARSE_TCP, 0);
    assert_eq!(run.ret, DNS_ERR_INCOMPLETE);

    // the length prefix frames the message exactly
    let mut padded = first.clone();
    padded.raw(&[0, 0]);
    assert_eq!(h.run(&padded.tcp(), DNS_PARSE_TCP, 0).ret, DNS_ERR_FORMAT);
}

#[test]
fn ignore_trailing_octets_of_a_datagram() {
    let mut open_obj = MaybeUninit::uninit();
    let mut h = Harness::new(&mut open_obj);

    let msg = query("example.com");
    let mut padded = msg.clone();
    padded.raw(&[0xAA; 7]);

    let run = h.udp(&padded.0);
    assert_eq!(run.ret as usize, msg.0.len());
    assert_eq!(run.res.len as usize, msg.0.len());
    assert_eq!(run.res.flags, DNS_RES_TRAILING);
}

#[test]
fn reject_short_and_truncated_messages() {
    let mut open_obj = MaybeUninit::uninit();
    let mut h = Harness::new(&mut open_obj);

    assert_eq!(h.udp(&[0; 11]).ret, DNS_ERR_FORMAT);

    let msg = query("example.com");
    assert_eq!(h.udp(&msg.0[..msg.0.len() - 1]).ret, DNS_ERR_FORMAT);

    // counts that announce more records than there are
    let mut msg = Msg::header(1, FLAG_QR, [1, 2, 0, 0]);
    msg.question(&name("example.com"), TYPE_A, CLASS_IN);
    msg.rr(&ptr(12), TYPE_A, CLASS_IN, 0, &[1, 2, 3, 4]);
    assert_eq!(h.udp(&msg.0).ret, DNS_ERR_FORMAT);

    // unless the message is truncated, RFC 2181 9
    let mut msg = Msg::header(1, FLAG_QR | FLAG_TC, [1, 2, 0, 0]);
    msg.question(&name("example.com"), TYPE_A, CLASS_IN);
    msg.rr(&ptr(12), TYPE_A, CLASS_IN, 0, &[1, 2, 3, 4]);
    let run = h.udp(&msg.0);
    assert_eq!(run.ret, msg.0.len() as i32);
    assert_eq!(run.res.flags, DNS_RES_PARTIAL);
    assert_eq!(run.rrs.len(), 1);
}

#[test]
fn allow_at_most_one_question_in_a_query() {
    let mut open_obj = MaybeUninit::uninit();
    let mut h = Harness::new(&mut open_obj);

    // RFC 9619
    let mut msg = Msg::header(1, 0, [2, 0, 0, 0]);
    msg.question(&name("a"), TYPE_A, CLASS_IN);
    msg.question(&name("b"), TYPE_A, CLASS_IN);
    assert_eq!(h.udp(&msg.0).ret, DNS_ERR_FORMAT);

    // which does not make an empty question section malformed
    let msg = Msg::header(1, FLAG_QR, [0, 0, 0, 0]);
    let run = h.udp(&msg.0);
    assert_eq!(run.ret, 12);
    assert_eq!(run.qname_ret, 0);
}

#[test]
fn parse_dso_messages() {
    let mut open_obj = MaybeUninit::uninit();
    let mut h = Harness::new(&mut open_obj);

    // RFC 8490: a keepalive TLV
    let mut msg = Msg::header(1, OPCODE_DSO, [0, 0, 0, 0]);
    msg.u16(1).u16(8).u32(15000).u32(15000);
    let run = h.run(&msg.tcp(), DNS_PARSE_TCP, 0);
    assert_eq!(run.ret as usize, 2 + msg.0.len());
    assert_eq!(run.rr_ret, DNS_ERR_END);

    // with a TLV that overruns the message
    let mut msg = Msg::header(1, OPCODE_DSO, [0, 0, 0, 0]);
    msg.u16(1).u16(9).u32(15000).u32(15000);
    assert_eq!(h.run(&msg.tcp(), DNS_PARSE_TCP, 0).ret, DNS_ERR_FORMAT);

    // with a count that is not zero
    let mut msg = Msg::header(1, OPCODE_DSO, [1, 0, 0, 0]);
    msg.question(&name("a"), TYPE_A, CLASS_IN);
    assert_eq!(h.run(&msg.tcp(), DNS_PARSE_TCP, 0).ret, DNS_ERR_FORMAT);
}

/// An OPT record with the given extended RCODE, DO bit and options.
fn opt(owner: &[u8], ext_rcode: u8, dnssec_ok: bool, options: &[u8]) -> (Vec<u8>, u32) {
    let ttl = (ext_rcode as u32) << 24 | if dnssec_ok { 1 << 15 } else { 0 };
    (
        Msg::default()
            .rr(owner, TYPE_OPT, 1232, ttl, options)
            .0
            .clone(),
        ttl,
    )
}

#[test]
fn parse_edns() {
    let mut open_obj = MaybeUninit::uninit();
    let mut h = Harness::new(&mut open_obj);

    // an NSID and a cookie option, RCODE BADVERS
    let options = [0, 3, 0, 0, 0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8];
    let (rr, _) = opt(&[0], 1, true, &options);
    let mut msg = Msg::header(1, FLAG_QR, [1, 0, 0, 1]);
    msg.question(&name("example.com"), TYPE_A, CLASS_IN);
    let opt_off = msg.0.len();
    msg.raw(&rr);

    let run = h.udp(&msg.0);
    assert_eq!(run.ret, msg.0.len() as i32);
    assert_eq!(run.res.flags, DNS_RES_EDNS);
    assert_eq!(run.res.rcode, 16);
    assert_eq!(run.res.edns.off, abs(opt_off));
    assert_eq!(run.res.edns.udp_size, 1232);
    assert_eq!(run.res.edns.ext_rcode, 1);
    assert_eq!(run.res.edns.version, 0);
    assert_eq!(run.res.edns.flags, 1 << 15);
    assert_eq!(run.res.edns.rdlen as usize, options.len());
    assert_eq!(run.res.edns.rdata_off, abs(opt_off + 11));
    assert_eq!(run.res.sec_off[3], abs(opt_off));
    assert_eq!(run.rrs.len(), 1);
    assert_eq!(run.rrs[0].0.section, 3);

    // options that overrun the record
    let (rr, _) = opt(&[0], 0, false, &[0, 3, 0, 1]);
    let mut msg = Msg::header(1, 0, [0, 0, 0, 1]);
    msg.raw(&rr);
    assert_eq!(h.udp(&msg.0).ret, DNS_ERR_FORMAT);

    // an owner other than the root
    let (rr, _) = opt(&name("a"), 0, false, &[]);
    let mut msg = Msg::header(1, 0, [0, 0, 0, 1]);
    msg.raw(&rr);
    assert_eq!(h.udp(&msg.0).ret, DNS_ERR_FORMAT);

    // two of them
    let (rr, _) = opt(&[0], 0, false, &[]);
    let mut msg = Msg::header(1, 0, [0, 0, 0, 2]);
    msg.raw(&rr).raw(&rr);
    assert_eq!(h.udp(&msg.0).ret, DNS_ERR_FORMAT);

    // outside of the additional section
    let mut msg = Msg::header(1, 0, [0, 1, 0, 0]);
    msg.raw(&rr);
    assert_eq!(h.udp(&msg.0).ret, DNS_ERR_FORMAT);
}

#[test]
fn require_tsig_to_come_last() {
    let mut open_obj = MaybeUninit::uninit();
    let mut h = Harness::new(&mut open_obj);

    let (opt_rr, _) = opt(&[0], 0, false, &[]);
    let tsig = Msg::default()
        .rr(&name("key"), TYPE_TSIG, CLASS_ANY, 0, &[0; 8])
        .0
        .clone();

    let mut msg = Msg::header(1, 0, [1, 0, 0, 2]);
    msg.question(&name("example.com"), TYPE_A, CLASS_IN);
    msg.raw(&opt_rr);
    let tsig_off = msg.0.len();
    msg.raw(&tsig);
    let run = h.udp(&msg.0);
    assert_eq!(run.ret, msg.0.len() as i32);
    assert_eq!(run.res.flags, DNS_RES_EDNS | DNS_RES_TSIG);
    assert_eq!(run.res.tsig_off, abs(tsig_off));

    let mut msg = Msg::header(1, 0, [1, 0, 0, 2]);
    msg.question(&name("example.com"), TYPE_A, CLASS_IN);
    msg.raw(&tsig).raw(&opt_rr);
    assert_eq!(h.udp(&msg.0).ret, DNS_ERR_FORMAT);

    let mut msg = Msg::header(1, 0, [1, 1, 0, 0]);
    msg.question(&name("example.com"), TYPE_A, CLASS_IN);
    msg.raw(&tsig);
    assert_eq!(h.udp(&msg.0).ret, DNS_ERR_FORMAT);
}

#[test]
fn check_the_rdata_of_well_known_types() {
    let mut open_obj = MaybeUninit::uninit();
    let mut h = Harness::new(&mut open_obj);

    let response = |rtype: u16, class: u16, rdata: &[u8]| {
        let mut msg = Msg::header(1, FLAG_QR, [1, 1, 0, 0]);
        msg.question(&name("example.com"), rtype, class);
        msg.rr(&ptr(12), rtype, class, 3600, rdata);
        msg
    };

    assert!(h.udp(&response(TYPE_A, CLASS_IN, &[1, 2, 3, 4]).0).ret > 0);
    assert_eq!(
        h.udp(&response(TYPE_A, CLASS_IN, &[1, 2, 3, 4, 5]).0).ret,
        DNS_ERR_FORMAT
    );
    // the address of an A record depends on its class
    assert!(h.udp(&response(TYPE_A, 3, &[1, 2, 3, 4, 5]).0).ret > 0);

    let mut mx = vec![0, 10];
    mx.extend(name("mail.example.com"));
    assert!(h.udp(&response(TYPE_MX, CLASS_IN, &mx).0).ret > 0);
    mx.push(0);
    assert_eq!(
        h.udp(&response(TYPE_MX, CLASS_IN, &mx).0).ret,
        DNS_ERR_FORMAT
    );

    let mut soa = name("ns.example.com");
    soa.extend(ptr(12));
    soa.extend([0; 20]);
    assert!(h.udp(&response(TYPE_SOA, CLASS_IN, &soa).0).ret > 0);
    soa.pop();
    assert_eq!(
        h.udp(&response(TYPE_SOA, CLASS_IN, &soa).0).ret,
        DNS_ERR_FORMAT
    );

    assert!(h.udp(&response(TYPE_NS, CLASS_IN, &ptr(12)).0).ret > 0);
    assert_eq!(
        h.udp(&response(TYPE_NS, CLASS_IN, &[]).0).ret,
        DNS_ERR_FORMAT
    );

    // opaque RDATA
    assert!(h.udp(&response(16, CLASS_IN, &[3, b'a', b'b', b'c']).0).ret > 0);
}

#[test]
fn parse_updates() {
    let mut open_obj = MaybeUninit::uninit();
    let mut h = Harness::new(&mut open_obj);

    // RFC 2136: delete all A records of www.example.com
    let mut msg = Msg::header(1, OPCODE_UPDATE, [1, 0, 1, 0]);
    msg.question(&name("example.com"), TYPE_SOA, CLASS_IN);
    let mut owner = vec![3, b'w', b'w', b'w'];
    owner.extend(ptr(12));
    msg.rr(&owner, TYPE_A, CLASS_ANY, 0, &[]);
    let run = h.udp(&msg.0);
    assert_eq!(run.ret, msg.0.len() as i32);
    assert_eq!(run.rrs.len(), 1);
    assert_eq!(run.rrs[0].0.section, 2);

    // a zone section without exactly one SOA
    let mut msg = Msg::header(1, OPCODE_UPDATE, [2, 0, 0, 0]);
    msg.question(&name("example.com"), TYPE_SOA, CLASS_IN);
    msg.question(&name("example.org"), TYPE_SOA, CLASS_IN);
    assert_eq!(h.udp(&msg.0).ret, DNS_ERR_FORMAT);

    let mut msg = Msg::header(1, OPCODE_UPDATE, [1, 0, 0, 0]);
    msg.question(&name("example.com"), TYPE_A, CLASS_IN);
    assert_eq!(h.udp(&msg.0).ret, DNS_ERR_FORMAT);

    // empty RDATA is only allowed in updates
    let mut msg = Msg::header(1, FLAG_QR, [0, 1, 0, 0]);
    msg.rr(&name("www.example.com"), TYPE_A, CLASS_IN, 0, &[]);
    assert_eq!(h.udp(&msg.0).ret, DNS_ERR_FORMAT);
}

#[test]
fn reject_names_beyond_the_parser_limits() {
    let mut open_obj = MaybeUninit::uninit();
    let mut h = Harness::new(&mut open_obj);

    // the opaque RDATA of the first record holds a chain of pointers, each
    // pointing at the one before it, the first at the question
    let chain = |hops: u16| {
        let mut msg = Msg::header(1, FLAG_QR, [1, 2, 0, 0]);
        msg.question(&name("a"), TYPE_A, CLASS_IN);
        let rdata_off = msg.0.len() as u16 + 12; // owner pointer, type, class, ttl, rdlength
        let mut rdata = ptr(12);
        for i in 1..hops {
            rdata.extend(ptr(rdata_off + 2 * (i - 1)));
        }
        msg.rr(&ptr(12), 16, CLASS_IN, 0, &rdata);
        msg.rr(
            &ptr(rdata_off + 2 * (hops - 1)),
            TYPE_A,
            CLASS_IN,
            0,
            &[1, 2, 3, 4],
        );
        msg
    };

    // the walk takes a step for the owner's pointer, one for each pointer of
    // the chain and one for each of the two labels, 192 in all
    let msg = chain(189);
    let run = h.udp(&msg.0);
    assert_eq!(run.ret, msg.0.len() as i32);
    assert_eq!(run.rrs[1].2, name("a"));

    assert_eq!(h.udp(&chain(190).0).ret, DNS_ERR_LIMIT);
}
