//! The wire-format parser tests of Hickory DNS (`hickory-proto`), replicated
//! for beeper.
//!
//! Each test sends the messages of one of hickory-proto's tests over TCP, so
//! that beeper parses them in the kernel, and checks that beeper reads them
//! the way hickory-proto does: both have to accept or reject a message, and
//! agree on what an accepted one holds. hickory-proto builds the messages its
//! own tests build with its types, much like the HTTP/2 tests use the `h2`
//! crate as their client, and raw vectors are sent as they are.
//!
//! Where beeper deliberately parts ways with hickory-proto, the test says so
//! and asserts both outcomes.

use beeper::dns;
use hickory_proto::{
    dnssec::SupportedAlgorithms,
    op::{Edns, Header, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{
            A, AAAA, MX, OPT, SOA, TSIG,
            opt::{ClientSubnet, EdnsCode, EdnsOption},
            tsig::TsigAlgorithm,
        },
    },
    serialize::binary::{BinDecodable, BinEncodable, BinEncoder},
};
use std::{net::SocketAddr, str::FromStr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use utils::{
    server,
    test::{DnsMsg, Hook, TestProgram},
};
use xbpf::OpenObject;

// Must stay in sync with beeper/dns.h.
const DNS_RES_EDNS: u16 = 1 << 0;
const DNS_RES_TSIG: u16 = 1 << 1;
const DNS_RES_PARTIAL: u16 = 1 << 2;
const DNS_ERR_LIMIT: i32 = -3;

const TYPE_A: u16 = 1;
const TYPE_NULL: u16 = 10;
const TYPE_OPT: u16 = 41;
const TYPE_TSIG: u16 = 250;
const CLASS_IN: u16 = 1;

/// The number of records the test program keeps of a message.
const MAX_RRS: usize = 8;

/// A connection to the echo server, over which messages travel as they do
/// over TCP, each preceded by its length.
struct Client {
    stream: TcpStream,
}

impl Client {
    async fn connect(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).await.expect("connect");
        Self { stream }
    }

    /// Sends `msg` and waits until it is echoed back, by which time the
    /// program parsed it.
    async fn send(&mut self, msg: &[u8]) {
        let mut buf = (msg.len() as u16).to_be_bytes().to_vec();
        buf.extend_from_slice(msg);
        self.stream.write_all(&buf).await.expect("write");

        let mut echo = vec![0; buf.len()];
        self.stream.read_exact(&mut echo).await.expect("read echo");
        assert_eq!(echo, buf);
    }

    /// Encodes `msg` with hickory-proto, sends it, and returns its encoding.
    async fn send_message(&mut self, msg: &Message) -> Vec<u8> {
        let bytes = msg.to_vec().expect("encode message");
        self.send(&bytes).await;
        bytes
    }
}

/// Attaches a parser providing every function of the DNS parser.
fn attach_dns_parser(prog_fd: i32, hook: Hook) -> dns::AttachedParser {
    let suffix = hook.to_string();
    dns::Parser::new()
        .parse_fn(format!("parse_dns_{suffix}"), hook.into())
        .next_rr_fn(format!("next_dns_rr_{suffix}"), hook.into())
        .extract_name_fn(format!("extract_dns_name_{suffix}"), hook.into())
        .attach(prog_fd)
        .expect("attach parser")
}

/// Spells `name` the way the test program extracts names: lowercased, with
/// the labels joined by dots, and the root as a single dot.
fn dotted(name: &Name) -> String {
    let name = name.to_lowercase().to_ascii();
    match name.strip_suffix('.') {
        Some("") | None => ".".to_string(),
        Some(name) => name.to_string(),
    }
}

/// Returns the `len` octets at the buffer offset `off` of the message `msg`
/// beeper parsed as `res`.
fn slice<'m>(msg: &'m [u8], res: &DnsMsg, off: u16, len: u16) -> &'m [u8] {
    let start = (off - res.base) as usize;
    &msg[start..start + len as usize]
}

/// Asserts that beeper read `msg` the way hickory-proto does, and returns what
/// beeper made of it.
fn assert_parsed_like_hickory(prog: &TestProgram, msg: &[u8]) -> DnsMsg {
    let res = prog.last_dns();
    let expected = match Message::from_vec(msg) {
        Ok(expected) => expected,
        Err(err) => {
            assert!(
                res.ret < 0,
                "hickory rejects the message ({err}), beeper accepts it: {res:?}"
            );
            return res;
        }
    };

    assert!(
        res.ret >= 0,
        "hickory accepts the message, beeper rejects it ({}): {expected:?}",
        res.ret
    );
    assert_eq!(res.len as usize, msg.len());

    // the header
    let meta = &expected.metadata;
    let flag = |bit: u16| res.flags & bit != 0;
    assert_eq!(res.id, meta.id);
    assert_eq!(flag(1 << 15), meta.message_type == MessageType::Response);
    assert_eq!(((res.flags >> 11) & 0xF) as u8, u8::from(meta.op_code));
    assert_eq!(flag(1 << 10), meta.authoritative);
    assert_eq!(flag(1 << 9), meta.truncation);
    assert_eq!(flag(1 << 8), meta.recursion_desired);
    assert_eq!(flag(1 << 7), meta.recursion_available);
    assert_eq!(flag(1 << 5), meta.authentic_data);
    assert_eq!(flag(1 << 4), meta.checking_disabled);
    assert_eq!(res.rcode, u16::from(meta.response_code));

    // the question
    if let Some(query) = expected.queries.first() {
        assert_eq!(res.qname.as_deref(), Some(dotted(&query.name).as_str()));
        assert_eq!(res.qtype, u16::from(query.query_type));
        assert_eq!(res.qclass, u16::from(query.query_class));
    }

    // the records, of which hickory-proto takes the OPT and TSIG ones apart
    let sections = [
        (1, &expected.answers),
        (2, &expected.authorities),
        (3, &expected.additionals),
    ];
    let expected_rrs: Vec<_> = sections
        .iter()
        .flat_map(|(section, rrs)| rrs.iter().map(move |rr| (*section, rr)))
        .collect();
    let actual_rrs: Vec<_> = res
        .rrs
        .iter()
        .filter(|rr| rr.rtype != TYPE_OPT && rr.rtype != TYPE_TSIG)
        .collect();

    if res.rrs.len() < MAX_RRS {
        assert_eq!(actual_rrs.len(), expected_rrs.len(), "{res:?}");
    }
    for (actual, (section, expected)) in actual_rrs.iter().zip(&expected_rrs) {
        assert_eq!(actual.owner, dotted(&expected.name));
        assert_eq!(actual.rtype, u16::from(expected.record_type()));
        assert_eq!(actual.class, u16::from(expected.dns_class));
        assert_eq!(actual.ttl, expected.ttl);
        assert_eq!(actual.section, *section);

        // the addresses tell whether beeper found the RDATA where it is
        let rdata = slice(msg, &res, actual.rdata_off, actual.rdlen);
        match &expected.data {
            RData::A(a) => assert_eq!(rdata, a.0.octets()),
            RData::AAAA(aaaa) => assert_eq!(rdata, aaaa.0.octets()),
            _ => {}
        }
    }

    // EDNS(0), of which hickory-proto raises the payload size to 512
    assert_eq!(res.res_flags & DNS_RES_EDNS != 0, expected.edns.is_some());
    if let Some(edns) = &expected.edns {
        assert_eq!(res.edns_udp_size.max(512), edns.max_payload());
        assert_eq!(res.edns_version, edns.version());
        assert_eq!(res.edns_ext_rcode, edns.rcode_high());
        assert_eq!(res.edns_flags, u16::from(*edns.flags()));
    }

    assert_eq!(
        res.res_flags & DNS_RES_TSIG != 0,
        expected.signature.is_some()
    );

    res
}

/// Builds a message of `answers` and `additionals`, the way hickory-proto's
/// `encode_and_read_records` lays out records, behind a response header.
fn records_message(answers: &[Record], additionals: &[Record]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut encoder = BinEncoder::new(&mut buf);
    for v in [
        1,
        0x8180,
        0,
        answers.len() as u16,
        0,
        additionals.len() as u16,
    ] {
        encoder.emit_u16(v).expect("emit header");
    }
    for rr in answers.iter().chain(additionals) {
        rr.emit(&mut encoder).expect("emit record");
    }

    buf
}

/// A question for `name`, as a query of the type A.
fn query_message(name: &[u8]) -> Vec<u8> {
    let mut msg = vec![0, 1, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    msg.extend_from_slice(name);
    msg.extend_from_slice(&[0, 1, 0, 1]);
    msg
}

fn a_record(name: &str, ttl: u32) -> Record {
    Record::from_rdata(
        Name::from_str(name).unwrap(),
        ttl,
        RData::A(A::new(127, 0, 0, 1)),
    )
}

fn opt_record() -> Record {
    Record::from_rdata(
        Name::new(),
        0,
        RData::OPT(OPT::new(vec![(
            EdnsCode::Subnet,
            EdnsOption::Subnet(ClientSubnet::new([127, 0, 0, 1].into(), 0, 24)),
        )])),
    )
}

/// The TSIG record of hickory-proto's `fake_tsig`, owned by `name`.
fn tsig_record(name: &str) -> Record {
    Record::from_rdata(
        Name::from_str(name).unwrap(),
        0,
        RData::TSIG(TSIG::new(
            TsigAlgorithm::HmacSha256,
            0,
            0,
            vec![],
            0,
            None,
            vec![],
        )),
    )
}

/// A response to a query for `name`, with `answers`.
fn response(name: &str, answers: Vec<Record>) -> Message {
    let mut msg = Message::response(7, OpCode::Query);
    msg.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    msg.add_answers(answers);
    msg
}

// name.rs: test_read
#[tokio::test]
async fn read_names() {
    let addr = server::launch_tcp_echo().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach_dns(addr, &mut open_obj, Hook::Msg).expect("attach");
    let _dns = attach_dns_parser(prog.prog_fd(), Hook::Msg);
    let mut client = Client::connect(addr).await;

    let names: [(&str, &[u8]); 4] = [
        (".", &[0]),
        ("a.", &[1, b'a', 0]),
        ("a.bc.", &[1, b'a', 2, b'b', b'c', 0]),
        (
            "a.xn--g6h.",
            &[1, b'a', 7, b'x', b'n', b'-', b'-', b'g', b'6', b'h', 0],
        ),
    ];

    for (name, wire) in names {
        let msg = query_message(wire);
        client.send(&msg).await;

        let res = assert_parsed_like_hickory(&prog, &msg);
        assert_eq!(
            res.qname.as_deref(),
            Some(dotted(&Name::from_str(name).unwrap()).as_str())
        );
    }
}

async fn read_pointers(hook: Hook) {
    let addr = server::launch_tcp_echo().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach_dns(addr, &mut open_obj, hook).expect("attach");
    let _dns = attach_dns_parser(prog.prog_fd(), hook);
    let mut client = Client::connect(addr).await;

    // name.rs: test_pointer, where each name ends in a pointer to the ones
    // before it
    let owners = ["ra.rb.rc.", "rb.rc.", "rc.", "z.ra.rb.rc."];
    let msg = response(
        "ra.rb.rc.",
        owners.iter().map(|o| a_record(o, 60)).collect(),
    );
    let msg = client.send_message(&msg).await;

    let res = assert_parsed_like_hickory(&prog, &msg);
    let actual: Vec<_> = res.rrs.iter().map(|rr| rr.owner.as_str()).collect();
    assert_eq!(actual, ["ra.rb.rc", "rb.rc", "rc", "z.ra.rb.rc"]);
    // the owners take 2 + 2 + 2 + 4 octets, rather than the 10 + 7 + 4 + 12
    // they would uncompressed
    let records = 4 * (2 + 2 + 4 + 2 + 4);
    assert_eq!(msg.len(), 12 + 10 + 4 + records + 2 + 2 + 2 + 4);

    // name.rs: test_pointer_with_pointer_ending_labels, where a label is
    // followed by a pointer to a suffix
    let owners = ["ra.rb.rc.", "ra.rc.", "ra.rc."];
    let msg = response(
        "ra.rb.rc.",
        owners.iter().map(|o| a_record(o, 60)).collect(),
    );
    let msg = client.send_message(&msg).await;

    let res = assert_parsed_like_hickory(&prog, &msg);
    let actual: Vec<_> = res.rrs.iter().map(|rr| rr.owner.as_str()).collect();
    assert_eq!(actual, ["ra.rb.rc", "ra.rc", "ra.rc"]);
}

#[tokio::test]
async fn read_pointers_in_msg() {
    read_pointers(Hook::Msg).await;
}

#[tokio::test]
async fn read_pointers_in_skb() {
    read_pointers(Hook::Skb).await;
}

#[tokio::test]
async fn reject_recursive_pointers() {
    let addr = server::launch_tcp_echo().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach_dns(addr, &mut open_obj, Hook::Msg).expect("attach");
    let _dns = attach_dns_parser(prog.prog_fd(), Hook::Msg);
    let mut client = Client::connect(addr).await;

    let names: [&[u8]; 4] = [
        // points into the pointer itself
        &[0xC0, 0x0D],
        // points at itself
        &[0xC0, 0x0C],
        // a label, then a pointer back to it
        &[0x01, 0x41, 0xC0, 0x0C],
        // a pointer forwards, to a pointer back
        &[0xC0, 0x0E, 0xC0, 0x0C],
    ];

    for name in names {
        let msg = query_message(name);
        client.send(&msg).await;

        let res = assert_parsed_like_hickory(&prog, &msg);
        assert!(res.ret < 0, "{name:x?}");
    }
}

/// A message whose second record is owned by the end of a chain of `hops`
/// pointers, each pointing at the one before it and the first at the root.
fn pointer_chain_message(hops: u16) -> Vec<u8> {
    let mut msg = vec![0, 1, 0x81, 0x80, 0, 0, 0, 2, 0, 0, 0, 0];

    let start = msg.len() as u16 + 11; // the root owner, type, class, ttl, rdlength
    let mut chain = vec![0x00];
    for i in 0..hops {
        let target = if i == 0 {
            start
        } else {
            start + 1 + 2 * (i - 1)
        };
        chain.extend((0xC000 | target).to_be_bytes());
    }
    let last = start + 1 + 2 * (hops - 1);

    msg.push(0);
    msg.extend(TYPE_NULL.to_be_bytes());
    msg.extend(CLASS_IN.to_be_bytes());
    msg.extend(0u32.to_be_bytes());
    msg.extend((chain.len() as u16).to_be_bytes());
    msg.extend(chain);

    msg.extend((0xC000 | last).to_be_bytes());
    msg.extend(TYPE_A.to_be_bytes());
    msg.extend(CLASS_IN.to_be_bytes());
    msg.extend(0u32.to_be_bytes());
    msg.extend(4u16.to_be_bytes());
    msg.extend([192, 0, 2, 1]);

    msg
}

// hickory-proto follows a chain of 8000 pointers, beeper stops after 192
// steps of a name walk, as the verifier needs a bound. A chain that long
//  is never written by a server.
#[tokio::test]
async fn limit_long_pointer_chains() {
    let addr = server::launch_tcp_echo().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach_dns(addr, &mut open_obj, Hook::Msg).expect("attach");
    let _dns = attach_dns_parser(prog.prog_fd(), Hook::Msg);
    let mut client = Client::connect(addr).await;

    // a chain within the bound reads as hickory-proto reads it
    let msg = pointer_chain_message(100);
    client.send(&msg).await;
    let res = assert_parsed_like_hickory(&prog, &msg);
    assert_eq!(res.rrs[1].owner, ".");

    // the chain of hickory-proto's test
    let msg = pointer_chain_message(8000);
    client.send(&msg).await;
    let expected = Message::from_vec(&msg).expect("hickory reads the chain");
    assert!(expected.answers[1].name.is_root());
    assert_eq!(prog.last_dns().ret, DNS_ERR_LIMIT);
}

// A name whose labels run on into the
// pointers that follow them, and whose pointers lead back into those labels.
// As in hickory-proto, the bytes are at the start of the buffer, which is the
// RDATA of a record here, and the name is read 31 octets in.
#[tokio::test]
async fn reject_overlapping_labels() {
    let addr = server::launch_tcp_echo().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach_dns(addr, &mut open_obj, Hook::Msg).expect("attach");
    let _dns = attach_dns_parser(prog.prog_fd(), Hook::Msg);
    let mut client = Client::connect(addr).await;

    let mut msg = vec![0, 1, 0x81, 0x80, 0, 0, 0, 2, 0, 0, 0, 0];
    let start = msg.len() as u16 + 11; // the root owner, type, class, ttl, rdlength

    let n: u8 = 31;
    let mut bytes = Vec::new();
    for _ in 0..=5 {
        bytes.extend(std::iter::repeat_n(n, n as usize));
    }
    bytes.push(n + 1);
    for b in 0..n {
        bytes.push(1 + n + b);
    }
    bytes.extend_from_slice(&[1, 0]);
    for b in 0..n {
        bytes.extend((0xC000 | (start + b as u16)).to_be_bytes());
    }

    msg.push(0);
    msg.extend(TYPE_NULL.to_be_bytes());
    msg.extend(CLASS_IN.to_be_bytes());
    msg.extend(0u32.to_be_bytes());
    msg.extend((bytes.len() as u16).to_be_bytes());
    msg.extend(bytes);

    msg.extend((0xC000 | (start + n as u16)).to_be_bytes());
    msg.extend(TYPE_A.to_be_bytes());
    msg.extend(CLASS_IN.to_be_bytes());
    msg.extend(0u32.to_be_bytes());
    msg.extend(4u16.to_be_bytes());
    msg.extend([192, 0, 2, 1]);

    client.send(&msg).await;
    let res = assert_parsed_like_hickory(&prog, &msg);
    assert!(res.ret < 0);
}

#[tokio::test]
async fn limit_names_to_255_octets() {
    let addr = server::launch_tcp_echo().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach_dns(addr, &mut open_obj, Hook::Msg).expect("attach");
    let _dns = attach_dns_parser(prog.prog_fd(), Hook::Msg);
    let mut client = Client::connect(addr).await;

    // 256 labels of one octet
    let mut name = Vec::new();
    for _ in 0..256 {
        name.extend_from_slice(&[1, b'a']);
    }
    name.push(0);
    let msg = query_message(&name);
    client.send(&msg).await;
    let res = assert_parsed_like_hickory(&prog, &msg);
    assert!(res.ret < 0);

    // three labels of 63 octets and one of 61, 255 octets in all
    let mut name = Vec::new();
    for len in [63, 63, 63, 61] {
        name.push(len);
        name.extend(std::iter::repeat_n(b'a', len as usize));
    }
    name.push(0);
    assert_eq!(name.len(), 255);
    let msg = query_message(&name);
    client.send(&msg).await;
    let res = assert_parsed_like_hickory(&prog, &msg);
    let expected = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "a".repeat(61));
    assert_eq!(res.qname.as_deref(), Some(expected.as_str()));

    // one octet more
    name[0] += 1;
    name.insert(1, b'a');
    let msg = query_message(&name);
    client.send(&msg).await;
    let res = assert_parsed_like_hickory(&prog, &msg);
    assert!(res.ret < 0);
}

#[rustfmt::skip]
const LEGIT_MESSAGE: &[u8] = &[
    0x10, 0x00, 0x81, 0x80, // id = 4096, response, op=query, recursion_desired, recursion_available, no_error
    0x00, 0x01, 0x00, 0x01, // 1 query, 1 answer,
    0x00, 0x00, 0x00, 0x00, // 0 nameservers, 0 additional record
    0x03, b'w', b'w', b'w', // query --- www.example.com
    0x07, b'e', b'x', b'a', //
    b'm', b'p', b'l', b'e', //
    0x03, b'c', b'o', b'm', //
    0x00,                   // 0 = endname
    0x00, 0x01, 0x00, 0x01, // RecordType = A, Class = IN
    0xC0, 0x0C,             // name pointer to www.example.com
    0x00, 0x01, 0x00, 0x01, // RecordType = A, Class = IN
    0x00, 0x00, 0x00, 0x02, // TTL = 2 seconds
    0x00, 0x04,             // record length = 4 (ipv4 address)
    0x5D, 0xB8, 0xD7, 0x0E, // address = 93.184.215.14
];

async fn read_legit_message(hook: Hook) {
    let addr = server::launch_tcp_echo().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach_dns(addr, &mut open_obj, hook).expect("attach");
    let _dns = attach_dns_parser(prog.prog_fd(), hook);
    let mut client = Client::connect(addr).await;

    client.send(LEGIT_MESSAGE).await;
    let res = assert_parsed_like_hickory(&prog, LEGIT_MESSAGE);
    assert_eq!(res.id, 4096);
    assert_eq!(res.qname.as_deref(), Some("www.example.com"));
    assert_eq!(res.rrs[0].owner, "www.example.com");
    assert_eq!(res.rrs[0].ttl, 2);
    assert_eq!(
        slice(LEGIT_MESSAGE, &res, res.rrs[0].rdata_off, 4),
        [93, 184, 215, 14]
    );

    // and once more, as hickory-proto encodes it
    let msg = Message::from_vec(LEGIT_MESSAGE).expect("decode");
    let msg = client.send_message(&msg).await;
    let res = assert_parsed_like_hickory(&prog, &msg);
    assert_eq!(res.id, 4096);
    assert_eq!(res.num_msgs, 2);
}

#[tokio::test]
async fn read_legit_message_in_msg() {
    read_legit_message(Hook::Msg).await;
}

#[tokio::test]
async fn read_legit_message_in_skb() {
    read_legit_message(Hook::Skb).await;
}

// hickory-proto reads type 0 as the
// placeholder of an UPDATE and rejects its RDATA. RFC 6895 reserves the type,
// but RFC 1035 lays its RDATA out like any other, so beeper accepts it as
// opaque.
#[tokio::test]
async fn accept_rdata_of_type_zero() {
    let addr = server::launch_tcp_echo().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach_dns(addr, &mut open_obj, Hook::Msg).expect("attach");
    let _dns = attach_dns_parser(prog.prog_fd(), Hook::Msg);
    let mut client = Client::connect(addr).await;

    let msg = [
        160, 160, 0, 13, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0,
    ];
    client.send(&msg).await;

    assert!(Message::from_vec(&msg).is_err());
    let res = prog.last_dns();
    assert_eq!(res.ret as usize, 2 + msg.len());
    assert_eq!(res.rrs.len(), 1);
    assert_eq!(res.rrs[0].rtype, 0);
    assert_eq!(res.rrs[0].rdlen, 1);
}

// message.rs: nsec_deserialization, an mDNS response that once crashed
// hickory-proto
#[tokio::test]
async fn read_nsec_message() {
    let addr = server::launch_tcp_echo().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach_dns(addr, &mut open_obj, Hook::Msg).expect("attach");
    let _dns = attach_dns_parser(prog.prog_fd(), Hook::Msg);
    let mut client = Client::connect(addr).await;

    const MSG: &[u8] = &[
        0, 0, 132, 0, 0, 0, 0, 1, 0, 0, 0, 1, 36, 49, 101, 48, 101, 101, 51, 100, 51, 45, 100, 52,
        50, 52, 45, 52, 102, 55, 56, 45, 57, 101, 52, 99, 45, 99, 51, 56, 51, 51, 55, 55, 56, 48,
        102, 50, 98, 5, 108, 111, 99, 97, 108, 0, 0, 1, 128, 1, 0, 0, 0, 120, 0, 4, 192, 168, 1,
        17, 36, 49, 101, 48, 101, 101, 51, 100, 51, 45, 100, 52, 50, 52, 45, 52, 102, 55, 56, 45,
        57, 101, 52, 99, 45, 99, 51, 56, 51, 51, 55, 55, 56, 48, 102, 50, 98, 5, 108, 111, 99, 97,
        108, 0, 0, 47, 128, 1, 0, 0, 0, 120, 0, 5, 192, 70, 0, 1, 64,
    ];
    client.send(MSG).await;

    let res = assert_parsed_like_hickory(&prog, MSG);
    assert_eq!(res.rrs.len(), 2);
    assert_eq!(res.rrs[1].section, 3);
}

// Each case lays out its records the way
// hickory-proto's `encode_and_read_records` does, in the answer or in the
// additional section, and both parsers have to accept or reject them.
#[tokio::test]
async fn read_records() {
    let addr = server::launch_tcp_echo().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach_dns(addr, &mut open_obj, Hook::Msg).expect("attach");
    let _dns = attach_dns_parser(prog.prog_fd(), Hook::Msg);
    let mut client = Client::connect(addr).await;

    let a = || a_record("example.com.", 300);
    let tsig = || tsig_record("tsig.example.com.");
    let sig0 = || tsig_record("sig0.example.com.");

    // the name of the case, its answers and additional records, and the
    // flags beeper reports, if it accepts the case
    type Case = (&'static str, Vec<Record>, Vec<Record>, Option<u16>);
    let cases: Vec<Case> = vec![
        (
            "unsigned",
            vec![a(), a_record("www.example.com.", 300)],
            vec![],
            Some(0),
        ),
        ("edns", vec![], vec![a(), opt_record()], Some(DNS_RES_EDNS)),
        ("tsig", vec![], vec![a(), tsig()], Some(DNS_RES_TSIG)),
        (
            "edns_tsig",
            vec![],
            vec![a(), opt_record(), tsig()],
            Some(DNS_RES_EDNS | DNS_RES_TSIG),
        ),
        (
            "unsigned_multiple_edns",
            vec![],
            vec![opt_record(), a(), opt_record()],
            None,
        ),
        ("opt_not_additional", vec![opt_record(), a()], vec![], None),
        (
            "signed_multiple_edns",
            vec![],
            vec![opt_record(), a(), opt_record(), tsig()],
            None,
        ),
        ("tsig_not_additional", vec![a(), tsig()], vec![], None),
        ("tsig_not_last", vec![], vec![a(), tsig(), a()], None),
        ("sig0_not_last", vec![], vec![a(), sig0(), a()], None),
        ("multiple_tsig", vec![], vec![a(), tsig(), tsig()], None),
        ("multiple_sig0", vec![], vec![a(), sig0(), sig0()], None),
    ];

    for (case, answers, additionals, expected) in cases {
        let msg = records_message(&answers, &additionals);
        client.send(&msg).await;

        let res = assert_parsed_like_hickory(&prog, &msg);
        match expected {
            Some(flags) => assert_eq!(res.res_flags, flags, "{case}"),
            None => assert!(res.ret < 0, "{case}: {res:?}"),
        }
    }
}

// hickory-proto only reads the header, whose counts
// announce more than the message holds. As it is truncated, beeper accepts
// it, RFC 2181 9, while hickory-proto's message parser does not.
#[tokio::test]
async fn read_header() {
    let addr = server::launch_tcp_echo().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach_dns(addr, &mut open_obj, Hook::Msg).expect("attach");
    let _dns = attach_dns_parser(prog.prog_fd(), Hook::Msg);
    let mut client = Client::connect(addr).await;

    let msg = [
        0x01, 0x10, 0xAA, 0x83, // 0b1010 1010 1000 0011
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    ];
    client.send(&msg).await;

    let expected = Header::from_bytes(&msg).expect("decode header");
    assert_eq!(expected.metadata.op_code, OpCode::Update);
    assert_eq!(expected.metadata.response_code, ResponseCode::NXDomain);
    assert!(Message::from_vec(&msg).is_err());

    let res = prog.last_dns();
    assert_eq!(res.ret as usize, 2 + msg.len());
    assert_eq!(res.res_flags, DNS_RES_PARTIAL);
    assert_eq!(res.id, expected.metadata.id);
    assert_eq!(res.flags, 0xAA83);
    assert_eq!(res.rcode, u16::from(expected.metadata.response_code));
    let counts = &expected.counts;
    assert_eq!(
        res.counts,
        [
            counts.queries,
            counts.answers,
            counts.authorities,
            counts.additionals
        ]
    );
}

#[tokio::test]
async fn read_query() {
    let addr = server::launch_tcp_echo().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach_dns(addr, &mut open_obj, Hook::Msg).expect("attach");
    let _dns = attach_dns_parser(prog.prog_fd(), Hook::Msg);
    let mut client = Client::connect(addr).await;

    let mut msg = Message::query();
    msg.add_query(Query::query(
        Name::from_ascii("WWW.example.com.").unwrap(),
        RecordType::AAAA,
    ));
    let msg = client.send_message(&msg).await;

    let res = assert_parsed_like_hickory(&prog, &msg);
    assert_eq!(res.qname.as_deref(), Some("www.example.com"));
    assert_eq!(res.qtype, u16::from(RecordType::AAAA));
    // the case of the name is left as it is on the wire
    assert_eq!(&msg[13..16], b"WWW");
}

// opt.rs: test_read_empty_option_at_end_of_opt
#[tokio::test]
async fn read_empty_option_at_end_of_opt() {
    let addr = server::launch_tcp_echo().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach_dns(addr, &mut open_obj, Hook::Msg).expect("attach");
    let _dns = attach_dns_parser(prog.prog_fd(), Hook::Msg);
    let mut client = Client::connect(addr).await;

    let options: &[u8] = &[
        0x00, 0x0a, 0x00, 0x08, 0x0b, 0x64, 0xb4, 0xdc, 0xd7, 0xb0, 0xcc, 0x8f, 0x00, 0x08, 0x00,
        0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00,
    ];
    let mut msg = vec![0, 1, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 1, 0];
    msg.extend(TYPE_OPT.to_be_bytes());
    msg.extend(1232u16.to_be_bytes());
    msg.extend(0u32.to_be_bytes());
    msg.extend((options.len() as u16).to_be_bytes());
    msg.extend(options);
    client.send(&msg).await;

    let res = assert_parsed_like_hickory(&prog, &msg);
    assert_eq!(res.edns_rdlen as usize, options.len());

    let expected = Message::from_vec(&msg).unwrap();
    assert_eq!(expected.edns.unwrap().options().as_ref().len(), 3);
}

#[tokio::test]
async fn read_edns() {
    let addr = server::launch_tcp_echo().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach_dns(addr, &mut open_obj, Hook::Msg).expect("attach");
    let _dns = attach_dns_parser(prog.prog_fd(), Hook::Msg);
    let mut client = Client::connect(addr).await;

    let mut edns = Edns::new();
    let flags = edns.flags_mut();
    flags.dnssec_ok = true;
    flags.z = 1;
    edns.set_max_payload(0x8008);
    edns.set_version(0x40);
    edns.options_mut()
        .insert(EdnsOption::DAU(SupportedAlgorithms::all()));

    // hickory-proto takes the upper bits of the RCODE from the header
    let mut msg = Message::response(1, OpCode::Query);
    msg.metadata.response_code = ResponseCode::from(0x01, 0);
    msg.set_edns(edns);
    let msg = client.send_message(&msg).await;

    let res = assert_parsed_like_hickory(&prog, &msg);
    assert_eq!(res.edns_flags, 0x8001);
    assert_eq!(res.edns_udp_size, 0x8008);
    assert_eq!(res.edns_version, 0x40);
    assert_eq!(res.edns_ext_rcode, 0x01);
    assert_eq!(res.rcode, 0x10);
}

#[tokio::test]
async fn read_addresses() {
    let addr = server::launch_tcp_echo().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach_dns(addr, &mut open_obj, Hook::Msg).expect("attach");
    let _dns = attach_dns_parser(prog.prog_fd(), Hook::Msg);
    let mut client = Client::connect(addr).await;

    let a = [
        "0.0.0.0",
        "1.0.0.0",
        "0.1.0.0",
        "0.0.1.0",
        "0.0.0.1",
        "127.0.0.1",
        "192.168.64.32",
    ];
    let aaaa = [
        "::",
        "1::",
        "0:1::",
        "0:0:1::",
        "0:0:0:1::",
        "::1:0:0:0",
        "::1:0:0",
        "::1:0",
        "::1",
        "::127.0.0.1",
        "FF00::192.168.64.32",
    ];

    let rdatas = a
        .iter()
        .map(|a| RData::A(A::from_str(a).unwrap()))
        .chain(aaaa.iter().map(|a| RData::AAAA(AAAA::from_str(a).unwrap())));

    for rdata in rdatas {
        let msg = response(
            "example.com.",
            vec![Record::from_rdata(
                Name::from_str("example.com.").unwrap(),
                60,
                rdata,
            )],
        );
        let msg = client.send_message(&msg).await;

        let res = assert_parsed_like_hickory(&prog, &msg);
        assert_eq!(res.rrs.len(), 1);
    }
}

#[tokio::test]
async fn read_names_in_rdata() {
    let addr = server::launch_tcp_echo().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach_dns(addr, &mut open_obj, Hook::Msg).expect("attach");
    let _dns = attach_dns_parser(prog.prog_fd(), Hook::Msg);
    let mut client = Client::connect(addr).await;

    let name = || Name::from_str("example.com.").unwrap();
    let mx = RData::MX(MX::new(16, Name::from_str("mail.example.com.").unwrap()));
    let soa = RData::SOA(SOA::new(
        Name::from_str("m.example.com.").unwrap(),
        Name::from_str("r.example.com.").unwrap(),
        1,
        2,
        3,
        4,
        5,
    ));

    for rdata in [mx, soa] {
        let msg = response("example.com.", vec![Record::from_rdata(name(), 60, rdata)]);
        let msg = client.send_message(&msg).await;

        let res = assert_parsed_like_hickory(&prog, &msg);
        assert_eq!(res.rrs.len(), 1);
    }

    // with the RDATA cut short by an octet, which leaves the last name
    // running into the next record
    let rdata = RData::MX(MX::new(16, Name::from_str("mail.example.com.").unwrap()));
    let msg = response(
        "example.com.",
        vec![
            Record::from_rdata(name(), 60, rdata),
            a_record("example.com.", 60),
        ],
    );
    let mut msg = msg.to_vec().unwrap();
    // the A record takes 16 octets, the MX RDATA 9: the preference, the label
    // `mail` and a pointer to the question
    let rdlen_off = msg.len() - 16 - 9 - 2;
    assert_eq!(msg[rdlen_off..rdlen_off + 2], [0, 9]);
    msg[rdlen_off + 1] -= 1;
    client.send(&msg).await;

    let res = assert_parsed_like_hickory(&prog, &msg);
    assert!(res.ret < 0);
}
