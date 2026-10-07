use beeper::dns;
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use utils::{
    server,
    test::{DnsMsg, DnsRr, Hook, TestProgram},
};
use xbpf::OpenObject;

// Must stay in sync with beeper/dns.h.
const DNS_RES_EDNS: u16 = 1 << 0;
const DNS_ERR_FORMAT: i32 = -2;

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_OPT: u16 = 41;
const CLASS_IN: u16 = 1;

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
#[derive(Default)]
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

    fn raw(&mut self, v: &[u8]) -> &mut Msg {
        self.0.extend_from_slice(v);
        self
    }

    fn question(&mut self, owner: &[u8], qtype: u16, qclass: u16) -> &mut Msg {
        self.raw(owner).u16(qtype).u16(qclass)
    }

    fn rr(&mut self, owner: &[u8], rtype: u16, class: u16, ttl: u32, rdata: &[u8]) -> &mut Msg {
        self.raw(owner).u16(rtype).u16(class);
        self.0.extend_from_slice(&ttl.to_be_bytes());
        self.u16(rdata.len() as u16).raw(rdata)
    }

    /// The message with the length prefix it carries over TCP.
    fn tcp(&self) -> Vec<u8> {
        let mut out = (self.0.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&self.0);
        out
    }
}

fn query(id: u16, qname: &str) -> Msg {
    let mut msg = Msg::header(id, 0x0100, [1, 0, 0, 0]);
    msg.question(&name(qname), TYPE_A, CLASS_IN);
    msg
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

/// Writes `buf` to a connection to the echo server at `addr` and waits until
/// it is echoed back, by which time the program parsed it.
async fn send(addr: SocketAddr, buf: &[u8]) {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream.write_all(buf).await.expect("write");

    let mut echo = vec![0; buf.len()];
    stream.read_exact(&mut echo).await.expect("read echo");
    assert_eq!(echo, buf);
}

/// Sends `msgs` in a single write over the hook `hook` and returns what the
/// parser made of the last one.
async fn parse(hook: Hook, msgs: &[&Msg]) -> DnsMsg {
    let addr = server::launch_tcp_echo().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach_dns(addr, &mut open_obj, hook).expect("attach");
    let _parser = attach_dns_parser(prog.prog_fd(), hook);

    let buf: Vec<u8> = msgs.iter().flat_map(|msg| msg.tcp()).collect();
    send(addr, &buf).await;

    prog.last_dns()
}

async fn parse_a_query(hook: Hook) {
    let msg = query(0xBEEF, "www.Example.com");
    let res = parse(hook, &[&msg]).await;

    assert_eq!(res.ret as usize, 2 + msg.0.len());
    assert_eq!(res.num_msgs, 1);
    assert_eq!(res.len as usize, msg.0.len());
    assert_eq!(res.id, 0xBEEF);
    assert_eq!(res.flags, 0x0100);
    assert_eq!(res.qname.as_deref(), Some("www.example.com"));
    assert_eq!(res.qtype, TYPE_A);
    assert!(res.rrs.is_empty());
}

#[tokio::test]
async fn parse_a_query_in_msg() {
    parse_a_query(Hook::Msg).await;
}

#[tokio::test]
async fn parse_a_query_in_skb() {
    parse_a_query(Hook::Skb).await;
}

#[tokio::test]
async fn parse_pipelined_queries() {
    // RFC 7766 6.2.1.1: a client may send several queries back to back
    let first = query(1, "a.example");
    let second = query(2, "b.example");
    let res = parse(Hook::Msg, &[&first, &second]).await;

    assert_eq!(res.num_msgs, 2);
    assert_eq!(res.id, 2);
    assert_eq!(res.qname.as_deref(), Some("b.example"));
}

async fn parse_a_response(hook: Hook) {
    // www.example.com CNAME web.example.com, web.example.com A 192.0.2.1,
    // with an OPT record that extends the RCODE
    let mut msg = Msg::header(7, 0x8180, [1, 2, 0, 1]);
    msg.question(&name("www.example.com"), TYPE_A, CLASS_IN);
    let cname_off = msg.0.len() as u16;
    let mut cname = vec![3, b'w', b'e', b'b'];
    cname.extend(ptr(16));
    msg.rr(&ptr(12), TYPE_CNAME, CLASS_IN, 300, &cname);
    msg.rr(&ptr(cname_off + 12), TYPE_A, CLASS_IN, 60, &[192, 0, 2, 1]);
    msg.rr(&[0], TYPE_OPT, 1232, 1 << 24, &[]);

    let res = parse(hook, &[&msg]).await;
    assert_eq!(res.ret as usize, 2 + msg.0.len());
    assert_eq!(res.res_flags, DNS_RES_EDNS);
    assert_eq!(res.rcode, 16);
    assert_eq!(res.edns_udp_size, 1232);

    let rr = |owner: &str, rtype, class, ttl, rdlen, section| DnsRr {
        owner: owner.to_string(),
        rtype,
        class,
        ttl,
        rdlen,
        section,
    };
    assert_eq!(
        res.rrs,
        vec![
            rr("www.example.com", TYPE_CNAME, CLASS_IN, 300, 6, 1),
            rr("web.example.com", TYPE_A, CLASS_IN, 60, 4, 1),
            rr(".", TYPE_OPT, 1232, 1 << 24, 0, 3),
        ]
    );
}

#[tokio::test]
async fn parse_a_response_in_msg() {
    parse_a_response(Hook::Msg).await;
}

#[tokio::test]
async fn parse_a_response_in_skb() {
    parse_a_response(Hook::Skb).await;
}

#[tokio::test]
async fn reject_a_compression_loop() {
    let mut msg = Msg::header(1, 0, [1, 0, 0, 0]);
    msg.question(&ptr(12), TYPE_A, CLASS_IN);

    let res = parse(Hook::Msg, &[&msg]).await;
    assert_eq!(res.ret, DNS_ERR_FORMAT);
    assert_eq!(res.num_msgs, 0);
}
