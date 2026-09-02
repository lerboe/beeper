use std::{net::SocketAddr, time::Duration};

use ::h2::{RecvStream, client};
use beeper::{h1, h2};
use bytes::Bytes;
use httlib_huffman as huffman;
use http::{HeaderName, HeaderValue, Request, Response, header};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use utils::{
    server,
    test::{Direction, TestProgram},
};
use xbpf::OpenObject;

const TEST_HEADER: HeaderName = HeaderName::from_static("testheader");
const METHOD_HEADER: HeaderName = HeaderName::from_static("method");
const AUTHORITY_HEADER: HeaderName = HeaderName::from_static("authority");
const PATH_HEADER: HeaderName = HeaderName::from_static("path");

fn huffman_decode(val: &[u8]) -> String {
    let mut res = Vec::new();
    huffman::decode(val, &mut res, huffman::DecoderSpeed::OneBit).unwrap();
    String::from_utf8(res).unwrap()
}

fn dynamic_table_size_for_headers(headers: &[(HeaderName, HeaderValue)]) -> u32 {
    headers.iter().fold(0, |acc, (k, v)| {
        acc + (k.as_str().len() + v.len() + 32) as u32
    })
}

fn assert_match_eq(prog: &TestProgram, idx: usize, expected: Option<&HeaderValue>) {
    let actual_hf = prog.get_match(idx).expect("get_match");
    let actual = actual_hf.map(|val| huffman_decode(&val));

    if expected.is_none() {
        assert!(
            actual.is_none(),
            "get_match({idx}): {}, expected: none",
            actual.unwrap()
        );
    } else {
        let expected = expected.unwrap().to_str().unwrap();
        assert!(
            actual.is_some(),
            "get_match({idx}): none, expected: {expected}"
        );
        assert_eq!(actual.unwrap().as_str(), expected);
    }
}

struct Client {
    send_request: client::SendRequest<Bytes>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl Client {
    async fn connect(addr: SocketAddr, header_table_size: Option<u32>) -> Self {
        let stream = TcpStream::connect(addr).await.expect("connect");
        let local_addr = stream.local_addr().expect("local_addr");
        let remote_addr = stream.peer_addr().expect("peer_addr");

        let mut builder = client::Builder::new();
        if let Some(size) = header_table_size {
            builder.header_table_size(size);
        }

        let (send_request, connection) = builder
            .handshake::<_, Bytes>(stream)
            .await
            .expect("handshake");

        tokio::spawn(async move {
            connection.await.expect("connection");
        });

        Self {
            send_request,
            local_addr,
            remote_addr,
        }
    }

    #[allow(unused_results)]
    async fn get(
        &self,
        uri: String,
        headers: &[(header::HeaderName, HeaderValue)],
    ) -> Response<RecvStream> {
        let response = self.send(uri, headers).await;
        assert!(
            response.status().is_success(),
            "status: {}",
            response.status()
        );

        response
    }

    /// Same as [`Client::get`], but does not expect the server to have accepted
    /// the request. A header list the server turns down still reaches the
    /// parser, which is all some tests need of it.
    #[allow(unused_results)]
    async fn send(
        &self,
        uri: String,
        headers: &[(header::HeaderName, HeaderValue)],
    ) -> Response<RecvStream> {
        let mut req = Request::builder().method("GET").uri(uri);
        for (name, value) in headers {
            req = req.header(name, value);
        }
        let request = req.body(()).expect("build request");

        let mut send_request = self.send_request.clone().ready().await.expect("ready");
        let (response, _) = send_request
            .send_request(request, true)
            .expect("send_request");
        response.await.expect("response")
    }
}

/// The HTTP/2 connection preface, see section 3.5 of RFC 7540.
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The first index of the dynamic table, the static one taking up everything
/// below it.
const FIRST_DYNAMIC_INDEX: u8 = 62;

/// Renders an HTTP/2 frame.
fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    f.push(kind);
    f.push(flags);
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// Renders an HPACK string, spelled out rather than Huffman coded. Only short
/// strings are handled, which is all these tests send.
fn raw_str(s: &str) -> Vec<u8> {
    assert!(s.len() < 127, "raw_str only encodes a one byte length");

    let mut out = vec![s.len() as u8];
    out.extend_from_slice(s.as_bytes());

    out
}

/// A client that writes its own HPACK, which is the only way to send a header
/// that is not Huffman coded: `h2`'s encoder always codes. Real clients do send
/// them, curl among them.
struct RawClient {
    stream: TcpStream,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    next_stream_id: u32,
}

impl RawClient {
    /// Connects and completes the handshake.
    async fn connect(addr: SocketAddr) -> Self {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let local_addr = stream.local_addr().expect("local_addr");
        let remote_addr = stream.peer_addr().expect("peer_addr");

        stream.write_all(PREFACE).await.expect("preface");
        // empty, so every parameter keeps its default
        stream
            .write_all(&frame(0x04, 0, 0, &[]))
            .await
            .expect("settings");
        stream.flush().await.expect("flush");

        let mut client = Self {
            stream,
            local_addr,
            remote_addr,
            next_stream_id: 1,
        };

        client.read_frame(0x04).await;
        client
            .stream
            .write_all(&frame(0x04, 0x01, 0, &[]))
            .await
            .expect("settings ack");
        client.stream.flush().await.expect("flush");

        client
    }

    /// Reads frames until one of type `kind` arrives, and returns its payload.
    async fn read_frame(&mut self, kind: u8) -> Vec<u8> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);

        loop {
            let mut head = [0; 9];
            tokio::time::timeout_at(deadline, self.stream.read_exact(&mut head))
                .await
                .expect("timed out waiting for a frame")
                .expect("read frame header");

            let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
            let mut payload = vec![0; len];
            tokio::time::timeout_at(deadline, self.stream.read_exact(&mut payload))
                .await
                .expect("timed out reading a frame")
                .expect("read frame payload");

            if head[3] == kind {
                return payload;
            }
        }
    }

    /// Sends a request carrying `block` and waits for its response, so that the
    /// parser has seen it by the time this returns.
    async fn request(&mut self, block: Vec<u8>) {
        self.request_all(&[(0, block)]).await;
    }

    /// Sends a request whose header block is split at `split`, the first half
    /// going out in the HEADERS frame and the second in a CONTINUATION frame,
    /// see section 6.10 of RFC 9113.
    async fn request_continued(&mut self, block: Vec<u8>, split: usize) {
        let id = self.next_stream_id;
        self.next_stream_id += 2;

        let mut out = Vec::new();
        // END_STREAM, but the block carries on
        out.extend_from_slice(&frame(0x01, 0x01, id, &block[..split]));
        // CONTINUATION | END_HEADERS
        out.extend_from_slice(&frame(0x09, 0x04, id, &block[split..]));

        self.stream.write_all(&out).await.expect("request");
        self.stream.flush().await.expect("flush");

        self.read_frame(0x01).await;
    }

    /// Sends every request in `reqs` in a single write, so that the parser has
    /// to find each frame by the length of the one before it. Each of them is
    /// the flags its HEADERS frame carries on top of END_STREAM and
    /// END_HEADERS, and the payload of that frame, which the caller lays out
    /// itself rather than handing over a bare block.
    async fn request_all(&mut self, reqs: &[(u8, Vec<u8>)]) {
        let mut out = Vec::new();
        for (flags, payload) in reqs {
            let id = self.next_stream_id;
            self.next_stream_id += 2;

            out.extend_from_slice(&frame(0x01, 0x05 | flags, id, payload));
        }

        self.stream.write_all(&out).await.expect("request");
        self.stream.flush().await.expect("flush");

        for _ in reqs {
            self.read_frame(0x01).await;
        }
    }

    /// Writes `bytes` as they are, without expecting an answer.
    ///
    /// A malformed frame is answered with a GOAWAY at best, so there is nothing
    /// to wait for, and nothing is read back: a read of whatever happens to
    /// have arrived can stop in the middle of a frame and leave the stream out
    /// of step for the next one. The parser runs on the way out of `write_all`,
    /// which is what makes that safe -- an `sk_msg` program runs as part of the
    /// send, so it has seen these bytes by the time this returns.
    async fn send_raw(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.expect("write");
        self.stream.flush().await.expect("flush");
    }
}

fn attach_preface_parser(prog_fd: i32) -> h1::AttachedParser {
    h1::Parser::new()
        .match_h2_preface()
        .replace_parse_msg("parse_h1")
        .replace_matched("matched_h1")
        .replace_extract("extract_h1_match")
        .attach(prog_fd)
        .expect("attach parser")
}

fn attach_h2_parser(prog_fd: i32, hdrs: &[HeaderName]) -> h2::AttachedParser {
    let mut h2 = h2::Parser::new();
    for hdr in hdrs {
        h2 = h2.capture_hdr(hdr).expect(&format!("capture {:?}", hdr));
    }

    h2.replace_parse_msg("parse_h2")
        .replace_extract("extract_h2_match")
        .attach(prog_fd)
        .expect("attach parser")
}

#[tokio::test]
async fn parse_header_field_indexed_in_static_table() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let _h2 = attach_h2_parser(prog.prog_fd(), &[METHOD_HEADER]);

    let client = Client::connect(addr, None).await;
    client.get(format!("http://{}", addr), &[]).await;

    let method_val = HeaderValue::from_static("GET");
    assert_match_eq(&prog, 0, Some(&method_val));
}

#[tokio::test]
async fn parse_header_field_no_indexing_name_indexed_in_static_table() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let _h2 = attach_h2_parser(prog.prog_fd(), &[header::AUTHORIZATION]);

    let auth_val = HeaderValue::from_static("Basic YmVlbGluZTpiZWVsaW5l"); // beeper:beeper in base64

    let client = Client::connect(addr, None).await;
    client
        .get(
            format!("http://{}", addr),
            &[(header::AUTHORIZATION, auth_val.clone())],
        )
        .await;

    assert_match_eq(&prog, 0, Some(&auth_val));
}

#[tokio::test]
async fn parse_header_field_never_indexing_name_indexed_in_static_table() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let _h2 = attach_h2_parser(prog.prog_fd(), &[TEST_HEADER]);

    let mut test_header_val = HeaderValue::from_static("my secret");
    test_header_val.set_sensitive(true);

    let client = Client::connect(addr, None).await;
    client
        .get(
            format!("http://{}", addr),
            &[(TEST_HEADER, test_header_val.clone())],
        )
        .await;

    assert_match_eq(&prog, 0, Some(&test_header_val));
}

#[tokio::test]
async fn parse_header_field_never_indexing_new_name() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let _h2 = attach_h2_parser(prog.prog_fd(), &[TEST_HEADER]);

    let mut test_header_val = HeaderValue::from_static("my secret");
    test_header_val.set_sensitive(true);

    let client = Client::connect(addr, None).await;
    client
        .get(
            format!("http://{}", addr),
            &[(TEST_HEADER, test_header_val.clone())],
        )
        .await;

    assert_match_eq(&prog, 0, Some(&test_header_val));
}

#[tokio::test]
async fn parse_header_field_incremental_indexing_name_indexed_in_static_table() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let _h2 = attach_h2_parser(prog.prog_fd(), &[header::USER_AGENT, PATH_HEADER]);

    let user_agent_val = HeaderValue::from_static("beeper");
    let path = "/bee/1234";
    let path_val = HeaderValue::from_static(path);

    let client = Client::connect(addr, None).await;
    client
        .get(
            format!("http://{}{}", addr, path),
            &[(header::USER_AGENT, user_agent_val.clone())],
        )
        .await;
    assert_match_eq(&prog, 0, Some(&user_agent_val));
    assert_match_eq(&prog, 1, Some(&path_val));
}

// #[tokio::test]
// async fn parse_header_field_incremental_indexing_name_indexed_in_dynamic_table() {
//     todo!();
// }

#[tokio::test]
async fn parse_header_field_incremental_indexing_new_name() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let _h2 = attach_h2_parser(prog.prog_fd(), &[TEST_HEADER, PATH_HEADER]);

    let test_header_val = HeaderValue::from_static("beeper");
    let path = "/bee/1234";
    let path_val = HeaderValue::from_static(&path);

    let client = Client::connect(addr, None).await;
    client
        .get(
            format!("http://{}{}", addr, path),
            &[(TEST_HEADER, test_header_val.clone())],
        )
        .await;
    assert_match_eq(&prog, 0, Some(&test_header_val));
    assert_match_eq(&prog, 1, Some(&path_val));
}

#[tokio::test]
async fn parse_header_field_incremental_indexing_indexed_in_dynamic_table() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let _h2 = attach_h2_parser(
        prog.prog_fd(),
        &[header::USER_AGENT, header::ACCEPT_LANGUAGE],
    );

    let user_agent_val = HeaderValue::from_static("beeper");
    let lang_val = HeaderValue::from_static("sumsum");

    let client = Client::connect(addr, None).await;
    client
        .get(
            format!("http://{}", addr),
            &[
                (header::USER_AGENT, user_agent_val.clone()),
                (header::ACCEPT_LANGUAGE, lang_val.clone()),
            ],
        )
        .await;
    assert_match_eq(&prog, 0, Some(&user_agent_val));
    assert_match_eq(&prog, 1, Some(&lang_val));

    // repeat the request with other headers
    // this will check if it indexes the dynamic table correctly
    client
        .get(
            format!("http://{}", addr),
            &[(header::VIA, HeaderValue::from_static("the hive"))],
        )
        .await;
    assert_match_eq(&prog, 0, None);
    assert_match_eq(&prog, 1, None);

    // we repeat this request to check if the header has been added to the dynamic table
    client
        .get(
            format!("http://{}", addr),
            &[
                (header::ACCEPT_LANGUAGE, lang_val.clone()),
                (header::USER_AGENT, user_agent_val.clone()),
            ],
        )
        .await;
    assert_match_eq(&prog, 0, Some(&user_agent_val));
    assert_match_eq(&prog, 1, Some(&lang_val));
}

/// Builds the header block of a request whose fields are spelled out rather
/// than Huffman coded.
///
/// The only entries it adds to the dynamic table are the ones in `indexed`,
/// whose name is either taken from the static table or, for `None`, spelled
/// out.
fn raw_request_block(authority: &str, indexed: &[(Option<u8>, &str, &str)]) -> Vec<u8> {
    // :method: GET, :scheme: http and :path: /
    let mut block = vec![0x82, 0x86, 0x84];

    // :authority, without indexing so that it stays out of the dynamic table
    block.push(0x01);
    block.extend_from_slice(&raw_str(authority));

    for (name_idx, name, value) in indexed {
        match name_idx {
            Some(idx) => block.push(0x40 | idx),
            None => {
                block.push(0x40);
                block.extend_from_slice(&raw_str(name));
            }
        }
        block.extend_from_slice(&raw_str(value));
    }

    block
}

#[tokio::test]
async fn parse_header_field_incremental_indexing_not_huffman_encoded() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let h2 = attach_h2_parser(prog.prog_fd(), &[header::ACCEPT]);

    let accept_val = HeaderValue::from_static("*/*");
    let test_header_val = HeaderValue::from_static("in-the-hive");

    // the first spells its name out too, which the DFA cannot match, as it is
    // built from Huffman coded names. both are still added to the table.
    let mut client = RawClient::connect(addr).await;
    client
        .request(raw_request_block(
            &addr.to_string(),
            &[
                (None, TEST_HEADER.as_str(), "in-the-hive"),
                (Some(19), "accept", "*/*"),
            ],
        ))
        .await;

    assert_eq!(
        prog.get_match(0).expect("get_match").as_deref(),
        Some(accept_val.as_bytes()),
        "a value that was not Huffman coded did not come back as it was sent"
    );

    // an entry is sized by its name and value as text, whichever form they were
    // sent in
    let expected_dt = &[
        (TEST_HEADER, test_header_val.clone()),
        (header::ACCEPT, accept_val.clone()),
    ];
    let info = h2
        .dynamic_table_info(client.local_addr, client.remote_addr)
        .expect("dynamic_table_info");

    assert_eq!(info.count, expected_dt.len() as u32);
    assert_eq!(info.size, dynamic_table_size_for_headers(expected_dt));
    assert_eq!(info.max_size, 4096);
}

#[tokio::test]
async fn resolve_index_of_entry_that_was_not_huffman_encoded() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let _h2 = attach_h2_parser(prog.prog_fd(), &[header::ACCEPT]);

    let accept_val = HeaderValue::from_static("*/*");

    let mut client = RawClient::connect(addr).await;
    client
        .request(raw_request_block(
            &addr.to_string(),
            &[(Some(19), "accept", "*/*")],
        ))
        .await;
    assert_eq!(
        prog.get_match(0).expect("get_match").as_deref(),
        Some(accept_val.as_bytes())
    );

    // the entry is now the most recent one, so a second request can refer to it
    // by index alone
    let mut block = vec![0x82, 0x86, 0x84];
    block.push(0x01);
    block.extend_from_slice(&raw_str(&addr.to_string()));
    block.push(0x80 | FIRST_DYNAMIC_INDEX);

    client.request(block).await;

    assert_eq!(
        prog.get_match(0).expect("get_match").as_deref(),
        Some(accept_val.as_bytes()),
        "an entry that was not Huffman coded did not resolve from the table"
    );
}

#[tokio::test]
async fn ignore_frame_that_ends_before_it_claims_to() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let h2 = attach_h2_parser(prog.prog_fd(), &[header::ACCEPT]);

    let mut client = RawClient::connect(addr).await;

    // a request the parser does get through first, so that there is something
    // for a malformed frame to damage: a capture and an entry in the table
    let accept_val = HeaderValue::from_static("*/*");
    client
        .request(raw_request_block(
            &addr.to_string(),
            &[(Some(19), "accept", "*/*")],
        ))
        .await;

    let before = h2
        .dynamic_table_info(client.local_addr, client.remote_addr)
        .expect("dynamic_table_info");
    assert_eq!(before.count, 1);

    // and now a HEADERS frame whose header claims a hundred bytes that were
    // never sent
    let block = raw_request_block(&addr.to_string(), &[(Some(19), "accept", "*/*")]);
    let mut truncated = frame(0x01, 0x05, 3, &block);
    truncated[0] = 0;
    truncated[1] = 0;
    truncated[2] = 100;

    client.send_raw(&truncated).await;

    // the parser gives up on a frame it cannot see the end of, leaving what it
    // had captured before it alone rather than half overwriting it
    assert_eq!(
        prog.get_match(0).expect("get_match").as_deref(),
        Some(accept_val.as_bytes()),
        "a frame that was never fully sent changed what was captured"
    );

    let after = h2
        .dynamic_table_info(client.local_addr, client.remote_addr)
        .expect("dynamic_table_info");
    assert_eq!(after.count, before.count);
    assert_eq!(after.size, before.size);
}

#[tokio::test]
async fn ignore_header_field_indexed_past_the_end_of_the_table() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let h2 = attach_h2_parser(prog.prog_fd(), &[header::ACCEPT]);

    let mut client = RawClient::connect(addr).await;

    // the dynamic table is empty, so nothing has that index yet
    let mut block = vec![0x82, 0x86, 0x84];
    block.push(0x01);
    block.extend_from_slice(&raw_str(&addr.to_string()));
    block.push(0x80 | FIRST_DYNAMIC_INDEX);

    client.send_raw(&frame(0x01, 0x05, 1, &block)).await;

    assert_eq!(
        prog.get_match(0).expect("get_match"),
        None,
        "an index no entry sits at resolved to something"
    );

    let info = h2
        .dynamic_table_info(client.local_addr, client.remote_addr)
        .expect("dynamic_table_info");
    assert_eq!(info.count, 0);
}

#[tokio::test]
async fn ignore_header_field_whose_value_runs_past_the_frame() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let h2 = attach_h2_parser(prog.prog_fd(), &[header::ACCEPT]);

    let mut client = RawClient::connect(addr).await;

    // the frame is the length it says it is, but the value inside it claims a
    // hundred bytes with two left to read
    let mut block = vec![0x82, 0x86, 0x84];
    block.push(0x01);
    block.extend_from_slice(&raw_str(&addr.to_string()));
    block.push(0x40 | 19);
    block.push(100);
    block.extend_from_slice(b"ab");

    client.send_raw(&frame(0x01, 0x05, 1, &block)).await;

    assert_eq!(
        prog.get_match(0).expect("get_match"),
        None,
        "a value reaching past the frame was captured"
    );

    // and it is no more welcome in the table than it is in a capture
    let info = h2
        .dynamic_table_info(client.local_addr, client.remote_addr)
        .expect("dynamic_table_info");
    assert_eq!(info.count, 0);
    assert_eq!(info.size, 0);
}

#[tokio::test]
async fn parse_frame_after_an_unknown_one() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let _h2 = attach_h2_parser(prog.prog_fd(), &[header::ACCEPT]);

    let mut client = RawClient::connect(addr).await;

    // an unassigned frame type, which RFC 7540 says a peer has to discard
    // rather than choke on
    client.send_raw(&frame(0xFA, 0, 0, b"beeper")).await;

    // the parser has to pick the stream back up on the next frame
    let accept_val = HeaderValue::from_static("*/*");
    client
        .request(raw_request_block(
            &addr.to_string(),
            &[(Some(19), "accept", "*/*")],
        ))
        .await;

    assert_eq!(
        prog.get_match(0).expect("get_match").as_deref(),
        Some(accept_val.as_bytes()),
        "the parser did not recover from a frame it skipped"
    );
}

#[tokio::test]
async fn update_dynamic_table_size() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let h2 = attach_h2_parser(prog.prog_fd(), &[]);

    let client = Client::connect(addr, Some(1234)).await;
    client.get(format!("http://{}", addr), &[]).await;

    let max_size = h2
        .dynamic_table_info(client.local_addr, client.remote_addr)
        .expect("dynamic_table_info")
        .max_size;
    assert_eq!(max_size, 1234);
}

#[tokio::test]
async fn evict_header_field_from_dynamic_table() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let h2 = attach_h2_parser(prog.prog_fd(), &[TEST_HEADER, header::USER_AGENT]);

    let test_header_val = HeaderValue::from_static("asdfqwerasdfqwerasdfqwerasdfqwer");
    let user_agent_val = HeaderValue::from_static("test-agent");

    // this request immediately exceeds the dynamic table limit
    let client = Client::connect(addr, Some(254)).await;
    client
        .get(
            format!("http://{}", addr),
            &[(TEST_HEADER, test_header_val.clone())],
        )
        .await;

    let info = h2
        .dynamic_table_info(client.local_addr, client.remote_addr)
        .expect("dynamic_table_info");

    let authority = addr.to_string();
    let expected_dt = &[
        (TEST_HEADER, test_header_val.clone()),
        (
            AUTHORITY_HEADER,
            HeaderValue::from_str(&authority.as_str()).unwrap(),
        ),
    ];
    assert_eq!(info.max_size, 254);
    assert_eq!(info.count, expected_dt.len() as u32);
    assert_eq!(info.size, dynamic_table_size_for_headers(expected_dt));
    assert_match_eq(&prog, 0, Some(&test_header_val));

    client
        .get(
            format!("http://{}", addr),
            &[(header::USER_AGENT, user_agent_val.clone())],
        )
        .await;

    // this should add the user-agent to the dynamic table, but not evict TEST_HEADER
    let info = h2
        .dynamic_table_info(client.local_addr, client.remote_addr)
        .expect("dynamic_table_info");
    let expected_dt = &[
        (TEST_HEADER, test_header_val.clone()),
        (
            AUTHORITY_HEADER,
            HeaderValue::from_str(&authority.as_str()).unwrap(),
        ),
        (header::USER_AGENT, user_agent_val.clone()),
    ];
    assert_eq!(info.max_size, 254);
    assert_eq!(info.count, expected_dt.len() as u32);
    assert_eq!(info.size, dynamic_table_size_for_headers(expected_dt));
    assert_match_eq(&prog, 1, Some(&user_agent_val));

    client
        .get(
            format!("http://{}", addr),
            &[(header::USER_AGENT, test_header_val.clone())],
        )
        .await;

    // this should evict the authority, the oldest entry, and nothing more
    let info = h2
        .dynamic_table_info(client.local_addr, client.remote_addr)
        .expect("dynamic_table_info");
    let expected_dt = &[
        (TEST_HEADER, test_header_val.clone()),
        (header::USER_AGENT, user_agent_val.clone()),
        (header::USER_AGENT, test_header_val.clone()),
    ];
    assert_eq!(info.max_size, 254);
    assert_eq!(info.count, expected_dt.len() as u32);
    assert_eq!(info.size, dynamic_table_size_for_headers(expected_dt));
    assert_eq!(info.deleted, 1);
    assert_match_eq(&prog, 1, Some(&test_header_val));
}

/// The flag of a HEADERS frame saying that its block is padded, see section 6.2
/// of RFC 9113.
const PADDED_FLAG: u8 = 0x08;

/// The flag saying that a priority comes in front of its block.
const PRIORITY_FLAG: u8 = 0x20;

/// Renders the payload of a HEADERS frame that pads `block` with `pad`, see
/// section 6.2 of RFC 9113: the length of the padding, the block, and the
/// padding itself.
fn padded(block: Vec<u8>, pad: &[u8]) -> Vec<u8> {
    let mut payload = vec![pad.len() as u8];
    payload.extend_from_slice(&block);
    payload.extend_from_slice(pad);

    payload
}

/// Renders the payload of a HEADERS frame that puts a priority in front of
/// `block`, see section 6.3 of RFC 9113: a stream dependency and a weight.
fn prioritised(block: Vec<u8>) -> Vec<u8> {
    let mut payload = vec![0x00, 0x00, 0x00, 0x00, 0x10];
    payload.extend_from_slice(&block);

    payload
}

#[tokio::test]
async fn parse_padded_header_frame() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let h2 = attach_h2_parser(prog.prog_fd(), &[header::ACCEPT]);

    let authority = addr.to_string();
    let padded_val = HeaderValue::from_static("padded");
    let next_val = HeaderValue::from_static("after-the-padding");

    // the padding is a field that would be added to the dynamic table if it
    // were read as one, which is how the test tells that it was skipped
    let pad = [0x40, 0x00, 0x00];

    // both requests go out in a single write, so the second is only found if
    // the padded frame reported its own length correctly
    let mut client = RawClient::connect(addr).await;
    client
        .request_all(&[
            (
                PADDED_FLAG,
                padded(
                    raw_request_block(&authority, &[(Some(19), "accept", "padded")]),
                    &pad,
                ),
            ),
            (
                0,
                raw_request_block(&authority, &[(Some(19), "accept", "after-the-padding")]),
            ),
        ])
        .await;

    assert_eq!(
        prog.get_match(0).expect("get_match").as_deref(),
        Some(next_val.as_bytes()),
        "the frame after the padded one was not found"
    );

    let info = h2
        .dynamic_table_info(client.local_addr, client.remote_addr)
        .expect("dynamic_table_info");

    let expected_dt = &[
        (header::ACCEPT, padded_val.clone()),
        (header::ACCEPT, next_val.clone()),
    ];
    assert_eq!(
        info.count,
        expected_dt.len() as u32,
        "the padding was read as a header field"
    );
    assert_eq!(info.size, dynamic_table_size_for_headers(expected_dt));
}

#[tokio::test]
async fn parse_header_frame_that_carries_a_priority() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let h2 = attach_h2_parser(prog.prog_fd(), &[header::ACCEPT]);

    let authority = addr.to_string();
    let accept_val = HeaderValue::from_static("after-the-priority");

    let mut client = RawClient::connect(addr).await;
    client
        .request_all(&[(
            PRIORITY_FLAG,
            prioritised(raw_request_block(
                &authority,
                &[(Some(19), "accept", "after-the-priority")],
            )),
        )])
        .await;

    assert_eq!(
        prog.get_match(0).expect("get_match").as_deref(),
        Some(accept_val.as_bytes()),
        "the block was not read from behind the priority"
    );

    let info = h2
        .dynamic_table_info(client.local_addr, client.remote_addr)
        .expect("dynamic_table_info");

    let expected_dt = &[(header::ACCEPT, accept_val.clone())];
    assert_eq!(
        info.count,
        expected_dt.len() as u32,
        "the priority was read as a header field"
    );
    assert_eq!(info.size, dynamic_table_size_for_headers(expected_dt));
}

#[tokio::test]
async fn resolve_index_of_entry_added_after_an_eviction() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let h2 = attach_h2_parser(prog.prog_fd(), &[TEST_HEADER, header::USER_AGENT]);

    let long_val = HeaderValue::from_static("asdfqwerasdfqwerasdfqwerasdfqwer");
    let agent_val = HeaderValue::from_static("test-agent");
    let other_agent_val = HeaderValue::from_static("other-agent");
    let url = format!("http://{}", addr);

    // a table this small fills up over the three requests below, the last of
    // which evicts the authority the connection opened with
    let client = Client::connect(addr, Some(254)).await;
    client
        .get(url.clone(), &[(TEST_HEADER, long_val.clone())])
        .await;
    client
        .get(url.clone(), &[(header::USER_AGENT, agent_val.clone())])
        .await;
    client
        .get(url.clone(), &[(header::USER_AGENT, long_val.clone())])
        .await;

    let info = h2
        .dynamic_table_info(client.local_addr, client.remote_addr)
        .expect("dynamic_table_info");
    assert_eq!(
        info.deleted, 1,
        "nothing was evicted, so the entries below are stored where they would be anyway"
    );

    // this one is added to a table that has already evicted, which is what
    // decides whether the entries added before it keep the index they were
    // stored under
    client
        .get(url.clone(), &[(header::USER_AGENT, other_agent_val.clone())])
        .await;
    assert_match_eq(&prog, 1, Some(&other_agent_val));

    // the client still holds the long user agent, so it sends it as nothing but
    // the index of the entry it was added under before the eviction
    client
        .get(url.clone(), &[(header::USER_AGENT, long_val.clone())])
        .await;

    assert_match_eq(&prog, 1, Some(&long_val));
}
#[tokio::test]
async fn parse_header_block_split_over_a_continuation_frame() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let h2 = attach_h2_parser(prog.prog_fd(), &[header::ACCEPT]);

    let authority = addr.to_string();
    let accept_val = HeaderValue::from_static("in-the-continuation");
    let block = raw_request_block(&authority, &[(Some(19), "accept", "in-the-continuation")]);

    // the block breaks right after the three indexed pseudo headers it opens
    // with, so every field of it is whole in the frame that carries it
    let mut client = RawClient::connect(addr).await;
    client.request_continued(block, 3).await;

    assert_eq!(
        prog.get_match(0).expect("get_match").as_deref(),
        Some(accept_val.as_bytes()),
        "the field in the continuation frame was not read"
    );

    let info = h2
        .dynamic_table_info(client.local_addr, client.remote_addr)
        .expect("dynamic_table_info");

    let expected_dt = &[(header::ACCEPT, accept_val.clone())];
    assert_eq!(info.count, expected_dt.len() as u32);
    assert_eq!(info.size, dynamic_table_size_for_headers(expected_dt));
    assert_eq!(
        info.dirty, 0,
        "a block that breaks between fields left the table looking untrustworthy"
    );
}

#[tokio::test]
async fn mark_the_table_as_drifted_when_a_continuation_frame_splits_a_field() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let h2 = attach_h2_parser(prog.prog_fd(), &[header::ACCEPT]);

    let authority = addr.to_string();
    let accept_val = HeaderValue::from_static("across-the-break");
    let block = raw_request_block(&authority, &[(Some(19), "accept", "across-the-break")]);

    // the block breaks two bytes into the authority, whose first half is in a
    // frame the parser cannot address once the second one arrives
    let mut client = RawClient::connect(addr).await;
    client.request_continued(block, 3 + 1 + 1 + 2).await;

    // the fields behind the break are still read, the parser only loses the one
    // the break falls inside of
    assert_eq!(
        prog.get_match(0).expect("get_match").as_deref(),
        Some(accept_val.as_bytes()),
        "the field behind the break was not read"
    );

    let info = h2
        .dynamic_table_info(client.local_addr, client.remote_addr)
        .expect("dynamic_table_info");
    assert_eq!(
        info.dirty, 1,
        "a block that breaks inside a field left the table looking trustworthy"
    );
}
