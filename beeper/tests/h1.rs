use beeper::h1;
use http::{HeaderName, HeaderValue, header};
use reqwest::Client;
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use utils::{
    server,
    test::{Direction, TestProgram},
};
use xbpf::OpenObject;

fn assert_match_eq(prog: &TestProgram, idx: usize, expected: Option<&HeaderValue>) {
    let actual = prog.get_match(idx).expect("get_match");
    let actual = actual.map(|s| String::from_utf8(s).unwrap());

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

fn build_client() -> Client {
    Client::builder().build().expect("client")
}

/// Writes `req` to a raw connection to `addr` and returns the response it reads back.
async fn send_raw(addr: SocketAddr, req: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(req.as_bytes())
        .await
        .expect("write request");

    let mut buf = [0; 1024];
    let len = stream.read(&mut buf).await.expect("read response");

    String::from_utf8_lossy(&buf[..len]).into_owned()
}

/// Writes `req` to a raw connection to `addr` and returns the response it reads
/// back. Unlike [`send_raw`], the request does not have to be valid UTF-8.
async fn send_raw_bytes(addr: SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream.write_all(req).await.expect("write request");

    let mut buf = [0; 1024];
    let len = stream.read(&mut buf).await.expect("read response");

    buf[..len].to_vec()
}

/// Same as [`assert_match_eq`], but compares the raw bytes of the capture, so
/// that a value that is not valid UTF-8 can be asserted on as well.
fn assert_match_bytes_eq(prog: &TestProgram, idx: usize, expected: Option<&[u8]>) {
    let actual = prog.get_match(idx).expect("get_match");

    match expected {
        None => assert!(
            actual.is_none(),
            "get_match({idx}): {:?}, expected: none",
            String::from_utf8_lossy(&actual.unwrap())
        ),
        Some(expected) => {
            assert!(
                actual.is_some(),
                "get_match({idx}): none, expected: {:?}",
                String::from_utf8_lossy(expected)
            );
            let actual = actual.unwrap();
            assert_eq!(
                String::from_utf8_lossy(&actual),
                String::from_utf8_lossy(expected)
            );
        }
    }
}

fn attach_h1_parser(prog_fd: i32, match_preface: bool, hdrs: &[HeaderName]) -> h1::AttachedParser {
    let mut h1 = h1::Parser::new();
    if match_preface {
        h1 = h1.match_h2_preface();
    }
    for hdr in hdrs {
        h1 = h1.capture_hdr(hdr);
    }

    h1.replace_parse_msg("parse_h1")
        .replace_matched("matched_h1")
        .replace_extract("extract_h1_match")
        .attach(prog_fd)
        .expect("attach parser")
}

#[tokio::test]
async fn match_h2_preface() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");

    let _h1 = attach_h1_parser(prog.prog_fd(), true, &[]);
    let client = Client::builder()
        .http2_prior_knowledge()
        .build()
        .expect("client");
    let resp = client
        .get(format!("http://{}", addr))
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert_eq!(prog.num_upgraded_conns().unwrap(), 1);
}

#[tokio::test]
async fn parse_simple_header() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");
    let _h1 = attach_h1_parser(prog.prog_fd(), true, &[header::USER_AGENT]);

    let user_agent = HeaderValue::from_static("some user agent");
    let client = build_client();
    let resp = client
        .get(format!("http://{}", addr))
        .header(header::USER_AGENT, user_agent.clone())
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 1, Some(&user_agent));
}

#[tokio::test]
async fn ignore_header_case() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");
    let _h1 = attach_h1_parser(prog.prog_fd(), true, &[header::USER_AGENT]);

    // reqwest normalizes header names, so the request is written to the socket as is
    let user_agent = HeaderValue::from_static("beeper");
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {addr}\r\nUsEr-aGEnT: {}\r\n\r\n",
        user_agent.to_str().unwrap()
    );

    let resp = send_raw(addr, &req).await;

    assert!(
        resp.starts_with("HTTP/1.1 200 OK"),
        "unexpected response: {resp}"
    );
    assert_match_eq(&prog, 1, Some(&user_agent));
}

#[tokio::test]
async fn ignores_header_whitespace() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");
    let _h1 = attach_h1_parser(prog.prog_fd(), true, &[header::USER_AGENT]);

    // the whitespace between the colon and the value is not part of the value
    let user_agent = HeaderValue::from_static("beeper");
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {addr}\r\nuser-agent:  \t{}\r\n\r\n",
        user_agent.to_str().unwrap()
    );

    let resp = send_raw(addr, &req).await;

    assert!(
        resp.starts_with("HTTP/1.1 200 OK"),
        "unexpected response: {resp}"
    );
    assert_match_eq(&prog, 1, Some(&user_agent));

    // beeper also matches whitespace between the name and the colon. the server
    // rejects such a request as a smuggling risk, but it is parsed off the wire
    // before it ever gets there, so its status is of no interest here
    let user_agent = HeaderValue::from_static("sumsum");
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {addr}\r\nuser-agent \t:  {}\r\n\r\n",
        user_agent.to_str().unwrap()
    );

    _ = send_raw(addr, &req).await;

    assert_match_eq(&prog, 1, Some(&user_agent));
}

#[tokio::test]
async fn parse_subsequent_headers() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");

    let _h1 = attach_h1_parser(
        prog.prog_fd(),
        true,
        &[header::USER_AGENT, header::ACCEPT_LANGUAGE],
    );

    let client = build_client();
    let user_agent = HeaderValue::from_static("beeper");
    let lang = HeaderValue::from_static("sumsum");
    let resp = client
        .get(format!("http://{}", addr))
        .header(header::USER_AGENT, user_agent.clone())
        .header(header::ACCEPT_LANGUAGE, lang.clone())
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 1, Some(&user_agent));
    assert_match_eq(&prog, 2, Some(&lang));
}

#[tokio::test]
async fn parse_status_line_only() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");

    let _h1 = attach_h1_parser(
        prog.prog_fd(),
        true,
        &[beeper::header::PATH, beeper::header::METHOD],
    );

    let client = build_client();
    let resp = client
        .get(format!("http://{}", addr))
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    let method = HeaderValue::from_static("GET");
    let path = HeaderValue::from_static("/");
    assert_match_eq(&prog, 1, Some(&path));
    assert_match_eq(&prog, 2, Some(&method));
}

#[tokio::test]
async fn parse_status_line_and_subsequent_header() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");

    let _h1 = attach_h1_parser(
        prog.prog_fd(),
        true,
        &[beeper::header::PATH, header::CONTENT_LENGTH],
    );

    let body = "Hello, world!";
    let client = build_client();
    let resp = client
        .get(format!("http://{}", addr))
        .body(body)
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    let path = HeaderValue::from_static("/");
    let content_length = HeaderValue::from_str(&format!("{}", body.len())).unwrap();
    assert_match_eq(&prog, 1, Some(&path));
    assert_match_eq(&prog, 2, Some(&content_length));
}

#[tokio::test]
async fn parse_status_code() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Upstream).expect("attach");

    let _h1 = attach_h1_parser(
        prog.prog_fd(),
        true,
        &[beeper::header::STATUS, header::CONTENT_LENGTH],
    );

    let body = "Hello, world!";
    let client = build_client();
    let resp = client
        .get(format!("http://{}", addr))
        .body(body)
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    let status = HeaderValue::from_static("200");
    let content_length = HeaderValue::from_str(&format!("{}", body.len())).unwrap();
    assert_match_eq(&prog, 1, Some(&status));
    assert_match_eq(&prog, 2, Some(&content_length));
}

#[tokio::test]
async fn ignore_a_preface_that_is_not_one() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");
    let _h1 = attach_h1_parser(prog.prog_fd(), true, &[]);

    // the preface asks for the target `*`, which is also the character the DFA
    // spells "any byte" with. Anything else in its place is a different message
    let req = "PRI X HTTP/2.0\r\n\r\nSM\r\n\r\n";
    _ = send_raw(addr, req).await;

    assert_eq!(
        prog.num_upgraded_conns().unwrap(),
        0,
        "a request that only looks like the preface upgraded the connection"
    );
}

#[tokio::test]
async fn match_a_star_in_a_header_name_literally() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");

    // `*` is a legal character of a field name, and one the DFA spells "any
    // byte" with
    let starred = HeaderName::from_bytes(b"x*y").expect("header name");
    let _h1 = attach_h1_parser(prog.prog_fd(), true, &[starred]);

    let req = format!("GET / HTTP/1.1\r\nHost: {addr}\r\nxzy: beeper\r\n\r\n");
    _ = send_raw(addr, &req).await;

    // no field of the request is named `x*y`, so there is nothing to capture
    assert_match_eq(&prog, 1, None);
}

#[tokio::test]
async fn keep_a_value_that_carries_high_bytes_together() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");
    let _h1 = attach_h1_parser(prog.prog_fd(), true, &[header::USER_AGENT]);

    // a field value may carry obs-text, i.e. any byte from 0x80 to 0xFF. 0x8D
    // and 0x8A are the two that a parser masking its input down to seven bits
    // reads as a CRLF, which is what ends a field value
    let value: &[u8] = b"good\x8d\x8auser-agent: evil";

    let mut req = Vec::new();
    req.extend_from_slice(format!("GET / HTTP/1.1\r\nHost: {addr}\r\nuser-agent: ").as_bytes());
    req.extend_from_slice(value);
    req.extend_from_slice(b"\r\n\r\n");

    _ = send_raw_bytes(addr, &req).await;

    assert_match_bytes_eq(&prog, 1, Some(value));
}

#[tokio::test]
async fn capture_nothing_for_an_empty_value() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");
    let _h1 = attach_h1_parser(prog.prog_fd(), true, &[header::USER_AGENT]);

    // an empty value is legal, and there is nothing to capture in it. The
    // fields behind it are not part of it either
    let req =
        format!("GET / HTTP/1.1\r\nHost: {addr}\r\nuser-agent:\r\naccept: text/plain\r\n\r\n");

    let resp = send_raw(addr, &req).await;
    assert!(
        resp.starts_with("HTTP/1.1 200 OK"),
        "unexpected response: {resp}"
    );

    assert_match_eq(&prog, 1, None);
}

#[tokio::test]
async fn parse_a_header_in_the_first_half_of_a_long_message() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");
    let _h1 = attach_h1_parser(prog.prog_fd(), true, &[header::USER_AGENT]);

    // the parser walks the first 0x7FFF bytes of a message. The field below
    // sits well inside of them, the padding behind it pushes the message well
    // past them
    let user_agent = HeaderValue::from_static("beeper");
    let pad = "p".repeat(1000);

    let mut req = format!("GET / HTTP/1.1\r\nHost: {addr}\r\n");
    for i in 0..8 {
        req += &format!("x-pad-{i}: {pad}\r\n");
    }
    req += "user-agent: beeper\r\n";
    for i in 8..38 {
        req += &format!("x-pad-{i}: {pad}\r\n");
    }
    req += "\r\n";

    assert!(req.len() > 0x7FFF, "the message is not long enough");
    _ = send_raw(addr, &req).await;

    assert_match_eq(&prog, 1, Some(&user_agent));
}

#[tokio::test]
async fn parse_lf_endings() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");
    let _h1 = attach_h1_parser(prog.prog_fd(), true, &[header::USER_AGENT]);

    // section 2.2 of RFC 9112 lets a recipient read a bare LF as a line terminator
    let user_agent = HeaderValue::from_static("beeper");
    let req = format!("GET / HTTP/1.1\nHost: {addr}\nuser-agent: beeper\n\n");

    let resp = send_raw(addr, &req).await;
    assert!(
        resp.starts_with("HTTP/1.1 200 OK"),
        "unexpected response: {resp}"
    );

    assert_match_eq(&prog, 1, Some(&user_agent));
}

// TODO: How to inject an invalid response?
// #[tokio::test]
// async fn rejects_multi_cr_endings() {
//     let addr = server::launch().await.expect("launch server");

//     let mut open_obj = OpenObject::new();
//     let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");
//     let _h1 = attach_h1_parser(prog.prog_fd(), true, &[header::USER_AGENT]);

//     // section 2.2 of RFC 9112 lets a recipient read a bare LF as a line terminator
//     let user_agent = HeaderValue::from_static("beeper");
//     let req = format!("GET / HTTP/1.1\r\nHost: {addr}\nuser-agent: beeper\r\r\n\n");

//     let resp = send_raw(addr, &req).await;
//     assert!(
//         resp.starts_with("HTTP/1.1 200 OK"),
//         "unexpected response: {resp}"
//     );

//     assert_match_eq(&prog, 1, Some(&user_agent));
// }
