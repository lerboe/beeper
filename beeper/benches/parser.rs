//! Times how long a parser takes to walk a single message in the kernel.
//!
//! Both parsers are configured to capture the same three fields — the user
//! agent, the content length and the path of the request — and are then run
//! over a request carrying them. Every round loads the parser afresh and hands
//! it to a `SEC("syscall")` program that parses the message [`PASSES`] times,
//! so what the numbers say is what a parse costs and not what the syscall
//! around it costs.
//!
//! Run it with `cargo bench`. Loading a BPF program takes `CAP_BPF` and
//! `CAP_PERFMON`, so on a host that does not hand those to ordinary users the
//! binary has to be run as root instead:
//!
//! ```console
//! $ cargo bench --no-run && sudo ./target/release/deps/parser-*
//! ```

use beeper::{h1, h2, header::PATH};
use httlib_huffman as huffman;
use http::header::{CONTENT_LENGTH, USER_AGENT};
use std::time::Duration;

/// How often a run parses the message. The whole run is a single
/// `BPF_PROG_TEST_RUN`, so this is what keeps the syscall out of the result.
const PASSES: u32 = 50_000;

/// How many runs the reported numbers are taken over.
const ROUNDS: u32 = 10;

/// The index of `:authority` in the HPACK static table, see appendix A of RFC
/// 7541. The fields below it are the ones this benchmark sends.
const AUTHORITY_INDEX: u8 = 1;
const PATH_INDEX: u8 = 4;
const ACCEPT_INDEX: u8 = 19;
const CONTENT_LENGTH_INDEX: u8 = 28;
const USER_AGENT_INDEX: u8 = 58;

/// The request the HTTP/1.1 parser is timed on.
fn h1_msg() -> Vec<u8> {
    concat!(
        "GET /index.html HTTP/1.1\r\n",
        "Host: example.com\r\n",
        "User-Agent: beeper/0.1\r\n",
        "Content-Length: 0\r\n",
        "Accept: */*\r\n",
        "\r\n",
    )
    .as_bytes()
    .to_vec()
}

/// Renders an HPACK string, Huffman coded the way a client sends it.
fn hpack_str(s: &str) -> Vec<u8> {
    let mut s = {
        let mut coded = Vec::new();
        huffman::encode(s.as_bytes(), &mut coded).expect("huffman encode");
        coded
    };
    assert!(s.len() < 0x7F, "hpack_str only encodes a one byte length");

    let mut out = vec![0x80 | s.len() as u8];
    out.append(&mut s);
    out
}

/// Renders a header field that names the `idx`th entry of the static table for
/// its name and spells its value out, never indexed. See section 6.2.3 of RFC
/// 7541 for the representation and section 5.1 for the integer in its prefix.
fn hpack_field(idx: u8, value: &str) -> Vec<u8> {
    let mut out = if idx < 0x0F {
        vec![idx]
    } else {
        vec![0x0F, idx - 0x0F]
    };

    out.extend_from_slice(&hpack_str(value));
    out
}

/// The HEADERS frame the HTTP/2 parser is timed on. It carries the fields the
/// request of [`h1_msg`] carries.
fn h2_frame() -> Vec<u8> {
    // an indexed `:method: GET` and an indexed `:scheme: http`
    let mut block = vec![0x82, 0x86];
    block.extend_from_slice(&hpack_field(PATH_INDEX, "/index.html"));
    block.extend_from_slice(&hpack_field(AUTHORITY_INDEX, "example.com"));
    block.extend_from_slice(&hpack_field(USER_AGENT_INDEX, "beeper/0.1"));
    block.extend_from_slice(&hpack_field(CONTENT_LENGTH_INDEX, "0"));
    block.extend_from_slice(&hpack_field(ACCEPT_INDEX, "*/*"));

    let mut frame = Vec::new();
    frame.extend_from_slice(&(block.len() as u32).to_be_bytes()[1..]);
    // a HEADERS frame flagged END_STREAM | END_HEADERS, on stream 1
    frame.push(0x01);
    frame.push(0x05);
    frame.extend_from_slice(&1u32.to_be_bytes());
    frame.extend_from_slice(&block);

    frame
}

/// Times one round of the HTTP/1.1 parser over `msg`.
fn h1_round(msg: &[u8]) -> Duration {
    h1::Parser::new()
        .capture_hdr(&USER_AGENT)
        .capture_hdr(&CONTENT_LENGTH)
        .capture_hdr(&PATH)
        .bench(msg, PASSES)
        .expect("bench the http/1.1 parser")
}

/// Times one round of the HTTP/2 parser over `frame`.
fn h2_round(frame: &[u8]) -> Duration {
    h2::Parser::new()
        .capture_hdr(&USER_AGENT)
        .expect("capture the user agent")
        .capture_hdr(&CONTENT_LENGTH)
        .expect("capture the content length")
        .capture_hdr(&PATH)
        .expect("capture the path")
        .bench(frame, PASSES)
        .expect("bench the http/2 parser")
}

/// Runs `round` [`ROUNDS`] times and prints what a pass took under `name`.
fn report(name: &str, len: usize, round: impl Fn() -> Duration) {
    let mut runs = Vec::with_capacity(ROUNDS as usize);
    for _ in 0..ROUNDS {
        runs.push(round());
    }

    let total: Duration = runs.iter().sum();
    let avg = total / ROUNDS;
    let min = runs.iter().min().expect("a round was run");
    let max = runs.iter().max().expect("a round was run");

    let ns = |d: &Duration| d.as_secs_f64() * 1e9;
    println!(
        "{name:<8} {len:>4} bytes   avg {:>7.1} ns   min {:>7.1} ns   max {:>7.1} ns   {:>5.2} ns/byte",
        ns(&avg),
        ns(min),
        ns(max),
        ns(&avg) / len as f64,
    );
}

fn main() {
    println!("{PASSES} passes per round, {ROUNDS} rounds\n");

    let msg = h1_msg();
    report("http/1.1", msg.len(), || h1_round(&msg));

    let frame = h2_frame();
    report("http/2", frame.len(), || h2_round(&frame));
}
