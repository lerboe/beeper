//! Checks what the HTTP/2 parser makes of the traffic h2spec sends to the echo
//! server, and of the responses the server sends back. See `ci/h2spec.sh`,
//! which drives it.
//!
//! It launches a server on the address it is given, `127.0.0.1:8080` by
//! default, that answers a request with its own regular fields and a body, as
//! h2spec expects one. It then prints `listening on <addr>` and then reads commands from stdin:
//!
//! * `case <id>` configures the parser for the h2spec case `<id>`, i.e. to
//!   capture every field the case sends, and prints `ready <id>` once it is
//!   attached.
//! * `check <id>`, sent once h2spec has run the case, waits until every
//!   connection to the server has been closed, and with it parsed, then
//!   checks what the parser captured of each header block. It prints a line
//!   per problem, indented, followed by `pass <id>` or `fail <id>`.
//!
//! Every request block must carry what [`cases`] lists for it. A response
//! block must carry what the server answers to one of the requests, as the
//! server does not answer every request, and whether it does may hinge on
//! timing.

use anyhow::{Context, Result, anyhow, bail};
use axum::{Router, http::HeaderMap, routing::get};
use beeper::{MessageBuffer, http1, http2};
use cases::{Block, Case, DUMMY_LEN, Value};
use httlib_huffman as huffman;
use std::{
    collections::{BTreeSet, HashMap},
    fmt::Write as _,
    io::{BufRead, Write},
    net::SocketAddr,
    sync::mpsc::{Receiver, RecvTimeoutError},
    time::{Duration, Instant},
};
use utils::test::{Capture, Direction, Frame, ParseResult, RESULT_VAL_LEN, TestProgram};
use xbpf::OpenObject;

mod cases;

/// The body the server answers with.
const BODY: &str = "h2spec";

/// Launches the server h2spec is run against on `addr`, and returns the address
/// it is bound to.
async fn launch(addr: SocketAddr) -> Result<SocketAddr> {
    let app = Router::new().route("/", get(|headers: HeaderMap| async { (headers, BODY) }));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move { axum::serve(listener, app).await });

    Ok(addr)
}

/// How long `check` waits for the connections of a case to be closed.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

/// The fields of a response the parser captures in every case, on top of the
/// ones the case sends, which the server echoes.
const RESPONSE_FIELDS: &[&str] = &[":status", "content-type", "content-length", "allow"];

/// The flag of a HEADERS or CONTINUATION frame that ends its header block.
const END_HEADERS: u8 = 0x4;

/// The frame type a header block starts with.
const HEADERS: u8 = 0x1;

/// The frame type that carries on a header block.
const CONTINUATION: u8 = 0x9;

/// A header block as the parser saw it, put together from its frames.
#[derive(Debug, Default)]
struct ParsedBlock {
    client_port: u16,
    sid: u32,

    /// What the parser returned for the first of its frames it failed on.
    error: Option<i32>,

    /// What the parser captured, indexed by match id.
    captures: Vec<Option<Capture>>,
}

impl ParsedBlock {
    fn add(&mut self, frame: &Frame) {
        if frame.ret < 0 && self.error.is_none() {
            self.error = Some(frame.ret);
        }
        self.captures.resize(frame.captures.len(), None);
        for (i, capture) in frame.captures.iter().enumerate() {
            if capture.is_some() {
                self.captures[i] = capture.clone();
            }
        }
    }
}

/// Puts the header frames the parser reported together into the blocks they
/// make up, requests and responses apart, each in the order they were sent.
///
/// A CONTINUATION frame carries on the block of its stream if that block has
/// not ended yet, and starts a block of its own otherwise.
fn blocks(frames: &[Frame]) -> (Vec<ParsedBlock>, Vec<ParsedBlock>, Vec<String>) {
    let mut requests = Vec::new();
    let mut responses = Vec::new();
    let mut problems = Vec::new();

    // the blocks that have not ended yet, by connection, direction and stream
    let mut open: HashMap<(u16, bool, u32), usize> = HashMap::new();

    for frame in frames {
        if frame.frame_type != HEADERS && frame.frame_type != CONTINUATION {
            problems.push(format!(
                "the parser failed on a frame of type {} on stream {}",
                frame.frame_type, frame.sid
            ));
            continue;
        }

        let blocks = if frame.upstream {
            &mut responses
        } else {
            &mut requests
        };

        let key = (frame.client_port, frame.upstream, frame.sid);
        let idx = match open.remove(&key) {
            Some(idx) if frame.frame_type == CONTINUATION => idx,
            _ => {
                blocks.push(ParsedBlock {
                    client_port: frame.client_port,
                    sid: frame.sid,
                    ..Default::default()
                });
                blocks.len() - 1
            }
        };

        blocks[idx].add(frame);
        if frame.flags & END_HEADERS == 0 {
            open.insert(key, idx);
        }
    }

    (requests, responses, problems)
}

/// What a captured value is expected to be.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Expected {
    /// Nothing.
    Absent,

    /// This value, which may have been sent Huffman coded or not.
    Value(Vec<u8>),

    /// These bytes, as they were sent.
    Raw(Vec<u8>),

    /// What the inner one expects, which the parser is known to get wrong for
    /// the reason given.
    Limited(Box<Expected>, &'static str),
}

impl Expected {
    fn new(value: &Value, authority: &str) -> Self {
        let value = match value {
            Value::Str(s) => s.as_bytes().to_vec(),
            Value::Authority => authority.as_bytes().to_vec(),
            Value::Dummy => vec![b'x'; DUMMY_LEN],
            Value::Raw(raw) => return Expected::Raw(raw.to_vec()),
            Value::Split(value) => {
                let inner = Expected::new(value, authority);
                return Expected::Limited(Box::new(inner), "a value split across frames");
            }
        };

        Expected::Value(value)
    }

    /// Whether `capture` is what is expected.
    ///
    /// Only the first [`RESULT_VAL_LEN`] bytes of a value are reported, along
    /// with its length. A value that was read out of the dynamic table is cut
    /// to that length, as the parser only keeps that much of an entry.
    fn matches(&self, capture: Option<&Capture>) -> bool {
        let sent = match (self, capture) {
            (Expected::Limited(inner, _), _) => return inner.matches(capture),
            (Expected::Absent, None) => return true,
            (Expected::Absent, Some(_)) | (_, None) => return false,
            (Expected::Raw(raw), Some(capture)) => {
                return capture.len as usize == raw.len() && capture.head == *raw;
            }
            (Expected::Value(value), Some(_)) => {
                let mut coded = Vec::new();
                huffman::encode(value, &mut coded).expect("huffman encode");
                [value.clone(), coded]
            }
        };

        let capture = capture.unwrap();
        sent.iter().any(|sent| {
            let len = capture.len as usize;
            let cut = len == RESULT_VAL_LEN && sent.len() > len;
            (len == sent.len() || cut) && sent.starts_with(&capture.head)
        })
    }
}

impl std::fmt::Display for Expected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expected::Absent => write!(f, "nothing"),
            Expected::Value(value) => write!(f, "{:?}", abbreviate(value)),
            Expected::Raw(raw) => write!(f, "{raw:x?}"),
            Expected::Limited(inner, why) => write!(f, "{inner} (known limitation: {why})"),
        }
    }
}

/// Shortens `value` for a message.
fn abbreviate(value: &[u8]) -> String {
    let s = String::from_utf8_lossy(value);
    if s.chars().count() > 40 {
        format!(
            "{}... ({}B)",
            s.chars().take(40).collect::<String>(),
            value.len()
        )
    } else {
        s.into_owned()
    }
}

/// Describes `capture` for a message, decoded if it is a Huffman code.
fn describe(capture: Option<&Capture>) -> String {
    let Some(capture) = capture else {
        return "nothing".to_string();
    };

    let mut decoded = Vec::new();
    let value =
        if huffman::decode(&capture.head, &mut decoded, huffman::DecoderSpeed::OneBit).is_ok() {
            format!("{:?} (Huffman coded)", abbreviate(&decoded))
        } else {
            format!("{:?}", abbreviate(&capture.head))
        };

    format!("{value}, {}B sent", capture.len)
}

/// The values a block is expected to carry, by field name: the last value it
/// sends for every field, and nothing for a field it does not send.
type Fields = HashMap<&'static str, Expected>;

fn expected_fields(block: &[(&'static str, Value)], authority: &str) -> Fields {
    block
        .iter()
        .map(|(name, value)| (*name, Expected::new(value, authority)))
        .collect()
}

/// The fields the server answers the request `block` with, or `None` if it does
/// not answer it, see [`launch`].
fn response_fields(block: &[(&'static str, Value)], authority: &str) -> Option<Fields> {
    let method = block
        .iter()
        .rev()
        .find_map(|(name, value)| match (*name, value) {
            (":method", Value::Str(method)) => Some(*method),
            _ => None,
        })?;

    let value = |s: &str| Expected::Value(s.as_bytes().to_vec());
    let mut fields = Fields::new();
    if method == "GET" || method == "HEAD" {
        fields.insert(":status", value("200"));
        fields.insert("content-type", value("text/plain; charset=utf-8"));
        fields.insert("content-length", value(&BODY.len().to_string()));

        // the server echoes the regular fields of the request
        for (name, val) in block.iter().filter(|(name, _)| !name.starts_with(':')) {
            fields.insert(name, Expected::new(val, authority));
        }
    } else {
        fields.insert(":status", value("405"));
        fields.insert("allow", value("GET,HEAD"));
        fields.insert("content-length", value("0"));
    }

    Some(fields)
}

/// The parser of a case, along with the field each match id stands for.
struct CaseParser {
    names: Vec<&'static str>,
    _parser: http2::AttachedParser,
}

impl CaseParser {
    /// Attaches a parser to `prog` that captures every field `case` sends, and
    /// the ones of the responses.
    fn attach(prog: &TestProgram, case: &Case) -> Result<Self> {
        let names: BTreeSet<&'static str> = case
            .blocks
            .iter()
            .filter_map(Block::sent)
            .flatten()
            .map(|(name, _)| *name)
            .chain(RESPONSE_FIELDS.iter().copied())
            .collect();

        let mut parser = http2::Parser::new();
        let mut by_mid = vec![""; names.len()];
        for name in names {
            let mid = parser
                .capture_hdr(name)
                .with_context(|| format!("capture {name:?}"))?;
            by_mid[u8::from(mid) as usize] = name;
        }

        let parser = parser
            .matched_fn("matched_http2")
            .parse_fn("parse_http2_msg", MessageBuffer::Msg)
            .extract_fn("extract_http2_match_msg", MessageBuffer::Msg)
            .attach(prog.prog_fd())?;

        Ok(Self {
            names: by_mid,
            _parser: parser,
        })
    }

    /// Checks that `block` carries `fields` and nothing else the parser
    /// captures, and describes the mismatches if it does not.
    fn check(&self, block: &ParsedBlock, fields: &Fields) -> Vec<String> {
        let mut problems = Vec::new();
        for (mid, name) in self.names.iter().enumerate() {
            let expected = fields.get(name).cloned().unwrap_or(Expected::Absent);
            let capture = block.captures.get(mid).and_then(Option::as_ref);
            if !expected.matches(capture) {
                problems.push(format!(
                    "{name}: captured {}, expected {expected}",
                    describe(capture)
                ));
            }
        }

        problems
    }
}

/// Follows what the program reports.
struct Results {
    rx: Receiver<ParseResult>,

    /// The ends of the connections to the server that are still open, by the
    /// port of the client end and whether it is the server's end.
    open: BTreeSet<(u16, bool)>,

    /// The header frames parsed since the last call to `take_frames`.
    frames: Vec<Frame>,

    /// Whether the mark `sync` waits for has been handled.
    marked: bool,
}

impl Results {
    fn handle(&mut self, res: ParseResult) {
        match res {
            ParseResult::Open {
                client_port,
                server,
            } => {
                self.open.insert((client_port, server));
            }
            ParseResult::Close {
                client_port,
                server,
            } => {
                self.open.remove(&(client_port, server));
            }
            ParseResult::Frame(frame) => self.frames.push(frame),
            ParseResult::Mark => self.marked = true,
        }
    }

    /// Waits until everything the program reported before this call has been
    /// handled.
    fn sync(&mut self, prog: &TestProgram, deadline: Instant) -> Result<()> {
        self.marked = false;
        prog.mark_results()?;
        while !self.marked {
            self.recv(deadline)?;
        }

        Ok(())
    }

    /// Handles the next report, waiting for it until `deadline`.
    fn recv(&mut self, deadline: Instant) -> Result<()> {
        let left = deadline.saturating_duration_since(Instant::now());
        match self.rx.recv_timeout(left) {
            Ok(res) => self.handle(res),
            Err(RecvTimeoutError::Timeout) => bail!(
                "connections still open after {CLOSE_TIMEOUT:?}: {:?}",
                self.open
            ),
            Err(e) => bail!("results: {e}"),
        }

        Ok(())
    }

    /// Handles what has been reported so far.
    fn drain(&mut self) -> Result<()> {
        loop {
            match self.rx.try_recv() {
                Ok(res) => self.handle(res),
                Err(std::sync::mpsc::TryRecvError::Empty) => return Ok(()),
                Err(e) => bail!("results: {e}"),
            }
        }
    }

    /// Waits until every connection that was opened has been closed again, i.e.
    /// until all of their frames have been reported.
    ///
    /// The reports of a connection that has been opened may still be on their
    /// way, so it first waits for everything reported so far.
    fn wait_closed(&mut self, prog: &TestProgram) -> Result<()> {
        let deadline = Instant::now() + CLOSE_TIMEOUT;
        self.sync(prog, deadline)?;
        while !self.open.is_empty() {
            self.recv(deadline)?;
        }

        self.drain()
    }

    fn take_frames(&mut self) -> Vec<Frame> {
        std::mem::take(&mut self.frames)
    }
}

/// Describes what the parser made of a block, by what it returned for the first
/// of its frames it failed on.
fn describe_error(error: Option<i32>) -> String {
    match error {
        None => "parsed".to_string(),
        Some(err) if err == -libc::EPROTO => "the parser failed on it with -EPROTO".to_string(),
        Some(err) => format!("the parser failed on it ({err})"),
    }
}

/// Checks what the parser made of the case `case`, and describes what it got
/// wrong.
fn check(
    parser: &CaseParser,
    case: &Case,
    frames: &[Frame],
    authority: &str,
) -> (Vec<String>, String) {
    let (requests, responses, mut problems) = blocks(frames);

    if requests.len() != case.blocks.len() {
        problems.push(format!(
            "parsed {} request blocks, h2spec sends {}",
            requests.len(),
            case.blocks.len()
        ));
    }

    for (i, (parsed, sent)) in requests.iter().zip(&case.blocks).enumerate() {
        let what = format!("request block {i} (stream {})", parsed.sid);
        match (sent, parsed.error) {
            (Block::Broken, Some(err)) if err == -libc::EPROTO => {}
            (Block::Malformed, Some(err)) if err != -libc::EPROTO => {}
            (Block::Broken, _) => problems.push(format!(
                "{what}: {}, expected -EPROTO as it breaks a header block",
                describe_error(parsed.error)
            )),
            (Block::Malformed, _) => problems.push(format!(
                "{what}: {}, expected the parser to fail on it",
                describe_error(parsed.error)
            )),
            (Block::Fields(_), Some(err)) => {
                problems.push(format!("{what}: the parser failed on it ({err})"))
            }
            (Block::Fields(sent), None) => {
                let fields = expected_fields(sent, authority);
                problems.extend(
                    parser
                        .check(parsed, &fields)
                        .into_iter()
                        .map(|p| format!("{what}: {p}")),
                );
            }
        }
    }

    let answers: Vec<Fields> = case
        .blocks
        .iter()
        .filter_map(Block::sent)
        .filter_map(|block| response_fields(block, authority))
        .collect();

    for (i, parsed) in responses.iter().enumerate() {
        let what = format!("response block {i} (stream {})", parsed.sid);
        if let Some(err) = parsed.error {
            problems.push(format!("{what}: the parser failed on it ({err})"));
            continue;
        }

        // the closest answer is the one the problems are reported against
        let mismatches = answers
            .iter()
            .map(|fields| parser.check(parsed, fields))
            .min_by_key(Vec::len);
        match mismatches {
            None => problems.push(format!("{what}: the server answers none of the requests")),
            Some(mismatches) => {
                problems.extend(mismatches.into_iter().map(|p| format!("{what}: {p}")))
            }
        }
    }

    let conns: BTreeSet<u16> = requests.iter().map(|b| b.client_port).collect();
    let summary = format!(
        "{} request and {} response blocks on {} connection(s)",
        requests.len(),
        responses.len(),
        conns.len()
    );

    (problems, summary)
}

fn main() -> Result<()> {
    let addr: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".to_string())
        .parse()
        .context("parse address")?;

    let rt = tokio::runtime::Runtime::new()?;
    let addr = rt.block_on(launch(addr))?;
    let authority = addr.to_string();

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Both)?;
    let mut results = Results {
        rx: prog.results()?,
        open: BTreeSet::new(),
        frames: Vec::new(),
        marked: false,
    };

    // the HTTP/1.1 parser only tells the connections that start with the
    // HTTP/2 preface, which the program then parses as HTTP/2
    let mut h1 = http1::Parser::new();
    let preface = h1.match_http2_preface()?;
    if u8::from(preface) != 0 {
        bail!("the program expects the preface to be match 0");
    }
    let _h1 = h1
        .matched_fn("matched_http1")
        .parse_fn("parse_http1_msg", MessageBuffer::Msg)
        .extract_fn("extract_http1_match_msg", MessageBuffer::Msg)
        .attach(prog.prog_fd())?;

    let cases = cases::cases();
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "listening on {addr}")?;

    let mut current: Option<(&Case, CaseParser)> = None;
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        let (cmd, id) = line
            .split_once(' ')
            .ok_or_else(|| anyhow!("malformed command: {line:?}"))?;

        match cmd {
            "case" => {
                let case = cases
                    .iter()
                    .find(|case| case.ids.contains(&id))
                    .ok_or_else(|| anyhow!("unknown case: {id}"))?;

                // the old parser has to let go of the program first
                drop(current.take());
                let parser = CaseParser::attach(&prog, case)?;

                // what is left of the case before does not count
                results.sync(&prog, Instant::now() + CLOSE_TIMEOUT)?;
                results.take_frames();
                current = Some((case, parser));

                writeln!(stdout, "ready {id}")?;
            }
            "check" => {
                let (case, parser) = current
                    .as_ref()
                    .ok_or_else(|| anyhow!("check before case: {id}"))?;

                let (problems, summary) = match results.wait_closed(&prog) {
                    Ok(()) => check(parser, case, &results.take_frames(), &authority),
                    Err(e) => (vec![e.to_string()], String::new()),
                };

                let mut out = String::new();
                for problem in &problems {
                    writeln!(out, "  {problem}")?;
                }
                let verdict = if problems.is_empty() { "pass" } else { "fail" };
                writeln!(out, "{verdict} {id}: {summary}")?;
                stdout.write_all(out.as_bytes())?;
            }
            _ => bail!("unknown command: {line:?}"),
        }

        stdout.flush()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture(sent: &[u8]) -> Capture {
        Capture {
            len: sent.len() as u32,
            head: sent[..sent.len().min(RESULT_VAL_LEN)].to_vec(),
        }
    }

    fn huffman(value: &[u8]) -> Vec<u8> {
        let mut coded = Vec::new();
        huffman::encode(value, &mut coded).unwrap();
        coded
    }

    #[test]
    fn match_a_value_sent_either_way() {
        let expected = Expected::new(&Value::Str("h2spec"), "");
        assert!(expected.matches(Some(&capture(b"h2spec"))));
        assert!(expected.matches(Some(&capture(&huffman(b"h2spec")))));
        assert!(!expected.matches(Some(&capture(b"h2spe"))));
        assert!(!expected.matches(None));
    }

    #[test]
    fn match_a_long_value_by_its_head_and_length() {
        let expected = Expected::new(&Value::Dummy, "");
        let dummy = vec![b'x'; DUMMY_LEN];
        assert!(expected.matches(Some(&capture(&dummy))));
        assert!(expected.matches(Some(&capture(&huffman(&dummy)))));
        assert!(!expected.matches(Some(&capture(&dummy[1..]))));

        // what is left of it in the dynamic table
        assert!(expected.matches(Some(&capture(&dummy[..RESULT_VAL_LEN]))));
    }

    #[test]
    fn expect_an_empty_value_to_be_captured() {
        let expected = Expected::new(&Value::Str(""), "");
        assert!(expected.matches(Some(&capture(b""))));
        assert!(!expected.matches(None));
        assert!(!expected.matches(Some(&capture(b"x"))));
    }

    #[test]
    fn expect_what_was_sent_despite_a_known_limitation() {
        let expected = Expected::new(&Value::Split(Box::new(Value::Str("ok"))), "");
        assert!(matches!(expected, Expected::Limited(..)));
        assert!(expected.matches(Some(&capture(b"ok"))));
        assert!(!expected.matches(None));
        assert!(expected.to_string().contains("known limitation"));
    }

    #[test]
    fn match_raw_bytes_exactly() {
        let expected = Expected::new(&Value::Raw(b"\x49\x50\x90"), "");
        assert!(expected.matches(Some(&capture(b"\x49\x50\x90"))));
        assert!(!expected.matches(Some(&capture(b"\x49\x50"))));
    }

    fn frame(frame_type: u8, flags: u8, sid: u32, upstream: bool, ret: i32) -> Frame {
        Frame {
            client_port: 1234,
            upstream,
            ret,
            sid,
            frame_type,
            flags,
            captures: vec![None; 2],
        }
    }

    #[test]
    fn put_continued_blocks_together() {
        let frames = [
            frame(HEADERS, 0, 1, false, 10),
            frame(HEADERS, END_HEADERS, 3, false, 10),
            frame(CONTINUATION, END_HEADERS, 1, false, 10),
            // a CONTINUATION after the block ended starts one of its own
            frame(CONTINUATION, END_HEADERS, 1, false, -libc::EPROTO),
            frame(HEADERS, END_HEADERS, 1, true, -1),
        ];

        let (requests, responses, problems) = blocks(&frames);
        assert!(problems.is_empty());
        assert_eq!(
            requests
                .iter()
                .map(|b| (b.sid, b.error))
                .collect::<Vec<_>>(),
            vec![(1, None), (3, None), (1, Some(-libc::EPROTO))]
        );
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].error, Some(-1));
    }

    #[test]
    fn answer_requests_like_the_server() {
        let get = vec![(":method", Value::Str("GET")), ("x-test", Value::Str("ok"))];
        let fields = response_fields(&get, "").unwrap();
        assert_eq!(fields[":status"], Expected::Value(b"200".to_vec()));
        assert_eq!(fields["x-test"], Expected::Value(b"ok".to_vec()));

        let post = vec![(":method", Value::Str("POST"))];
        assert_eq!(
            response_fields(&post, "").unwrap()[":status"],
            Expected::Value(b"405".to_vec())
        );

        assert!(response_fields(&[("x-test", Value::Str("ok"))], "").is_none());
    }

    #[test]
    fn list_every_case_once() {
        let cases = cases::cases();
        let mut ids: Vec<_> = cases.iter().flat_map(|c| c.ids.iter()).collect();
        let num = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), num);
        assert_eq!(num, 146);
    }
}
