//! Runs the [h2spec](https://github.com/summerwind/h2spec) conformance suite
//! through the HTTP/2 parser.
//!
//! h2spec tests servers, and beeper is not one: it only watches the traffic of
//! the echo server of `utils`. So every case is run twice, against a bare
//! server and against one whose requests the parser reads, and the parser
//! passes a case if
//!
//! * h2spec comes to the same verdict both times, i.e. the parser neither
//!   stalled nor corrupted the connection, and
//! * the parser did not give up on a frame of it, unless the case is one of
//!   [`EXPECTED_PARSE_ERRORS`].
//!
//! The h2spec binary is taken from `$H2SPEC`, or downloaded into the target
//! directory on first use. The tests are ignored by default, as they need the
//! network for that, root for the parser, and take a few minutes; run them with
//!
//! ```sh
//! cargo test -p beeper --test h2spec -- --include-ignored
//! ```

use beeper::{MatchId, http1, http2, pseudo_header};
use http::header;
use std::{
    collections::BTreeMap,
    fmt,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use tokio::{process::Command, sync::OnceCell};
use utils::{
    server,
    test::{Direction, Hook, TestProgram},
};
use xbpf::OpenObject;

/// The h2spec release that is downloaded if `$H2SPEC` is not set.
const H2SPEC_VERSION: &str = "v2.6.0";

/// The cases in which the parser is expected to give up on a frame, because
/// h2spec sends a malformed one on purpose.
const EXPECTED_PARSE_ERRORS: &[&str] = &[
    // a field indexed with 0, which no table entry has
    "hpack/6.1/1",
    // a HEADERS frame whose padding is longer than its payload
    "http2/6.2/4",
];

/// How often a case whose verdict differs from the one without the parser is
/// retried, on both servers. A few cases hinge on timeouts, which a loaded
/// machine can miss, the bare server included.
const RETRIES: usize = 2;

/// Returns the h2spec binary, downloading it first if needed.
async fn h2spec() -> PathBuf {
    // the tests run alongside each other, and only one of them downloads it
    static BIN: OnceCell<PathBuf> = OnceCell::const_new();
    BIN.get_or_init(fetch_h2spec).await.clone()
}

async fn fetch_h2spec() -> PathBuf {
    if let Some(bin) = std::env::var_os("H2SPEC") {
        return bin.into();
    }

    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("h2spec")
        .join(H2SPEC_VERSION);
    let bin = dir.join("h2spec");
    if bin.exists() {
        return bin;
    }

    assert!(
        cfg!(all(target_os = "linux", target_arch = "x86_64")),
        "no h2spec release for this platform, point $H2SPEC to a build of it"
    );

    std::fs::create_dir_all(&dir).expect("create h2spec dir");
    let url = format!(
        "https://github.com/summerwind/h2spec/releases/download/{H2SPEC_VERSION}/h2spec_linux_amd64.tar.gz"
    );
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "curl -sSfL '{url}' | tar -xz -C '{}' h2spec",
            dir.display()
        ))
        .status()
        .await
        .expect("run curl");
    assert!(status.success(), "download h2spec from {url}");

    bin
}

/// Returns the id of every case of the suite, e.g. `http2/6.5.3/2`, which is
/// how h2spec is told to run just that one.
///
/// h2spec has no machine readable listing, so the ids are pieced together from
/// the titles of `--dryrun`: a line without indentation starts a suite, one
/// that starts with a dotted number a section of it, and one that starts with
/// `<n>:` a case of the section above it.
async fn cases(bin: &Path) -> Vec<String> {
    let out = Command::new(bin)
        .arg("--dryrun")
        .output()
        .await
        .expect("run h2spec --dryrun");
    assert!(out.status.success(), "h2spec --dryrun: {out:?}");

    let mut suite = "";
    let mut section = String::new();
    let mut cases = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let title = line.trim_start();
        if title.is_empty() {
            continue;
        }

        if title.len() == line.len() {
            suite = if title.starts_with("Generic") {
                "generic"
            } else if title.starts_with("HPACK") {
                "hpack"
            } else if title.starts_with("Hypertext") {
                "http2"
            } else {
                panic!("unknown h2spec suite: {title}")
            };
            continue;
        }

        let num: String = title
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        match title[num.len()..].chars().next() {
            Some(':') => cases.push(format!("{suite}/{section}/{num}")),
            _ => section = num.trim_end_matches('.').to_string(),
        }
    }

    assert!(!cases.is_empty(), "h2spec lists no cases");
    cases
}

/// What h2spec made of a case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    Passed,
    Failed,
    Skipped,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Runs the case `id` against the server at `addr`, and returns h2spec's
/// verdict along with what it printed, which says why a case failed.
async fn run_case(bin: &Path, addr: SocketAddr, id: &str) -> (Verdict, String) {
    // the tests run alongside each other, each against a server of its own
    let report = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("h2spec-{}.xml", addr.port()));
    _ = std::fs::remove_file(&report);

    let out = Command::new(bin)
        .arg(id)
        .args(["-h", &addr.ip().to_string()])
        .args(["-p", &addr.port().to_string()])
        .arg("-j")
        .arg(&report)
        .output()
        .await
        .expect("run h2spec");
    let log = String::from_utf8_lossy(&out.stdout).into_owned();

    let report = std::fs::read_to_string(&report).unwrap_or_default();
    if !report.contains("<testcase") {
        panic!("h2spec {id} ran no case: {out:?}");
    }

    let verdict = if report.contains("<failure") || report.contains("<error") {
        Verdict::Failed
    } else if report.contains("<skipped") {
        Verdict::Skipped
    } else {
        Verdict::Passed
    };

    (verdict, log)
}

/// What a case came to without and with the parser attached.
struct Outcome {
    bare: Verdict,
    parsed: Verdict,

    /// What h2spec printed with the parser attached.
    log: String,

    /// The HTTP/2 frames the parser saw, and the ones it gave up on.
    frames: u64,
    errors: u64,
}

/// Runs the case `id` against both servers, `bare` and `parsed`, the second of
/// which `prog` parses the traffic of.
async fn run_case_twice(
    bin: &Path,
    bare: SocketAddr,
    parsed: SocketAddr,
    id: &str,
    prog: &TestProgram<'_>,
) -> Outcome {
    let (bare, _) = run_case(bin, bare, id).await;

    let (frames, errors) = prog.h2_frame_counts();
    let (verdict, log) = run_case(bin, parsed, id).await;
    let (frames_after, errors_after) = prog.h2_frame_counts();

    Outcome {
        bare,
        parsed: verdict,
        log,
        frames: frames_after - frames,
        errors: errors_after - errors,
    }
}

fn attach_http1_parser(prog_fd: i32, hook: Hook) -> http1::AttachedParser {
    let mut h1 = http1::Parser::new();
    h1.match_http2_preface().expect("match preface");

    let suffix = hook.to_string();
    h1.matched_fn("matched_http1")
        .parse_fn(format!("parse_http1_{suffix}"), hook.into())
        .extract_fn(format!("extract_http1_match_{suffix}"), hook.into())
        .attach(prog_fd)
        .expect("attach http1 parser")
}

/// Attaches a parser that captures a few fields h2spec sends, so that the
/// captures are exercised along with the rest of the parser.
fn attach_http2_parser(prog_fd: i32, hook: Hook) -> (http2::AttachedParser, Vec<MatchId>) {
    let mut h2 = http2::Parser::new();

    let mids = [
        pseudo_header::PATH.as_str(),
        pseudo_header::AUTHORITY.as_str(),
        header::CONTENT_LENGTH.as_str(),
        "x-dummy0",
    ]
    .into_iter()
    .map(|hdr| {
        h2.capture_hdr(hdr)
            .unwrap_or_else(|e| panic!("capture {hdr:?}: {e}"))
    })
    .collect();

    let suffix = hook.to_string();
    let h2 = h2
        .matched_fn("matched_http2")
        .parse_fn(format!("parse_http2_{suffix}"), hook.into())
        .extract_fn(format!("extract_http2_match_{suffix}"), hook.into())
        .attach(prog_fd)
        .expect("attach http2 parser");

    (h2, mids)
}

async fn conformance(hook: Hook) {
    let bin = h2spec().await;
    let cases = cases(&bin).await;

    // the program only parses the connections to the address it is attached
    // to, so the bare server is left alone
    let bare = server::launch().await.expect("launch server");
    let parsed = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach_to(parsed, &mut open_obj, Direction::Downstream, hook)
        .expect("attach program");
    let _h1 = attach_http1_parser(prog.prog_fd(), hook);
    let _h2 = attach_http2_parser(prog.prog_fd(), hook);

    let mut outcomes = BTreeMap::new();
    for id in &cases {
        let mut outcome = run_case_twice(&bin, bare, parsed, id, &prog).await;
        for _ in 0..RETRIES {
            if outcome.bare == outcome.parsed {
                break;
            }
            outcome = run_case_twice(&bin, bare, parsed, id, &prog).await;
        }

        outcomes.insert(id.as_str(), outcome);
    }

    let mut problems = Vec::new();
    let mut frames = 0;
    println!(
        "{:<20} {:<8} {:<8} {:>6} {:>6}",
        "case", "bare", "parsed", "frames", "errors"
    );
    for (id, o) in &outcomes {
        let flag = if o.bare != o.parsed {
            problems.push(format!(
                "{id}: {} without the parser, {} with it\n{}",
                o.bare,
                o.parsed,
                o.log.trim_end()
            ));
            " <- verdict"
        } else if o.errors > 0 && !EXPECTED_PARSE_ERRORS.contains(id) {
            problems.push(format!("{id}: the parser failed on {} frame(s)", o.errors));
            " <- parse error"
        } else {
            ""
        };

        println!(
            "{id:<20} {:<8} {:<8} {:>6} {:>6}{flag}",
            o.bare, o.parsed, o.frames, o.errors
        );
        frames += o.frames;
    }

    let stale: Vec<_> = EXPECTED_PARSE_ERRORS
        .iter()
        .filter(|id| outcomes.get(**id).is_none_or(|o| o.errors == 0))
        .collect();

    assert!(frames > 0, "the parser saw no HTTP/2 frame");
    assert!(
        problems.is_empty(),
        "{} of {} h2spec cases fail with the parser attached:\n{}",
        problems.len(),
        outcomes.len(),
        problems.join("\n")
    );
    assert!(
        stale.is_empty(),
        "expected parse errors that did not occur: {stale:?}"
    );
}

#[tokio::test]
#[ignore = "downloads h2spec and runs for minutes"]
async fn h2spec_msg() {
    conformance(Hook::Msg).await;
}

#[tokio::test]
#[ignore = "downloads h2spec and runs for minutes"]
async fn h2spec_skb() {
    conformance(Hook::Skb).await;
}

/// The echo server on its own, to tell the cases the parser fails apart from
/// the ones the server fails anyway.
#[tokio::test]
#[ignore = "downloads h2spec and runs for minutes"]
async fn h2spec_server() {
    let bin = h2spec().await;
    let cases = cases(&bin).await;
    let addr = server::launch().await.expect("launch server");

    let mut failed = Vec::new();
    for id in &cases {
        let (verdict, _) = run_case(&bin, addr, id).await;
        println!("{id:<20} {verdict}");
        if verdict == Verdict::Failed {
            failed.push(id.as_str());
        }
    }

    println!(
        "{} of {} cases fail on the bare server: {failed:?}",
        failed.len(),
        cases.len()
    );
}
