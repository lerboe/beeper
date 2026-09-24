use beeper::{MatchId, resp2};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use utils::{
    server,
    test::{Direction, Hook, TestProgram},
};
use xbpf::OpenObject;

/// Asserts that the parser captured `expected` for `mid` in the last command
/// it parsed, or nothing if `expected` is `None`.
fn assert_match_eq(prog: &TestProgram, mid: MatchId, expected: Option<&[u8]>) {
    let actual = prog.get_match(mid).expect("get_match");
    assert_eq!(
        actual.as_deref().map(String::from_utf8_lossy),
        expected.map(String::from_utf8_lossy),
        "get_match({mid:?})"
    );
}

/// Encodes `args` as the array of bulk strings a client sends a command as.
fn cmd(args: &[&[u8]]) -> Vec<u8> {
    let mut msg = format!("*{}\r\n", args.len()).into_bytes();
    for arg in args {
        msg.extend(format!("${}\r\n", arg.len()).bytes());
        msg.extend(*arg);
        msg.extend(b"\r\n");
    }
    msg
}

/// Writes `req` to `stream` in a single write and asserts that the server
/// answers it with `reply`.
async fn request(stream: &mut TcpStream, req: &[u8], reply: &[u8]) {
    stream.write_all(req).await.expect("write request");

    let mut buf = vec![0; reply.len()];
    stream.read_exact(&mut buf).await.expect("read reply");
    assert_eq!(
        String::from_utf8_lossy(&buf),
        String::from_utf8_lossy(reply)
    );
}

/// Attaches a parser capturing the arguments at `args` and returns it along
/// with the match id of each of them, in the order they were configured in.
fn attach_resp2_parser(
    prog_fd: i32,
    hook: Hook,
    args: &[usize],
) -> (resp2::AttachedParser, Vec<MatchId>) {
    let mut parser = resp2::Parser::new();

    let mut mids = Vec::new();
    for &arg in args {
        mids.push(parser.capture_arg(arg).expect("capture argument"));
    }

    let suffix = hook.to_string();
    let parser = parser
        .matched_fn("matched_resp2")
        .parse_fn(format!("parse_resp2_{suffix}"), hook.into())
        .extract_fn(format!("extract_resp2_match_{suffix}"), hook.into());

    (parser.attach(prog_fd).expect("attach parser"), mids)
}

/// Sets `key` to `value` on a fresh Redis at `hook` and asserts that the
/// command, the key and the value are captured.
async fn set_a_key_at(hook: Hook) {
    let redis = server::launch_redis().await.expect("launch redis");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach_resp2(redis.addr, &mut open_obj, Direction::Downstream, hook)
        .expect("attach");
    let (_resp2, mids) = attach_resp2_parser(prog.prog_fd(), hook, &[0, 1, 2]);

    let mut stream = TcpStream::connect(redis.addr).await.expect("connect");
    request(&mut stream, &cmd(&[b"SET", b"key", b"value"]), b"+OK\r\n").await;

    assert_match_eq(&prog, mids[0], Some(b"SET"));
    assert_match_eq(&prog, mids[1], Some(b"key"));
    assert_match_eq(&prog, mids[2], Some(b"value"));
}

/// Gets a key that was set before on a fresh Redis at `hook` and asserts that
/// the command and the key are captured, and nothing for the value a `GET`
/// does not have.
async fn get_a_key_at(hook: Hook) {
    let redis = server::launch_redis().await.expect("launch redis");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach_resp2(redis.addr, &mut open_obj, Direction::Downstream, hook)
        .expect("attach");
    let (_resp2, mids) = attach_resp2_parser(prog.prog_fd(), hook, &[0, 1, 2]);

    let mut stream = TcpStream::connect(redis.addr).await.expect("connect");
    request(&mut stream, &cmd(&[b"SET", b"key", b"value"]), b"+OK\r\n").await;
    request(&mut stream, &cmd(&[b"GET", b"key"]), b"$5\r\nvalue\r\n").await;

    assert_match_eq(&prog, mids[0], Some(b"GET"));
    assert_match_eq(&prog, mids[1], Some(b"key"));
    assert_match_eq(&prog, mids[2], None);
}

#[tokio::test]
async fn set_a_key() {
    set_a_key_at(Hook::Msg).await;
}

#[tokio::test]
async fn set_a_key_in_skb() {
    set_a_key_at(Hook::Skb).await;
}

#[tokio::test]
async fn get_a_key() {
    get_a_key_at(Hook::Msg).await;
}

#[tokio::test]
async fn get_a_key_in_skb() {
    get_a_key_at(Hook::Skb).await;
}

#[tokio::test]
async fn parse_every_command_of_a_pipeline() {
    let redis = server::launch_redis().await.expect("launch redis");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach_resp2(redis.addr, &mut open_obj, Direction::Downstream, Hook::Msg)
            .expect("attach");
    let (_resp2, mids) = attach_resp2_parser(prog.prog_fd(), Hook::Msg, &[0, 1, 2]);

    // both commands go out in a single message. The parser only reaches the
    // second one if it reports exactly where the first one ends
    let req = [cmd(&[b"SET", b"key", b"value"]), cmd(&[b"GET", b"other"])].concat();

    let mut stream = TcpStream::connect(redis.addr).await.expect("connect");
    request(&mut stream, &req, b"+OK\r\n$-1\r\n").await;

    assert_match_eq(&prog, mids[0], Some(b"GET"));
    assert_match_eq(&prog, mids[1], Some(b"other"));
    assert_match_eq(&prog, mids[2], None);
}

#[tokio::test]
async fn capture_a_value_that_holds_crlf() {
    let redis = server::launch_redis().await.expect("launch redis");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach_resp2(redis.addr, &mut open_obj, Direction::Downstream, Hook::Msg)
            .expect("attach");
    let (_resp2, mids) = attach_resp2_parser(prog.prog_fd(), Hook::Msg, &[1, 2]);

    // the value looks like the start of another command
    let value = b"a\r\n*1\r\n$1\r\nb";
    let mut stream = TcpStream::connect(redis.addr).await.expect("connect");
    request(&mut stream, &cmd(&[b"SET", b"key", value]), b"+OK\r\n").await;

    assert_match_eq(&prog, mids[0], Some(b"key"));
    assert_match_eq(&prog, mids[1], Some(value));
}

#[tokio::test]
async fn capture_nothing_for_an_empty_value() {
    let redis = server::launch_redis().await.expect("launch redis");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach_resp2(redis.addr, &mut open_obj, Direction::Downstream, Hook::Msg)
            .expect("attach");
    let (_resp2, mids) = attach_resp2_parser(prog.prog_fd(), Hook::Msg, &[1, 2]);

    let mut stream = TcpStream::connect(redis.addr).await.expect("connect");
    request(&mut stream, &cmd(&[b"SET", b"key", b""]), b"+OK\r\n").await;

    assert_match_eq(&prog, mids[0], Some(b"key"));
    assert_match_eq(&prog, mids[1], None);
}

#[tokio::test]
async fn ignore_an_inline_command() {
    let redis = server::launch_redis().await.expect("launch redis");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach_resp2(redis.addr, &mut open_obj, Direction::Downstream, Hook::Msg)
            .expect("attach");
    let (_resp2, mids) = attach_resp2_parser(prog.prog_fd(), Hook::Msg, &[0, 1, 2]);

    // Redis accepts commands typed into a telnet session, which are no RESP
    let mut stream = TcpStream::connect(redis.addr).await.expect("connect");
    request(&mut stream, b"SET key value\r\n", b"+OK\r\n").await;

    for mid in mids {
        assert_match_eq(&prog, mid, None);
    }
}

#[tokio::test]
async fn report_the_arguments_that_were_matched() {
    let redis = server::launch_redis().await.expect("launch redis");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach_resp2(redis.addr, &mut open_obj, Direction::Downstream, Hook::Msg)
            .expect("attach");
    let (_resp2, mids) = attach_resp2_parser(prog.prog_fd(), Hook::Msg, &[0, 1, 2]);

    let mut stream = TcpStream::connect(redis.addr).await.expect("connect");
    request(&mut stream, &cmd(&[b"GET", b"key"]), b"$-1\r\n").await;

    // a GET has no third argument
    assert_eq!(
        prog.last_matches(),
        1 << u8::from(mids[0]) | 1 << u8::from(mids[1]),
        "only the command and the key are matched"
    );
}
