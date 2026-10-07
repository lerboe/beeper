//! What h2spec sends in each of its cases, i.e. what the parser is expected to
//! capture of it.
//!
//! A case is listed with every header block it sends, in order, and the parser
//! is configured to capture every field these blocks carry. Cases that send the
//! same blocks share an entry, and with it a configuration.

/// The value of a header field as h2spec sends it.
#[derive(Clone, Debug)]
pub enum Value {
    Str(&'static str),

    /// The address of the server, which h2spec sends as `:authority`.
    Authority,

    /// The value h2spec pads its header blocks with, `--max-header-length`
    /// times `x`.
    Dummy,

    /// Bytes that are not a valid Huffman code, which the parser is expected
    /// to capture as they are.
    Raw(&'static [u8]),

    /// Known limitation: a value that is split across a HEADERS and a
    /// CONTINUATION frame. The parser points into the frame it parses, so it
    /// cannot point at a value that is in two of them, and captures nothing.
    Split(Box<Value>),
}

use Value::*;

/// A header field, by name and value.
pub type Field = (&'static str, Value);

/// A header block as h2spec sends it.
#[derive(Clone, Debug)]
pub enum Block {
    /// A block that carries these fields.
    Fields(Vec<Field>),

    /// A block the parser is expected to fail on, as it is malformed, e.g. one
    /// that refers to an index no table has.
    Malformed,

    /// A block that is broken by a frame that violates the rules for the frames
    /// a header block is sent in, e.g. a CONTINUATION frame that does not carry
    /// on the block of its stream, see `EPROTO` in beeper/http2.h. Such a frame
    /// is a connection error, and the parser is expected to fail on it with
    /// `-EPROTO`.
    Broken,
}

pub use Block::{Broken, Malformed};

impl Block {
    /// The fields the block carries, if it is not one the parser is expected
    /// to fail on.
    pub fn sent(&self) -> Option<&[Field]> {
        match self {
            Block::Fields(fields) => Some(fields),
            Block::Malformed | Block::Broken => None,
        }
    }
}

/// What the cases `ids` send.
pub struct Case {
    pub ids: &'static [&'static str],
    pub expect: Expect,
}

/// What a case sends, and with it what the parser is expected to make of it.
pub enum Expect {
    /// These header blocks, in order.
    Blocks(Vec<Block>),

    /// These header blocks, in order, the last of which is [`Broken`] by a
    /// violation of the rules for the frames a header block is sent in.
    ///
    /// The peer may close the connection as soon as it sees the violation, so
    /// what h2spec gets to send after it, and the parser to see, hinges on
    /// timing. Any block the parser sees after the listed ones is expected to
    /// be broken, too.
    Violation(Vec<Block>),
}

pub use Expect::{Blocks, Violation};

impl Case {
    /// The header blocks the case sends.
    pub fn blocks(&self) -> &[Block] {
        match &self.expect {
            Blocks(blocks) | Violation(blocks) => blocks,
        }
    }
}

/// The value h2spec pads its header blocks with, see [`Value::Dummy`].
pub const DUMMY_LEN: usize = 4000;

/// The pseudo-header fields of a request with `method`, followed by `fields`.
fn request(method: &'static str, fields: Vec<Field>) -> Block {
    let mut block = vec![
        (":method", Str(method)),
        (":scheme", Str("http")),
        (":path", Str("/")),
        (":authority", Authority),
    ];
    block.extend(fields);
    Block::Fields(block)
}

fn get(fields: Vec<Field>) -> Block {
    request("GET", fields)
}

fn head(fields: Vec<Field>) -> Block {
    request("HEAD", fields)
}

fn post(fields: Vec<Field>) -> Block {
    request("POST", fields)
}

/// A block that carries nothing but `fields`.
fn fields(fields: Vec<Field>) -> Block {
    Block::Fields(fields)
}

/// Returns every case h2spec runs.
pub fn cases() -> Vec<Case> {
    vec![
        Case {
            ids: &[
                // a PRIORITY frame comes between the HEADERS and the
                // CONTINUATION frame of a block
                "http2/4.3/2",
                "http2/6.2/1",
                // a CONTINUATION frame on a stream that is idle
                "http2/5.1/4",
                // an unknown extension frame follows the HEADERS frame of a
                // block that has not ended
                "http2/5.5/2",
                // a HEADERS frame on stream 0
                "http2/6.2/3",
                // a DATA frame follows a CONTINUATION frame of a block that
                // has not ended
                "http2/6.10/2",
                // a DATA frame comes between the HEADERS and the CONTINUATION
                // frame of a block
                "http2/6.10/6",
            ],
            expect: Violation(vec![Broken]),
        },
        Case {
            ids: &[
                // the HEADERS frame of another stream comes between the HEADERS
                // and the CONTINUATION frame of a block, which breaks both
                "http2/4.3/3",
                "http2/6.2/2",
                // a CONTINUATION frame on stream 0 does, too
                "http2/6.10/3",
            ],
            expect: Violation(vec![Broken, Broken]),
        },
        // a CONTINUATION frame on a stream whose block has ended
        Case {
            ids: &[
                "http2/5.1/7",
                "http2/5.1/10",
                "http2/5.1/13",
                "http2/6.10/4",
            ],
            expect: Violation(vec![get(vec![]), Broken]),
        },
        Case {
            ids: &["http2/6.10/5"],
            expect: Violation(vec![get(vec![("x-dummy0", Dummy)]), Broken]),
        },
        Case {
            ids: &[
                "generic/1/1",
                "generic/2/1",
                "generic/3.5/1",
                "generic/3.7/1",
                "generic/3.8/1",
                "generic/3.9/1",
                "http2/3.5/1",
                "http2/3.5/2",
                "http2/4.1/1",
                "http2/4.1/2",
                "http2/4.1/3",
                "http2/5.1/1",
                "http2/5.1/2",
                "http2/5.1/3",
                "http2/5.3.1/2",
                "http2/5.4.1/1",
                "http2/5.5/1",
                "http2/6.1/1",
                "http2/6.3/1",
                "http2/6.4/1",
                "http2/6.4/2",
                "http2/6.5/1",
                "http2/6.5/2",
                "http2/6.5/3",
                "http2/6.5.2/1",
                "http2/6.5.2/2",
                "http2/6.5.2/3",
                "http2/6.5.2/4",
                "http2/6.5.2/5",
                "http2/6.5.3/2",
                "http2/6.7/1",
                "http2/6.7/2",
                "http2/6.7/3",
                "http2/6.7/4",
                "http2/6.8/1",
                "http2/6.9/1",
                "http2/6.9/3",
                "http2/6.9.1/2",
                "http2/6.9.2/3",
                "http2/7/1",
                "http2/8.2/1",
            ],
            expect: Blocks(vec![]),
        },
        Case {
            ids: &[
                "generic/2/2",
                "generic/2/3",
                "generic/2/4",
                "generic/2/5",
                "generic/3.2/1",
                "generic/3.2/2",
                "generic/3.2/3",
                "generic/3.3/1",
                "generic/3.3/2",
                "generic/3.3/3",
                "generic/3.3/4",
                "generic/3.3/5",
                "generic/3.4/1",
                "generic/3.9/2",
                "generic/4/1",
                "generic/5/14",
                "generic/5/15",
                "http2/5.1/5",
                "http2/5.1/8",
                "http2/5.1/11",
                "http2/5.1.1/1",
                "http2/5.3.1/1",
                "http2/6.3/2",
                "http2/6.4/3",
                "http2/6.9/2",
                "http2/6.9.1/3",
                "hpack/2.3.3/1",
                "hpack/2.3.3/2",
                "hpack/4.2/1",
                "hpack/6.3/1",
            ],
            expect: Blocks(vec![get(vec![])]),
        },
        Case {
            ids: &[
                "generic/3.1/1",
                "generic/3.1/2",
                "generic/3.1/3",
                "generic/4/3",
                "http2/4.2/1",
                "http2/4.2/2",
                "http2/6.1/2",
                "http2/7/2",
            ],
            expect: Blocks(vec![post(vec![])]),
        },
        Case {
            ids: &["generic/4/2"],
            expect: Blocks(vec![head(vec![])]),
        },
        Case {
            ids: &["generic/4/4"],
            expect: Blocks(vec![
                post(vec![("trailer", Str("x-test"))]),
                fields(vec![("x-test", Str("ok"))]),
            ]),
        },
        Case {
            ids: &["generic/5/1"],
            expect: Blocks(vec![get(vec![("user-agent", Str(""))])]),
        },
        Case {
            ids: &[
                "generic/5/2",
                "generic/5/3",
                "generic/5/6",
                "generic/5/7",
                "generic/5/10",
                "generic/5/11",
            ],
            expect: Blocks(vec![get(vec![("user-agent", Str("h2spec"))])]),
        },
        Case {
            ids: &[
                "generic/5/4",
                "generic/5/5",
                "generic/5/8",
                "generic/5/9",
                "generic/5/12",
                "generic/5/13",
            ],
            expect: Blocks(vec![get(vec![("x-test", Str("h2spec"))])]),
        },
        Case {
            ids: &["http2/4.2/3"],
            expect: Blocks(vec![get(vec![
                ("x-dummy0", Dummy),
                ("x-dummy1", Dummy),
                ("x-dummy2", Dummy),
                ("x-dummy3", Dummy),
                ("x-dummy4", Dummy),
            ])]),
        },
        Case {
            ids: &["http2/4.3/1"],
            expect: Blocks(vec![fields(vec![])]),
        },
        Case {
            ids: &[
                "http2/5.1/6",
                "http2/5.1/9",
                "http2/5.1/12",
                "http2/5.1.1/2",
                // h2spec first asks for / on a connection of its own, to learn
                // how long the body is
                "http2/6.5.3/1",
                "http2/6.9.1/1",
                "http2/6.9.2/1",
                "http2/6.9.2/2",
            ],
            expect: Blocks(vec![get(vec![]), get(vec![])]),
        },
        Case {
            ids: &["http2/5.1.2/1"],
            expect: Blocks(vec![get(vec![]); 201]),
        },
        Case {
            ids: &["http2/6.1/3"],
            expect: Blocks(vec![post(vec![("content-length", Str("4"))])]),
        },
        Case {
            ids: &["http2/6.2/4", "hpack/6.1/1"],
            expect: Blocks(vec![Malformed]),
        },
        Case {
            ids: &["http2/6.10/1"],
            expect: Blocks(vec![get(vec![("x-dummy0", Dummy), ("x-dummy0", Dummy)])]),
        },
        // the HEADERS frame is split after its 5th byte, in the middle of the
        // value of :authority
        Case {
            ids: &["generic/3.10/1", "generic/3.10/2"],
            expect: Blocks(vec![fields(vec![
                (":method", Str("GET")),
                (":scheme", Str("http")),
                (":path", Str("/")),
                (":authority", Split(Box::new(Authority))),
            ])]),
        },
        Case {
            ids: &["http2/8.1/1"],
            expect: Blocks(vec![post(vec![]), fields(vec![("x-test", Str("ok"))])]),
        },
        Case {
            ids: &["http2/8.1.2/1"],
            expect: Blocks(vec![get(vec![("X-TEST", Str("ok"))])]),
        },
        Case {
            ids: &["http2/8.1.2.1/1"],
            expect: Blocks(vec![get(vec![(":test", Str("ok"))])]),
        },
        Case {
            ids: &["http2/8.1.2.1/2"],
            expect: Blocks(vec![get(vec![(":status", Str("200"))])]),
        },
        Case {
            ids: &["http2/8.1.2.1/3"],
            expect: Blocks(vec![post(vec![]), fields(vec![(":method", Str("POST"))])]),
        },
        Case {
            ids: &["http2/8.1.2.1/4"],
            expect: Blocks(vec![fields(vec![
                ("x-test", Str("ok")),
                (":method", Str("GET")),
                (":scheme", Str("http")),
                (":path", Str("/")),
                (":authority", Authority),
            ])]),
        },
        Case {
            ids: &["http2/8.1.2.2/1"],
            expect: Blocks(vec![get(vec![("connection", Str("keep-alive"))])]),
        },
        Case {
            ids: &["http2/8.1.2.2/2"],
            expect: Blocks(vec![get(vec![
                ("trailers", Str("test")),
                ("te", Str("trailers, deflate")),
            ])]),
        },
        Case {
            ids: &["http2/8.1.2.3/1"],
            expect: Blocks(vec![fields(vec![
                (":method", Str("GET")),
                (":scheme", Str("http")),
                (":path", Str("")),
                (":authority", Authority),
            ])]),
        },
        Case {
            ids: &["http2/8.1.2.3/2"],
            expect: Blocks(vec![fields(vec![
                (":path", Str("/")),
                (":authority", Authority),
            ])]),
        },
        Case {
            ids: &["http2/8.1.2.3/3"],
            expect: Blocks(vec![fields(vec![
                (":method", Str("GET")),
                (":path", Str("/")),
                (":authority", Authority),
            ])]),
        },
        Case {
            ids: &["http2/8.1.2.3/4"],
            expect: Blocks(vec![fields(vec![
                (":method", Str("GET")),
                (":scheme", Str("http")),
                (":authority", Authority),
            ])]),
        },
        Case {
            ids: &["http2/8.1.2.3/5"],
            expect: Blocks(vec![get(vec![(":method", Str("GET"))])]),
        },
        Case {
            ids: &["http2/8.1.2.3/6"],
            expect: Blocks(vec![get(vec![(":scheme", Str("http"))])]),
        },
        Case {
            ids: &["http2/8.1.2.3/7"],
            expect: Blocks(vec![get(vec![(":path", Str("/"))])]),
        },
        Case {
            ids: &["http2/8.1.2.6/1", "http2/8.1.2.6/2"],
            expect: Blocks(vec![post(vec![("content-length", Str("1"))])]),
        },
        Case {
            ids: &["hpack/5.2/1"],
            expect: Blocks(vec![get(vec![("x-test", Raw(b"\x49\x50\x9f\xff"))])]),
        },
        Case {
            ids: &["hpack/5.2/2"],
            expect: Blocks(vec![get(vec![("x-test", Raw(b"\x49\x50\x90"))])]),
        },
        Case {
            ids: &["hpack/5.2/3"],
            expect: Blocks(vec![get(vec![(
                "x-test",
                Raw(b"\x49\x51\xff\xff\xff\xfa\x7f"),
            )])]),
        },
    ]
}
