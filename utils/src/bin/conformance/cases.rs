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

    /// Known limitation: a value in a CONTINUATION frame that does not carry
    /// on the header block of its stream, e.g. one that follows a block that
    /// has ended. The parser captures nothing of it.
    Stray(Box<Value>),
}

use Value::*;

/// A header field, by name and value.
pub type Field = (&'static str, Value);

/// The fields of a header block, or `None` for one the parser is expected to
/// reject.
pub type Block = Option<Vec<Field>>;

/// The header blocks the cases `ids` send.
pub struct Case {
    pub ids: &'static [&'static str],
    pub blocks: Vec<Block>,
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
    Some(block)
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
    Some(fields)
}

/// `block`, sent in a CONTINUATION frame that does not carry on a block, see
/// [`Value::Stray`].
fn stray(block: Block) -> Block {
    block.map(|fields| {
        fields
            .into_iter()
            .map(|(name, value)| (name, Stray(Box::new(value))))
            .collect()
    })
}

/// Returns every case h2spec runs.
pub fn cases() -> Vec<Case> {
    vec![
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
            blocks: vec![],
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
                "http2/5.5/2",
                "http2/6.2/3",
                "http2/6.3/2",
                "http2/6.4/3",
                "http2/6.9/2",
                "http2/6.9.1/3",
                "hpack/2.3.3/1",
                "hpack/2.3.3/2",
                "hpack/4.2/1",
                "hpack/6.3/1",
            ],
            blocks: vec![get(vec![])],
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
            blocks: vec![post(vec![])],
        },
        Case {
            ids: &["generic/4/2"],
            blocks: vec![head(vec![])],
        },
        Case {
            ids: &["generic/4/4"],
            blocks: vec![
                post(vec![("trailer", Str("x-test"))]),
                fields(vec![("x-test", Str("ok"))]),
            ],
        },
        Case {
            ids: &["generic/5/1"],
            blocks: vec![get(vec![("user-agent", Str(""))])],
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
            blocks: vec![get(vec![("user-agent", Str("h2spec"))])],
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
            blocks: vec![get(vec![("x-test", Str("h2spec"))])],
        },
        Case {
            ids: &["http2/4.2/3"],
            blocks: vec![get(vec![
                ("x-dummy0", Dummy),
                ("x-dummy1", Dummy),
                ("x-dummy2", Dummy),
                ("x-dummy3", Dummy),
                ("x-dummy4", Dummy),
            ])],
        },
        Case {
            ids: &["http2/4.3/1"],
            blocks: vec![fields(vec![])],
        },
        Case {
            ids: &["http2/4.3/2", "http2/6.2/1"],
            blocks: vec![get(vec![("x-dummy0", Dummy)])],
        },
        // the HEADERS frame of another stream comes between the HEADERS and
        // the CONTINUATION frame of the first
        Case {
            ids: &["http2/4.3/3", "http2/6.2/2"],
            blocks: vec![get(vec![("x-dummy0", Stray(Box::new(Dummy)))]), get(vec![])],
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
            blocks: vec![get(vec![]), get(vec![])],
        },
        Case {
            ids: &["http2/6.10/3"],
            blocks: vec![get(vec![]), fields(vec![("x-dummy0", Dummy)])],
        },
        Case {
            ids: &["http2/5.1.2/1"],
            blocks: vec![get(vec![]); 201],
        },
        Case {
            ids: &["http2/6.1/3"],
            blocks: vec![post(vec![("content-length", Str("4"))])],
        },
        Case {
            ids: &["http2/6.2/4", "hpack/6.1/1"],
            blocks: vec![None],
        },
        Case {
            ids: &["http2/6.10/1"],
            blocks: vec![get(vec![("x-dummy0", Dummy), ("x-dummy0", Dummy)])],
        },
        Case {
            ids: &["http2/6.10/2"],
            blocks: vec![post(vec![("x-dummy0", Dummy)])],
        },
        Case {
            ids: &["http2/6.10/5"],
            blocks: vec![
                get(vec![("x-dummy0", Dummy)]),
                stray(fields(vec![("x-dummy0", Dummy)])),
            ],
        },
        Case {
            ids: &["http2/6.10/6"],
            blocks: vec![
                post(vec![("x-dummy0", Dummy)]),
                stray(fields(vec![("x-dummy0", Dummy)])),
            ],
        },
        // the HEADERS frame is split after its 5th byte, in the middle of the
        // value of :authority
        Case {
            ids: &["generic/3.10/1", "generic/3.10/2"],
            blocks: vec![fields(vec![
                (":method", Str("GET")),
                (":scheme", Str("http")),
                (":path", Str("/")),
                (":authority", Split(Box::new(Authority))),
            ])],
        },
        // a CONTINUATION frame on a stream that is idle
        Case {
            ids: &["http2/5.1/4"],
            blocks: vec![stray(get(vec![]))],
        },
        // a CONTINUATION frame on a stream whose block has ended
        Case {
            ids: &["http2/5.1/7"],
            blocks: vec![get(vec![]), stray(get(vec![]))],
        },
        Case {
            ids: &["http2/5.1/10", "http2/5.1/13", "http2/6.10/4"],
            blocks: vec![get(vec![]), stray(fields(vec![("x-dummy0", Dummy)]))],
        },
        Case {
            ids: &["http2/8.1/1"],
            blocks: vec![post(vec![]), fields(vec![("x-test", Str("ok"))])],
        },
        Case {
            ids: &["http2/8.1.2/1"],
            blocks: vec![get(vec![("X-TEST", Str("ok"))])],
        },
        Case {
            ids: &["http2/8.1.2.1/1"],
            blocks: vec![get(vec![(":test", Str("ok"))])],
        },
        Case {
            ids: &["http2/8.1.2.1/2"],
            blocks: vec![get(vec![(":status", Str("200"))])],
        },
        Case {
            ids: &["http2/8.1.2.1/3"],
            blocks: vec![post(vec![]), fields(vec![(":method", Str("POST"))])],
        },
        Case {
            ids: &["http2/8.1.2.1/4"],
            blocks: vec![fields(vec![
                ("x-test", Str("ok")),
                (":method", Str("GET")),
                (":scheme", Str("http")),
                (":path", Str("/")),
                (":authority", Authority),
            ])],
        },
        Case {
            ids: &["http2/8.1.2.2/1"],
            blocks: vec![get(vec![("connection", Str("keep-alive"))])],
        },
        Case {
            ids: &["http2/8.1.2.2/2"],
            blocks: vec![get(vec![
                ("trailers", Str("test")),
                ("te", Str("trailers, deflate")),
            ])],
        },
        Case {
            ids: &["http2/8.1.2.3/1"],
            blocks: vec![fields(vec![
                (":method", Str("GET")),
                (":scheme", Str("http")),
                (":path", Str("")),
                (":authority", Authority),
            ])],
        },
        Case {
            ids: &["http2/8.1.2.3/2"],
            blocks: vec![fields(vec![(":path", Str("/")), (":authority", Authority)])],
        },
        Case {
            ids: &["http2/8.1.2.3/3"],
            blocks: vec![fields(vec![
                (":method", Str("GET")),
                (":path", Str("/")),
                (":authority", Authority),
            ])],
        },
        Case {
            ids: &["http2/8.1.2.3/4"],
            blocks: vec![fields(vec![
                (":method", Str("GET")),
                (":scheme", Str("http")),
                (":authority", Authority),
            ])],
        },
        Case {
            ids: &["http2/8.1.2.3/5"],
            blocks: vec![get(vec![(":method", Str("GET"))])],
        },
        Case {
            ids: &["http2/8.1.2.3/6"],
            blocks: vec![get(vec![(":scheme", Str("http"))])],
        },
        Case {
            ids: &["http2/8.1.2.3/7"],
            blocks: vec![get(vec![(":path", Str("/"))])],
        },
        Case {
            ids: &["http2/8.1.2.6/1", "http2/8.1.2.6/2"],
            blocks: vec![post(vec![("content-length", Str("1"))])],
        },
        Case {
            ids: &["hpack/5.2/1"],
            blocks: vec![get(vec![("x-test", Raw(b"\x49\x50\x9f\xff"))])],
        },
        Case {
            ids: &["hpack/5.2/2"],
            blocks: vec![get(vec![("x-test", Raw(b"\x49\x50\x90"))])],
        },
        Case {
            ids: &["hpack/5.2/3"],
            blocks: vec![get(vec![("x-test", Raw(b"\x49\x51\xff\xff\xff\xfa\x7f"))])],
        },
    ]
}
