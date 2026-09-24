#include "beeper/beeper.h"

// The interface a BPF program shares with every HTTP parser beeper attaches to
// it: the type a parser reports its results in, and the macros declaring the
// functions it replaces for all protocol versions. The stubs of a single
// version live in `beeper/http1.h` and `beeper/http2.h`.

#ifndef __BEEPER_HTTP_H__
#define __BEEPER_HTTP_H__

// A single captured header field. If `in_msg` is set, `idx` is the offset of
// the field in the parsed message and `len` its length. Otherwise the field was
// not spelled out on the wire and `idx` is the HPACK index it has to be read
// from the static or the dynamic table with. `huff` says whether the bytes are
// Huffman coded, which HPACK leaves to the sender.
struct http_match {
    u16 idx;
    u16 len;
    bool in_msg;
    bool huff;
};

// The result of parsing a single message, holding one entry per match id the
// parser was configured with. It is what `matched` and `extract_match` read the
// captured ranges out of.
struct http_parse_res {
    struct http_match ms[MAX_MATCHES];
};

// Stubs for the parser programs beeper attaches with `freplace`, see
// `beeper/beeper.h`. The macros for `parse_fn` are declared in the header of the
// protocol version the parser speaks.

// Creates `name`, a stub reporting whether the match at `idx` was found
// (`matched_fn`).
#define BEEPER_MATCHED(name) __BEEPER_MATCHED(name, http_parse_res)

// Creates `name`, a stub reading the match at `idx` out of `msg`
// (`extract_fn`, `MessageBuffer::Msg`).
#define BEEPER_EXTRACT_MATCH_MSG(name) __BEEPER_EXTRACT_MATCH_MSG(name, http_parse_res)

// Creates `name`, a stub reading the match at `idx` out of `skb`
// (`extract_fn`, `MessageBuffer::Skb`).
#define BEEPER_EXTRACT_MATCH_SKB(name) __BEEPER_EXTRACT_MATCH_SKB(name, http_parse_res)

#endif // __BEEPER_HTTP_H__
