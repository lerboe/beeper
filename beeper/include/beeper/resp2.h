#include "beeper/beeper.h"

// The RESP2 specific part of the interface between a BPF program and the
// parsers beeper attaches to it: the type a parser reports its results in and
// the stubs of the functions it replaces.

#ifndef __BEEPER_RESP2_H__
#define __BEEPER_RESP2_H__

// A single captured argument: `idx` is its offset in the parsed message and
// `len` its length.
struct resp2_match {
    u16 idx;
    u16 len;
};

// The result of parsing a single message, holding one entry per match id the
// parser was configured with. It is what `matched` and `extract_match` read the
// captured ranges out of.
struct resp2_parse_res {
    struct resp2_match ms[MAX_MATCHES];
};

// Creates `name`, a stub reporting whether the match at `idx` was found
// (`resp2::Parser::matched_fn`).
#define BEEPER_RESP2_MATCHED(name) __BEEPER_MATCHED(name, resp2_parse_res)

// Creates `name`, a stub reading the match at `idx` out of `msg`
// (`resp2::Parser::extract_fn`, `MessageBuffer::Msg`).
#define BEEPER_RESP2_EXTRACT_MATCH_MSG(name) __BEEPER_EXTRACT_MATCH_MSG(name, resp2_parse_res)

// Creates `name`, a stub reading the match at `idx` out of `skb`
// (`resp2::Parser::extract_fn`, `MessageBuffer::Skb`).
#define BEEPER_RESP2_EXTRACT_MATCH_SKB(name) __BEEPER_EXTRACT_MATCH_SKB(name, resp2_parse_res)

// Creates `name`, a stub for the RESP2 message parser
// (`resp2::Parser::parse_fn`, `MessageBuffer::Msg`).
#define BEEPER_RESP2_PARSE_MSG(name) __BEEPER_PARSE_MSG(name, resp2_parse_res)

// Creates `name`, a stub for the RESP2 sk_buff parser
// (`resp2::Parser::parse_fn`, `MessageBuffer::Skb`).
#define BEEPER_RESP2_PARSE_SKB(name) __BEEPER_PARSE_SKB(name, resp2_parse_res)

#endif // __BEEPER_RESP2_H__
