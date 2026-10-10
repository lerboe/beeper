#include "beeper/http.h"

// The HTTP/2 specific part of the interface between a BPF program and the
// parsers beeper attaches to it. See `beeper/http.h` for the type a parser
// reports its results in and the stubs every HTTP parser shares.

#ifndef __BEEPER_HTTP2_H__
#define __BEEPER_HTTP2_H__

// The header of the HTTP/2 frame a parsed message starts with.
struct http2_frame {
    u32 sid;
    u8 type;
    u8 flags;

    // The entries in the connection's dynamic table, before and after decoding
    // this frame.
    u32 dt_count_before;
    u32 dt_count;

    // The length of the frame's payload, as its header announces it.
    u32 len;

    // The number of bytes, counted from the start of the frame, the message
    // has to hold for the parser to get on with it, if it returned `-EAGAIN`.
    // The caller is to wait until they have arrived, e.g. with
    // `bpf_msg_cork_bytes`, and parse the frame again.
    u32 need;
};

// What an HTTP/2 parser returns, negated, for a frame that has not arrived in
// full yet, or for a HEADERS frame whose header block carries on into
// CONTINUATION frames that have not all arrived yet: a block is only read once
// all of it is there, see `need` in `http2_frame`.
#ifndef EAGAIN
#define EAGAIN 11
#endif

// What an HTTP/2 parser returns, negated, for a frame that violates the rules
// for the frames a header block is sent in, see sections 4.3, 5.5, 6.2 and 6.10
// of RFC 9113: a HEADERS or CONTINUATION frame on stream 0, a HEADERS frame
// whose block is broken into by any frame but a CONTINUATION frame of its
// stream, and a CONTINUATION frame that carries on no block. The parser reads
// a block in one go, from its HEADERS frame to the frame that ends it, so a
// CONTINUATION frame it is handed on its own carries on no block. The peer is
// to treat a violation as a connection error, and it is up to the caller to
// remember that the connection is broken: the parser does not parse the frame,
// captures nothing of it, and changes none of its state, so that it reads the
// frames after it as if it had not been sent. Every other frame that cannot be
// parsed is reported as -1.
#ifndef EPROTO
#define EPROTO 71
#endif

// The number of bytes of a name or a value that are kept in a dynamic table
// entry. Longer fields are truncated, which bounds the copies for the
// verifier. Must stay in sync with `HEADER_FIELD_MAXLEN` of http2/parser.bpf.c.
#define BEEPER_HTTP2_FIELD_MAXLEN 128

// A single field of the HPACK static or dynamic table, stored the way it
// appeared on the wire. `key_huff` and `val_huff` say whether that was the
// Huffman coded form; a peer may send either, so a reader that hands an entry
// on has to say which one it is holding.
struct http2_hdr_field {
    u8 key[BEEPER_HTTP2_FIELD_MAXLEN];
    u8 key_len;
    u8 val[BEEPER_HTTP2_FIELD_MAXLEN];
    u8 val_len;
    u8 key_huff;
    u8 val_huff;
};

// Creates `name`, a stub for the HTTP/2 message parser
// (`http2::Parser::parse_fn`, `MessageBuffer::Msg`).
#define BEEPER_HTTP2_PARSE_MSG(name)                                                                  \
    __noinline int name(struct sk_msg_md *msg, struct http_parse_res *pres __arg_nonnull,               \
                        struct http2_frame *frame __arg_nonnull) {                                    \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(msg);                                                                               \
        __sink(pres);                                                                              \
        __sink(frame);                                                                             \
        __sink(ret);                                                                               \
                                                                                                   \
        /* the replacement pulls in the whole message, so the stub has to do */                    \
        /* the same for the verifier to invalidate the caller's data pointers */                   \
        bpf_msg_pull_data(msg, 0, msg->size, 0);                                                   \
                                                                                                   \
        return ret;                                                                                \
    }

// Creates `name`, a stub for the HTTP/2 sk_buff parser
// (`http2::Parser::parse_fn`, `MessageBuffer::Skb`).
#define BEEPER_HTTP2_PARSE_SKB(name)                                                                  \
    __noinline int name(struct __sk_buff *skb, u32 off, struct http_parse_res *pres __arg_nonnull,      \
                        struct http2_frame *frame __arg_nonnull, struct null_prefix *null_prefix) {   \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(skb);                                                                               \
        __sink(off);                                                                               \
        __sink(pres);                                                                              \
        __sink(frame);                                                                             \
        __sink(null_prefix);                                                                       \
        __sink(ret);                                                                               \
                                                                                                   \
        /* the replacement pulls in the whole sk_buff, so the stub has to do */                    \
        /* the same for the verifier to invalidate the caller's data pointers */                   \
        bpf_skb_pull_data(skb, skb->len);                                                          \
                                                                                                   \
        return ret;                                                                                \
    }

// Creates `name`, a stub for the HTTP/2 buffer parser
// (`http2::Parser::parse_fn`, `MessageBuffer::DynPtr`).
#define BEEPER_HTTP2_PARSE_BUF(name)                                                                  \
    __noinline int name(const struct bpf_dynptr *buf_ptr, struct ip4_conn *conn,                   \
                        struct http_parse_res *pres __arg_nonnull,                                      \
                        struct http2_frame *frame __arg_nonnull,                                      \
                        struct null_prefix *null_prefix) {                                         \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(buf_ptr);                                                                           \
        __sink(conn);                                                                              \
        __sink(pres);                                                                              \
        __sink(frame);                                                                             \
        __sink(null_prefix);                                                                       \
        __sink(ret);                                                                               \
                                                                                                   \
        return ret;                                                                                \
    }

// Creates `name`, a stub reading the `idx`th entry of the dynamic table of the
// connection a message parsed with an HTTP/2 parser belongs to
// (`http2::Parser::get_dynamic_table_entry`). `idx` is counted the HPACK way, i.e. 1
// is the most recently added entry and `dt_count` (see `http2_frame`) the oldest
// still live one. Returns 0 on success, -1 if there is no such entry.
#define BEEPER_HTTP2_GET_DT_ENTRY(name)                                                               \
    __noinline int name(const struct ip4_conn *conn __arg_nonnull, u32 idx,                        \
                        struct http2_hdr_field *out __arg_nonnull) {                                  \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(conn);                                                                              \
        __sink(idx);                                                                               \
        __sink(out);                                                                               \
        __sink(ret);                                                                               \
                                                                                                   \
        return ret;                                                                                \
    }

#endif // __BEEPER_HTTP2_H__
