#include "beeper/http.h"

// The HTTP/2 specific part of the interface between a BPF program and the
// parsers beeper attaches to it. See `beeper/http.h` for the type a parser
// reports its results in and the stubs every HTTP parser shares.

#ifndef __BEEPER_HTTP2_H__
#define __BEEPER_HTTP2_H__

// The header of the HTTP/2 frame a parsed message starts with.
struct h2_frame {
    u32 sid;
    u8 type;
    u8 flags;

    // The entries in the connection's dynamic table, before and after decoding
    // this frame.
    u32 dt_count_before;
    u32 dt_count;
};

// The number of bytes of a name or a value that are kept in a dynamic table
// entry. Longer fields are truncated, which bounds the copies for the
// verifier. Must stay in sync with `HEADER_FIELD_MAXLEN` of h2/parser.bpf.c.
#define BEEPER_H2_FIELD_MAXLEN 128

// A single field of the HPACK static or dynamic table, stored the way it
// appeared on the wire. `key_huff` and `val_huff` say whether that was the
// Huffman coded form; a peer may send either, so a reader that hands an entry
// on has to say which one it is holding.
struct h2_hdr_field {
    u8 key[BEEPER_H2_FIELD_MAXLEN];
    u8 key_len;
    u8 val[BEEPER_H2_FIELD_MAXLEN];
    u8 val_len;
    u8 key_huff;
    u8 val_huff;
};

// Creates `name`, a stub for the HTTP/2 message parser
// (`h2::Parser::parse_fn`, `MessageBuffer::Msg`).
#define BEEPER_H2_PARSE_MSG(name)                                                                  \
    __noinline int name(struct sk_msg_md *msg, struct http_parse_res *pres __arg_nonnull,               \
                        struct h2_frame *frame __arg_nonnull) {                                    \
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
// (`h2::Parser::parse_fn`, `MessageBuffer::Skb`).
#define BEEPER_H2_PARSE_SKB(name)                                                                  \
    __noinline int name(struct __sk_buff *skb, u32 off, struct http_parse_res *pres __arg_nonnull,      \
                        struct h2_frame *frame __arg_nonnull, struct null_prefix *null_prefix) {   \
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
// (`h2::Parser::parse_fn`, `MessageBuffer::DynPtr`).
#define BEEPER_H2_PARSE_BUF(name)                                                                  \
    __noinline int name(const struct bpf_dynptr *buf_ptr, struct ip4_conn *conn,                   \
                        struct http_parse_res *pres __arg_nonnull,                                      \
                        struct h2_frame *frame __arg_nonnull,                                      \
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
// (`h2::Parser::get_dynamic_table_entry`). `idx` is counted the HPACK way, i.e. 1
// is the most recently added entry and `dt_count` (see `h2_frame`) the oldest
// still live one. Returns 0 on success, -1 if there is no such entry.
#define BEEPER_H2_GET_DT_ENTRY(name)                                                               \
    __noinline int name(const struct ip4_conn *conn __arg_nonnull, u32 idx,                        \
                        struct h2_hdr_field *out __arg_nonnull) {                                  \
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
