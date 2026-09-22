#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// The interface between a BPF program and the parsers beeper attaches to it:
// the types a parser reports its results in, and the macros declaring the
// functions it replaces.

#ifndef __BEEPER_H__
#define __BEEPER_H__

char LICENSE[] SEC("license") = "GPL";

// these restrictions are needed to make the verifier happy

// The number of bytes a parser walks at most. Bounding the length of a message
// bounds the parsing loop.
#define MAX_BYTES 0x7FFF

// The number of matches a `parse_res` holds, i.e. the number of ranges a parser
// can be configured to capture.
#define MAX_MATCHES 32

// Masks a match id down to a valid index into `parse_res`, so that the verifier
// can see that the access is in bounds.
#define MAX_MATCH_MASK 31

// Clamps VAR into [UMIN, UMAX]. It is written in inline assembly so that clang
// cannot reason the bounds away again, which would leave the verifier without a
// range for VAR.
#ifndef bpf_clamp_uminmax
#define bpf_clamp_uminmax(VAR, UMIN, UMAX)                                                         \
    asm volatile("if %0 >= %[min] goto +2\n"                                                       \
                 "%0 = %[min]\n"                                                                   \
                 "goto +2\n"                                                                       \
                 "if %0 <= %[max] goto +1\n"                                                       \
                 "%0 = %[max]\n"                                                                   \
                 : "+r"(VAR)                                                                       \
                 : [min] "i"(UMIN), [max] "i"(UMAX))
#endif

// An IPv4 endpoint. `ip4` is stored the way the kernel hands it out, in network
// byte order, `port` in host byte order.
struct ip4_addr {
    u32 ip4;
    u32 port;
};

// The pair of endpoints identifying a connection. Beeper keys the state it
// keeps per connection with it, e.g. the dynamic table of an HTTP/2 peer.
struct ip4_conn {
    struct ip4_addr local;
    struct ip4_addr remote;
};

// A single captured header field. If `in_msg` is set, `idx` is the offset of
// the field in the parsed message and `len` its length. Otherwise the field was
// not spelled out on the wire and `idx` is the HPACK index it has to be read
// from the static or the dynamic table with. `huff` says whether the bytes are
// Huffman coded, which HPACK leaves to the sender.
struct hdr_match {
    u16 idx;
    u16 len;
    bool in_msg;
    bool huff;
};

// A borrowed string, pointing either into the parsed message or into one of the
// HPACK tables. It is only valid for as long as the program does not invalidate
// the pointers of the message it was extracted from.
struct hdr_str {
    u32 len;
    const u8* ptr;
};

// The result of parsing a single message, holding one entry per match id the
// parser was configured with. It is what `matched` and `extract_match` read the
// captured ranges out of.
struct parse_res {
    struct hdr_match ms[MAX_MATCHES];
};

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
struct header_field {
    u8 key[BEEPER_H2_FIELD_MAXLEN];
    u8 key_len;
    u8 val[BEEPER_H2_FIELD_MAXLEN];
    u8 val_len;
    u8 key_huff;
    u8 val_huff;
};

/// The number of NULL bytes in front of the HTTP message.
///
/// kTLS will zero out the TLS header, but will not strip it. This struct
/// is used to indicate the length of this prefix. This struct is necessary
/// because freplace only allows struct arguments.
struct null_prefix {
    u16 len;
};

// A single transition of the DFA a parser walks: the state it leads to, and the
// action to run upon entering that state. The action is a bit field, see the
// `a_*` constants of the parser programs for its encoding.
struct trans {
    u16 state;
    u16 action;
};

// Stubs for the parser programs beeper attaches with `freplace`.
//
// A program that uses a beeper parser declares the functions it passes to the
// `parse_fn`, `matched_fn` and `extract_fn` builder methods with these macros. Each one expands to a global
// (`__noinline`) function with the exact signature the corresponding parser
// program expects.

#ifndef __sink
#define __sink(expr) asm volatile("" : "+g"(expr))
#endif

// Creates `name`, a stub for the HTTP/1.x message parser
// (`h1::Parser::parse_fn`, `MessageBuffer::Msg`).
#define BEEPER_H1_PARSE_MSG(name)                                                                  \
    __noinline int name(struct sk_msg_md *msg, struct parse_res *pres __arg_nonnull) {             \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(msg);                                                                               \
        __sink(pres);                                                                              \
        __sink(ret);                                                                               \
                                                                                                   \
        /* the replacement pulls in the whole message, so the stub has to do */                    \
        /* the same for the verifier to invalidate the caller's data pointers */                   \
        bpf_msg_pull_data(msg, 0, msg->size, 0);                                                   \
                                                                                                   \
        return ret;                                                                                \
    }

// Creates `name`, a stub for the HTTP/1.x sk_buff parser
// (`h1::Parser::parse_fn`, `MessageBuffer::Skb`).
#define BEEPER_H1_PARSE_SKB(name)                                                                  \
    __noinline int name(struct __sk_buff *skb, u32 off, struct parse_res *pres __arg_nonnull,      \
                        struct null_prefix *null_prefix) {                                         \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(skb);                                                                               \
        __sink(off);                                                                               \
        __sink(pres);                                                                              \
        __sink(null_prefix);                                                                       \
        __sink(ret);                                                                               \
                                                                                                   \
        /* the replacement pulls in the whole sk_buff, so the stub has to do */                    \
        /* the same for the verifier to invalidate the caller's data pointers */                   \
        bpf_skb_pull_data(skb, skb->len);                                                          \
                                                                                                   \
        return ret;                                                                                \
    }

// Creates `name`, a stub for the HTTP/1.x buffer parser
// (`h1::Parser::parse_fn`, `MessageBuffer::DynPtr`).
#define BEEPER_H1_PARSE_BUF(name)                                                                  \
    __noinline int name(const struct bpf_dynptr *buf_ptr, u32 len,                                 \
                        struct parse_res *pres __arg_nonnull, struct null_prefix *null_prefix) {   \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(buf_ptr);                                                                           \
        __sink(len);                                                                               \
        __sink(pres);                                                                              \
        __sink(null_prefix);                                                                       \
        __sink(ret);                                                                               \
                                                                                                   \
        return ret;                                                                                \
    }

// Creates `name`, a stub for the HTTP/2 message parser
// (`h2::Parser::parse_fn`, `MessageBuffer::Msg`).
#define BEEPER_H2_PARSE_MSG(name)                                                                  \
    __noinline int name(struct sk_msg_md *msg, struct parse_res *pres __arg_nonnull,               \
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
    __noinline int name(struct __sk_buff *skb, u32 off, struct parse_res *pres __arg_nonnull,      \
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
                        struct parse_res *pres __arg_nonnull,                                      \
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

// Creates `name`, a stub reporting whether the match at `idx` was found
// (`matched_fn`).
#define BEEPER_MATCHED(name)                                                                       \
    __noinline bool name(const struct parse_res *pres __arg_nonnull, u8 idx) {                     \
        bool ret = false;                                                                          \
                                                                                                   \
        __sink(pres);                                                                              \
        __sink(idx);                                                                               \
        __sink(ret);                                                                               \
                                                                                                   \
        return ret;                                                                                \
    }

// Creates `name`, a stub reading the match at `idx` out of `msg`
// (`extract_fn`, `MessageBuffer::Msg`).
#define BEEPER_EXTRACT_MATCH_MSG(name)                                                             \
    __noinline int name(const struct sk_msg_md *msg, const struct parse_res *pres __arg_nonnull,   \
                        u8 idx, struct hdr_str *str __arg_nonnull) {                               \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(msg);                                                                               \
        __sink(pres);                                                                              \
        __sink(idx);                                                                               \
        __sink(str);                                                                               \
        __sink(ret);                                                                               \
                                                                                                   \
        return ret;                                                                                \
    }

// Creates `name`, a stub reading the match at `idx` out of `skb`
// (`extract_fn`, `MessageBuffer::Skb`).
#define BEEPER_EXTRACT_MATCH_SKB(name)                                                             \
    __noinline int name(const struct __sk_buff *skb, const struct parse_res *pres __arg_nonnull,   \
                        u8 idx, struct hdr_str *str __arg_nonnull) {                               \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(skb);                                                                               \
        __sink(pres);                                                                              \
        __sink(idx);                                                                               \
        __sink(str);                                                                               \
        __sink(ret);                                                                               \
                                                                                                   \
        return ret;                                                                                \
    }

// Creates `name`, a stub reading the match at `idx` out of the buffer
// `buf_ptr` points at (`h1::Parser::extract_fn`, `MessageBuffer::DynPtr`).
#define BEEPER_H1_EXTRACT_MATCH_BUF(name)                                                          \
    __noinline int name(const struct bpf_dynptr *buf_ptr,                                          \
                        const struct parse_res *pres __arg_nonnull, u8 idx,                        \
                        struct hdr_str *str __arg_nonnull) {                                       \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(buf_ptr);                                                                           \
        __sink(pres);                                                                              \
        __sink(idx);                                                                               \
        __sink(str);                                                                               \
        __sink(ret);                                                                               \
                                                                                                   \
        return ret;                                                                                \
    }

// Creates `name`, a stub reading the match at `idx` out of the buffer
// `buf_ptr` points at (`h2::Parser::extract_fn`, `MessageBuffer::DynPtr`). A
// match the peer only referenced by index is read out of the HPACK tables of
// `conn` instead, which is why the buffer parser takes the connection along.
#define BEEPER_H2_EXTRACT_MATCH_BUF(name)                                                          \
    __noinline int name(const struct bpf_dynptr *buf_ptr,                                          \
                        const struct ip4_conn *conn __arg_nonnull,                                 \
                        const struct parse_res *pres __arg_nonnull, u8 idx,                        \
                        struct hdr_str *str __arg_nonnull) {                                       \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(buf_ptr);                                                                           \
        __sink(conn);                                                                              \
        __sink(pres);                                                                              \
        __sink(idx);                                                                               \
        __sink(str);                                                                               \
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
                        struct header_field *out __arg_nonnull) {                                  \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(conn);                                                                              \
        __sink(idx);                                                                               \
        __sink(out);                                                                               \
        __sink(ret);                                                                               \
                                                                                                   \
        return ret;                                                                                \
    }

#endif // __BEEPER_H__
