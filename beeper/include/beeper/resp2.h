#include "beeper/beeper.h"

// The RESP2 specific part of the interface between a BPF program and the
// parsers beeper attaches to it.

#ifndef __BEEPER_RESP2_H__
#define __BEEPER_RESP2_H__

// A single captured header field. If `in_msg` is set, `idx` is the offset of
// the field in the parsed message and `len` its length. Otherwise the field was
// not spelled out on the wire and `idx` is the HPACK index it has to be read
// from the static or the dynamic table with. `huff` says whether the bytes are
// Huffman coded, which HPACK leaves to the sender.
struct resp_match {
    u16 idx;
    u16 len;
    bool in_msg;
};

// The result of parsing a single message, holding one entry per match id the
// parser was configured with. It is what `matched` and `extract_match` read the
// captured ranges out of.
struct resp2_parse_res {
    struct resp_match ms[MAX_MATCHES];
};

// Creates `name`, a stub for the RESP2 message parser
// (`resp2::Parser::parse_fn`, `MessageBuffer::Msg`).
#define BEEPER_RESP2_PARSE_MSG(name)                                                               \
    __noinline int name(struct sk_msg_md *msg, struct http_parse_res *pres __arg_nonnull) {             \
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

// Creates `name`, a stub for the RESP2 sk_buff parser
// (`resp2::Parser::parse_fn`, `MessageBuffer::Skb`).
#define BEEPER_RESP2_PARSE_SKB(name)                                                               \
    __noinline int name(struct __sk_buff *skb, u32 off, struct http_parse_res *pres __arg_nonnull,      \
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

// Creates `name`, a stub for the RESP2 buffer parser
// (`resp2::Parser::parse_fn`, `MessageBuffer::DynPtr`).
#define BEEPER_RESP2_PARSE_BUF(name)                                                               \
    __noinline int name(const struct bpf_dynptr *buf_ptr, u32 len,                                 \
                        struct http_parse_res *pres __arg_nonnull, struct null_prefix *null_prefix) {   \
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

#endif // __BEEPER_RESP2_H__
