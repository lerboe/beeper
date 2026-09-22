#include "beeper/http.h"

// The HTTP/1.x specific part of the interface between a BPF program and the
// parsers beeper attaches to it. See `beeper/http.h` for the type a parser
// reports its results in and the stubs every HTTP parser shares.

#ifndef __BEEPER_HTTP1_H__
#define __BEEPER_HTTP1_H__

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

#endif // __BEEPER_HTTP1_H__
