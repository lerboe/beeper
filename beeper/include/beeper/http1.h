#include "beeper/http.h"

#ifndef __BEEPER_HTTP1_H__
#define __BEEPER_HTTP1_H__

// Declares a stub for the parse function for SK_MSG.
#define BEEPER_HTTP1_PARSE_MSG(name)                                                               \
    __noinline int name(struct sk_msg_md *msg, struct http_parse_res *pres __arg_nonnull) {        \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(msg);                                                                               \
        __sink(pres);                                                                              \
        __sink(ret);                                                                               \
                                                                                                   \
        bpf_msg_pull_data(msg, 0, msg->size, 0);                                                   \
                                                                                                   \
        return ret;                                                                                \
    }

// Declares a stub for the parse function for SK_SKB.
#define BEEPER_HTTP1_PARSE_SKB(name)                                                               \
    __noinline int name(struct __sk_buff *skb, u32 off, struct http_parse_res *pres __arg_nonnull, \
                        struct null_prefix *null_prefix) {                                         \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(skb);                                                                               \
        __sink(off);                                                                               \
        __sink(pres);                                                                              \
        __sink(null_prefix);                                                                       \
        __sink(ret);                                                                               \
                                                                                                   \
        bpf_skb_pull_data(skb, skb->len);                                                          \
                                                                                                   \
        return ret;                                                                                \
    }

// Declares a stub for the parse function for DYN_PTR.
#define BEEPER_HTTP1_PARSE_BUF(name)                                                               \
    __noinline int name(const struct bpf_dynptr *buf_ptr, u32 len,                                 \
                        struct http_parse_res *pres __arg_nonnull,                                 \
                        struct null_prefix *null_prefix) {                                         \
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
