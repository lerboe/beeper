#include "beeper/beeper.h"

#ifndef __BEEPER_HTTP_H__
#define __BEEPER_HTTP_H__

// Where the bytes of a captured header field are.
enum http_match_source {
    // In the message that was parsed: `idx` is the offset they start at.
    HTTP_SRC_MSG = 0,

    // In an entry of the HPACK static or dynamic table: `idx` addresses it.
    HTTP_SRC_TABLE = 1,

    // In the per-CPU buffer used when a header spans across multiple CONTINUATION frames.
    HTTP_SRC_BUF = 2,
};

// A single captured header field.
struct http_match {
    u16 idx;
    u16 len;
    u8 source;
    bool huff;
};

// The result of parsing a single message.
struct http_parse_res {
    struct http_match ms[MAX_MATCHES];
};

// Declares a stub for the matched function.
#define BEEPER_MATCHED(name)                                                                       \
    __noinline bool name(const struct http_parse_res *pres __arg_nonnull, u8 idx) {                     \
        bool ret = false;                                                                          \
                                                                                                   \
        __sink(pres);                                                                              \
        __sink(idx);                                                                               \
        __sink(ret);                                                                               \
                                                                                                   \
        return ret;                                                                                \
    }

// Declares a stub for the get function for SK_MSG. Once replaced, it returns
// 0, -EINVAL (invalid id), -ENOENT (absent/unavailable capture), or -EFAULT
// (unreadable HTTP/1 range). The stub returns -ENOSYS until replaced.
#define BEEPER_GET_MATCH_MSG(name)                                                             \
    __noinline int name(const struct sk_msg_md *msg, const struct http_parse_res *pres __arg_nonnull,   \
                        u8 idx, struct bytes *str __arg_nonnull) {                                 \
        int ret = -ENOSYS;                                                                         \
                                                                                                   \
        __sink(msg);                                                                               \
        __sink(pres);                                                                              \
        __sink(idx);                                                                               \
        __sink(str);                                                                               \
        __sink(ret);                                                                               \
                                                                                                   \
        return ret;                                                                                \
    }

// Declares a stub for the get function for SK_SKB.
#define BEEPER_GET_MATCH_SKB(name)                                                             \
    __noinline int name(const struct __sk_buff *skb, const struct http_parse_res *pres __arg_nonnull,   \
                        u8 idx, struct bytes *str __arg_nonnull) {                                 \
        int ret = -ENOSYS;                                                                         \
                                                                                                   \
        __sink(skb);                                                                               \
        __sink(pres);                                                                              \
        __sink(idx);                                                                               \
        __sink(str);                                                                               \
        __sink(ret);                                                                               \
                                                                                                   \
        return ret;                                                                                \
    }

#endif // __BEEPER_HTTP_H__
