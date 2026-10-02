#include "beeper/beeper.h"

#ifndef __BEEPER_HTTP_H__
#define __BEEPER_HTTP_H__

// A single captured header field.
struct http_match {
    u16 idx;
    u16 len;
    bool in_msg;
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

    // Declares a stub for the extract function for SK_MSG.
#define BEEPER_EXTRACT_MATCH_MSG(name)                                                             \
    __noinline int name(const struct sk_msg_md *msg, const struct http_parse_res *pres __arg_nonnull,   \
                        u8 idx, struct bytes *str __arg_nonnull) {                                 \
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

// Declares a stub for the extract function for SK_SKB.
#define BEEPER_EXTRACT_MATCH_SKB(name)                                                             \
    __noinline int name(const struct __sk_buff *skb, const struct http_parse_res *pres __arg_nonnull,   \
                        u8 idx, struct bytes *str __arg_nonnull) {                                 \
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

#endif // __BEEPER_HTTP_H__
