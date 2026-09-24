#include "beeper/http.h"

// The HTTP/1.x specific part of the interface between a BPF program and the
// parsers beeper attaches to it. See `beeper/http.h` for the type a parser
// reports its results in and the stubs every HTTP parser shares.

#ifndef __BEEPER_HTTP1_H__
#define __BEEPER_HTTP1_H__

// Creates `name`, a stub for the HTTP/1.x message parser
// (`http1::Parser::parse_fn`, `MessageBuffer::Msg`).
#define BEEPER_HTTP1_PARSE_MSG(name) __BEEPER_PARSE_MSG(name, http_parse_res)

// Creates `name`, a stub for the HTTP/1.x sk_buff parser
// (`http1::Parser::parse_fn`, `MessageBuffer::Skb`).
#define BEEPER_HTTP1_PARSE_SKB(name) __BEEPER_PARSE_SKB(name, http_parse_res)

// Creates `name`, a stub for the HTTP/1.x buffer parser
// (`http1::Parser::parse_fn`, `MessageBuffer::DynPtr`).
#define BEEPER_HTTP1_PARSE_BUF(name)                                                                  \
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

#endif // __BEEPER_HTTP1_H__
