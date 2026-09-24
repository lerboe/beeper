#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// The protocol agnostic core of the interface between a BPF program and the
// parsers beeper attaches to it: the verifier bounds every parser is built
// with, the types that carry no protocol of their own and the stubs of the
// functions a parser replaces. What every HTTP parser shares lives in
// `beeper/http.h`, what a single version adds in `beeper/http1.h` and
// `beeper/http2.h`. RESP2 lives in `beeper/resp2.h`.

#ifndef __BEEPER_H__
#define __BEEPER_H__

char LICENSE[] SEC("license") = "GPL";

// these restrictions are needed to make the verifier happy

// The number of bytes a parser walks at most. Bounding the length of a message
// bounds the parsing loop.
#define MAX_BYTES 0x7FFF

// The number of matches a `http_parse_res` holds, i.e. the number of ranges a parser
// can be configured to capture.
#define MAX_MATCHES 32

// Masks a match id down to a valid index into `http_parse_res`, so that the verifier
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

// A borrowed string, pointing either into the parsed message or into one of the
// HPACK tables. It is only valid for as long as the program does not invalidate
// the pointers of the message it was extracted from.
struct bytes {
    u32 len;
    const u8* ptr;
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

// Keeps clang from optimising an unused argument of a stub away, so that the
// stub keeps the signature the parser program replacing it expects.
#ifndef __sink
#define __sink(expr) asm volatile("" : "+g"(expr))
#endif

// Stubs for the parser programs beeper attaches with `freplace`, generic over
// the struct `res` a parser reports its results in.
//
// The header of every protocol turns them into the `BEEPER_*` macros a program
// declares the functions it hands to a parser with. Each one expands to a
// global (`__noinline`) function with the exact signature the corresponding
// parser program expects, which includes the name of `res`.

// Creates `name`, a stub reporting whether the match at `idx` was found
// (`matched_fn`).
#define __BEEPER_MATCHED(name, res)                                                                \
    __noinline bool name(const struct res *pres __arg_nonnull, u8 idx) {                          \
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
#define __BEEPER_EXTRACT_MATCH_MSG(name, res)                                                      \
    __noinline int name(const struct sk_msg_md *msg, const struct res *pres __arg_nonnull,        \
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

// Creates `name`, a stub reading the match at `idx` out of `skb`
// (`extract_fn`, `MessageBuffer::Skb`).
#define __BEEPER_EXTRACT_MATCH_SKB(name, res)                                                      \
    __noinline int name(const struct __sk_buff *skb, const struct res *pres __arg_nonnull,        \
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

// Creates `name`, a stub for a DFA parser of messages
// (`parse_fn`, `MessageBuffer::Msg`).
#define __BEEPER_PARSE_MSG(name, res)                                                              \
    __noinline int name(struct sk_msg_md *msg, struct res *pres __arg_nonnull) {                  \
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

// Creates `name`, a stub for a DFA parser of sk_buffs
// (`parse_fn`, `MessageBuffer::Skb`).
#define __BEEPER_PARSE_SKB(name, res)                                                              \
    __noinline int name(struct __sk_buff *skb, u32 off, struct res *pres __arg_nonnull,           \
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

#endif // __BEEPER_H__
