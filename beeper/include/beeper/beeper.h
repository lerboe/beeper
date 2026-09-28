#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#ifndef __BEEPER_H__
#define __BEEPER_H__

char LICENSE[] SEC("license") = "GPL";

// The number of bytes a parser walks at most.
#define MAX_BYTES 0x7FFF

// The number of matches a any parser can extract.
#define MAX_MATCHES 32
#define MAX_MATCH_MASK 31

// An IPv4 endpoint. `ip4` is stored in network byte order,
// `port` in host byte order.
struct ip4_addr {
    u32 ip4;
    u32 port;
};

// The pair of endpoints identifying a connection.
struct ip4_conn {
    struct ip4_addr local;
    struct ip4_addr remote;
};

// A borrowed string, pointing either into the parsed message or into a
// data structure internal to the parser. It is only valid for as long
// as the program does not invalidate the pointers of the message it was
// extracted from.
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

// A single edge of the DFA a parser walks: the state it leads to, and the
// action to run upon entering that state.
struct trans {
    u16 state;
    u16 action;
};

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

// Keeps clang from optimising an unused argument of a stub away, so that the
// stub keeps the signature the parser program replacing it expects.
#ifndef __sink
#define __sink(expr) asm volatile("" : "+g"(expr))
#endif

#endif // __BEEPER_H__
