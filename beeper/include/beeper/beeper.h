#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <asm-generic/errno.h>

#ifndef __BEEPER_H__
#define __BEEPER_H__

char LICENSE[] SEC("license") = "GPL";

// The number of bytes a parser walks at most.
#define MAX_BYTES 0x7FFF

// The number of matches a any parser can get.
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
// geted from.
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

extern void *bpf_dynptr_slice(const struct bpf_dynptr *p, u32 offset, void *buffer__opt, u32 buffer__szk) __ksym;

// The number of bytes `bpf_dynptr_for_each` reads with one slice.
#define BPF_DYNPTR_SLICE_LEN 128

// Runs the statements that follow `at` once for every byte of the dynptr `dp`
// in [FROM, TO), with `c` the byte and `at` its offset. `tmp` is the
// `BPF_DYNPTR_SLICE_LEN` bytes a slice is copied to if the dynptr cannot hand
// out its bytes directly; the caller declares it to keep the stack small.
//
// A slice is as long as the verifier is told at load time, so the bytes are
// read in slices of `BPF_DYNPTR_SLICE_LEN`, or of the largest power of two up
// to TO if the dynptr is shorter than that. The last slice is moved back to
// end at TO, and the bytes it shares with the one before are skipped.
//
// Returns -EFAULT from the calling function if a slice cannot be read.
#define bpf_dynptr_for_each(dp, tmp, FROM, TO, c, at, ...)                                         \
    do {                                                                                           \
        u32 __to = (TO);                                                                           \
        if (__to >= BPF_DYNPTR_SLICE_LEN) __bpf_dynptr_for_each(BPF_DYNPTR_SLICE_LEN, dp, tmp, FROM, __to, c, at, __VA_ARGS__);\
        else if (__to >= 64) __bpf_dynptr_for_each(64, dp, tmp, FROM, __to, c, at, __VA_ARGS__);   \
        else if (__to >= 32) __bpf_dynptr_for_each(32, dp, tmp, FROM, __to, c, at, __VA_ARGS__);   \
        else if (__to >= 16) __bpf_dynptr_for_each(16, dp, tmp, FROM, __to, c, at, __VA_ARGS__);   \
        else if (__to >= 8) __bpf_dynptr_for_each(8, dp, tmp, FROM, __to, c, at, __VA_ARGS__);     \
        else if (__to >= 4) __bpf_dynptr_for_each(4, dp, tmp, FROM, __to, c, at, __VA_ARGS__);     \
        else if (__to >= 2) __bpf_dynptr_for_each(2, dp, tmp, FROM, __to, c, at, __VA_ARGS__);     \
        else if (__to >= 1) __bpf_dynptr_for_each(1, dp, tmp, FROM, __to, c, at, __VA_ARGS__);     \
    } while (0)

// One window length of `bpf_dynptr_for_each`.
#define __bpf_dynptr_for_each(LEN, dp, tmp, FROM, TO, c, at, ...)                                  \
    do {                                                                                           \
        u32 __o = (FROM);                                                                          \
        u32 __k = 0;                                                                               \
        bpf_for(__k, 0, (TO) / (LEN) + 2) {                                                        \
            if (__o >= (TO)) break;                                                                \
                                                                                                   \
            u32 __start = (__o + (LEN) > (TO)) ? (TO) - (LEN) : __o;                               \
            u8 *__p = bpf_dynptr_slice((dp), __start, (tmp), (LEN));                               \
            if (__p == NULL) return -EFAULT;                                                       \
                                                                                                   \
            u32 __j = 0;                                                                           \
            bpf_for(__j, __o - __start, (LEN)) {                                                   \
                u8 c = __p[__j];                                                                   \
                u32 at = __start + __j;                                                            \
                __VA_ARGS__                                                                        \
            }                                                                                      \
                                                                                                   \
            __o = __start + (LEN);                                                                 \
        }                                                                                          \
    } while (0)

#endif // __BEEPER_H__
