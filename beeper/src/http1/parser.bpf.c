#include "vmlinux.h"
#include "beeper/http1.h"
#include "xbpf.h"
#include <bpf/bpf_helpers.h>
#include <asm-generic/errno.h>

// The source state the DFA initiates parsing with.
const u16 s_init = 0;

// The fallback state, to which all edges lead to if no input matched.
const u16 s_any = 1;

// The action kinds and flags. User space defines them in http1/action.rs and
// loads them before the program is loaded.
volatile const u8 HTTP1A_START_CAPTURE;
volatile const u8 HTTP1A_END_CAPTURE;
volatile const u8 HTTP1F_DONE;

// A single action of the DFA.
struct http1_action {
    u8 kind;
    u8 flags;
    u8 mid;
};

// Restrictions are needed to make the verifier happy. `MAX_STATES` and
// `MAX_ACTIONS` are masked onto an index, so both have to be powers of two.
#define MAX_STATES 512
#define MAX_ACTIONS 256
#define MAX_EDGES 257
#define ANY_EDGE 256

// The edges of the DFA, indexed by state and input byte, along with their
// actions. User space fills both in before the program is loaded, after
// which they are read-only.
volatile const struct trans states[MAX_STATES][MAX_EDGES];
volatile const struct http1_action actions[MAX_ACTIONS];

// Reads the action an edge carries. Edge 0 leads to the fallback state.
static __always_inline struct http1_action _action(u16 id) {
    return actions[id & (MAX_ACTIONS - 1)];
}

// Follows the edge `input` takes out of `state`. A state that has no
// edge for `input` falls back to the one matching any byte, and if it has
// none either, back to the fallback state.
static __always_inline void _next(u16 state, u8 input, u16 *next_state, u16 *action) {
    state &= MAX_STATES - 1;

    struct trans t = states[state][input];
    if (t.state == 0 && t.action == 0) {
        t = states[state][ANY_EDGE];
        if (t.state == 0 && t.action == 0) {
            *next_state = s_any;
            *action = 0;
            return;
        }
    }

    *next_state = t.state;
    *action = t.action;
}

// Walks the DFA over `data`, starting at offset `start` and in state `*s`, and
// records the ranges it captures in `ms`. `cidx` holds the start index of every
// open capture, `s` the state the walk ended in, so that a caller can resume
// where it stopped.
//
// `null_prefix` is the length of the run of NULL bytes at the beginning of the
// buffer that is to be skipped rather than parsed; it is updated as those bytes
// are consumed. It may be NULL if the data cannot carry such a prefix.
//
// Returns the number of bytes consumed, or its negative if data ran out.
// The public entry points translate this internal offset into errno.
static __always_inline int _parse_from(u8 *data, u8 *data_end, u16 start, struct http_match *ms, u32* cidx, u16* s, struct null_prefix *null_prefix) {
    u32 len = (u32)(data_end - data);
    bpf_clamp_uminmax(len, 0, MAX_BYTES);

    if (start >= len) {
        return 0;
    }

    u32 i;
    bpf_for(i, start, len+1) {
        if (data + i + 1 > data_end) break;
        u8 c = data[i];

        // skb clears the TLS header, but does not remove it
        if (null_prefix && c == '\0' && i == null_prefix->len) {
            null_prefix->len = i + 1;
            continue;
        }

        u16 a = 0;
        _next(*s, c, s, &a);

        if (*s == s_any) {
            _next(s_any, c, s, &a);
        }

        struct http1_action act = _action(a);
        if (act.kind == HTTP1A_START_CAPTURE) {
            u16 mid = act.mid & MAX_MATCH_MASK;
            bpf_debug("start capture range (%d) in [%d, ...]", mid, i+1);
            cidx[mid] = i + 1;
        }
        else if (act.kind == HTTP1A_END_CAPTURE) {
            u16 mid = act.mid & MAX_MATCH_MASK;
            bpf_debug("end capture range (%d) in [%d, %d]", mid, cidx[mid], i - cidx[mid] + 1);

            ms[mid] = (struct http_match) {
                .idx = cidx[mid],
                .len = i - cidx[mid] + 1,
                .source = HTTP_SRC_MSG
            };
        }

        if ((act.flags & HTTP1F_DONE) != 0) {
            bpf_debug("done parsing at %d", i);
            return i+1;
        }
    }

    return -len;
}

// Parses the header block of the message and reports what it captured in
// `pres`. Only the linear part of the message is parsed at first; if the DFA is
// not done by the end of it, the whole message is pulled in and parsing resumes
// where it stopped.
//
// Returns the header length, -EAGAIN if more bytes are needed, -E2BIG if the
// header exceeds MAX_BYTES, or -EFAULT if the message cannot be pulled in.
SEC("freplace")
int parse_msg(struct sk_msg_md *msg, struct http_parse_res *pres __arg_nonnull) {
    u32 cidx[MAX_MATCHES] = { 0 };
    u16 s = s_init;
    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;
    int res = _parse_from(data, data_end, 0, pres->ms, cidx, &s, NULL);

    if (res < 0 && msg->size > -res) {
        if (bpf_msg_pull_data(msg, 0, msg->size, 0) < 0) {
            return -EFAULT;
        }

        u8 *data = (u8 *)(long)msg->data;
        u8 *data_end = (u8 *)(long)msg->data_end;

        res = _parse_from(data, data_end, -res, pres->ms, cidx, &s, NULL);
    }

    if (res > 0) return res;
    return msg->size >= MAX_BYTES ? -E2BIG : -EAGAIN;
}

// Parses the header block of the message that starts `off` bytes into the
// packet. The captured ranges are offsets into the
// sk_buff, the return value is counted from the start of the message. See
// `parse_msg` for the return value.
SEC("freplace")
int parse_skb(struct __sk_buff *skb, u32 off, struct http_parse_res *pres __arg_nonnull, struct null_prefix *null_prefix) {
    if (off >= MAX_BYTES) return -E2BIG;
    if (off > skb->len) return -EINVAL;
    if (off == skb->len) return -EAGAIN;

    u8 *data = (u8 *)(long)skb->data;
    u8 *data_end = (u8 *)(long)skb->data_end;
    if (data + skb->len > data_end) {
        if (bpf_skb_pull_data(skb, skb->len) < 0) return -EFAULT;

        data = (u8 *)(long)skb->data;
        data_end = (u8 *)(long)skb->data_end;
    }

    u32 cidx[MAX_MATCHES] = { 0 };
    u16 s = s_init;
    int res = _parse_from(data, data_end, off, pres->ms, cidx, &s, null_prefix);

    if (res > 0) return res - (int)off;
    return skb->len >= MAX_BYTES ? -E2BIG : -EAGAIN;
}

// Returns whether the parser captured a range for the match `idx`.
SEC("freplace")
bool matched(const struct http_parse_res *pres __arg_nonnull, u8 idx) {
    if (idx >= MAX_MATCHES) return false;

    struct http_match m = pres->ms[idx & MAX_MATCH_MASK];
    return (m.len > 0);
}

// Points `str` at the range captured for the match `idx`. The range points into
// `msg`, so it is only valid until the program invalidates its data pointers.
//
// Returns 0 on success, -EINVAL for an invalid id, -ENOENT for no capture,
// or -EFAULT if the captured range is no longer readable.
SEC("freplace")
int get_match_msg(const struct sk_msg_md *msg, const struct http_parse_res *pres __arg_nonnull, u8 idx, struct bytes* str __arg_nonnull) {
    if (idx >= MAX_MATCHES) return -EINVAL;

    struct http_match m = pres->ms[idx & MAX_MATCH_MASK];
    if (m.len == 0) return -ENOENT;

    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;

    if (data + m.idx + m.len > data_end) return -EFAULT;

    str->ptr = data + m.idx;
    str->len = m.len;

    return 0;
}

// Same as `get_match`, for a match taken out of an sk_buff. The range
// points into `skb`, so it is only valid until the program invalidates its data
// pointers.
SEC("freplace")
int get_match_skb(const struct __sk_buff *skb, const struct http_parse_res *pres __arg_nonnull, u8 idx, struct bytes* str __arg_nonnull) {
    if (idx >= MAX_MATCHES) return -EINVAL;

    struct http_match m = pres->ms[idx & MAX_MATCH_MASK];
    if (m.len == 0) return -ENOENT;

    u8 *data = (u8 *)(long)skb->data;
    u8 *data_end = (u8 *)(long)skb->data_end;

    if (data + m.idx + m.len > data_end) return -EFAULT;

    str->ptr = data + m.idx;
    str->len = m.len;

    return 0;
}
