#include "vmlinux.h"
#include "beeper.h"
#include "xbpf.h"
#include <bpf/bpf_helpers.h>

// The parser for HTTP/1.x messages. It walks a message byte by byte, following
// the transitions user space injected into `s2ts`, and runs the action every
// one of them carries.

// The state a message is parsed from.
const u16 s_init = 0;

// The state input that matches no pattern leads back to.
const u16 s_any = 1;

// What the parser does upon taking a transition. Must stay in sync with the
// action kinds of h1/action.rs.

// Nothing.
#define H1A_NONE 0

// A capture starts at the byte behind the transition: `cid` names the one whose
// start index is to be written down.
#define H1A_START_CAPTURE 1

// The open capture ends at the byte the transition read: `cid` names the one
// whose start index is to be read back, `mid` the match its range is reported
// under.
#define H1A_END_CAPTURE 2

// Parsing is complete, the rest of the message is not a header anymore.
#define H1F_DONE (1 << 0)

// A single action of the DFA.
//
// Actions are kept in a table of their own so that a transition only has to
// name the index of the one it carries, which leaves room for saying more than
// the 16 bits of a transition would hold.
struct h1_action {
    u8 kind;
    u8 flags;
    u8 mid;
};

// these restrictions are needed to make the verifier happy. All three are
// masked onto an index, so all three have to be powers of two.
#define MAX_STATES 512
#define MAX_TRANS 128
#define MAX_ACTIONS 256

// The transition table of the DFA, indexed by state and input byte, and the
// actions its transitions carry. User space fills both in before the program is
// loaded, after which they are read-only.
volatile const struct trans s2ts[MAX_STATES][MAX_TRANS];
volatile const struct h1_action a2as[MAX_ACTIONS];

// Reads the action a transition carries. Transition 0 is the one a state
// without a transition for the byte it read falls back to, and carries none.
static __always_inline struct h1_action _action(u16 id) {
    return a2as[id & (MAX_ACTIONS - 1)];
}

// Follows the transition `input` takes out of `state`. A state that has no
// transition for `input` falls back to the one matching any byte, and if it has
// none either, back to `s_any`.
static __always_inline void _next(u16 state, u8 input, u16 *next_state, u16 *action) {
    state &= MAX_STATES - 1;
    input &= MAX_TRANS - 1;

    struct trans t = s2ts[state][input];
    if (t.state == 0 && t.action == 0) {
        t = s2ts[state]['*'];
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
// `null_prefix` is the length of the run of NUL bytes at the beginning of the
// buffer that is to be skipped rather than parsed; it is updated as those bytes
// are consumed. It may be NULL if the data cannot carry such a prefix.
//
// Returns the number of bytes it consumed once the DFA is done, or minus the
// number of bytes it looked at if the data ran out first.
static __always_inline int _parse_from(u8 *data, u8 *data_end, u16 start, struct hdr_match *ms, u32* cidx, u16* s, u16 *null_prefix) {
    u32 len = (u32)(data_end - data) & MAX_BYTES;

    if (len-start == 0) {
        return 0;
    }

    u32 i;
    bpf_for(i, start, len+1) {
        if (data + i + 1 > data_end) break;
        u8 c = data[i];

        // skb clears the TLS header, but does not remove it
        if (null_prefix && c == '\0' && i == *null_prefix) {
            *null_prefix = i + 1;
            continue;
        }

        u16 a = 0;
        _next(*s, c, s, &a);

        if (*s == s_any) {
            _next(s_any, c, s, &a);
        }

        struct h1_action act = _action(a);
        if (act.kind == H1A_START_CAPTURE) {
            u16 mid = act.mid & MAX_MATCH_MASK;
            bpf_debug("start capture range (%d) in [%d, ...]", mid, i+1);
            cidx[mid] = i + 1;
        }
        else if (act.kind == H1A_END_CAPTURE) {
            u16 mid = act.mid & MAX_MATCH_MASK;
            bpf_debug("end capture range (%d) in [%d, %d]", mid, cidx[mid], i - cidx[mid] + 1);

            ms[mid] = (struct hdr_match) {
                .idx = cidx[mid],
                .len = i - cidx[mid] + 1,
                .in_msg = true
            };
        }

        if ((act.flags & H1F_DONE) != 0) {
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
// Returns the number of bytes the header block occupies, or a negative value if
// the message ended before the header block did.
SEC("freplace")
int parse_msg(struct sk_msg_md *msg, struct parse_res *pres __arg_nonnull) {
    u32 cidx[MAX_MATCHES] = { 0 };
    u16 s = s_init;
    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;
    int res = _parse_from(data, data_end, 0, pres->ms, cidx, &s, NULL);

    if (res < 0 && msg->size > -res) {
        if (bpf_msg_pull_data(msg, 0, msg->size, 0) < 0) {
            return res;
        }

        u8 *data = (u8 *)(long)msg->data;
        u8 *data_end = (u8 *)(long)msg->data_end;

        res = _parse_from(data, data_end, -res, pres->ms, cidx, &s, NULL);
    }

    return res;
}

// Parses the header block of the packet, pulling it in entirely if the linear
// part of the sk_buff is not enough. See `parse_msg` for the return value.
SEC("freplace")
int parse_skb(struct __sk_buff *skb, struct parse_res *pres __arg_nonnull, u16 *null_prefix) {
    u32 cidx[MAX_MATCHES] = { 0 };
    u16 s = s_init;
    u8 *data = (u8 *)(long)skb->data;
    u8 *data_end = (u8 *)(long)skb->data_end;
    int res = _parse_from(data, data_end, 0, pres->ms, cidx, &s, null_prefix);

    if (res < 0 && skb->len > -res) {
        if (bpf_skb_pull_data(skb, skb->len) < 0) {
            return res;
        }

        u8 *data = (u8 *)(long)skb->data;
        u8 *data_end = (u8 *)(long)skb->data_end;

        res = _parse_from(data, data_end, -res, pres->ms, cidx, &s, null_prefix);
    }

    return res;
}

// Parses the header block of the first `len` bytes of `buf_ptr`. Unlike a
// message or a packet, a buffer is contiguous, so there is nothing to pull in
// and a single pass is enough. See `parse_msg` for the return value.
SEC("freplace")
int parse_buf(const struct bpf_dynptr *buf_ptr, u32 len, struct parse_res *pres __arg_nonnull, u16 *null_prefix) {
    u32 cidx[MAX_MATCHES] = { 0 };
    u16 s = s_init;

    u8 *data = bpf_dynptr_data(buf_ptr, 0, len);
    if (data == NULL) return -1;

    u8 *data_end = data + len;

    int res = _parse_from(data, data_end, 0, pres->ms, cidx, &s, null_prefix);

    return res;
}

// Returns whether the parser captured a range for the match `idx`.
SEC("freplace")
bool matched(const struct sk_msg_md *msg, const struct parse_res *pres __arg_nonnull, u8 idx) {
    if (idx >= MAX_MATCHES) return false;

    struct hdr_match m = pres->ms[idx & MAX_MATCH_MASK];
    return (m.len > 0);
}

// Points `str` at the range captured for the match `idx`. The range points into
// `msg`, so it is only valid until the program invalidates its data pointers.
//
// Returns 0 on success, -1 if nothing was captured for `idx` or if the range
// lies outside of the part of the message the program can read.
SEC("freplace")
int extract_match(const struct sk_msg_md *msg, const struct parse_res *pres __arg_nonnull, u8 idx, struct hdr_str* str __arg_nonnull) {
    if (idx >= MAX_MATCHES) return -1;

    struct hdr_match m = pres->ms[idx & MAX_MATCH_MASK];
    if (m.len == 0) return -1;

    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;

    if (data + m.idx + m.len > data_end) return -1;

    str->ptr = data + m.idx;
    str->len = m.len;

    return 0;
}
