#include "vmlinux.h"
#include "beeper.h"
#include "xbpf.h"
#include <bpf/bpf_helpers.h>

// The parser for HTTP/1.x messages. It walks a message byte by byte, following
// the transitions user space injected into `s2ts`, and runs the action of every
// state it enters. The flags below are how those actions are encoded; they are
// read back by the Rust side, which is what assembles the table.

// Parsing is complete, the rest of the message is not a header anymore.
const u16 a_done = 1 << 14;

// The capture identified by the low bits starts at the next byte.
const u16 a_start_capture = 1 << 13;

// The capture identified by the low bits ends at the current byte.
const u16 a_end_capture = 1 << 12;

// Reserved for the HTTP/2 parser, unused here.
const u16 a_h2_read_st = 1 << 11;
const u16 a_h2_read_dt = 1 << 10;

// if a_done -> then this is 0
// if a_start_capture -> then this is the cid
// if a_end_capture -> then this is cid | mid
const u16 a_id_mask = 0x0FFF;
const u16 a_id_1_mask = 0x0FC0;
const u16 a_id_2_mask = 0x003F;

// The state a message is parsed from.
const u16 s_init = 0;

// The state input that matches no pattern leads back to.
const u16 s_any = 1;


#define MAX_STATES 512
#define MAX_TRANS 128

// The transition table of the DFA, indexed by state and input byte. User space
// fills it in before the program is loaded, after which it is read-only.
volatile const struct trans s2ts[MAX_STATES][MAX_TRANS];

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

        u16 old_state = *s;
        u16 a = 0;
        _next(*s, c, s, &a);

        if (*s == s_any) {
            _next(s_any, c, s, &a);
        }

        if ((a & a_start_capture) != 0) {
            u16 cid = a & a_id_mask & MAX_MATCH_MASK;
            bpf_debug("start capture range (%d, ?) in [%d, ...]", cid, i+1);
            cidx[cid] = i + 1;
        }
        if ((a & a_end_capture) != 0) {
            u16 cid = ((a & a_id_1_mask) >> 6) & MAX_MATCH_MASK;
            u16 mid = a & a_id_2_mask & MAX_MATCH_MASK;
            bpf_debug("end capture range (%d, %d) in [%d, %d]", cid, mid, cidx[cid], i - cidx[cid] + 1);

            ms[mid] = (struct hdr_match) {
                .idx = cidx[cid],
                .len = i - cidx[cid] + 1,
                .in_msg = true
            };
        }
        if ((a & a_done) != 0) {
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
