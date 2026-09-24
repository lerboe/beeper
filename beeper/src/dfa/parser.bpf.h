// A parser that walks a message byte by byte, following the transitions user
// space injected into `s2ts`, and runs the action every one of them carries.
//
// It knows no protocol of its own. The parser program of a protocol includes
// it after naming the types the protocol reports its results in:
//
// - `PARSE_RES`, the struct the functions below fill in, e.g. `http_parse_res`
// - `MATCH`, the struct of a single entry of it, e.g. `http_match`
// - `MATCH_EXTRA`, the designated initializers of the fields `MATCH` has on top
//   of `idx` and `len`, followed by a comma. It may be empty.

#ifndef __BEEPER_DFA_PARSER_BPF_H__
#define __BEEPER_DFA_PARSER_BPF_H__

// The state a message is parsed from.
const u16 s_init = 0;

// The state input that matches no pattern leads back to.
const u16 s_any = 1;

// What the parser does upon taking a transition. Must stay in sync with the
// action kinds of dfa/action.rs.

// Nothing.
#define DFAA_NONE 0

// A capture starts at the byte behind the transition: `mid` names the one whose
// start index is to be written down.
#define DFAA_START_CAPTURE 1

// The open capture ends at the byte the transition read: `mid` names the one
// whose start index is to be read back and whose range is reported.
#define DFAA_END_CAPTURE 2

// The byte the transition read is the next decimal digit of a length.
#define DFAA_LEN_DIGIT 3

// The bytes behind the transition are skipped rather than parsed, as many as
// the length read so far says. With `DFAF_CAPTURE`, they are also reported
// under `mid`.
#define DFAA_SKIP 4

// Parsing is complete, the rest of the message is not to be parsed.
#define DFAF_DONE (1 << 0)

// The bytes a `DFAA_SKIP` skips are captured.
#define DFAF_CAPTURE (1 << 1)

// A single action of the DFA.
//
// Actions are kept in a table of their own so that a transition only has to
// name the index of the one it carries, which leaves room for saying more than
// the 16 bits of a transition would hold.
struct dfa_action {
    u8 kind;
    u8 flags;
    u8 mid;
};

// these restrictions are needed to make the verifier happy. `MAX_STATES` and
// `MAX_ACTIONS` are masked onto an index, so both have to be powers of two.
#define MAX_STATES 512
#define MAX_ACTIONS 256
#define MAX_TRANS 257
#define ANY_TRANS 256

// The transition table of the DFA, indexed by state and input byte, and the
// actions its transitions carry. User space fills both in before the program is
// loaded, after which they are read-only.
volatile const struct trans s2ts[MAX_STATES][MAX_TRANS];
volatile const struct dfa_action a2as[MAX_ACTIONS];

// Where a walk over a message stopped, so that it can be resumed.
struct walk {
    // The start index of every open capture.
    u32 cidx[MAX_MATCHES];

    // The state the walk is in.
    u16 s;

    // The length the `DFAA_LEN_DIGIT` transitions read so far.
    u32 len;

    // The number of bytes that are still to be skipped.
    u32 skip;
};

// Reads the action a transition carries. Transition 0 is the one a state
// without a transition for the byte it read falls back to, and carries none.
static __always_inline struct dfa_action _action(u16 id) {
    return a2as[id & (MAX_ACTIONS - 1)];
}

// Follows the transition `input` takes out of `state`. A state that has no
// transition for `input` falls back to the one matching any byte, and if it has
// none either, back to `s_any`.
static __always_inline void _next(u16 state, u8 input, u16 *next_state, u16 *action) {
    state &= MAX_STATES - 1;

    // `input` is a byte and the row holds a column for every one of them, so it
    // needs no bound of its own
    struct trans t = s2ts[state][input];
    if (t.state == 0 && t.action == 0) {
        t = s2ts[state][ANY_TRANS];
        if (t.state == 0 && t.action == 0) {
            *next_state = s_any;
            *action = 0;
            return;
        }
    }

    *next_state = t.state;
    *action = t.action;
}

// Walks the DFA over `data`, starting at offset `start` and where `w` stopped,
// and records the ranges it captures in `ms`.
//
// `null_prefix` is the length of the run of NUL bytes at the beginning of the
// buffer that is to be skipped rather than parsed; it is updated as those bytes
// are consumed. It may be NULL if the data cannot carry such a prefix.
//
// Returns the number of bytes it consumed once the DFA is done, or minus the
// number of bytes it looked at if the data ran out first.
static __always_inline int _parse_from(u8 *data, u8 *data_end, u16 start, struct MATCH *ms, struct walk *w, struct null_prefix *null_prefix) {
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

        if (w->skip > 0) {
            w->skip -= 1;
            continue;
        }

        u16 a = 0;
        _next(w->s, c, &w->s, &a);

        if (w->s == s_any) {
            _next(s_any, c, &w->s, &a);
        }

        struct dfa_action act = _action(a);
        u16 mid = act.mid & MAX_MATCH_MASK;
        if (act.kind == DFAA_START_CAPTURE) {
            bpf_debug("start capture range (%d) in [%d, ...]", mid, i+1);
            w->cidx[mid] = i + 1;
        }
        else if (act.kind == DFAA_END_CAPTURE) {
            bpf_debug("end capture range (%d) in [%d, %d]", mid, w->cidx[mid], i - w->cidx[mid] + 1);

            ms[mid] = (struct MATCH) {
                .idx = w->cidx[mid],
                .len = i - w->cidx[mid] + 1,
                MATCH_EXTRA
            };
        }
        else if (act.kind == DFAA_LEN_DIGIT) {
            // anything but a digit makes for a length that runs past any message
            if (c < '0' || c > '9' || w->len > MAX_BYTES) {
                w->len = MAX_BYTES + 1;
            } else {
                w->len = w->len * 10 + (c - '0');
            }
        }
        else if (act.kind == DFAA_SKIP) {
            bpf_debug("skip %d bytes behind %d", w->len, i);
            w->skip = w->len;
            w->len = 0;

            if ((act.flags & DFAF_CAPTURE) != 0) {
                bpf_debug("capture range (%d) in [%d, %d]", mid, i+1, w->skip);

                ms[mid] = (struct MATCH) {
                    .idx = i + 1,
                    .len = w->skip,
                    MATCH_EXTRA
                };
            }
        }

        if ((act.flags & DFAF_DONE) != 0) {
            bpf_debug("done parsing at %d", i);
            return i+1;
        }
    }

    return -len;
}

// Parses the message and reports what it captured in `pres`. Only the linear
// part of the message is parsed at first; if the DFA is not done by the end of
// it, the whole message is pulled in and parsing resumes where it stopped.
//
// Returns the number of bytes the DFA consumed, or a negative value if the
// message ended before the DFA was done.
SEC("freplace")
int parse_msg(struct sk_msg_md *msg, struct PARSE_RES *pres __arg_nonnull) {
    struct walk w = { .s = s_init };
    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;
    int res = _parse_from(data, data_end, 0, pres->ms, &w, NULL);

    if (res < 0 && msg->size > -res) {
        if (bpf_msg_pull_data(msg, 0, msg->size, 0) < 0) {
            return res;
        }

        u8 *data = (u8 *)(long)msg->data;
        u8 *data_end = (u8 *)(long)msg->data_end;

        res = _parse_from(data, data_end, -res, pres->ms, &w, NULL);
    }

    return res;
}

// Parses the message that starts `off` bytes into the packet. The captured
// ranges are offsets into the sk_buff, the return value is counted from the
// start of the message. See `parse_msg` for the return value.
SEC("freplace")
int parse_skb(struct __sk_buff *skb, u32 off, struct PARSE_RES *pres __arg_nonnull, struct null_prefix *null_prefix) {
    if (off >= MAX_BYTES || off >= skb->len) return 0;

    u8 *data = (u8 *)(long)skb->data;
    u8 *data_end = (u8 *)(long)skb->data_end;
    if (data + skb->len > data_end) {
        if (bpf_skb_pull_data(skb, skb->len) < 0) return -1;

        data = (u8 *)(long)skb->data;
        data_end = (u8 *)(long)skb->data_end;
    }

    struct walk w = { .s = s_init };
    int res = _parse_from(data, data_end, off, pres->ms, &w, null_prefix);

    // `_parse_from` counts from the start of the sk_buff
    return res > 0 ? res - (int)off : res + (int)off;
}

// Returns whether the parser captured a range for the match `idx`.
SEC("freplace")
bool matched(const struct PARSE_RES *pres __arg_nonnull, u8 idx) {
    if (idx >= MAX_MATCHES) return false;

    struct MATCH m = pres->ms[idx & MAX_MATCH_MASK];
    return (m.len > 0);
}

// Points `str` at the range captured for the match `idx`. The range points into
// `msg`, so it is only valid until the program invalidates its data pointers.
//
// Returns 0 on success, -1 if nothing was captured for `idx` or if the range
// lies outside of the part of the message the program can read.
SEC("freplace")
int extract_match_msg(const struct sk_msg_md *msg, const struct PARSE_RES *pres __arg_nonnull, u8 idx, struct bytes* str __arg_nonnull) {
    if (idx >= MAX_MATCHES) return -1;

    struct MATCH m = pres->ms[idx & MAX_MATCH_MASK];
    if (m.len == 0) return -1;

    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;

    if (data + m.idx + m.len > data_end) return -1;

    str->ptr = data + m.idx;
    str->len = m.len;

    return 0;
}

// Same as `extract_match_msg`, for a match taken out of an sk_buff. The range
// points into `skb`, so it is only valid until the program invalidates its data
// pointers.
SEC("freplace")
int extract_match_skb(const struct __sk_buff *skb, const struct PARSE_RES *pres __arg_nonnull, u8 idx, struct bytes* str __arg_nonnull) {
    if (idx >= MAX_MATCHES) return -1;

    struct MATCH m = pres->ms[idx & MAX_MATCH_MASK];
    if (m.len == 0) return -1;

    u8 *data = (u8 *)(long)skb->data;
    u8 *data_end = (u8 *)(long)skb->data_end;

    if (data + m.idx + m.len > data_end) return -1;

    str->ptr = data + m.idx;
    str->len = m.len;

    return 0;
}

#endif // __BEEPER_DFA_PARSER_BPF_H__
