#include "vmlinux.h"
#include "beeper.h"
#include "xbpf.h"
#include <bpf/bpf_helpers.h>

// The parser for HTTP/1.x messages. It walks a message byte by byte, following
// the transitions user space injected into `s2es`, and runs the action every
// one of them carries.

// The row of the state a message is parsed from. User space fills it in with
// the offset it laid that state down at, see `s2es`.
volatile const u16 s_init = 0;

// The row of the state input that matches no pattern leads back to. It is
// compared against on every byte, so user space always lays that state down at
// this offset rather than reporting where it put it, which spares the walk a
// load. Must stay in sync with `ANY_ROW` of h1/parser.rs.
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

// these restrictions are needed to make the verifier happy. `MAX_EDGES` and
// `MAX_ACTIONS` are masked onto an index, so both have to be powers of two.
#define MAX_ACTIONS 256
#define MAX_EDGES 4096

// The column a state matches any byte it has no transition of its own for with.
#define ANY_INPUT 256

// How a transition is packed into the word holding it. Must stay in sync with
// `edge` of h1/parser.rs.
//
// The row the transition leaves is kept alongside it because rows overlap: a
// slot only answers for the row that claims it, and a row is never 0, so a free
// slot answers for none.
#define E_ROW_MASK 0xFFF
#define E_STATE_SHIFT 12
#define E_ACTION_SHIFT 24

// The transition table of the DFA and the actions its transitions carry. User
// space fills both in before the program is loaded, after which they are
// read-only.
//
// A row holds a column for every byte and one for `ANY_INPUT`, but hardly any
// of them are taken, so the rows are laid over each other wherever they leave
// each other's columns free: the transition a state takes on `input` sits at
// `row + input`, where `row` is the offset user space laid that state down at
// and is what a walk carries instead of the id of the state. That leaves a
// table small enough to stay in a cache, which is what a walk over a message
// would otherwise spend most of its time waiting for.
volatile const u32 s2es[MAX_EDGES];
volatile const struct h1_action a2as[MAX_ACTIONS];

// Reads the action a transition carries. Transition 0 is the one a state
// without a transition for the byte it read falls back to, and carries none.
static __always_inline struct h1_action _action(u16 id) {
    return a2as[id & (MAX_ACTIONS - 1)];
}

// Follows the transition `input` takes out of the state laid down at `state`. A
// state that has no transition for `input` falls back to the one matching any
// byte, and if it has none either, back to `s_any`.
static __always_inline void _next(u16 state, u8 input, u16 *next_state, u16 *action) {
    // an index that leaves the table wraps around rather than being turned
    // down, and lands on no slot the row could claim: a slot of a row sits
    // within `ANY_INPUT` of it, and the table is wider than that
    u32 e = s2es[(state + input) & (MAX_EDGES - 1)];
    if ((e & E_ROW_MASK) != state) {
        e = s2es[(state + ANY_INPUT) & (MAX_EDGES - 1)];
        if ((e & E_ROW_MASK) != state) {
            *next_state = s_any;
            *action = 0;
            return;
        }
    }

    *next_state = (e >> E_STATE_SHIFT) & E_ROW_MASK;
    *action = e >> E_ACTION_SHIFT;
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
    u32 len = (u32)(data_end - data);
    bpf_clamp_uminmax(len, 0, MAX_BYTES);

    if (start >= len) {
        return 0;
    }

    // the last index the loop may reach has to stay below `len`: a dynptr
    // slice is a plain memory region, and the verifier bounds a read into it by
    // the index alone rather than by the check below
    u32 i;
    bpf_for(i, start, len) {
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
//
// The slice is taken at `BEEPER_BUF_LEN`, the only length the verifier lets the
// program ask for, so `buf_ptr` has to hold that many bytes no matter how long
// the message in it is. Anything past `len` is ignored.
//
// The work sits in a function of its own because libbpf turns down a call that
// reaches from one program section into another, and `bench` has to call it too.
__noinline __weak int _parse_buf(const struct bpf_dynptr *buf_ptr, u32 len, struct parse_res *pres __arg_nonnull, u16 *null_prefix) {
    u32 cidx[MAX_MATCHES] = { 0 };
    u16 s = s_init;

    u8 *data = bpf_dynptr_data(buf_ptr, 0, BEEPER_BUF_LEN);
    if (data == NULL) return -1;

    bpf_clamp_uminmax(len, 0, BEEPER_BUF_LEN);
    u8 *data_end = data + len;

    int res = _parse_from(data, data_end, 0, pres->ms, cidx, &s, null_prefix);

    return res;
}

SEC("freplace")
int parse_buf(const struct bpf_dynptr *buf_ptr, u32 len, struct parse_res *pres __arg_nonnull, u16 *null_prefix) {
    return _parse_buf(buf_ptr, len, pres, null_prefix);
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

// What the benchmark program is run with: the message, the number of bytes of
// it that are to be parsed, and how often that is to happen. The buffer is
// carried in the context rather than in a map so that a single
// `BPF_PROG_TEST_RUN` says everything about a run.
struct bench_args {
    u32 n;
    u32 len;
    u8 buf[BEEPER_BUF_LEN];
};

// A copy of the message the benchmark program parses. `bpf_dynptr_from_mem`
// only makes a dynptr of a map value, so the message cannot be parsed out of
// the context it arrives in.
struct bench_buf {
    u8 data[BEEPER_BUF_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct bench_buf);
} bench_bufs SEC(".maps");

// Parses `args->buf` `args->n` times over, so that user space can time the
// parser without paying for a syscall per message. Every pass reports into the
// same `parse_res`, which the next one overwrites again.
//
// Returns what the last pass returned, or -1 if the buffer could not be set up.
SEC("syscall")
int bench(struct bench_args *args) {
    u32 key = 0;
    struct bench_buf *buf = bpf_map_lookup_elem(&bench_bufs, &key);
    if (buf == NULL) return -1;

    __builtin_memcpy(buf->data, args->buf, BEEPER_BUF_LEN);

    struct bpf_dynptr ptr;
    if (bpf_dynptr_from_mem(buf->data, BEEPER_BUF_LEN, 0, &ptr) < 0) return -1;

    struct parse_res pres = { 0 };
    u32 len = args->len;
    u32 n = args->n;
    int res = 0;

    u32 i;
    bpf_for(i, 0, n) {
        res = _parse_buf(&ptr, len, &pres, NULL);

        // without this the compiler is free to notice that every pass computes
        // the same thing and to run only one of them
        __sink(res);
    }

    return res;
}
