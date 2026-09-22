#include "beeper/http1.h"
#include "beeper/http2.h"
#include "xbpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// Monitors every request the server receives and every response it sends,
// logging the traffic without altering it. A connection is parsed as
// HTTP/1.1 until it upgrades to HTTP/2. HTTP/2 header fields are Huffman
// coded, so only the frame itself is logged for that protocol, not its
// headers.

// Connections that carried an HTTP/2 preface and are parsed as HTTP/2 from
// then on.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct ip4_conn);
    __type(value, int);
} upgraded_conns SEC(".maps");

// Both ends of every connection to the server, i.e. the sockets `msg_verdict`
// runs on.
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 16384);
    __type(key, struct ip4_conn);
    __type(value, int);
} sock_map SEC(".maps");

// The address of the server being monitored, set by user space before the
// program is loaded.
volatile const u32 ip4;
volatile const u32 port;

// The matches the h1 parser is configured with, set by user space before the
// program is loaded, from the ids the parser handed back for them.
volatile const u8 h1_preface_mid;
volatile const u8 h1_path_mid;
volatile const u8 h1_accept_language_mid;
volatile const u8 h1_status_mid;

// The frame type carrying a message's body, see section 6.1 of RFC 9113.
#define H2_DATA_FRAME 0x00

// The functions beeper replaces with an HTTP/1.1 parser.
BEEPER_MATCHED(matched_h1)
BEEPER_EXTRACT_MATCH_MSG(extract_h1_match)
BEEPER_H1_PARSE_MSG(parse_h1)

// The function beeper replaces with an HTTP/2 parser. Its header fields are
// not captured, so there is no extract stub to replace.
BEEPER_H2_PARSE_MSG(parse_h2)

// The size of the buffer a value is copied into before it is logged.
#define FIELD_MAXLEN 128

// The buffers a message's fields are copied into before being logged. This
// lives in a per-CPU map rather than on the stack: `msg_verdict` inlines
// every helper below into a single stack frame together with beeper's own
// parsing state, and a pair of 128 byte buffers on top of that overflows the
// 512 byte limit the verifier allows it.
struct log_scratch {
    char a[FIELD_MAXLEN];
    char b[FIELD_MAXLEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct log_scratch);
} log_scratch_map SEC(".maps");

// Copies up to `FIELD_MAXLEN - 1` bytes starting at `ptr` into `buf` and NUL
// terminates it, so that it can be logged with `%s` without running into
// whatever data follows it in memory.
static __always_inline void copy_bounded(const void *ptr, u32 len, char buf[FIELD_MAXLEN]) {
    bpf_clamp_uminmax(len, 0, FIELD_MAXLEN - 1);
    bpf_probe_read_kernel(buf, len, ptr);
    buf[len] = 0;
}

// Logs an HTTP/1.1 request: its path and its Accept-Language header, if it
// sent one.
static __always_inline void log_h1_request(struct sk_msg_md *msg, struct parse_res *pres) {
    u32 zero = 0;
    struct log_scratch *scratch = bpf_map_lookup_elem(&log_scratch_map, &zero);
    if (!scratch) return;

    struct bytes path = { 0 };
    if (extract_h1_match(msg, pres, h1_path_mid, &path) < 0) return;
    copy_bounded(path.ptr, path.len, scratch->a);

    struct bytes lang = { 0 };
    if (extract_h1_match(msg, pres, h1_accept_language_mid, &lang) == 0) {
        copy_bounded(lang.ptr, lang.len, scratch->b);
        bpf_debug("--> %s accept-language: %s", scratch->a, scratch->b);
    } else {
        bpf_debug("--> %s", scratch->a);
    }
}

// Logs an HTTP/1.1 response: its status and its body, which sits right behind
// the header block `hdr_len` bytes into the message.
static __always_inline void log_h1_response(struct sk_msg_md *msg, struct parse_res *pres, int hdr_len) {
    u32 zero = 0;
    struct log_scratch *scratch = bpf_map_lookup_elem(&log_scratch_map, &zero);
    if (!scratch) return;

    struct bytes status = { 0 };
    if (extract_h1_match(msg, pres, h1_status_mid, &status) < 0) return;
    copy_bounded(status.ptr, status.len, scratch->a);

    copy_bounded((u8 *)(long)msg->data + hdr_len, msg->size - hdr_len, scratch->b);

    bpf_debug("<-- %s body: %s", scratch->a, scratch->b);
}

// Logs an HTTP/2 frame. Its header fields are Huffman coded, so only its type
// and stream are logged, except for a DATA frame, whose body is plain text.
static __always_inline void log_h2_frame(struct sk_msg_md *msg, struct h2_frame *frame, int frame_len, bool is_downstream) {
    const char *arrow = is_downstream ? "-->" : "<--";

    if (frame->type == H2_DATA_FRAME) {
        u32 zero = 0;
        struct log_scratch *scratch = bpf_map_lookup_elem(&log_scratch_map, &zero);
        if (!scratch) return;

        copy_bounded((u8 *)(long)msg->data + 9, frame_len - 9, scratch->a);

        bpf_debug("%s [h2 stream %u] body: %s", arrow, frame->sid, scratch->a);
    } else {
        bpf_debug("%s [h2 stream %u] frame type %u", arrow, frame->sid, frame->type);
    }
}

// Parses the message the connection carries and logs it, in whichever
// direction it travels.
SEC("sk_msg")
int msg_verdict(struct sk_msg_md *msg) {
    // socket identifier of the ingress connection
    struct ip4_conn ikey = {
        .local = {
            .ip4 = msg->local_ip4,
            .port = msg->local_port
        },
        .remote = {
            .ip4 = msg->remote_ip4,
            .port = bpf_ntohl(msg->remote_port)
        }
    };

    bool is_downstream = (ikey.remote.ip4 == ip4 && ikey.remote.port == port);
    bpf_debug("Processing %dB msg from [%pI4:%u->%pI4:%u] (downstream: %d)", msg->size, &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, is_downstream);

    bool is_h2 = (bpf_map_lookup_elem(&upgraded_conns, &ikey) != NULL);
    int msg_len;
    struct parse_res pres = { 0 };

    if (is_h2) {
        struct h2_frame frame = { 0 };
        msg_len = parse_h2(msg, &pres, &frame);
        if (msg_len < 0) {
            bpf_error("Failed to parse h2 message");
            return SK_PASS;
        }

        log_h2_frame(msg, &frame, msg_len, is_downstream);
    }
    else {
        msg_len = parse_h1(msg, &pres);
        if (msg_len < 0) {
            return SK_PASS;
        }

        if (matched_h1(&pres, h1_preface_mid)) {
            bpf_trace("Upgrading connection to HTTP/2");

            // the preface only ever arrives on the client's own socket, but
            // the server's accepted socket sees the same connection under the
            // opposite key, local and remote swapped, so both are marked
            int val = 1;
            bpf_map_update_elem(&upgraded_conns, &ikey, &val, BPF_ANY);

            struct ip4_conn rkey = { .local = ikey.remote, .remote = ikey.local };
            bpf_map_update_elem(&upgraded_conns, &rkey, &val, BPF_ANY);

            // the H2 preface is 24 bytes long
            bpf_msg_apply_bytes(msg, 24);
            return SK_PASS;
        }

        if (is_downstream) {
            log_h1_request(msg, &pres);
        } else {
            log_h1_response(msg, &pres, msg_len);
        }
    }

    bpf_debug("Apply verdict to %d/%dB", msg_len, msg->size);
    bpf_msg_apply_bytes(msg, msg_len);

    return SK_PASS;
}

// Adds both ends of every connection to the server to `sock_map`, so that
// `msg_verdict` sees the messages travelling on them. On localhost, where
// client and server share a network namespace, this catches both the
// requests a client sends and the responses the server sends back.
SEC("sockops")
int monitor_sockets(struct bpf_sock_ops *ops) {
    if (ops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB || ops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        // we don't want to get called anymore for this connection
        bpf_sock_ops_cb_flags_set(ops, 0);

        struct ip4_conn skey = {
            .local = {
                .ip4 = ops->local_ip4,
                .port = ops->local_port
            },
            .remote = {
                .ip4 = ops->remote_ip4,
                .port = bpf_ntohl(ops->remote_port)
            }
        };

        bpf_debug("Established socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);

        // the client socket carries the requests, the accepted one the responses
        bool is_client = (skey.remote.ip4 == ip4 && skey.remote.port == port);
        bool is_server = (skey.local.ip4 == ip4 && skey.local.port == port);

        if (is_client || is_server) {
            if (bpf_sock_hash_update(ops, &sock_map, &skey, BPF_ANY) < 0) {
                bpf_error("Failed to add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
                return SK_PASS;
            }

            bpf_debug("Add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
        }
    }

    return SK_PASS;
}
