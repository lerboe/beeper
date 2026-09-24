#include "beeper/http1.h"
#include "beeper/http2.h"
#include "xbpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

// The program the integration tests attach a parser to. It parses every message
// travelling in the direction under test and stores what the parser captured in
// `matches`, where the test can read it back from user space.

// The connections that carried an HTTP/2 preface and are parsed as HTTP/2 from
// then on.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct ip4_conn);
    __type(value, int);
} upgraded_conns SEC(".maps");
u32 num_upgraded_conns = 0;

// The sockets of the server under test, i.e. the ones `msg_verdict` runs on.
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 16384);
    __type(key, struct ip4_conn);
    __type(value, int);
} sock_map SEC(".maps");

// The address of the server under test, set by user space before the program is
// loaded.
volatile const u32 ip4;
volatile const u32 port;

// parse the responses the server sends instead of the requests it receives
volatile const bool http_parse_resp;

// the parsers run at the `sk_skb` hook rather than at `sk_msg`
volatile const bool hook_skb;

// What the parser captured in the message parsed last, keyed by match id. An id
// with nothing captured for it is absent from the map.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, u32);
    __type(value, char[128]);
} matches SEC(".maps");

// The functions beeper replaces with a parser when a test attaches one.
BEEPER_MATCHED(matched_http1)
BEEPER_EXTRACT_MATCH_MSG(extract_http1_match_msg)
BEEPER_HTTP1_PARSE_MSG(parse_http1_msg)

BEEPER_MATCHED(matched_http2)
BEEPER_EXTRACT_MATCH_MSG(extract_http2_match_msg)
BEEPER_HTTP2_PARSE_MSG(parse_http2_msg)

BEEPER_EXTRACT_MATCH_SKB(extract_http1_match_skb)
BEEPER_HTTP1_PARSE_SKB(parse_http1_skb)

BEEPER_EXTRACT_MATCH_SKB(extract_http2_match_skb)
BEEPER_HTTP2_PARSE_SKB(parse_http2_skb)

extern void *bpf_cast_to_kern_ctx(void *obj) __ksym;

// Returns where the message a stream parser cut out of `skb` starts. The kernel
// hands `sk_skb/stream_parser` and `sk_skb/stream_verdict` programs the whole
// sk_buff the message was found in, which may carry the tail of the message
// before it, and only records the offset in the control block. It is what the
// `off` argument of the sk_buff parsers takes.
static __always_inline u32 strp_offset(struct __sk_buff *skb) {
    struct sk_buff *kskb = bpf_cast_to_kern_ctx(skb);
    struct sk_skb_cb *cb = (struct sk_skb_cb *)kskb->cb;

    return BPF_CORE_READ(cb, strp.strp.offset);
}

// The dynamic table counts of the last HTTP/2 frame that was parsed.
u32 last_dt_count_before = 0;
u32 last_dt_count = 0;

// The match ids the parser reported a capture for in the last message that was
// parsed, one bit per id.
u32 last_matches = 0;

// Records which of the 32 match ids the parser captured a value for.
static __always_inline void store_matched(const struct http_parse_res *pres, bool is_h2) {
    u32 mask = 0;
    u32 i = 0;
    bpf_for(i, 0, 32) {
        bool matched = is_h2 ? matched_http2(pres, i) : matched_http1(pres, i);
        if (matched) mask |= (u32)1 << i;
    }

    last_matches = mask;
}

// Stores the value `extract` found for the match `i` in `matches`, or clears
// the match if there is none.
static __always_inline void store_match(u32 i, int res, const struct bytes *str) {
    if (res != 0) {
        bpf_map_delete_elem(&matches, &i);
        return;
    }

    u16 len = str->len;
    if (len > 128) len = 128;

    char tmp[128] = {0};
    bpf_probe_read_kernel(tmp, len, str->ptr);
    bpf_map_update_elem(&matches, &i, tmp, BPF_ANY);
}

// Parses the messages of the connection under test and records the captured
// ranges in `matches`. A message that carries the HTTP/2 preface upgrades its
// connection, after which its messages are parsed as HTTP/2.
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
    bpf_trace("Processing %dB msg from [%pI4:%u->%pI4:%u] (downstream: %d)", msg->size, &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, is_downstream);

    // requests travel downstream, responses upstream. only one direction is parsed,
    // the other one would just clear the matches of the first
    if (is_downstream == http_parse_resp) {
        return SK_PASS;
    }

    bool is_h2 = (bpf_map_lookup_elem(&upgraded_conns, &ikey) != NULL);
    bool store_matches = false;
    int msg_len = 0;
    struct http_parse_res pres = { 0 };

    if (is_h2) {
        struct http2_frame frame = { 0 };
        msg_len = parse_http2_msg(msg, &pres, &frame);
        if (msg_len < 0) {
            bpf_error("Failed to parse h2 message: %s", msg->data);
            return SK_PASS;
        }

        store_matches = (msg_len > 9);
        last_dt_count_before = frame.dt_count_before;
        last_dt_count = frame.dt_count;
    }
    else {
        msg_len = parse_http1_msg(msg, &pres);
        if (msg_len < 0) {
            // It's possible that this fails because we're actually parsing the body.
            // To avoid this, we'd have to parse the content-length to skip the body.
            // Consult the example to see how to do this.
            return SK_PASS;
        }

        if (matched_http1(&pres, 0)) {
            int flag = 1;
            bpf_map_update_elem(&upgraded_conns, &ikey, &flag, BPF_ANY);
            num_upgraded_conns += 1;
        }

        store_matches = true;
    }

    // only store matches if we parsed a HEADER frame
    if (store_matches) {
        store_matched(&pres, is_h2);

        u32 i = 0;
        bpf_for(i, 0, 32) {
            struct bytes str = { 0 };
            int res = is_h2 ? extract_http2_match_msg(msg, &pres, i, &str) : extract_http1_match_msg(msg, &pres, i, &str);
            store_match(i, res, &str);
        }
    }

    bpf_debug("Apply verdict to %d/%dB", msg_len, msg->size);
    bpf_msg_apply_bytes(msg, msg_len);

    return SK_PASS;
}

// The connection an sk_buff arrived on, as seen from the socket it arrived at.
static __always_inline struct ip4_conn skb_conn(const struct __sk_buff *skb) {
    return (struct ip4_conn) {
        .local = {
            .ip4 = skb->local_ip4,
            .port = skb->local_port
        },
        .remote = {
            .ip4 = skb->remote_ip4,
            .port = bpf_ntohl(skb->remote_port)
        }
    };
}

#define HTTP2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define HTTP2_PREFACE_LEN 24

// Cuts what arrives on a socket into the messages `skb_verdict` parses: an
// HTTP/2 frame at a time on an upgraded connection, the preface on its own, and
// whatever arrived otherwise.
//
// The message starts `off` bytes into the sk_buff, the kernel hands over the
// whole of it, and the length returned is counted from `off`.
SEC("sk_skb/stream_parser")
int skb_parser(struct __sk_buff *skb) {
    struct ip4_conn ikey = skb_conn(skb);
    u32 off = strp_offset(skb);
    if (off >= skb->len) return 0;

    u32 avail = skb->len - off;

    if (bpf_map_lookup_elem(&upgraded_conns, &ikey) != NULL) {
        u8 hdr[3];
        if (bpf_skb_load_bytes(skb, off, hdr, sizeof(hdr)) < 0) return 0;

        u32 len = (u32)hdr[0] << 16 | (u32)hdr[1] << 8 | hdr[2];
        return 9 + len;
    }

    const char preface[] = HTTP2_PREFACE;
    char head[HTTP2_PREFACE_LEN];
    if (bpf_skb_load_bytes(skb, off, head, HTTP2_PREFACE_LEN) == 0) {
        bool is_preface = true;
        for (int i = 0; i < HTTP2_PREFACE_LEN; i++) {
            if (head[i] != preface[i]) {
                is_preface = false;
                break;
            }
        }

        if (is_preface) return HTTP2_PREFACE_LEN;
    }

    return avail;
}

// Same as `msg_verdict`, for the messages `skb_parser` cut out of what arrived
// on a socket.
SEC("sk_skb/stream_verdict")
int skb_verdict(struct __sk_buff *skb) {
    struct ip4_conn ikey = skb_conn(skb);

    // what arrives at the server is travelling downstream
    bool is_downstream = (ikey.local.ip4 == ip4 && ikey.local.port == port);
    bpf_trace("Processing %dB skb on [%pI4:%u->%pI4:%u] (downstream: %d)", skb->len, &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, is_downstream);

    if (is_downstream == http_parse_resp) {
        return SK_PASS;
    }

    u32 off = strp_offset(skb);
    bool is_h2 = (bpf_map_lookup_elem(&upgraded_conns, &ikey) != NULL);
    bool store_matches = false;
    struct http_parse_res pres = { 0 };

    if (is_h2) {
        struct http2_frame frame = { 0 };
        int len = parse_http2_skb(skb, off, &pres, &frame, NULL);
        if (len < 0) {
            bpf_error("Failed to parse h2 skb");
            return SK_PASS;
        }

        store_matches = (len > 9);
        last_dt_count_before = frame.dt_count_before;
        last_dt_count = frame.dt_count;
    }
    else {
        if (parse_http1_skb(skb, off, &pres, NULL) < 0) return SK_PASS;

        if (matched_http1(&pres, 0)) {
            int flag = 1;
            bpf_map_update_elem(&upgraded_conns, &ikey, &flag, BPF_ANY);
            num_upgraded_conns += 1;
        }

        store_matches = true;
    }

    if (store_matches) {
        store_matched(&pres, is_h2);

        u32 i = 0;
        bpf_for(i, 0, 32) {
            struct bytes str = { 0 };
            int res = is_h2 ? extract_http2_match_skb(skb, &pres, i, &str) : extract_http1_match_skb(skb, &pres, i, &str);
            store_match(i, res, &str);
        }
    }

    return SK_PASS;
}

// Adds both ends of every connection to the server under test to `sock_map`, so
// that `msg_verdict` sees the messages travelling on them.
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

        // `msg_verdict` sees a message as it is sent, `skb_verdict` as it
        // arrives, so the two hooks read the direction under test off opposite
        // ends of the connection. Only the end that is parsed goes into the
        // map: a stream parser cuts up everything the map holds, and cutting a
        // direction this program does not parse stalls it.
        bool parsed_here = hook_skb ? (http_parse_resp ? is_client : is_server)
                                    : (http_parse_resp ? is_server : is_client);

        if (parsed_here) {
            if (bpf_sock_hash_update(ops, &sock_map, &skey, BPF_ANY) < 0) {
                bpf_error("Failed to add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
                return SK_PASS;
            }

            bpf_debug("Add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
        }
    }

    return SK_PASS;
}

// Returns the number of connections that were upgraded to HTTP/2.
SEC("syscall")
int get_num_upgraded_conns() {
    return num_upgraded_conns;
}
