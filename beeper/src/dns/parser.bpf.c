#include "vmlinux.h"
#include "beeper/dns.h"
#include "dns.bpf.h"
#include "xbpf.h"
#include <bpf/bpf_helpers.h>

// The programs that replace the stubs of beeper/dns.h. Unlike the HTTP parsers
// they need no DFA, as a DNS message is laid out in binary and tells the
// parser how long each of its parts is.

// Parses the DNS-over-TCP message whose length prefix starts at `off`.
SEC("freplace")
int parse_msg(struct sk_msg_md *msg, u32 off, struct dns_parse_res *pres __arg_nonnull) {
    // pulling in what is linear already is cheap, and doing it either way
    // keeps clang from merging the context accesses of both cases
    if (bpf_msg_pull_data(msg, 0, msg->size, 0) < 0) return DNS_ERR_LIMIT;

    struct dns_msg m = _dns_msg((u64)(long)msg->data, (u64)(long)msg->data_end);

    int res = _dns_parse(&m, off, DNS_PARSE_TCP, pres);
    bpf_debug("parsed dns message at %d: %d", off, res);

    return res;
}

// Parses the DNS message at `off` of the sk_buff.
SEC("freplace")
int parse_skb(struct __sk_buff *skb, u32 off, u32 flags, struct dns_parse_res *pres __arg_nonnull) {
    if (bpf_skb_pull_data(skb, skb->len) < 0) return DNS_ERR_LIMIT;

    struct dns_msg m = _dns_msg((u64)(long)skb->data, (u64)(long)skb->data_end);

    int res = _dns_parse(&m, off, flags, pres);
    bpf_debug("parsed dns message at %d: %d", off, res);

    return res;
}

// Moves `rr` to the next record of the message in `msg`.
SEC("freplace")
int next_rr_msg(const struct sk_msg_md *msg, const struct dns_parse_res *pres __arg_nonnull, struct dns_rr *rr __arg_nonnull) {
    struct dns_msg m = _dns_msg((u64)(long)msg->data, (u64)(long)msg->data_end);

    return _dns_next_rr(&m, pres, rr);
}

// Moves `rr` to the next record of the message in `skb`.
SEC("freplace")
int next_rr_skb(const struct __sk_buff *skb, const struct dns_parse_res *pres __arg_nonnull, struct dns_rr *rr __arg_nonnull) {
    struct dns_msg m = _dns_msg((u64)(long)skb->data, (u64)(long)skb->data_end);

    return _dns_next_rr(&m, pres, rr);
}

// Decompresses the name at `off` of the message in `msg`.
SEC("freplace")
int extract_name_msg(const struct sk_msg_md *msg, const struct dns_parse_res *pres __arg_nonnull, u32 off, u32 flags, struct dns_name_buf *out __arg_nonnull) {
    struct dns_msg m = _dns_msg((u64)(long)msg->data, (u64)(long)msg->data_end);

    return _dns_extract_name(&m, pres, off, flags, out);
}

// Decompresses the name at `off` of the message in `skb`.
SEC("freplace")
int extract_name_skb(const struct __sk_buff *skb, const struct dns_parse_res *pres __arg_nonnull, u32 off, u32 flags, struct dns_name_buf *out __arg_nonnull) {
    struct dns_msg m = _dns_msg((u64)(long)skb->data, (u64)(long)skb->data_end);

    return _dns_extract_name(&m, pres, off, flags, out);
}
