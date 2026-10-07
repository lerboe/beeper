#include "vmlinux.h"
#include "beeper/dns.h"
#include "dns.bpf.h"
#include <bpf/bpf_helpers.h>

// Runs the parser of dns.bpf.h with BPF_PROG_TEST_RUN, for the unit tests of
// the dns module. The input is an Ethernet frame whose payload starts at
// `test_off`, user space reads the results back from the globals below.

#define TEST_MAX_RRS 16

u32 test_off = 0;
u32 test_flags = 0;
u32 test_name_flags = 0;

int test_ret = 0;
struct dns_parse_res test_res = { 0 };

// The records the iterator returned, along with what it returned last.
int test_rr_ret = 0;
u32 test_num_rrs = 0;
struct dns_rr test_rrs[TEST_MAX_RRS] = { 0 };

// The cursor of the iterator. It is kept out of the stack, as it is behind the
// pointer the target program passes to the record iterator.
struct dns_rr test_cur = { 0 };

// The question name and the owner of every record in `test_rrs`, decompressed.
int test_qname_ret = 0;
struct dns_name_buf test_qname = { 0 };
int test_rr_name_ret[TEST_MAX_RRS] = { 0 };
struct dns_name_buf test_rr_names[TEST_MAX_RRS] = { 0 };

SEC("tc")
int run(struct __sk_buff *skb) {
    struct dns_msg m = _dns_msg((u64)(long)skb->data, (u64)(long)skb->data_end);

    test_ret = _dns_parse(&m, test_off, test_flags, &test_res);
    if (test_ret < 0) return 0;

    if (test_res.hdr.qdcount > 0 && !(test_res.flags & DNS_RES_PARTIAL)) {
        test_qname_ret = _dns_extract_name(&m, &test_res, test_res.q.name.off, test_name_flags, &test_qname);
    }

    u32 i;
    bpf_for(i, 0, TEST_MAX_RRS) {
        test_rr_ret = _dns_next_rr(&m, &test_res, &test_cur);
        if (test_rr_ret < 0) break;

        test_rrs[i] = test_cur;
        test_num_rrs = i + 1;
        test_rr_name_ret[i] = _dns_extract_name(&m, &test_res, test_cur.name.off, test_name_flags, &test_rr_names[i]);
    }

    return 0;
}
