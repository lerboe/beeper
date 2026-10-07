#include "beeper/beeper.h"

// The DNS specific part of the interface between a BPF program and the parser
// beeper attaches to it.
//
// The parser implements the message format of RFC 1035 along with the updates
// that change how a message is laid out or which messages are well-formed:
//
// - RFC 2181:  labels and names are limited to 63 and 255 octets, labels may
//              hold any octet value.
// - RFC 2136:  UPDATE (opcode 5) reuses the four sections as zone,
//              prerequisite, update and additional, allows the classes NONE
//              and ANY and empty RDATA, and requires exactly one zone.
// - RFC 1996:  NOTIFY (opcode 4).
// - RFC 2535, RFC 4035:  the AD and CD bits of the header.
// - RFC 2673, RFC 6891:  extended label types (the `01` label prefix) are not
//              in use, a name carrying one is malformed, as is one carrying
//              the reserved `10` prefix.
// - RFC 2845, RFC 8945:  a TSIG record may only appear once, as the last
//              record of the additional section.
// - RFC 3425:  IQUERY (opcode 1) is obsolete. Such messages are still parsed,
//              it is up to the program to answer them with NOTIMP.
// - RFC 4343:  names compare case-insensitively, for ASCII letters only, see
//              `DNS_NAME_LOWER`.
// - RFC 5966, RFC 7766:  over TCP every message is preceded by its two octet
//              length, and a stream may carry many of them back to back.
// - RFC 6891:  the OPT pseudo-RR (EDNS(0)), its extended RCODE, version, flags
//              and options. It may only appear once, in the additional section,
//              and only with the root as its owner.
// - RFC 8490:  DSO (opcode 6) messages carry no sections, all four counts are
//              zero and TLVs follow the header instead.
// - RFC 8767:  the TTL is an unsigned 32 bit value, a set high-order bit no
//              longer means zero. `DNS_TTL_CAP` is the recommended cap.
// - RFC 9619:  a QUERY (opcode 0) holds at most one question.
//
// RFC 1101, 1183, 1348, 1876, 2065, 2137, 3658, 4033 and 4034 only add RR
// types, whose RDATA is passed on as is. RFC 1982, 1995, 2308, 5936, 6604 and
// 8482 change how messages are interpreted or produced, not how they are laid
// out.

#ifndef __BEEPER_DNS_H__
#define __BEEPER_DNS_H__

// The bits of `dns_header.flags`, RFC 1035 4.1.1, RFC 4035 3.2.
#define DNS_FLAG_QR (1 << 15)
#define DNS_FLAG_AA (1 << 10)
#define DNS_FLAG_TC (1 << 9)
#define DNS_FLAG_RD (1 << 8)
#define DNS_FLAG_RA (1 << 7)
#define DNS_FLAG_Z (1 << 6)
#define DNS_FLAG_AD (1 << 5)
#define DNS_FLAG_CD (1 << 4)
#define DNS_OPCODE(flags) (((flags) >> 11) & 0xF)
#define DNS_HDR_RCODE(flags) ((flags) & 0xF)

// Opcodes.
#define DNS_OPCODE_QUERY 0
#define DNS_OPCODE_IQUERY 1 // obsolete, RFC 3425
#define DNS_OPCODE_STATUS 2
#define DNS_OPCODE_NOTIFY 4 // RFC 1996
#define DNS_OPCODE_UPDATE 5 // RFC 2136
#define DNS_OPCODE_DSO 6    // RFC 8490

// Response codes. The ones above 15 need EDNS(0) to be expressed.
#define DNS_RCODE_NOERROR 0
#define DNS_RCODE_FORMERR 1
#define DNS_RCODE_SERVFAIL 2
#define DNS_RCODE_NXDOMAIN 3
#define DNS_RCODE_NOTIMP 4
#define DNS_RCODE_REFUSED 5
#define DNS_RCODE_YXDOMAIN 6 // RFC 2136
#define DNS_RCODE_YXRRSET 7  // RFC 2136
#define DNS_RCODE_NXRRSET 8  // RFC 2136
#define DNS_RCODE_NOTAUTH 9  // RFC 2136
#define DNS_RCODE_NOTZONE 10 // RFC 2136
#define DNS_RCODE_DSOTYPENI 11 // RFC 8490
#define DNS_RCODE_BADVERS 16 // RFC 6891

// Record types.
#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_MD 3
#define DNS_TYPE_MF 4
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA 6
#define DNS_TYPE_MB 7
#define DNS_TYPE_MG 8
#define DNS_TYPE_MR 9
#define DNS_TYPE_NULL 10
#define DNS_TYPE_WKS 11
#define DNS_TYPE_PTR 12
#define DNS_TYPE_HINFO 13
#define DNS_TYPE_MINFO 14
#define DNS_TYPE_MX 15
#define DNS_TYPE_TXT 16
#define DNS_TYPE_AAAA 28
#define DNS_TYPE_OPT 41   // RFC 6891
#define DNS_TYPE_TSIG 250 // RFC 8945
#define DNS_TYPE_IXFR 251 // RFC 1995
#define DNS_TYPE_AXFR 252 // RFC 5936
#define DNS_TYPE_ANY 255

// Classes.
#define DNS_CLASS_IN 1
#define DNS_CLASS_CH 3
#define DNS_CLASS_HS 4
#define DNS_CLASS_NONE 254 // RFC 2136
#define DNS_CLASS_ANY 255

// The sections of a message. UPDATE calls them zone, prerequisite, update and
// additional.
#define DNS_SECTION_QUESTION 0
#define DNS_SECTION_ANSWER 1
#define DNS_SECTION_AUTHORITY 2
#define DNS_SECTION_ADDITIONAL 3

// Limits, RFC 1035 2.3.4, RFC 2181 11.
#define DNS_MAX_LABEL 63
#define DNS_MAX_NAME 255
#define DNS_HDR_LEN 12

// The cap RFC 8767 recommends for a TTL, in seconds.
#define DNS_TTL_CAP 604800

// The smallest UDP payload size EDNS(0) may advertise, RFC 6891 6.2.5. Smaller
// values are passed on as they are and are to be treated as this one.
#define DNS_EDNS_MIN_UDP_SIZE 512

// The `flags` of the parse function. With `DNS_PARSE_TCP`, the message is
// preceded by its two octet length, as it is over TCP (RFC 7766 8). Otherwise
// it spans the remainder of the buffer, as it does in a UDP datagram.
#define DNS_PARSE_TCP (1 << 0)

// The bits of `dns_parse_res.flags`.
#define DNS_RES_EDNS (1 << 0)    // the message carries an OPT record
#define DNS_RES_TSIG (1 << 1)    // the message ends with a TSIG record
#define DNS_RES_PARTIAL (1 << 2) // TC is set and the message holds fewer
                                 // entries than the counts announce
#define DNS_RES_TRAILING (1 << 3) // the datagram carries octets after the
                                  // message, which are not part of it

// The bit of `dns_edns.flags` that asks for DNSSEC records, RFC 3225.
#define DNS_EDNS_DO (1 << 15)

// The errors the parser functions return.
#define DNS_ERR_INCOMPLETE -1 // the buffer ends before the message does
#define DNS_ERR_FORMAT -2     // the message is malformed (FORMERR)
#define DNS_ERR_LIMIT -3      // the message exceeds what the parser handles,
                              // e.g. a buffer of more than MAX_BYTES octets
#define DNS_ERR_END -4        // there are no more records to iterate

// The `flags` of the name extraction. By default a name is extracted in its
// uncompressed wire format: length-prefixed labels, ending in the empty root
// label. `DNS_NAME_DOTTED` joins the labels with dots instead, with the root
// spelled as a single dot. As a label may contain dots itself, only the wire
// format is unambiguous. `DNS_NAME_LOWER` lowercases ASCII letters, which is all
// RFC 4343 asks of a comparison.
#define DNS_NAME_DOTTED (1 << 0)
#define DNS_NAME_LOWER (1 << 1)

// The header of a message, in host byte order.
struct dns_header {
    u16 id;
    u16 flags;
    u16 qdcount;
    u16 ancount;
    u16 nscount;
    u16 arcount;
};

// A name as it is found in the buffer. `off` is its offset in the buffer, `len`
// the number of octets it occupies there, which ends with its first
// compression pointer, if any.
struct dns_name {
    u16 off;
    u16 len;
};

// An entry of the question section.
struct dns_question {
    struct dns_name name;
    u16 qtype;
    u16 qclass;
};

// The OPT pseudo-RR of a message, RFC 6891 6.1. Only valid if
// `DNS_RES_EDNS` is set.
struct dns_edns {
    u16 off;      // offset of the record in the buffer
    u16 udp_size; // the requestor's UDP payload size
    u8 ext_rcode; // the upper 8 bits of the 12 bit RCODE
    u8 version;
    u16 flags;      // DO and Z
    u16 rdata_off;  // offset of the options in the buffer
    u16 rdlen;      // length of the options
};

// The result of parsing a single message. All offsets point into the buffer
// that was parsed.
struct dns_parse_res {
    u16 base; // offset of the header
    u16 len;  // length of the message, not counting the TCP length prefix
    struct dns_header hdr;
    struct dns_question q; // the first question, if `hdr.qdcount > 0`
    u16 sec_off[4];        // offset of the first entry of each section
    u16 rcode;             // the full RCODE, extended by EDNS(0)
    u16 flags;             // DNS_RES_*
    u16 tsig_off;          // offset of the TSIG record if DNS_RES_TSIG
    struct dns_edns edns;
};

// A resource record, as filled in by the record iterator. Zero it before the
// first call, and pass it back unchanged to get the next record.
struct dns_rr {
    struct dns_name name;
    u16 type;
    u16 class;
    u32 ttl;
    u16 rdlen;
    u16 rdata_off; // offset of the RDATA in the buffer
    u16 off;       // offset of the record in the buffer
    u16 next;      // offset of the next record, 0 before the first call
    u16 idx;       // number of records returned so far, this one included
    u8 section;    // DNS_SECTION_*
};

// A name decompressed by the name extraction. `len` counts the octets in `buf`,
// without the NUL that always follows them.
struct dns_name_buf {
    u16 len;
    u16 labels; // the number of labels, without the root
    u8 buf[DNS_MAX_NAME + 1];
};

// Creates `name`, a stub for the DNS-over-TCP parser
// (`dns::Parser::parse_fn`, `MessageBuffer::Msg`). It parses the message that
// starts with its length prefix at `off`, so a program can walk all messages
// of a buffer. It returns the number of octets the message occupies, prefix
// included, or one of the `DNS_ERR_*`. On `DNS_ERR_INCOMPLETE`,
// `pres->len` holds the announced length, if the prefix was complete.
#define BEEPER_DNS_PARSE_MSG(name)                                                                 \
    __noinline int name(struct sk_msg_md *msg, u32 off, struct dns_parse_res *pres __arg_nonnull) { \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(msg);                                                                               \
        __sink(off);                                                                               \
        __sink(pres);                                                                              \
        __sink(ret);                                                                               \
                                                                                                   \
        bpf_msg_pull_data(msg, 0, msg->size, 0);                                                   \
                                                                                                   \
        return ret;                                                                                \
    }

// Creates `name`, a stub for the sk_buff parser (`dns::Parser::parse_fn`,
// `MessageBuffer::Skb`). The message starts at `off`, `flags` takes
// `DNS_PARSE_TCP`. See `BEEPER_DNS_PARSE_MSG` for the return value.
#define BEEPER_DNS_PARSE_SKB(name)                                                                 \
    __noinline int name(struct __sk_buff *skb, u32 off, u32 flags,                                 \
                        struct dns_parse_res *pres __arg_nonnull) {                                \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(skb);                                                                               \
        __sink(off);                                                                               \
        __sink(flags);                                                                             \
        __sink(pres);                                                                              \
        __sink(ret);                                                                               \
                                                                                                   \
        bpf_skb_pull_data(skb, skb->len);                                                          \
                                                                                                   \
        return ret;                                                                                \
    }

// Creates `name`, a stub for the record iterator (`dns::Parser::next_rr_fn`,
// `MessageBuffer::Msg`). It moves `rr` to the next record of the answer,
// authority and additional sections of a message the parser accepted. Returns
// 0, or `DNS_ERR_END` once all records were returned.
#define BEEPER_DNS_NEXT_RR_MSG(name)                                                               \
    __noinline int name(const struct sk_msg_md *msg, const struct dns_parse_res *pres __arg_nonnull, \
                        struct dns_rr *rr __arg_nonnull) {                                         \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(msg);                                                                               \
        __sink(pres);                                                                              \
        __sink(rr);                                                                                \
        __sink(ret);                                                                               \
                                                                                                   \
        return ret;                                                                                \
    }

// Same as `BEEPER_DNS_NEXT_RR_MSG`, for `MessageBuffer::Skb`.
#define BEEPER_DNS_NEXT_RR_SKB(name)                                                               \
    __noinline int name(const struct __sk_buff *skb, const struct dns_parse_res *pres __arg_nonnull, \
                        struct dns_rr *rr __arg_nonnull) {                                         \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(skb);                                                                               \
        __sink(pres);                                                                              \
        __sink(rr);                                                                                \
        __sink(ret);                                                                               \
                                                                                                   \
        return ret;                                                                                \
    }

// Creates `name`, a stub for the name extraction (`dns::Parser::extract_name_fn`,
// `MessageBuffer::Msg`). It decompresses the name at `off` of a message the
// parser accepted into `out`, as `flags` (DNS_NAME_*) ask. Returns `out->len`,
// or one of the `DNS_ERR_*`.
#define BEEPER_DNS_EXTRACT_NAME_MSG(name)                                                          \
    __noinline int name(const struct sk_msg_md *msg, const struct dns_parse_res *pres __arg_nonnull, \
                        u32 off, u32 flags, struct dns_name_buf *out __arg_nonnull) {              \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(msg);                                                                               \
        __sink(pres);                                                                              \
        __sink(off);                                                                               \
        __sink(flags);                                                                             \
        __sink(out);                                                                               \
        __sink(ret);                                                                               \
                                                                                                   \
        return ret;                                                                                \
    }

// Same as `BEEPER_DNS_EXTRACT_NAME_MSG`, for `MessageBuffer::Skb`.
#define BEEPER_DNS_EXTRACT_NAME_SKB(name)                                                          \
    __noinline int name(const struct __sk_buff *skb, const struct dns_parse_res *pres __arg_nonnull, \
                        u32 off, u32 flags, struct dns_name_buf *out __arg_nonnull) {              \
        int ret = -1;                                                                              \
                                                                                                   \
        __sink(skb);                                                                               \
        __sink(pres);                                                                              \
        __sink(off);                                                                               \
        __sink(flags);                                                                             \
        __sink(out);                                                                               \
        __sink(ret);                                                                               \
                                                                                                   \
        return ret;                                                                                \
    }

#endif // __BEEPER_DNS_H__
