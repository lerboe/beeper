#include "vmlinux.h"
#include "beeper/dns.h"
#include <bpf/bpf_helpers.h>

// The DNS message parser, shared by the parser program and its tests.
//
// A message is walked name by name and record by record, and how far each one
// reaches is only known once it is read. Following that with direct packet
// access would have the verifier walk every path through every record. The
// walk is therefore split into global functions, each of which the verifier
// checks once, on its own. As a global function cannot be handed a packet
// pointer, they read the message with `bpf_probe_read_kernel` instead, after
// checking that what they read lies within it.

#ifndef __BEEPER_DNS_BPF_H__
#define __BEEPER_DNS_BPF_H__

// The number of steps a name walk takes at most, each consuming a label or a
// compression pointer. A name holds at most 128 labels (RFC 1035 3.1, the
// root included), which leaves room for at least 64 pointers. RFC 1035 does
// not limit them, but as every pointer has to point before the previous one, a
// chain only ever gets this long if it is crafted to.
#define DNS_NAME_STEPS (128 + 64)

// The number of option TLVs in an OPT record, or of TLVs in a DSO message, the
// parser walks. Each takes at least four octets.
#define DNS_MAX_TLVS ((MAX_BYTES + 1) / 4)

// The message a parser works on. `data` is the address of the buffer, of which
// `size` octets can be read. The message's header is at `base`, and the
// message ends at `end`. All offsets are relative to `data`.
struct dns_msg {
    u64 data;
    u32 size;
    u32 base;
    u32 end;
};

// Describes the linear buffer between `data` and `data_end`, the data pointers
// of a program's context.
static __always_inline struct dns_msg _dns_msg(u64 data, u64 data_end) {
    return (struct dns_msg) {
        .data = data,
        .size = data_end > data ? data_end - data : 0,
    };
}

// Returns `off`, of which the verifier then only knows that it fits 16 bits.
// Applied to a value a loop carries from one iteration to the next, it keeps
// the verifier from following every value it could take, as the loop
// converges once the value spans its whole range. It must only be applied to
// values that are known to fit.
//
// The verifier tracks a value through registers and fixed stack slots, but not
// through a stack read at an offset it does not know, so `off` is read back
// from one of two slots holding it, picked by the iteration `i`.
static __always_inline u32 _dns_widen(u32 off, u32 i) {
    volatile u64 slots[2];
    slots[0] = off;
    slots[1] = off;

    u64 o = slots[i & 1];
    asm volatile("%0 &= 0xFFFF" : "+r"(o));
    return o;
}

// Copies the `size` octets at `off` into `dst`, if they lie within the message.
static __always_inline int _dns_read(const struct dns_msg *m, u32 off, void *dst, u32 size) {
    u64 end = (u64)off + size;
    if (end > m->end || end > m->size) return DNS_ERR_FORMAT;

    if (bpf_probe_read_kernel(dst, size, (const void *)(m->data + off)) < 0) return DNS_ERR_FORMAT;
    return 0;
}

// Reads the u16 at `off`.
static __always_inline int _dns_u16(const struct dns_msg *m, u32 off, u16 *v) {
    u8 b[2];
    if (_dns_read(m, off, b, sizeof(b)) < 0) return DNS_ERR_FORMAT;

    *v = ((u16)b[0] << 8) | b[1];
    return 0;
}

// Reads the u32 at `off`.
static __always_inline int _dns_u32(const struct dns_msg *m, u32 off, u32 *v) {
    u8 b[4];
    if (_dns_read(m, off, b, sizeof(b)) < 0) return DNS_ERR_FORMAT;

    *v = ((u32)b[0] << 24) | ((u32)b[1] << 16) | ((u32)b[2] << 8) | b[3];
    return 0;
}

// Appends the label of `len` octets at `off` to `out`, as `flags` (DNS_NAME_*)
// ask. The label is read a few octets at a time, to keep the stack small.
static __always_inline int _dns_append_label(const struct dns_msg *m, u32 off, u8 len, u32 flags,
                                             struct dns_name_buf *out) {
    len &= DNS_MAX_LABEL;
    if (len == 0) return DNS_ERR_FORMAT;

    u32 olen = out->len;
    if (!(flags & DNS_NAME_DOTTED)) {
        out->buf[olen & DNS_MAX_NAME] = len;
        olen += 1;
    }
    else if (olen > 0) {
        out->buf[olen & DNS_MAX_NAME] = '.';
        olen += 1;
    }

    u32 k;
    bpf_for(k, 0, (len + 7) / 8) {
        u8 chunk[8];
        u32 done = k * 8;
        u32 size = len - done > 8 ? 8 : len - done;
        if (_dns_read(m, off + done, chunk, size) < 0) return DNS_ERR_FORMAT;

        u32 j;
        bpf_for(j, 0, size) {
            u8 ch = chunk[j & 7];
            if ((flags & DNS_NAME_LOWER) && ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';

            out->buf[(olen + done + j) & DNS_MAX_NAME] = ch;
        }
    }

    out->len = olen + len;
    out->labels += 1;

    return 0;
}

// Terminates the name in `out`.
static __always_inline void _dns_finish_name(u32 flags, struct dns_name_buf *out) {
    u32 olen = out->len;
    if (!(flags & DNS_NAME_DOTTED)) {
        out->buf[olen & DNS_MAX_NAME] = 0;
        olen += 1;
    }
    else if (olen == 0) {
        out->buf[0] = '.';
        olen = 1;
    }

    olen &= DNS_MAX_NAME;
    out->buf[olen] = '\0';
    out->len = olen;
}

// Walks the name at `pos`, following its compression pointers. If `out` is not
// NULL, the name is decompressed into it as `flags` (DNS_NAME_*) ask.
//
// A pointer has to point before the label sequence it is part of (RFC 1035
// 4.1.4 calls it a prior occurrence), which also keeps a walk from looping.
// Labels with the `01` (RFC 6891 5) or `10` prefix are malformed, as are names
// longer than 255 octets (RFC 1035 3.1).
//
// Returns where the name ends at `pos`, or one of the `DNS_ERR_*`.
__noinline __weak int _dns_name(const struct dns_msg *m __arg_nonnull, u32 pos, u32 flags,
                                struct dns_name_buf *out) {
    u32 p = pos;
    u32 floor = pos;
    u32 wlen = 0;
    u32 next = 0;

    if (out) {
        out->len = 0;
        out->labels = 0;
    }

    u32 i;
    bpf_for(i, 0, DNS_NAME_STEPS) {
        u8 len = 0;
        if (_dns_read(m, p, &len, 1) < 0) return DNS_ERR_FORMAT;

        u8 kind = len & 0xC0;
        if (kind == 0xC0) {
            u16 ptr = 0;
            if (_dns_u16(m, p, &ptr) < 0) return DNS_ERR_FORMAT;
            if (next == 0) next = p + 2;

            // the header holds no names, and a pointer has to lead backwards
            u32 target = m->base + (ptr & 0x3FFF);
            if (target < m->base + DNS_HDR_LEN || target >= floor) return DNS_ERR_FORMAT;

            p = target;
            floor = target;
            continue;
        }

        if (kind != 0) return DNS_ERR_FORMAT;

        wlen = _dns_widen(wlen, i) + 1 + len;
        if (wlen > DNS_MAX_NAME) return DNS_ERR_FORMAT;

        if (len == 0) {
            if (next == 0) next = p + 1;
            if (out) _dns_finish_name(flags, out);

            return next;
        }

        if (out && _dns_append_label(m, p + 1, len, flags, out) < 0) return DNS_ERR_FORMAT;

        p = _dns_widen(p + 1 + len, i);
    }

    return DNS_ERR_LIMIT;
}

// Checks that `len` octets at `pos` are a sequence of TLVs, each a 16 bit type
// and a 16 bit length followed by that many octets, as the options of an OPT
// record (RFC 6891 6.1.2) and the body of a DSO message (RFC 8490 5.4) are.
__noinline __weak int _dns_tlvs(const struct dns_msg *m __arg_nonnull, u32 pos, u32 len) {
    u32 end = pos + len;
    if (end > m->end) return DNS_ERR_FORMAT;

    u32 i;
    bpf_for(i, 0, DNS_MAX_TLVS) {
        if (pos == end) return 0;

        u16 tlv_len = 0;
        if (pos + 4 > end || _dns_u16(m, pos + 2, &tlv_len) < 0) return DNS_ERR_FORMAT;

        pos = _dns_widen(pos, i) + 4 + tlv_len;
        if (pos > end) return DNS_ERR_FORMAT;
    }

    return pos == end ? 0 : DNS_ERR_LIMIT;
}

// Checks the RDATA of the types RFC 1035 3.3 lays out with names, which are
// the ones that may be compressed (RFC 3597 4), along with the fixed size
// addresses. The RDATA of other types is opaque to the parser.
__noinline __weak int _dns_rdata(const struct dns_msg *m __arg_nonnull, u32 type, u32 class,
                                 u32 pos, u32 len) {
    u32 end = pos + len;
    int next = 0;

    switch (type) {
    case DNS_TYPE_A:
        // the address format depends on the class, e.g. CH carries a name
        return (class != DNS_CLASS_IN || len == 4) ? 0 : DNS_ERR_FORMAT;
    case DNS_TYPE_AAAA:
        return (class != DNS_CLASS_IN || len == 16) ? 0 : DNS_ERR_FORMAT;
    case DNS_TYPE_NS:
    case DNS_TYPE_MD:
    case DNS_TYPE_MF:
    case DNS_TYPE_CNAME:
    case DNS_TYPE_MB:
    case DNS_TYPE_MG:
    case DNS_TYPE_MR:
    case DNS_TYPE_PTR:
        next = _dns_name(m, pos, 0, NULL);
        break;
    case DNS_TYPE_MX:
        if (len < 3) return DNS_ERR_FORMAT;
        next = _dns_name(m, pos + 2, 0, NULL);
        break;
    case DNS_TYPE_MINFO:
    case DNS_TYPE_SOA:
        next = _dns_name(m, pos, 0, NULL);
        if (next < 0) return next;
        if (next >= end) return DNS_ERR_FORMAT;

        next = _dns_name(m, next, 0, NULL);
        if (next >= 0 && type == DNS_TYPE_SOA) next += 20;
        break;
    default:
        return 0;
    }

    if (next < 0) return next;
    return next == end ? 0 : DNS_ERR_FORMAT;
}

// Parses the record at `pos` into `rr`, all but its section and position in
// the message. Returns the offset of the next record, or one of the
// `DNS_ERR_*`.
__noinline __weak int _dns_rr(const struct dns_msg *m __arg_nonnull, u32 pos,
                              struct dns_rr *rr __arg_nonnull) {
    int next = _dns_name(m, pos, 0, NULL);
    if (next < 0) return next;

    u16 type = 0, class = 0, rdlen = 0;
    u32 ttl = 0;
    if (_dns_u16(m, next, &type) < 0 || _dns_u16(m, next + 2, &class) < 0 ||
        _dns_u32(m, next + 4, &ttl) < 0 || _dns_u16(m, next + 8, &rdlen) < 0) {
        return DNS_ERR_FORMAT;
    }

    u32 rdata = next + 10;
    if (rdata + rdlen > m->end) return DNS_ERR_FORMAT;

    rr->off = pos;
    rr->name.off = pos;
    rr->name.len = next - pos;
    rr->type = type;
    rr->class = class;
    rr->ttl = ttl;
    rr->rdlen = rdlen;
    rr->rdata_off = rdata;

    return rdata + rdlen;
}

// Parses the question and record sections of the message `m` points at, whose
// header `pres` already holds. Returns the offset at which they end, or one of
// the `DNS_ERR_*`.
__noinline __weak int _dns_sections(const struct dns_msg *m __arg_nonnull,
                                    struct dns_parse_res *pres __arg_nonnull) {
    u16 hflags = pres->hdr.flags;
    u32 opcode = DNS_OPCODE(hflags);
    bool tc = (hflags & DNS_FLAG_TC) != 0;
    bool update_req = opcode == DNS_OPCODE_UPDATE && !(hflags & DNS_FLAG_QR);
    u32 qd = pres->hdr.qdcount, an = pres->hdr.ancount;
    u32 ns = pres->hdr.nscount, ar = pres->hdr.arcount;
    u32 p = m->base + DNS_HDR_LEN;

    pres->rcode = DNS_HDR_RCODE(hflags);
    pres->sec_off[DNS_SECTION_QUESTION] = p;
    pres->sec_off[DNS_SECTION_ANSWER] = p;
    pres->sec_off[DNS_SECTION_AUTHORITY] = p;
    pres->sec_off[DNS_SECTION_ADDITIONAL] = p;

    if (opcode == DNS_OPCODE_DSO) {
        // RFC 8490 5.4: no sections, but TLVs up to the end of the message
        if (qd || an || ns || ar) return DNS_ERR_FORMAT;
        if (_dns_tlvs(m, p, m->end - p) < 0) return DNS_ERR_FORMAT;

        return m->end;
    }

    // RFC 9619 4
    if (opcode == DNS_OPCODE_QUERY && qd > 1) return DNS_ERR_FORMAT;

    // RFC 2136 3.1.1, the zone section of an update holds a single SOA
    if (update_req && qd != 1) return DNS_ERR_FORMAT;

    u32 i;
    bpf_for(i, 0, qd) {
        // RFC 2181 9, a truncated message may lack what did not fit
        if (p == m->end && tc) {
            pres->flags |= DNS_RES_PARTIAL;
            return p;
        }

        int next = _dns_name(m, p, 0, NULL);
        if (next < 0) return next;

        u16 qtype = 0, qclass = 0;
        if (_dns_u16(m, next, &qtype) < 0 || _dns_u16(m, next + 2, &qclass) < 0) {
            return DNS_ERR_FORMAT;
        }

        if (i == 0) {
            if (update_req && qtype != DNS_TYPE_SOA) return DNS_ERR_FORMAT;

            pres->q.name.off = p;
            pres->q.name.len = next - p;
            pres->q.qtype = qtype;
            pres->q.qclass = qclass;
        }

        p = next + 4;
    }

    pres->sec_off[DNS_SECTION_ANSWER] = p;
    pres->sec_off[DNS_SECTION_AUTHORITY] = p;
    pres->sec_off[DNS_SECTION_ADDITIONAL] = p;

    u32 total = an + ns + ar;
    bpf_for(i, 0, total) {
        if (i == an) pres->sec_off[DNS_SECTION_AUTHORITY] = p;
        if (i == an + ns) pres->sec_off[DNS_SECTION_ADDITIONAL] = p;

        if (p == m->end && tc) {
            pres->flags |= DNS_RES_PARTIAL;
            return p;
        }

        struct dns_rr rr = { 0 };
        int next = _dns_rr(m, p, &rr);
        if (next < 0) return next;

        u8 section = i < an ? DNS_SECTION_ANSWER
                   : i < an + ns ? DNS_SECTION_AUTHORITY
                   : DNS_SECTION_ADDITIONAL;

        if (rr.type == DNS_TYPE_OPT) {
            // RFC 6891 6.1.1
            if (section != DNS_SECTION_ADDITIONAL || rr.name.len != 1) return DNS_ERR_FORMAT;
            if (pres->flags & DNS_RES_EDNS) return DNS_ERR_FORMAT;
            if (_dns_tlvs(m, rr.rdata_off, rr.rdlen) < 0) return DNS_ERR_FORMAT;

            pres->flags |= DNS_RES_EDNS;
            pres->edns.off = p;
            pres->edns.udp_size = rr.class;
            pres->edns.ext_rcode = rr.ttl >> 24;
            pres->edns.version = (rr.ttl >> 16) & 0xFF;
            pres->edns.flags = rr.ttl & 0xFFFF;
            pres->edns.rdata_off = rr.rdata_off;
            pres->edns.rdlen = rr.rdlen;
            pres->rcode = ((u16)(rr.ttl >> 24) << 4) | DNS_HDR_RCODE(hflags);
        }
        else if (rr.type == DNS_TYPE_TSIG) {
            // RFC 8945 5.1, the last record of the additional section
            if (section != DNS_SECTION_ADDITIONAL || i + 1 != total) return DNS_ERR_FORMAT;

            pres->flags |= DNS_RES_TSIG;
            pres->tsig_off = p;
        }
        // RFC 2136 2.4, 2.5: prerequisites and updates may come without RDATA
        else if (!(opcode == DNS_OPCODE_UPDATE && rr.rdlen == 0)) {
            int ret = _dns_rdata(m, rr.type, rr.class, rr.rdata_off, rr.rdlen);
            if (ret < 0) return ret;
        }

        p = next;
    }

    return p;
}

// Parses the message at `off` of `m`, which only needs `data` and `size` set,
// and reports it in `pres`. See `BEEPER_DNS_PARSE_SKB`.
__noinline __weak int _dns_parse(struct dns_msg *m __arg_nonnull, u32 off, u32 flags,
                                 struct dns_parse_res *pres __arg_nonnull) {
    bool tcp = (flags & DNS_PARSE_TCP) != 0;
    __builtin_memset(pres, 0, sizeof(*pres));

    // the parser addresses at most MAX_BYTES octets. Over TCP that only limits
    // the messages it reaches, a datagram has to fit as a whole
    u32 size = m->size;
    if (size > MAX_BYTES + 1) {
        if (!tcp) return DNS_ERR_LIMIT;
        size = MAX_BYTES + 1;
    }
    if (off >= size) return DNS_ERR_INCOMPLETE;

    m->size = size;
    m->base = off;
    m->end = size;

    u32 base = off;
    u32 len = size - off;
    if (tcp) {
        // RFC 1035 4.2.2, RFC 7766 8
        u16 prefix = 0;
        if (_dns_u16(m, off, &prefix) < 0) return DNS_ERR_INCOMPLETE;

        base = off + 2;
        len = prefix;
        pres->len = len;

        if (base + len > MAX_BYTES + 1) return DNS_ERR_LIMIT;
        if (base + len > size) return DNS_ERR_INCOMPLETE;
    }

    if (len < DNS_HDR_LEN) return DNS_ERR_FORMAT;

    m->base = base;
    m->end = base + len;
    pres->base = base;

    struct dns_header *hdr = &pres->hdr;
    if (_dns_u16(m, base, &hdr->id) < 0 || _dns_u16(m, base + 2, &hdr->flags) < 0 ||
        _dns_u16(m, base + 4, &hdr->qdcount) < 0 || _dns_u16(m, base + 6, &hdr->ancount) < 0 ||
        _dns_u16(m, base + 8, &hdr->nscount) < 0 || _dns_u16(m, base + 10, &hdr->arcount) < 0) {
        return DNS_ERR_FORMAT;
    }

    int end = _dns_sections(m, pres);
    if (end < 0) return end;

    if (end != m->end) {
        // over TCP the length prefix frames the message exactly
        if (tcp && !(pres->flags & DNS_RES_PARTIAL)) return DNS_ERR_FORMAT;
        if (!tcp) pres->flags |= DNS_RES_TRAILING;
    }

    if (!tcp) len = end - base;
    pres->len = len;

    return tcp ? 2 + len : len;
}

// Moves `rr` to the record that follows it. See `BEEPER_DNS_NEXT_RR_MSG`.
__noinline __weak int _dns_next_rr(struct dns_msg *m __arg_nonnull,
                                   const struct dns_parse_res *pres __arg_nonnull,
                                   struct dns_rr *rr __arg_nonnull) {
    const struct dns_header *hdr = &pres->hdr;
    u32 an = hdr->ancount, ns = hdr->nscount, ar = hdr->arcount;
    u32 idx = rr->idx;

    if (DNS_OPCODE(hdr->flags) == DNS_OPCODE_DSO || idx >= an + ns + ar) return DNS_ERR_END;

    m->base = pres->base;
    m->end = pres->base + pres->len;

    u32 pos = idx == 0 ? pres->sec_off[DNS_SECTION_ANSWER] : rr->next;
    if (pos >= m->end) return DNS_ERR_END;

    int next = _dns_rr(m, pos, rr);
    if (next < 0) return next;

    rr->next = next;
    rr->idx = idx + 1;
    rr->section = idx < an ? DNS_SECTION_ANSWER
                : idx < an + ns ? DNS_SECTION_AUTHORITY
                : DNS_SECTION_ADDITIONAL;

    return 0;
}

// Decompresses the name at `off`. See `BEEPER_DNS_EXTRACT_NAME_MSG`.
__noinline __weak int _dns_extract_name(struct dns_msg *m __arg_nonnull,
                                        const struct dns_parse_res *pres __arg_nonnull,
                                        u32 off, u32 flags, struct dns_name_buf *out __arg_nonnull) {
    m->base = pres->base;
    m->end = pres->base + pres->len;

    if (off < m->base + DNS_HDR_LEN || off >= m->end) return DNS_ERR_FORMAT;

    int ret = _dns_name(m, off, flags, out);
    if (ret < 0) return ret;

    return out->len;
}

#endif // __BEEPER_DNS_BPF_H__
