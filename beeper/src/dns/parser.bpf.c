#include "vmlinux.h"
#include "beeper/dns.h"
#include "xbpf.h"
#include <bpf/bpf_helpers.h>

// The DNS parser. Like the HTTP parsers, it walks a message byte by byte along
// a DFA that user space builds and injects, see dns/grammar.rs. The DFA knows
// the layout of the header, of a name and of every entry, and its actions tell
// the runtime below what a byte is. The runtime keeps what the DFA cannot: the
// counts of the entries, the lengths of labels, RDATA and TLVs, which it skips,
// and the compression pointers, which it follows with the name walk.

// The number of steps a name walk takes at most. A name holds at most 128 labels
// (RFC 1035 3.1, the root included), which leaves room for at least 64 pointers.
#define DNS_NAME_STEPS (128 + 64)

// A hook-agnostic message context.
struct msg_ctx {
    u64 data;
    u32 size;
    u32 base;
    u32 end;
};

static __always_inline struct msg_ctx _new_msg_ctx(u64 data, u64 data_end) {
    return (struct msg_ctx) {
        .data = data,
        .size = data_end > data ? data_end - data : 0,
    };
}

// Returns `off`, of which the verifier then only knows that it fits 16 bits.
static __always_inline u32 _dns_widen(u32 off, u32 i) {
    volatile u64 slots[2];
    slots[0] = off;
    slots[1] = off;

    u64 o = slots[i & 1];
    asm volatile("%0 &= 0xFFFF" : "+r"(o));
    return o;
}

static __always_inline int _dns_read(const struct msg_ctx *m, u32 off, void *dst, u32 size) {
    u64 end = (u64)off + size;
    if (end > m->end || end > m->size) return DNS_ERR_FORMAT;

    if (bpf_probe_read_kernel(dst, size, (const void *)(m->data + off)) < 0) return DNS_ERR_FORMAT;
    return 0;
}

static __always_inline int _dns_u16(const struct msg_ctx *m, u32 off, u16 *v) {
    u8 b[2];
    if (_dns_read(m, off, b, sizeof(b)) < 0) return DNS_ERR_FORMAT;

    *v = ((u16)b[0] << 8) | b[1];
    return 0;
}

static __always_inline int _dns_u32(const struct msg_ctx *m, u32 off, u32 *v) {
    u8 b[4];
    if (_dns_read(m, off, b, sizeof(b)) < 0) return DNS_ERR_FORMAT;

    *v = ((u32)b[0] << 24) | ((u32)b[1] << 16) | ((u32)b[2] << 8) | b[3];
    return 0;
}

static __always_inline int _dns_append_label(const struct msg_ctx *m, u32 off, u8 len, u32 flags,
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
// NULL, the name is decompressed into it as `flags` (DNS_NAME_*) ask. `steps`
// counts the steps a walk took to reach `pos`, if it is the target of a
// pointer.
//
// A pointer has to point before the label sequence it is part of (RFC 1035
// 4.1.4 calls it a prior occurrence), which also keeps a walk from looping.
// Labels with the `01` (RFC 6891 5) or `10` prefix are malformed, as are names
// longer than 255 octets (RFC 1035 3.1).
//
// Returns the length of the uncompressed name, root label included, or one of
// the `DNS_ERR_*`.
__noinline __weak int _dns_name(const struct msg_ctx *m __arg_nonnull, u32 pos, u32 flags,
                                struct dns_name_buf *out, u32 steps) {
    u32 p = pos;
    u32 floor = pos;
    u32 wlen = 0;

    if (out) {
        out->len = 0;
        out->labels = 0;
    }

    u32 i;
    bpf_for(i, steps, DNS_NAME_STEPS) {
        u8 len = 0;
        if (_dns_read(m, p, &len, 1) < 0) return DNS_ERR_FORMAT;

        u8 kind = len & 0xC0;
        if (kind == 0xC0) {
            u16 ptr = 0;
            if (_dns_u16(m, p, &ptr) < 0) return DNS_ERR_FORMAT;

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
            if (out) _dns_finish_name(flags, out);

            return wlen;
        }

        if (out && _dns_append_label(m, p + 1, len, flags, out) < 0) return DNS_ERR_FORMAT;

        p = _dns_widen(p + 1 + len, i);
    }

    return DNS_ERR_LIMIT;
}

// The states the runtime refers to. Every other one is left to the DFA that
// user space builds, see dns/grammar.rs.
#define S_HDR 2
#define S_QNAME 14
#define S_RRNAME 15
#define S_TLV 16
#define S_SKIP 17

// Nothing.
#define DNSA_NONE 0

// A byte of the header, `val` being its index.
#define DNSA_HDR 1

// The length of a label, which `val` holds. The runtime skips the label.
#define DNSA_LABEL 2

// The root label that ends a name.
#define DNSA_ROOT 3

// The first byte of a compression pointer, `val` holding its upper bits.
#define DNSA_PTR_HI 4

// The second byte of a compression pointer, which ends the name.
#define DNSA_PTR_LO 5

// A byte of a field that is not its last one.
#define DNSA_ACC 6

// The last byte of a field, `val` being one of the `DNS_FIELD_*`.
#define DNSA_STORE 7

// The byte is malformed where it is.
#define DNSA_ERR 8

// The transition ends the entry, a question or the RDATA of a record.
#define DNSF_END (1 << 0)

// The fields a `DNSA_STORE` completes.
#define DNS_FIELD_QTYPE 1
#define DNS_FIELD_QCLASS 2
#define DNS_FIELD_TYPE 3
#define DNS_FIELD_CLASS 4
#define DNS_FIELD_TTL 5
#define DNS_FIELD_RDLEN 6       // RDATA the DFA walks
#define DNS_FIELD_RDLEN_SKIP 7  // opaque RDATA
#define DNS_FIELD_RDLEN_A 8     // the address of an A record of the class IN
#define DNS_FIELD_RDLEN_AAAA 9  // the address of an AAAA record of the class IN
#define DNS_FIELD_RDLEN_TLV 10  // the TLVs of an OPT record
#define DNS_FIELD_TLV_LEN 11

// A single action of the DFA.
struct dns_action {
    u16 val;
    u8 kind;
    u8 flags;
};

// All three are masked onto an index, so all three have to be powers of two.
#define MAX_STATES 256
#define MAX_EDGES 256
#define MAX_ACTIONS 256

// The edges of the DFA, indexed by state and input byte, along with their
// actions. User space fills both in before the program is loaded.
volatile const struct trans s2ts[MAX_STATES][MAX_EDGES];
volatile const struct dns_action a2as[MAX_ACTIONS];

// The state of a walk over a message.
struct dns_parse_state {
    struct msg_ctx m;

    // the state of the DFA, and the field it accumulates
    u32 s;
    u32 acc;

    // the bytes the runtime skips without the DFA, and whether the entry ends
    // with them
    u32 skip;
    u32 skip_ends;

    // the questions still to read, the record being read, and the number of
    // records the header announces
    u32 qd;
    u32 idx;
    u32 total;

    // the offset of the entry being read
    u32 entry;

    // the name being read: where it starts, its uncompressed length, and the
    // number of its labels before a pointer
    u32 in_name;
    u32 name_start;
    u32 name_len;
    u32 name_labels;

    // the RDATA the DFA walks: where it ends
    u32 in_rdata;
    u32 rd_end;

    // the message is a DSO message, whose TLVs follow the header
    u32 dso;

    // where the message ended once it did
    u32 done;

    // the record to extract, or -1, and whether it was
    s32 want;
    u32 found;

    // the entry being read
    struct dns_rr rr;
};

static __always_inline void _name_begin(struct dns_parse_state *ps, u32 i) {
    if (ps->in_name) return;

    ps->in_name = 1;
    ps->name_start = i;
    ps->name_len = 0;
    ps->name_labels = 0;
}

static __always_inline int _name_add(struct dns_parse_state *ps, u32 i, u32 len) {
    _name_begin(ps, i);

    ps->name_len += len;
    return ps->name_len > DNS_MAX_NAME ? DNS_ERR_FORMAT : 0;
}

// Ends the name with the byte at `i`. The first name of an entry is its owner.
static __always_inline void _name_end(struct dns_parse_state *ps, u32 i) {
    ps->in_name = 0;
    if (ps->rr.name.len > 0) return;

    ps->rr.name.off = ps->name_start;
    ps->rr.name.len = i + 1 - ps->name_start;
}

// Starts the entry at `off`, or ends the message there if none is left.
//
// Returns 0, or 1 once the message ended.
static __always_inline int _next_entry(struct dns_parse_state *ps, struct dns_parse_res *pres, u32 off) {
    ps->entry = off;
    ps->in_name = 0;
    ps->in_rdata = 0;
    ps->skip = 0;
    ps->acc = 0;
    __builtin_memset(&ps->rr, 0, sizeof(ps->rr));
    ps->rr.off = off;

    if (ps->qd > 0) {
        ps->s = S_QNAME;
        return 0;
    }

    u32 an = pres->hdr.ancount, ns = pres->hdr.nscount;
    if (ps->idx == 0) {
        pres->sec_off[DNS_SECTION_ANSWER] = off;
        pres->sec_off[DNS_SECTION_AUTHORITY] = off;
        pres->sec_off[DNS_SECTION_ADDITIONAL] = off;
    }
    if (ps->idx == an) pres->sec_off[DNS_SECTION_AUTHORITY] = off;
    if (ps->idx == an + ns) pres->sec_off[DNS_SECTION_ADDITIONAL] = off;

    if (ps->idx < ps->total) {
        ps->rr.section = ps->idx < an ? DNS_SECTION_ANSWER
                       : ps->idx < an + ns ? DNS_SECTION_AUTHORITY
                       : DNS_SECTION_ADDITIONAL;
        ps->s = S_RRNAME;
        return 0;
    }

    ps->done = off;
    return 1;
}

// Ends the entry being read at `off`, and starts the next one.
//
// Returns 0, or 1 once the message ended or the record to extract was read.
static __always_inline int _end_entry(struct dns_parse_state *ps, struct dns_parse_res *pres, struct dns_rr *out, u32 off) {
    struct dns_rr *rr = &ps->rr;

    if (ps->qd > 0) {
        if (ps->qd == pres->hdr.qdcount) {
            pres->q.name = rr->name;
            pres->q.qtype = rr->type;
            pres->q.qclass = rr->class;
        }

        ps->qd -= 1;
        return _next_entry(ps, pres, off);
    }

    if (rr->type == DNS_TYPE_OPT) {
        pres->flags |= DNS_RES_EDNS;
        pres->edns.off = rr->off;
        pres->edns.udp_size = rr->class;
        pres->edns.ext_rcode = rr->ttl >> 24;
        pres->edns.version = (rr->ttl >> 16) & 0xFF;
        pres->edns.flags = rr->ttl & 0xFFFF;
        pres->edns.rdata_off = rr->rdata_off;
        pres->edns.rdlen = rr->rdlen;
        pres->rcode = ((u16)(rr->ttl >> 24) << 4) | DNS_HDR_RCODE(pres->hdr.flags);
    }
    else if (rr->type == DNS_TYPE_TSIG) {
        pres->flags |= DNS_RES_TSIG;
        pres->tsig_off = rr->off;
    }

    if (ps->want == (s32)ps->idx) {
        if (out) *out = *rr;
        ps->found = 1;
        ps->done = off;
        return 1;
    }

    ps->idx += 1;
    return _next_entry(ps, pres, off);
}

// Reads the header the DFA walked, and starts the first entry at `off`.
static __always_inline int _begin(struct dns_parse_state *ps, struct dns_parse_res *pres, u32 off) {
    const struct dns_header *hdr = &pres->hdr;
    u32 opcode = DNS_OPCODE(hdr->flags);
    u32 qd = hdr->qdcount, an = hdr->ancount, ns = hdr->nscount, ar = hdr->arcount;

    pres->rcode = DNS_HDR_RCODE(hdr->flags);
    pres->sec_off[DNS_SECTION_QUESTION] = off;
    ps->qd = qd;
    ps->total = an + ns + ar;

    if (opcode == DNS_OPCODE_DSO) {
        // RFC 8490 5.4: no sections, but TLVs up to the end of the message
        if (qd || an || ns || ar) return DNS_ERR_FORMAT;

        pres->sec_off[DNS_SECTION_ANSWER] = off;
        pres->sec_off[DNS_SECTION_AUTHORITY] = off;
        pres->sec_off[DNS_SECTION_ADDITIONAL] = off;

        ps->dso = 1;
        ps->in_rdata = 1;
        ps->rd_end = ps->m.end;
        ps->s = S_TLV;
        return 0;
    }

    // RFC 9619 4
    if (opcode == DNS_OPCODE_QUERY && qd > 1) return DNS_ERR_FORMAT;

    // RFC 2136 3.1.1, the zone section of an update holds a single SOA
    if (opcode == DNS_OPCODE_UPDATE && !(hdr->flags & DNS_FLAG_QR) && qd != 1) return DNS_ERR_FORMAT;

    return _next_entry(ps, pres, off);
}

// Stores the value `v` of `field`, whose last byte is at `i`.
static __always_inline int _store(struct dns_parse_state *ps, struct dns_parse_res *pres, struct dns_rr *out, u32 field, u32 v, u32 i) {
    struct dns_rr *rr = &ps->rr;
    u16 hflags = pres->hdr.flags;
    bool update = DNS_OPCODE(hflags) == DNS_OPCODE_UPDATE;

    switch (field) {
    case DNS_FIELD_QTYPE:
        // RFC 2136 3.1.1
        if (update && !(hflags & DNS_FLAG_QR) && v != DNS_TYPE_SOA) return DNS_ERR_FORMAT;
        rr->type = v;
        return 0;
    case DNS_FIELD_QCLASS:
    case DNS_FIELD_CLASS:
        rr->class = v;
        return 0;
    case DNS_FIELD_TYPE:
        rr->type = v;
        if (v == DNS_TYPE_OPT) {
            // RFC 6891 6.1.1
            if (rr->section != DNS_SECTION_ADDITIONAL || rr->name.len != 1) return DNS_ERR_FORMAT;
            if (pres->flags & DNS_RES_EDNS) return DNS_ERR_FORMAT;
        }
        else if (v == DNS_TYPE_TSIG) {
            // RFC 8945 5.1, the last record of the additional section
            if (rr->section != DNS_SECTION_ADDITIONAL || ps->idx + 1 != ps->total) return DNS_ERR_FORMAT;
        }
        return 0;
    case DNS_FIELD_TTL:
        rr->ttl = v;
        return 0;
    case DNS_FIELD_TLV_LEN:
        ps->skip = v;
        ps->skip_ends = 0;
        return 0;
    }

    // what is left are the RDATA lengths
    rr->rdlen = v;
    rr->rdata_off = i + 1;
    ps->rd_end = i + 1 + v;
    if (ps->rd_end > ps->m.end) return DNS_ERR_FORMAT;

    // RFC 2136 2.4, 2.5: prerequisites and updates may come without RDATA
    if (v == 0 && (update || field == DNS_FIELD_RDLEN_SKIP || field == DNS_FIELD_RDLEN_TLV)) {
        return _end_entry(ps, pres, out, i + 1);
    }

    if (field == DNS_FIELD_RDLEN_A && v != 4) return DNS_ERR_FORMAT;
    if (field == DNS_FIELD_RDLEN_AAAA && v != 16) return DNS_ERR_FORMAT;

    if (field == DNS_FIELD_RDLEN || field == DNS_FIELD_RDLEN_TLV) {
        ps->in_rdata = 1;
        return 0;
    }

    ps->skip = v;
    ps->skip_ends = 1;
    return 0;
}

// Reads the byte `c` at `i` of the message.
//
// Returns 0 to go on, 1 once the message ended or the record to extract was
// read, or one of the `DNS_ERR_*`.
__noinline __weak int _dns_step(struct dns_parse_state *ps __arg_nonnull, struct dns_parse_res *pres __arg_nonnull,
                                struct dns_rr *out, u32 c, u32 i) {
    // RDATA the DFA walks may only end where a TLV of it would start
    if (ps->in_rdata && i >= ps->rd_end) {
        if (i != ps->rd_end || ps->s != S_TLV || ps->skip > 0) return DNS_ERR_FORMAT;

        int ret = _end_entry(ps, pres, out, i);
        if (ret != 0) return ret;
    }

    if (ps->skip > 0) {
        ps->skip -= 1;
        if (ps->skip == 0 && ps->skip_ends) return _end_entry(ps, pres, out, i + 1);
        return 0;
    }

    struct trans t = s2ts[ps->s & (MAX_STATES - 1)][c & (MAX_EDGES - 1)];
    struct dns_action act = a2as[t.action & (MAX_ACTIONS - 1)];
    if (t.state == 0 || act.kind == DNSA_ERR) {
        bpf_debug("dns: malformed at %d (state %d, byte %d)", i, ps->s, c);
        return DNS_ERR_FORMAT;
    }

    ps->s = t.state;

    int ret = 0;
    switch (act.kind) {
    case DNSA_HDR: {
        u16 v = (ps->acc << 8) | c;
        ps->acc = v;
        if ((act.val & 1) == 0) break;

        ps->acc = 0;
        switch (act.val >> 1) {
        case 0: pres->hdr.id = v; break;
        case 1: pres->hdr.flags = v; break;
        case 2: pres->hdr.qdcount = v; break;
        case 3: pres->hdr.ancount = v; break;
        case 4: pres->hdr.nscount = v; break;
        default: pres->hdr.arcount = v; return _begin(ps, pres, i + 1);
        }
        break;
    }
    case DNSA_LABEL:
        ret = _name_add(ps, i, 1 + act.val);
        ps->name_labels += 1;
        ps->skip = act.val;
        ps->skip_ends = 0;
        break;
    case DNSA_ROOT:
        ret = _name_add(ps, i, 1);
        _name_end(ps, i);
        break;
    case DNSA_PTR_HI:
        _name_begin(ps, i);
        ps->acc = act.val;
        break;
    case DNSA_PTR_LO: {
        // the header holds no names, and a pointer has to lead before the
        // name it is part of
        u32 target = ps->m.base + ((ps->acc << 8) | c);
        ps->acc = 0;
        if (target < ps->m.base + DNS_HDR_LEN || target >= ps->name_start) return DNS_ERR_FORMAT;

        // the walk of the name extraction takes a step for each label and
        // the pointer, which leave fewer for the rest
        int len = _dns_name(&ps->m, target, 0, NULL, ps->name_labels + 1);
        if (len < 0) return len;

        ret = _name_add(ps, i, len);
        _name_end(ps, i);
        break;
    }
    case DNSA_ACC:
        ps->acc = (ps->acc << 8) | c;
        break;
    case DNSA_STORE: {
        u32 v = (ps->acc << 8) | c;
        ps->acc = 0;
        ret = _store(ps, pres, out, act.val, v, i);
        break;
    }
    }

    if (ret != 0) return ret;

    if (act.flags & DNSF_END) {
        // the RDATA of a record has to end with what the DFA walked of it
        if (ps->qd == 0 && i + 1 != ps->rd_end) return DNS_ERR_FORMAT;
        return _end_entry(ps, pres, out, i + 1);
    }

    return 0;
}

// Ends the walk at the end of the message.
//
// Returns 1, or one of the `DNS_ERR_*` if the message ended before its last
// entry did.
__noinline __weak int _dns_finish(struct dns_parse_state *ps __arg_nonnull, struct dns_parse_res *pres __arg_nonnull,
                                  struct dns_rr *out) {
    u32 end = ps->m.end;

    if (ps->in_rdata) {
        if (ps->rd_end != end || ps->s != S_TLV || ps->skip > 0) return DNS_ERR_FORMAT;

        if (ps->dso) {
            ps->done = end;
            return 1;
        }

        int ret = _end_entry(ps, pres, out, end);
        if (ret != 0) return ret;
    }

    // RFC 2181 9, a truncated message may lack the entries that did not fit
    if (ps->skip > 0 || ps->in_name || ps->entry != end) return DNS_ERR_FORMAT;
    if (ps->s != S_QNAME && ps->s != S_RRNAME) return DNS_ERR_FORMAT;
    if (!(pres->hdr.flags & DNS_FLAG_TC)) return DNS_ERR_FORMAT;

    pres->flags |= DNS_RES_PARTIAL;
    ps->done = end;
    return 1;
}

// Walks the message `ps` describes from its header to its end, byte by byte.
//
// Returns 1 once it ended or the record to extract was read, or one of the
// `DNS_ERR_*`.
static __always_inline int _run(const u8 *data, const u8 *data_end, struct dns_parse_state *ps,
                                struct dns_parse_res *pres, struct dns_rr *out) {
    u32 start = ps->m.base;
    u32 end = ps->m.end;
    bpf_clamp_uminmax(end, 0, MAX_BYTES + 1);

    ps->s = S_HDR;

    u32 i;
    bpf_for(i, start, end) {
        if (data + i + 1 > data_end) return DNS_ERR_FORMAT;

        int ret = _dns_step(ps, pres, out, data[i], i);
        if (ret != 0) return ret;
    }

    return _dns_finish(ps, pres, out);
}

// Parses the message at `off` of the buffer between `data` and `data_end`. See
// `BEEPER_DNS_PARSE_SKB`.
static __always_inline int _parse(const u8 *data, const u8 *data_end, u32 off, u32 flags,
                                  struct dns_parse_res *pres) {
    bool tcp = (flags & DNS_PARSE_TCP) != 0;
    __builtin_memset(pres, 0, sizeof(*pres));

    struct dns_parse_state ps = { .want = -1 };
    ps.m = _new_msg_ctx((u64)(long)data, (u64)(long)data_end);

    u32 size = ps.m.size;
    if (size > MAX_BYTES + 1) {
        if (!tcp) return DNS_ERR_LIMIT;
        size = MAX_BYTES + 1;
    }
    if (off >= size) return DNS_ERR_INCOMPLETE;

    ps.m.size = size;
    ps.m.base = off;
    ps.m.end = size;

    u32 base = off;
    u32 len = size - off;
    if (tcp) {
        // RFC 1035 4.2.2, RFC 7766 8
        u16 prefix = 0;
        if (_dns_u16(&ps.m, off, &prefix) < 0) return DNS_ERR_INCOMPLETE;

        base = off + 2;
        len = prefix;
        pres->len = len;

        if (base + len > MAX_BYTES + 1) return DNS_ERR_LIMIT;
        if (base + len > size) return DNS_ERR_INCOMPLETE;
    }

    if (len < DNS_HDR_LEN) return DNS_ERR_FORMAT;

    ps.m.base = base;
    ps.m.end = base + len;
    pres->base = base;

    int ret = _run(data, data_end, &ps, pres, NULL);
    if (ret < 0) return ret;

    if (ps.done != ps.m.end) {
        // over TCP the length prefix frames the message exactly
        if (tcp) return DNS_ERR_FORMAT;
        pres->flags |= DNS_RES_TRAILING;
    }

    if (!tcp) len = ps.done - base;
    pres->len = len;

    return tcp ? 2 + len : len;
}

// Extracts the record at `idx` of the message `pres` describes, walking it once
// more up to there. See `BEEPER_DNS_EXTRACT_RR_MSG`.
static __always_inline int _extract_rr(const u8 *data, const u8 *data_end, const struct dns_parse_res *pres,
                                       u32 idx, struct dns_rr *rr) {
    const struct dns_header *hdr = &pres->hdr;
    if (DNS_OPCODE(hdr->flags) == DNS_OPCODE_DSO) return DNS_ERR_END;
    if (idx >= (u32)hdr->ancount + hdr->nscount + hdr->arcount) return DNS_ERR_END;

    struct dns_parse_state ps = { .want = idx };
    ps.m = _new_msg_ctx((u64)(long)data, (u64)(long)data_end);
    ps.m.base = pres->base;
    ps.m.end = pres->base + pres->len;
    if (ps.m.end > ps.m.size) return DNS_ERR_FORMAT;

    struct dns_parse_res scratch = { 0 };
    int ret = _run(data, data_end, &ps, &scratch, rr);
    if (ret < 0) return ret;

    // a truncated message may hold fewer records than the counts announce
    return ps.found ? 0 : DNS_ERR_END;
}

static __always_inline int _extract_name(struct msg_ctx *m __arg_nonnull,
                                        const struct dns_parse_res *pres __arg_nonnull,
                                        u32 off, u32 flags, struct dns_name_buf *out __arg_nonnull) {
    m->base = pres->base;
    m->end = pres->base + pres->len;

    if (off < m->base + DNS_HDR_LEN || off >= m->end) return DNS_ERR_FORMAT;

    int ret = _dns_name(m, off, flags, out, 0);
    if (ret < 0) return ret;

    return out->len;
}

SEC("freplace")
int parse_msg(struct sk_msg_md *msg, u32 off, struct dns_parse_res *pres __arg_nonnull) {
    if (bpf_msg_pull_data(msg, 0, msg->size, 0) < 0) return DNS_ERR_LIMIT;

    int res = _parse((const u8 *)(long)msg->data, (const u8 *)(long)msg->data_end, off, DNS_PARSE_TCP, pres);
    bpf_debug("parsed dns message at %d: %d", off, res);

    return res;
}

SEC("freplace")
int parse_skb(struct __sk_buff *skb, u32 off, u32 flags, struct dns_parse_res *pres __arg_nonnull) {
    if (bpf_skb_pull_data(skb, skb->len) < 0) return DNS_ERR_LIMIT;

    int res = _parse((const u8 *)(long)skb->data, (const u8 *)(long)skb->data_end, off, flags, pres);
    bpf_debug("parsed dns message at %d: %d", off, res);

    return res;
}

SEC("freplace")
int extract_rr_msg(const struct sk_msg_md *msg, const struct dns_parse_res *pres __arg_nonnull, u32 idx, struct dns_rr *rr __arg_nonnull) {
    return _extract_rr((const u8 *)(long)msg->data, (const u8 *)(long)msg->data_end, pres, idx, rr);
}

SEC("freplace")
int extract_rr_skb(const struct __sk_buff *skb, const struct dns_parse_res *pres __arg_nonnull, u32 idx, struct dns_rr *rr __arg_nonnull) {
    return _extract_rr((const u8 *)(long)skb->data, (const u8 *)(long)skb->data_end, pres, idx, rr);
}

SEC("freplace")
int extract_name_msg(const struct sk_msg_md *msg, const struct dns_parse_res *pres __arg_nonnull, u32 off, u32 flags, struct dns_name_buf *out __arg_nonnull) {
    struct msg_ctx m = _new_msg_ctx((u64)(long)msg->data, (u64)(long)msg->data_end);
    return _extract_name(&m, pres, off, flags, out);
}

SEC("freplace")
int extract_name_skb(const struct __sk_buff *skb, const struct dns_parse_res *pres __arg_nonnull, u32 off, u32 flags, struct dns_name_buf *out __arg_nonnull) {
    struct msg_ctx m = _new_msg_ctx((u64)(long)skb->data, (u64)(long)skb->data_end);
    return _extract_name(&m, pres, off, flags, out);
}
