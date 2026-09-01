#include "vmlinux.h"
#include "beeper.h"
#include "xbpf.h"
#include <bpf/bpf_helpers.h>

// The parser for HTTP/2 messages. It decodes the HPACK representation of a
// header block far enough to find the field names and values, matches the names
// against the DFA user space injected into `s2ts`, and mirrors the peer's
// dynamic table so that fields which are only referenced by index can be
// resolved as well.

// The number of bytes of a name or a value that are kept in a table entry.
// Longer fields are truncated, which bounds the copies for the verifier.
// `header_field`, which both tables are made of, is declared in beeper.h so
// that a target program reading dynamic table entries with
// `BEEPER_H2_GET_DT_ENTRY` agrees on its layout.
#define HEADER_FIELD_MAXLEN BEEPER_H2_FIELD_MAXLEN
#define HEADER_FIELD_MASK (HEADER_FIELD_MAXLEN - 1)

// The number of entries of the HPACK static table, see appendix A of RFC 7541.
#define STATIC_TABLE_SIZE 61

// The identifier of the SETTINGS parameter announcing the size of the dynamic
// table.
#define SETTINGS_HEADER_TABLE_SIZE 0x1

// The length of a frame header, see section 4.1 of RFC 9113.
#define H2_FRAME_HDR_LEN 9

// The frame types the parser reads. Every other one is skipped.
#define H2_HEADERS_FRAME 0x01
#define H2_SETTINGS_FRAME 0x04
#define H2_CONTINUATION_FRAME 0x09

// The flags of a HEADERS frame that move the header block within it, and the
// one saying that the block ends with the frame rather than carrying on into a
// CONTINUATION frame. See sections 6.2 and 6.10 of RFC 9113.
#define H2_END_HEADERS_FLAG 0x04
#define H2_PADDED_FLAG 0x08
#define H2_PRIORITY_FLAG 0x20

// The number of bytes the priority of a HEADERS frame takes up, a stream
// dependency and a weight.
#define H2_PRIORITY_LEN 5

// The HPACK static table. User space populates and freezes it when the parser
// is attached.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, STATIC_TABLE_SIZE+1);
    __type(key, u32);
    __type(value, struct header_field);
} static_table SEC(".maps");

// The dynamic table is per connection, and its entries are addressed by the
// order in which they were added.
struct dynamic_table_key {
    struct ip4_conn conn;
    u32 idx;
};

// An entry of the dynamic table, along with the size it accounts for in the
// table, which is computed from the decoded lengths of its name and value.
struct dynamic_table_entry {
    struct header_field field;
    u32 size;
};

// The dynamic table of every connection the parser has seen a header block on.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct dynamic_table_key);
	__type(value, struct dynamic_table_entry);
} dynamic_table SEC(".maps");

// Scratch space for the entry that is being added to the dynamic table. An
// entry is far too large for the stack the verifier allows.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct dynamic_table_entry);
} dynamic_table_entry SEC(".maps");

// The state of the dynamic table of a connection. `deleted` counts the entries
// that were evicted, which is what turns an HPACK index, counted from the most
// recently added entry, into the index an entry is stored under.
struct dynamic_table_info {
    u32 count;
    u32 size;
    u32 max_size;
    u32 deleted;

    // Whether the table has drifted from the peer's, which happens when a
    // header block is split over frames in the middle of a field: the parser
    // cannot address the half that is already gone, so the entry the peer adds
    // is one it cannot mirror. A table that has drifted is neither added to nor
    // resolved from, as its indices no longer mean what the peer means by them.
    u32 dirty;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct ip4_conn);
	__type(value, struct dynamic_table_info);
} dynamic_table_info SEC(".maps");

// The states the shape of a header field representation is walked with. HPACK
// spells a field out as a sequence of integers and strings, and which one comes
// next is decided by the bytes read so far, so it is the DFA that keeps track
// of it rather than the parser.
//
// User space fills the rows of `s2ts` these index, and hands out the ids from
// `S_RESERVED` on to the states of the field name trie. They must stay in sync
// with the state ids of h2/hpack.rs.

// A field name that matched no pattern. It carries no transition of its own, so
// the parser stays in it until the name it is reading ends.
#define S_DEAD 2

// At the first byte of a field representation.
#define S_FIELD 3

// At the first byte of the length of a field name, respectively of a value.
#define S_KEY_LEN 4
#define S_VAL_LEN 5

// The root of the trie of the field names to capture.
#define S_NAME 6

// The continuation of an integer that did not fit into the prefix of its first
// byte. There is one state per representation, as what the integer means
// differs, and one per Huffman bit for the lengths, as that bit is announced by
// the first byte but is only recorded once the last one has been read.
#define S_IDX7_CONT 7
#define S_IDX6_CONT 8
#define S_IDX4_CONT 9
#define S_STG_CONT 10
#define S_KEY_LEN_CONT 11
#define S_KEY_LEN_CONT_HUFF 12
#define S_VAL_LEN_CONT 13
#define S_VAL_LEN_CONT_HUFF 14

// The number of state ids the ones above reserve.
#define S_RESERVED 15

// What the parser does upon taking a transition. Must stay in sync with the
// action kinds of h2/hpack.rs.

// Nothing.
#define H2A_NONE 0

// A field spelled out by nothing but an index: `val` addresses the entry of the
// static or the dynamic table both its name and its value are read from.
#define H2A_INDEXED 1

// A field whose name is an index and whose value is spelled out: `val`
// addresses the entry the name is read from.
#define H2A_IDX_NAME 2

// A field whose name is spelled out as well.
#define H2A_LIT_NAME 3

// The length of a field name, respectively of a value: `val` counts the bytes
// it occupies on the wire.
#define H2A_KEY_LEN 4
#define H2A_VAL_LEN 5

// A dynamic table size update: `val` is the size the peer resizes to.
#define H2A_TABLE_SIZE 6

// The first byte of an integer that does not fit into the prefix of that byte:
// `val` is the prefix maximum the integer is counted from.
#define H2A_INT_START 7

// A byte of such an integer that is not its last one either.
#define H2A_INT_CONT 8

// The name of the field being read just matched a pattern, `val` being the id
// its value is to be captured under.
#define H2A_CAPTURE 9

// The representation is malformed. There is no telling where the next field
// starts, so the rest of the block is dropped.
#define H2A_ERR 10

// The string the action describes is Huffman coded.
#define H2F_HUFF (1 << 0)

// The field the action describes is added to the dynamic table.
#define H2F_ADD_DT (1 << 1)

// The integer the action describes is spread over several bytes, so it is to be
// read out of the accumulator rather than out of `val`.
#define H2F_CONT (1 << 2)

// A single action of the DFA. `val` is an index, a length or a table size,
// depending on `kind`.
//
// Actions are kept in a table of their own because they do not fit into the 16
// bits `struct trans` carries; the action of a transition is the index of its
// entry. Keeping them on the transition rather than on the state it leads to is
// what keeps the automaton small: every index a representation can carry is a
// transition of its own, but all of them lead to the same handful of states.
struct h2_action {
    u16 val;
    u8 kind;
    u8 flags;
};

// these restrictions are needed to make the verifier happy. All three are
// masked onto an index, so all three have to be powers of two.
#define MAX_STATES 1024
#define MAX_TRANS 256
#define MAX_ACTIONS 1024

// The transition table of the DFA, indexed by state and input byte, and the
// actions its transitions carry. User space fills both in before the program is
// loaded, after which they are read-only.
volatile const struct trans s2ts[MAX_STATES][MAX_TRANS];
volatile const struct h2_action a2as[MAX_ACTIONS];

// Reads the action a transition carries. Transition 0 is the one a state
// without a transition for the byte it read falls back to, and carries none.
static __always_inline struct h2_action _action(u16 id) {
    return a2as[id & (MAX_ACTIONS - 1)];
}

// The length of the longest code of the HPACK Huffman code.
#define HPACK_HUFF_MAXLEN 30

// The HPACK Huffman code of appendix B of RFC 7541, flattened into the number
// of symbols per code length and the first code of each length. That is enough
// to tell where a code ends, which is all the parser needs.
static const u8 huff_count[HPACK_HUFF_MAXLEN + 2] = {
    0, 0, 0, 0, 0, 10, 26, 32, 6, 0, 5, 3, 2, 6, 2, 3,
    0, 0, 0, 3, 8, 13, 26, 29, 12, 4, 15, 19, 29, 0, 4, 0
};

static const u32 huff_first_code[HPACK_HUFF_MAXLEN + 2] = {
    0, 0, 0, 0, 0, 0, 20, 92, 248, 508, 1016, 2042, 4090, 8184, 16380, 32764,
    65534, 131068, 262136, 524272, 1048550, 2097116, 4194258, 8388568, 16777194,
    33554412, 67108832, 134217694, 268435426, 536870910, 1073741820, 0
};

// Consumes bit `b` of `c`. Once the bits read so far form a valid code, a
// symbol is counted and the next code starts. A run that grows past the longest
// code is the EOS padding of the last byte and is dropped.
#define HPACK_HUFF_STEP(c, b) do {                              \
    code = (code << 1) | (((c) >> (b)) & 1u);                   \
    len++;                                                      \
    if (len > HPACK_HUFF_MAXLEN) {                                \
        code = 0;                                                \
        len = 0;                                                 \
    }                                                             \
    else {                                                        \
        u32 rel = code - huff_first_code[len];                    \
        if (rel < huff_count[len]) {                              \
            n++;                                                 \
            code = 0;                                             \
            len = 0;                                             \
        }                                                         \
    }                                                              \
} while (0)

// Returns the number of characters the Huffman encoded `src` decodes to. HPACK
// sizes a table entry by the decoded length of its name and value, so the
// mirrored table can only be evicted in step with the peer's if this is known.
static __always_inline u32 hpack_huffman_decoded_len(const u8 *src, u16 src__sz) {
    u32 code = 0, len = 0, n = 0;
    u32 i = 0;

    bpf_for (i, 0, src__sz) {
        u8 c = src[i];
        HPACK_HUFF_STEP(c, 7);
        HPACK_HUFF_STEP(c, 6);
        HPACK_HUFF_STEP(c, 5);
        HPACK_HUFF_STEP(c, 4);
        HPACK_HUFF_STEP(c, 3);
        HPACK_HUFF_STEP(c, 2);
        HPACK_HUFF_STEP(c, 1);
        HPACK_HUFF_STEP(c, 0);
    }

    return n;
}

// The offsets of the header block of the frame at `data`, whose payload is
// `len` bytes long. A HEADERS frame may put a pad length and a priority in
// front of its block and pad it at the end, see section 6.2 of RFC 9113. Every
// other frame is nothing but its payload.
//
// Returns 0, or -1 if the frame is too short to hold what its flags announce.
static __always_inline int _h2_block(const u8 *data, const u8 *data_end, u32 len, u8 type, u8 flags, u16 *start, u16 *end) {
    u32 off = H2_FRAME_HDR_LEN;
    u32 pad_len = 0;

    if (type == H2_HEADERS_FRAME) {
        if ((flags & H2_PADDED_FLAG) != 0) {
            if (data + off + 1 > data_end) return -1;
            pad_len = data[off];
            off += 1;
        }

        if ((flags & H2_PRIORITY_FLAG) != 0) off += H2_PRIORITY_LEN;
    }

    if (off + pad_len > H2_FRAME_HDR_LEN + len) return -1;

    *start = off;
    *end = H2_FRAME_HDR_LEN + len - pad_len;

    return 0;
}

// Everything the parser needs of the message it walks, no matter whether that
// message came in as an sk_msg, an sk_buff or a dynptr: the bytes to parse and
// the connection they belong to, which is what keys the dynamic table.
struct msg_ctx {
    u8 *data;
    u8 *data_end;
    struct ip4_conn conn;
};

// Reads the stream id out of the frame header `data` points at. `data` must be
// known to hold at least the 9 bytes of a frame header.
static __always_inline struct h2_frame _new_h2_frame(const u8 *data, u8 type, u8 flags) {
    return (struct h2_frame) {
        // the top bit of the stream id is reserved
        .sid = ((u32)data[5] << 24 | (u32)data[6] << 16 | (u32)data[7] << 8 | (u32)data[8]) & 0x7FFFFFFF,
        .type = type,
        .flags = flags,
    };
}

// Builds the parse context of an sk_msg.
static __always_inline struct msg_ctx _new_msg_ctx(const struct sk_msg_md *msg) {
    return (struct msg_ctx) {
        .data = msg->data,
        .data_end = msg->data_end,
        .conn = {
            .local = {
                .ip4 = msg->local_ip4,
                .port = msg->local_port
            },
            .remote = {
                .ip4 = msg->remote_ip4,
                .port = bpf_ntohl(msg->remote_port)
            }
        }
    };
}

// Builds the parse context of an sk_buff.
static __always_inline struct msg_ctx _new_skb_ctx(const struct __sk_buff *skb) {
    return (struct msg_ctx) {
        .data = (u8 *)(long)skb->data,
        .data_end = (u8 *)(long)skb->data_end,
        .conn = {
            .local = {
                .ip4 = skb->local_ip4,
                .port = skb->local_port
            },
            .remote = {
                .ip4 = skb->remote_ip4,
                .port = bpf_ntohl(skb->remote_port)
            }
        }
    };
}

// Builds the key the `idx`th entry of `conn`'s dynamic table is stored under.
static __always_inline struct dynamic_table_key _new_dynamic_table_key(const struct ip4_conn *conn, u32 idx) {
    return (struct dynamic_table_key) {
        .conn = *conn,
        .idx = idx
    };
}

// Translates the HPACK index `idx`, which counts backwards from the entry that
// was added last, into the index the entry is stored under.
static __always_inline u32 _get_dynamic_table_index(const struct dynamic_table_info *dt_info __arg_nonnull, u32 idx) {
    u32 end_idx = STATIC_TABLE_SIZE + dt_info->count + dt_info->deleted;
    return (end_idx - idx) + STATIC_TABLE_SIZE;
}

// Resolves the match `m` into the bytes it refers to, either in the message
// itself or, if the peer only referenced the field by index, in the static or
// the dynamic table. `is_key` selects the name of a table entry over its value.
// `*out` is left untouched if the match cannot be resolved.
static __always_inline void _extract_match(const struct msg_ctx *ctx, const struct hdr_match *m, bool is_key, u8 **out, u32 *len, bool *huff) {
    if (m->in_msg) {
        if (ctx->data + m->idx + m->len > ctx->data_end) return;
        *out = ctx->data + m->idx;
        *len = m->len;
        if (huff) *huff = m->huff;
        return;
    }

    struct dynamic_table_entry *entry = NULL;
    if (m->idx > STATIC_TABLE_SIZE) {
        struct dynamic_table_info *dt_info = bpf_map_lookup_elem(&dynamic_table_info, &ctx->conn);
        if (dt_info == NULL) return;

        u32 idx = _get_dynamic_table_index(dt_info, m->idx);
        struct dynamic_table_key key = _new_dynamic_table_key(&ctx->conn, idx);
        entry = bpf_map_lookup_elem(&dynamic_table, &key);
    }
    else {
        u32 key = m->idx;
        entry = bpf_map_lookup_elem(&static_table, &key);
    }

    if (entry == NULL) return;
    barrier(); // this is needed so that clang doesn't reorder the null check

    if (is_key) {
        *out = entry->field.key;
        *len = entry->field.key_len;
        if (huff) *huff = (entry->field.key_huff != 0);
    } else {
        *out = entry->field.val;
        *len = entry->field.val_len;
        if (huff) *huff = (entry->field.val_huff != 0);
    }
}

// Follows the transition `input` takes out of `state`. A state that has no
// transition for `input` falls back to `S_DEAD`, which has none either: the
// rows the shape of a representation is walked with carry a transition per
// byte, so this only happens while a field name is being read, and a name that
// took a byte no pattern has cannot match one anymore.
static __always_inline void _next(u16 state, u8 input, u16 *next_state, u16 *action) {
    state &= MAX_STATES - 1;
    input &= MAX_TRANS - 1;

    struct trans t = s2ts[state][input];
    if (t.state == 0 && t.action == 0) {
        *next_state = S_DEAD;
        *action = 0;
        return;
    }

    *next_state = t.state;
    *action = t.action;
}

// Looks up the field the HPACK index `idx` refers to, in the static table if it
// is one of the first `STATIC_TABLE_SIZE` indices and in the dynamic table of
// `conn` otherwise. `*hf` is NULL if there is no such entry.
static __always_inline void _get_table_entry(const struct ip4_conn *conn __arg_nonnull, const struct dynamic_table_info *dt_info __arg_nonnull, u32 idx, struct header_field **hf) {
    if (idx > STATIC_TABLE_SIZE) {
        if (dt_info->dirty) {
            *hf = NULL;
            return;
        }

        u32 dt_idx = _get_dynamic_table_index(dt_info, idx);
        struct dynamic_table_key key = _new_dynamic_table_key(conn, dt_idx);

        bpf_trace("lookup dt: %d (hpack: %d)", dt_idx, idx);

        // `field` is the first member of `dynamic_table_entry`, so this cast
        // preserves NULL and avoids an extra branch on the lookup result.
        *hf = (struct header_field *)bpf_map_lookup_elem(&dynamic_table, &key);
    }
    else {
        *hf = bpf_map_lookup_elem(&static_table, &idx);
    }
}

// Walks the name trie over `key`, the name of a field the peer only referenced
// by index, and returns the id of the capture it matched, or -1 if the name
// matches no pattern.
//
// It is only reached through `_run_action`, so the walk is verified once rather
// than as part of every byte of the block the parser reads.
static __always_inline int _match_header_key(const u8 *key __arg_nonnull, u16 key__sz) {
    u16 s = S_NAME;
    u16 j = 0;
    bpf_for(j, 0, key__sz) {
        u16 a = 0;
        _next(s, key[j], &s, &a);

        struct h2_action act = _action(a);
        if (act.kind == H2A_CAPTURE) return act.val & MAX_MATCH_MASK;
    }

    return -1;
}

// Returns the state of `conn`'s dynamic table, creating an empty table with the
// default maximum size of RFC 7540 if this is the first header block seen on
// the connection. Returns NULL if the table could not be created.
static __always_inline struct dynamic_table_info* _get_dynamic_table(const struct ip4_conn *conn __arg_nonnull) {
    struct dynamic_table_info *info = bpf_map_lookup_elem(&dynamic_table_info, conn);
    if (info) return info;

    struct dynamic_table_info new_info = {
        .count = 0,
        .size = 0,
        .max_size = 4096,
        .deleted = 0,
        .dirty = 0,
    };
    bpf_map_update_elem(&dynamic_table_info, conn, &new_info, BPF_ANY);
    return bpf_map_lookup_elem(&dynamic_table_info, conn);
}

// Evicts the oldest entries of the dynamic table until an entry of
// `new_entry_size` fits into it, which is what section 4.4 of RFC 7541 has the
// peer do before adding one. Returns the number of bytes freed.
//
// An entry that does not fit into the empty table frees all of them, and is
// then dropped by the caller, which is what the peer does with it as well.
__noinline __weak u32 _try_evict_dynamic_table_entries(const struct msg_ctx *ctx __arg_nonnull, struct dynamic_table_info *dt_info __arg_nonnull, u32 new_entry_size) {
    bpf_trace("dt: try evicting %dB (%d actual entries)", new_entry_size, dt_info->count);

    u32 freed = 0;
    bpf_repeat(dt_info->count) {
        if (dt_info->size + new_entry_size <= dt_info->max_size) break;

        // entries are stored under the running count of the ones added so far,
        // so the oldest one that is still live sits right above the evicted
        u32 idx = STATIC_TABLE_SIZE + dt_info->deleted;
        struct dynamic_table_key key = _new_dynamic_table_key(&ctx->conn, idx);
        struct dynamic_table_entry *entry = bpf_map_lookup_elem(&dynamic_table, &key);
        if (!entry) {
            bpf_error("dt: no entry at index %d", idx);
            break;
        }

        bpf_trace("dt: evicting %dB entry at index %d", entry->size, idx);

        // the table has to shrink as the entries go, or the loop would not know
        // when it has freed enough
        dt_info->size -= entry->size;
        dt_info->count--;
        dt_info->deleted++;
        freed += entry->size;

        bpf_map_delete_elem(&dynamic_table, &key);
    }

    bpf_trace("dt: evicted %dB", freed);

    return freed;
}

// Adds the field made up of `key` and `val` to the dynamic table, evicting as
// many of the oldest entries as it takes to make room for it. Both matches are
// resolved first, as either of them may refer to an entry of a table rather
// than to the message itself.
//
// Returns 0 if the entry was added, -1 if it could not be resolved or does not
// fit into the table even when emptied, in which case the peer drops it too.
__noinline __weak int _add_dynamic_table_entry(const struct msg_ctx *ctx __arg_nonnull, struct dynamic_table_info *dt_info __arg_nonnull, const struct hdr_match *key __arg_nonnull, const struct hdr_match *val __arg_nonnull) {
    if (dt_info->dirty) return -1;

    u8 *key_ptr = NULL;
    u32 key_len = 0;
    bool key_huff = false;
    _extract_match(ctx, key, true, &key_ptr, &key_len, &key_huff);
    if (!key_ptr) return -1;

    u8 *val_ptr = NULL;
    u32 val_len = 0;
    bool val_huff = false;
    _extract_match(ctx, val, false, &val_ptr, &val_len, &val_huff);
    if (!val_ptr) return -1;

    key_len = key_len & HEADER_FIELD_MASK;
    val_len = val_len & HEADER_FIELD_MASK;

    int per_cpu_key = 0;
    struct dynamic_table_entry *dt_val = bpf_map_lookup_elem(&dynamic_table_entry, &per_cpu_key);
    if (!dt_val) return -1;

    u32 idx = STATIC_TABLE_SIZE + dt_info->count + dt_info->deleted;
    struct dynamic_table_key dt_key = _new_dynamic_table_key(&ctx->conn, idx);

    __builtin_memset(dt_val, 0, sizeof(*dt_val));
    int ret = bpf_probe_read_kernel(dt_val->field.key, key_len, key_ptr);
    dt_val->field.key_len = !ret * key_len;

    ret = bpf_probe_read_kernel(dt_val->field.val, val_len, val_ptr);
    dt_val->field.val_len = !ret * val_len;

    dt_val->field.key_huff = key_huff;
    dt_val->field.val_huff = val_huff;

    u16 key_len_decoded = key_huff ? hpack_huffman_decoded_len(dt_val->field.key, key_len) : key_len;
    u16 val_len_decoded = val_huff ? hpack_huffman_decoded_len(dt_val->field.val, val_len) : val_len;
    dt_val->size = key_len_decoded + val_len_decoded + 32;

    _try_evict_dynamic_table_entries(ctx, dt_info, dt_val->size);
    if (dt_info->size + dt_val->size > dt_info->max_size) {
        bpf_debug("dt: entry size %d exceeds max size %d", dt_val->size, dt_info->max_size);
        return -1;
    }

    bpf_map_update_elem(&dynamic_table, &dt_key, dt_val, BPF_ANY);

    dt_info->size += dt_val->size;
    dt_info->count += 1;

    bpf_debug("dt: add with index %d, key size: %d, val size: %d, new total size %d", dt_key.idx, key_len_decoded, val_len_decoded, dt_info->size);
    bpf_debug("dt: add key { %d %d %d }", key->idx, key->len, key->in_msg);
    bpf_debug("dt: add val { %d %d %d }", val->idx, val->len, val->in_msg);

    return 0;
}

// Reads the settings of a SETTINGS frame, which are 6 bytes each, and applies
// the ones that resize the dynamic table. Returns the offset it stopped at.
//
// See `_parse_hdr_from` for `start`, `end` and `null_prefix`.
static __always_inline int _parse_stg_from(const struct msg_ctx *ctx, u16 start, u16 end, u16 *s, struct parse_res *pres, u16 *null_prefix) {
    const u8 *data = ctx->data;
    const u8 *data_end = ctx->data_end;
    u32 len = (u32)(data_end - data) & MAX_BYTES;
    if (end < len) len = end & MAX_BYTES;
    if (data + 9 > data_end) return 0;

    u8 type = data[3];
    u8 flags = data[4];
    u32 stream_id = data[5] << 24 | data[6] << 16 | data[7] << 8 | data[8];

    struct dynamic_table_info *dt_info = _get_dynamic_table(&ctx->conn);
    if (!dt_info) return 0;

    u32 i = 0;
    u8 j = 0;
    u16 id = 0;
    u32 val = 0;

    bpf_for(i, start, len+1) {
        if (data + i + 1 > data_end) break;
        u8 c = data[i];

        // skb clears the TLS header, but does not remove it
        if (null_prefix && c == '\0' && i == *null_prefix) {
            *null_prefix = i + 1;
            continue;
        }

        if (j < 2) {
            id = (id << 8) | c;
        }
        else {
            val = (val << 8) | c;
        }
        j++;

        if (j == 6) {
            if (id == SETTINGS_HEADER_TABLE_SIZE) {
                dt_info->max_size = (u16)val;
                bpf_debug("stg: table header size: %u", (u16)val);
            }
            j = 0;
            id = 0;
            val = 0;
        }
    }

    return i;
}

// Everything the parser carries from one byte of a header block to the next,
// along with the transition it is about to run. The DFA holds the shape of a
// representation, so what is left is the integer a multi byte length or index
// accumulates into, how many bytes of the string that was announced are still
// to come, and the field being assembled out of the two.
struct h2_parse_state {
    // the state of the DFA
    u16 s;

    // the integer being accumulated and the shift of its next byte
    u32 k;
    u32 m;

    // the bytes of the string that was announced that are still to be read, and
    // whether they are a name, which is walked so that it can match a pattern,
    // rather than a value, which is only counted
    u32 skip;
    bool is_key;

    // the capture the name of the field being read matched, or -1
    s8 cid;

    // whether the peer adds the field being read to its dynamic table
    u8 add_to_dt;

    // the name of that field
    struct hdr_match key;

    // the offset of the byte being read, and the action and the integer of the
    // transition it took
    u32 i;
    u32 v;
    u8 kind;
    u8 flags;
};

// The state of a header block that carries on into a CONTINUATION frame, see
// section 6.10 of RFC 9113.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct ip4_conn);
    __type(value, struct h2_parse_state);
} continued_blocks SEC(".maps");

// Returns the state a header block is read from its first byte with.
static __always_inline struct h2_parse_state _new_h2_parse_state(void) {
    return (struct h2_parse_state) {
        .s = S_FIELD,
        .k = 0,
        .m = 0,
        .skip = 0,
        .is_key = false,
        .cid = -1,
        .add_to_dt = 0,
        .key = {
            .idx = 0,
            .len = 0,
            .in_msg = true,
            .huff = false,
        },
        .i = 0,
        .v = 0,
        .kind = H2A_NONE,
        .flags = 0,
    };
}

// Runs the action of the transition `ps` holds, which is what turns the parts
// of a field the DFA picked out into a capture, into an entry of the mirrored
// dynamic table, or into both.
//
// It is a program of its own so that it is verified once rather than as part of
// every byte of the block the parser reads.
//
// Returns 0, or -1 if the block cannot be read any further.
__noinline __weak int _run_action(const struct msg_ctx *ctx __arg_nonnull, struct dynamic_table_info *dt_info __arg_nonnull, struct parse_res *pres __arg_nonnull, struct h2_parse_state *ps __arg_nonnull) {
    u32 v = ps->v & MAX_BYTES;

    bpf_trace("hdr: %d: kind %d, val %d", ps->i, ps->kind, v);

    // a name that is an index has to be read out of a table before it can be
    // matched. Both representations that carry one are handled here, so that the
    // walk over the entry is only built into the program once
    if (ps->kind == H2A_INDEXED || ps->kind == H2A_IDX_NAME) {
        ps->add_to_dt = (ps->flags & H2F_ADD_DT) != 0;
        ps->cid = -1;
        ps->key = (struct hdr_match) {
            .idx = v,
            .len = 0,
            .in_msg = false,
            .huff = false,
        };

        struct header_field *hf = NULL;
        _get_table_entry(&ctx->conn, dt_info, v, &hf);
        if (hf == NULL) return 0;

        int mid = _match_header_key(hf->key, hf->key_len & HEADER_FIELD_MASK);
        if (mid < 0) return 0;

        if (ps->kind == H2A_IDX_NAME) {
            ps->cid = mid;
            return 0;
        }

        // both halves of the field are in the table, so the value is reported
        // as the index it is to be read back with
        pres->ms[mid & MAX_MATCH_MASK] = (struct hdr_match) {
            .idx = v,
            .len = HEADER_FIELD_MASK,
            .in_msg = false,
            .huff = false,
        };

        return 0;
    }

    if (ps->kind == H2A_LIT_NAME) {
        ps->add_to_dt = (ps->flags & H2F_ADD_DT) != 0;
        ps->cid = -1;
        return 0;
    }

    if (ps->kind == H2A_KEY_LEN) {
        ps->key = (struct hdr_match) {
            .idx = ps->i + 1,
            .len = v,
            .in_msg = true,
            .huff = (ps->flags & H2F_HUFF) != 0,
        };

        ps->skip = v;
        ps->is_key = true;
        if (v == 0) ps->s = S_VAL_LEN;

        return 0;
    }

    if (ps->kind == H2A_VAL_LEN) {
        struct hdr_match val = (struct hdr_match) {
            .idx = ps->i + 1,
            .len = v,
            .in_msg = true,
            .huff = (ps->flags & H2F_HUFF) != 0,
        };

        if (ps->add_to_dt) {
            _add_dynamic_table_entry(ctx, dt_info, &ps->key, &val);
        }

        if (ps->cid >= 0) {
            pres->ms[ps->cid & MAX_MATCH_MASK] = val;
            ps->cid = -1;
        }

        ps->skip = v;
        ps->is_key = false;

        return 0;
    }

    if (ps->kind == H2A_TABLE_SIZE) {
        bpf_debug("hdr: table size update: %u", v);
        dt_info->max_size = v;
        return 0;
    }

    if (ps->kind == H2A_ERR) {
        bpf_debug("hdr: malformed representation at %d", ps->i);
        return -1;
    }

    return 0;
}

// Decodes the header block between the offsets `start` and `end` and records
// the values of the fields whose name matches a pattern in `pres`. Fields the
// peer adds to its dynamic table are added to the mirrored one, so that later
// blocks can resolve the indices referring to them. `ps` is where the walk
// picks up, which for the beginning of a block is `_new_h2_parse_state`.
//
// `null_prefix` is the length of the run of NUL bytes at the beginning of the
// buffer that is to be skipped rather than parsed; it is updated as those bytes
// are consumed. It may be NULL if the data cannot carry such a prefix.
//
// Returns the offset it stopped at, which is `end` if the whole block was read.
static __always_inline int _parse_hdr_from(const struct msg_ctx *ctx, u16 start, u16 end, struct dynamic_table_info *dt_info, struct h2_parse_state *ps, struct parse_res *pres, u16 *null_prefix) {
    const u8 *data = ctx->data;
    const u8 *data_end = ctx->data_end;
    u32 len = (u32)(data_end - data) & MAX_BYTES;
    if (end < len) len = end & MAX_BYTES;

    u32 i = 0;
    bpf_for(i, start, len+1) {
        // the block ends before the message does when the message carries more
        // than one frame, so the loop cannot lean on the bounds check alone
        if (i >= len) break;
        if (data + i + 1 > data_end) break;
        u8 c = data[i];

        // skb clears the TLS header, but does not remove it
        if (null_prefix && c == '\0' && i == *null_prefix) {
            *null_prefix = i + 1;
            continue;
        }

        if (ps->skip > 0) {
            if (ps->is_key) {
                u16 a = 0;
                _next(ps->s, c, &ps->s, &a);

                struct h2_action act = _action(a);
                if (act.kind == H2A_CAPTURE) ps->cid = act.val & MAX_MATCH_MASK;
            }

            ps->skip--;
            // the name ended, so the length of the value comes next. A value
            // ends on the transition that announced it, which already leads
            // back to `S_FIELD`
            if (ps->skip == 0 && ps->is_key) ps->s = S_VAL_LEN;

            continue;
        }

        u16 a = 0;
        _next(ps->s, c, &ps->s, &a);
        struct h2_action act = _action(a);

        if (act.kind == H2A_INT_START) {
            ps->k = act.val;
            ps->m = 0;
            continue;
        }
        if (act.kind == H2A_INT_CONT) {
            // an integer wider than the longest block the parser reads is of no
            // use, and shifting by more than the width of the accumulator is
            // not defined. Such an integer is left short, which makes the field
            // it belongs to unresolvable rather than the block unparsable
            if (ps->m <= 28) {
                ps->k += (u32)(c & 0x7F) << ps->m;
                ps->m += 7;
            }

            continue;
        }

        ps->i = i;
        ps->v = act.val;
        if ((act.flags & H2F_CONT) != 0) {
            ps->v = ps->k;
            if (ps->m <= 28) ps->v += (u32)(c & 0x7F) << ps->m;
        }
        ps->kind = act.kind;
        ps->flags = act.flags;

        if (_run_action(ctx, dt_info, pres, ps) < 0) break;
    }

    return i;
}

// Reads the header block of a HEADERS or a CONTINUATION frame, picking up where
// the frame before it left off if the block is split over several of them.
//
// A field whose bytes straddle two frames has half of itself in a frame the
// parser cannot address anymore. The block itself stays readable, as the parser
// only has to count those bytes, but the field can neither be captured nor
// mirrored, so the dynamic table is marked as drifted.
//
// Returns the offset it stopped at, see `_parse_hdr_from`.
static __always_inline int _parse_hdr_frame(const struct msg_ctx *ctx, u16 start, u16 end, u8 type, u8 flags, struct parse_res *pres, u16 *null_prefix) {
    struct dynamic_table_info *dt_info = _get_dynamic_table(&ctx->conn);
    if (!dt_info) return start;

    struct h2_parse_state ps = _new_h2_parse_state();
    if (type == H2_CONTINUATION_FRAME) {
        struct h2_parse_state *resumed = bpf_map_lookup_elem(&continued_blocks, &ctx->conn);
        if (resumed == NULL) {
            bpf_debug("hdr: a continuation of a block that was not followed");
            return end;
        }

        ps = *resumed;
    }

    int res = _parse_hdr_from(ctx, start, end, dt_info, &ps, pres, null_prefix);

    if ((flags & H2_END_HEADERS_FLAG) != 0) {
        bpf_map_delete_elem(&continued_blocks, &ctx->conn);
        return res;
    }

    if (ps.skip > 0 && !dt_info->dirty) {
        bpf_debug("dt: a field split over two frames, the table has drifted");
        dt_info->dirty = 1;
    }

    // the pending field belongs to the frame that is ending, so nothing of it
    // survives into the next one
    ps.cid = -1;
    ps.add_to_dt = 0;

    bpf_map_update_elem(&continued_blocks, &ctx->conn, &ps, BPF_ANY);

    return res;
}

// Parses the frame the message starts with and describes it in `frame`, so that
// the caller can tell which stream it belongs to and where it ends. HEADERS
// frames are decoded into `pres`, SETTINGS frames are applied to the mirrored
// dynamic table and every other frame is skipped.
//
// The whole frame is pulled into the linear part of the message before it is
// parsed. A message may carry several frames, so a caller has to keep calling
// this until the message is consumed.
//
// Returns the number of bytes the frame occupies, or a negative value if the
// message ends before the frame does.
SEC("freplace")
int parse_msg(struct sk_msg_md *msg, struct parse_res *pres __arg_nonnull, struct h2_frame *frame __arg_nonnull) {
    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;

    if (data + H2_FRAME_HDR_LEN > data_end) return 0;

    u32 len = data[0] << 16 | data[1] << 8 | data[2];
    u8 type = data[3];
    u8 flags = data[4];
    u32 frame_len = H2_FRAME_HDR_LEN + len;

    *frame = _new_h2_frame(data, type, flags);

    bpf_debug("Parsing HTTP/2 message with length %d, type %d, flags %d", len, type, flags);

    bool is_hdr = (type == H2_HEADERS_FRAME || type == H2_CONTINUATION_FRAME);
    bool is_stg = (type == H2_SETTINGS_FRAME);
    if (!is_hdr && !(is_stg && flags == 0)) {
        return frame_len;
    }

    if (bpf_msg_pull_data(msg, 0, frame_len, 0) < 0) {
        return -(data_end - data);
    }

    struct msg_ctx ctx = _new_msg_ctx(msg);

    u16 start = 0, end = 0;
    if (_h2_block(ctx.data, ctx.data_end, len, type, flags, &start, &end) < 0) return -1;

    // the entry is only ever updated below, never deleted, so the pointer
    // stays good across the parse
    struct dynamic_table_info *dt_info = _get_dynamic_table(&ctx.conn);
    frame->dt_count_before = dt_info ? dt_info->count : 0;

    int res;
    if (is_hdr) {
        res = _parse_hdr_frame(&ctx, start, end, type, flags, pres, NULL);
    } else {
        u16 s = S_FIELD;
        res = _parse_stg_from(&ctx, start, end, &s, pres, NULL);
    }

    frame->dt_count = dt_info ? dt_info->count : 0;

    if (res < end) return -1;

    return frame_len;
}

// Parses the frame the packet starts with, pulling it into the linear part of
// the sk_buff first. Unlike `parse_msg`, this only decodes HEADERS frames. See
// `parse_msg` for the return value.
SEC("freplace")
int parse_skb(struct __sk_buff *skb, struct parse_res *pres __arg_nonnull, struct h2_frame *frame __arg_nonnull, u16 *null_prefix) {
    u8 *data = (u8 *)(long)skb->data;
    u8 *data_end = (u8 *)(long)skb->data_end;

    if (data + H2_FRAME_HDR_LEN > data_end) return 0;

    u32 len = data[0] << 16 | data[1] << 8 | data[2];
    u8 type = data[3];
    u8 flags = data[4];
    u32 frame_len = H2_FRAME_HDR_LEN + len;

    *frame = _new_h2_frame(data, type, flags);

    bpf_debug("Parsing HTTP/2 sk_buff with length %d, type %d, flags %d", len, type, flags);

    if (type != H2_HEADERS_FRAME && type != H2_CONTINUATION_FRAME) {
        return frame_len;
    }

    if (bpf_skb_pull_data(skb, frame_len) < 0) {
        return -(data_end - data);
    }

    struct msg_ctx ctx = _new_skb_ctx(skb);

    u16 start = 0, end = 0;
    if (_h2_block(ctx.data, ctx.data_end, len, type, flags, &start, &end) < 0) return -1;

    int res = _parse_hdr_frame(&ctx, start, end, type, flags, pres, null_prefix);
    if (res < end) return -1;

    return frame_len;
}

// Parses the frame `buf_ptr` starts with. A buffer carries no connection of its
// own, so `conn` has to name the one it belongs to for the dynamic table to be
// found. Only HEADERS frames are decoded. See `parse_msg` for the return value.
SEC("freplace")
int parse_buf(const struct bpf_dynptr *buf_ptr, struct ip4_conn *conn, struct parse_res *pres __arg_nonnull, struct h2_frame *frame __arg_nonnull, u16 *null_prefix) {
    u8 *data = bpf_dynptr_data(buf_ptr, 0, 9);
    if (data == NULL) return -1;

    u32 len = data[0] << 16 | data[1] << 8 | data[2];
    u8 type = data[3];
    u8 flags = data[4];
    u32 frame_len = H2_FRAME_HDR_LEN + len;

    *frame = _new_h2_frame(data, type, flags);

    bpf_debug("Parsing HTTP/2 buf with length %d, type %d, flags %d", len, type, flags);

    if (type != H2_HEADERS_FRAME && type != H2_CONTINUATION_FRAME) {
        return frame_len;
    }

    data = bpf_dynptr_data(buf_ptr, 0, frame_len);
    if (data == NULL) return -1;

    struct msg_ctx ctx = {
        .data = data,
        .data_end = data + frame_len,
        .conn = *conn
    };

    u16 start = 0, end = 0;
    if (_h2_block(ctx.data, ctx.data_end, len, type, flags, &start, &end) < 0) return -1;

    return _parse_hdr_frame(&ctx, start, end, type, flags, pres, null_prefix);
}

// Reads the `idx`th entry of `conn`'s dynamic table into `out`, `idx` counted
// as `_get_table_entry` counts it. Returns 0 on success, -1 if there is no
// such entry.
SEC("freplace")
int get_dt_entry(const struct ip4_conn *conn __arg_nonnull, u32 idx, struct header_field *out __arg_nonnull) {
    struct dynamic_table_info *dt_info = bpf_map_lookup_elem(&dynamic_table_info, conn);
    if (dt_info == NULL) return -1;

    struct header_field *hf = NULL;
    _get_table_entry(conn, dt_info, idx, &hf);
    if (hf == NULL) return -1;

    __builtin_memcpy(out, hf, sizeof(*out));

    return 0;
}

// Returns whether the parser captured a value for the match `idx`.
SEC("freplace")
bool matched(const struct sk_msg_md *msg, const struct parse_res *pres __arg_nonnull, u8 idx) {
    if (idx >= MAX_MATCHES) return false;

    struct hdr_match m = pres->ms[idx & MAX_MATCH_MASK];
    return (m.len > 0);
}

// Points `str` at the value captured for the match `idx`, still Huffman encoded
// if that is how it was sent. The value points either into `msg` or into one of
// the HPACK tables, so it is only valid until the program invalidates the data
// pointers of the message.
//
// Returns 0 on success, -1 if nothing was captured for `idx` or if the value
// can no longer be resolved.
SEC("freplace")
int extract_match(const struct sk_msg_md *msg, const struct parse_res *pres __arg_nonnull, u8 idx, struct hdr_str *str __arg_nonnull) {
    if (idx >= MAX_MATCHES) return -1;

    struct hdr_match m = pres->ms[idx & MAX_MATCH_MASK];
    if (m.len == 0) return -1;

    struct msg_ctx ctx = _new_msg_ctx(msg);
    u8 *ptr = NULL;
    u32 len = 0;
    _extract_match(&ctx, &m, false, &ptr, &len, NULL);
    if (ptr == NULL) return -1;

    *str = (struct hdr_str) {
        .len = len,
        .ptr = ptr
    };
    return 0;
}
