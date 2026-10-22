#include "vmlinux.h"
#include "beeper/http2.h"
#include "xbpf.h"
#include <bpf/bpf_helpers.h>

// The number of bytes of a name or a value that are kept in a table entry.
#define HEADER_FIELD_MAXLEN BEEPER_HTTP2_FIELD_MAXLEN
#define HEADER_FIELD_MASK (HEADER_FIELD_MAXLEN - 1)

// The number of entries of the HPACK static table.
#define STATIC_TABLE_SIZE 61

// The index the first entry of a dynamic table is stored under. User space
// defines it in http2/parser.rs and loads it before the program is loaded.
volatile const u32 DYNAMIC_TABLE_BASE;

// The identifier of the SETTINGS parameter announcing the size of the dynamic
// table.
#define SETTINGS_HEADER_TABLE_SIZE 0x1

// The length of a frame header, see section 4.1 of RFC 9113.
#define HTTP2_FRAME_HDR_LEN 9

// The frame types the parser reads. Every other one is skipped.
#define HTTP2_HEADERS_FRAME 0x01
#define HTTP2_SETTINGS_FRAME 0x04
#define HTTP2_CONTINUATION_FRAME 0x09

// The flags of a HEADERS frame that move the header block within it.
#define HTTP2_END_HEADERS_FLAG 0x04
#define HTTP2_PADDED_FLAG 0x08
#define HTTP2_PRIORITY_FLAG 0x20

// The number of bytes the priority of a HEADERS frame takes up, a stream
// dependency and a weight.
#define HTTP2_PRIORITY_LEN 5

// The HPACK static table. User space populates and freezes it when the parser
// is attached.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, STATIC_TABLE_SIZE+1);
    __type(key, u32);
    __type(value, struct http2_hdr_field);
} static_table SEC(".maps");

// The dynamic table is per connection, and its entries are addressed by the
// order in which they were added.
struct dynamic_table_key {
    struct ip4_conn conn;
    u32 idx;
};

// An entry of the dynamic table, along with the size it accounts for in the
// table.
struct dynamic_table_entry {
    struct http2_hdr_field field;
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

// The number of bytes of `block_buf` a header block can be put together in.
// The largest value a per-CPU map holds is 32KiB, and a copy into the buffer
// may be up to as long as a block to any offset below that length, which is
// all the verifier knows of it, so a block takes up at most half of it.
#define BLOCK_BUF_SIZE (32768 - sizeof(u32))
#define BLOCK_MAXLEN (BLOCK_BUF_SIZE / 2)

// A header block that is sent in more than one frame, put together from the
// fragments its frames carry, see `_collect_block`.
struct block_buf {
    u32 len;
    u8 data[BLOCK_BUF_SIZE];
};

// The header block the parser read last on the CPU, which the matches with the
// source `HTTP_SRC_BUF` it captured point into.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct block_buf);
} block_bufs SEC(".maps");

// The state of the dynamic table of a connection. `deleted` counts the entries
// that were evicted, which is what turns an HPACK index, counted from the most
// recently added entry, into the index an entry is stored under.
struct dynamic_table_info {
    u32 count;
    u32 size;
    u32 max_size;
    u32 deleted;
    u32 dirty;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct ip4_conn);
	__type(value, struct dynamic_table_info);
} dynamic_table_info SEC(".maps");

// The state ids, action kinds and flags. User space defines them in
// http2/action.rs and loads them before the program is loaded.
volatile const u16 S_DEAD;
volatile const u16 S_FIELD;
volatile const u16 S_VAL_LEN;
volatile const u16 S_NAME;
volatile const u16 S_NAME_PLAIN;

#define HTTP2A_NONE 0

volatile const u8 HTTP2A_INDEXED;
volatile const u8 HTTP2A_IDX_NAME;
volatile const u8 HTTP2A_LIT_NAME;
volatile const u8 HTTP2A_KEY_LEN;
volatile const u8 HTTP2A_VAL_LEN;
volatile const u8 HTTP2A_TABLE_SIZE;
volatile const u8 HTTP2A_INT_START;
volatile const u8 HTTP2A_INT_CONT;
volatile const u8 HTTP2A_CAPTURE;
volatile const u8 HTTP2A_ERR;

volatile const u8 HTTP2F_HUFF;
volatile const u8 HTTP2F_ADD_DT;
volatile const u8 HTTP2F_CONT;

// A single action of the DFA. `val` is an index, a length or a table size,
// depending on `kind`.
struct http2_action {
    u16 val;
    u8 kind;
    u8 flags;
};

// these restrictions are needed to make the verifier happy. All three are
// masked onto an index, so all three have to be powers of two.
#define MAX_STATES 1024
#define MAX_EDGES 256
#define MAX_ACTIONS 1024

// The edges of the DFA, indexed by state and input byte, along with their
// actions. User space fills both in before the program is loaded, after
// which they are read-only.
volatile const struct trans states[MAX_STATES][MAX_EDGES];
volatile const struct http2_action actions[MAX_ACTIONS];

// Reads the action an edge carries. Edge 0 leads to the fallback state.
static __always_inline struct http2_action _action(u16 id) {
    return actions[id & (MAX_ACTIONS - 1)];
}

// The length of the longest code of the HPACK Huffman code.
#define HPACK_HUFF_MAXLEN 30

// The HPACK Huffman code of appendix B of RFC 7541, flattened into the number
// of symbols per code length and the first code of each length.
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
    if (len > HPACK_HUFF_MAXLEN) {                              \
        code = 0;                                               \
        len = 0;                                                \
    }                                                           \
    else {                                                      \
        u32 rel = code - huff_first_code[len];                  \
        if (rel < huff_count[len]) {                            \
            n++;                                                \
            code = 0;                                           \
            len = 0;                                            \
        }                                                       \
    }                                                           \
} while (0)

// Returns the number of characters the first `src_len` bytes of the Huffman
// encoded key or value decodes to.
__noinline __weak u32 hpack_huffman_decoded_len(const struct http2_hdr_field *hf __arg_nonnull, bool is_val, u32 src_len) {
    const u8 *src = is_val ? hf->val : hf->key;
    u32 code = 0, len = 0, n = 0;
    u32 i = 0;

    bpf_clamp_uminmax(src_len, 0, HEADER_FIELD_MAXLEN);
    bpf_for (i, 0, src_len) {
        u8 c = src[i & HEADER_FIELD_MASK];
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
// `len` bytes long.
//
// Returns 0, -EBADMSG for invalid padding/priority, or -EFAULT if unreadable.
static __always_inline int _http2_block(const u8 *data, const u8 *data_end, u32 len, u8 type, u8 flags, u16 *start, u16 *end) {
    u32 off = HTTP2_FRAME_HDR_LEN;
    u32 pad_len = 0;

    if (type == HTTP2_HEADERS_FRAME) {
        if ((flags & HTTP2_PADDED_FLAG) != 0) {
            if (data + off + 1 > data_end) return -EFAULT;
            pad_len = data[off];
            off += 1;
        }

        if ((flags & HTTP2_PRIORITY_FLAG) != 0) off += HTTP2_PRIORITY_LEN;
    }

    if (off + pad_len > HTTP2_FRAME_HDR_LEN + len) return -EBADMSG;

    *start = off;
    *end = HTTP2_FRAME_HDR_LEN + len - pad_len;

    return 0;
}

// A hook-agnostic context struct.
struct msg_ctx {
    u8 *data;
    u8 *data_end;
    struct ip4_conn conn;
};

// Reads the stream id out of the frame header `data` points at. `data` must be
// known to hold at least the 9 bytes of a frame header.
static __always_inline struct http2_frame _new_http2_frame(const u8 *data, u32 len, u8 type, u8 flags) {
    return (struct http2_frame) {
        .len = len,
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
    return (end_idx - idx) + DYNAMIC_TABLE_BASE;
}

// Whether `idx` names an entry either table holds.
static __always_inline bool _is_valid_hpack_index(const struct dynamic_table_info *dt_info __arg_nonnull, u32 idx) {
    return idx > 0 && idx <= STATIC_TABLE_SIZE + dt_info->count;
}

// Resolves the match `m` into the bytes it refers to.
static __always_inline void _get_match(const struct msg_ctx *ctx, const struct http_match *m, bool is_key, u8 **out, u32 *len, bool *huff) {
    if (m->source == HTTP_SRC_MSG) {
        if (ctx->data + m->idx + m->len > ctx->data_end) return;
        *out = ctx->data + m->idx;
        *len = m->len;
        if (huff) *huff = m->huff;
        return;
    }

    if (m->source == HTTP_SRC_BUF) {
        u32 zero = 0;
        struct block_buf *buf = bpf_map_lookup_elem(&block_bufs, &zero);
        if (buf == NULL) return;

        u32 idx = m->idx;
        if (idx + m->len > buf->len) return;
        bpf_clamp_uminmax(idx, 0, BLOCK_MAXLEN);

        *out = buf->data + idx;
        *len = m->len;
        if (huff) *huff = m->huff;
        return;
    }

    struct dynamic_table_entry *entry = NULL;
    if (m->idx >= DYNAMIC_TABLE_BASE) {
        // an entry that has been evicted since the match was taken is one the
        // lookup no longer finds, which is the answer either way
        struct dynamic_table_key key = _new_dynamic_table_key(&ctx->conn, m->idx);
        entry = bpf_map_lookup_elem(&dynamic_table, &key);
    }
    else {
        // the static table is an array, so it answers for every index below its
        // size, index 0 included, which HPACK does not use
        if (m->idx == 0) return;

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

// Follows the edge `input` takes out of `state`. A state that has no
// edge for `input` falls back to the one matching any byte, and if it has
// none either, back to the fallback state.
static __always_inline void _next(u16 state, u8 input, u16 *next_state, u16 *action) {
    state &= MAX_STATES - 1;
    input &= MAX_EDGES - 1;

    struct trans t = states[state][input];
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
static __always_inline void _get_table_entry(const struct ip4_conn *conn __arg_nonnull, const struct dynamic_table_info *dt_info __arg_nonnull, u32 idx, struct http2_hdr_field **hf) {
    if (!_is_valid_hpack_index(dt_info, idx)) {
        *hf = NULL;
        return;
    }

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
        *hf = (struct http2_hdr_field *)bpf_map_lookup_elem(&dynamic_table, &key);
    }
    else {
        *hf = bpf_map_lookup_elem(&static_table, &idx);
    }
}

// Walks the name trie over `key`, the name of a field the peer only referenced
// by index, and returns the id of the capture it matched, or -1 if the name
// matches no pattern.
static __always_inline int _match_header_key(const u8 *key __arg_nonnull, u16 key__sz, bool huff) {
    u16 s = huff ? S_NAME : S_NAME_PLAIN;
    u16 j = 0;
    int mid = -1;
    bpf_for(j, 0, key__sz) {
        u16 a = 0;
        _next(s, key[j], &s, &a);

        struct http2_action act = _action(a);
        mid = (act.kind == HTTP2A_CAPTURE) ? (int)(act.val & MAX_MATCH_MASK) : -1;
    }

    return mid;
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
// `new_entry_size` fits into it.
static __always_inline u32 _try_evict_dynamic_table_entries(const struct msg_ctx *ctx __arg_nonnull, struct dynamic_table_info *dt_info __arg_nonnull, u32 new_entry_size) {
    bpf_trace("dt: try evicting %dB (%d actual entries)", new_entry_size, dt_info->count);

    u32 freed = 0;
    bpf_repeat(dt_info->count) {
        if (dt_info->size + new_entry_size <= dt_info->max_size) break;

        // entries are stored under the running count of the ones added so far,
        // so the oldest one that is still live sits right above the evicted
        u32 idx = DYNAMIC_TABLE_BASE + dt_info->deleted;
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
// many of the oldest entries as it takes to make room for it.
static __always_inline int _add_dynamic_table_entry(const struct msg_ctx *ctx __arg_nonnull, struct dynamic_table_info *dt_info __arg_nonnull, const struct http_match *key __arg_nonnull, const struct http_match *val __arg_nonnull) {
    if (dt_info->dirty) return -EBADMSG;

    u8 *key_ptr = NULL;
    u32 key_len = 0;
    bool key_huff = false;
    _get_match(ctx, key, true, &key_ptr, &key_len, &key_huff);
    if (!key_ptr) return key->source == HTTP_SRC_TABLE ? -ENOENT : -EBADMSG;

    u8 *val_ptr = NULL;
    u32 val_len = 0;
    bool val_huff = false;
    _get_match(ctx, val, false, &val_ptr, &val_len, &val_huff);
    if (!val_ptr) return val->source == HTTP_SRC_TABLE ? -ENOENT : -EBADMSG;

    // an entry only keeps the first `HEADER_FIELD_MAXLEN` bytes of a field, but
    // it is sized by everything the peer sent, or the two tables would evict at
    // different points
    u32 key_wire_len = key_len;
    u32 val_wire_len = val_len;
    bool key_cut = (key_len > HEADER_FIELD_MAXLEN);
    bool val_cut = (val_len > HEADER_FIELD_MAXLEN);
    bpf_clamp_uminmax(key_len, 0, HEADER_FIELD_MAXLEN);
    bpf_clamp_uminmax(val_len, 0, HEADER_FIELD_MAXLEN);

    int per_cpu_key = 0;
    struct dynamic_table_entry *dt_val = bpf_map_lookup_elem(&dynamic_table_entry, &per_cpu_key);
    if (!dt_val) return -ENOSPC;

    u32 idx = DYNAMIC_TABLE_BASE + dt_info->count + dt_info->deleted;
    struct dynamic_table_key dt_key = _new_dynamic_table_key(&ctx->conn, idx);

    __builtin_memset(dt_val, 0, sizeof(*dt_val));
    int ret = bpf_probe_read_kernel(dt_val->field.key, key_len, key_ptr);
    dt_val->field.key_len = !ret * key_len;

    ret = bpf_probe_read_kernel(dt_val->field.val, val_len, val_ptr);
    dt_val->field.val_len = !ret * val_len;

    dt_val->field.key_huff = key_huff;
    dt_val->field.val_huff = val_huff;

    // the decoded length of a Huffman coded field can only be counted off the
    // bytes the entry kept, so a coded field that was truncated is one the
    // mirrored table can no longer size the way the peer does
    if ((key_cut && key_huff) || (val_cut && val_huff)) {
        bpf_debug("dt: a Huffman coded field longer than %d bytes, the table has drifted", HEADER_FIELD_MAXLEN);
        dt_info->dirty = 1;
        return -E2BIG;
    }

    u32 key_len_decoded = key_huff ? hpack_huffman_decoded_len(&dt_val->field, false, key_len) : key_wire_len;
    u32 val_len_decoded = val_huff ? hpack_huffman_decoded_len(&dt_val->field, true, val_len) : val_wire_len;
    dt_val->size = key_len_decoded + val_len_decoded + 32;

    _try_evict_dynamic_table_entries(ctx, dt_info, dt_val->size);
    if (dt_info->size + dt_val->size > dt_info->max_size) {
        bpf_debug("dt: entry size %d exceeds max size %d", dt_val->size, dt_info->max_size);
        return 0; // HPACK does not insert entries larger than the table.
    }

    if (bpf_map_update_elem(&dynamic_table, &dt_key, dt_val, BPF_ANY) < 0) return -ENOSPC;

    dt_info->size += dt_val->size;
    dt_info->count += 1;

    bpf_debug("dt: add with index %d, key size: %d, val size: %d, new total size %d", dt_key.idx, key_len_decoded, val_len_decoded, dt_info->size);
    bpf_debug("dt: add key { %d %d %d }", key->idx, key->len, key->source);
    bpf_debug("dt: add val { %d %d %d }", val->idx, val->len, val->source);

    return 0;
}

// Reads the SETTINGS frame.
static __always_inline int _parse_stg_from(const struct msg_ctx *ctx, u16 start, u16 end, u16 *s, struct http_parse_res *pres, struct null_prefix *null_prefix) {
    const u8 *data = ctx->data;
    const u8 *data_end = ctx->data_end;
    u32 len = (u32)(data_end - data);
    bpf_clamp_uminmax(len, 0, MAX_BYTES);
    if (end < len) len = end;
    if (data + 9 > data_end) return 0;

    u8 type = data[3];
    u8 flags = data[4];
    u32 stream_id = data[5] << 24 | data[6] << 16 | data[7] << 8 | data[8];

    struct dynamic_table_info *dt_info = _get_dynamic_table(&ctx->conn);
    if (!dt_info) return -ENOSPC;

    u32 i = start;
    u8 j = 0;
    u16 id = 0;
    u32 val = 0;

    bpf_for(i, start, len) {
        if (data + i + 1 > data_end) return -EFAULT;
        u8 c = data[i];

        // skb clears the TLS header, but does not remove it
        if (null_prefix && c == '\0' && i == null_prefix->len) {
            null_prefix->len = i + 1;
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
                dt_info->max_size = val;
                bpf_debug("stg: table header size: %u", val);
            }
            j = 0;
            id = 0;
            val = 0;
        }
    }

    return i;
}

// The current parser state.
struct http2_parse_state {
    // the state of the DFA
    u16 s;

    // the integer being accumulated and the shift of its next byte
    u32 k;
    u32 m;

    // the bytes of the string that was announced that are still to be read
    u32 skip;
    bool is_key;

    // the capture the name of the field being read matched, or -1
    s8 cid;

    // whether the peer adds the field being read to its dynamic table
    u8 add_to_dt;

    // the name of that field
    struct http_match key;

    // the offset of the byte being read, and the action and the integer of the
    // transition it took
    u32 i;
    u32 v;
    u8 kind;
    u8 flags;
    u8 src;
};

// Returns the state a header block is read from its first byte with, out of
// `src`, see `http2_parse_state`.
static __always_inline struct http2_parse_state _new_http2_parse_state(u8 src) {
    return (struct http2_parse_state) {
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
            .source = src,
            .huff = false,
        },
        .i = 0,
        .v = 0,
        .kind = HTTP2A_NONE,
        .flags = 0,
        .src = src,
    };
}

// Runs the action of the edges `ps` holds.
//
// Returns 0 or a negative errno if the block cannot be read any further.
static __always_inline int _run_action(const struct msg_ctx *ctx __arg_nonnull, struct dynamic_table_info *dt_info __arg_nonnull, struct http_parse_res *pres __arg_nonnull, struct http2_parse_state *ps __arg_nonnull) {
    u32 v = ps->v & MAX_BYTES;

    bpf_trace("hdr: %d: kind %d, val %d", ps->i, ps->kind, v);

    // a name that is an index has to be read out of a table before it can be
    // matched. Both representations that carry one are handled here, so that the
    // walk over the entry is only built into the program once
    if (ps->kind == HTTP2A_INDEXED || ps->kind == HTTP2A_IDX_NAME) {
        u32 idx = ps->v;
        bool in_range = _is_valid_hpack_index(dt_info, idx);

        u32 slot = 0;
        if (in_range) {
            slot = idx > STATIC_TABLE_SIZE ? _get_dynamic_table_index(dt_info, idx) : idx;

            // if we overflow, at least we won't report the wrong header
            if (slot > 0xffff) slot = 0;
        }

        ps->add_to_dt = (ps->flags & HTTP2F_ADD_DT) != 0;
        ps->cid = -1;

        // an index that cannot be reported is reported as 0, which names no
        // entry either
        ps->key = (struct http_match) {
            .idx = slot,
            .len = 0,
            .source = HTTP_SRC_TABLE,
            .huff = false,
        };

        struct http2_hdr_field *hf = NULL;
        _get_table_entry(&ctx->conn, dt_info, idx, &hf);
        if (hf == NULL) return 0;

        u32 key_len = hf->key_len;
        bpf_clamp_uminmax(key_len, 0, HEADER_FIELD_MAXLEN);

        int mid = _match_header_key(hf->key, key_len, hf->key_huff != 0);
        if (mid < 0) return 0;

        if (ps->kind == HTTP2A_IDX_NAME) {
            ps->cid = mid;
            return 0;
        }

        // both halves of the field are in the table, so the value is reported
        // as the index it is to be read back with
        pres->ms[mid & MAX_MATCH_MASK] = (struct http_match) {
            .idx = slot,
            .len = HEADER_FIELD_MASK,
            .source = HTTP_SRC_TABLE,
            .huff = false,
        };

        return 0;
    }

    if (ps->kind == HTTP2A_LIT_NAME) {
        ps->add_to_dt = (ps->flags & HTTP2F_ADD_DT) != 0;
        ps->cid = -1;
        return 0;
    }

    if (ps->kind == HTTP2A_KEY_LEN) {
        ps->key = (struct http_match) {
            .idx = ps->i + 1,
            .len = v,
            .source = ps->src,
            .huff = (ps->flags & HTTP2F_HUFF) != 0,
        };

        ps->skip = v;
        ps->is_key = true;
        if (v == 0) ps->s = S_VAL_LEN;

        return 0;
    }

    if (ps->kind == HTTP2A_VAL_LEN) {
        struct http_match val = (struct http_match) {
            .idx = ps->i + 1,
            .len = v,
            .source = ps->src,
            .huff = (ps->flags & HTTP2F_HUFF) != 0,
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

    if (ps->kind == HTTP2A_TABLE_SIZE) {
        bpf_debug("hdr: table size update: %u", ps->v);
        dt_info->max_size = ps->v;
        _try_evict_dynamic_table_entries(ctx, dt_info, 0);
        return 0;
    }

    if (ps->kind == HTTP2A_ERR) {
        bpf_debug("hdr: malformed representation at %d", ps->i);
        return -EBADMSG;
    }

    return 0;
}

// Feeds the byte `c` at the offset `ps->i` to the header block `ps` reads, and
// records the values of the fields whose name matches a pattern in `pres`.
// Returns 0 or a negative errno if the block cannot be read any further.
__noinline __weak int _parse_hdr_byte(const struct msg_ctx *ctx __arg_nonnull, struct dynamic_table_info *dt_info __arg_nonnull, struct http_parse_res *pres __arg_nonnull, struct http2_parse_state *ps __arg_nonnull, u32 c) {
    c &= 0xff;

    if (ps->skip > 0) {
        if (ps->is_key) {
            u16 a = 0;
            _next(ps->s, c, &ps->s, &a);

            struct http2_action act = _action(a);
            ps->cid = (act.kind == HTTP2A_CAPTURE) ? (s8)(act.val & MAX_MATCH_MASK) : -1;
        }

        ps->skip--;
        if (ps->skip == 0 && ps->is_key) ps->s = S_VAL_LEN;

        return 0;
    }

    u16 a = 0;
    _next(ps->s, c, &ps->s, &a);
    struct http2_action act = _action(a);

    if (act.kind == HTTP2A_INT_START) {
        ps->k = act.val;
        ps->m = 0;
        return 0;
    }
    if (act.kind == HTTP2A_INT_CONT) {
        // an integer wider than the longest block the parser reads is of no
        // use, and shifting by more than the width of the accumulator is not
        // defined. Such an integer is left short, which makes the field it
        // belongs to unresolvable rather than the block unparsable
        if (ps->m <= 28) {
            ps->k += (u32)(c & 0x7F) << ps->m;
            ps->m += 7;
        }

        return 0;
    }

    ps->v = act.val;
    if ((act.flags & HTTP2F_CONT) != 0) {
        ps->v = ps->k;
        if (ps->m <= 28) ps->v += (u32)(c & 0x7F) << ps->m;
    }
    ps->kind = act.kind;
    ps->flags = act.flags;

    return _run_action(ctx, dt_info, pres, ps);
}

// Decodes the header block between the offsets `start` and `end` and records
// the values of the fields whose name matches a pattern in `pres`.
//
// Returns the offset it stopped at, which is `end` if the whole block was read.
static __always_inline int _parse_hdr_from(const struct msg_ctx *ctx, u16 start, u16 end, struct dynamic_table_info *dt_info, struct http2_parse_state *ps, struct http_parse_res *pres, struct null_prefix *null_prefix) {
    const u8 *data = ctx->data;
    const u8 *data_end = ctx->data_end;

    u32 len = (u32)(data_end - data);
    bpf_clamp_uminmax(len, 0, MAX_BYTES);
    if (end < len) len = end;

    u32 i = start;
    bpf_for(i, start, len) {
        if (data + i + 1 > data_end) return -EFAULT;
        u8 c = data[i];

        // skb clears the TLS header, but does not remove it
        if (null_prefix && c == '\0' && i == null_prefix->len) {
            null_prefix->len = i + 1;
            continue;
        }

        ps->i = i;
        int err = _parse_hdr_byte(ctx, dt_info, pres, ps, c);
        if (err < 0) return err;
    }

    return i;
}

// Returns 1 if a frame of `type` sent on the stream `sid`, at the start of a
// message, violates the rules for the frames a header block is sent in.
static __always_inline bool _violates_block_rules(u32 type, u32 sid) {
    if (type == HTTP2_CONTINUATION_FRAME) {
        bpf_debug("hdr: a continuation of stream %u carries on no block", sid);
        return true;
    }

    if (type == HTTP2_HEADERS_FRAME && sid == 0) {
        bpf_debug("hdr: a HEADERS frame on stream 0");
        return true;
    }

    return false;
}

static __always_inline int _reject_frame(struct http2_frame *frame, u32 frame_len, u32 avail) {
    if (frame_len <= avail) return -EPROTO;

    frame->need = frame_len;
    return -EAGAIN;
}

// Reads the header block a HEADERS frame carries whole, between the offsets
// `start` and `end`.
//
// Returns the offset it stopped at, see `_parse_hdr_from`.
static __always_inline int _parse_hdr_frame(const struct msg_ctx *ctx, u16 start, u16 end, struct http_parse_res *pres, struct null_prefix *null_prefix) {
    struct dynamic_table_info *dt_info = _get_dynamic_table(&ctx->conn);
    if (!dt_info) return -ENOSPC;

    struct http2_parse_state ps = _new_http2_parse_state(HTTP_SRC_MSG);
    return _parse_hdr_from(ctx, start, end, dt_info, &ps, pres, null_prefix);
}

struct collected_block {
    u32 len;
    u32 need;
};

// Puts the header block of the HEADERS frame `off` bytes into `ctx` together in
// `block_bufs`.
__noinline __weak int _collect_block(const struct msg_ctx *ctx __arg_nonnull, u32 off, struct collected_block *blk __arg_nonnull) {
    u32 zero = 0;
    struct block_buf *buf = bpf_map_lookup_elem(&block_bufs, &zero);
    if (buf == NULL) return -ENOSPC;

    const u8 *data = ctx->data;
    u32 avail = (u32)(ctx->data_end - ctx->data);

    u32 o = off;
    u32 pos = 0;
    u32 sid = 0;
    u32 k = 0;

    // a frame takes up at least the 9 bytes of its header
    bpf_for(k, 0, MAX_BYTES / HTTP2_FRAME_HDR_LEN + 1) {
        if (o > MAX_BYTES) return -E2BIG;

        if (o + HTTP2_FRAME_HDR_LEN > avail) {
            blk->need = o - off + HTTP2_FRAME_HDR_LEN;
            return -EAGAIN;
        }

        u8 hdr[HTTP2_FRAME_HDR_LEN];
        if (bpf_probe_read_kernel(hdr, sizeof(hdr), data + o) < 0) return -EFAULT;

        u32 len = (u32)hdr[0] << 16 | (u32)hdr[1] << 8 | (u32)hdr[2];
        u8 type = hdr[3];
        u8 flags = hdr[4];
        u32 fsid = ((u32)hdr[5] << 24 | (u32)hdr[6] << 16 | (u32)hdr[7] << 8 | (u32)hdr[8]) & 0x7FFFFFFF;

        if (k == 0) {
            sid = fsid;
        } else if (type != HTTP2_CONTINUATION_FRAME || fsid != sid) {
            bpf_debug("hdr: a frame of type %u of stream %u breaks the block of stream %u", type, fsid, sid);
            return -EPROTO;
        }

        u32 frame_len = HTTP2_FRAME_HDR_LEN + len;
        if (o + frame_len > avail) {
            blk->need = o - off + frame_len;
            return -EAGAIN;
        }

        // only the HEADERS frame may be padded and carry a priority
        u32 start = HTTP2_FRAME_HDR_LEN;
        u32 pad_len = 0;
        if (k == 0 && (flags & HTTP2_PADDED_FLAG) != 0) {
            u8 pad = 0;
            if (start + 1 > frame_len) return -EBADMSG;
            if (bpf_probe_read_kernel(&pad, 1, data + o + start) < 0) return -EFAULT;
            pad_len = pad;
            start += 1;
        }
        if (k == 0 && (flags & HTTP2_PRIORITY_FLAG) != 0) start += HTTP2_PRIORITY_LEN;
        if (start + pad_len > frame_len) return -EBADMSG;

        u32 n = frame_len - pad_len - start;
        if (pos + n > BLOCK_MAXLEN) {
            bpf_debug("hdr: a block longer than %u bytes", BLOCK_MAXLEN);
            return -E2BIG;
        }

        bpf_clamp_uminmax(pos, 0, BLOCK_MAXLEN);
        bpf_clamp_uminmax(n, 0, BLOCK_MAXLEN);
        if (n > 0 && bpf_probe_read_kernel(buf->data + pos, n, data + o + start) < 0) return -EFAULT;

        pos += n;
        o += frame_len;

        if ((flags & HTTP2_END_HEADERS_FLAG) != 0) {
            buf->len = pos;
            blk->len = pos;
            return o - off;
        }
    }

    return -E2BIG;
}

// Decodes the header block `_collect_block` put together, `len` bytes long, and
// records the values of the fields whose name matches a pattern in `pres`.
//
// Returns the offset it stopped at, which is `len` if the whole block was read.
static __always_inline int _parse_hdr_buf(const struct msg_ctx *ctx, u32 len, struct dynamic_table_info *dt_info, struct http2_parse_state *ps, struct http_parse_res *pres) {
    u32 zero = 0;
    struct block_buf *buf = bpf_map_lookup_elem(&block_bufs, &zero);
    if (buf == NULL) return -ENOSPC;

    bpf_clamp_uminmax(len, 0, BLOCK_MAXLEN);

    // the loop runs one past the block, so that `i` ends up at its end once it
    // is read, rather than at its last byte
    u32 i = 0;
    bpf_for(i, 0, len + 1) {
        if (i >= len) break;

        u32 j = i;
        bpf_clamp_uminmax(j, 0, BLOCK_MAXLEN - 1);

        ps->i = i;
        int err = _parse_hdr_byte(ctx, dt_info, pres, ps, buf->data[j]);
        if (err < 0) return err;
    }

    return i;
}

// Reads the header block of the HEADERS frame `off` bytes into `ctx`, which
// does not end it, along with the CONTINUATION frames that carry it on, and
// describes it in `frame`.
//
// Returns the number of bytes the frames of the block take up, or what
// `_collect_block` fails with, or -EBADMSG if the block could not be decoded.
static __always_inline int _parse_block(const struct msg_ctx *ctx, u32 off, struct http_parse_res *pres, struct http2_frame *frame) {
    struct collected_block blk = { 0 };
    int total = _collect_block(ctx, off, &blk);
    if (total < 0) {
        if (total == -EAGAIN) frame->need = blk.need;
        return total;
    }

    struct dynamic_table_info *dt_info = _get_dynamic_table(&ctx->conn);
    if (!dt_info) return -ENOSPC;

    frame->dt_count_before = dt_info->count;

    struct http2_parse_state ps = _new_http2_parse_state(HTTP_SRC_BUF);
    int res = _parse_hdr_buf(ctx, blk.len, dt_info, &ps, pres);

    frame->dt_count = dt_info->count;

    if (res < 0) return res;
    return (res < blk.len) ? -EBADMSG : total;
}

// Whether a frame carries anything the parser needs to read.
static __always_inline bool _is_parsed_frame(u8 type, u8 flags) {
    bool is_hdr = (type == HTTP2_HEADERS_FRAME || type == HTTP2_CONTINUATION_FRAME);
    bool is_stg = (type == HTTP2_SETTINGS_FRAME && flags == 0);

    return is_hdr || is_stg;
}

// Describes the dynamic table of `conn` in `frame` for a frame that leaves it
// untouched.
static __always_inline void _skip_frame(const struct ip4_conn *conn, struct http2_frame *frame) {
    struct dynamic_table_info *dt_info = bpf_map_lookup_elem(&dynamic_table_info, conn);
    u32 count = dt_info ? dt_info->count : 0;

    frame->dt_count_before = count;
    frame->dt_count = count;
}

// Parses the frame that starts `off` bytes into `ctx`.
//
// Returns 0 or a negative errno if the frame could not be read to its end.
static __always_inline int _parse_frame(const struct msg_ctx *ctx, u32 off, u32 len, u8 type, u8 flags, struct http_parse_res *pres, struct http2_frame *frame, struct null_prefix *null_prefix) {
    if (off > MAX_BYTES) return -E2BIG;
    bpf_clamp_uminmax(off, 0, MAX_BYTES);

    u16 start = 0, end = 0;
    int block_err = _http2_block(ctx->data + off, ctx->data_end, len, type, flags, &start, &end);
    if (block_err < 0) return block_err;

    if (off + end > MAX_BYTES) return -E2BIG;
    start += off;
    end += off;

    struct dynamic_table_info *dt_info = _get_dynamic_table(&ctx->conn);
    frame->dt_count_before = dt_info ? dt_info->count : 0;

    int res;
    if (type == HTTP2_SETTINGS_FRAME) {
        u16 s = S_FIELD;
        res = _parse_stg_from(ctx, start, end, &s, pres, null_prefix);
    } else {
        res = _parse_hdr_frame(ctx, start, end, pres, null_prefix);
    }

    frame->dt_count = dt_info ? dt_info->count : 0;

    if (res < 0) return res;
    return (res < end-1) ? -EBADMSG : 0;
}

// Parses the frame the message starts with and describes it in `frame`, so that
// the caller can tell which stream it belongs to and where it ends. HEADERS
// frames are decoded into `pres`, SETTINGS frames are applied to the mirrored
// dynamic table and every other frame is skipped.
//
// Returns the number of bytes the frame and the CONTINUATION frames of its block
// occupy, 0 if the message is too short to hold a frame header, `-EAGAIN` if it
// is too short to hold the frame or the rest of its block, or another negative
// errno described in beeper/http2.h.
SEC("freplace")
int parse_msg(struct sk_msg_md *msg, struct http_parse_res *pres __arg_nonnull, struct http2_frame *frame __arg_nonnull) {
    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;

    if (data + HTTP2_FRAME_HDR_LEN > data_end) return 0;

    u32 len = data[0] << 16 | data[1] << 8 | data[2];
    u8 type = data[3];
    u8 flags = data[4];
    u32 frame_len = HTTP2_FRAME_HDR_LEN + len;
    u32 size = msg->size;

    *frame = _new_http2_frame(data, len, type, flags);

    bpf_debug("Parsing HTTP/2 message with length %d, type %d, flags %d", len, type, flags);

    struct msg_ctx ctx = _new_msg_ctx(msg);
    if (_violates_block_rules(type, frame->sid)) {
        return _reject_frame(frame, frame_len, size);
    }

    if (!_is_parsed_frame(type, flags)) {
        _skip_frame(&ctx.conn, frame);

        return frame_len;
    }

    if (frame_len > size) {
        frame->need = frame_len;
        return -EAGAIN;
    }

    if (type == HTTP2_HEADERS_FRAME && (flags & HTTP2_END_HEADERS_FLAG) == 0) {
        // the frames behind it are pulled in as well, as far as they can be read
        u32 pulled = size;
        if (pulled > MAX_BYTES) pulled = MAX_BYTES;
        if (bpf_msg_pull_data(msg, 0, pulled, 0) < 0) return -EFAULT;

        ctx = _new_msg_ctx(msg);
        int res = _parse_block(&ctx, 0, pres, frame);

        // a block whose frames have arrived, but not all of which could be
        // pulled in, would never be read
        if (res == -EAGAIN && frame->need <= size) return -E2BIG;

        return res;
    }

    if (bpf_msg_pull_data(msg, 0, frame_len, 0) < 0) return -EFAULT;

    ctx = _new_msg_ctx(msg);
    int err = _parse_frame(&ctx, 0, len, type, flags, pres, frame, NULL);
    if (err < 0) return err;

    return frame_len;
}

// Parses the frame that starts `off` bytes into the packet. Returns what
// `parse_msg` returns.
SEC("freplace")
int parse_skb(struct __sk_buff *skb, u32 off, struct http_parse_res *pres __arg_nonnull, struct http2_frame *frame __arg_nonnull, struct null_prefix *null_prefix) {
    if (off > MAX_BYTES) return -E2BIG;
    if (skb->len < off + HTTP2_FRAME_HDR_LEN) return 0;
    bpf_clamp_uminmax(off, 0, MAX_BYTES);

    u8 *data = (u8 *)(long)skb->data;
    u8 *data_end = (u8 *)(long)skb->data_end;

    // the linear part may well be empty, with everything in the fragments
    if (data + off + HTTP2_FRAME_HDR_LEN > data_end) {
        if (bpf_skb_pull_data(skb, off + HTTP2_FRAME_HDR_LEN) < 0) return -EFAULT;

        data = (u8 *)(long)skb->data;
        data_end = (u8 *)(long)skb->data_end;
    }

    u8 *hdr = data + off;
    if (hdr + HTTP2_FRAME_HDR_LEN > data_end) return -EFAULT;

    u32 len = hdr[0] << 16 | hdr[1] << 8 | hdr[2];
    u8 type = hdr[3];
    u8 flags = hdr[4];
    u32 frame_len = HTTP2_FRAME_HDR_LEN + len;
    u32 size = skb->len - off;

    *frame = _new_http2_frame(hdr, len, type, flags);

    bpf_debug("Parsing HTTP/2 sk_buff with length %d, type %d, flags %d", len, type, flags);

    struct msg_ctx ctx = _new_skb_ctx(skb);
    if (_violates_block_rules(type, frame->sid)) {
        return _reject_frame(frame, frame_len, size);
    }

    if (!_is_parsed_frame(type, flags)) {
        _skip_frame(&ctx.conn, frame);

        return frame_len;
    }

    if (frame_len > size) {
        frame->need = frame_len;
        return -EAGAIN;
    }

    if (type == HTTP2_HEADERS_FRAME && (flags & HTTP2_END_HEADERS_FLAG) == 0) {
        // see `parse_msg`
        u32 pulled = skb->len;
        if (pulled > off + MAX_BYTES) pulled = off + MAX_BYTES;
        if (bpf_skb_pull_data(skb, pulled) < 0) return -EFAULT;

        ctx = _new_skb_ctx(skb);
        int res = _parse_block(&ctx, off, pres, frame);
        if (res == -EAGAIN && frame->need <= size) return -E2BIG;

        return res;
    }

    if (bpf_skb_pull_data(skb, off + frame_len) < 0) return -EFAULT;

    ctx = _new_skb_ctx(skb);
    int err = _parse_frame(&ctx, off, len, type, flags, pres, frame, null_prefix);
    if (err < 0) return err;

    return frame_len;
}

// Reads the `idx`th entry of `conn`'s dynamic table into `out`, `idx` counted
// as `_get_table_entry` counts it. Returns 0 on success, -EINVAL for index 0,
// or -ENOENT when no entry is available.
SEC("freplace")
int get_dt_entry(const struct ip4_conn *conn __arg_nonnull, u32 idx, struct http2_hdr_field *out __arg_nonnull) {
    struct dynamic_table_info *dt_info = bpf_map_lookup_elem(&dynamic_table_info, conn);
    if (idx == 0) return -EINVAL;
    if (dt_info == NULL) return -ENOENT;

    struct http2_hdr_field *hf = NULL;
    _get_table_entry(conn, dt_info, idx, &hf);
    if (hf == NULL) return -ENOENT;

    __builtin_memcpy(out, hf, sizeof(*out));

    return 0;
}

// Points `str` at the value captured for the match `m`, resolving it against
// `ctx`. Returns 0 on success or -ENOENT if the value cannot be resolved.
static __always_inline int _get_str(const struct msg_ctx *ctx, const struct http_match *m, struct bytes *str) {
    u8 *ptr = NULL;
    u32 len = 0;
    _get_match(ctx, m, false, &ptr, &len, NULL);
    if (ptr == NULL) return -ENOENT;

    *str = (struct bytes) {
        .len = len,
        .ptr = ptr
    };
    return 0;
}

// Whether `m` holds a capture. A match nothing was captured for is all zeros,
// while a value that was captured empty still points behind the length that
// announced it, so its `idx` is never 0.
static __always_inline bool _is_captured(const struct http_match *m) {
    return m->len > 0 || m->idx > 0;
}

// Returns whether the parser captured a value for the match `idx`, which may
// be empty.
SEC("freplace")
bool matched(const struct http_parse_res *pres __arg_nonnull, u8 idx) {
    if (idx >= MAX_MATCHES) return false;

    struct http_match m = pres->ms[idx & MAX_MATCH_MASK];
    return _is_captured(&m);
}

// Points `str` at the value captured for the match `idx`, still Huffman encoded
// if that is how it was sent.
//
// Returns 0 on success, -EINVAL for an invalid id, or -ENOENT if the capture
// is absent or can no longer be resolved.
SEC("freplace")
int get_match_msg(const struct sk_msg_md *msg, const struct http_parse_res *pres __arg_nonnull, u8 idx, struct bytes *str __arg_nonnull) {
    if (idx >= MAX_MATCHES) return -EINVAL;

    struct http_match m = pres->ms[idx & MAX_MATCH_MASK];
    if (!_is_captured(&m)) return -ENOENT;

    struct msg_ctx ctx = _new_msg_ctx(msg);
    return _get_str(&ctx, &m, str);
}

// Same as `get_match`, for a match taken out of an sk_buff.
SEC("freplace")
int get_match_skb(const struct __sk_buff *skb, const struct http_parse_res *pres __arg_nonnull, u8 idx, struct bytes *str __arg_nonnull) {
    if (idx >= MAX_MATCHES) return -EINVAL;

    struct http_match m = pres->ms[idx & MAX_MATCH_MASK];
    if (!_is_captured(&m)) return -ENOENT;

    struct msg_ctx ctx = _new_skb_ctx(skb);
    return _get_str(&ctx, &m, str);
}
