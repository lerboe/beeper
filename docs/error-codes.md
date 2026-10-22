# eBPF parser return codes

The eBPF functions return **negative Linux errno values** from
`<asm-generic/errno.h>` (the BPF build's counterpart of libc's `<errno.h>`).
They do not set libc's `errno`. A positive parser result is the number of
bytes consumed; a match getter returns `0` on success.

| Return | Meaning | Client action |
| --- | --- | --- |
| `-EAGAIN` | More bytes are required. HTTP/1 has not reached the end of its header block; HTTP/2 needs the rest of a frame or header block. | Keep the bytes and retry when more arrive. At `sk_msg`, cork HTTP/1 to `msg->size + 1` **only when the caller knows these bytes begin an HTTP/1 header**; for HTTP/2 cork to `frame.need`. Do not treat this as malformed input. |
| `-EPROTO` | An HTTP/2 frame violates header-block framing rules, such as a standalone CONTINUATION or HEADERS on stream 0. | Treat the connection as having a protocol error. Do not cork. The parser leaves its header-block state intact so a client that keeps observing traffic can skip the rejected frame. |
| `-EBADMSG` | An HTTP/2 frame or HPACK block is malformed, including impossible padding or an invalid representation. | Reject the bad message/connection and log the frame. More bytes will not repair it. |
| `-E2BIG` | A header, frame, or collected header block exceeds the parser's fixed limit. | Reject or bypass parsing for this message. Do not cork indefinitely; raise a parser limit only if the application needs to accept larger input. |
| `-EFAULT` | A BPF pull/read failed or an HTTP/1 captured range is no longer readable. | Stop using the current parse result, log the failure, and check buffer lifetime and BPF helper behavior. Retrying by corking is not sufficient. |
| `-ENOSPC` | HTTP/2 map-backed parser state or scratch storage could not be allocated. | Fail this parse, check map capacity and resource pressure, and retry only after restoring capacity. |
| `-ENOENT` | A requested match or dynamic-table entry does not exist, or an HTTP/2 value can no longer be resolved. | For an optional capture, continue without it. For an expected capture or table entry, investigate the match ID and connection/table state. |
| `-EINVAL` | The caller supplied an invalid match ID, HPACK index 0, or an HTTP/1 skb offset beyond the buffer. | Fix the caller argument. Do not retry unchanged. |
| `-ENOSYS` | A declared stub was called before a parser/getter was attached to replace it. | Attach the corresponding parser function before processing traffic. |

HTTP/2 `parse_msg` and `parse_skb` also return `0` when fewer than nine bytes
of a frame header are available. At `sk_msg`, cork to nine bytes in this case.
When they return `-EAGAIN`, `frame.need` is the total byte count needed from
the start of the current frame or header block. HTTP/1 does not know the final
header length in advance, so it asks for one more byte at a time.

For example, an `sk_msg` verdict that has already identified the start of an
HTTP/1 header can handle incomplete input as follows:

```c
int len = parse_http1(msg, &pres);
if (len == -EAGAIN && msg->size < MAX_BYTES) {
    bpf_msg_cork_bytes(msg, msg->size + 1);
    return SK_PASS;
}
if (len < 0) {
    // Report or reject according to the table above.
    return SK_PASS;
}
```

The HTTP/2 example in [`example/src/monitor.bpf.c`](../example/src/monitor.bpf.c)
shows the `0`, `-EAGAIN`, and `-EPROTO` branches in context. On an `sk_skb`
hook, use the stream's reassembly/retention mechanism rather than
`bpf_msg_cork_bytes`, which is an `sk_msg` helper.

The current example and test verdicts also see message bodies after the header.
They pass an HTTP/1 `-EAGAIN` through rather than corking it, because those
bytes may be body data. Applications that track header/body boundaries can
cork incomplete headers safely.

`-ENOENT` from a match getter is normal when a configured field was absent.
Use `matched(...)` first if only its presence matters. A successful parse does
not guarantee every configured field was present.
