# Beeper: Application-Layer Parsing in eBPF

[![Crates.io][crates-badge]][crates-url]
[![GPL-v3 licensed][gpl-badge]][gpl-url]
[![Build Status][actions-badge]][actions-url]
[![DOI][doi-badge]][doi-url]

[crates-badge]: https://img.shields.io/crates/v/beeper.svg
[crates-url]: https://crates.io/crates/beeper
[gpl-badge]: https://img.shields.io/badge/License-GPL_v3-blue.svg
[gpl-url]: LICENSE
[actions-badge]: https://github.com/lerboe/beeper/actions/workflows/ci.yml/badge.svg
[actions-url]: https://github.com/lerboe/beeper/actions/workflows/ci.yml
[doi-badge]: https://img.shields.io/badge/DOI-10.48550/arXiv.2605.31084-purple.svg
[doi-url]: https://doi.org/10.48550/arXiv.2605.31084

<p align="center">
    <img src="https://github.com/lerboe/beeper/raw/main/beeper.png" alt="beeper" width="500">
</p>

Beeper (BEEline's ParsER) is an application-layer parser for eBPF. It allows you to process L7 protocols directly in the kernel, which can accelerate user space applications significantly. It achieves this by constructing an Aho-Corasick-like DFA in user space, reducing the parsing complexity to an eBPF-compatible level. With beeper, you can for example monitor application-layer traffic, redirect it based on its payload, or respond to it, directly from the kernel. For more information, please have a look at the [full paper][doi-url].

Protocol      | Status  | Minimal Kernel Version
------------- | ------- | ----------------------
HTTP/1.1      | ✅      | 6.8
HTTP/2        | ✅      | 6.8
gRPC          | WIP     | 

## Use Cases

[hyper-fast-path](https://github.com/lerboe/hyper-fast-path) uses beeper to serve static assets from the kernel. This improves the throughput of HTTP servers by up to **4.5x**.

## Usage

First, in the Rust program, create a new parser instance, add the desired headers that it should capture, and attach it to an existing eBPF program:
```rust
use beeper::{MessageBuffer, http2, pseudo_header::PATH};
use http::header::CONTENT_LENGTH;

let mut h2 = http2::Parser::new();
let path_mid = h2.capture_hdr(&PATH)?;
let content_length_mid = h2.capture_hdr(&CONTENT_LENGTH)?;

// hand the match ids to the eBPF program before it is loaded
rodata.h2_path_mid = path_mid.into();
rodata.h2_content_length_mid = content_length_mid.into();

let h2 = h2
    .parse_fn("parse_http2", MessageBuffer::Msg)
    .extract_fn("extract_http2_match", MessageBuffer::Msg)
    .attach(prog_fd)?;
```

Next, in your eBPF program, import the header of the protocol you parse, define the stub functions, and call them with the input buffer:
```c
#include "beeper/http2.h"

// stub funcs
BEEPER_EXTRACT_MATCH_MSG(extract_http2_match)
BEEPER_HTTP2_PARSE_MSG(parse_http2)

// the match ids the parser handed back, set by user space
volatile const u8 h2_path_mid;
volatile const u8 h2_content_length_mid;

SEC("sk_msg")
int msg_verdict(struct sk_msg_md *msg) {
    struct http_parse_res pres = { 0 };
    struct http2_frame frame = { 0 };
    int msg_len = parse_http2(msg, &pres, &frame);
    if (msg_len >= 0) {
        struct bytes path = { 0 };
        if (extract_http2_match(msg, &pres, h2_path_mid, &path) == 0) {
            // note that path can be Huffman-encoded
        }
    }

    return SK_PASS;
}
```

Finally, to make this all compile, beeper relies on [xbpf](https://crates.io/crates/xbpf). Add the following to `build.rs`:

```rust
use beeper::build::clang_args;
use xbpf::build::Builder;

fn main() {
    Builder::new()
        .clang_arg(clang_args().iter())
        .export_headers()
        .build();
}
```

Please refer to the [example](example) for a simple HTTP monitoring tool.

## Build

To build and test beeper, you need to install the following packages:

```bash
sudo apt install clang-18 llvm-18 libelf-dev zlib1g-dev linux-headers-`uname -r` linux-tools-`uname -r` 
```

You should now be able to compile and test beeper as follows:

```bash
RUST_LOG=trace cargo test
```

## Citation

If you use this library to conduct your own research, please cite the full paper as follows:
```
@misc{beeline,
      title={Enforcing Application-Layer Policies in eBPF}, 
      author={Laurin Brandner and Ayush Mishra and Sebastiano Miano and Aurojit Panda and Gianni Antichi and Laurent Vanbever},
      year={2026},
      eprint={2605.31084},
      archivePrefix={arXiv},
      primaryClass={cs.NI},
      url={https://arxiv.org/abs/2605.31084}, 
}
```
