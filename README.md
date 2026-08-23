# Beeper: Application-Layer Parsing in eBPF

[![Crates.io][crates-badge]][crates-url]
[![GPL-v3 licensed][gpl-badge]][gpl-url]
[![Build Status][actions-badge]][actions-url]
[![DOI][doi-badge]][doi-url]

[crates-badge]: https://img.shields.io/crates/v/beeper.svg
[crates-url]: https://crates.io/crates/beeper
[gpl-badge]: https://img.shields.io/badge/License-GPL_v3-blue.svg
[gpl-url]: LICENSE
[actions-badge]: https://github.com/lbrndnr/beeper/actions/workflows/ci.yml/badge.svg
[actions-url]: https://github.com/lbrndnr/beeper/actions/workflows/ci.yml
[doi-badge]: https://img.shields.io/badge/DOI-10.48550/arXiv.2605.31084-purple.svg
[doi-url]: https://doi.org/10.48550/arXiv.2605.31084

Beeper (BEEline's ParsER) is an application-layer parser for eBPF. It allows you to process L7 protocols directly in the kernel, which can accelerate user space applications significantly. It achieves this by constructing an Aho-Corasick-like DFA in user space, reducing the parsing complexity to an eBPF-compatible level. With Beeper, you can for example monitor application-layer traffic, redirect it based on its payload, or respond to it, directly from the kernel. For more information, please have a look at the [full paper][doi-url].

Protocol      | Status  | Minimal Kernel Version
------------- | ------- | ----------------------
HTTP/1.1      | ✅      | 6.8
HTTP/2        | ✅      | 7.0
gRPC          | WIP     | 

## Build

To build and test Beeper, you need to install the following packages:

```bash
sudo apt install clang-18 llvm-18 libelf-dev zlib1g-dev linux-headers-`uname -r` linux-tools-`uname -r` 
```

You should now be able to compile and test Beeper as follows:

```bash
RUST_LOG=trace cargo test
```

## Running the Example

Once you can build Beeper, you can also run the example. It is a simple HTTP server, with Beeper attached to it. It will serve some static files directly from the kernel. To run it, first start the server:
```bash
cargo run --bin example
```

Then, in another terminal, make a request to the server:
```bash
curl -vv http://127.0.0.1:8080/index.html
```

In the logs of the server, you should find a line that indicates that the request was served directly from the kernel:
```
Served request
```

To benchmark the server, run the following:
```bash
# server accelerated with beeper
RUST_LOG= cargo run -r --bin example
# baseline: server without the fastpath
RUST_LOG= cargo run -r --bin example -- --no-fastpath
```

In a new window, you can now run the load test:
```bash
cargo install oha

# to test http1 performance
oha -c 100 -q 1000 -z 30s --latency-correction --urls-from-file example/load.txt
# to test http2 performance
oha -c 100 -q 1000 -z 30s --http2 --latency-correction --urls-from-file example/load.txt
```

## Citation

If you use this library to conduct your own research, please cite the full paper as follows:
```
@misc{brandner2026enforcingapplicationlayerpoliciesebpf,
      title={Enforcing Application-Layer Policies in eBPF}, 
      author={Laurin Brandner and Ayush Mishra and Sebastiano Miano and Aurojit Panda and Gianni Antichi and Laurent Vanbever},
      year={2026},
      eprint={2605.31084},
      archivePrefix={arXiv},
      primaryClass={cs.NI},
      url={https://arxiv.org/abs/2605.31084}, 
}
```
