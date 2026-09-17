# Example

This example is a simple monitoring tool for an HTTP server. Run it as follows:
```bash
RUST_LOG=trace cargo run --bin example
```

In a separate terminal, make a request to the server:
```bash
curl -vv -H "accept-language: en" http://127.0.0.1:8080
```
