# Fuzz targets

This directory holds `cargo-fuzz` targets. Later tasks add them under
`fuzz/fuzz_targets/`, starting with `parse_response`.

Run one target with the nightly toolchain:

```
cargo +nightly fuzz run parse_response -- -max_total_time=60
```

The nightly CI job skips itself while `fuzz/fuzz_targets` is empty.
