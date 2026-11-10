# Fuzz targets

This directory holds `cargo-fuzz` targets under `fuzz/fuzz_targets/`. It is
its own Cargo workspace, so the root workspace never builds it.

| Target | What it feeds |
|---|---|
| `parse_response` | arbitrary bytes to the NTP reply parser, raw and with our origin spliced in |

Run one target with the nightly toolchain:

```
cargo +nightly fuzz run parse_response -- -max_total_time=60
```

The nightly CI job skips itself while `fuzz/fuzz_targets` is empty.
