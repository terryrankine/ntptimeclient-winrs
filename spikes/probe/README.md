# probe (THROWAWAY)

Spike for Task 1. Not shipped, no tests. Never sets or adjusts the system clock.

- `cargo run -- live pool.ntp.org:123 fixture-reply.bin` sends one request, saves the raw reply, prints fields.
- `cargo run -- file fixture-reply.bin` parses a saved reply.
- `cargo run -- kalman` feeds synthetic measurements to `KalmanClockController` with a mock clock.

`fixture-reply.bin` is a real 48 byte reply from pool.ntp.org captured on 2026-11-10.
