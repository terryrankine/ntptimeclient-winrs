# Architecture

## Crate map

- `ntpc-core`: the engine. Source selection, filtering, clock discipline, poll timing. No OS or network code.
- `ntpc-platform`: Windows adapters. Clock, sockets, registry, DHCP.
- `ntpc-service`: the service binary. It wires the core to the adapters.
- `fuzz/`: `cargo-fuzz` targets. Outside the workspace. A future `fuzz/Cargo.toml` must have its own `[workspace]` table.

## Dependency rule

- `ntpc-core` depends on `thiserror` only.
- `ntpc-platform` depends on `ntpc-core`.
- `ntpc-service` depends on `ntpc-core` and `ntpc-platform`.

`scripts/check-deps.ps1` fails if `ntpc-core` gains any other dependency. CI also builds and tests `ntpc-core` alone on Linux. That proves it has no OS dependency.

## Sans-IO pattern

The core never reads a clock, opens a socket or touches a file. The caller feeds it events and carries out the actions it returns.

- Events in: a reply arrived, a timer fired, sources changed, the machine resumed.
- Actions out: send a query, set a timer, slew, step, log.

Time is passed in as a value. Nothing inside the core calls "now". The exact types are defined by later tasks.

## Unsafe policy

- The workspace sets `unsafe_code = "forbid"`.
- `ntpc-platform` sets `deny` and allows `unsafe` in one module, `win32`.
- Each `unsafe` block carries a `// SAFETY:` comment.
- Win32 API names are to be confirmed in Task 11.

## Simulation testing

Because the core is sans-IO, tests drive it with a simulated world. The world has virtual time, seeded randomness and scripted servers and faults. Scenarios run in milliseconds and give the same result every time. The world sits behind the `sim` feature of `ntpc-core`. A later task builds it.

## How to add an adapter

1. Decide what the core needs from the outside world. Express it as an event or an action in `ntpc-core`, not as a call.
2. Implement the effect in `ntpc-platform`. Keep any `unsafe` inside `win32`.
3. Wire it in `ntpc-service`.
4. Add a simulation scenario for the new event or action in `ntpc-core`.
5. Run `scripts/check-deps.ps1` to confirm the core gained no dependency.
