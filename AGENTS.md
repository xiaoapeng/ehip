# Repository Guidelines

## Project Structure & Module Organization
This repository provides the EHIP network stack component used by FLY.
- `src/`: C implementation files.
- `src/ehip-ipv4/`: IPv4, ARP, ICMP, UDP, TCP, routing, ping.
- `src/ehip-mac/`, `src/ehip-netdev/`, `src/ehip-netdev-class/`: MAC and network-device layers.
- `src/ehip-protocol/`: higher-level protocols (for example DNS).
- `src/include/`: public headers, organized to mirror implementation submodules.
- `CMakeLists.txt`: defines the `ehip` object library and links it with `eventhub` dependencies.

## Build, Test, and Development Commands
Use CMake for local build verification:
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --target ehip -j
```
- First command configures a local build tree.
- Second command compiles the `ehip` target only (fastest compile check).

This package is typically integrated and executed from the parent FLY workspace, not as a standalone binary.

## Coding Style & Naming Conventions
- Follow existing C style in touched files: function braces on same line, concise comments, and module-local `static` helpers.
- Keep naming consistent: `snake_case` for functions/variables, `EHIP_*` for macros/constants.
- Keep module pairing clear: update matching headers in `src/include/...` when changing `src/...` APIs.
- Prefer narrow, protocol-focused files (for example, `ip_tx.c`, `icmp_error.c`) over large mixed changes.

## Testing Guidelines
There is currently no dedicated `tests/` directory in this package.
- Minimum requirement: successful local compile of `ehip`.
- For behavior changes, validate through parent-project integration (network bring-up, ping, DNS, TCP/UDP flows).
- Document manual verification steps in the PR.

## Commit & Pull Request Guidelines
Git history uses an emoji + type style, often with optional scope, e.g.:
- `🐞 fix:修复...`
- `✨ feat(tcp):添加...`
- `🎈 perf(dns):优化...`

Keep commits focused and descriptive. For PRs, include:
- what changed and why,
- impacted modules/headers,
- build + runtime verification steps,
- linked issue/task (if any).

## Configuration Tips
Default stack limits and timeouts live in `src/include/ehip_conf.h`. When tuning pool sizes or protocol limits, note RAM/latency trade-offs in your PR description.
