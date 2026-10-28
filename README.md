# argus

Production-grade Windows CLI/TUI for inspecting and managing the processes, services, and
sockets listening on your machine. Built in Rust on top of the native Windows IP Helper,
process, service, and console APIs.

## Features

- Enumerates listening (and optionally all) TCP/IPv4, TCP/IPv6, UDP/IPv4, UDP/IPv6 sockets
  via `GetExtendedTcpTable` / `GetExtendedUdpTable`.
- Per entry: protocol, address, port, state, PID, process name + image path, command line
  (best-effort), start time, working set, owning service + status, and an inferred kind
  (`frontend` / `backend` / `database` / `system` / `unknown`).
- Status classification: `Active`, `Dead`, `Stale`, `Paused`.
- Interactive TUI: search, sort, detail modal, kill confirmation modal, auto-refresh.
- One-shot CLI mode with `--json` for scripting.
- Embedded `requireAdministrator` manifest → UAC prompt at launch.
- Kill safety: confirmation modal (press `Y` then `Enter`) before any termination.

## Build (cross-compile from Linux)

```sh
rustup target add x86_64-pc-windows-gnu
sudo pacman -S mingw-w64-toolchain   # or your distro's mingw-w64
cargo build --release --target x86_64-pc-windows-gnu
```

Binary: `target/x86_64-pc-windows-gnu/release/argus.exe`

## Usage

```text
argus                       # interactive TUI
argus list                  # print table once
argus list --json           # machine-readable
argus list --all            # include established connections
argus list --node           # only Node/Bun/Deno
argus list --port 3000
argus kill 1234             # confirms before killing
argus kill 1234 --yes       # skip confirmation (still UAC-gated)
argus doctor                # environment / privilege check
```

TUI keys: `↑/↓` or `j/k` move, `/` search, `s` sort, `r` refresh, `a` toggle all,
`n` node-only, `Enter`/`d` details, `x` kill, `q` quit.

## Safety

- The binary is marked `requireAdministrator`; Windows shows a UAC prompt on launch.
- Kills require an explicit confirmation (arm with `Y`, confirm with `Enter`).
- Service-owned PIDs are stopped through the SCM first; otherwise `TerminateProcess`.

## Notes

- Command-line retrieval reads the target process PEB and is best-effort; protected
  processes may report `n/a`.
- Suspended detection is intentionally conservative.
- Cannot be executed in this Linux build environment; validated by compilation and
  `cargo test` (pure logic).
