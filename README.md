# rusty-croc 🦀🐊

> **Archived — merged into [Rusty Mill](https://github.com/Rusty-Mill/rusty_mill).** This crate now lives at [`crates/rusty_croc`](https://github.com/Rusty-Mill/rusty_mill/tree/main/crates/rusty_croc) in the Rusty Mill monorepo, which is where active development, issues, and pull requests happen now. This standalone repo is kept for historical reference only.

[![CI](https://github.com/baileyrd/rusty_croc/actions/workflows/ci.yml/badge.svg)](https://github.com/baileyrd/rusty_croc/actions/workflows/ci.yml)

A Rust port of [croc](https://github.com/schollz/croc) — a tool for easily and
securely transferring files and folders between two computers, using a code
phrase and (when needed) a relay.

**Status: functionally complete.** rusty-croc is a complete croc client and
relay, **wire-compatible with stock croc v10**: it sends to, receives from,
relays for, and reconnects alongside stock croc — files, folders, text, and
zipped folders, with resume/skip, local-network hand-off (IPv4 + IPv6
discovery), direct `--ip`, throttling, all four hash algorithms, `.gitignore`
mode, SOCKS5 / HTTP-CONNECT proxies, and public-DNS relay resolution
(`--internal-dns`). The PAKE runs on constant-time curve arithmetic for
*every* curve — the standard NIST curves via RustCrypto and croc's
nonstandard SIEC via a from-scratch Montgomery backend — key material is
zeroized on drop, and the parsers have `cargo-fuzz` harnesses. Verified end-to-end against the real Go binary in
`scripts/interop_test.sh`. See [MIGRATION.md](MIGRATION.md) for the full
analysis and module mapping, and [CHANGELOG.md](CHANGELOG.md) for release
notes.

## Usage

```sh
# Send a file or folder (prints a code phrase)
rusty-croc send my-file.txt

# Receive on the other machine (rusty-croc or stock croc, either works)
rusty-croc receive 1234-foo-bar-baz
CROC_SECRET=1234-foo-bar-baz croc     # stock croc receiving from rusty-croc

# Start a relay that stock croc clients can use
rusty-croc relay --ports 9009,9010,9011,9012,9013 --pass pass123

# Health-check any croc relay (Go or Rust)
rusty-croc ping croc.schollz.com:9009
```

```sh
# More ways to send
rusty-croc send --text "quick message"      # send text instead of a file
echo hi | rusty-croc send -                 # send stdin
rusty-croc send --zip my-folder             # zip the folder first
rusty-croc send --throttle 10M big-file     # limit upload speed

# Receive directly from a sender on your network (no relay round-trip)
rusty-croc receive --ip 192.168.1.5:9009 <code>
```

Useful flags: `--relay host:port`, `--pass`, `--yes` (skip the accept
prompt), `--overwrite`, `--curve p256|p384|p521|siec`,
`--hash xxhash|imohash|highway|md5`, `--no-compress`, `--no-multi`,
`--local` (LAN only), `--no-local`, `--exclude .git,node_modules`,
`--git` (respect `.gitignore`), `--qr` (show the code as a QR code),
`--remember` (persist relay settings), `--socks5 host:port` /
`--connect host:port` (or `$SOCKS5_PROXY` / `$HTTP_PROXY`).

If the relay drops mid-transfer, both sides reconnect in a pre-agreed
rendezvous room and resume where they left off (croc's ReconnectVersion 1 —
works cross-implementation with stock croc).

When sender and receiver share a network, rusty-croc behaves like croc: the
sender starts a local relay and announces it (UDP multicast + the `ips?`
side-channel through the relay), and the receiver hops onto it so data never
leaves the LAN.

## What's ported

| Area | Status |
|---|---|
| Frame protocol (`comm`) | ✅ byte-compatible |
| Encryption (`crypt`: PBKDF2+AES-GCM, Argon2id+XChaCha20) | ✅ vector-tested against Go |
| Message envelope (`message`, JSON+DEFLATE+AES) | ✅ vector-tested against Go |
| PAKE (schollz/pake v3, incl. the SIEC curve) | ✅ live-tested against Go, both roles |
| Code phrases (`mnemonicode`) | ✅ vector-tested against Go |
| Relay server + relay client handshake (`tcp`) | ✅ end-to-end with stock croc |
| File-transfer engine (`croc`: send/receive, folders, resume) | ✅ interop-tested both directions |
| Local-network path (discovery, local relay, `ips?` probe, `--ip`) | ✅ interop-tested both directions |
| Text sending, stdin, `--zip`, `--throttle`, imohash/highway | ✅ interop-tested |
| Reconnect-and-resume after relay drops (ReconnectVersion 1) | ✅ interop-tested |
| `--exclude`, `--qr`, `--remember`, code prompt | ✅ |
| `--git` (.gitignore), SOCKS5/HTTP proxies, IPv6 discovery | ✅ interop/unit-tested |
| Zeroized key material, `cargo-fuzz` parser harnesses | ✅ |
| Constant-time PAKE curves — p256/p384/p521 (RustCrypto) + SIEC (own Montgomery backend) | ✅ interop-tested |
| Custom-DNS relay resolution (`--internal-dns`) | ✅ live-tested |

## Performance

Full-stack loopback benchmark (each implementation's own client + relay,
best-of-N, 4-core machine — see `scripts/bench.sh`). Loopback isolates
CPU/protocol cost; over a real network both are network-bound and tie.

| Scenario | rusty-croc | Go croc |
|---|---|---|
| Handshake latency (64 KiB) | 0.32 s | **0.28 s** |
| 200 MB random, compression on (default) | **97 MB/s** | 57 MB/s |
| 200 MB random, `--no-compress` | **240 MB/s** | 192 MB/s |
| 200 MB zeros, compression on | **230 MB/s** | 65 MB/s |
| Peak RSS (200 MB transfer) | ~6 MB | ~6 MB |
| Binary size | **4.8 MB** | 15.0 MB |

rusty-croc is faster on throughput (most on the compression path, where
`flate2` beats Go's `compress/flate`) at equal memory and a third of the
binary size. Go retains a small edge on fixed handshake latency. Run it
yourself: `CROC_SRC=/path/to/croc scripts/bench.sh`.

## Fuzzing

The frame, message-envelope, PAKE, and mnemonicode parsers have
`cargo-fuzz` targets under `fuzz/`:

```sh
cargo +nightly fuzz run message   # or: frame, pake, mnemonicode
```

## Development

```sh
cargo test                  # self-contained tests incl. Go-generated vectors
cargo fmt --all --check     # formatting
cargo clippy --all-targets  # lints
scripts/interop_test.sh     # live Go↔Rust interop (needs Go toolchain + git)
scripts/bench.sh            # rusty-croc vs Go croc throughput/latency
```

CI (`.github/workflows/ci.yml`) runs fmt + clippy + tests and the full
interop suite against a freshly built stock Go croc on every push and PR;
the parser fuzz targets run on a weekly schedule.

The module layout mirrors the Go source tree (`src/comm.rs` ↔ `src/comm`,
etc.) to keep the port reviewable side by side with upstream.

## License

MIT, matching upstream croc. The mnemonic word list is from the original
mnemonicode project (Oren Tirosh, MIT).
