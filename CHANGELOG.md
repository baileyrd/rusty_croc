# Changelog

## Unreleased

### Fixed

- Speak croc's peer PAKE protocol version 2, so transfers with stock Go croc
  work again instead of being rejected with "peer uses unsupported PAKE
  protocol version 0". The peer exchange is now bound to the room, purpose and
  wire transcript (new `src/pakekey.rs`: identity-bound PAKE, HKDF-SHA256 key
  schedule over a 32-byte salt, and a mutual `pake-confirm` round before any
  encrypted traffic), and `message.Message` carries the `v`/`f` fields.
- Emit croc's full `Pake.Bytes()` JSON, including the `null` fields of Go's
  `Public()` struct. A compact reply is shorter than the value it answers,
  which made Go peers decode it over their own stored `pake1` value and derive
  a different key on the local `ips?` probe.

## v0.1.0

First release: a Rust port of [croc](https://github.com/schollz/croc)
(schollz/croc, v10), **wire-compatible with the stock Go implementation** —
rusty-croc sends to, receives from, relays for, and reconnects alongside
stock croc.

### Features

- Secure peer-to-peer file/folder transfer over a PAKE-authenticated relay.
- Send files, folders, text (`--text`), stdin (`-`), and zipped folders (`--zip`).
- Local-network path: auto-started local relay, IPv4/IPv6 multicast discovery,
  the `ips?` probe hand-off, and direct `--ip` connections.
- Reconnect-and-resume after a mid-transfer relay drop (ReconnectVersion 1).
- Resume/skip via `xxhash` / `imohash` / `highway` / `md5` file hashing.
- Upload throttling (`--throttle`), `.gitignore` mode (`--git`), path
  exclusion (`--exclude`), QR codes (`--qr`), config persistence (`--remember`).
- SOCKS5 / HTTP-CONNECT proxies (`--socks5` / `--connect`); public-DNS relay
  resolution (`--internal-dns`).
- A full relay server (`relay`) that stock croc clients can use.

### Security

- Constant-time PAKE curve arithmetic for **every** curve: p256/p384/p521 via
  RustCrypto, and croc's nonstandard SIEC via a from-scratch Montgomery backend.
- Key material zeroized on drop.
- `cargo-fuzz` harnesses for the frame, message, PAKE, and mnemonicode parsers.

### Quality & performance

- Verified byte-for-byte and end-to-end against the real Go binary in both
  directions (`scripts/interop_test.sh`, 8 transfer groups).
- 49 unit tests, including Go-generated crypto/curve/wire vectors.
- CI runs fmt + clippy + tests + the live interop suite on every push/PR.
- Faster throughput than Go croc at equal memory and ~⅓ the binary size;
  near-parity handshake latency (`scripts/bench.sh`).

See [MIGRATION.md](MIGRATION.md) for the full architecture analysis, module
mapping, and the constant-time / scalability write-ups.
