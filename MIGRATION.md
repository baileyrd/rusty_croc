# Migrating croc to Rust

This repository is a Rust port of [schollz/croc](https://github.com/schollz/croc)
(v10, ~8k lines of Go excluding tests) — a tool for securely sending files
between two computers via a code phrase, using a relay when the peers cannot
connect directly.

The port's guiding constraint is **wire compatibility**: a rusty-croc relay
must serve stock Go croc clients, and (eventually) a rusty-croc client must
talk to stock relays and stock peers. That constraint drives most of the
design decisions below, and it is already verified end-to-end for the relay
(see [Verification status](#verification-status)).

## croc's architecture (what we're porting)

| Go package | Lines | Role |
|---|---|---|
| `src/croc` | ~3,000 | Client engine: send/receive state machine, chunked transfers, resume, local-network discovery |
| `src/cli` | ~840 | CLI (urfave/cli): flags, config persistence, code-phrase entry |
| `src/tcp` | ~780 | Relay server: PAKE-authenticated rooms, socket stapling, multi-port transfers |
| `src/utils` | ~890 | Hashing (xxhash/imohash/highwayhash), file walking, IP discovery, misc |
| `src/comm` | ~220 | Framed TCP messaging (also SOCKS5/HTTP proxy dialing) |
| `src/message` | ~90 | JSON control-message envelope (compressed + encrypted) |
| `src/crypt` | ~125 | PBKDF2 + AES-256-GCM; Argon2id + XChaCha20-Poly1305 |
| `src/compress` | ~55 | Raw DEFLATE via `compress/flate` |
| `src/mnemonicode` | ~400 | Bytes → memorable words for code phrases (vendored, MIT) |
| `src/models` | ~170 | Constants, default relay resolution (incl. custom DNS) |
| `src/diskusage`, `src/install`, `src/message` | misc | Platform helpers |

Key third-party dependencies and their protocol relevance:

* **`schollz/pake/v3`** — SPAKE2-style PAKE (Boneh–Shoup fig. 21) over a
  pluggable curve. Wire format is JSON of the public struct fields, whose
  names contain Unicode subscripts (`Uᵤ`, `Xᵥ`, …) and whose coordinates are
  arbitrary-precision decimal JSON numbers (Go `big.Int`).
* **`tscholl2/siec`** — a nonstandard 255-bit "super-isolated" elliptic curve
  (y² = x³ + 19 over a 255-bit prime, generator (5,12)). **The relay
  handshake hardcodes this curve**, so no Rust port can interop with stock
  croc without implementing SIEC — no crates.io implementation exists. The
  peer-to-peer PAKE defaults to `p256` and negotiates the curve in-band
  (recipient's choice, sent alongside its PAKE message).

## The wire protocol (as implemented by croc v10)

### Framing (`comm`)

Every message on every socket (except raw piped transfer bytes) is framed:

```
b"croc" | u32 little-endian payload length | payload
```

Reads are guarded by a 64 MiB max size, a 3 h idle deadline and a 10 min
body deadline.

### Relay handshake (`tcp`)

1. Client → relay: PAKE role-0 message over **siec** with the fixed weak key
   `[1,2,3]`; relay answers with its role-1 message. Both derive
   `strongKey = SHA-256(pw ‖ X ‖ Y ‖ Z)`.
   (Alternatively a client sends the literal frame `ping` and gets `pong` —
   that's the health check.)
2. Client → relay: 8-byte salt; both sides compute
   `key = PBKDF2-HMAC-SHA256(strongKey, salt, 100 iters, 32 bytes)`.
   All further frames on this socket are `AES-256-GCM(12-byte nonce ‖ ct ‖ tag)`.
3. Client → relay: encrypted relay password (default `pass123`; this is
   access control for the relay, not transfer security). Relay → client:
   `"<banner>|||<client-external-ip>"`, where the banner on the main port
   lists the extra transfer ports (e.g. `9010,9011,9012,9013`).
4. Client → relay: room name (croc uses the first characters of the code
   phrase). First occupant gets `ok` and then a framed `[1]` keep-alive every
   second. When the second occupant joins, the relay sends it `ok` and
   staples the sockets — from then on it pipes raw bytes both ways and the
   clients speak directly to each other (encrypted end-to-end with keys the
   relay never learns).

### Peer protocol (over the stapled connection)

1. Peers run a second PAKE using the code phrase (minus the room prefix) —
   default curve `p256`, recipient picks and announces the curve. The exchange
   is bound to the room and its purpose (croc peer PAKE protocol version 2,
   `src/pakekey`): the session key is expanded with HKDF-SHA256 over the exact
   transcript (purpose, room, curve, both wire values, a 32-byte salt from the
   sender) into the transfer key plus two confirmation tags, which both sides
   exchange as `pake-confirm` before any encrypted traffic flows. A peer that
   announces a different protocol version is rejected.
2. Control messages are `message.Message` JSON
   (`{"t","v","m","b","b2","n","f"}`, byte fields base64) → DEFLATE → AES-256-GCM,
   covering: `pake`, `pake-confirm`, `externalip`, `fileinfo`,
   `recipientready`, `finished`, `error`, `close-*`.
3. File data flows over N parallel connections (the extra relay ports), in
   chunks: `u64 LE file position ‖ chunk data`, encrypted, with per-file
   hashing (xxhash default; imohash/highwayhash options) for resume support.

## Rust module mapping

| Go | Rust | Status | Notes |
|---|---|---|---|
| `src/comm` | `src/comm.rs` | ✅ ported | Frame-byte compatible (unit-tested against exact Go frame bytes). Proxy dialing deferred. |
| `src/crypt` | `src/crypt.rs` | ✅ ported | Verified against Go-generated PBKDF2/AES-GCM vectors. |
| `src/compress` | `src/compress.rs` | ✅ ported | `flate2`; decodes Go's HuffmanOnly output (vector-tested). Streams are mutually decodable, not byte-identical — that's fine, DEFLATE is DEFLATE. |
| `src/message` | `src/message.rs` | ✅ ported | JSON field names/base64/omitempty match Go exactly (vector-tested). |
| `src/mnemonicode` | `src/mnemonicode.rs` | ✅ ported | Same 1633-word list + algorithm, vector-tested. |
| `schollz/pake/v3` | `src/pake.rs` | ✅ ported | All four curves incl. SIEC, written against Go-generated curve vectors; live-tested against Go in both roles. `ed25519` option not yet ported (croc never defaults to it). |
| `src/tcp` | `src/tcp.rs` | ✅ ported | Relay serves stock Go croc clients (verified end-to-end); client-side `connect_to_tcp_server` verified against the stock Go relay. |
| `src/models` | `src/models.rs` | ✅ constants | Custom-DNS default-relay resolution deferred. |
| `src/utils` | `src/utils.rs` | ✅ core ported | Code phrases, all four hash algorithms (xxhash/imohash/highway/md5, vector-tested), chunk ranges, open-port scan, local IPs. |
| `schollz/peerdiscovery` | `src/discovery.rs` | ✅ ported | UDP multicast announce/discover (IPv4; same wire format, same self-filter semantics). IPv6 group pending. |
| `src/croc` | `src/croc.rs` | ✅ ported | Send/receive engine incl. the local path: auto-started local relay, multicast announce, `ips?` probe hand-off, `--ip` direct, zip mode, text mode, throttling. Reconnect-after-drop pending (phase 4). |
| `src/cli` | `src/main.rs` | 🟡 mostly | `send` (files/folders/text/stdin/zip/throttle), `receive`, `relay`, `ping`. Pending: `--remember`, QR, proxies, excludes, `--git`. |
| `src/diskusage`, `src/install` | — | ⬜ later | Platform niceties, not protocol. |

### Crate choices

* **Crypto**: RustCrypto (`aes-gcm`, `chacha20poly1305`, `pbkdf2`, `argon2`,
  `sha2`) — mature, pure-Rust, parameter-compatible with `golang.org/x/crypto`.
* **Curve math for PAKE**: `num-bigint` with a generic affine short-Weierstrass
  implementation. Rationale: (a) SIEC exists in no Rust crate, so bignum math
  is required anyway; (b) the PAKE wire format serializes raw affine
  coordinates as decimal, which fights the RustCrypto curve APIs; (c) it
  mirrors what Go does (`math/big` via `crypto/elliptic`'s legacy interface —
  also not constant-time in the SIEC path). Hardening note below.
* **Concurrency**: std threads, mirroring croc's goroutine structure 1:1.
  The relay is I/O-light (a few sockets per transfer); async brings no win at
  this scale and a large complexity tax during a port whose main risk is
  protocol divergence. Revisit tokio in phase 4 if relay fan-out matters.
* **CLI**: `clap` (derive) in place of `urfave/cli`.
* **JSON**: `serde_json` with `arbitrary_precision` (required: PAKE
  coordinates are >64-bit JSON numbers; without the feature they'd be lossily
  parsed as `f64`).

### Compatibility gotchas discovered while porting

These are the traps for anyone continuing this migration:

1. **SIEC is mandatory** for relay interop (hardcoded in `tcp.go`), even
   though peers default to p256.
2. **Go `big.Int` marshals as a bare decimal JSON number** of arbitrary size;
   `serde_json` needs `arbitrary_precision` or values silently round-trip
   through `f64` and corrupt.
3. **Go `[]byte` marshals as standard-alphabet padded base64 strings** in
   `message.Message`.
4. **`big.Int.Bytes()` is minimal big-endian and empty for zero** — the PAKE
   session-key hash transcript depends on this exact encoding.
5. **`omitempty` semantics** must be mirrored field-by-field or JSON
   comparisons (and hashes over JSON) diverge.
6. **The PAKE struct's JSON keys contain Unicode subscript characters**
   (`Uᵤ`); serde derive + rename handles it, but hand-rolled serializers must
   emit them byte-exactly.
7. **The relay keep-alive `[1]` frames** interleave with the handshake on the
   first occupant's socket; clients must skip them, and the relay must stop
   sending them under the same lock that staples the room, or a stray `[1]`
   corrupts the piped stream.
8. **PBKDF2 with 100 iterations** (not a typo — croc's choice, presumably for
   throughput on the already-high-entropy PAKE output) and **8-byte salts**.
   That schedule is still what the relay handshake uses; the *peer* transfer
   key moved to the HKDF/confirmation schedule in `src/pakekey.rs`.
9. Go's `elliptic.ScalarMult` semantics (scalar not pre-reduced) are safe to
   replicate with plain double-and-add because all four curves have prime
   order — reduction cannot change the result.
10. **`Pake.Bytes()` marshals the whole `Public()` struct**, so the wire value
   carries every field of Go's struct — including the private ones as `null`.
   Emitting a compact subset is *not* equivalent: croc decodes a `pake2` reply
   on top of the struct that still holds its own `pake1` value, and Go's JSON
   decoder reuses that backing array whenever the reply is shorter, which
   silently rewrites the peer's own copy of the transcript and makes the two
   sides derive different keys.

## Verification status

Everything below runs in `scripts/interop_test.sh` (needs Go + the croc
source) or `cargo test` (self-contained):

* ✅ `cargo test` — 38 unit tests, including Go-generated vectors for:
  PBKDF2 keys, AES-GCM decryption, DEFLATE decompression of Go output,
  message envelope decode (plain + encrypted), mnemonicode encodings,
  scalar/add/double results on all four curves, xxhash/md5 file hashes,
  and the FileInfo/SenderInfo/RemoteFileRequest/SimpleMessage JSON shapes.
* ✅ **Stock Go croc binary transfers a 1 MiB file through the rusty-croc
  relay** (5 ports, parallel transfer connections), checksums equal.
* ✅ Rust client handshake (`connect_to_tcp_server`) joins a room on the
  stock Go relay and reads the banner.
* ✅ **Transfer matrix through the rusty-croc relay**: rust→rust,
  rust→go, and go→rust file transfers, checksums equal. Folder transfers
  (nested + empty dirs) and identical-file skip verified in both
  directions during development.
* ✅ **Local-network route**: a stock Go recipient's `ips?` probe hops
  onto the rusty-croc sender's auto-started local relay (and vice versa —
  the Rust recipient hops onto Go's); `--ip` direct connections verified
  both directions; multicast announce/discover unit-tested over loopback.
* ✅ **`--text` both directions**, **`--zip` go→rust** (auto-unpacked),
  `--throttle` rate limiting, and a live identical-file skip with
  `--hash imohash` across implementations.
* ✅ **Reconnect-and-resume**: the relay severs every piped connection
  mid-transfer (test hook); rust↔rust, rust→go, and go→rust all detect the
  interruption, rendezvous in the reconnect room, and finish with matching
  checksums.
* ✅ **`--git`**: a rust sender with `--git` omits `.gitignore`d files; a
  stock Go recipient receives only the kept files.
* ✅ **SOCKS5 tunnel** unit-tested end-to-end (greeting → CONNECT → bridged
  echo); **IPv6 loopback discovery** unit-tested; parser **fuzz targets**
  run clean (mnemonicode >1M execs, message/frame tens of thousands, no
  panics).

## Roadmap

### Phase 1 — foundations + relay (done)

See the mapping table.

### Phase 2 — the file-transfer engine (done: core)

`src/croc.rs` ports the transfer state machine: peer PAKE with curve
negotiation, the transcript-bound key schedule and `pake-confirm` round
(`src/pakekey.rs`), the optional pake1/ips?
handshake probe (answered for stock recipients doing local discovery),
`fileinfo`/`recipientready` exchange, parallel chunked transfer striped
round-robin over the relay's transfer ports (`u64 LE position ‖ data`,
per-chunk DEFLATE + AES-GCM), missing-chunk resume, folder + empty-folder
+ symlink handling, and the close/finished handshakes.

Notable divergences (documented in code): `ModTime` is sent as Go's zero
time (peers then skip their optional chtimes on skipped files), reconnect
support is declared as version 0 (Go peers fall back to no-reconnect),
and `imohash`/`highway` hash options aren't ported yet.

### Phase 3 — local-network path + everyday features (done: core)

* **Local path**: the sender auto-starts a relay on open ports (0.0.0.0),
  announces `croc<port>` over UDP multicast (`src/discovery.rs`, same wire
  format as `peerdiscovery`), and races the local route against the remote
  relay. The recipient tries multicast discovery, then the `ips?` probe —
  a SimpleMessage PAKE + encrypted query over the relay that returns the
  sender's `[local-port, ip...]` — and hops onto the sender's local relay
  when reachable. `--ip` connects straight to a sender. Verified against
  stock croc in both directions (the probe hand-off is croc's own
  same-host/TestFlag path; multicast between distinct hosts is
  unit-tested via loopback).
* **`--text` / stdin**: temp `croc-stdin-*` files with `SendingText`,
  printed on arrival; incoming text files get random local names exactly
  like Go (this matters — without the rename, a same-directory transfer
  self-skips).
* **`--zip`**: folders zipped (stored, base-name-prefixed entries like
  `utils.ZipDirectory`), sent as `TempFile`, auto-unpacked and removed on
  the receiving side.
* **`--throttle`**: token-bucket rate limit shared across data threads.
* **imohash/highway**: full hash-algorithm parity, vector-tested and
  live-tested (identical-file skip with `--hash imohash` across
  implementations).

Still pending from this phase: IPv6 multicast group, custom
`--multicast` address.

### Phase 4 — reconnect + CLI tail (done: core)

* **Reconnect-and-resume (ReconnectVersion 1)**: each `fileinfo` announces
  a fresh random rendezvous room; both sides advertise version 1 (SenderInfo
  and RemoteFileRequest). On a mid-transfer disconnect (classified from the
  control-connection error), each side backs off (100 ms · 2ⁿ, capped 5 s),
  resets its transfer state, rejoins the reconnect room on the first
  reachable relay candidate (current control address, then the original
  relay), redoes the handshake (sender waits ≤ 2 s, like Go), and reruns
  the transfer — the recipient's missing-chunk request makes the resume
  incremental. Verified cross-implementation in both directions using the
  relay's test-only `--test-sever-after` hook, which drops every piped
  connection once N bytes have crossed (a deterministic "network blip").
* **CLI tail**: interactive code prompt on receive (TTY only), `--exclude`
  (case-insensitive substring on the remote path, post-walk, like cli.go),
  `--qr` terminal QR code, `--remember` (persists relay/pass/curve to
  `$XDG_CONFIG_HOME/rusty-croc/{send,receive}.json` — a rusty-croc-owned
  file, so stock croc's config is never touched).

### Phase 5 — remaining features + hardening (done: core)

* **Proxies**: SOCKS5 (RFC 1928, no-auth, domain-name CONNECT) and HTTP
  `CONNECT` tunnels, in `src/comm.rs`, selected by `--socks5` / `--connect`
  (or `$SOCKS5_PROXY` / `$HTTP_PROXY`). Skipped for local destinations via
  a port of `utils.IsLocalIP` (RFC1918 / loopback / link-local / ULA).
* **`--git`**: `.gitignore` respected during file collection using the
  `ignore` crate with `require_git(false)`, so rules apply even outside a
  git repo (matching croc, which compiles `.gitignore` directly).
* **IPv6 discovery**: `src/discovery.rs` now opens either an IPv4
  (`239.255.255.250`) or IPv6 (`ff02::c`) multicast socket; the sender
  announces and the recipient discovers on both stacks concurrently, like
  croc.
* **Zeroization**: `Pake` wipes its password, blinding scalar, and session
  key on drop; the client wipes the derived transfer key on drop, on
  rekey, and on reconnect reset (`zeroize` crate).
* **Fuzzing**: `cargo-fuzz` targets for the frame reader, message envelope,
  PAKE update, and mnemonic encoder (`fuzz/`); a deterministic
  garbage-input robustness test also runs under `cargo test`.

### Phase 6 — constant-time curves (done)

* The standard NIST curves (`p256`, `p384`, `p521`) now run their PAKE
  scalar multiplications and point additions through the audited RustCrypto
  crates (`p256`/`p384`/`p521`, `arithmetic` feature) — constant-time with
  respect to the secret scalar, unlike the previous `num-bigint`
  double-and-add. `src/pake.rs` keeps the affine-coordinate wire format:
  each op converts big-int coordinates in, runs the constant-time group
  operation, and converts back out. Scalars are reduced mod the group order
  first — Go's `crypto/elliptic.ScalarMult` leaves the scalar unreduced, but
  every one of these curves is prime-order with cofactor 1, so
  `k·P == (k mod n)·P` and the point is byte-identical (the Go-generated
  vector tests confirm this).
* **SIEC** was later given its own constant-time backend too (`siec_ct`),
  so *every* curve rusty-croc offers is now constant-time in the scalar —
  see the "Constant-time SIEC" section below.
* Bonus: the constant-time field arithmetic is also markedly faster than
  bignum, cutting the unit-test suite runtime ~4×.

### Constant-time SIEC (exceeds upstream)

SIEC (`y² = x³ + 19` over a 255-bit prime) is croc's nonstandard
relay-handshake curve; no crate implements it and Go's `tscholl2/siec` is
variable-time, so this is the one place the port goes *beyond* the
reference rather than matching it. `src/pake.rs::siec_ct` implements it
constant-time in the scalar:

* Field arithmetic is `crypto-bigint`'s Montgomery form (`FixedMontyForm`),
  which is constant-time.
* Point addition uses the Renes–Costello–Batina **complete** formula
  (Algorithm 7, `a = 0`) in homogeneous projective coordinates — uniform,
  so the same operations run for `P + Q`, `P + P`, and identity, with no
  input-dependent branches.
* Scalar multiplication is a **double-and-add-always** ladder with `subtle`
  conditional selection, processing exactly `8·len(k)` bits (the length is
  public: the 3-byte weak key for the handshake, or a 32-byte ephemeral).

Verified byte-identical to Go via the existing SIEC vector tests
(`scalar_base_mult`/`scalar_mult`/`add`) and the full siec handshake, and
live against stock croc in both roles: the relay handshake (whose ephemeral
scalar *is* secret) and a peer PAKE over `--curve siec`.

Security note: this has marginal practical value — SIEC only guards the
relay handshake, whose only secret is a per-connection ephemeral, and the
peer PAKE (with the user's actual secret) defaults to the now-constant-time
p256. It's a completeness/craftsmanship item, and it removes the last
variable-time scalar path from the codebase.

### Phase 7 — custom-DNS relay resolution (done)

* `--internal-dns` resolves the relay hostname by querying a hardcoded list
  of public DNS resolvers directly over UDP:53, for when the local resolver
  is broken or censored (croc's identically named feature). `src/models.rs`
  hand-rolls a minimal DNS client — build an A/AAAA query, fan out to the
  resolvers in parallel, take the first answer — in the same
  dependency-light style as `comm`/`discovery`. `connect_relay` resolves the
  host up front so the transfer ports reuse the same IP. Without the flag,
  the system resolver is used (croc's `localLookupIP`), which was already
  the behavior.
* This closes the **last functional gap**: rusty-croc now matches stock
  croc v10 across every feature the reference implementation exposes.

### Performance

`scripts/bench.sh` benchmarks each implementation full-stack over loopback
(best-of-N). rusty-croc is faster on throughput at every size tested —
most on the compression path (`flate2`/miniz_oxide beats Go's
`compress/flate`), and still ahead with `--no-compress` — at ~equal peak
RSS (~6 MB, both stream in 32 KB chunks) and a third of the binary size
(4.8 MB vs 15 MB).

One regression surfaced by the benchmark and fixed: the transfer-port relay
handshakes were done **sequentially**, serializing N slow SIEC PAKEs and
inflating first-byte latency (~0.55 s). `process_pake` now fans them out
across threads like Go's goroutines, cutting handshake latency to ~0.32 s —
within ~40 ms of Go. (The SIEC handshake later moved to a constant-time
Montgomery backend, which is also faster than the old bignum path.)

### Phase 8 — divergence budget

* ~~Constant-time curve arithmetic for p256/p384/p521~~ — done (phase 6).
* ~~Zeroize key material~~ — done (phase 5).
* ~~Fuzz the frame/message/PAKE parsers~~ — done (phase 5, `fuzz/`).
* ~~Cross-check Go and Rust binaries in CI~~ — done: `.github/workflows/ci.yml`
  runs `scripts/interop_test.sh` (the full transfer matrix against a freshly
  built stock croc) on every push/PR, alongside fmt/clippy/tests, plus a
  weekly parser fuzz smoke.
* ~~Constant-time SIEC~~ — done (`src/pake.rs::siec_ct`); exceeds upstream.
  Every curve is now constant-time in the scalar.
* ~~Evaluate async for relay scalability~~ — done; see below. Threads are
  adequate; async deferred.
* Evaluate `croc`'s newer features as upstream moves (this port tracks
  v10.2.x behavior).

### Relay scalability (evaluated — threads kept)

The relay is thread-per-connection: a control thread per client plus two
pipe threads per stapled room, so a single transfer (1 control + N data
rooms) costs roughly `2·(N+1)` relay threads. `scripts/relay_scale.sh`
drives K simultaneous transfers through one relay over loopback and reports
success rate, peak thread count, and peak RSS.

Measured on a 4-core box (best-effort; loopback co-locates the clients):

| concurrent transfers | success | relay peak threads | relay peak RSS | notes |
|---|---|---|---|---|
| 30  | 30/30   | 615  | 25 MB | |
| 100 | 100/100 | 1307 | 50 MB | |
| 200 | 200/200 | 2095 | 75 MB | ~10.5 threads/transfer, linear |
| 400 | 223/400 | 2900 | 118 MB | **test-rig limit**, not the relay |

Threads and memory scale **linearly** (~10.5 threads and ~375 KB RSS per
concurrent transfer) with 100% success through 200 concurrent transfers.
The 400 row is *not* a relay ceiling: driving 400 transfers means 800
co-located client processes on 4 cores, which saturate CPU and time out —
the relay itself was still healthy at 2900 threads / 118 MB. On a dedicated
relay host (clients elsewhere), the practical ceiling is the OS thread
limit (here `ulimit -u` ≈ 64k), i.e. thousands of concurrent transfers.

**Conclusion: keep the thread model.** For personal/team relays and
moderate public use it is simple, correct, and comfortably sufficient.
Async (tokio) would cut per-connection memory and lift the ceiling to many
thousands of concurrent transfers, but only matters for a high-fanout
public relay, and the rewrite carries interop risk not justified by current
needs. Revisit if deploying at that scale.

## Building and testing

```sh
cargo build --release            # produces target/release/rusty-croc
cargo test                       # self-contained unit + vector tests
scripts/interop_test.sh          # full Go↔Rust interop (needs Go toolchain)

target/release/rusty-croc relay  # start a relay stock croc clients can use
target/release/rusty-croc ping 127.0.0.1:9009
```
