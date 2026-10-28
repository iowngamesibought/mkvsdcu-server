# Development

## Toolchain

- Rust/Cargo 1.99.1, edition 2024, `x86_64-pc-windows-msvc`, pinned by
  `rust-toolchain.toml`.
- OpenSSL 3.5.8 MSVC static build with `enable-ssl3`, `enable-ssl3-method`,
  `enable-weak-ssl-ciphers`, `no-shared` and `no-module`. The local default is
  set in `.cargo/config.toml`; a real `OPENSSL_DIR` takes precedence.

## Commands

```powershell
cargo test --workspace
cargo test --workspace --locked --offline
cargo build --release
cargo run --release --bin mkvsdcu-server -- --check-config --config <file>
cargo run --release --bin mkvsdcu-server -- run --config <file>
```

The workspace lives on a network share. If Cargo fails to remove or copy a test
binary with `os error 5`, set a local `CARGO_TARGET_DIR` (for example
`$env:TEMP\mkvdc-target`). Incremental compilation is disabled in
`.cargo/config.toml` for the same reason.

## Structure

- `mkvsdcu-proto` has no sockets, TLS, clock or randomness. It parses and builds
  wire messages, including the PeerChat line format and the GameSpy stream
  cipher, and has unit tests for framing, field order, MD5 vectors and
  cross-language cipher vectors (including a key with zero bytes).
- `mkvsdcu-server` owns listeners, the in-memory AuthService→session map,
  certificate generation, TLS policy and TOML configuration. The PeerChat
  listener derives one cipher per direction after the `CRYPT` key exchange; the
  keys are generated with `openssl::rand`, and avoiding a zero after the XOR is
  defensive rather than required by the pinned client.
- The session map is process-local and intentionally bounded (4096 entries,
  15-minute TTL). Both GPCM and PeerChat resolve the same AuthService token;
  there is no single-use restriction in M1.

## PeerChat title secret

`peerchat.title_secret` is the game's Peer title `sbSecretKey`. It is
game-derived, so it belongs only in the git-ignored local TOML; never in the
example, tests, logs, docs or commits. The loopback tests use a synthetic
secret. For this deployment the value was recovered from the operator's own
copy of update 01.01 and confirmed statically at the game's `peerSetTitleA`
call site (`0x878460`–`0x878490` in the decrypted update executable); it lives only
in the ignored local `mkvsdcu-server.toml` and is not yet verified against a
console. Do not brute-force or guess the real value; recover it from the
operator's own copy of the game, or stop.

## Test inventory

`cargo test --workspace` runs 48 tests: 35 in `mkvsdcu-proto`, 12 in
`mkvsdcu-server` (including GPCM and PeerChat loopback tests), and one SSL3
AuthService integration test. The PeerChat loopback tests cover the cipher key
exchange, `LOGINPREAUTH`, `USRIP`, `USER`/`NICK`, `CDKEY` and the `:s 708`
rejection path. They do not prove that a real client accepts the cipher or the
title secret.

## Evidence rule

Protocol changes start from the pinned SDK client source or a captured client
exchange. Do not infer a field from convenience. Unknown fields are logged, not
silently invented. A local loopback test is not console acceptance.
