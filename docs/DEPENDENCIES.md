# Dependencies

## Build toolchain

| Dependency | Version | Use |
| --- | --- | --- |
| Rust / Cargo | 1.99.1, edition 2024, `x86_64-pc-windows-msvc` | Build and test; pinned in `rust-toolchain.toml` |
| OpenSSL (native) | 3.5.8, static MSVC build with `enable-ssl3`, `enable-ssl3-method`, `enable-weak-ssl-ciphers`, `no-shared`, `no-module` | SSL3/RC4-MD5 AuthService transport, RSA keys, certificates and randomness |

`.cargo/config.toml` sets a default `OPENSSL_DIR` pointing at the verified
local build. A real `OPENSSL_DIR` environment variable overrides it. The
native library must be built with SSL3 and weak ciphers; a default OpenSSL 3
build cannot serve the AuthService listener.

## Rust crates (locked in `Cargo.lock`)

| Crate | Version | Use |
| --- | --- | --- |
| `openssl` | 0.10.81 | TLS acceptor, certificate generation, RNG |
| `md5` | 0.8.0 | GPCM password hash and server proof |
| `serde` | 1.0.229 | Typed configuration deserialization |
| `toml` | 0.9.12 | TOML parsing with unknown-key rejection |

No async runtime, database driver, HTTP client or logging framework is used.
The server runs one thread per listener plus one thread per connection.

## External services

| Service | Status |
| --- | --- |
| Platform sign-in and account ticket | Remains the console's own connection to its platform. The server does not contact the platform service, does not validate the account ticket and never logs it. |
| GameSpy / other third-party services | Not contacted. No discovery, probing or connection is performed. |
| DNS | Operator-provided local override. The server does not run a DNS server. |

## Runtime data

M1 has no runtime game-file dependency: it does not read the executable or an
archive. The only game-derived input is `[peerchat] title_secret`, which the
operator supplies in the git-ignored local TOML. No database is used.

## Research references (not linked, not shipped)

- Pinned OpenMOHAA GameSpy SDK snapshot at
  `openmoh/openmohaa@a2f340195975f4f042e28a60b62561dd9a0b2700`, kept in the
  research workspace. It is behavioral evidence for client-side wire formats;
  no source is compiled, copied or linked into this project.
- Static analysis and protocol evidence in
  the separate research tree, outside this repository.

Both are research material, not execution instructions. Their licenses are
recorded in `THIRD_PARTY_NOTICES.md` and, for the snapshot, in its own license
files.
