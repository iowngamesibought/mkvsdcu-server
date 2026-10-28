# Third-party notices

| Component | Version / source | Use | License |
| --- | --- | --- | --- |
| OpenSSL | 3.5.8, static MSVC build at a local static build directory outside this repository | Native TLS/crypto for the legacy SSL3/RC4-MD5 listener; RSA key and certificate generation | Apache-2.0 |
| openssl (Rust crate) | 0.10.81 (crates.io) | Safe Rust bindings to the native library above | Apache-2.0 / MIT |
| md5 (Rust crate) | 0.8.0 (crates.io) | GPCM proof and password hash | Apache-2.0 / MIT |
| serde / toml (Rust crates) | 1.0.229 / 0.9.12 (crates.io) | Typed TOML operator configuration | Apache-2.0 / MIT |
| OpenMOHAA GameSpy SDK snapshot | `openmoh/openmohaa@a2f340195975f4f042e28a60b62561dd9a0b2700`, local research copy | Behavioral reference for client-side wire formats only; not linked, not copied into this project | See the snapshot's own license files; recorded in the research repository |

No GameSpy SDK source, decompiled game code, or third-party private-server code is compiled into this project. The service is implemented from the documented wire behavior and from evidence held in a separate research tree outside this repository.
