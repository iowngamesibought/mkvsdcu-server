//! Wire-format contracts for the MKVSDCU service.
//!
//! This crate is deliberately pure: no sockets, no TLS, no clock and no
//! randomness. It models only the messages the shipped client sends or
//! accepts. The evidence trail and the implementation contract live in the
//! research repository:
//!
//! `docs/games/mortal-kombat-vs-dc-universe/rust-implementation-plan.md`
//!
//! Implemented slices:
//! - GameSpy availability probe (`gsAvailable.c`).
//! - Bounded HTTP/1 request parsing for the AuthService POST.
//! - AuthService certificate-login SOAP request/response (`AuthService.c:574-719`).
//! - GPCM pre-authenticated login framing and proof (`GP/gpiConnect.c`).
//! - PeerChat line format and the `CRYPT des` stream cipher (`Chat/chatCrypt.c`).

pub mod authservice;
pub mod availability;
pub mod gp;
pub mod gpsp;
pub mod gstats;
pub mod http;
pub mod natneg;
pub mod peerchat;
pub mod stats;
