# Deployment

Status: **partially verified**. Login, the stats read and chat registration are
confirmed on the operator's console. Matchmaking and the result path are
implemented and locally tested but have not been through a two-console run.

## Supported environment

- Server host: Windows, Rust/Cargo 1.99.1 with the MSVC target, matching
  `rust-toolchain.toml`.
- Native OpenSSL 3.5.8 static MSVC build with SSL3 and weak ciphers enabled;
  see `DEVELOPMENT.md` and `.cargo/config.toml`.
- Local network reachable by the console. The server does not need internet
  access for its own operation.
- The console signs in to its platform account service itself. The server never
  contacts that service and never sees the console's account credentials.
- Two consoles, for anything past the online menu. A match is played between
  two of them directly; the server only introduces them.

## Build

```powershell
cd Z:\projects\mkvdc_server
cargo build --release --locked
```

There is no prebuilt binary and no installer. The build output is
`target\release\mkvsdcu-server.exe`.

## Configuration

1. Copy `mkvsdcu-server.example.toml` to the git-ignored `mkvsdcu-server.toml`.
2. Set each bind address to the interface the console can reach. The loopback
   examples are not reachable from a console and are for local tests only.
3. Set `[peerchat] title_secret` from the operator's own copy of the game. The
   example value is a placeholder. Keep the real value in the ignored local
   TOML only.
4. Enable `[natneg]`, `[gstats]` and `[identity]`. Without `[natneg]` two
   consoles cannot reach each other; without `[identity]` there are no durable
   player records for a result to update.
5. Validate without opening a listener:

   ```powershell
   .\target\release\mkvsdcu-server.exe --check-config --config <absolute path>\mkvsdcu-server.toml
   ```

The configuration rejects unknown keys, port zero, duplicate TCP binds, an
empty or oversized title secret and out-of-range body limits.

## Ports

| Service | Transport | Needed for |
| --- | --- | --- |
| Availability | UDP 27900 | The first probe of the online flow |
| AuthService | TCP 443 | Login, over SSL3/RC4-MD5 |
| Initial stats HTTP | TCP 80 | The player-history read the title makes before chat |
| GPCM | TCP 29900 | The player session every later service checks |
| PeerChat | TCP 6667 | Rooms, metadata and the challenge exchange |
| Profile search | TCP 29901 | Resolving an opponent's nickname during a challenge |
| NAT negotiation | UDP 27901 | Getting two consoles into one match |
| Result ingestion | TCP 29920 | Match results and the player records |

Allow these inbound on the server machine from the local network only. Do not
forward them on the router. Do not expose the server to the internet: it has no
authentication beyond the token it mints, no rate limiting and no TLS peer
verification.

## DNS

The console must resolve the game's compiled-in GameSpy host names to the
server. Follow `AGENTS.md` step 2 and the `dns-override` skill. Recovered host
names stay in the operator's local DNS notes; never put them in this
repository.

Seven names are needed, by role: availability, AuthService, the stats web host,
GPCM, PeerChat, and **all three NAT-negotiation matchup hosts**. The three
matchup names must all resolve to this server, on the one UDP port above.

That last point is easy to get wrong and silently breaks matchmaking, in two
separate ways.

**Resolution happens first, for all three names together.** Before it sends
anything, the title resolves the three matchup host names and caches the
results. If *any* of the three fails to resolve, negotiation returns a DNS
error immediately and **no packet is ever sent**, so nothing appears in this
server's log at all. Login and rooms still work; the challenge is still
delivered; the match then fails at once with nothing pointing at DNS.

**Then every source must be acknowledged.** Once resolution succeeds the title
sends an init from each source it intends to use and will not start a match
until each one is acknowledged.

Two practical consequences:

- Verify all three names from the console's own resolver, not from the server
  host: `nslookup <name> <console's DNS server>`.
- Resolved addresses are cached for the life of the process. If the console
  ever resolved these names to anything else, **restart the game** after
  correcting DNS; backing out of the online menu is not enough.

## Start

```powershell
.\target\release\mkvsdcu-server.exe run --config <absolute path>\mkvsdcu-server.toml
```

Expected listeners:

```text
[availability] listening on <address> (UDP)
[auth] listening on <address> (TCP, SSLv3, RC4-MD5, self-signed)
[stats] listening on <address> (TCP, HTTP)
[gp] listening on <address> (TCP, GPCM)
[peerchat] listening on <address> (TCP, PeerChat)
[natneg] listening on <address> (UDP, v3 rendezvous)
[gstats] listening on <address> (TCP, result ingestion)
```

The certificate is generated in memory at startup; nothing is written to disk.
Stopping the process discards the certificate and all AuthService tokens.
Player records persist in the `[identity]` directory.

## Reading a match in the log

A match between two consoles should produce, in order:

```text
[rooms] <channel> session generation=<n> profiles=[<a>, <b>]
[natneg] cookie=<c> client=0 registered porttype=... from=...
[natneg] cookie=<c> client=1 registered porttype=... from=...
[natneg] cookie=<c> paired both clients
[natneg] cookie=<c> connect to=<console> partner=<other console>
[gstats] authentication accepted
[gstats] generation=<n> committed=true winner=<a> loser=<b> disconnect=None
```

Where it stops says what failed:

| Last line seen | Meaning |
| --- | --- |
| Challenge exchanged, then both consoles `PART` and `QUIT`, with **no `[natneg]` line at all** | The console gave up before sending anything. `NNBeginNegotiationWithSocket` returns an error without a single packet in two cases: the negotiation SDK was never initialized, or **it could not resolve all three matchup host names**. The second is far more likely. No server change can affect this; fix name resolution on the console. See "DNS" above. |
| No `[rooms] ... session` line | The two consoles never announced the same match. The challenge did not get through, or one of them was not in the room. |
| `registered` for one client only | The other console never reached the matchup hosts. Check that all three matchup names resolve here. |
| `registered` but never `paired` | A console did not register every source. Same cause: usually one matchup name still resolving elsewhere. |
| `no partner for <address>` | One console negotiated alone for 30 seconds. Its opponent never started, or started a different match. |
| `paired` but no `[gstats]` | The consoles could not reach each other directly. Expected when they are behind separate routers; this server does not relay gameplay. |
| `result not recorded: ...` | The report arrived but could not be tied to a watched pairing. The message says which check failed. |
| `only profile <id> reported; nothing recorded` | One console's account arrived and its opponent's did not, within the agreement window. A match counts only on agreement, so neither record moves. |

## Current deployment limits

- No service supervision, restart policy, log rotation or deployment script.
- A restart invalidates all sessions and tokens; a console has to log in again.
  Player records survive, match pairings in progress do not, and a result that
  was decided but not yet written is lost with them. That is accepted: a match
  moves both players' counters together or not at all, and nothing durable
  records matches themselves.
- No gameplay relay. If two consoles cannot reach each other after negotiation,
  the match cannot start; there is no fallback path.
- No hardware acceptance for matchmaking or results. Treat a console run as
  evidence only after its log is captured and checked against `AGENTS.md`.

## Rollback

Stop the process and remove the local DNS override. Player records stay in the
`[identity]` directory; delete that directory to discard them.
