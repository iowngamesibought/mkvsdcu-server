# Current status

Updated 2026-10-28. Login is confirmed on hardware; two-console play is not.

## Confirmed on the console

Availability, SSL3/RC4-MD5, AuthService and GPCM succeed, the client's GPCM
response matches the server calculation, the player-stats HTTP read completes,
and PeerChat reaches registration. The operator sees the online menu, their account
name on the leaderboard and their stats in User Statistics. Live logs show one
player row served through both HTTP views with no errors.

Two corrections were needed to get there and are in place: an explicit X.509
version field, and ordinary secure `USER`/`NICK` registration rather than
`LOGINPREAUTH` — update 01.01 uses `peerConnectA`, and the real order is
`CRYPT` then `USRIP`.

## How a match actually works

Established from the title's own code and the matching SDK sources, not guessed:

- A room is where players meet. A match is a separate one-versus-one session
  between two of them.
- Players publish their own metadata as room keys: `b_ip`, `b_addr`, `b_port`,
  `b_PID`, `b_mid`, `b_gt`, `b_gm`, `b_gv`, `b_s`, plus the SDK's `n` and `r`.
  A challenge travels as an opaque peer message; agreeing on a shared `b_mid`
  is what announces the match.
- `ConnectMatchJob` then runs `StepGetPreferredURL` → `StepWaitForGetPreferredURL`
  → `StepJoinNetSession` → `StepWaitForMatchConnection`. The first step calls
  `NNBeginNegotiationWithSocket(gameSocket, cookie, clientIndex, ...)` with the
  cookie and index the title already holds. The "preferred URL" is simply the
  endpoint negotiation returns.
- The engine session either side creates around a room or match is local to the
  console. Chat membership is not a gameplay session, and the server owns
  neither.
- **The server's whole role in a match is: relay the room metadata faithfully,
  pair the two negotiation requests that share a cookie, tell each client where
  the other is, and record what they report afterwards.** The match is played
  console to console.

The client will not advance until every source it sent an init from has been
acknowledged: the three matchup hosts plus the game port. All three matchup host
names must therefore resolve to this server. This is the single most likely
reason for a match that never starts.

## Implemented

- Availability, AuthService, GPCM, and X.509 v3 without extensions for the
  title's parser. Logout expires the session and its claims.
- Ordinary secure and pre-authenticated PeerChat registration.
- HTTP player-stats and leaderboard views from one durable aggregate store.
- account-name identities (case insensitive), stable numeric IDs, and atomic
  two-player record transactions. No raw match history is kept.
- Rooms: `LIST`, `JOIN`, `NAMES`, `PART`, `TOPIC`, `MODE`, `SETGROUP`, room
  modes, keys and limits, cleanup, operator transfer, removal of empty channels,
  `WHO`/`WHOIS`, direct and channel `PRIVMSG`/`NOTICE`/`UTM`/`ATM`, invitations,
  kicks, bans, modes, nickname changes, and the player/room metadata key
  commands with cookie completion and broadcast updates. Game-specific `LIST k`
  metadata is packed into the fourth numeric-322 parameter as the title's
  listing parser expects.
- NAT negotiation (UDP 27901): acknowledges every source with its own port type,
  pairs by title and cookie, hands each client the other's endpoint, prefers the
  reported private address when both clients are seen at one public address,
  retries until acknowledged, answers reports, and tells a client that waited
  alone for 30 seconds that no partner arrived.
- Session tracking: two room members announcing the same `b_mid` are a pairing,
  given a server generation so a rematch is distinguishable even if the title
  reuses its identity. Leaving or dropping ends the pairing but keeps it
  reportable for ten minutes.
- Result recording (TCP 29920): title authentication, reporting-player proof
  against the verified login session and observed source, then attribution to a
  watched pairing. Participants in the report must be that pairing. Winner comes
  from the round counters; an abort credits the opponent of the profile the title
  blames; a disconnect credits the reporter and records the drop against the
  other player. An undecided report writes nothing. Commits are keyed by
  generation, so retries and both consoles reporting count once.

## Validation

122 tests pass: 54 protocol, 67 server, one SSL3 integration. Workspace clippy
with all targets and warnings denied passes, as do the release build and the
offline config check.

Tests cover the negotiation contract (per-source acknowledgement, shared-public
-address fallback, lone-client failure, incomplete clients never paired),
session pairing and rematch generations, result decoding and every outcome rule,
refusal of unwatched or mis-stated matches, single-commit behaviour, encrypted
registration and channels, persistent identity and records, concurrent duplicate
outcomes, failed-write recovery, and both HTTP views.

**None of this proves console acceptance of matchmaking or results.** The local
tests drive the server's own state machine against synthetic clients.

## Remaining work

- A two-console run: challenge, match start, completion, rematch, abort,
  disconnect and logout. That run is what would establish the result path.
- Whether the round counters reset per match or accumulate across a rematch is
  not established from the code. Keying commits by server generation makes the
  question moot for counting, but a cumulative counter would make the recorded
  margin wrong; check it against a real report.
- Ranked versus private eligibility is unresolved. The title's result producer
  emits `game_type` 0 and `rank_mode` 1 for every match it sends, which are wire
  facts and not evidence that every match should count. Currently all accepted
  results count.
- No gameplay relay. Two consoles behind separate routers that cannot reach each
  other after negotiation have no fallback.
- Optional SDK user-quiet mode (`MODE +q`) is unsupported.
- No service supervision, log rotation or deployment script.

## Local operations and evidence

Optional TOML sections: `stats`, `natneg`, `gstats`, `identity`. Identity state
must stay in ignored runtime storage or outside the public tree. The store caps profiles and
duplicate markers at 10,000 each and refuses new results at capacity rather than
silently dropping replay protection. `MKVSDCU_GP_TRACE_DIR` writes sensitive GPCM
diagnostics and must also target ignored local storage.

Durable ticket-derived profile IDs are implemented and extract identity without
validating platform signatures.

Game-derived decompilation stays in the private research workspace. Server logs,
exact exchanges and DNS notes stay in ignored `game/`. No host names, account
data, tickets, packet captures or decompiled game code belong in this tree.
