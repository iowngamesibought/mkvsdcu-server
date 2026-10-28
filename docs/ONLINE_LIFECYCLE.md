# Online lifecycle and statistics contract

Updated 2026-10-28. Scope: the operator's own copy, update 01.01. This is a
functional contract and implementation boundary, not a claim of full multiplayer
acceptance. Console online-menu login is confirmed. Matchmaking and the result
path are implemented against the title's own code and await a two-console run.

## Player flow and service responsibilities

1. **Sign in and load identity.** The console obtains its account ticket. Availability,
   AuthService and GPCM establish a player session. Durable local profile identity
   survives ticket refresh and restart when the identity store is enabled. Rows use
   the ticket's account name (case insensitive), with numeric protocol IDs retained.
   This does not verify platform signatures. A changed name needs explicit migration.
2. **Load player statistics.** Initial HTTP player-history completion is required
   before ordinary secure PeerChat registration. The response now reads the same aggregate records as leaderboards.
3. **Enter online menu/lobby.** Secure PeerChat exchanges USRIP then USER/NICK.
   Keep online connection, persistent profile, displayed nickname and room membership
   as distinct state. Login reaching the menu is already confirmed on the console.
4. **Browse/create/join/leave rooms.** Channel LIST/JOIN/NAMES/TOPIC/MODE/SETGROUP
   carry room state. The game creates and destroys local engine sessions around
   room transitions; chat membership alone does not prove a gameplay session.
5. **Select a match.** Challenge, accept and decline metadata travels through
   opaque peer messages. The two players announce the match by publishing the
   same `b_mid` alongside their `b_PID`, address and port as room keys; the
   server watches those updates and treats that as the pairing. Do not infer
   ranked eligibility from UI labels or rewrite client match IDs.
6. **Connect and play.** `ConnectMatchJob` begins NAT negotiation with a cookie
   and client index the title already holds, and the endpoint negotiation
   returns is the "preferred URL" it then joins. All three matchup host names
   must resolve to this server, because the client holds negotiation until every
   source it used is acknowledged. Gameplay runs console to console; the server
   is not in that path and does not relay it.
7. **Complete/abort/disconnect.** Preserve these outcomes separately. Result snapshots
   include participants, a shared game ID, counters, aborting profile and disconnect
   information. They require validation and reconciliation before updating totals.
8. **Rematch.** Session teardown/recreation and match-generation identity must be
   established. A shared game ID alone is not proven unique across rematches.
9. **Read profiles and leaderboards.** Both views must use one consistent aggregate
   revision. Reconnect must not create another lifetime account or reset its history.
10. **Logout and recovery.** Remove online membership, cancel stale negotiations,
    expire login credentials, and retain bounded proof material long enough to finish
    legitimate pending results. Retain persistent profiles and bounded duplicate markers; no play history is stored.

## Statistics visible to the client

The player-history reader accepts rating/rank, leaderboard position, wins, losses,
current streak, best streak, disconnects, games played, scored and scored-against,
partitioned by game type. Some serialized match fields have different roles and
must not be counted merely because their names resemble these totals.

The leaderboard table displays rank, player name, wins, losses, best streak,
skill and games played. Hall of Fame selects maxima for wins, best streak and
games from the returned rows. A limited response can therefore change Hall of
Fame semantics; pagination/cutoff behavior must be deliberate and tested.

The leaderboard-state HTTP request uses CreateOnlineStats.asp. Its name does not
make it a result-submission endpoint. Earlier classification was incorrect.
The result-submission path is GStats. The response parser selects ONLINE_STATS
for group 1, then STATS with reset type 0 and entries whose fields supply the
seven displayed columns. These fields are XML attributes. Column order is rank,
player name, skill, wins, losses, games played, best streak. The client skips the
first child under STATS before processing ENTRY rows; an initial metadata/header
child must be preserved or the first player row is lost. Its original name is
not established. Hall-of-Fame ties retain the earlier row because comparisons
use strict greater-than. Native-client serialization fixtures still need validation.

## Result integrity and exactly-once accounting

The approved storage model is one account-name player row with wins, losses,
disconnects, games, streak and best streak. The numeric profile ID remains stable.
Chat nickname decorations are not part of identity. Case-only name changes share
a row; an actual rename is a future migration question.

An accepted outcome updates both players and its duplicate marker in a single
atomic transaction. Duplicate submissions do not update counters again; conflicting
outcomes for the same key are rejected. There is no permanent raw report or play
history. The current bounded store allows 10,000 profiles and 10,000 markers;
when full it rejects new outcomes rather than silently removing replay protection.
A safe expiry policy tied to a verified match lifecycle remains future work.

Leaderboard policy: wins descending, losses ascending, disconnects ascending,
then case-insensitive account name. Displayed skill is the win count. These are local
rules, not a reconstruction of the original service rating. Both HTTP views read
the same aggregate snapshot. Untracked score/bank attributes are omitted.

GStats validates both title authentication and reporting-player proof using the
GP-verified login session and observed source. Unverified tokens expire after
15 minutes; verified proof material is bounded to 24 hours from issue and is
lost on restart. This is a temporary result-grace policy, not complete logout or
active-match lifetime management. No static IP allowlist is introduced.

Results now update the records. A report is committed only when the title
authenticates, the reporting player proves ownership of a verified login session
from the observed source, and the match it names is a pairing the server watched
two room members announce. The report's participants must be that pairing.

The commit is keyed by the server's own generation for that pairing, not by the
title's `b_mid`. That is deliberate: `b_mid` reuse across a rematch is not
disproved, while a generation is never reused, so each match counts once whether
or not the title reuses its identity, and retries or both consoles reporting
collapse to one commit.

Outcome rules, stated because the title settles only part of this:

- An abort credits the opponent of the profile the title names in
  `profile_aborted`. An abort with no profile named is refused, not guessed.
- A disconnect credits the reporter and records the drop against the other
  player. The title marks that a disconnect happened without naming whose it
  was; attributing it to the side that did not report is this server's rule.
- Otherwise the player with the higher round-win counter wins. Equal counters
  decide nothing and write nothing.

Two questions remain open and are not papered over. Whether the round counter
resets per match or accumulates across a rematch is not established from the
code; generation keying makes that irrelevant to counting once, but a cumulative
counter would make the recorded margin wrong. And ranked versus private
eligibility is unresolved: the result producer emits `game_type` 0 and
`rank_mode` 1 for every match it sends, which is a wire fact rather than
evidence that every match should count, so for now all accepted results do.

## Validation still required

A two-console run must cover completion, rematch, abort, disconnect and logout.
Verify that each match counts once regardless of report order or retries, that
rematches count separately, that the recorded margin matches what was played,
and that profiles and leaderboards agree after a restart.
The operator confirmed the new identity and HTTP XML responses on the console:
their account name appears on the leaderboard and User Statistics displays their
stats. Live logs show both views serving one player row. Nonzero match updates,
rematches and restart readback still need console validation.

## Evidence boundary

Decompilation, raw literals and detailed address ledgers remain in the private
research workspace: DEC-MKVSDC-20261027/decomp-login-20261028 and the local
stats-session-findings ledger. These conclusions combine the supplied update,
the pinned SDK reference and observed console logs. Some decompiler functions
have TOC/dead-code warnings; key branches were checked against PPC instructions.
No service hostnames, tickets, account values or raw decompiled game code are
included here.
