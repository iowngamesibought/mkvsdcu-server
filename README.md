# mkvsdcu-server

A community server for the online mode of **MKVSDCU** on a certain game console.

This project is not affiliated with or endorsed by the game's developer or publisher. It ships no game files and no game secrets: the one value it needs comes from **your own installed copy**, and it never contacts the platform's account service.

Status: a full online session has been confirmed on two real consoles — login, the online menu, rooms, a challenge, NAT negotiation, a played match, and the result written to both players' records. The server is never in the gameplay path.

## Required: a DNS override

The console only reaches this server if the service host names the game contacts resolve to this machine. Without that override the console keeps trying the original hosts, which no longer serve the game, and nothing arrives here.

This README deliberately doesn't name the hosts. To find them, **ask an AI agent to follow [AGENTS.md](AGENTS.md)**: it works the names out from your own executable, derives the ones the game builds at runtime, then walks you through the override and checks each one resolves. Getting this list wrong is the single most common reason a match never starts, because the game gives up before it sends a packet.

## Required: one secret from your copy of the game

The server reads **no game file while it runs**. It needs exactly one value, set in the config:

| Config key | What it is |
|---|---|
| `peerchat.title_secret` | The game's chat secret. The chat handshake and the result listener both authenticate with it. Without the real value the console connects and then closes before registering. |

This README deliberately doesn't name the value or where it sits. To obtain it, **ask an AI agent to follow [AGENTS.md](AGENTS.md)**: it locates it in your own decrypted executable. Never download it or take it from anywhere but your own copy, and keep it only in your local config.

**Where things go:** put anything derived from your copy of the game in a `game/` folder next to your `mkvsdcu-server.toml`, and point the config at it:

```
mkvsdcu-server.toml
game/
  <your decrypted executable, if you keep a copy for the agent to read>
  players/            <- the server's own player records
```
```toml
[identity]
storage_dir = "game/players"
```

Relative paths are resolved from the config file's folder, so the whole set can be moved together, and absolute paths work too. `game/` and every `mkvsdcu-server*.toml` except the example are listed in this project's `.gitignore`, so they won't be committed by accident.

## Run

Building needs a Rust toolchain (https://rustup.rs); there is no prebuilt binary.

```
cp mkvsdcu-server.example.toml mkvsdcu-server.toml   # set title_secret and the bind addresses
cargo run --release -p mkvsdcu-server -- run --config mkvsdcu-server.toml
```

Other commands:
- `--check-config --config <file>`: validates the config and prints `config.valid` without opening a listener or touching the player records. Run it from a different folder to confirm the paths resolve.

`MKVSDCU_CHAT_TRACE=1` logs every chat line and every result frame. It is a debugging aid and it prints LAN addresses, profile identifiers and authentication tokens, so keep its output local.

## Network setup

- **DNS:** map the game's service host names to this machine. Several of them are built at runtime from the game's own short name, so the list is not simply the literal names in the executable; see [Required: a DNS override](#required-a-dns-override). Missing even one of the match-negotiation names breaks every match while leaving login and rooms working.
- **Binds:** every bind address must be one the console can reach. `0.0.0.0` is fine; the loopback addresses in the example are for a local check only.
- **Firewall:** allow inbound UDP 27900 and 27901 and TCP 80, 443, 6667, 29900, 29901 and 29920 from your local network only, and don't forward these ports on your router.
- **Ports:** the console uses fixed port numbers, so run one server per LAN.
- **Restarts:** a restart invalidates issued login tokens, so consoles already online need to sign in again.

| Service | Transport | Needed for |
| --- | --- | --- |
| Availability | UDP 27900 | The first probe of the online flow |
| Login (legacy TLS) | TCP 443 | Signing in |
| Player history | TCP 80 | The stats read the title makes before chat |
| Player session | TCP 29900 | The session every later service checks |
| Chat and rooms | TCP 6667 | Rooms, metadata and the challenge exchange |
| Profile search | TCP 29901 | Resolving an opponent's nickname during a challenge |
| Match negotiation | UDP 27901 | Introducing two consoles to each other |
| Result ingestion | TCP 29920 | Match results and the player records |

## How a match works

Players meet in a room and challenge each other through room metadata and a pair of peer messages. The server resolves each side's nickname to a profile, relays the exchange, then introduces the two consoles by NAT negotiation. **The match itself is played directly between the two consoles**; this server only introduces them and records what they report afterwards.

A result counts only when **both** consoles describe the same outcome: it then becomes a change to both players' records and nothing else is kept about the match. If the two disagree, or if one goes silent and the other's account waits out a short window, the match is dropped and no record moves — there is nothing here that could decide between them, and one console's word is not enough. Driving that queue is lazy: it advances on session events, so a result that looks stuck lands as soon as either player starts another session. Results waiting at the moment the server stops are lost with it; a match either counts in full or not at all.

Ranking is a local policy, not a reconstruction of the original service: wins descending, then losses and disconnects ascending, then name.

## Layout

| Path | Purpose |
| --- | --- |
| `crates/mkvsdcu-proto` | Pure wire codecs. No sockets, no TLS. |
| `crates/mkvsdcu-server` | Listeners, session correlation, rooms, match tracking, player records, legacy TLS, configuration, CLI. |
| `docs/` | Protocol notes, deployment detail and current status. |
| `mkvsdcu-server.example.toml` | Published configuration example. |
| `game/`, `mkvsdcu-server.toml` | Local-only, git-ignored. |

## Tests

`cargo test` covers the wire codecs against known-answer vectors and captured client traffic, the chat cipher, room and metadata handling, quiet-mode recovery, match pairing and the result queue's agreement, conflict and timeout paths, the player-record transaction, the HTTP views, and configuration validation. One integration test completes a legacy-TLS login against a loopback listener.

Offline tests prove the local codecs and transport paths. They do not prove console acceptance; the status line above says what hardware has shown.

## Open questions

- Whether the round counter resets per match or accumulates across a rematch is unresolved. Results are keyed per pairing, so a result still counts once either way, but a recorded margin could be wrong.
- Ranked versus private eligibility is not established; the title reports the same mode fields for every match observed.
- The game ships a development address for a companion service that no retail session has been seen to need. It is not implemented.

## License

MIT, see [LICENSE](LICENSE). Dependency licenses are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
