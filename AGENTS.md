# Instructions for agents helping a user set up mkvsdcu-server

You are helping someone run this server for their own copy of the game. Work through the steps below in order, and check each one before moving on. Read `README.md` first for what the server does.

<!-- Shared ground rules: copied verbatim from the game-server agent-docs template. Edit them there, then copy to every project. -->
## Ground rules

- **Use only the user's own copy of the game.** Never download game files, decrypted executables, keys or license files from the internet, and never suggest where to get them. If the user doesn't have the files, stop and tell them what's missing.
- **Decrypting the executable is the user's job.** Where the server needs the executable decrypted, the user provides that form from their own copy; it is their responsibility. Don't explain how to decrypt it, and never obtain a decrypted copy elsewhere.
- **Never put game-derived files in this repository**: executables, archives, generated output, decompiler projects or exports, server logs, stored uploads. Keep them in a folder outside it, or in the git-ignored folders this guide names.
- **The host names you find go into the user's DNS setup only.** Don't write them into this repository (code, docs, config examples, commits or issues), and don't copy anything else out of the executable: no keys, code or text. The server reads what it needs from the user's files at runtime.
- **Change the user's system only with their agreement**: firewall rules, DNS, router settings.
<!-- End of shared ground rules. -->

In this project the git-ignored folder for game-derived files is `game/`, alongside every local `mkvsdcu-server*.toml` except the example.

## Status and scope

A full online session is confirmed on two real consoles: login, the online menu, the player-history read, chat registration, rooms and metadata, a challenge, match negotiation, a played match, and the result written to both players' records. The match itself is played console to console; this server introduces the two and records what they report.

The server has **no runtime game-file dependency**. It reads no executable and no archive while running. It needs its configuration, the local OpenSSL build, one secret from the user's own copy of the game, and the network ports listed in `README.md`.

## 1. Supply the required value and the files that belong in `game/`

The server needs exactly **one value** from the user's own copy: the game's chat secret, set as `peerchat.title_secret`. This guide deliberately doesn't name the value. Identify it as described below.

### What goes into `game/`

Everything derived from the user's copy lives in a `game/` folder next to their `mkvsdcu-server.toml`. Relative paths in the config resolve from the config file's folder.

| Path | What it is | Who writes it |
| --- | --- | --- |
| `game/<decrypted main executable>` | The latest update's main executable, decrypted by the user from their own installation. Needed only to derive the chat secret and the host names; the running server never opens it. Keep a copy here only if the user wants one locally, and never commit it. | The user |
| `game/players/` | The server's own player records: names, counters and committed results. Set `identity.storage_dir = "game/players"`. | The server |

Follow the [pick-game-files](.claude/skills/pick-game-files/SKILL.md) skill to choose the latest update's executable over the base game's. The update's copy is the one the console runs, so it is the one to read.

### Obtaining the chat secret

The secret is a short string the game hands to its chat library at start-up. Work it out from the **user's own decrypted executable**:

1. Find the call site where the title registers itself with the chat library. That registration function takes the game's short name and the secret as adjacent arguments, so the secret is the second of the two strings loaded there.
2. Read the string that call site loads as the secret, and set it verbatim as `peerchat.title_secret` in the local config.
3. Record nothing else from the executable, and do not write the value into this repository, notes, issues or commits.

If the secret cannot be established, stop on this step. The chat handshake cannot work without the real value, and guessing or brute-forcing it is not an option.

**Check:**

1. `mkvsdcu-server.example.toml` has been copied to the ignored `mkvsdcu-server.toml`.
2. `peerchat.title_secret` is the real value, not the example placeholder.
3. Every bind address is one the console can reach. The example's loopback addresses are not.
4. Run the offline check from a different working directory, which also proves the relative paths resolve:

   ```powershell
   cargo run --release -p mkvsdcu-server -- --check-config --config <absolute path>\mkvsdcu-server.toml
   ```

   It must print `config.valid` and must not open a listener or touch the player records.

## 2. Work out the host names in the user's executable

The client contacts service host names belonging to the online middleware the game used. Recover **only** the roles this server replaces, and no others:

| Role | What the server answers on it |
| --- | --- |
| Availability | The first probe of the online flow |
| Login | The certificate login, over legacy TLS |
| Player history | The stats read the title makes before chat |
| Player session | The session every later service checks back against |
| Chat | Rooms, metadata and the challenge exchange |
| Profile search | Resolving an opponent's nickname during a challenge |
| Match negotiation | **All three** matchup hosts |
| Result ingestion | Finished-match reports |

This guide deliberately doesn't name them. List the executable's strings and work from the service labels you find, keeping that output out of the repository.

### The composition rule, which must be read before writing any DNS entry

**Several of these names are not the literal strings in the executable.** For each service the middleware holds two things: an *override pointer* and a *default label*. When the override pointer is null, the name it actually resolves is composed:

```
<game's short name> . <default label>
```

In the build checked, the three match-negotiation override pointers live in `.bss` and are zero at load, and nothing sets them, so the names the console looks up are the **composed, short-name-prefixed** forms, not the bare labels sitting in the string table. The availability, login and one of the stats roles compose the same way.

Why this step carries its own warning:

- Reading a default label out of the string table and overriding **that** leaves the real lookups unanswered. The game then abandons the match **before sending a single packet**, so the server log stays completely silent and the console reports only that the session is no longer available. Login and rooms keep working, which makes it look like a match bug.
- For each role, check whether its override pointer is set in the build in front of you. If it is null, the name to override is the composed form.
- A host name alone is not evidence of its role. Confirm the role from the code path that resolves it, or from an existing capture. If a role cannot be established, stop rather than redirecting a guessed name.

Keep the resulting list in the user's own DNS notes only.

## 3. Set up the DNS override

Follow the [dns-override](.claude/skills/dns-override/SKILL.md) skill to point every confirmed name at the server's reachable address. Scope the override to the console where the resolver supports it.

**Check:**

1. `nslookup <host name> <console's DNS server>` must return the server's address for **every** name from step 2, including all three match-negotiation names. Query the console's DNS server explicitly: the machine you run the check on may use a different resolver.
2. Allow inbound UDP 27900 and 27901 and TCP 80, 443, 6667, 29900, 29901 and 29920, from the local network only. Do not forward these ports on the router.
3. The middleware caches a resolved address for the lifetime of the game process. After a DNS change the game needs a **cold restart** on the console; leaving and re-entering online mode is not enough.
4. Start the game's online mode. The server log should show, in order:

   ```
   [availability] probe game="..." from <console>
   [auth] <console> negotiated SSLv3 / RC4-MD5
   [auth] <console> cert login responseCode=0
   [gp] <console> login success sent profileid=... userid=... sesskey=...
   [stats] read view=player rows=...
   [peerchat] <console> CRYPT des 1 game="..."
   [peerchat] <console> secure USER/NICK registration correlated profileid=...
   ```

   The login line confirms the availability path and the token mint. The session line confirms the client consumed that token and accepted the server proof. The stats read must complete before chat: the title will not register without it.

5. A match needs a second console. Both resolve each other's nickname first, then challenge, then negotiate:

   ```
   [gpsp] <console> search uniquenick="..." found profileid=...
   [match] generation=<n> paired profiles=[...] answer=Some(0)
   [natneg] cookie=<c> client=0 registered porttype=... from=<console>
   [natneg] cookie=<c> client=1 registered porttype=... from=<other console>
   [natneg] cookie=<c> paired both clients
   [gstats] generation=<n> both peers agree
   [gstats] generation=<n> committed=true winner=... loser=...
   ```

   `no match` lines from the profile search are normal: only players this server knows resolve, and a console looks up its whole friend list.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| No request reaches the server | The console is using a different resolver, the override is not scoped to it, or the bind address is not reachable. Follow "No request reaches the server" in the [dns-override](.claude/skills/dns-override/SKILL.md) skill, starting with the first name the console contacts. |
| Availability log is missing | UDP 27900 is blocked, or that name points elsewhere. The middleware continues after a timeout, so absence is not a pass. |
| Login TLS fails | The console and server did not agree on the legacy cipher, or the self-signed certificate shape was rejected. A loopback test passing does not prove console acceptance. |
| Session login returns an error or stalls | The login token is missing or expired (a server restart invalidates it), or the client rejected the server proof. Capture the exchange before changing code. |
| Chat sends nothing after connecting, or closes before `CRYPT` | The console is not reaching the chat listener, or it reached a service that did not speak first. Confirm the role before changing code. |
| Chat registration never completes, or the key line is rejected | Almost always a wrong or missing `peerchat.title_secret`. The value must come from the user's own copy. Do not guess or brute-force it. |
| **A challenge is answered, then both consoles leave, with no `[natneg]` line at all** | The match-negotiation names are wrong, most often because the bare labels were overridden instead of the composed forms (see step 2), or the game was not cold-restarted after the DNS change. The game returns before sending any packet, so silence is the expected symptom. |
| A challenge is answered and nothing happens, with no `[gpsp]` lines | The profile-search name is not overridden. The console blocks resolving its opponent and gives up. |
| `[natneg] no partner for ...` | Only one console negotiated. Its opponent never started, or started a different match. |
| Negotiation pairs but no result arrives | The consoles could not reach each other directly. This server does not relay gameplay. |
| `[gstats] ... peers disagree; nothing recorded` | The two consoles described different outcomes. Nothing here can decide between them, so nothing is written. |
| `[gstats] ... report ... ignored; not awaiting one` | The report did not belong to a pairing this server watched begin, or that pairing was already settled. |
| Players vanish from a room after a match | The chat listener owes the client a fresh member list when it leaves quiet mode. If that path has been changed, re-check it. |

## Boundaries and publication

- Do not start, stop or restart a service, change DNS, firewall or router settings, or run the game merely because a build or review was requested. Existing explicit user authorization governs.
- Never put real host names, console account data, account tickets, packet captures or game files in the public tree.
- Offline tests prove only the local codecs and transport paths. They do not prove console acceptance, login, or multiplayer.
