//! In-memory PeerChat channels. Wire behavior follows the SDK handlers;
//! game-specific topic contents are opaque and never synthesized here.
use mkvsdcu_proto::peerchat::Message;
use std::collections::{BTreeMap, BTreeSet};

pub type Delivery = (String, String);
#[derive(Default)]
pub struct Rooms {
    channels: BTreeMap<String, Channel>,
    identities: BTreeMap<String, Identity>,
    global_keys: BTreeMap<String, BTreeMap<String, String>>,
    /// Watches the room metadata that announces a one-versus-one session.
    matches: Option<std::sync::Arc<crate::matches::Matches>>,
}
struct Identity {
    user: String,
    host: String,
    real_name: String,
}
struct Channel {
    members: BTreeSet<String>,
    owner: String,
    topic: String,
    key: String,
    limit: Option<usize>,
    group: String,
    no_external: bool,
    topic_owner: bool,
    flags: BTreeSet<char>,
    invited: BTreeSet<String>,
    operators: BTreeSet<String>,
    voices: BTreeSet<String>,
    bans: BTreeSet<String>,
    keys: BTreeMap<String, String>,
    member_keys: BTreeMap<String, BTreeMap<String, String>>,
}
impl Default for Channel {
    fn default() -> Self {
        Self {
            members: BTreeSet::new(),
            owner: String::new(),
            topic: String::new(),
            key: String::new(),
            limit: None,
            group: String::new(),
            no_external: true,
            topic_owner: true,
            flags: BTreeSet::new(),
            invited: BTreeSet::new(),
            operators: BTreeSet::new(),
            voices: BTreeSet::new(),
            bans: BTreeSet::new(),
            keys: BTreeMap::new(),
            member_keys: BTreeMap::new(),
        }
    }
}
impl Rooms {
    /// Report departures to the session tracker, and let the listener reach it
    /// for the challenge exchange it sees before dispatch.
    pub fn watch_sessions(&mut self, matches: std::sync::Arc<crate::matches::Matches>) {
        self.matches = Some(matches);
    }
    pub fn session_tracker(&self) -> Option<std::sync::Arc<crate::matches::Matches>> {
        self.matches.clone()
    }
    pub fn set_identity(&mut self, nick: &str, user: &str, host: &str, real_name: &str) {
        self.identities.insert(
            nick.to_owned(),
            Identity {
                user: user.to_owned(),
                host: host.to_owned(),
                real_name: real_name.to_owned(),
            },
        );
    }
    fn prefix(&self, nick: &str) -> String {
        match self.identities.get(nick) {
            Some(identity) => format!("{nick}!{}@{}", identity.user, identity.host),
            None => format!("{nick}!user@local"),
        }
    }
    pub fn command(&mut self, nick: &str, message: &Message<'_>) -> Vec<Delivery> {
        let prefix = self.prefix(nick);
        let matches = self.matches.clone();
        // Needed while a channel is borrowed, so it is taken up front.
        let registered: BTreeMap<String, String> = if message.command == "GETCKEY" {
            self.identities
                .iter()
                .map(|(who, identity)| (who.clone(), identity.user.clone()))
                .collect()
        } else {
            BTreeMap::new()
        };
        let p = &message.params;
        let mut out = Vec::new();
        let reply =
            |code: u16, text: &str| (nick.to_owned(), format!(":s {code:03} {nick} {text}\r\n"));
        if message.command == "WHOIS" {
            let target = p.last().copied().unwrap_or(nick);
            if let Some(id) = self.identities.get(target) {
                out.push(reply(
                    311,
                    &format!("{target} {} {} * :{}", id.user, id.host, id.real_name),
                ));
                for (name, c) in &self.channels {
                    if c.members.contains(target)
                        && (!c.flags.contains(&'s') || c.members.contains(nick))
                    {
                        out.push(reply(
                            319,
                            &format!(
                                "{target} :{}{name}",
                                if is_operator(c, target) { "@" } else { "" }
                            ),
                        ));
                    }
                }
            } else {
                out.push(reply(401, &format!("{target} :No such nick")));
            }
            out.push(reply(318, &format!("{target} :End of WHOIS")));
            return out;
        }
        if message.command == "SETKEY" {
            if p.len() != 1 {
                return vec![reply(461, "SETKEY :Invalid parameters")];
            }
            let Some(pairs) = parse_keys(p[0]) else {
                return vec![reply(461, "SETKEY :Invalid keys")];
            };
            let mut updated = self.global_keys.get(nick).cloned().unwrap_or_default();
            for (key, value) in pairs {
                if value.is_empty() {
                    updated.remove(key);
                } else {
                    updated.insert(key.to_owned(), value.to_owned());
                }
            }
            if updated.len() > 64
                || updated
                    .iter()
                    .map(|(k, v)| k.len() + v.len() + 2)
                    .sum::<usize>()
                    > 2500
            {
                return vec![reply(461, "SETKEY :Key capacity reached")];
            }
            self.global_keys.insert(nick.to_owned(), updated);
            return out;
        }
        if message.command == "GETKEY" {
            if p.len() != 4 || p[1].len() > 64 || p[3].len() > 1024 {
                return vec![reply(461, "GETKEY :Invalid parameters")];
            }
            let target = p[0];
            let cookie = p[1];
            let members = self.channels.get(target);
            if !self.identities.contains_key(target) && members.is_none() {
                return vec![reply(401, &format!("{target} :No such target"))];
            }
            for who in self.identities.keys() {
                if who == target || members.is_some_and(|c| c.members.contains(who)) {
                    let empty = BTreeMap::new();
                    let values = key_values(self.global_keys.get(who).unwrap_or(&empty), p[3]);
                    if values.len() > 3000 {
                        return vec![reply(461, "GETKEY :Response too large")];
                    }
                    out.push(reply(700, &format!("{who} {cookie} :{values}")));
                }
            }
            if members.is_some() {
                out.push(reply(701, &format!("{target} {cookie} :End of keys")));
            }
            return out;
        }
        if message.command == "WHO" {
            let target = p.first().copied().unwrap_or("*");
            let members = self.channels.get(target);
            for (other, identity) in &self.identities {
                if other == target || members.is_some_and(|c| c.members.contains(other)) {
                    let channel = if members.is_some() { target } else { "*" };
                    let flags = if members.is_some_and(|c| is_operator(c, other)) {
                        "H@"
                    } else {
                        "H"
                    };
                    out.push(reply(
                        352,
                        &format!(
                            "{channel} {} {} s {other} {flags} :0 {}",
                            identity.user, identity.host, identity.real_name
                        ),
                    ));
                }
            }
            out.push(reply(315, &format!("{target} :End of WHO")));
            return out;
        }
        if matches!(message.command, "PRIVMSG" | "NOTICE" | "UTM" | "ATM")
            && p.first().is_some_and(|target| !target.starts_with('#'))
        {
            if p.len() != 2 || p[1].len() > 3500 {
                return vec![reply(461, "Message :Invalid parameters")];
            }
            let target = p[0];
            if self.identities.contains_key(target) {
                return vec![(
                    target.to_owned(),
                    format!(":{prefix} {} {target} :{}\r\n", message.command, p[1]),
                )];
            }
            if message.command == "NOTICE" {
                return out;
            }
            return vec![reply(401, &format!("{target} :No such nick"))];
        }
        if message.command == "LIST" {
            out.push(reply(321, "Channel :Users Name"));
            let filter = p.first().copied().unwrap_or("");
            for (name, c) in &self.channels {
                if c.flags.contains(&'s') && !c.members.contains(nick) {
                    continue;
                }
                // GameSpy title-group enumeration explicitly selects private rooms.
                if c.flags.contains(&'p')
                    && !c.members.contains(nick)
                    && filter != c.group
                    && filter != name
                {
                    continue;
                }
                if filter.is_empty() || wildcard(filter, name) || filter == c.group {
                    // GameSpy's k option packs metadata into the fourth parameter;
                    // adding a fifth parameter makes the SDK discard the row.
                    let topic = if p.get(1).is_some_and(|flags| flags.contains('k')) {
                        let mut metadata = format!("\\topic\\{}", c.topic);
                        if let Some(limit) = c.limit {
                            metadata.push_str(&format!("\\limit\\{limit}"));
                        }
                        metadata
                    } else {
                        c.topic.clone()
                    };
                    out.push(reply(322, &format!("{name} {} :{topic}", c.members.len())));
                }
            }
            out.push(reply(323, ":End of LIST"));
            return out;
        }
        if message.command == "INVITE" {
            if p.len() != 2 {
                return vec![reply(461, "INVITE :Invalid parameters")];
            }
            let target = p[0];
            let name = p[1];
            if !self.identities.contains_key(target) {
                return vec![reply(401, &format!("{target} :No such nick"))];
            }
            let Some(c) = self.channels.get_mut(name) else {
                return vec![reply(403, &format!("{name} :No such channel"))];
            };
            if !c.members.contains(nick) {
                return vec![reply(442, &format!("{name} :Not on channel"))];
            }
            if c.flags.contains(&'i') && !is_operator(c, nick) {
                return vec![reply(482, &format!("{name} :Channel operator required"))];
            }
            if c.members.contains(target) {
                return vec![reply(443, &format!("{target} {name} :Already on channel"))];
            }
            c.invited.insert(target.to_owned());
            return vec![
                reply(341, &format!("{target} {name}")),
                (
                    target.to_owned(),
                    format!(":{prefix} INVITE {target} :{name}\r\n"),
                ),
            ];
        }
        let Some(&name) = p.first() else {
            return vec![reply(
                461,
                &format!("{} :Not enough parameters", message.command),
            )];
        };
        // Quiet mode is a user mode, not a channel mode: chatSetQuietMode
        // sends "MODE <own nick> +q" or "-q". Leaving it is the part that
        // matters here. The client calls ciClearAllUsers, wiping every room
        // player list it holds, then installs one UNQUIET filter per joined
        // channel. Only a NAMES reply resolves that filter, and the client
        // never asks for one -- the server owes it unprompted. Answering 403
        // instead leaves every room on screen permanently empty.
        //
        // Entering quiet mode is accepted and nothing more: the real service
        // also withholds traffic while quiet, but the client keeps its lists
        // across that and discards them on the way out, so suppressing
        // nothing changes what it ends up displaying.
        if message.command == "MODE" && p.len() == 2 && name == nick {
            match p[1] {
                "+q" => return out,
                "-q" => {
                    for (channel, state) in &self.channels {
                        if state.members.iter().any(|member| member == nick) {
                            names(nick, channel, state, &mut out);
                        }
                    }
                    return out;
                }
                _ => {}
            }
        }
        if !name.starts_with('#') || name.len() > 128 || name.contains([',', ' ', ':']) {
            return vec![reply(403, &format!("{name} :Invalid channel"))];
        }
        if message.command == "JOIN" {
            if !self.channels.contains_key(name) && self.channels.len() >= 1024 {
                return vec![reply(471, &format!("{name} :Channel capacity reached"))];
            }
            let c = self.channels.entry(name.to_owned()).or_default();
            if c.members.contains(nick) {
                return out;
            }
            if c.bans.iter().any(|mask| wildcard(mask, &prefix)) {
                return vec![reply(474, &format!("{name} :Banned from channel"))];
            }
            if c.flags.contains(&'i') && !c.invited.contains(nick) {
                return vec![reply(473, &format!("{name} :Invite only channel"))];
            }
            if !c.key.is_empty() && p.get(1).copied().unwrap_or("") != c.key {
                return vec![reply(475, &format!("{name} :Bad channel key"))];
            }
            if c.members.len() >= 4096 || c.limit.is_some_and(|limit| c.members.len() >= limit) {
                return vec![reply(471, &format!("{name} :Channel is full"))];
            }
            if c.members.is_empty() {
                c.owner = nick.to_owned();
            }
            c.members.insert(nick.to_owned());
            c.invited.remove(nick);
            broadcast(c, &format!(":{prefix} JOIN :{name}\r\n"), &mut out);
            out.push(reply(
                if c.topic.is_empty() { 331 } else { 332 },
                &format!("{name} :{}", c.topic),
            ));
            names(nick, name, c, &mut out);
            return out;
        }
        let Some(c) = self.channels.get_mut(name) else {
            return vec![reply(403, &format!("{name} :No such channel"))];
        };
        if message.command == "NAMES" {
            names(nick, name, c, &mut out);
            return out;
        }
        // SDK key reads may target a room before joining it (browser metadata).
        if matches!(message.command, "GETCKEY" | "GETCHANKEY") {
            let member = message.command == "GETCKEY";
            let expected = if member { 5 } else { 4 };
            if p.len() != expected {
                return vec![reply(461, "GETKEY :Invalid parameters")];
            }
            let cookie = p[if member { 2 } else { 1 }];
            let requested = p[expected - 1];
            if cookie.len() > 64 || requested.len() > 1024 {
                return vec![reply(461, "GETKEY :Parameters too long")];
            }
            if member {
                let target = p[1];
                // The SDK retains discovered broadcast keys in this request's
                // filter. Later rows must provide their values before new pairs.
                let mut known: Vec<String> = requested
                    .split('\\')
                    .filter(|key| !key.is_empty() && *key != "b_*")
                    .map(str::to_owned)
                    .collect();
                let broadcast_keys = requested.split('\\').any(|key| key == "b_*");
                for who in &c.members {
                    if target != "*" && target != who {
                        continue;
                    }
                    let empty = BTreeMap::new();
                    let keys = c.member_keys.get(who).unwrap_or(&empty);
                    let mut values = String::new();
                    for key in &known {
                        values.push('\\');
                        match keys.get(key) {
                            Some(value) => values.push_str(value),
                            // The client asks for these without ever setting
                            // them, so the server answers them itself.
                            None => values.push_str(&server_key(key, who, &registered)),
                        }
                    }
                    if broadcast_keys {
                        for (key, value) in keys {
                            if key.starts_with("b_") && !known.contains(key) {
                                values.push('\\');
                                values.push_str(key);
                                values.push('\\');
                                values.push_str(value);
                                known.push(key.clone());
                            }
                        }
                    }
                    if values.len() > 3000 {
                        return vec![reply(461, "GETKEY :Response too large")];
                    }
                    out.push(reply(702, &format!("{name} {who} {cookie} :{values}")));
                }
                if target == "*" {
                    out.push(reply(703, &format!("{name} {cookie} :End of keys")));
                } else if !c.members.contains(target) {
                    return vec![reply(401, &format!("{target} :No such channel user"))];
                }
            } else {
                let values = key_values(&c.keys, requested);
                if values.len() > 3000 {
                    return vec![reply(461, "GETKEY :Response too large")];
                }
                out.push(reply(704, &format!("{name} {cookie} :{values}")));
            }
            return out;
        }
        if message.command == "MODE" && p.len() == 2 && matches!(p[1], "+b" | "b") {
            for mask in &c.bans {
                out.push(reply(367, &format!("{name} {mask}")));
            }
            out.push(reply(368, &format!("{name} :End of bans")));
            return out;
        }
        if !c.members.contains(nick)
            && !(matches!(message.command, "PRIVMSG" | "NOTICE" | "UTM" | "ATM") && !c.no_external)
        {
            return vec![reply(442, &format!("{name} :Not on channel"))];
        }
        match message.command {
            "SETCKEY" | "SETCHANKEY" => {
                let member = message.command == "SETCKEY";
                if p.len() != if member { 3 } else { 2 } {
                    return vec![reply(461, "SETKEY :Invalid parameters")];
                }
                let target = if member { p[1] } else { "" };
                if member && !c.members.contains(target) {
                    return vec![reply(401, &format!("{target} :No such channel user"))];
                }
                if (member && target != nick || !member) && !is_operator(c, nick) {
                    return vec![reply(482, &format!("{name} :Channel operator required"))];
                }
                let Some(pairs) = parse_keys(p[p.len() - 1]) else {
                    return vec![reply(461, "SETKEY :Invalid key pairs")];
                };
                let keys = if member {
                    c.member_keys.entry(target.to_owned()).or_default()
                } else {
                    &mut c.keys
                };
                let mut updated = keys.clone();
                for (key, value) in &pairs {
                    if value.is_empty() {
                        updated.remove(*key);
                    } else {
                        updated.insert((*key).to_owned(), (*value).to_owned());
                    }
                }
                // Bound total payload as well as count so wildcard replies fit a line.
                if updated.len() > 64
                    || updated
                        .iter()
                        .map(|(k, v)| k.len() + v.len() + 2)
                        .sum::<usize>()
                        > 2500
                {
                    return vec![reply(461, "SETKEY :Key capacity reached")];
                }
                *keys = updated;
                let mut changes = String::new();
                for (key, value) in pairs {
                    if key.starts_with("b_") {
                        changes.push('\\');
                        changes.push_str(key);
                        changes.push('\\');
                        changes.push_str(value);
                    }
                }
                // A key-change push is a GETCKEY reply with the literal "BCAST"
                // where a reply to a request carries that request's cookie, and
                // key/value pairs instead of values positioned against a key
                // list. That is the client's own form: ciRplGetCKeyHandler
                // tests `strcmp(cookie, "BCAST")` and then walks the payload
                // with strstr(flags, "b_"), so only b_-prefixed keys may appear
                // -- a non-b_ key makes that strstr return NULL and the walk
                // dereference it.
                if !changes.is_empty() {
                    for recipient in &c.members {
                        let body = if member {
                            format!("702 {recipient} {name} {target} BCAST :{changes}")
                        } else {
                            format!("704 {recipient} {name} BCAST :{changes}")
                        };
                        out.push((recipient.clone(), format!(":s {body}\r\n")));
                    }
                }
            }
            "KICK" => {
                if p.len() < 2 || p.len() > 3 {
                    return vec![reply(461, "KICK :Invalid parameters")];
                }
                if !is_operator(c, nick) {
                    return vec![reply(482, &format!("{name} :Channel operator required"))];
                }
                let target = p[1];
                if !c.members.contains(target) {
                    return vec![reply(441, &format!("{target} {name} :Not on channel"))];
                }
                broadcast(
                    c,
                    &format!(
                        ":{prefix} KICK {name} {target} :{}\r\n",
                        p.get(2).copied().unwrap_or(nick)
                    ),
                    &mut out,
                );
                c.members.remove(target);
                c.member_keys.remove(target);
                c.operators.remove(target);
                c.voices.remove(target);
                c.invited.remove(target);
                transfer_owner(name, c, &mut out);
                if c.members.is_empty() {
                    self.channels.remove(name);
                }
                if let Some(matches) = &matches {
                    matches.forget(target);
                }
            }
            "PART" => {
                broadcast(
                    c,
                    &format!(
                        ":{prefix} PART {name} :{}\r\n",
                        p.get(1).copied().unwrap_or("Leaving")
                    ),
                    &mut out,
                );
                c.members.remove(nick);
                c.member_keys.remove(nick);
                c.operators.remove(nick);
                c.voices.remove(nick);
                c.invited.remove(nick);
                transfer_owner(name, c, &mut out);
                if c.members.is_empty() {
                    self.channels.remove(name);
                }
                if let Some(matches) = &matches {
                    matches.forget(nick);
                }
            }
            "TOPIC" if p.len() == 1 => out.push(reply(
                if c.topic.is_empty() { 331 } else { 332 },
                &format!("{name} :{}", c.topic),
            )),
            "MODE" if p.len() == 1 => {
                let mut modes = format!("+{}", c.flags.iter().collect::<String>());
                if c.no_external {
                    modes.push('n');
                }
                if c.topic_owner {
                    modes.push('t');
                }
                let mut args = String::new();
                if let Some(limit) = c.limit {
                    modes.push('l');
                    args.push_str(&format!(" {}", limit));
                }
                if !c.key.is_empty() {
                    modes.push('k');
                    args.push_str(&format!(" {}", c.key));
                }
                out.push(reply(324, &format!("{name} {modes}{args}")));
            }
            "PRIVMSG" | "NOTICE" | "UTM" | "ATM" if p.len() == 2 && p[1].len() <= 3500 => {
                if c.flags.contains(&'m') && !is_operator(c, nick) && !c.voices.contains(nick) {
                    return vec![reply(404, &format!("{name} :Channel is moderated"))];
                }
                for member in &c.members {
                    if member != nick {
                        out.push((
                            member.clone(),
                            format!(":{prefix} {} {name} :{}\r\n", message.command, p[1]),
                        ));
                    }
                }
            }
            // Both players configure the room they meet in: each one sends
            // TOPIC, MODE and SETGROUP for the match it is setting up, not
            // only whichever of them created the channel. Refusing the one
            // that joined leaves the two consoles with different views of the
            // same room, so room configuration is open to any member. Moderation
            // (KICK, and the operator/ban mode letters) still requires an
            // operator; those are handled where they are applied.
            "MODE" if p.len() >= 2 && !is_operator(c, nick) && moderation_modes(p[1]) => {
                out.push(reply(482, &format!("{name} :Channel operator required")))
            }
            "TOPIC" if p.len() == 2 && p[1].len() <= 512 => {
                c.topic = p[1].to_owned();
                broadcast(
                    c,
                    &format!(":{prefix} TOPIC {name} :{}\r\n", p[1]),
                    &mut out,
                );
            }
            "SETGROUP" if p.len() == 2 => c.group = p[1].to_owned(),
            "MODE" if p.len() >= 2 => {
                let mut adding = true;
                let mut arg = 2;
                // Validate every mode before applying changes.
                let mut key = c.key.clone();
                let mut limit = c.limit;
                let mut no_external = c.no_external;
                let mut topic_owner = c.topic_owner;
                let mut flags = c.flags.clone();
                let mut operators = c.operators.clone();
                let mut owner = c.owner.clone();
                let mut voices = c.voices.clone();
                let mut bans = c.bans.clone();
                for mode in p[1].chars() {
                    match mode {
                        '+' => adding = true,
                        '-' => adding = false,
                        'n' => no_external = adding,
                        't' => topic_owner = adding,
                        'i' | 'p' | 's' | 'm' | 'e' => {
                            if adding {
                                flags.insert(mode);
                            } else {
                                flags.remove(&mode);
                            }
                        }
                        'o' | 'v' | 'b' => {
                            let Some(value) = p.get(arg) else {
                                return vec![reply(461, "MODE :Missing target")];
                            };
                            arg += 1;
                            if mode != 'b' && !c.members.contains(*value) {
                                return vec![reply(
                                    441,
                                    &format!("{value} {name} :Not on channel"),
                                )];
                            }
                            if mode == 'o' && !adding && owner == *value {
                                owner.clear();
                            }
                            let set = match mode {
                                'o' => &mut operators,
                                'v' => &mut voices,
                                _ => &mut bans,
                            };
                            if adding {
                                if set.len() >= 4096 {
                                    return vec![reply(478, "MODE :List capacity reached")];
                                }
                                set.insert((*value).to_owned());
                            } else {
                                set.remove(*value);
                            }
                        }
                        'k' => {
                            if adding {
                                let Some(value) = p.get(arg) else {
                                    return vec![reply(461, "MODE :Missing key")];
                                };
                                key = (*value).to_owned();
                                arg += 1;
                            } else {
                                key.clear();
                                if p.get(arg).is_some() {
                                    arg += 1;
                                }
                            }
                        }
                        'l' => {
                            if adding {
                                let Some(value) = p
                                    .get(arg)
                                    .and_then(|v| v.parse::<usize>().ok())
                                    .filter(|v| *v > 0 && *v <= 4096)
                                else {
                                    return vec![reply(461, "MODE :Invalid limit")];
                                };
                                limit = Some(value);
                                arg += 1;
                            } else {
                                limit = None;
                            }
                        }
                        _ => return vec![reply(472, &format!("{mode} :Unsupported channel mode"))],
                    }
                }
                c.key = key;
                c.limit = limit;
                c.no_external = no_external;
                c.topic_owner = topic_owner;
                c.flags = flags;
                c.owner = owner;
                c.operators = operators;
                c.voices = voices;
                c.bans = bans;
                broadcast(
                    c,
                    &format!(":{prefix} MODE {name} {}\r\n", p[1..].join(" ")),
                    &mut out,
                );
            }
            _ => out.push(reply(
                461,
                &format!("{} :Invalid parameters", message.command),
            )),
        }
        out
    }
    /// Rename a registered peer while preserving its room and key state.
    /// The caller holds the dispatch lock and moves its writer to the new key.
    pub fn rename(&mut self, old: &str, new: &str) -> Result<Vec<Delivery>, String> {
        if new.is_empty()
            || new.len() > 128
            || !new.bytes().all(|b| b.is_ascii_graphic())
            || new.contains([':', ',', '!', '@', '#', '*'])
        {
            return Err("Invalid nickname".into());
        }
        if old == new {
            return Ok(Vec::new());
        }
        if self.identities.contains_key(new) {
            return Err("Nickname already in use".into());
        }
        let prefix = self.prefix(old);
        let identity = self
            .identities
            .remove(old)
            .ok_or("Nickname is not registered")?;
        self.identities.insert(new.to_owned(), identity);
        if let Some(keys) = self.global_keys.remove(old) {
            self.global_keys.insert(new.to_owned(), keys);
        }
        let mut recipients = BTreeSet::from([new.to_owned()]);
        for c in self.channels.values_mut() {
            if c.members.remove(old) {
                c.members.insert(new.to_owned());
                recipients.extend(c.members.iter().cloned());
            }
            if c.owner == old {
                c.owner = new.to_owned();
            }
            for set in [&mut c.operators, &mut c.voices, &mut c.invited] {
                if set.remove(old) {
                    set.insert(new.to_owned());
                }
            }
            if let Some(keys) = c.member_keys.remove(old) {
                c.member_keys.insert(new.to_owned(), keys);
            }
        }
        Ok(recipients
            .into_iter()
            .map(|recipient| (recipient, format!(":{prefix} NICK :{new}\r\n")))
            .collect())
    }
    pub fn disconnect(&mut self, nick: &str) -> Vec<Delivery> {
        let prefix = self.prefix(nick);
        if let Some(matches) = &self.matches {
            matches.forget(nick);
        }
        self.identities.remove(nick);
        self.global_keys.remove(nick);
        let mut recipients = BTreeSet::new();
        let mut out = Vec::new();
        for (name, c) in &mut self.channels {
            c.member_keys.remove(nick);
            c.operators.remove(nick);
            c.voices.remove(nick);
            c.invited.remove(nick);
            if c.members.remove(nick) {
                recipients.extend(c.members.iter().cloned());
                transfer_owner(name, c, &mut out);
            }
        }
        for recipient in recipients {
            out.push((recipient, format!(":{prefix} QUIT :Disconnected\r\n")));
        }
        self.channels.retain(|_, c| !c.members.is_empty());
        out
    }
}
// Explicit keys return values in request order; b_* appends key/value pairs.
fn key_values(keys: &BTreeMap<String, String>, requested: &str) -> String {
    let mut result = String::new();
    let all = requested == "*";
    for key in requested
        .split('\\')
        .filter(|k| !k.is_empty() && *k != "b_*" && *k != "*")
    {
        result.push('\\');
        result.push_str(keys.get(key).map(String::as_str).unwrap_or(""));
    }
    if all || requested.split('\\').any(|k| k == "b_*") {
        for (key, value) in keys {
            if all || key.starts_with("b_") {
                result.push('\\');
                result.push_str(key);
                result.push('\\');
                result.push_str(value);
            }
        }
    }
    result
}
fn parse_keys(value: &str) -> Option<Vec<(&str, &str)>> {
    if value.len() > 2500 || !value.starts_with('\\') {
        return None;
    }
    let parts: Vec<_> = value[1..].split('\\').collect();
    if !parts.len().is_multiple_of(2) || parts.len() > 128 {
        return None;
    }
    let pairs: Vec<_> = parts
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| (p[0], p[1]))
        .collect();
    if pairs
        .iter()
        .any(|(k, v)| k.is_empty() || k.len() > 64 || v.len() > 512)
    {
        return None;
    }
    Some(pairs)
}
/// Width of a `b_uid` value, in hex characters. The client parses the value
/// as hex byte pairs, so this is an eight-byte identifier.
const UID_HEX_WIDTH: usize = 16;

/// Values for keys a client asks for but never sets.
///
/// `username` is the name the client registered, so reporting it back is
/// reporting a fact; the client demangles the peer's address and profile from
/// it. `b_uid` is a user identifier the client reads but no client publishes,
/// so the server has to supply it; it is derived from the same profile the
/// registered name carries, which keeps it stable for a player across rooms.
/// The client accepts lowercase hex only, in byte pairs.
///
/// `b_flags` is answered empty, and that is the correct answer rather than a
/// gap. The value goes to `piSetPlayerRoomFlags`, and the flags it encodes are
/// letters, not a number -- `peer.h` documents PEER_FLAG_STAGING/READY/
/// PLAYING/AWAY/HOST as `s`/`r`/`g`/`a`/`h`. A digit is not a flag letter, so
/// a server-invented "0" is a malformed value, not a neutral one. The key also
/// belongs to the client: `piKeyCacheRefresh` skips requesting flags for a
/// player who just joined because "he just joined, and will set them". A real
/// server therefore returns an empty value until some client sets the key, and
/// this title sets `b_s` instead and never sets `b_flags` at all.
fn server_key(key: &str, who: &str, registered: &BTreeMap<String, String>) -> String {
    let name = registered.get(who);
    match key {
        "username" => name.cloned().unwrap_or_default(),
        "b_uid" => name
            .and_then(|name| name.rsplit_once('|'))
            .and_then(|(_, profile)| profile.parse::<u64>().ok())
            .filter(|profile| *profile > 0)
            .map(|profile| format!("{profile:0UID_HEX_WIDTH$x}"))
            .unwrap_or_default(),
        _ => String::new(),
    }
}
fn is_operator(c: &Channel, nick: &str) -> bool {
    c.owner == nick || c.operators.contains(nick)
}
/// Mode letters that grant or revoke standing over other members, as opposed
/// to describing the room itself.
fn moderation_modes(modes: &str) -> bool {
    modes.chars().any(|mode| matches!(mode, 'o' | 'b'))
}
fn transfer_owner(name: &str, c: &mut Channel, out: &mut Vec<Delivery>) {
    if !c.members.contains(&c.owner)
        && let Some(next) = c.members.first()
    {
        c.owner = next.clone();
        broadcast(c, &format!(":s MODE {name} +o {}\r\n", c.owner), out);
    }
}
fn broadcast(c: &Channel, line: &str, out: &mut Vec<Delivery>) {
    for nick in &c.members {
        out.push((nick.clone(), line.to_owned()));
    }
}
fn names(nick: &str, name: &str, c: &Channel, out: &mut Vec<Delivery>) {
    // One name per reply bounds lines even for large channels.
    for member in &c.members {
        out.push((
            nick.to_owned(),
            format!(
                ":s 353 {nick} = {name} :{}{member}\r\n",
                if is_operator(c, member) {
                    "@"
                } else if c.voices.contains(member) {
                    "+"
                } else {
                    ""
                }
            ),
        ));
    }
    out.push((
        nick.to_owned(),
        format!(":s 366 {nick} {name} :End of NAMES\r\n"),
    ));
}
fn wildcard(pattern: &str, value: &str) -> bool {
    let (mut p, mut v, mut star, mut retry) = (0, 0, None, 0);
    let (pats, vals) = (pattern.as_bytes(), value.as_bytes());
    while v < vals.len() {
        if p < pats.len() && (pats[p] == b'?' || pats[p] == vals[v]) {
            p += 1;
            v += 1;
        } else if p < pats.len() && pats[p] == b'*' {
            star = Some(p);
            p += 1;
            retry = v;
        } else if let Some(s) = star {
            retry += 1;
            v = retry;
            p = s + 1;
        } else {
            return false;
        }
    }
    while p < pats.len() && pats[p] == b'*' {
        p += 1;
    }
    p == pats.len()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn run(rooms: &mut Rooms, nick: &str, line: &str) -> Vec<Delivery> {
        rooms.command(nick, &mkvsdcu_proto::peerchat::parse_line(line).unwrap())
    }

    #[test]
    fn sdk_broadcast_key_filter_accumulates_columns_across_users() {
        let mut r = Rooms::default();
        for nick in ["a", "b", "c"] {
            run(&mut r, nick, "JOIN #test");
        }
        run(&mut r, "a", r"SETCKEY #test a :\b_addr\first\b_ready\1");
        run(&mut r, "b", r"SETCKEY #test b :\b_addr\second\b_extra\new");
        run(&mut r, "c", r"SETCKEY #test c :\b_ready\0");
        let replies = run(&mut r, "a", r"GETCKEY #test * 123 0 :\missing\b_*");
        let mut known = vec!["missing".to_owned()];
        let mut decoded = Vec::new();
        for (_, line) in replies.iter().take(3) {
            let message = mkvsdcu_proto::peerchat::parse_line(line.trim_end()).unwrap();
            let mut parts = message.params[4].strip_prefix('\\').unwrap().split('\\');
            let mut row = BTreeMap::new();
            for key in &known {
                row.insert(key.clone(), parts.next().unwrap().to_owned());
            }
            while let Some(key) = parts.next() {
                let value = parts.next().expect("broadcast keys are pairs");
                known.push(key.to_owned());
                row.insert(key.to_owned(), value.to_owned());
            }
            decoded.push(row);
        }
        assert_eq!(decoded[0]["b_addr"], "first");
        assert_eq!(decoded[1]["b_addr"], "second");
        assert_eq!(decoded[1]["b_ready"], "");
        assert_eq!(decoded[1]["b_extra"], "new");
        assert_eq!(decoded[2]["b_ready"], "0");
        assert_eq!(decoded[2]["b_extra"], "");
        assert_eq!(known, vec!["missing", "b_addr", "b_ready", "b_extra"]);
    }
    #[test]
    fn list_key_option_keeps_four_parameters_and_plain_list_topic() {
        let mut r = Rooms::default();
        run(&mut r, "a", "JOIN #room");
        run(&mut r, "a", "TOPIC #room :Test room");
        run(&mut r, "a", "SETGROUP #room test_m1");
        run(&mut r, "a", "MODE #room +l 8");
        let keyed = run(&mut r, "b", "LIST test_m1 k");
        let row = mkvsdcu_proto::peerchat::parse_line(keyed[1].1.trim_end()).unwrap();
        assert_eq!(
            row.params,
            vec!["b", "#room", "1", r"\topic\Test room\limit\8"]
        );
        let plain = run(&mut r, "b", "LIST test_m1");
        let row = mkvsdcu_proto::peerchat::parse_line(plain[1].1.trim_end()).unwrap();
        assert_eq!(row.params, vec!["b", "#room", "1", "Test room"]);
        run(&mut r, "a", "MODE #room -l");
        let no_limit = run(&mut r, "b", "LIST test_m1 k");
        assert!(no_limit[1].1.ends_with(":\\topic\\Test room\r\n"));
    }
    #[test]
    fn sdk_key_cookies_broadcasts_and_cleanup() {
        let mut r = Rooms::default();
        for n in ["a", "b"] {
            r.set_identity(n, "user", "host", "Player");
            run(&mut r, n, "JOIN #test");
        }
        let updates = run(&mut r, "a", r"SETCKEY #test a :\b_ready\1\private\hidden");
        assert_eq!(updates.len(), 2);
        assert!(
            updates
                .iter()
                .all(|(_, l)| l.contains("BCAST :\\b_ready\\1") && !l.contains("hidden"))
        );
        // Every pushed line must end CRLF: a bare LF mis-frames the
        // client's line parser and it loses the room view.
        assert!(
            updates.iter().all(|(_, l)| l.ends_with("\r\n")),
            "{updates:?}"
        );
        let keys = run(&mut r, "b", r"GETCKEY #test * 001 0 :\private\missing\b_*");
        assert_eq!(keys.len(), 3);
        assert_eq!(
            keys[0].1,
            ":s 702 b #test a 001 :\\hidden\\\\b_ready\\1\r\n"
        );
        assert_eq!(
            mkvsdcu_proto::peerchat::parse_line(keys[0].1.trim_end())
                .unwrap()
                .params
                .len(),
            5
        );
        assert!(keys[2].1.contains("703 b #test 001 :"));
        run(&mut r, "a", r"SETCHANKEY #test :\b_map\arena\count\2");
        assert_eq!(
            run(&mut r, "b", r"GETCHANKEY #test 002 0 :\count")[0].1,
            ":s 704 b #test 002 :\\2\r\n"
        );
        assert!(
            run(&mut r, "b", r"SETCHANKEY #test :\count\3")[0]
                .1
                .contains(" 482 ")
        );
        run(&mut r, "a", r"SETKEY :\rank\4");
        assert_eq!(
            run(&mut r, "b", r"GETKEY a 003 0 :\rank")[0].1,
            ":s 700 b a 003 :\\4\r\n"
        );
        let renamed = r.rename("a", "c").unwrap();
        assert_eq!(renamed.len(), 2);
        assert!(
            run(&mut r, "b", r"GETCKEY #test c 004 0 :\b_ready")[0]
                .1
                .contains(":\\1")
        );
        run(&mut r, "c", "PART #test");
        run(&mut r, "c", "JOIN #test");
        assert_eq!(
            run(&mut r, "b", r"GETCKEY #test c 005 0 :\b_ready")[0].1,
            ":s 702 b #test c 005 :\\\r\n"
        );
        r.disconnect("c");
        assert!(
            run(&mut r, "b", r"GETKEY c 006 0 :\rank")[0]
                .1
                .contains(" 401 ")
        );
        run(&mut r, "b", "PART #test");
        run(&mut r, "b", "JOIN #test");
        assert_eq!(
            run(&mut r, "b", r"GETCHANKEY #test 007 0 :*")[0].1,
            ":s 704 b #test 007 :\r\n"
        );
    }
    #[test]
    fn invite_kick_ban_and_operator_voice_management() {
        let mut r = Rooms::default();
        for n in ["a", "b", "c"] {
            r.set_identity(n, "user", "host", "Player");
        }
        run(&mut r, "a", "JOIN #test");
        run(&mut r, "a", "MODE #test +i");
        assert!(run(&mut r, "b", "JOIN #test")[0].1.contains(" 473 "));
        assert!(
            run(&mut r, "a", "INVITE b #test")
                .iter()
                .any(|(n, l)| n == "b" && l.contains(" INVITE b :#test"))
        );
        run(&mut r, "b", "JOIN #test");
        run(&mut r, "a", "MODE #test +m");
        assert!(
            run(&mut r, "b", "PRIVMSG #test :hello")[0]
                .1
                .contains(" 404 ")
        );
        run(&mut r, "a", "MODE #test +v b");
        assert!(
            run(&mut r, "b", "PRIVMSG #test :hello")[0]
                .1
                .contains(" PRIVMSG ")
        );
        run(&mut r, "a", "MODE #test +o b");
        assert!(
            run(&mut r, "b", "TOPIC #test :operator")[0]
                .1
                .contains(" TOPIC ")
        );
        run(&mut r, "a", "MODE #test -o b");
        assert!(run(&mut r, "b", "KICK #test a")[0].1.contains(" 482 "));
        assert_eq!(run(&mut r, "a", "KICK #test b :reason").len(), 2);
        run(&mut r, "a", "MODE #test -i+b b!*@*");
        assert!(run(&mut r, "b", "JOIN #test")[0].1.contains(" 474 "));
        assert!(run(&mut r, "a", "MODE #test +b")[0].1.contains(" 367 "));
        run(&mut r, "a", "MODE #test -b b!*@*");
        assert!(run(&mut r, "b", "JOIN #test")[0].1.contains(" JOIN "));
    }
    #[test]
    fn sdk_room_mode_and_group_listing() {
        let mut rooms = Rooms::default();
        run(&mut rooms, "a", "JOIN #test");
        run(&mut rooms, "a", "SETGROUP #test title_m1");
        let mode = run(&mut rooms, "a", "MODE #test -i+p-s-m-n-t+l-e 8");
        assert!(mode[0].1.contains(" MODE #test "));
        assert!(
            run(&mut rooms, "a", "MODE #test")[0]
                .1
                .contains("#test +pl 8")
        );
        assert!(
            run(&mut rooms, "b", "LIST title_m1 k")
                .iter()
                .any(|(_, line)| line.contains(" 322 "))
        );
        assert_eq!(run(&mut rooms, "b", "LIST").len(), 2);
        run(&mut rooms, "a", "MODE #test +i");
        assert!(run(&mut rooms, "b", "JOIN #test")[0].1.contains(" 473 "));
    }
    #[test]
    fn mode_changes_update_permissions_and_queries() {
        let mut rooms = Rooms::default();
        run(&mut rooms, "a", "JOIN #test");
        run(&mut rooms, "b", "JOIN #test");
        assert!(
            run(&mut rooms, "c", "PRIVMSG #test :external")[0]
                .1
                .contains(" 442 ")
        );
        run(&mut rooms, "a", "MODE #test -nt");
        assert!(
            run(&mut rooms, "a", "MODE #test")[0]
                .1
                .contains("#test +\r\n")
        );
        assert_eq!(run(&mut rooms, "c", "PRIVMSG #test :external").len(), 2);
        assert!(
            run(&mut rooms, "b", "TOPIC #test :allowed")[0]
                .1
                .contains("TOPIC #test :allowed")
        );
        assert!(run(&mut rooms, "a", "MODE #test +z")[0].1.contains(" 472 "));
    }
    #[test]
    fn uid_matches_the_encoding_the_client_parses() {
        // The client reads b_uid as hex byte pairs and accepts lowercase
        // digits only: it rejects anything outside 0-9 and a-f.
        let mut registered = BTreeMap::new();
        registered.insert("a".to_owned(), "X1fsaFvFqX|1".to_owned());
        registered.insert("b".to_owned(), "X1fsaFvFWX|255".to_owned());
        registered.insert("c".to_owned(), "no-profile".to_owned());

        let uid = server_key("b_uid", "a", &registered);
        assert_eq!(uid, "0000000000000001");
        assert_eq!(uid.len(), UID_HEX_WIDTH);
        assert!(uid.len().is_multiple_of(2), "parsed as byte pairs");
        assert!(
            uid.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "{uid}"
        );
        // A value with a hex letter stays lowercase.
        let uid = server_key("b_uid", "b", &registered);
        assert_eq!(uid, "00000000000000ff");
        // Nothing to derive it from yields no value rather than a wrong one.
        assert_eq!(server_key("b_uid", "c", &registered), "");
        assert_eq!(server_key("b_uid", "missing", &registered), "");
        // Still not inventing flags.
        assert_eq!(server_key("b_flags", "a", &registered), "");
    }

    #[test]
    fn server_answers_the_keys_a_client_never_sets() {
        // Observed on console: right after joining, each client asks for
        // exactly these two keys and sets neither of them.
        let mut rooms = Rooms::default();
        rooms.set_identity("a", "X1fsaFvFqX|1", "10.0.0.220", "real");
        rooms.set_identity("b", "X1fsaFvFWX|2", "10.0.0.221", "real");
        run(&mut rooms, "a", "JOIN #gsp!test!1");
        run(&mut rooms, "b", "JOIN #gsp!test!1");
        let replies = run(
            &mut rooms,
            "b",
            "GETCKEY #gsp!test!1 * 006 0 :\\username\\b_flags",
        );
        let rows: Vec<&String> = replies
            .iter()
            .filter(|(_, line)| line.contains(" 702 "))
            .map(|(_, line)| line)
            .collect();
        assert_eq!(rows.len(), 2);
        // The registered name is reported, not an empty value.
        assert!(
            rows.iter().any(|line| line.contains("X1fsaFvFqX|1")),
            "{rows:?}"
        );
        assert!(
            rows.iter().any(|line| line.contains("X1fsaFvFWX|2")),
            "{rows:?}"
        );
        // b_flags is empty because no client set it; the flags encoding is
        // letters, so a digit here would be the malformed answer.
        assert!(rows.iter().all(|line| line.ends_with("\\\r\n")), "{rows:?}");
    }

    #[test]
    fn two_clients_crud_and_cleanup() {
        let mut rooms = Rooms::default();
        let join = run(&mut rooms, "a", "JOIN #test");
        assert!(join[0].1.contains(" JOIN "));
        assert!(join.last().unwrap().1.contains(" 366 "));
        run(&mut rooms, "a", "TOPIC #test :Test room");
        run(&mut rooms, "a", "MODE #test +kl secret 2");
        assert!(
            run(&mut rooms, "b", "JOIN #test wrong")[0]
                .1
                .contains(" 475 ")
        );
        assert!(
            run(&mut rooms, "b", "JOIN #test secret")
                .iter()
                .any(|(n, l)| n == "a" && l.contains("JOIN"))
        );
        assert!(
            run(&mut rooms, "c", "JOIN #test secret")[0]
                .1
                .contains(" 471 ")
        );
        // Room configuration is open to any member: both consoles configure
        // the room they are setting a match up in, so a member that only
        // joined still has its TOPIC, MODE and SETGROUP applied.
        let topic = run(&mut rooms, "b", "TOPIC #test :set by joiner");
        assert!(topic.iter().all(|(_, l)| !l.contains(" 482 ")));
        assert!(
            topic
                .iter()
                .any(|(n, l)| n == "a" && l.contains("TOPIC #test :set by joiner"))
        );
        assert!(
            run(&mut rooms, "b", "SETGROUP #test group")
                .iter()
                .all(|(_, l)| !l.contains(" 482 "))
        );
        // Standing over other members still needs an operator.
        assert!(
            run(&mut rooms, "b", "MODE #test +o c")[0]
                .1
                .contains(" 482 ")
        );
        run(&mut rooms, "a", "TOPIC #test :Test room");
        let list = run(&mut rooms, "b", "LIST #t*");
        assert!(list.iter().any(|(_, l)| l.contains("#test 2 :Test room")));
        let chat = run(&mut rooms, "b", "PRIVMSG #test :hello");
        assert_eq!(chat.len(), 1);
        assert_eq!(chat[0].0, "a");
        let left = rooms.disconnect("a");
        assert!(left.iter().any(|(_, l)| l.contains("MODE #test +o b")));
        run(&mut rooms, "b", "TOPIC #test :new owner");
        run(&mut rooms, "b", "PART #test");
        assert_eq!(run(&mut rooms, "b", "LIST").len(), 2);
    }

    #[test]
    fn leaving_quiet_mode_resends_the_player_list_unprompted() {
        // Observed after a match: both consoles send "+q" on the way in and
        // "-q" on the way out, and the client has cleared its player lists by
        // the time it sends "-q".
        let mut r = Rooms::default();
        for n in ["a", "b"] {
            r.set_identity(n, "user", "host", "Player");
            run(&mut r, n, "JOIN #test");
        }
        // Entering quiet mode is accepted without an error reply.
        assert!(run(&mut r, "a", "MODE a +q").is_empty());
        let back = run(&mut r, "a", "MODE a -q");
        // One 353 per member, then the 366 terminator, all to the asker.
        let members: Vec<&String> = back
            .iter()
            .filter(|(_, l)| l.contains(" 353 "))
            .map(|(_, l)| l)
            .collect();
        assert_eq!(members.len(), 2, "{back:?}");
        assert!(members.iter().any(|l| l.ends_with(":@a\r\n")), "{back:?}");
        assert!(members.iter().any(|l| l.ends_with(":b\r\n")), "{back:?}");
        assert!(back.last().unwrap().1.contains(" 366 "), "{back:?}");
        assert!(back.iter().all(|(to, _)| to == "a"), "{back:?}");
        // A channel the asker is not in must not be reported.
        run(&mut r, "b", "JOIN #other");
        let again = run(&mut r, "a", "MODE a -q");
        assert!(
            again.iter().all(|(_, l)| !l.contains("#other")),
            "{again:?}"
        );
        // A real channel mode on a channel target still works.
        assert!(!run(&mut r, "a", "MODE #test").is_empty());
    }
}
