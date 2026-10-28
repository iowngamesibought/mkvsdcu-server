//! AuthService-to-GPCM session correlation.
//!
//! AuthService mints `authToken` and `partnerChallenge`; GPCM receives the token
//! from the client and must know the matching challenge to compute the server
//! `proof`. M1 keeps this in memory only: a restart invalidates all tokens and
//! the console has to run the online login again.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SESSION_TTL: Duration = Duration::from_secs(15 * 60);
const VERIFIED_SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_SESSIONS: usize = 4096;

#[derive(Debug, Clone)]
pub struct AuthSession {
    pub partner_challenge: String,
    pub profile_id: u32,
    pub user_id: u32,
    created: Instant,
    gp_peer: Option<IpAddr>,
}

impl AuthSession {
    fn valid(&self, now: Instant) -> bool {
        now.duration_since(self.created)
            < if self.gp_peer.is_some() {
                VERIFIED_SESSION_TTL
            } else {
                SESSION_TTL
            }
    }
}

#[derive(Debug, Default)]
pub struct AuthSessions {
    inner: Mutex<Inner>,
    identity: Option<Arc<crate::identity::IdentityStore>>,
}

#[derive(Debug, Default)]
struct Inner {
    sessions: HashMap<String, AuthSession>,
    next_profile_id: u32,
}

impl AuthSessions {
    pub fn identity_store(&self) -> Option<Arc<crate::identity::IdentityStore>> {
        self.identity.as_ref().map(Arc::clone)
    }
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful AuthService login. Tokens are bounded and expired
    /// entries are pruned so a client cannot grow the map without limit.
    pub fn with_identity(store: crate::identity::IdentityStore) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            identity: Some(Arc::new(store)),
        }
    }

    pub fn insert_ticket(
        &self,
        token: String,
        partner_challenge: String,
        ticket: Option<&str>,
    ) -> Result<(), String> {
        let profile_id = match &self.identity {
            Some(store) => Some(store.profile_for_ticket(ticket.ok_or("missing account ticket")?)?),
            None => None,
        };
        self.insert_profile(token, partner_challenge, profile_id);
        Ok(())
    }

    pub fn insert(&self, token: String, partner_challenge: String) {
        self.insert_profile(token, partner_challenge, None);
    }

    fn insert_profile(&self, token: String, partner_challenge: String, profile_id: Option<u32>) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        inner.sessions.retain(|_, session| session.valid(now));

        while inner.sessions.len() >= MAX_SESSIONS {
            let Some(oldest) = inner
                .sessions
                .iter()
                .min_by_key(|(_, session)| session.created)
                .map(|(token, _)| token.clone())
            else {
                break;
            };
            inner.sessions.remove(&oldest);
        }

        let profile_id = profile_id.unwrap_or_else(|| next_id(&mut inner.next_profile_id));
        inner.sessions.insert(
            token,
            AuthSession {
                partner_challenge,
                profile_id,
                user_id: profile_id,
                created: now,
                gp_peer: None,
            },
        );
    }

    /// Resolve the GPCM login token. Reusing a token returns the same profile,
    /// which keeps a reconnecting client stable for the lifetime of the entry.
    pub fn begin_gp_login(&self, token: &str) -> Option<AuthSession> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        inner.sessions.retain(|_, session| session.valid(now));
        inner.sessions.get(token).cloned()
    }

    /// Bind a verified GPCM token to its observed peer for ordinary secure
    /// PeerChat registration. This is session correlation, not a network allowlist.
    pub fn bind_gp_peer(&self, token: &str, peer: IpAddr) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(session) = inner.sessions.get_mut(token)
            && session.valid(Instant::now())
        {
            session.gp_peer = Some(peer);
        }
    }

    pub fn for_peer_profile(&self, peer: IpAddr, profile_id: u32) -> Option<AuthSession> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner
            .sessions
            .values()
            .find(|session| {
                session.profile_id == profile_id
                    && session.gp_peer == Some(peer)
                    && session.valid(Instant::now())
            })
            .cloned()
    }

    /// End a login. The console reports its last match before logging out, so
    /// an expired token owns nothing further: it can no longer start a chat
    /// registration or claim a result. Returns the profile that logged out.
    pub fn expire(&self, token: &str) -> Option<u32> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner
            .sessions
            .remove(token)
            .map(|session| session.profile_id)
    }

    /// Match submissions may arrive after the short login-token window. Only
    /// GP-verified sessions from the same connection source may own a report.
    pub fn verify_result(
        &self,
        peer: IpAddr,
        profile_id: u32,
        connection_id: i32,
        proof: &str,
    ) -> bool {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.sessions.values().any(|session| {
            session.profile_id == profile_id
                && session.gp_peer == Some(peer)
                && session.valid(Instant::now())
                && mkvsdcu_proto::gstats::player_response(connection_id, &session.partner_challenge)
                    .is_ok_and(|expected| {
                        expected.len() == proof.len()
                            && openssl::memcmp::eq(expected.as_bytes(), proof.as_bytes())
                    })
        })
    }
    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .sessions
            .len()
    }
}

fn next_id(next: &mut u32) -> u32 {
    if *next == 0 {
        *next = 1;
    }
    let value = *next;
    *next = next.wrapping_add(1);
    if *next == 0 {
        *next = 1;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn result_proof_requires_verified_owner_and_survives_login_window() {
        let sessions = AuthSessions::new();
        sessions.insert("token".into(), "synthetic".into());
        let id = sessions.begin_gp_login("token").unwrap().profile_id;
        let peer = "192.0.2.1".parse().unwrap();
        let proof = mkvsdcu_proto::gstats::player_response(7, "synthetic").unwrap();
        assert!(!sessions.verify_result(peer, id, 7, &proof));
        sessions.bind_gp_peer("token", peer);
        sessions
            .inner
            .lock()
            .unwrap()
            .sessions
            .get_mut("token")
            .unwrap()
            .created = Instant::now() - Duration::from_secs(3600);
        assert!(sessions.verify_result(peer, id, 7, &proof));
        assert!(sessions.begin_gp_login("token").is_some());
        assert!(!sessions.verify_result(peer, id, 8, &proof));
        assert!(!sessions.verify_result(peer, id + 1, 7, &proof));
        assert!(!sessions.verify_result("192.0.2.2".parse().unwrap(), id, 7, &proof));
        sessions
            .inner
            .lock()
            .unwrap()
            .sessions
            .get_mut("token")
            .unwrap()
            .created = Instant::now() - VERIFIED_SESSION_TTL;
        assert!(!sessions.verify_result(peer, id, 7, &proof));
    }

    #[test]
    fn secure_chat_requires_profile_bound_by_verified_gp_peer() {
        let sessions = AuthSessions::new();
        sessions.insert("token".into(), "synthetic".into());
        let id = sessions.begin_gp_login("token").unwrap().profile_id;
        let peer = "192.0.2.1".parse().unwrap();
        assert!(sessions.for_peer_profile(peer, id).is_none());
        sessions.bind_gp_peer("token", peer);
        assert!(sessions.for_peer_profile(peer, id).is_some());
        assert!(
            sessions
                .for_peer_profile("192.0.2.2".parse().unwrap(), id)
                .is_none()
        );
        assert!(sessions.for_peer_profile(peer, id + 1).is_none());
    }
    #[test]
    fn logging_out_expires_the_token_and_its_claims() {
        let sessions = AuthSessions::new();
        sessions.insert("token".into(), "synthetic".into());
        let peer = "192.0.2.1".parse().unwrap();
        let id = sessions.begin_gp_login("token").unwrap().profile_id;
        sessions.bind_gp_peer("token", peer);
        let proof = mkvsdcu_proto::gstats::player_response(7, "synthetic").unwrap();
        assert!(sessions.verify_result(peer, id, 7, &proof));

        assert_eq!(sessions.expire("token"), Some(id));
        assert!(sessions.begin_gp_login("token").is_none());
        assert!(sessions.for_peer_profile(peer, id).is_none());
        assert!(!sessions.verify_result(peer, id, 7, &proof));
        // Logging out twice is not an error and reports nothing the second time.
        assert_eq!(sessions.expire("token"), None);
        assert_eq!(sessions.len(), 0);
    }

    #[test]
    fn correlates_token_and_stable_profile() {
        let sessions = AuthSessions::new();
        sessions.insert("token".to_owned(), "challenge".to_owned());

        let first = sessions.begin_gp_login("token").unwrap();
        let second = sessions.begin_gp_login("token").unwrap();
        assert_eq!(first.partner_challenge, "challenge");
        assert_eq!(first.profile_id, first.user_id);
        assert!(first.profile_id > 0);
        assert_eq!(first.profile_id, second.profile_id);
        assert!(sessions.begin_gp_login("missing").is_none());
    }

    #[test]
    fn profile_ids_are_distinct() {
        let sessions = AuthSessions::new();
        sessions.insert("a".to_owned(), "x".to_owned());
        sessions.insert("b".to_owned(), "y".to_owned());
        let a = sessions.begin_gp_login("a").unwrap();
        let b = sessions.begin_gp_login("b").unwrap();
        assert_ne!(a.profile_id, b.profile_id);
        assert_eq!(sessions.len(), 2);
    }
}
