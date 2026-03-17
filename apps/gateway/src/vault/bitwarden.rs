//! Bitwarden vault provider — `BitwardenVaultProvider` implementing `VaultProvider`.
//!
//! Contains all Bitwarden-specific logic: `RemoteClient` lifecycle, PSK pairing,
//! Noise protocol, credential caching, and session restore. Per-user sessions are
//! stored in a `DashMap<user_id, Arc<BitwardenUserSession>>`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use ap_client::{
    CredentialData, CredentialQuery, DefaultProxyClient, IdentityFingerprint, IdentityProvider,
    Psk, RemoteClient, RemoteClientEvent,
};
use ap_proxy_client::ProxyClientConfig;
use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

use super::bitwarden_db::{BitwardenIdentityProvider, BitwardenSessionStore};
use super::{PairResult, ProviderStatus, VaultCredential, VaultProvider};
use crate::db;

/// Parse a hex-encoded fingerprint string into an `IdentityFingerprint`.
pub(super) fn parse_fingerprint(hex_str: &str) -> Option<IdentityFingerprint> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(IdentityFingerprint(arr))
}

/// How long to cache successful credential lookups.
const CREDENTIAL_CACHE_TTL: Duration = Duration::from_secs(60);
/// How long to cache negative (no credential found) results.
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(30);
/// Timeout for individual credential requests.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// How often the eviction task runs.
const EVICTION_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Evict sessions idle longer than this.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

// ── Connection data ─────────────────────────────────────────────────────

/// Bitwarden-specific data stored in `VaultConnection.connectionData`.
/// Each field is optional to support incremental state build-up during pairing.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct BitwardenConnectionData {
    /// Hex-encoded fingerprint of the remote (desktop) device.
    pub fingerprint: Option<String>,
    /// COSE-encoded identity keypair bytes.
    #[serde(
        serialize_with = "serialize_bytes_opt",
        deserialize_with = "deserialize_bytes_opt",
        default
    )]
    pub key_data: Option<Vec<u8>>,
    /// Noise protocol transport state (CBOR bytes).
    #[serde(
        serialize_with = "serialize_bytes_opt",
        deserialize_with = "deserialize_bytes_opt",
        default
    )]
    pub transport_state: Option<Vec<u8>>,
}

/// Serialize `Option<Vec<u8>>` as base64 string for JSON storage.
fn serialize_bytes_opt<S: serde::Serializer>(
    val: &Option<Vec<u8>>,
    s: S,
) -> Result<S::Ok, S::Error> {
    match val {
        Some(bytes) => {
            use base64::Engine;
            s.serialize_some(&base64::engine::general_purpose::STANDARD.encode(bytes))
        }
        None => s.serialize_none(),
    }
}

/// Deserialize `Option<Vec<u8>>` from base64 string.
fn deserialize_bytes_opt<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Vec<u8>>, D::Error> {
    let opt: Option<String> = Option::deserialize(d)?;
    match opt {
        Some(s) => {
            use base64::Engine;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&s)
                .map_err(serde::de::Error::custom)?;
            Ok(Some(bytes))
        }
        None => Ok(None),
    }
}

// ── Per-user session ────────────────────────────────────────────────────

struct CachedCredential {
    data: Option<CredentialData>,
    expires_at: Instant,
}

struct BitwardenUserSession {
    client: Mutex<Option<RemoteClient>>,
    identity: BitwardenIdentityProvider,
    /// Cached connectionData from DB — avoids redundant reads during lazy restore.
    connection_data: Option<BitwardenConnectionData>,
    credential_cache: DashMap<String, CachedCredential>,
    /// Last time this session was used (for eviction). Uses std::sync::Mutex since
    /// the update is instant (no .await while holding it).
    last_used: std::sync::Mutex<Instant>,
}

// ── Config ──────────────────────────────────────────────────────────────

pub(crate) struct BitwardenConfig {
    pub proxy_url: String,
}

// ── Provider ────────────────────────────────────────────────────────────

pub(crate) struct BitwardenVaultProvider {
    config: BitwardenConfig,
    pool: PgPool,
    sessions: Arc<DashMap<String, Arc<BitwardenUserSession>>>,
}

impl BitwardenVaultProvider {
    pub fn new(config: BitwardenConfig, pool: PgPool) -> Self {
        let sessions = Arc::new(DashMap::new());
        Self::spawn_eviction_task(Arc::clone(&sessions));
        Self {
            config,
            pool,
            sessions,
        }
    }

    /// Background task that evicts idle sessions every `EVICTION_INTERVAL`.
    /// For each idle session: acquires the client Mutex (ensuring no in-flight request),
    /// closes the RemoteClient, then removes from the DashMap.
    fn spawn_eviction_task(sessions: Arc<DashMap<String, Arc<BitwardenUserSession>>>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(EVICTION_INTERVAL);
            loop {
                interval.tick().await;

                // Collect user_ids to evict (don't hold DashMap iter across await)
                let to_evict: Vec<String> = sessions
                    .iter()
                    .filter_map(|entry| {
                        let last_used = entry.value().last_used.lock().ok()?;
                        if last_used.elapsed() > SESSION_IDLE_TIMEOUT {
                            Some(entry.key().clone())
                        } else {
                            None
                        }
                    })
                    .collect();

                for user_id in to_evict {
                    // Remove from map first — new requests will re-create from DB
                    if let Some((_, session)) = sessions.remove(&user_id) {
                        // Acquire lock to ensure no in-flight credential request
                        let mut guard = session.client.lock().await;
                        if let Some(mut client) = guard.take() {
                            client.close().await;
                        }
                        session.credential_cache.clear();
                        info!(user_id = %user_id, "bitwarden: evicted idle session");
                    }
                }
            }
        });
    }

    /// Load an existing session from memory or DB. Returns `None` if the user
    /// has never paired (no VaultConnection row). Does NOT generate a new identity.
    async fn load_session(&self, user_id: &str) -> Result<Option<Arc<BitwardenUserSession>>> {
        if let Some(session) = self.sessions.get(user_id) {
            return Ok(Some(Arc::clone(session.value())));
        }

        // Load from DB — if no row, user has never paired
        let row = match db::find_vault_connection(&self.pool, user_id, "bitwarden").await? {
            Some(r) => r,
            None => return Ok(None),
        };

        let cd: Option<BitwardenConnectionData> = row
            .connection_data
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let key_data = cd.as_ref().and_then(|c| c.key_data.as_ref());
        let identity = match key_data {
            Some(kd) => BitwardenIdentityProvider::from_cose(kd)?,
            None => return Ok(None), // row exists but no key_data — incomplete pairing
        };

        let session = Arc::new(BitwardenUserSession {
            client: Mutex::new(None),
            identity,
            connection_data: cd,
            credential_cache: DashMap::new(),
            last_used: std::sync::Mutex::new(Instant::now()),
        });

        self.sessions
            .insert(user_id.to_string(), Arc::clone(&session));
        Ok(Some(session))
    }

    /// Create a new session with a fresh identity for pairing.
    fn create_pairing_session(&self, user_id: &str) -> Arc<BitwardenUserSession> {
        let session = Arc::new(BitwardenUserSession {
            client: Mutex::new(None),
            identity: BitwardenIdentityProvider::generate(),
            connection_data: None,
            credential_cache: DashMap::new(),
            last_used: std::sync::Mutex::new(Instant::now()),
        });

        self.sessions
            .insert(user_id.to_string(), Arc::clone(&session));
        session
    }

    /// Create a connected `RemoteClient` for a user session.
    /// Always passes the identity's key_data to the session store so write-throughs
    /// never null it out — even for fresh pairings where connection_data is None.
    async fn create_and_connect_client(
        &self,
        user_id: &str,
        session: &BitwardenUserSession,
    ) -> Result<RemoteClient> {
        let (event_tx, event_rx) = mpsc::channel(64);
        let (_response_tx, response_rx) = mpsc::channel(16);

        Self::spawn_event_loop(user_id.to_string(), event_rx);

        let proxy_config = ProxyClientConfig {
            proxy_url: self.config.proxy_url.clone(),
            identity_keypair: Some(session.identity.identity().clone()),
        };
        let proxy_client = DefaultProxyClient::new(proxy_config);

        let key_data = Some(session.identity.to_cose());
        let identity_provider = session.identity.clone_provider();
        let session_store = BitwardenSessionStore::new(
            self.pool.clone(),
            user_id.to_string(),
            key_data,
            session.connection_data.as_ref(),
        );

        let client = RemoteClient::new(
            Box::new(identity_provider),
            Box::new(session_store),
            event_tx,
            response_rx,
            Box::new(proxy_client),
        )
        .await
        .map_err(|e| anyhow!("failed to create remote client: {e}"))?;

        Ok(client)
    }

    fn spawn_event_loop(user_id: String, mut event_rx: mpsc::Receiver<RemoteClientEvent>) {
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                match &event {
                    RemoteClientEvent::Connecting { proxy_url } => {
                        info!(user_id = %user_id, url = %proxy_url, "bitwarden: connecting");
                    }
                    RemoteClientEvent::Connected { fingerprint } => {
                        info!(
                            user_id = %user_id,
                            fingerprint = %hex::encode(fingerprint.0),
                            "bitwarden: connected"
                        );
                    }
                    RemoteClientEvent::Ready {
                        can_request_credentials,
                    } => {
                        info!(
                            user_id = %user_id,
                            can_request = can_request_credentials,
                            "bitwarden: ready"
                        );
                    }
                    RemoteClientEvent::CredentialReceived { credential, .. } => {
                        info!(user_id = %user_id, credential = ?credential, "bitwarden: credential received");
                    }
                    RemoteClientEvent::Error { message, context } => {
                        warn!(
                            user_id = %user_id,
                            message = %message,
                            context = ?context,
                            "bitwarden: error"
                        );
                    }
                    RemoteClientEvent::Disconnected { reason } => {
                        warn!(user_id = %user_id, reason = ?reason, "bitwarden: disconnected");
                    }
                    _ => {
                        info!(user_id = %user_id, event = ?event, "bitwarden: event");
                    }
                }
            }
        });
    }
}

#[async_trait]
impl VaultProvider for BitwardenVaultProvider {
    fn provider_name(&self) -> &'static str {
        "bitwarden"
    }

    async fn pair(&self, user_id: &str, params: &serde_json::Value) -> Result<PairResult> {
        let psk_hex = params
            .get("psk_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("missing psk_hex in pair params"))?;
        let fingerprint_hex = params
            .get("fingerprint_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("missing fingerprint_hex in pair params"))?;

        let psk = Psk::from_hex(psk_hex).map_err(|e| anyhow!("invalid PSK: {e}"))?;

        let remote_fingerprint = parse_fingerprint(fingerprint_hex)
            .ok_or_else(|| anyhow!("invalid fingerprint: must be 32 hex-encoded bytes"))?;

        let session = match self.load_session(user_id).await? {
            Some(s) => s,
            None => self.create_pairing_session(user_id),
        };

        // Create the DB row BEFORE pairing so that save_transport_state's
        // UPDATE has a row to write to. key_data + fingerprint go in now;
        // transport_state will be added by save_transport_state during pair_with_psk.
        let initial_cd = BitwardenConnectionData {
            fingerprint: Some(fingerprint_hex.to_string()),
            key_data: Some(session.identity.to_cose()),
            transport_state: None,
        };
        db::upsert_vault_connection(
            &self.pool,
            user_id,
            "bitwarden",
            "paired",
            Some(&serde_json::to_value(&initial_cd)?),
        )
        .await?;

        let mut client = self.create_and_connect_client(user_id, &session).await?;

        client
            .pair_with_psk(psk, remote_fingerprint)
            .await
            .map_err(|e| anyhow!("PSK pairing failed: {e}"))?;

        info!(
            user_id = %user_id,
            fingerprint = %fingerprint_hex,
            "bitwarden: paired via PSK"
        );

        *session.client.lock().await = Some(client);

        Ok(PairResult { display_name: None })
    }

    async fn request_credential(&self, user_id: &str, hostname: &str) -> Option<VaultCredential> {
        // Load existing session — returns None if user never paired
        let session = match self.load_session(user_id).await {
            Ok(Some(s)) => s,
            _ => return None,
        };

        // Touch last_used for eviction tracking
        if let Ok(mut last_used) = session.last_used.lock() {
            *last_used = Instant::now();
        }

        // Check credential cache first — avoids expensive lazy restore if cached
        if let Some(cached) = session.credential_cache.get(hostname) {
            if cached.expires_at > Instant::now() {
                return cached.data.as_ref().map(|c| VaultCredential {
                    username: c.username.clone(),
                    password: c.password.clone(),
                });
            }
        }
        session.credential_cache.remove(hostname);

        // If client is not connected, try to restore the cached session
        {
            let mut client_guard = session.client.lock().await;
            if client_guard.is_none() {
                // Extract fingerprint from cached connectionData (no DB read)
                let fingerprint = session
                    .connection_data
                    .as_ref()
                    .and_then(|cd| cd.fingerprint.as_deref())
                    .and_then(parse_fingerprint);

                let fp = fingerprint?;

                match self.create_and_connect_client(user_id, &session).await {
                    Ok(mut client) => match client.load_cached_session(fp).await {
                        Ok(()) => {
                            info!(user_id = %user_id, "bitwarden: lazy session restored");
                            *client_guard = Some(client);
                        }
                        Err(e) => {
                            warn!(user_id = %user_id, error = %e, "bitwarden: lazy restore failed");
                            let _ = client.close().await;
                            return None;
                        }
                    },
                    Err(e) => {
                        warn!(user_id = %user_id, error = %e, "bitwarden: failed to create client for lazy restore");
                        return None;
                    }
                }
            }
        }

        let mut client_guard = session.client.lock().await;
        let client = client_guard.as_mut()?;

        if !client.is_ready() {
            return None;
        }

        let query = CredentialQuery::Domain(hostname.to_string());
        let result = tokio::time::timeout(REQUEST_TIMEOUT, client.request_credential(&query)).await;

        let cred = match result {
            Ok(Ok(cred)) => Some(cred),
            Ok(Err(e)) => {
                warn!(
                    user_id = %user_id,
                    hostname = %hostname,
                    error = %e,
                    "bitwarden: credential request failed"
                );
                None
            }
            Err(_) => {
                warn!(
                    user_id = %user_id,
                    hostname = %hostname,
                    "bitwarden: credential request timed out"
                );
                None
            }
        };

        let (data, ttl) = match &cred {
            Some(c) => (Some(c.clone()), CREDENTIAL_CACHE_TTL),
            None => (None, NEGATIVE_CACHE_TTL),
        };

        session.credential_cache.insert(
            hostname.to_string(),
            CachedCredential {
                data,
                expires_at: Instant::now() + ttl,
            },
        );

        cred.map(|c| VaultCredential {
            username: c.username,
            password: c.password,
        })
    }

    async fn status(&self, user_id: &str) -> ProviderStatus {
        let session = match self.load_session(user_id).await {
            Ok(Some(s)) => s,
            _ => {
                return ProviderStatus {
                    connected: false,
                    name: None,
                    status_data: None,
                }
            }
        };

        let guard = session.client.lock().await;
        let connected = guard.as_ref().is_some_and(|c| c.is_ready());
        let fingerprint = hex::encode(session.identity.fingerprint().0);

        ProviderStatus {
            connected,
            name: None,
            status_data: Some(serde_json::json!({ "fingerprint": fingerprint })),
        }
    }

    async fn disconnect(&self, user_id: &str) -> Result<()> {
        if let Some((_, session)) = self.sessions.remove(user_id) {
            let mut guard = session.client.lock().await;
            if let Some(mut client) = guard.take() {
                client.close().await;
            }
            session.credential_cache.clear();
        }

        info!(user_id = %user_id, "bitwarden: disconnected");
        Ok(())
    }

    // No restore_sessions — sessions are loaded lazily on first request_credential call.
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_fingerprint ──────────────────────────────────────────────

    #[test]
    fn parse_fingerprint_valid() {
        let hex = hex::encode([42u8; 32]);
        let fp = parse_fingerprint(&hex).expect("should parse valid 32-byte hex");
        assert_eq!(fp.0, [42u8; 32]);
    }

    #[test]
    fn parse_fingerprint_wrong_length() {
        let hex = hex::encode([1u8; 16]); // 16 bytes, not 32
        assert!(parse_fingerprint(&hex).is_none());
    }

    #[test]
    fn parse_fingerprint_invalid_hex() {
        assert!(parse_fingerprint("zzzz_not_hex").is_none());
    }

    #[test]
    fn parse_fingerprint_empty() {
        assert!(parse_fingerprint("").is_none());
    }

    // ── BitwardenConnectionData serde ──────────────────────────────────

    #[test]
    fn connection_data_round_trip() {
        let cd = BitwardenConnectionData {
            fingerprint: Some("abc123".to_string()),
            key_data: Some(vec![1, 2, 3, 4]),
            transport_state: Some(vec![5, 6, 7]),
        };

        let json = serde_json::to_value(&cd).expect("serialize");
        let deserialized: BitwardenConnectionData =
            serde_json::from_value(json).expect("deserialize");

        assert_eq!(deserialized.fingerprint, cd.fingerprint);
        assert_eq!(deserialized.key_data, cd.key_data);
        assert_eq!(deserialized.transport_state, cd.transport_state);
    }

    #[test]
    fn connection_data_null_fields() {
        let cd = BitwardenConnectionData::default();
        let json = serde_json::to_value(&cd).expect("serialize");
        let deserialized: BitwardenConnectionData =
            serde_json::from_value(json).expect("deserialize");

        assert!(deserialized.fingerprint.is_none());
        assert!(deserialized.key_data.is_none());
        assert!(deserialized.transport_state.is_none());
    }
}
