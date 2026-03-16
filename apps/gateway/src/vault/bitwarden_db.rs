//! DB-backed `IdentityProvider` and `SessionStore` for the Bitwarden vault provider.
//!
//! Instead of files, identity keypair and session/transport state are stored in
//! the `VaultConnection.connectionData` JSON column (scoped to `provider = "bitwarden"`).
//!
//! The `SessionStore` trait methods are synchronous (`fn`, not `async fn`).
//! We use an in-memory cache with write-through: sessions are loaded into memory
//! on construction, mutations update both memory and DB via `tokio::task::block_in_place`
//! (requires multi-threaded tokio runtime, which the gateway uses).

use ap_client::{IdentityFingerprint, IdentityProvider, RemoteClientError, SessionStore};
use ap_noise::MultiDeviceTransport;
use ap_proxy_protocol::IdentityKeyPair;
use sqlx::PgPool;
use tracing::warn;

use super::bitwarden::{parse_fingerprint, BitwardenConnectionData};
use crate::db;

// ── BitwardenIdentityProvider ───────────────────────────────────────────

/// DB-backed identity provider. Keypair is extracted from `connectionData.key_data`
/// on construction, or generated fresh for new pairings.
pub(crate) struct BitwardenIdentityProvider {
    keypair: IdentityKeyPair,
}

impl BitwardenIdentityProvider {
    /// Create from an existing COSE-encoded keypair (loaded from DB).
    pub fn from_cose(cose_bytes: &[u8]) -> Result<Self, anyhow::Error> {
        let keypair = IdentityKeyPair::from_cose(cose_bytes)
            .map_err(|e| anyhow::anyhow!("failed to decode identity keypair: {e}"))?;
        Ok(Self { keypair })
    }

    /// Generate a new identity keypair.
    pub fn generate() -> Self {
        Self {
            keypair: IdentityKeyPair::generate(),
        }
    }

    /// Serialize the keypair to COSE bytes for storage.
    pub fn to_cose(&self) -> Vec<u8> {
        self.keypair.to_cose()
    }

    /// Clone the keypair into a new provider (for giving ownership to RemoteClient).
    pub fn clone_provider(&self) -> Self {
        Self {
            keypair: self.keypair.clone(),
        }
    }
}

impl IdentityProvider for BitwardenIdentityProvider {
    fn identity(&self) -> &IdentityKeyPair {
        &self.keypair
    }
}

// ── BitwardenSessionStore ───────────────────────────────────────────────

/// DB-backed session store, scoped to a single `user_id` with `provider = "bitwarden"`.
///
/// Sessions are cached in memory. Writes go through to the DB using
/// `tokio::task::block_in_place` to bridge sync trait → async DB calls.
pub(crate) struct BitwardenSessionStore {
    pool: PgPool,
    user_id: String,
    /// COSE-encoded keypair — kept here so write-throughs don't null out key_data in DB.
    key_data: Option<Vec<u8>>,
    /// In-memory session state (at most one session per user for Bitwarden).
    session: Option<SessionEntry>,
}

#[derive(Debug, Clone)]
struct SessionEntry {
    fingerprint: IdentityFingerprint,
    name: Option<String>,
    created_at: u64,
    last_connected_at: u64,
    transport_state: Option<Vec<u8>>,
}

impl BitwardenSessionStore {
    /// Create a new store, loading existing session from DB if present.
    pub fn new(
        pool: PgPool,
        user_id: String,
        key_data: Option<Vec<u8>>,
        connection_data: Option<&BitwardenConnectionData>,
    ) -> Self {
        let session = connection_data.and_then(|cd| {
            let fingerprint = parse_fingerprint(cd.fingerprint.as_deref()?)?;

            Some(SessionEntry {
                fingerprint,
                name: None,
                created_at: now_timestamp(),
                last_connected_at: now_timestamp(),
                transport_state: cd.transport_state.clone(),
            })
        });

        Self {
            pool,
            user_id,
            key_data,
            session,
        }
    }

    /// Persist the current connection data to DB (sync bridge).
    fn write_through(&self, cd: &BitwardenConnectionData) {
        let pool = self.pool.clone();
        let user_id = self.user_id.clone();
        let json = match serde_json::to_value(cd) {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "failed to serialize BitwardenConnectionData");
                return;
            }
        };

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                if let Err(e) =
                    db::update_vault_connection_data(&pool, &user_id, "bitwarden", &json).await
                {
                    warn!(error = %e, "failed to write-through vault connection data");
                }
            });
        });
    }

    /// Build current `BitwardenConnectionData` from in-memory state.
    fn current_connection_data(&self) -> BitwardenConnectionData {
        match &self.session {
            Some(s) => BitwardenConnectionData {
                fingerprint: Some(hex::encode(s.fingerprint.0)),
                key_data: self.key_data.clone(),
                transport_state: s.transport_state.clone(),
            },
            None => BitwardenConnectionData {
                fingerprint: None,
                key_data: self.key_data.clone(),
                transport_state: None,
            },
        }
    }
}

impl SessionStore for BitwardenSessionStore {
    fn has_session(&self, fingerprint: &IdentityFingerprint) -> bool {
        self.session
            .as_ref()
            .is_some_and(|s| s.fingerprint == *fingerprint)
    }

    fn list_sessions(&self) -> Vec<(IdentityFingerprint, Option<String>, u64, u64)> {
        self.session
            .iter()
            .map(|s| {
                (
                    s.fingerprint,
                    s.name.clone(),
                    s.created_at,
                    s.last_connected_at,
                )
            })
            .collect()
    }

    fn cache_session(&mut self, fingerprint: IdentityFingerprint) -> Result<(), RemoteClientError> {
        if self.has_session(&fingerprint) {
            return Ok(());
        }

        self.session = Some(SessionEntry {
            fingerprint,
            name: None,
            created_at: now_timestamp(),
            last_connected_at: now_timestamp(),
            transport_state: None,
        });

        // Write-through without key_data (we don't own it here).
        // The full connectionData (including key_data) is written by the provider after pairing.
        Ok(())
    }

    fn remove_session(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), RemoteClientError> {
        if self
            .session
            .as_ref()
            .is_some_and(|s| s.fingerprint == *fingerprint)
        {
            self.session = None;
        }
        Ok(())
    }

    fn clear(&mut self) -> Result<(), RemoteClientError> {
        self.session = None;
        Ok(())
    }

    fn set_session_name(
        &mut self,
        fingerprint: &IdentityFingerprint,
        name: String,
    ) -> Result<(), RemoteClientError> {
        if let Some(ref mut s) = self.session {
            if s.fingerprint == *fingerprint {
                s.name = Some(name);
            }
        }
        Ok(())
    }

    fn update_last_connected(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), RemoteClientError> {
        if let Some(ref mut s) = self.session {
            if s.fingerprint == *fingerprint {
                s.last_connected_at = now_timestamp();
            }
        }
        Ok(())
    }

    fn save_transport_state(
        &mut self,
        fingerprint: &IdentityFingerprint,
        transport: MultiDeviceTransport,
    ) -> Result<(), RemoteClientError> {
        if let Some(ref mut s) = self.session {
            if s.fingerprint == *fingerprint {
                let bytes = transport.save_state().map_err(|e| {
                    RemoteClientError::SessionCache(format!("failed to serialize transport: {e}"))
                })?;
                s.transport_state = Some(bytes);

                // Write-through to DB (includes key_data so we don't null it out)
                let cd = self.current_connection_data();
                self.write_through(&cd);
            }
        }
        Ok(())
    }

    fn load_transport_state(
        &self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<Option<MultiDeviceTransport>, RemoteClientError> {
        let Some(ref s) = self.session else {
            return Ok(None);
        };
        if s.fingerprint != *fingerprint {
            return Ok(None);
        }
        let Some(ref bytes) = s.transport_state else {
            return Ok(None);
        };

        let transport = MultiDeviceTransport::restore_state(bytes).map_err(|e| {
            RemoteClientError::SessionCache(format!("failed to restore transport: {e}"))
        })?;

        Ok(Some(transport))
    }
}

fn now_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
