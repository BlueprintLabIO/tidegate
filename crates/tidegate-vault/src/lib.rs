//! Tidegate's vault: the only place secrets exist in plaintext, and only in
//! memory, only inside a closure.
//!
//! Invariants owned here (docs/invariants.md):
//! - INV-V1: no plaintext secret bytes are ever written to disk.
//! - INV-V2: decryption is private to this crate; callers get
//!   [`Vault::with_secret`]'s closure, never key material or an owned copy.
//! - INV-V3: plaintext buffers are zeroized on drop; no secret type in this
//!   crate implements `Display`/`Debug`-with-content.
//! - INV-V4: the master key lives in the OS keychain — the database file
//!   alone cannot be decrypted. (`TIDEGATE_MASTER_KEY_FILE` provides an
//!   explicit, documented degraded mode for headless CI.)

#![forbid(unsafe_code)]

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

const KEYRING_SERVICE: &str = "dev.tidegate.vault";
const KEYRING_ACCOUNT: &str = "master";
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("vault io: {0}")]
    Io(#[from] std::io::Error),
    #[error("vault db: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("keychain: {0}")]
    Keychain(String),
    #[error("no secret named {0:?}")]
    NotFound(String),
    #[error("decryption failed for {0:?} — wrong master key or corrupted envelope")]
    Decrypt(String),
    #[error("encryption failed")]
    Encrypt,
}

/// Where the master key came from. Surfaced so the CLI can tell the user
/// when they are running in the degraded (file-key) mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    OsKeychain,
    /// `TIDEGATE_MASTER_KEY_FILE` — explicit, for headless machines and CI.
    KeyFile,
}

pub struct Vault {
    /// Behind a Mutex so the vault is `Sync`: the daemon shares one Gateway
    /// (and thus one Vault) across request threads.
    conn: Mutex<Connection>,
    /// Master key. Zeroized on drop. Never leaves this struct.
    key: Zeroizing<Vec<u8>>,
    source: KeySource,
}

// Deliberately no Debug derive: a Debug impl that prints the struct is a
// leak vector. This impl proves INV-V3's spirit at the type level.
impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault").field("source", &self.source).finish_non_exhaustive()
    }
}

impl Vault {
    /// Open (creating if needed) the vault under `dir`. The directory is
    /// created 0700 and the database 0600 on unix.
    pub fn open(dir: &Path) -> Result<Self, VaultError> {
        std::fs::create_dir_all(dir)?;
        restrict_dir(dir)?;
        let db_path = dir.join("vault.db");
        let conn = Connection::open(&db_path)?;
        restrict_file(&db_path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS secrets (
                name TEXT PRIMARY KEY,
                envelope BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );",
        )?;
        let (key, source) = master_key()?;
        Ok(Vault { conn: Mutex::new(conn), key, source })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn key_source(&self) -> KeySource {
        self.source
    }

    /// Store (or replace) a secret. The plaintext argument is zeroized by
    /// the caller owning it; we never persist it.
    pub fn store(&self, name: &str, plaintext: &[u8]) -> Result<(), VaultError> {
        let envelope = self.seal(plaintext)?;
        let now = unix_now();
        self.conn().execute(
            "INSERT INTO secrets (name, envelope, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT(name) DO UPDATE SET envelope = ?2, updated_at = ?3",
            rusqlite::params![name, envelope, now],
        )?;
        Ok(())
    }

    /// Use a secret without ever handing out an owned copy: the plaintext
    /// exists for the closure's duration in a zeroizing buffer (INV-V2).
    pub fn with_secret<R>(
        &self,
        name: &str,
        f: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, VaultError> {
        let envelope: Vec<u8> = self
            .conn()
            .query_row("SELECT envelope FROM secrets WHERE name = ?1", [name], |r| r.get(0))
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => VaultError::NotFound(name.to_string()),
                other => VaultError::Db(other),
            })?;
        let plaintext = self.unseal(name, &envelope)?;
        Ok(f(&plaintext))
    }

    pub fn list(&self) -> Result<Vec<SecretMeta>, VaultError> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT name, created_at, updated_at FROM secrets ORDER BY name")?;
        let rows = stmt
            .query_map([], |r| {
                Ok(SecretMeta { name: r.get(0)?, created_at: r.get(1)?, updated_at: r.get(2)? })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn delete(&self, name: &str) -> Result<bool, VaultError> {
        let n = self.conn().execute("DELETE FROM secrets WHERE name = ?1", [name])?;
        Ok(n > 0)
    }

    pub fn contains(&self, name: &str) -> Result<bool, VaultError> {
        let n: i64 = self
            .conn()
            .query_row("SELECT COUNT(*) FROM secrets WHERE name = ?1", [name], |r| r.get(0))?;
        Ok(n > 0)
    }

    // ---- private: the only encrypt/decrypt in the codebase (INV-V2) ----

    fn cipher(&self) -> Result<Aes256Gcm, VaultError> {
        Aes256Gcm::new_from_slice(&self.key).map_err(|_| VaultError::Encrypt)
    }

    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ct = self
            .cipher()?
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| VaultError::Encrypt)?;
        let mut envelope = Vec::with_capacity(NONCE_LEN + ct.len());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ct);
        Ok(envelope)
    }

    fn unseal(&self, name: &str, envelope: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if envelope.len() < NONCE_LEN {
            return Err(VaultError::Decrypt(name.to_string()));
        }
        let (nonce, ct) = envelope.split_at(NONCE_LEN);
        let pt = self
            .cipher()?
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| VaultError::Decrypt(name.to_string()))?;
        Ok(Zeroizing::new(pt))
    }
}

#[derive(Debug, Clone)]
pub struct SecretMeta {
    pub name: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Fetch-or-create the master key. Keychain first; explicit key-file mode
/// only when `TIDEGATE_MASTER_KEY_FILE` is set (headless/CI — degraded and
/// documented, never a silent fallback).
fn master_key() -> Result<(Zeroizing<Vec<u8>>, KeySource), VaultError> {
    if let Ok(path) = std::env::var("TIDEGATE_MASTER_KEY_FILE") {
        return Ok((file_key(&PathBuf::from(path))?, KeySource::KeyFile));
    }
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
        .map_err(|e| VaultError::Keychain(e.to_string()))?;
    match entry.get_secret() {
        Ok(mut bytes) => {
            if bytes.len() != KEY_LEN {
                bytes.zeroize();
                return Err(VaultError::Keychain(
                    "master key in keychain has unexpected length".into(),
                ));
            }
            Ok((Zeroizing::new(bytes), KeySource::OsKeychain))
        }
        Err(keyring::Error::NoEntry) => {
            let mut key = vec![0u8; KEY_LEN];
            rand::thread_rng().fill_bytes(&mut key);
            entry.set_secret(&key).map_err(|e| VaultError::Keychain(e.to_string()))?;
            Ok((Zeroizing::new(key), KeySource::OsKeychain))
        }
        Err(e) => Err(VaultError::Keychain(e.to_string())),
    }
}

fn file_key(path: &Path) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        if bytes.len() != KEY_LEN {
            return Err(VaultError::Keychain(format!(
                "key file {} must be exactly {KEY_LEN} raw bytes",
                path.display()
            )));
        }
        Ok(Zeroizing::new(bytes))
    } else {
        let mut key = vec![0u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut key);
        std::fs::write(path, &key)?;
        restrict_file(path)?;
        Ok(Zeroizing::new(key))
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(unix)]
fn restrict_dir(p: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
}

#[cfg(unix)]
fn restrict_file(p: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict_dir(_p: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file(_p: &Path) -> std::io::Result<()> {
    Ok(())
}
