//! INV-V1 (encrypted at rest) and INV-V4 (db alone is insufficient),
//! exercised in key-file mode so tests run headless without touching the
//! developer's real keychain.

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};
use tidegate_vault::{KeySource, Vault, VaultError};

/// `TIDEGATE_MASTER_KEY_FILE` is process-global; tests touching it must not
/// interleave. Every test takes this lock first.
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct KeyFileGuard(PathBuf);
impl Drop for KeyFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        std::env::remove_var("TIDEGATE_MASTER_KEY_FILE");
    }
}

fn with_key_file(dir: &std::path::Path) -> KeyFileGuard {
    let key_path = dir.join("master.key");
    std::env::set_var("TIDEGATE_MASTER_KEY_FILE", &key_path);
    KeyFileGuard(key_path)
}

#[test]
fn roundtrip_and_ciphertext_at_rest() {
    let _env = env_lock();
    let dir = tempfile::tempdir().unwrap();
    let _guard = with_key_file(dir.path());
    let vault = Vault::open(dir.path()).unwrap();
    assert_eq!(vault.key_source(), KeySource::KeyFile);

    let secret = b"ghp_notarealtoken_but_findable_1234567890";
    vault.store("github", secret).unwrap();

    // Round trip.
    let got = vault.with_secret("github", <[u8]>::to_vec).unwrap();
    assert_eq!(got, secret);

    // INV-V1: the raw database bytes must not contain the plaintext.
    drop(vault);
    let raw = std::fs::read(dir.path().join("vault.db")).unwrap();
    assert!(
        !raw.windows(secret.len()).any(|w| w == secret),
        "plaintext secret found in vault.db"
    );
}

#[test]
fn wrong_key_cannot_decrypt() {
    let _env = env_lock();
    let dir = tempfile::tempdir().unwrap();
    {
        let _guard = with_key_file(dir.path());
        let vault = Vault::open(dir.path()).unwrap();
        vault.store("github", b"sekrit").unwrap();
        // guard drop removes the key file and env var
    }
    // Reopen with a fresh key: the envelope must refuse, not garble.
    let other_key = dir.path().join("other.key");
    std::env::set_var("TIDEGATE_MASTER_KEY_FILE", &other_key);
    let vault = Vault::open(dir.path()).unwrap();
    let err = vault.with_secret("github", <[u8]>::to_vec).unwrap_err();
    std::env::remove_var("TIDEGATE_MASTER_KEY_FILE");
    assert!(matches!(err, VaultError::Decrypt(_)), "expected Decrypt, got {err:?}");
}

#[test]
fn missing_secret_is_not_found() {
    let _env = env_lock();
    let dir = tempfile::tempdir().unwrap();
    let _guard = with_key_file(dir.path());
    let vault = Vault::open(dir.path()).unwrap();
    assert!(matches!(vault.with_secret("nope", |_| ()), Err(VaultError::NotFound(_))));
    assert!(!vault.contains("nope").unwrap());
}

#[test]
fn list_delete() {
    let _env = env_lock();
    let dir = tempfile::tempdir().unwrap();
    let _guard = with_key_file(dir.path());
    let vault = Vault::open(dir.path()).unwrap();
    vault.store("a", b"1").unwrap();
    vault.store("b", b"2").unwrap();
    assert_eq!(vault.list().unwrap().len(), 2);
    assert!(vault.delete("a").unwrap());
    assert!(!vault.delete("a").unwrap());
    assert_eq!(vault.list().unwrap().len(), 1);
}
