use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::fs;
use zeroize::Zeroize;

use crate::crypto::{self, WrappedKey, AEAD_NONCE_LEN, FILE_KEY_LEN, MASTER_KEY_LEN, SALT_LEN};
use crate::model::{DefaultsConfig, VaultAccountEntry, VaultData, VaultFileEntry};
use crate::util::write_atomic;

#[derive(Debug)]
pub struct Vault {
    path: PathBuf,
    pub data: VaultData,
    master_key: [u8; MASTER_KEY_LEN],
    salt: [u8; SALT_LEN],
}

#[derive(Serialize, Deserialize)]
struct VaultContainer {
    salt: String,
    nonce: String,
    ciphertext: String,
}

impl Vault {
    /// Creates a new encrypted vault file with the provided defaults.
    ///
    /// # Errors
    /// Returns an error if the vault cannot be written to disk or the key derivation fails.
    pub async fn create(path: &Path, password: &str, defaults: DefaultsConfig) -> Result<Self> {
        let salt = crypto::random_salt();
        let master_key = crypto::derive_master_key(password.as_bytes(), &salt)?;
        let data = VaultData::new(defaults);
        let mut vault = Self {
            path: path.to_path_buf(),
            data,
            master_key,
            salt,
        };
        vault.save().await?;
        Ok(vault)
    }

    /// Opens an existing vault, decrypting it with the supplied password.
    ///
    /// # Errors
    /// Returns an error if the vault file is unreadable or the password is incorrect.
    pub async fn load(path: &Path, password: &str) -> Result<Self> {
        let bytes = fs::read(path)
            .await
            .with_context(|| format!("reading vault {}", path.display()))?;
        let container: VaultContainer = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing vault container {}", path.display()))?;

        let salt_vec = BASE64
            .decode(container.salt)
            .context("decoding vault salt")?;
        anyhow::ensure!(salt_vec.len() == SALT_LEN, "invalid vault salt length");
        let mut salt = [0_u8; SALT_LEN];
        salt.copy_from_slice(&salt_vec);
        let master_key = crypto::derive_master_key(password.as_bytes(), &salt)?;

        let nonce_vec = BASE64
            .decode(container.nonce)
            .context("decoding vault nonce")?;
        anyhow::ensure!(
            nonce_vec.len() == AEAD_NONCE_LEN,
            "invalid vault nonce length"
        );
        let mut nonce = [0_u8; AEAD_NONCE_LEN];
        nonce.copy_from_slice(&nonce_vec);
        let ciphertext = BASE64
            .decode(container.ciphertext)
            .context("decoding vault ciphertext")?;
        let plaintext = crypto::decrypt(&master_key, &nonce, &ciphertext)?;
        let data: VaultData = serde_json::from_slice(&plaintext).context("parsing vault data")?;

        Ok(Self {
            path: path.to_path_buf(),
            data,
            master_key,
            salt,
        })
    }

    /// Persists the current vault state to disk.
    ///
    /// # Errors
    /// Returns an error if the encrypted payload cannot be written to the vault file.
    pub async fn save(&mut self) -> Result<()> {
        let plaintext = serde_json::to_vec_pretty(&self.data)?;
        let nonce = crypto::random_nonce();
        let ciphertext = crypto::encrypt(&self.master_key, &nonce, &plaintext)?;
        let container = VaultContainer {
            salt: BASE64.encode(self.salt),
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
        };
        let data = serde_json::to_vec_pretty(&container)?;
        write_atomic(&self.path, &data).await
    }

    #[must_use]
    pub fn defaults(&self) -> DefaultsConfig {
        DefaultsConfig {
            k: self.data.default_k,
            m: self.data.default_m,
            cache_gb: self.data.cache_gb,
        }
    }

    /// Updates the configured cache size for this vault.
    ///
    /// # Errors
    /// Returns an error if the vault cannot be saved after updating the setting.
    pub async fn update_cache(&mut self, cache_gb: u32) -> Result<()> {
        self.data.cache_gb = cache_gb;
        self.save().await
    }

    /// Applies new Reed–Solomon defaults to the vault.
    ///
    /// # Errors
    /// Returns an error if saving the vault fails.
    pub async fn update_defaults(&mut self, defaults: DefaultsConfig) -> Result<()> {
        self.data.default_k = defaults.k;
        self.data.default_m = defaults.m;
        self.data.cache_gb = defaults.cache_gb;
        self.save().await
    }

    /// Wraps a file key using the unlocked vault master key.
    ///
    /// # Errors
    /// Returns an error if encryption fails while wrapping the key.
    pub fn wrap_file_key(
        &self,
        file_id: &str,
        key: &[u8; FILE_KEY_LEN],
    ) -> Result<WrappedKey, crypto::CryptoError> {
        crypto::wrap_file_key(&self.master_key, file_id, key)
    }

    /// Unwraps and decrypts a file key stored in the vault.
    ///
    /// # Errors
    /// Returns an error if decryption fails or the stored data is malformed.
    pub fn unwrap_file_key(
        &self,
        file_id: &str,
        entry: &VaultFileEntry,
    ) -> Result<[u8; FILE_KEY_LEN], crypto::CryptoError> {
        let wrapped = WrappedKey::from_base64(&entry.wrap_nonce, &entry.wrapped_key)?;
        crypto::unwrap_file_key(&self.master_key, file_id, &wrapped)
    }

    /// Stores or updates a wrapped file key for the provided entry.
    ///
    /// # Errors
    /// Returns an error if the vault cannot be saved.
    pub async fn store_entry(
        &mut self,
        mut entry: VaultFileEntry,
        wrapped: WrappedKey,
    ) -> Result<()> {
        let (nonce_b64, cipher_b64) = wrapped.to_base64();
        entry.wrap_nonce = nonce_b64;
        entry.wrapped_key = cipher_b64;
        self.data.upsert(entry);
        self.save().await
    }

    /// Deletes a file entry from the vault.
    ///
    /// # Errors
    /// Returns an error if the vault cannot be saved after removal.
    pub async fn remove_entry(&mut self, file_id: &str) -> Result<()> {
        self.data.remove(file_id);
        self.save().await
    }

    pub fn account(&self, account_id: i64) -> Option<&VaultAccountEntry> {
        self.data.find_account(account_id)
    }

    pub fn accounts(&self) -> &[VaultAccountEntry] {
        &self.data.accounts
    }

    pub async fn upsert_account(&mut self, entry: VaultAccountEntry) -> Result<()> {
        self.data.upsert_account(entry);
        self.save().await
    }

    pub async fn remove_account(&mut self, account_id: i64) -> Result<()> {
        self.data.remove_account(account_id);
        self.save().await
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.master_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn defaults() -> DefaultsConfig {
        DefaultsConfig {
            k: 4,
            m: 2,
            cache_gb: 8,
        }
    }

    #[tokio::test]
    async fn create_and_load_vault() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.bin");
        let vault = Vault::create(&path, "secret", defaults()).await.unwrap();
        assert_eq!(vault.defaults().k, 4);

        let loaded = Vault::load(&path, "secret").await.unwrap();
        assert_eq!(loaded.defaults().cache_gb, 8);
    }

    #[tokio::test]
    async fn reject_wrong_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.bin");
        let _ = Vault::create(&path, "secret", defaults()).await.unwrap();
        let err = Vault::load(&path, "wrong").await.unwrap_err();
        assert!(format!("{err}").contains("decrypt"));
    }

    #[tokio::test]
    async fn account_entries_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.bin");
        let mut vault = Vault::create(&path, "secret", defaults()).await.unwrap();
        let entry = VaultAccountEntry {
            account_id: 1,
            name: "primary".into(),
            backend: "httpbucket".into(),
            endpoint: "https://example".into(),
            token: "secret-token".into(),
            token_ref: "vault:token".into(),
        };
        vault.upsert_account(entry.clone()).await.unwrap();

        let reloaded = Vault::load(&path, "secret").await.unwrap();
        let stored = reloaded.account(1).unwrap();
        assert_eq!(stored.name, entry.name);
        assert_eq!(stored.token_ref, entry.token_ref);
    }
}
