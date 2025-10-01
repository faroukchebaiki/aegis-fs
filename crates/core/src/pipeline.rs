use std::collections::HashMap;
use std::io::Cursor;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::{self, AEAD_NONCE_LEN};
use crate::db::Database;
use crate::erasure::Erasure;
use crate::journal::Journal;
use crate::model::{
    AccountRecord, Credential, DefaultsConfig, FileDetails, FileMeta, FileRecord, JournalStage,
    RemoteRef, RemoteShardRecord, VaultAccountEntry, VaultFileEntry,
};
use crate::storage::httpbucket::{self, HttpBucketStorage};
use crate::storage::Storage;
use crate::store::FileStore;
use crate::util::{utc_now, HomePaths};
use crate::vault::Vault;

#[derive(Clone, Debug)]
pub struct PackOptions {
    pub source: PathBuf,
    pub file_id: String,
    pub name: Option<String>,
    pub k: Option<u8>,
    pub m: Option<u8>,
    pub compress: bool,
}

#[derive(Clone, Debug)]
pub struct UnpackOptions {
    pub file_id: String,
    pub destination: PathBuf,
    pub overwrite: bool,
    pub from_remote: bool,
    pub account: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AccountListing {
    pub record: AccountRecord,
    pub has_token: bool,
}

struct ResolvedAccount {
    record: AccountRecord,
    credential: Credential,
}

pub struct AegisFs {
    paths: HomePaths,
    db: Database,
}

impl AegisFs {
    /// Initialises the workspace by creating directories, database, and vault.
    ///
    /// # Errors
    /// Returns an error if filesystem or database setup fails, or if the vault already exists.
    pub async fn init(paths: HomePaths, password: &str, defaults: DefaultsConfig) -> Result<Self> {
        defaults.validate()?;
        paths.ensure().await?;
        if paths.vault_path.exists() {
            anyhow::bail!(
                "vault already initialised at {}",
                paths.vault_path.display()
            );
        }
        let db = Database::connect(&paths.state_db_path).await?;
        let _vault = Vault::create(&paths.vault_path, password, defaults).await?;
        db.set_setting("cache_gb", &defaults.cache_gb.to_string())
            .await?;
        Ok(Self { paths, db })
    }

    /// Connects to an existing workspace, ensuring directories and schema exist.
    ///
    /// # Errors
    /// Returns an error if required directories or the `SQLite` database cannot be prepared.
    pub async fn load(paths: HomePaths) -> Result<Self> {
        paths.ensure().await?;
        let db = Database::connect(&paths.state_db_path).await?;
        Ok(Self { paths, db })
    }

    /// Opens the vault using the supplied password.
    ///
    /// # Errors
    /// Returns an error if the vault is missing or the password is invalid.
    async fn unlock_vault(&self, password: &str) -> Result<Vault> {
        anyhow::ensure!(
            self.paths.vault_path.exists(),
            "vault not initialised: {}",
            self.paths.vault_path.display()
        );
        Vault::load(&self.paths.vault_path, password).await
    }

    /// Updates the configured cache capacity, persisting the change to the vault and database.
    ///
    /// # Errors
    /// Returns an error if unlocking the vault fails or database persistence fails.
    pub async fn set_cache(&self, password: &str, cache_gb: u32) -> Result<()> {
        let mut vault = self.unlock_vault(password).await?;
        vault.update_cache(cache_gb).await?;
        self.db
            .set_setting("cache_gb", &cache_gb.to_string())
            .await?;
        Ok(())
    }

    /// Adds a remote storage account backed by the encrypted vault.
    ///
    /// # Errors
    /// Returns an error if validation fails, the vault cannot be unlocked, or persistence fails.
    pub async fn add_account(
        &self,
        password: &str,
        name: &str,
        backend: &str,
        endpoint: &str,
        token: &str,
    ) -> Result<i64> {
        anyhow::ensure!(!name.trim().is_empty(), "account name cannot be empty");
        Self::validate_backend(backend)?;

        let mut vault = self.unlock_vault(password).await?;
        let token_ref = format!("vault:{}", Uuid::new_v4());
        let account_id = self
            .db
            .create_account(name, backend, endpoint, &token_ref)
            .await?;

        let entry = VaultAccountEntry {
            account_id,
            name: name.to_string(),
            backend: backend.to_string(),
            endpoint: endpoint.to_string(),
            token: token.to_string(),
            token_ref,
        };
        vault.upsert_account(entry).await?;
        Ok(account_id)
    }

    /// Lists configured accounts, indicating whether the vault has a stored credential.
    ///
    /// # Errors
    /// Returns an error if unlocking the vault or querying the database fails.
    pub async fn list_accounts(&self, password: &str) -> Result<Vec<AccountListing>> {
        let vault = self.unlock_vault(password).await?;
        let accounts = self.db.list_accounts().await?;
        let listings = accounts
            .into_iter()
            .map(|record| AccountListing {
                has_token: vault.account(record.id).is_some(),
                record,
            })
            .collect();
        Ok(listings)
    }

    /// Retrieves all tracked file records ordered by creation time.
    ///
    /// # Errors
    /// Returns an error if querying the database fails.
    pub async fn list(&self) -> Result<Vec<FileRecord>> {
        self.db.list_files().await
    }

    /// Fetches detailed information for a specific file identifier.
    ///
    /// # Errors
    /// Returns an error if the database query fails or the record is missing.
    pub async fn show(&self, file_id: &str) -> Result<FileDetails> {
        self.db.get_file(file_id).await?.context("file not found")
    }

    /// Packs and encrypts a source file into shards, updating the vault and database.
    ///
    /// # Errors
    /// Returns an error if unlocking the vault fails, IO fails, or persistence fails.
    pub async fn pack(&self, password: &str, options: PackOptions) -> Result<()> {
        anyhow::ensure!(!options.file_id.is_empty(), "file id cannot be empty");
        let mut vault = self.unlock_vault(password).await?;
        let defaults = vault.defaults();
        let config = DefaultsConfig {
            k: options.k.unwrap_or(defaults.k),
            m: options.m.unwrap_or(defaults.m),
            cache_gb: defaults.cache_gb,
        };
        config.validate()?;
        let k = config.k;
        let m = config.m;

        let coder = Erasure::new(k, m)?;
        let store = FileStore::new(self.paths.objects_dir.clone());
        store.ensure_dir(&options.file_id).await?;

        let journal_path = store.journal_path(&options.file_id);
        let mut journal = Journal::load(&journal_path).await?;
        if journal.current_stage() == JournalStage::Completed {
            anyhow::bail!("file {} already packed", options.file_id);
        }
        journal.record(JournalStage::Start).await?;

        info!(file_id = %options.file_id, "packing start");
        let plaintext = fs::read(&options.source)
            .await
            .with_context(|| format!("reading source file {}", options.source.display()))?;
        let plain_len = plaintext.len() as u64;

        let mut payload = plaintext;
        let mut compressed_len = payload.len() as u64;
        let compressed_flag = if options.compress {
            let compressed = zstd::stream::encode_all(Cursor::new(&payload), 0)
                .context("compressing payload")?;
            compressed_len = compressed.len() as u64;
            payload = compressed;
            true
        } else {
            false
        };

        let mut file_key = crypto::random_key();
        let nonce = crypto::random_nonce();
        let ciphertext = crypto::encrypt(&file_key, &nonce, &payload)?;
        let cipher_len = ciphertext.len() as u64;
        journal.record(JournalStage::Encrypted).await?;

        let (shards, shard_len) = coder.encode(&ciphertext)?;
        let shard_infos = store.write_shards(&options.file_id, &shards).await?;
        journal.record(JournalStage::Sharded).await?;

        let meta = FileMeta {
            file_id: options.file_id.clone(),
            name: options.name.clone(),
            plaintext_size: plain_len,
            compressed_size: compressed_len,
            ciphertext_size: cipher_len,
            shard_size: shard_len,
            k,
            m,
            compressed: compressed_flag,
            nonce: BASE64.encode(nonce),
            checksums: shard_infos,
        };
        store.write_meta(&options.file_id, &meta).await?;
        journal.record(JournalStage::Stored).await?;

        let created_at = utc_now();
        self.db.insert_file(&meta, created_at).await?;

        let vault_entry = VaultFileEntry {
            file_id: options.file_id.clone(),
            name: options.name.clone(),
            created_at,
            k,
            m,
            compressed: compressed_flag,
            wrap_nonce: String::new(),
            wrapped_key: String::new(),
        };
        let wrapped_key = vault
            .wrap_file_key(&options.file_id, &file_key)
            .context("wrapping file key")?;
        vault.store_entry(vault_entry, wrapped_key).await?;
        journal.record(JournalStage::Indexed).await?;

        journal.record(JournalStage::Completed).await?;

        file_key.zeroize();
        info!(file_id = %options.file_id, "pack completed");
        Ok(())
    }

    /// Uploads shards for a file to a remote backend.
    ///
    /// # Errors
    /// Returns an error if unlocking the vault fails, local shards are missing, or remote persistence fails.
    pub async fn upload_shards(
        &self,
        password: &str,
        file_id: &str,
        account_name: Option<&str>,
    ) -> Result<()> {
        let vault = self.unlock_vault(password).await?;
        let resolved = self
            .resolve_account(&vault, account_name)
            .await
            .context("resolving account")?;

        let storage = Self::instantiate_storage(&resolved.record.backend)?;
        let session = storage.login(&resolved.credential).await?;

        let store = FileStore::new(self.paths.objects_dir.clone());
        store.ensure_dir(file_id).await?;
        let meta = store.read_meta(file_id).await?;
        for shard in &meta.checksums {
            let shard_path = store.shard_path(file_id, shard.index as usize);
            if !shard_path.exists() {
                anyhow::bail!(
                    "local shard {} missing; run pack before upload",
                    shard.index
                );
            }
            let hint = format!("{}/shard_{:03}.bin", file_id, shard.index);
            info!(
                file_id = %file_id,
                index = shard.index,
                "uploading shard to account {}",
                resolved.record.name
            );
            let remote_ref = storage
                .upload(&session, &shard_path, Some(&hint))
                .await
                .with_context(|| format!("uploading shard {}", shard.index))?;
            let object_meta = storage
                .stat(&session, &remote_ref)
                .await
                .with_context(|| format!("stat remote shard {}", shard.index))?;

            info!(
                file_id = %file_id,
                index = shard.index,
                remote_size = object_meta.size,
                "remote shard uploaded (checksum {}...)",
                &shard.checksum[..shard.checksum.len().min(12)]
            );

            let record = RemoteShardRecord {
                file_id: file_id.to_string(),
                index: shard.index,
                account_id: resolved.record.id,
                remote_ref: remote_ref.locator.clone(),
                size: object_meta.size,
                etag: object_meta.etag.clone(),
            };
            self.db.upsert_remote_shard(&record).await?;
        }
        Ok(())
    }

    /// Restores a file from shards, repairing missing shards when parity is available.
    ///
    /// # Errors
    /// Returns an error if the vault cannot be unlocked, integrity checks fail, or IO fails.
    pub async fn unpack(&self, password: &str, options: UnpackOptions) -> Result<PathBuf> {
        let vault = self.unlock_vault(password).await?;
        let store = FileStore::new(self.paths.objects_dir.clone());
        let meta = store.read_meta(&options.file_id).await?;

        if options.from_remote {
            self.ensure_remote_shards(&vault, &meta, options.account.as_deref())
                .await?;
        }

        let entry = vault
            .data
            .find(&options.file_id)
            .cloned()
            .context("file key missing from vault")?;
        let file_key = vault
            .unwrap_file_key(&options.file_id, &entry)
            .context("unwrapping per-file key")?;

        let total_shards = (meta.k + meta.m) as usize;
        let mut shards = store.read_shards(&options.file_id, total_shards).await?;
        let mut healthy = 0_usize;
        for (idx, shard_opt) in shards.iter_mut().enumerate() {
            if let Some(ref shard) = shard_opt {
                let checksum = crypto::blake3_checksum_hex(shard);
                if checksum == meta.checksums[idx].checksum {
                    healthy += 1;
                } else {
                    warn!(index = idx, "detected checksum mismatch; dropping shard");
                    *shard_opt = None;
                }
            }
        }
        anyhow::ensure!(
            healthy >= meta.k as usize,
            "insufficient healthy shards (have {}, need {})",
            healthy,
            meta.k
        );

        let coder = Erasure::new(meta.k, meta.m)?;
        let cipher_len = usize::try_from(meta.ciphertext_size)
            .context("ciphertext size exceeds platform capacity")?;
        let ciphertext = coder.reconstruct(shards, cipher_len)?;

        let nonce_bytes = BASE64
            .decode(&meta.nonce)
            .context("decoding nonce from meta")?;
        anyhow::ensure!(nonce_bytes.len() == AEAD_NONCE_LEN, "nonce length mismatch");
        let mut nonce = [0_u8; AEAD_NONCE_LEN];
        nonce.copy_from_slice(&nonce_bytes);
        let decrypted = crypto::decrypt(&file_key, &nonce, &ciphertext)?;

        let payload = if meta.compressed {
            zstd::stream::decode_all(Cursor::new(decrypted)).context("decompressing payload")?
        } else {
            decrypted
        };

        let destination = options.destination.clone();
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("preparing destination directory {}", parent.display()))?;
        }
        if destination.exists() && !options.overwrite {
            anyhow::bail!("destination {} exists", destination.display());
        }
        let mut file = fs::File::create(&destination)
            .await
            .with_context(|| format!("creating destination file {}", destination.display()))?;
        file.write_all(&payload).await?;
        file.flush().await?;
        info!(file_id = %options.file_id, path = %destination.display(), "unpack completed");
        Ok(destination)
    }

    /// Removes a file's shards, database metadata, and vault key entry.
    ///
    /// # Errors
    /// Returns an error if the vault cannot be unlocked or persistence operations fail.
    pub async fn remove(&self, password: &str, file_id: &str) -> Result<()> {
        let mut vault = self.unlock_vault(password).await?;
        let store = FileStore::new(self.paths.objects_dir.clone());
        store.remove_file(file_id).await?;
        vault.remove_entry(file_id).await?;
        self.db.remove_file(file_id).await?;
        Ok(())
    }

    /// Removes remote shards for a file across matching accounts.
    ///
    /// # Errors
    /// Returns an error if unlocking the vault fails or remote deletion/database updates fail.
    pub async fn gc_remote(
        &self,
        password: &str,
        file_id: &str,
        account_name: Option<&str>,
    ) -> Result<()> {
        let vault = self.unlock_vault(password).await?;
        let mut remote_records = self.db.list_remote_shards(file_id).await?;
        if remote_records.is_empty() {
            anyhow::bail!("no remote shards recorded for {file_id}");
        }

        if let Some(name) = account_name {
            let account = self
                .db
                .get_account_by_name(name)
                .await?
                .ok_or_else(|| anyhow!("account '{name}' not found"))?;
            remote_records.retain(|record| record.account_id == account.id);
            if remote_records.is_empty() {
                anyhow::bail!("no remote shards for {file_id} stored on account '{name}'");
            }
        }

        let mut by_account: HashMap<i64, Vec<RemoteShardRecord>> = HashMap::new();
        for record in remote_records {
            by_account
                .entry(record.account_id)
                .or_default()
                .push(record);
        }

        for (account_id, entries) in by_account {
            let account_record = self
                .db
                .get_account_by_id(account_id)
                .await?
                .ok_or_else(|| anyhow!("account id {account_id} missing"))?;
            let vault_entry = vault.account(account_id).cloned().ok_or_else(|| {
                anyhow!(
                    "credentials for account '{name}' missing from vault",
                    name = account_record.name
                )
            })?;

            let credential = Credential {
                account_id,
                backend: account_record.backend.clone(),
                endpoint: account_record.endpoint.clone(),
                token: vault_entry.token.clone(),
                token_ref: vault_entry.token_ref.clone(),
            };

            let storage = Self::instantiate_storage(&account_record.backend)?;
            let session = storage.login(&credential).await?;

            for entry in entries {
                let idx = entry.index;
                let remote = RemoteRef {
                    backend: account_record.backend.clone(),
                    locator: entry.remote_ref.clone(),
                    etag: entry.etag.clone(),
                };
                storage
                    .delete(&session, &remote)
                    .await
                    .with_context(|| format!("deleting remote shard {idx}"))?;
                self.db.delete_remote_shard(file_id, idx).await?;
            }
        }

        Ok(())
    }

    #[must_use]
    pub fn home(&self) -> &HomePaths {
        &self.paths
    }

    fn validate_backend(backend: &str) -> Result<()> {
        match backend {
            httpbucket::BACKEND_ID => Ok(()),
            other => Err(anyhow!("unsupported backend '{other}'")),
        }
    }

    fn instantiate_storage(backend: &str) -> Result<Box<dyn Storage>> {
        match backend {
            httpbucket::BACKEND_ID => Ok(Box::new(HttpBucketStorage::new()?)),
            other => Err(anyhow!("unsupported backend '{other}'")),
        }
    }

    async fn resolve_account(
        &self,
        vault: &Vault,
        account_name: Option<&str>,
    ) -> Result<ResolvedAccount> {
        let record = if let Some(name) = account_name {
            self.db
                .get_account_by_name(name)
                .await?
                .ok_or_else(|| anyhow!("account '{name}' not found"))?
        } else {
            let mut accounts = self.db.list_accounts().await?;
            anyhow::ensure!(!accounts.is_empty(), "no remote accounts configured");
            accounts.remove(0)
        };

        let vault_entry = vault.account(record.id).cloned().ok_or_else(|| {
            anyhow!(
                "no credential stored in vault for account '{}'",
                record.name
            )
        })?;

        let credential = Credential {
            account_id: record.id,
            backend: record.backend.clone(),
            endpoint: record.endpoint.clone(),
            token: vault_entry.token.clone(),
            token_ref: vault_entry.token_ref.clone(),
        };

        Ok(ResolvedAccount { record, credential })
    }

    #[allow(clippy::too_many_lines)]
    async fn ensure_remote_shards(
        &self,
        vault: &Vault,
        meta: &FileMeta,
        account_override: Option<&str>,
    ) -> Result<()> {
        let store = FileStore::new(self.paths.objects_dir.clone());
        store.ensure_dir(&meta.file_id).await?;
        let mut remote_records = self.db.list_remote_shards(&meta.file_id).await?;
        if remote_records.is_empty() {
            let file_id = &meta.file_id;
            anyhow::bail!("no remote shards recorded for {file_id}");
        }

        if let Some(name) = account_override {
            let account = self
                .db
                .get_account_by_name(name)
                .await?
                .ok_or_else(|| anyhow!("account '{name}' not found"))?;
            remote_records.retain(|record| record.account_id == account.id);
            if remote_records.is_empty() {
                anyhow::bail!(
                    "no remote shards for {} stored on account '{}'",
                    meta.file_id,
                    name
                );
            }
        }

        let mut by_account: HashMap<i64, Vec<RemoteShardRecord>> = HashMap::new();
        for record in remote_records {
            by_account
                .entry(record.account_id)
                .or_default()
                .push(record);
        }

        for (account_id, entries) in by_account {
            let account_record = self
                .db
                .get_account_by_id(account_id)
                .await?
                .ok_or_else(|| anyhow!("account id {account_id} missing"))?;
            let vault_entry = vault.account(account_id).cloned().ok_or_else(|| {
                anyhow!(
                    "credentials for account '{name}' missing from vault",
                    name = account_record.name
                )
            })?;

            let credential = Credential {
                account_id,
                backend: account_record.backend.clone(),
                endpoint: account_record.endpoint.clone(),
                token: vault_entry.token.clone(),
                token_ref: vault_entry.token_ref.clone(),
            };

            let storage = Self::instantiate_storage(&account_record.backend)?;
            let session = storage.login(&credential).await?;

            for entry in entries {
                let idx = entry.index;
                let shard_info = meta
                    .checksums
                    .iter()
                    .find(|info| info.index == idx)
                    .ok_or_else(|| anyhow!("metadata missing shard {idx}"))?;
                let shard_path = store.shard_path(&meta.file_id, idx as usize);
                if shard_path.exists() {
                    let local_meta = fs::metadata(&shard_path).await?;
                    if local_meta.len() as u64 == entry.size {
                        continue;
                    }
                    info!(
                        file_id = %meta.file_id,
                        index = entry.index,
                        "local shard size mismatch ({} vs {}), refreshing",
                        local_meta.len(),
                        entry.size
                    );
                }

                let remote = RemoteRef {
                    backend: account_record.backend.clone(),
                    locator: entry.remote_ref.clone(),
                    etag: entry.etag.clone(),
                };
                let tmp_path = shard_path.with_extension("remote.part");
                info!(
                    file_id = %meta.file_id,
                    index = entry.index,
                    "downloading shard from account {}",
                    account_record.name
                );
                storage
                    .download(&session, &remote, &tmp_path)
                    .await
                    .with_context(|| format!("downloading shard {idx}"))?;
                let downloaded = fs::read(&tmp_path).await?;
                let digest = crypto::blake3_checksum_hex(&downloaded);
                if digest != shard_info.checksum {
                    fs::remove_file(&tmp_path).await.ok();
                    anyhow::bail!(
                        "checksum mismatch for shard {}: expected {}, got {}",
                        idx,
                        shard_info.checksum,
                        digest
                    );
                }
                fs::rename(&tmp_path, &shard_path)
                    .await
                    .with_context(|| format!("renaming {}", tmp_path.display()))?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::httpbucket::{
        self,
        test_support::{configure_bucket, BucketState},
    };
    use assert_fs::prelude::*;
    use httptest::Server;
    use std::path::Path;
    use tempfile::tempdir;

    const PASSWORD: &str = "correct horse battery";

    fn defaults() -> DefaultsConfig {
        DefaultsConfig {
            k: 4,
            m: 2,
            cache_gb: 4,
        }
    }

    async fn init_fs(base: &Path) -> AegisFs {
        let home = HomePaths::new(base.to_path_buf());
        AegisFs::init(home.clone(), PASSWORD, defaults())
            .await
            .unwrap();
        AegisFs::load(home).await.unwrap()
    }

    #[tokio::test]
    async fn remote_upload_and_fetch_round_trip() {
        let dir = tempdir().unwrap();
        let fs = init_fs(dir.path()).await;

        let server = Server::run();
        let bucket_state = BucketState::new();
        configure_bucket(&server, bucket_state.clone(), false);
        let endpoint = server.url("/bucket/").to_string();

        fs.add_account(
            PASSWORD,
            "primary",
            httpbucket::BACKEND_ID,
            &endpoint,
            "token-primary",
        )
        .await
        .unwrap();

        let payload = assert_fs::NamedTempFile::new("remote.bin").unwrap();
        payload.write_binary(b"remote payload bytes").unwrap();

        fs.pack(
            PASSWORD,
            PackOptions {
                source: payload.path().to_path_buf(),
                file_id: "remote-file".into(),
                name: None,
                k: Some(2),
                m: Some(1),
                compress: false,
            },
        )
        .await
        .unwrap();

        fs.upload_shards(PASSWORD, "remote-file", Some("primary"))
            .await
            .unwrap();

        let remotes = fs.db.list_remote_shards("remote-file").await.unwrap();
        let store = FileStore::new(fs.home().objects_dir.clone());
        let meta = store.read_meta("remote-file").await.unwrap();
        assert_eq!(remotes.len(), meta.checksums.len());

        for idx in 0..meta.checksums.len() {
            let path = store.shard_path("remote-file", idx);
            tokio::fs::remove_file(&path).await.unwrap();
        }

        let dest = dir.path().join("remote-restored.bin");
        let unpack_opts = UnpackOptions {
            file_id: "remote-file".into(),
            destination: dest.clone(),
            overwrite: true,
            from_remote: true,
            account: Some("primary".into()),
        };
        fs.unpack(PASSWORD, unpack_opts).await.unwrap();

        let restored = std::fs::read(&dest).unwrap();
        let original = std::fs::read(payload.path()).unwrap();
        assert_eq!(restored, original);

        fs.gc_remote(PASSWORD, "remote-file", Some("primary"))
            .await
            .unwrap();
        assert!(fs
            .db
            .list_remote_shards("remote-file")
            .await
            .unwrap()
            .is_empty());
        assert_eq!(bucket_state.len().await, 0);
    }

    #[tokio::test]
    async fn remote_resume_repairs_partial_objects() {
        let dir = tempdir().unwrap();
        let fs = init_fs(dir.path()).await;

        let server = Server::run();
        let bucket_state = BucketState::new();
        configure_bucket(&server, bucket_state.clone(), false);
        let endpoint = server.url("/resume/").to_string();

        fs.add_account(
            PASSWORD,
            "resume",
            httpbucket::BACKEND_ID,
            &endpoint,
            "token-resume",
        )
        .await
        .unwrap();

        let payload = assert_fs::NamedTempFile::new("resume.bin").unwrap();
        payload.write_binary(&vec![5_u8; 4096]).unwrap();

        fs.pack(
            PASSWORD,
            PackOptions {
                source: payload.path().to_path_buf(),
                file_id: "resume-file".into(),
                name: None,
                k: Some(2),
                m: Some(1),
                compress: false,
            },
        )
        .await
        .unwrap();

        fs.upload_shards(PASSWORD, "resume-file", Some("resume"))
            .await
            .unwrap();

        let remotes = fs.db.list_remote_shards("resume-file").await.unwrap();
        assert!(!remotes.is_empty());
        let target = remotes[0].clone();
        let remote_path = bucket_state
            .paths()
            .await
            .into_iter()
            .find(|path| path.ends_with(&target.remote_ref))
            .expect("remote shard missing path");

        let mut truncated = bucket_state
            .get(&remote_path)
            .await
            .expect("remote shard missing");
        truncated.truncate(truncated.len() / 2);
        bucket_state.replace(&remote_path, truncated).await;

        fs.upload_shards(PASSWORD, "resume-file", Some("resume"))
            .await
            .unwrap();

        let updated = fs.db.list_remote_shards("resume-file").await.unwrap();
        assert_eq!(updated.len(), remotes.len());
        let store = FileStore::new(fs.home().objects_dir.clone());
        let meta = store.read_meta("resume-file").await.unwrap();

        let refreshed = bucket_state.get(&remote_path).await.unwrap();
        let expected = meta.checksums[target.index as usize].size;
        assert_eq!(refreshed.len(), expected);
        let index_entry = updated
            .iter()
            .find(|entry| entry.index == target.index)
            .expect("updated shard missing");
        assert_eq!(index_entry.size, u64::try_from(expected).unwrap());
    }

    #[tokio::test]
    async fn pack_and_unpack_round_trip() {
        let dir = tempdir().unwrap();
        let fs = init_fs(dir.path()).await;

        let temp = assert_fs::NamedTempFile::new("payload.bin").unwrap();
        temp.write_binary(b"hello aegis").unwrap();

        let pack_opts = PackOptions {
            source: temp.path().to_path_buf(),
            file_id: "file1".into(),
            name: Some("demo".into()),
            k: None,
            m: None,
            compress: false,
        };
        fs.pack(PASSWORD, pack_opts).await.unwrap();

        let out_file = dir.path().join("restored.bin");
        let unpack_opts = UnpackOptions {
            file_id: "file1".into(),
            destination: out_file.clone(),
            overwrite: true,
            from_remote: false,
            account: None,
        };
        fs.unpack(PASSWORD, unpack_opts).await.unwrap();

        let restored = std::fs::read(out_file).unwrap();
        assert_eq!(restored, b"hello aegis");
    }

    #[tokio::test]
    async fn unpack_with_missing_shards_succeeds() {
        let dir = tempdir().unwrap();
        let fs = init_fs(dir.path()).await;

        let temp = assert_fs::NamedTempFile::new("payload.bin").unwrap();
        temp.write_binary(&vec![7_u8; 4096]).unwrap();

        let pack_opts = PackOptions {
            source: temp.path().to_path_buf(),
            file_id: "file2".into(),
            name: None,
            k: None,
            m: None,
            compress: false,
        };
        fs.pack(PASSWORD, pack_opts).await.unwrap();

        let store = FileStore::new(fs.home().objects_dir.clone());
        // Remove up to m shards
        tokio::fs::remove_file(store.shard_path("file2", 4))
            .await
            .unwrap();

        let unpack_opts = UnpackOptions {
            file_id: "file2".into(),
            destination: dir.path().join("restored2.bin"),
            overwrite: true,
            from_remote: false,
            account: None,
        };
        fs.unpack(PASSWORD, unpack_opts).await.unwrap();
    }

    #[tokio::test]
    async fn shard_corruption_triggers_parity_recovery() {
        let dir = tempdir().unwrap();
        let fs = init_fs(dir.path()).await;

        let temp = assert_fs::NamedTempFile::new("payload.bin").unwrap();
        temp.write_binary(&vec![1_u8; 8192]).unwrap();

        fs.pack(
            PASSWORD,
            PackOptions {
                source: temp.path().to_path_buf(),
                file_id: "file3".into(),
                name: None,
                k: None,
                m: None,
                compress: false,
            },
        )
        .await
        .unwrap();

        let store = FileStore::new(fs.home().objects_dir.clone());
        let shard_path = store.shard_path("file3", 1);
        let mut data = tokio::fs::read(&shard_path).await.unwrap();
        data[0] ^= 0xAA;
        tokio::fs::write(&shard_path, data).await.unwrap();

        fs.unpack(
            PASSWORD,
            UnpackOptions {
                file_id: "file3".into(),
                destination: dir.path().join("restored3.bin"),
                overwrite: true,
                from_remote: false,
                account: None,
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn resume_from_partial_journal() {
        let dir = tempdir().unwrap();
        let fs = init_fs(dir.path()).await;

        let temp = assert_fs::NamedTempFile::new("payload.bin").unwrap();
        temp.write_binary(&vec![2_u8; 2048]).unwrap();

        let store = FileStore::new(fs.home().objects_dir.clone());
        store.ensure_dir("resume").await.unwrap();
        let mut journal = Journal::load(store.journal_path("resume")).await.unwrap();
        journal.record(JournalStage::Sharded).await.unwrap();

        fs.pack(
            PASSWORD,
            PackOptions {
                source: temp.path().to_path_buf(),
                file_id: "resume".into(),
                name: None,
                k: None,
                m: None,
                compress: true,
            },
        )
        .await
        .unwrap();

        let unpack_opts = UnpackOptions {
            file_id: "resume".into(),
            destination: dir.path().join("resume.bin"),
            overwrite: true,
            from_remote: false,
            account: None,
        };
        fs.unpack(PASSWORD, unpack_opts).await.unwrap();
    }
}
