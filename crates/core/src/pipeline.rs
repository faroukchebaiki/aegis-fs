use std::borrow::ToOwned;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use backoff::future::retry;
use backoff::{Error as BackoffError, ExponentialBackoff};
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Error as ReqwestError;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, Semaphore};
use tracing::{error, info, warn};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::{self, AEAD_NONCE_LEN};
use crate::db::Database;
use crate::erasure::Erasure;
use crate::journal::Journal;
use crate::model::{
    AccountRecord, Credential, DefaultsConfig, FileDetails, FileMeta, FileRecord, JournalStage,
    PlacementPlanShard, RemoteRef, RemoteShardRecord, RemoteShardStatus, Session, ShardInfo,
    VaultAccountEntry, VaultFileEntry,
};
use crate::storage::httpbucket::{self, HttpBucketStorage, HttpStatusError};
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

type Limiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

#[derive(Clone)]
struct AccountRuntime {
    record: AccountRecord,
    session: Session,
    storage: Arc<dyn Storage>,
    limiter: Arc<Limiter>,
    stats: Arc<Mutex<AccountStats>>,
}

#[derive(Clone, Debug)]
struct AccountStats {
    success_rate: f64,
    last_error: Option<String>,
}

const GLOBAL_CONCURRENCY_LIMIT: usize = 8;
const BASE_RATE_PER_SECOND: u32 = 4;

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

    async fn build_account_runtime(
        &self,
        record: AccountRecord,
        vault_entry: VaultAccountEntry,
    ) -> Result<Arc<AccountRuntime>> {
        let credential = Credential {
            account_id: record.id,
            backend: record.backend.clone(),
            endpoint: record.endpoint.clone(),
            token: vault_entry.token.clone(),
            token_ref: vault_entry.token_ref.clone(),
        };

        let storage = Self::instantiate_storage(&record.backend)?;
        let session = storage.login(&credential).await?;
        let weight = u32::try_from(record.weight.max(1))
            .context("account weight exceeds platform range")?;
        let rate_per_second = (BASE_RATE_PER_SECOND.saturating_mul(weight)).max(1);
        let quota = Quota::per_second(
            std::num::NonZeroU32::new(rate_per_second).expect("non-zero quota"),
        );
        let limiter = Arc::new(RateLimiter::direct(quota));

        Ok(Arc::new(AccountRuntime {
            record,
            session,
            storage,
            limiter,
            stats: Arc::new(Mutex::new(AccountStats {
                success_rate: record.success_rate,
                last_error: record.last_error.clone(),
            })),
        }))
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

    /// Updates the weight for a stored account, ensuring credentials exist.
    pub async fn set_account_weight(
        &self,
        password: &str,
        name: &str,
        weight: i64,
    ) -> Result<()> {
        anyhow::ensure!(weight > 0, "weight must be > 0");
        let vault = self.unlock_vault(password).await?;
        let account = self
            .db
            .get_account_by_name(name)
            .await?
            .context("account not found")?;
        anyhow::ensure!(
            vault.account(account.id).is_some(),
            "credential missing from vault for account '{}'",
            account.name
        );
        self.db
            .update_account_weight(account.id, weight)
            .await?;
        Ok(())
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
    pub async fn plan_upload(
        &self,
        password: &str,
        file_id: &str,
        seed: Option<u64>,
    ) -> Result<Vec<PlacementPlanShard>> {
        let vault = self.unlock_vault(password).await?;
        let store = FileStore::new(self.paths.objects_dir.clone());
        store.ensure_dir(file_id).await?;
        let meta = store.read_meta(file_id).await?;
        let total_shards = usize::from(meta.k + meta.m);
        anyhow::ensure!(total_shards > 0, "file {file_id} has no shards to upload");

        let mut accounts = self.db.list_accounts().await?;
        accounts.retain(|record| {
            record.backend == httpbucket::BACKEND_ID
                && record.weight > 0
                && vault.account(record.id).is_some()
        });

        let available = accounts.len();
        anyhow::ensure!(
            available >= total_shards,
            "need ≥ {} accounts, have {}",
            total_shards,
            available
        );

        #[derive(Clone)]
        struct PlacementState {
            record: AccountRecord,
            current: i64,
        }

        let mut states: Vec<PlacementState> = accounts
            .into_iter()
            .map(|record| PlacementState {
                record,
                current: 0,
            })
            .collect();

        if let Some(seed_value) = seed {
            if !states.is_empty() {
                let shift = (seed_value as usize) % states.len();
                states.rotate_left(shift);
            }
        }

        let total_weight: i64 = states.iter().map(|state| state.record.weight).sum();
        anyhow::ensure!(total_weight > 0, "all account weights must be positive");

        let mut selected = Vec::with_capacity(total_shards);
        let mut iterations = 0_usize;
        while selected.len() < total_shards {
            iterations += 1;
            for state in &mut states {
                state.current += state.record.weight;
            }
            let (idx, _) = states
                .iter()
                .enumerate()
                .max_by_key(|(_, state)| state.current)
                .expect("non-empty state set");
            let state = &mut states[idx];
            if !selected.iter().any(|record: &AccountRecord| record.id == state.record.id) {
                selected.push(state.record.clone());
            }
            state.current -= total_weight;
            anyhow::ensure!(
                iterations <= total_shards * states.len() * 4,
                "weighted placement failed to converge"
            );
        }

        let mut shard_infos = meta.checksums.clone();
        shard_infos.sort_by_key(|info| info.index);

        self.db.clear_pending_plan(file_id).await?;

        let mut plan = Vec::with_capacity(total_shards);
        for (shard, account) in shard_infos.iter().zip(selected.iter()) {
            let size = u64::try_from(shard.size).context("shard size exceeds u64")?;
            let remote_ref = format!("{}/shard_{:03}.bin", file_id, shard.index);
            let record = RemoteShardRecord {
                file_id: file_id.to_string(),
                index: shard.index,
                account_id: account.id,
                remote_ref: remote_ref.clone(),
                size,
                etag: None,
                status: RemoteShardStatus::Pending,
            };
            self.db.upsert_remote_shard(&record).await?;
            plan.push(PlacementPlanShard {
                shard_index: shard.index,
                account_id: account.id,
                account_name: account.name.clone(),
                remote_ref,
                size,
            });
        }

        Ok(plan)
    }

    /// Uploads shards for a file to a remote backend.
    ///
    /// # Errors
    /// Returns an error if unlocking the vault fails, local shards are missing, or remote persistence fails.
    pub async fn upload_shards(&self, password: &str, file_id: &str) -> Result<()> {
        let vault = self.unlock_vault(password).await?;
        let store = Arc::new(FileStore::new(self.paths.objects_dir.clone()));
        store.ensure_dir(file_id).await?;
        let meta = store.read_meta(file_id).await?;

        let mut pending_plan = Vec::new();
        let mut account_cache: HashMap<i64, AccountRecord> = HashMap::new();
        for record in self.db.list_remote_shards(file_id).await? {
            if record.status != RemoteShardStatus::Pending {
                continue;
            }
            let account = if let Some(existing) = account_cache.get(&record.account_id) {
                existing.clone()
            } else {
                let fetched = self
                    .db
                    .get_account_by_id(record.account_id)
                    .await?
                    .context("account missing during plan load")?;
                account_cache.insert(record.account_id, fetched.clone());
                fetched
            };
            pending_plan.push(PlacementPlanShard {
                shard_index: record.index,
                account_id: record.account_id,
                account_name: account.name.clone(),
                remote_ref: record.remote_ref.clone(),
                size: record.size,
            });
        }

        if pending_plan.is_empty() {
            pending_plan = self.plan_upload(password, file_id, None).await?;
        }

        anyhow::ensure!(!pending_plan.is_empty(), "no shards to upload for {file_id}");

        let mut runtimes = HashMap::new();
        for plan in &pending_plan {
            if runtimes.contains_key(&plan.account_id) {
                continue;
            }
            let account_record = self
                .db
                .get_account_by_id(plan.account_id)
                .await?
                .context("account missing during upload")?;
            let vault_entry = vault
                .account(plan.account_id)
                .cloned()
                .context("vault credential missing")?;
            let runtime = self
                .build_account_runtime(account_record, vault_entry)
                .await?;
            runtimes.insert(plan.account_id, runtime);
        }

        let semaphore = Arc::new(Semaphore::new(GLOBAL_CONCURRENCY_LIMIT));
        let overall = ProgressBar::new(pending_plan.len() as u64);
        overall.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} uploading {pos}/{len} shards ({percent}%)",
            )
            .unwrap()
            .progress_chars("=>"),
        );

        let mut handles = Vec::new();
        for plan in pending_plan {
            let shard_meta = meta
                .checksums
                .iter()
                .find(|info| info.index == plan.shard_index)
                .cloned()
                .context("missing shard metadata")?;
            let runtime = runtimes
                .get(&plan.account_id)
                .cloned()
                .context("account runtime missing")?;
            let semaphore = semaphore.clone();
            let db = self.db.clone();
            let store = store.clone();
            let overall = overall.clone();
            let file_id = file_id.to_string();
            handles.push(tokio::spawn(async move {
                process_shard(
                    db,
                    store,
                    semaphore,
                    overall,
                    runtime,
                    file_id,
                    plan,
                    shard_meta,
                )
                .await
            }));
        }

        let mut errors = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => errors.push(err),
                Err(err) => errors.push(anyhow!("upload task panicked: {err}")),
            }
        }
        overall.finish_with_message("upload complete");

        if let Some(err) = errors.into_iter().next() {
            return Err(err);
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

    fn instantiate_storage(backend: &str) -> Result<Arc<dyn Storage>> {
        match backend {
            httpbucket::BACKEND_ID => Ok(Arc::new(HttpBucketStorage::new()?)),
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
    use std::collections::HashSet;
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
    async fn plan_upload_creates_pending_records() {
        let dir = tempdir().unwrap();
        let fs = init_fs(dir.path()).await;

        for name in ["alpha", "beta", "gamma"] {
            fs.add_account(
                PASSWORD,
                name,
                httpbucket::BACKEND_ID,
                "https://example",
                &format!("token-{name}"),
            )
            .await
            .unwrap();
        }

        let payload = assert_fs::NamedTempFile::new("plan.bin").unwrap();
        payload.write_binary(b"plan bytes").unwrap();

        let file_id = "plan-file";
        fs.pack(
            PASSWORD,
            PackOptions {
                source: payload.path().to_path_buf(),
                file_id: file_id.into(),
                name: None,
                k: Some(2),
                m: Some(1),
                compress: false,
            },
        )
        .await
        .unwrap();

        let plan = fs.plan_upload(PASSWORD, file_id, None).await.unwrap();
        assert_eq!(plan.len(), 3);
        let mut seen = HashSet::new();
        for shard in &plan {
            assert!(seen.insert(shard.account_id));
        }

        let remotes = fs.db.list_remote_shards(file_id).await.unwrap();
        assert_eq!(remotes.len(), 3);
        assert!(remotes
            .iter()
            .all(|remote| remote.status == RemoteShardStatus::Pending));
    }

    #[tokio::test]
    async fn plan_upload_respects_weights() {
        let dir = tempdir().unwrap();
        let fs = init_fs(dir.path()).await;

        for name in ["alpha", "beta", "gamma", "delta"] {
            fs.add_account(
                PASSWORD,
                name,
                httpbucket::BACKEND_ID,
                "https://example",
                &format!("token-{name}"),
            )
            .await
            .unwrap();
        }

        let payload = assert_fs::NamedTempFile::new("weight.bin").unwrap();
        payload.write_binary(b"weight bytes").unwrap();

        let file_id = "weight-file";
        fs.pack(
            PASSWORD,
            PackOptions {
                source: payload.path().to_path_buf(),
                file_id: file_id.into(),
                name: None,
                k: Some(2),
                m: Some(1),
                compress: false,
            },
        )
        .await
        .unwrap();

        let baseline = fs
            .plan_upload(PASSWORD, file_id, Some(0))
            .await
            .unwrap();
        let baseline_accounts: Vec<String> = baseline
            .iter()
            .map(|entry| entry.account_name.clone())
            .collect();

        fs.set_account_weight(PASSWORD, "delta", 5).await.unwrap();

        let weighted = fs
            .plan_upload(PASSWORD, file_id, Some(0))
            .await
            .unwrap();
        let weighted_accounts: Vec<String> = weighted
            .iter()
            .map(|entry| entry.account_name.clone())
            .collect();

        assert!(weighted_accounts.contains(&"delta".to_string()));
        assert_ne!(baseline_accounts, weighted_accounts);
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

async fn process_shard(
    db: Database,
    store: Arc<FileStore>,
    semaphore: Arc<Semaphore>,
    overall: ProgressBar,
    runtime: Arc<AccountRuntime>,
    file_id: String,
    plan: PlacementPlanShard,
    shard_meta: ShardInfo,
) -> Result<()> {
    let _permit = semaphore.acquire_owned().await?;
    let shard_path = store.shard_path(&file_id, usize::from(plan.shard_index));
    if !shard_path.exists() {
        overall.inc(1);
        db.set_remote_shard_status(&file_id, plan.shard_index, RemoteShardStatus::Missing)
            .await?;
        return Err(anyhow!(
            "local shard {} missing; run pack before upload",
            plan.shard_index
        ));
    }

    db.set_remote_shard_status(&file_id, plan.shard_index, RemoteShardStatus::Uploading)
        .await?;

    let expected_size = u64::try_from(shard_meta.size).context("shard size overflow")?;
    let storage = runtime.storage.clone();
    let session = runtime.session.clone();
    let limiter = runtime.limiter.clone();
    let remote_hint = plan.remote_ref.clone();

    let mut backoff = ExponentialBackoff {
        initial_interval: Duration::from_millis(200),
        max_interval: Duration::from_secs(5),
        max_elapsed_time: Some(Duration::from_secs(120)),
        randomization_factor: 0.2,
        ..ExponentialBackoff::default()
    };

    let upload_result = retry(backoff.clone(), || {
        let storage = storage.clone();
        let session = session.clone();
        let limiter = limiter.clone();
        let shard_path = shard_path.clone();
        let remote_hint = remote_hint.clone();
        async move {
            limiter.until_ready().await;
            match storage.upload(&session, &shard_path, Some(&remote_hint)).await {
                Ok(remote) => Ok(remote),
                Err(err) => Err(classify_backoff(err)),
            }
        }
    })
    .await;

    let remote_ref = match upload_result {
        Ok(remote) => remote,
        Err(BackoffError::Permanent(err) | BackoffError::Transient(err)) => {
            error!(
                file_id = %file_id,
                shard = plan.shard_index,
                "upload failed after retries: {err}"
            );
            db.set_remote_shard_status(&file_id, plan.shard_index, RemoteShardStatus::Missing)
                .await?;
            update_account_health(&db, &runtime, false, Some(&err.to_string())).await?;
            overall.inc(1);
            return Err(err);
        }
    };

    let stat_result = retry(backoff, || {
        let storage = storage.clone();
        let session = session.clone();
        let limiter = limiter.clone();
        let remote_ref = remote_ref.clone();
        async move {
            limiter.until_ready().await;
            match storage.stat(&session, &remote_ref).await {
                Ok(meta) => Ok(meta),
                Err(err) => Err(classify_backoff(err)),
            }
        }
    })
    .await;

    let object_meta = match stat_result {
        Ok(meta) => meta,
        Err(BackoffError::Permanent(err) | BackoffError::Transient(err)) => {
            error!(
                file_id = %file_id,
                shard = plan.shard_index,
                "stat after upload failed: {err}"
            );
            db.set_remote_shard_status(&file_id, plan.shard_index, RemoteShardStatus::Missing)
                .await?;
            update_account_health(&db, &runtime, false, Some(&err.to_string())).await?;
            overall.inc(1);
            return Err(err);
        }
    };

    let final_status = if object_meta.size == expected_size {
        RemoteShardStatus::Ok
    } else {
        warn!(
            file_id = %file_id,
            shard = plan.shard_index,
            expected = expected_size,
            actual = object_meta.size,
            "remote size mismatch"
        );
        RemoteShardStatus::Stale
    };

    let record = RemoteShardRecord {
        file_id: file_id.clone(),
        index: plan.shard_index,
        account_id: plan.account_id,
        remote_ref: remote_ref.locator.clone(),
        size: object_meta.size,
        etag: object_meta.etag.clone(),
        status: final_status,
    };
    db.upsert_remote_shard(&record).await?;
    update_account_health(&db, &runtime, final_status == RemoteShardStatus::Ok, None).await?;
    overall.inc(1);
    Ok(())
}

fn classify_backoff(err: anyhow::Error) -> BackoffError<anyhow::Error> {
    if is_transient(&err) {
        BackoffError::Transient(err)
    } else {
        BackoffError::Permanent(err)
    }
}

fn is_transient(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(status) = cause.downcast_ref::<HttpStatusError>() {
            if status.is_transient() {
                return true;
            }
        }
        if let Some(req_err) = cause.downcast_ref::<ReqwestError>() {
            if req_err.is_timeout() || req_err.is_connect() || req_err.is_request() {
                return true;
            }
        }
    }
    false
}

async fn update_account_health(
    db: &Database,
    runtime: &Arc<AccountRuntime>,
    success: bool,
    error: Option<&str>,
) -> Result<()> {
    let mut stats = runtime.stats.lock().await;
    let mut rate = stats.success_rate.clamp(0.0, 1.0);
    if success {
        rate = (rate * 0.8_f64) + 0.2_f64;
        stats.last_error = None;
    } else {
        rate = (rate * 0.5_f64).clamp(0.0, 1.0);
        stats.last_error = error.map(ToOwned::to_owned);
    }
    stats.success_rate = rate;
    db.update_account_health(runtime.record.id, rate, stats.last_error.as_deref())
        .await?;
    Ok(())
}
