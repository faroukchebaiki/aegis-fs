use anyhow::anyhow;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct DefaultsConfig {
    pub k: u8,
    pub m: u8,
    pub cache_gb: u32,
}

impl DefaultsConfig {
    /// Validates the defaults, ensuring positive shard counts.
    ///
    /// # Errors
    /// Returns an error if either shard count is zero or the combined value exceeds 255.
    pub fn validate(self) -> anyhow::Result<()> {
        anyhow::ensure!(self.k > 0, "parameter k must be > 0");
        anyhow::ensure!(self.m > 0, "parameter m must be > 0");
        anyhow::ensure!(
            u16::from(self.k) + u16::from(self.m) <= 255,
            "k + m must be <= 255"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultFileEntry {
    pub file_id: String,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub k: u8,
    pub m: u8,
    pub compressed: bool,
    pub wrap_nonce: String,
    pub wrapped_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultAccountEntry {
    pub account_id: i64,
    pub name: String,
    pub backend: String,
    pub endpoint: String,
    pub token: String,
    pub token_ref: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultData {
    pub version: u32,
    pub default_k: u8,
    pub default_m: u8,
    pub cache_gb: u32,
    pub files: Vec<VaultFileEntry>,
    #[serde(default)]
    pub accounts: Vec<VaultAccountEntry>,
}

impl VaultData {
    #[must_use]
    pub fn new(defaults: DefaultsConfig) -> Self {
        Self {
            version: 1,
            default_k: defaults.k,
            default_m: defaults.m,
            cache_gb: defaults.cache_gb,
            files: Vec::new(),
            accounts: Vec::new(),
        }
    }

    pub fn upsert(&mut self, entry: VaultFileEntry) {
        if let Some(existing) = self.files.iter_mut().find(|f| f.file_id == entry.file_id) {
            *existing = entry;
        } else {
            self.files.push(entry);
        }
    }

    pub fn remove(&mut self, file_id: &str) {
        self.files.retain(|entry| entry.file_id != file_id);
    }

    #[must_use]
    pub fn find(&self, file_id: &str) -> Option<&VaultFileEntry> {
        self.files.iter().find(|entry| entry.file_id == file_id)
    }

    pub fn upsert_account(&mut self, entry: VaultAccountEntry) {
        if let Some(existing) = self
            .accounts
            .iter_mut()
            .find(|acct| acct.account_id == entry.account_id)
        {
            *existing = entry;
        } else {
            self.accounts.push(entry);
        }
    }

    pub fn remove_account(&mut self, account_id: i64) {
        self.accounts.retain(|entry| entry.account_id != account_id);
    }

    #[must_use]
    pub fn find_account(&self, account_id: i64) -> Option<&VaultAccountEntry> {
        self.accounts
            .iter()
            .find(|entry| entry.account_id == account_id)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardInfo {
    pub index: u8,
    pub size: usize,
    pub checksum: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileMeta {
    pub file_id: String,
    pub name: Option<String>,
    pub plaintext_size: u64,
    pub compressed_size: u64,
    pub ciphertext_size: u64,
    pub shard_size: usize,
    pub k: u8,
    pub m: u8,
    pub compressed: bool,
    pub nonce: String,
    pub checksums: Vec<ShardInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileRecord {
    pub id: String,
    pub name: Option<String>,
    pub size: i64,
    pub created_at: DateTime<Utc>,
    pub k: i64,
    pub m: i64,
    pub compressed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileDetails {
    pub record: FileRecord,
    pub shards: Vec<ShardInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credential {
    pub account_id: i64,
    pub backend: String,
    pub endpoint: String,
    pub token: String,
    pub token_ref: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub account_id: i64,
    pub backend: String,
    pub endpoint: String,
    pub token: String,
    pub token_ref: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemoteRef {
    pub backend: String,
    pub locator: String,
    pub etag: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectMeta {
    pub size: u64,
    pub etag: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AccountRecord {
    pub id: i64,
    pub name: String,
    pub backend: String,
    pub endpoint: String,
    pub token_ref: String,
    pub weight: i64,
    pub success_rate: f64,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RemoteShardRecord {
    pub file_id: String,
    pub index: u8,
    pub account_id: i64,
    pub remote_ref: String,
    pub size: u64,
    pub etag: Option<String>,
    pub status: RemoteShardStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteShardStatus {
    Pending,
    Uploading,
    Ok,
    Missing,
    Stale,
}

#[derive(Clone, Debug)]
pub struct PlacementPlanShard {
    pub shard_index: u8,
    pub account_id: i64,
    pub account_name: String,
    pub remote_ref: String,
    pub size: u64,
}

impl RemoteShardStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Uploading => "UPLOADING",
            Self::Ok => "OK",
            Self::Missing => "MISSING",
            Self::Stale => "STALE",
        }
    }
}

impl TryFrom<&str> for RemoteShardStatus {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "PENDING" => Ok(Self::Pending),
            "UPLOADING" => Ok(Self::Uploading),
            "OK" => Ok(Self::Ok),
            "MISSING" => Ok(Self::Missing),
            "STALE" => Ok(Self::Stale),
            other => Err(anyhow!("invalid shard status '{other}'")),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JournalEntry {
    pub stage: JournalStage,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum JournalStage {
    Start,
    Encrypted,
    Sharded,
    Stored,
    Indexed,
    Completed,
}
