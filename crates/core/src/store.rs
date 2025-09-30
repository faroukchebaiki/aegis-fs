use std::{convert::TryFrom, path::PathBuf};

use anyhow::{Context, Result};
use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::crypto;
use crate::model::{FileMeta, ShardInfo};
use crate::util::write_atomic;

#[derive(Clone, Debug)]
pub struct FileStore {
    base: PathBuf,
}

impl FileStore {
    #[must_use]
    pub fn new(base: PathBuf) -> Self {
        Self { base }
    }

    #[must_use]
    pub fn file_dir(&self, file_id: &str) -> PathBuf {
        self.base.join(file_id)
    }

    #[must_use]
    pub fn meta_path(&self, file_id: &str) -> PathBuf {
        self.file_dir(file_id).join("meta.json")
    }

    #[must_use]
    pub fn shard_path(&self, file_id: &str, index: usize) -> PathBuf {
        self.file_dir(file_id).join(format!("shard_{index}.bin"))
    }

    #[must_use]
    pub fn journal_path(&self, file_id: &str) -> PathBuf {
        self.file_dir(file_id).join("journal.json")
    }

    /// Ensures the directory for a specific file exists.
    ///
    /// # Errors
    /// Returns an error if the directory cannot be created.
    pub async fn ensure_dir(&self, file_id: &str) -> Result<()> {
        let dir = self.file_dir(file_id);
        fs::create_dir_all(&dir)
            .await
            .with_context(|| format!("creating object directory {}", dir.display()))?;
        Ok(())
    }

    /// Writes shard payloads to disk and returns metadata for each shard.
    ///
    /// # Errors
    /// Returns an error if any shard cannot be written or flushed.
    pub async fn write_shards(&self, file_id: &str, shards: &[Vec<u8>]) -> Result<Vec<ShardInfo>> {
        self.ensure_dir(file_id).await?;
        let mut infos = Vec::with_capacity(shards.len());
        for (idx, shard) in shards.iter().enumerate() {
            let path = self.shard_path(file_id, idx);
            let mut file = fs::File::create(&path)
                .await
                .with_context(|| format!("creating shard {}", path.display()))?;
            file.write_all(shard).await?;
            file.flush().await?;
            let checksum = crypto::blake3_checksum_hex(shard);
            let index = u8::try_from(idx).context("shard index exceeds u8")?;
            infos.push(ShardInfo {
                index,
                size: shard.len(),
                checksum,
            });
        }
        Ok(infos)
    }

    /// Reads shards from disk, returning `None` if a shard file is missing.
    ///
    /// # Errors
    /// Returns an error if an existing shard cannot be read from disk.
    pub async fn read_shards(
        &self,
        file_id: &str,
        total_shards: usize,
    ) -> Result<Vec<Option<Vec<u8>>>> {
        let mut shards = Vec::with_capacity(total_shards);
        for idx in 0..total_shards {
            let path = self.shard_path(file_id, idx);
            if path.exists() {
                let data = fs::read(&path)
                    .await
                    .with_context(|| format!("reading shard {}", path.display()))?;
                shards.push(Some(data));
            } else {
                shards.push(None);
            }
        }
        Ok(shards)
    }

    /// Serializes and writes metadata describing the packed file.
    ///
    /// # Errors
    /// Returns an error if the metadata cannot be serialized or written.
    pub async fn write_meta(&self, file_id: &str, meta: &FileMeta) -> Result<()> {
        let path = self.meta_path(file_id);
        let data = serde_json::to_vec_pretty(meta)?;
        write_atomic(&path, &data).await
    }

    /// Reads and deserializes metadata for a packed file.
    ///
    /// # Errors
    /// Returns an error if the metadata file cannot be read or parsed.
    pub async fn read_meta(&self, file_id: &str) -> Result<FileMeta> {
        let path = self.meta_path(file_id);
        let data = fs::read(&path)
            .await
            .with_context(|| format!("reading metadata {}", path.display()))?;
        let meta = serde_json::from_slice(&data)
            .with_context(|| format!("parsing metadata {}", path.display()))?;
        Ok(meta)
    }

    /// Removes all on-disk data for the specified file.
    ///
    /// # Errors
    /// Returns an error if filesystem deletion fails.
    pub async fn remove_file(&self, file_id: &str) -> Result<()> {
        let dir = self.file_dir(file_id);
        if dir.exists() {
            fs::remove_dir_all(&dir)
                .await
                .with_context(|| format!("removing object dir {}", dir.display()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use tempfile::tempdir;

    #[tokio::test]
    async fn shard_round_trip() {
        let dir = tempdir().unwrap();
        let store = FileStore::new(dir.path().to_path_buf());
        let file_id = "file-1";
        let shards = vec![b"hello".to_vec(), b"world".to_vec()];
        let infos = store.write_shards(file_id, &shards).await.unwrap();
        assert_eq!(infos.len(), shards.len());

        let loaded = store.read_shards(file_id, shards.len()).await.unwrap();
        assert_eq!(loaded.len(), shards.len());
        assert_eq!(loaded[0].as_ref().unwrap(), &shards[0]);
    }

    #[tokio::test]
    async fn meta_round_trip() {
        let dir = tempdir().unwrap();
        let store = FileStore::new(dir.path().to_path_buf());
        let file_id = "file-meta";
        let meta = FileMeta {
            file_id: file_id.to_string(),
            name: Some("demo".into()),
            plaintext_size: 42,
            compressed_size: 40,
            ciphertext_size: 64,
            shard_size: 16,
            k: 3,
            m: 2,
            compressed: true,
            nonce: BASE64.encode([0_u8; 12]),
            checksums: vec![ShardInfo {
                index: 0,
                size: 16,
                checksum: "abcd".into(),
            }],
        };
        store.write_meta(file_id, &meta).await.unwrap();
        let loaded = store.read_meta(file_id).await.unwrap();
        assert_eq!(loaded.file_id, meta.file_id);
        assert_eq!(loaded.checksums.len(), 1);
    }
}
