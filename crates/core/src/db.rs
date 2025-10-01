use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous};
use sqlx::{Pool, Row, Sqlite};
use std::convert::TryFrom;
use tokio::fs;

use crate::model::{
    AccountRecord, FileDetails, FileMeta, FileRecord, RemoteShardRecord, ShardInfo,
};

#[derive(Clone)]
pub struct Database {
    pool: Pool<Sqlite>,
}

impl Database {
    /// Opens (and creates if needed) the `SQLite` database backing the workspace.
    ///
    /// # Errors
    /// Returns an error if the directory cannot be created or the database cannot be opened.
    pub async fn connect(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("creating database directory {}", parent.display()))?;
        }

        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal);

        let pool = Pool::<Sqlite>::connect_with(options)
            .await
            .with_context(|| format!("opening sqlite database {}", path.display()))?;

        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r"
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                name TEXT,
                size INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                k INTEGER NOT NULL,
                m INTEGER NOT NULL,
                compressed INTEGER NOT NULL
            );
            ",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r"
            CREATE TABLE IF NOT EXISTS shards (
                file_id TEXT NOT NULL,
                ix INTEGER NOT NULL,
                size INTEGER NOT NULL,
                checksum BLOB NOT NULL,
                PRIMARY KEY(file_id, ix),
                FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE
            );
            ",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r"
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            ",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r"
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                backend TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                token TEXT NOT NULL
            );
            ",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r"
            CREATE TABLE IF NOT EXISTS remote_shards (
                file_id TEXT NOT NULL,
                ix INTEGER NOT NULL,
                account_id INTEGER NOT NULL,
                remote_ref TEXT NOT NULL,
                size INTEGER NOT NULL,
                etag TEXT,
                PRIMARY KEY(file_id, ix),
                FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
                FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
            );
            ",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Inserts or updates a string setting in the database.
    ///
    /// # Errors
    /// Returns an error if the underlying SQL statement fails.
    pub async fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Retrieves an optional setting value from the database.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub async fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT value FROM settings WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|row| row.get::<String, _>("value")))
    }

    /// Creates a new remote storage account record.
    ///
    /// # Errors
    /// Returns an error if the record cannot be inserted.
    pub async fn create_account(
        &self,
        name: &str,
        backend: &str,
        endpoint: &str,
        token_ref: &str,
    ) -> Result<i64> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO accounts(name, backend, endpoint, token) VALUES(?, ?, ?, ?)")
            .bind(name)
            .bind(backend)
            .bind(endpoint)
            .bind(token_ref)
            .execute(&mut *tx)
            .await?;

        let account_id: i64 = sqlx::query_scalar("SELECT last_insert_rowid()")
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(account_id)
    }

    /// Lists all configured remote accounts.
    ///
    /// # Errors
    /// Returns an error if the underlying query fails.
    pub async fn list_accounts(&self) -> Result<Vec<AccountRecord>> {
        let rows = sqlx::query(
            "SELECT id, name, backend, endpoint, token FROM accounts ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut accounts = Vec::with_capacity(rows.len());
        for row in rows {
            accounts.push(AccountRecord {
                id: row.get("id"),
                name: row.get("name"),
                backend: row.get("backend"),
                endpoint: row.get("endpoint"),
                token_ref: row.get("token"),
            });
        }
        Ok(accounts)
    }

    /// Fetches an account by name.
    ///
    /// # Errors
    /// Returns an error if the lookup query fails.
    pub async fn get_account_by_name(&self, name: &str) -> Result<Option<AccountRecord>> {
        let row =
            sqlx::query("SELECT id, name, backend, endpoint, token FROM accounts WHERE name = ?")
                .bind(name)
                .fetch_optional(&self.pool)
                .await?;

        Ok(row.map(|row| AccountRecord {
            id: row.get("id"),
            name: row.get("name"),
            backend: row.get("backend"),
            endpoint: row.get("endpoint"),
            token_ref: row.get("token"),
        }))
    }

    /// Fetches an account by identifier.
    ///
    /// # Errors
    /// Returns an error if the lookup query fails.
    pub async fn get_account_by_id(&self, account_id: i64) -> Result<Option<AccountRecord>> {
        let row =
            sqlx::query("SELECT id, name, backend, endpoint, token FROM accounts WHERE id = ?")
                .bind(account_id)
                .fetch_optional(&self.pool)
                .await?;

        Ok(row.map(|row| AccountRecord {
            id: row.get("id"),
            name: row.get("name"),
            backend: row.get("backend"),
            endpoint: row.get("endpoint"),
            token_ref: row.get("token"),
        }))
    }

    /// Associates a remote shard reference with a file shard.
    ///
    /// # Errors
    /// Returns an error if the upsert fails.
    pub async fn upsert_remote_shard(&self, record: &RemoteShardRecord) -> Result<()> {
        sqlx::query(
            "INSERT INTO remote_shards(file_id, ix, account_id, remote_ref, size, etag) \
             VALUES(?, ?, ?, ?, ?, ?) \
             ON CONFLICT(file_id, ix) DO UPDATE SET \
                 account_id = excluded.account_id, \
                 remote_ref = excluded.remote_ref, \
                 size = excluded.size, \
                 etag = excluded.etag",
        )
        .bind(&record.file_id)
        .bind(i64::from(record.index))
        .bind(record.account_id)
        .bind(&record.remote_ref)
        .bind(i64::try_from(record.size).context("remote shard size exceeds i64")?)
        .bind(&record.etag)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Lists remote shard references for a file.
    ///
    /// # Errors
    /// Returns an error if the query fails or the stored metadata cannot be parsed.
    pub async fn list_remote_shards(&self, file_id: &str) -> Result<Vec<RemoteShardRecord>> {
        let rows = sqlx::query(
            "SELECT file_id, ix, account_id, remote_ref, size, etag FROM remote_shards WHERE file_id = ?",
        )
        .bind(file_id)
        .fetch_all(&self.pool)
        .await?;

        let mut entries = Vec::with_capacity(rows.len());
        for row in rows {
            let size: i64 = row.get("size");
            entries.push(RemoteShardRecord {
                file_id: row.get("file_id"),
                index: u8::try_from(row.get::<i64, _>("ix")).context("remote ix exceeds u8")?,
                account_id: row.get("account_id"),
                remote_ref: row.get("remote_ref"),
                size: u64::try_from(size).context("remote shard size negative")?,
                etag: row.try_get("etag").ok(),
            });
        }
        Ok(entries)
    }

    /// Removes all remote shard references for a file.
    ///
    /// # Errors
    /// Returns an error if the delete statement fails.
    pub async fn remove_remote_shards(&self, file_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM remote_shards WHERE file_id = ?")
            .bind(file_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Removes a single remote shard entry.
    ///
    /// # Errors
    /// Returns an error if the delete statement fails.
    pub async fn delete_remote_shard(&self, file_id: &str, index: u8) -> Result<()> {
        sqlx::query("DELETE FROM remote_shards WHERE file_id = ? AND ix = ?")
            .bind(file_id)
            .bind(i64::from(index))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Inserts a file record and associated shard metadata transactionally.
    ///
    /// # Errors
    /// Returns an error if any insert statement fails.
    pub async fn insert_file(&self, meta: &FileMeta, created_at: DateTime<Utc>) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "INSERT INTO files(id, name, size, created_at, k, m, compressed) VALUES(?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&meta.file_id)
        .bind(&meta.name)
        .bind(i64::try_from(meta.plaintext_size).context("file size exceeds i64")?)
        .bind(created_at.to_rfc3339())
        .bind(i64::from(meta.k))
        .bind(i64::from(meta.m))
        .bind(i64::from(meta.compressed))
        .execute(&mut *tx)
        .await?;

        for shard in &meta.checksums {
            let checksum = hex::decode(&shard.checksum)
                .with_context(|| format!("decoding checksum for shard {}", shard.index))?;
            sqlx::query("INSERT INTO shards(file_id, ix, size, checksum) VALUES(?, ?, ?, ?)")
                .bind(&meta.file_id)
                .bind(i64::from(shard.index))
                .bind(i64::try_from(shard.size).context("shard size exceeds i64")?)
                .bind(checksum)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// Removes a file and its shard metadata.
    ///
    /// # Errors
    /// Returns an error if either deletion fails.
    pub async fn remove_file(&self, file_id: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM remote_shards WHERE file_id = ?")
            .bind(file_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM shards WHERE file_id = ?")
            .bind(file_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM files WHERE id = ?")
            .bind(file_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Lists all file records ordered by creation timestamp descending.
    ///
    /// # Errors
    /// Returns an error if the query or timestamp parsing fails.
    pub async fn list_files(&self) -> Result<Vec<FileRecord>> {
        let rows = sqlx::query(
            "SELECT id, name, size, created_at, k, m, compressed FROM files ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut files = Vec::with_capacity(rows.len());
        for row in rows {
            let created_at_str: String = row.get("created_at");
            let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                .map(|dt| dt.with_timezone(&Utc))
                .with_context(|| format!("parsing timestamp {created_at_str}"))?;
            files.push(FileRecord {
                id: row.get("id"),
                name: row.try_get("name").ok(),
                size: row.get::<i64, _>("size"),
                created_at,
                k: row.get::<i64, _>("k"),
                m: row.get::<i64, _>("m"),
                compressed: row.get::<i64, _>("compressed") != 0,
            });
        }
        Ok(files)
    }

    /// Retrieves full details for a specific file, including shard metadata.
    ///
    /// # Errors
    /// Returns an error if database queries fail or timestamps cannot be parsed.
    pub async fn get_file(&self, file_id: &str) -> Result<Option<FileDetails>> {
        let row = sqlx::query(
            "SELECT id, name, size, created_at, k, m, compressed FROM files WHERE id = ?",
        )
        .bind(file_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };

        let created_at_str: String = row.get("created_at");
        let created_at = DateTime::parse_from_rfc3339(&created_at_str)
            .map(|dt| dt.with_timezone(&Utc))
            .with_context(|| format!("parsing timestamp {created_at_str}"))?;

        let record = FileRecord {
            id: row.get("id"),
            name: row.try_get("name").ok(),
            size: row.get::<i64, _>("size"),
            created_at,
            k: row.get::<i64, _>("k"),
            m: row.get::<i64, _>("m"),
            compressed: row.get::<i64, _>("compressed") != 0,
        };

        let shard_rows =
            sqlx::query("SELECT ix, size, checksum FROM shards WHERE file_id = ? ORDER BY ix")
                .bind(file_id)
                .fetch_all(&self.pool)
                .await?;
        let mut shards = Vec::with_capacity(shard_rows.len());
        for row in shard_rows {
            let checksum: Vec<u8> = row.get("checksum");
            let index = row.get::<i64, _>("ix");
            let size = row.get::<i64, _>("size");
            shards.push(ShardInfo {
                index: u8::try_from(index).context("shard index exceeds u8")?,
                size: usize::try_from(size).context("shard size negative")?,
                checksum: hex::encode(checksum),
            });
        }

        Ok(Some(FileDetails { record, shards }))
    }

    #[must_use]
    pub fn pool(&self) -> Pool<Sqlite> {
        self.pool.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::httpbucket;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use tempfile::tempdir;

    #[tokio::test]
    async fn insert_and_query_file() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let db = Database::connect(&db_path).await.unwrap();

        let meta = FileMeta {
            file_id: "file1".into(),
            name: Some("demo".into()),
            plaintext_size: 100,
            compressed_size: 80,
            ciphertext_size: 128,
            shard_size: 64,
            k: 3,
            m: 2,
            compressed: false,
            nonce: BASE64.encode([0_u8; 12]),
            checksums: vec![ShardInfo {
                index: 0,
                size: 64,
                checksum: "00".into(),
            }],
        };

        let created_at = Utc::now();
        db.insert_file(&meta, created_at).await.unwrap();

        let list = db.list_files().await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "file1");

        let details = db.get_file("file1").await.unwrap().unwrap();
        assert_eq!(details.shards.len(), 1);
    }

    #[tokio::test]
    async fn account_and_remote_tables() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let db = Database::connect(&db_path).await.unwrap();

        let account_id = db
            .create_account(
                "primary",
                httpbucket::BACKEND_ID,
                "https://example",
                "vault:token",
            )
            .await
            .unwrap();
        let accounts = db.list_accounts().await.unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, account_id);

        let file_meta = FileMeta {
            file_id: "file42".into(),
            name: None,
            plaintext_size: 0,
            compressed_size: 0,
            ciphertext_size: 0,
            shard_size: 0,
            k: 1,
            m: 1,
            compressed: false,
            nonce: BASE64.encode([0_u8; 12]),
            checksums: vec![ShardInfo {
                index: 1,
                size: 0,
                checksum: "00".into(),
            }],
        };
        db.insert_file(&file_meta, Utc::now()).await.unwrap();

        let record = RemoteShardRecord {
            file_id: "file42".into(),
            index: 1,
            account_id,
            remote_ref: "file42/shard_001.bin".into(),
            size: 1024,
            etag: Some("abc".into()),
        };
        db.upsert_remote_shard(&record).await.unwrap();

        let remotes = db.list_remote_shards("file42").await.unwrap();
        assert_eq!(remotes.len(), 1);
        assert_eq!(remotes[0].account_id, account_id);

        db.delete_remote_shard("file42", 1).await.unwrap();
        let remotes = db.list_remote_shards("file42").await.unwrap();
        assert!(remotes.is_empty());
    }
}
