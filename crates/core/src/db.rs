use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous};
use sqlx::{Pool, Row, Sqlite};
use std::convert::TryFrom;
use tokio::fs;

use crate::model::{FileDetails, FileMeta, FileRecord, ShardInfo};

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
}
