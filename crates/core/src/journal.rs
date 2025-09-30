use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::fs;

use crate::model::{JournalEntry, JournalStage};
use crate::util::{utc_now, write_atomic};

#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
    entries: Vec<JournalEntry>,
}

impl Journal {
    /// Loads an on-disk journal or creates a new in-memory view when none exists.
    ///
    /// # Errors
    /// Returns an error if the journal file cannot be read or parsed.
    pub async fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            let bytes = fs::read(&path)
                .await
                .with_context(|| format!("reading journal {}", path.display()))?;
            let entries: Vec<JournalEntry> = serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing journal json {}", path.display()))?;
            Ok(Self { path, entries })
        } else {
            Ok(Self {
                path,
                entries: Vec::new(),
            })
        }
    }

    /// Returns the most recently recorded stage, defaulting to `JournalStage::Start`.
    #[must_use]
    pub fn current_stage(&self) -> JournalStage {
        self.entries
            .last()
            .map_or(JournalStage::Start, |entry| entry.stage.clone())
    }

    /// Appends a stage transition to the journal and persists it atomically.
    ///
    /// # Errors
    /// Returns an error if the journal cannot be written.
    pub async fn record(&mut self, stage: JournalStage) -> Result<()> {
        self.entries.push(JournalEntry {
            stage,
            updated_at: utc_now(),
        });
        let data = serde_json::to_vec_pretty(&self.entries)?;
        write_atomic(&self.path, &data).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn record_stages() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("journal.json");
        let mut journal = Journal::load(&path).await.unwrap();
        assert_eq!(journal.current_stage(), JournalStage::Start);
        journal.record(JournalStage::Encrypted).await.unwrap();
        assert_eq!(journal.current_stage(), JournalStage::Encrypted);

        let reloaded = Journal::load(&path).await.unwrap();
        assert_eq!(reloaded.current_stage(), JournalStage::Encrypted);
    }
}
