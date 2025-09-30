use std::env;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use directories::BaseDirs;
use tokio::fs;
use tokio::io::AsyncWriteExt;

pub const ENV_HOME: &str = "AEGIS_FS_HOME";

#[derive(Clone, Debug)]
pub struct HomePaths {
    pub base: PathBuf,
    pub vault_path: PathBuf,
    pub objects_dir: PathBuf,
    pub state_db_path: PathBuf,
}

impl HomePaths {
    #[must_use]
    pub fn new(base: PathBuf) -> Self {
        let vault_path = base.join("vault.bin");
        let objects_dir = base.join("objects");
        let state_db_path = base.join("state.db");
        Self {
            base,
            vault_path,
            objects_dir,
            state_db_path,
        }
    }

    /// Ensures the home and objects directories exist.
    ///
    /// # Errors
    /// Returns an error if the directories cannot be created.
    pub async fn ensure(&self) -> Result<()> {
        fs::create_dir_all(&self.base)
            .await
            .with_context(|| format!("creating home directory at {}", self.base.display()))?;
        fs::create_dir_all(&self.objects_dir)
            .await
            .with_context(|| {
                format!(
                    "creating objects directory at {}",
                    self.objects_dir.display()
                )
            })?;
        Ok(())
    }
}

/// Resolves the workspace home directory using overrides, environment, or defaults.
///
/// # Errors
/// Returns an error if the user's home directory cannot be determined.
pub fn resolve_home(home_override: Option<&Path>) -> Result<HomePaths> {
    if let Some(path) = home_override {
        return Ok(HomePaths::new(expand_path(path)?));
    }

    if let Ok(env_path) = env::var(ENV_HOME) {
        return Ok(HomePaths::new(PathBuf::from(env_path)));
    }

    let base_dirs = BaseDirs::new().context("resolving user home directory")?;
    let default = base_dirs.home_dir().join(".aegis-fs");
    Ok(HomePaths::new(default))
}

/// Expands a filesystem path, handling a leading tilde to the current user's home.
///
/// # Errors
/// Returns an error if the home directory cannot be determined.
pub fn expand_path(path: &Path) -> Result<PathBuf> {
    let text = path.to_string_lossy();
    if let Some(stripped) = text.strip_prefix('~') {
        let base_dirs = BaseDirs::new().context("resolving user home directory")?;
        let home = base_dirs.home_dir();
        let joined = if stripped.is_empty() {
            home.to_path_buf()
        } else {
            home.join(stripped.trim_start_matches('/'))
        };
        Ok(joined)
    } else {
        Ok(PathBuf::from(path))
    }
}

#[must_use]
pub fn utc_now() -> DateTime<Utc> {
    Utc::now()
}

/// Writes data to a temporary file and renames it into place to provide atomic semantics.
///
/// # Errors
/// Returns an error if the temporary file cannot be written or renamed.
pub async fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp_path = path.with_extension("tmp");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("ensuring directory {}", parent.display()))?;
    }
    let mut file = fs::File::create(&tmp_path)
        .await
        .with_context(|| format!("creating temporary file {}", tmp_path.display()))?;
    file.write_all(data).await?;
    file.flush().await?;
    fs::rename(&tmp_path, path).await?;
    Ok(())
}
