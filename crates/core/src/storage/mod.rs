use std::path::Path;

use anyhow::Result;
use async_trait::async_trait;

use crate::model::{Credential, ObjectMeta, RemoteRef, Session};

pub mod httpbucket;

#[async_trait]
pub trait Storage: Send + Sync {
    async fn login(&self, cred: &Credential) -> Result<Session>;
    async fn upload(
        &self,
        sess: &Session,
        shard_path: &Path,
        remote_hint: Option<&str>,
    ) -> Result<RemoteRef>;
    async fn download(&self, sess: &Session, remote: &RemoteRef, dst: &Path) -> Result<()>;
    async fn delete(&self, sess: &Session, remote: &RemoteRef) -> Result<()>;
    async fn stat(&self, sess: &Session, remote: &RemoteRef) -> Result<ObjectMeta>;
}
