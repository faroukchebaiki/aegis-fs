use std::path::Path;

use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use blake3::Hasher;
use indicatif::{HumanBytes, ProgressBar, ProgressStyle};
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_LENGTH, ETAG};
use reqwest::{Client, StatusCode};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};
use tokio_util::io::ReaderStream;
use url::Url;

use crate::model::{Credential, ObjectMeta, RemoteRef, Session};
use crate::storage::Storage;

pub const BACKEND_ID: &str = "httpbucket";
const CHECKSUM_HEADER: &str = "x-aegis-checksum";

pub struct HttpBucketStorage {
    client: Client,
}

impl HttpBucketStorage {
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .user_agent("aegis-fs-httpbucket/0.1")
            .build()
            .context("building reqwest client")?;
        Ok(Self { client })
    }

    fn object_url(base: &str, locator: &str) -> Result<Url> {
        let mut url = Url::parse(base).context("parsing bucket endpoint")?;
        let clean_locator = locator.trim_start_matches('/');
        let ends_with_slash = url.path().ends_with('/');
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("endpoint must be a base URL"))?;
            if !ends_with_slash {
                segments.pop_if_empty();
            }
            for segment in clean_locator.split('/') {
                segments.push(segment);
            }
        }
        Ok(url)
    }

    fn progress_bar(action: &str, locator: &str, len: Option<u64>) -> ProgressBar {
        let pb = match len {
            Some(total) => ProgressBar::new(total),
            None => ProgressBar::new_spinner(),
        };
        pb.set_message(format!("{} {}", action, locator));
        if len.is_some() {
            pb.set_style(
                ProgressStyle::with_template(
                    "{spinner:.green} {msg}: {bytes}/{total_bytes} ({binary_bytes_per_sec}, {eta})",
                )
                .unwrap()
                .progress_chars("=>"),
            );
        } else {
            pb.set_style(
                ProgressStyle::with_template("{spinner:.green} {msg}: {bytes} ({binary_bytes_per_sec})")
                    .unwrap(),
            );
        }
        pb
    }

    async fn try_stat_locator(&self, sess: &Session, locator: &str) -> Result<Option<ObjectMeta>> {
        let url = Self::object_url(&sess.endpoint, locator)?;
        let response = self
            .client
            .head(url)
            .header(AUTHORIZATION, Self::bearer(&sess.token)?)
            .send()
            .await
            .context("issuing HEAD request")?;

        match response.status() {
            StatusCode::OK => {
                let len = response
                    .headers()
                    .get(CONTENT_LENGTH)
                    .and_then(|val| val.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                let etag = response
                    .headers()
                    .get(ETAG)
                    .and_then(|val| val.to_str().ok())
                    .map(|s| s.trim_matches('\"').to_string());
                Ok(Some(ObjectMeta { size: len, etag }))
            }
            StatusCode::NOT_FOUND => Ok(None),
            status => Err(anyhow!("unexpected status {} during HEAD", status)),
        }
    }

    fn bearer(token: &str) -> Result<HeaderValue> {
        let mut value = HeaderValue::from_str(&format!("Bearer {}", token))
            .context("constructing bearer header")?;
        value.set_sensitive(true);
        Ok(value)
    }

    async fn compute_checksum(path: &Path) -> Result<String> {
        let mut file = fs::File::open(path)
            .await
            .with_context(|| format!("opening {} for checksum", path.display()))?;
        let mut hasher = Hasher::new();
        let mut buf = vec![0_u8; 8192];
        loop {
            let read = file.read(&mut buf).await?;
            if read == 0 {
                break;
            }
            hasher.update(&buf[..read]);
        }
        Ok(hasher.finalize().to_hex().to_string())
    }
}

#[async_trait::async_trait]
impl Storage for HttpBucketStorage {
    async fn login(&self, cred: &Credential) -> Result<Session> {
        // For now, login simply validates that the endpoint parses and returns the credential as session.
        let _ = Url::parse(&cred.endpoint).context("parsing endpoint during login")?;
        Ok(Session {
            account_id: cred.account_id,
            backend: cred.backend.clone(),
            endpoint: cred.endpoint.clone(),
            token: cred.token.clone(),
            token_ref: cred.token_ref.clone(),
        })
    }

    async fn upload(
        &self,
        sess: &Session,
        shard_path: &Path,
        remote_hint: Option<&str>,
    ) -> Result<RemoteRef> {
        let locator = remote_hint
            .map(|h| h.trim_start_matches('/').to_string())
            .or_else(|| {
                shard_path
                    .file_name()
                    .map(|name| name.to_string_lossy().to_string())
            })
            .ok_or_else(|| anyhow!("unable to determine remote object name"))?;

        let meta = fs::metadata(shard_path)
            .await
            .with_context(|| format!("reading metadata for {}", shard_path.display()))?;
        let total = meta.len();
        let checksum = Self::compute_checksum(shard_path).await?;
        let pb = Self::progress_bar("upload", &locator, Some(total));
        pb.set_position(0);

        let existing = self.try_stat_locator(sess, &locator).await?;
        let mut upload_etag: Option<String> = None;
        if let Some(ref meta) = existing {
            if meta.size == total {
                pb.finish_with_message(format!("upload {} skipped (already present)", &locator));
                return Ok(RemoteRef {
                    backend: sess.backend.clone(),
                    locator,
                    etag: meta.etag.clone(),
                });
            }
            upload_etag = meta.etag.clone();
        }

        let url = Self::object_url(&sess.endpoint, &locator)?;

        let mut attempt = 0;
        loop {
            let resume_from = match (attempt, existing.as_ref()) {
                (0, Some(meta)) if meta.size > 0 && meta.size < total => {
                    pb.println(format!(
                        "resuming {} from {} of {}",
                        locator,
                        HumanBytes(meta.size),
                        HumanBytes(total)
                    ));
                    meta.size
                }
                _ => {
                    if attempt > 0 {
                        pb.println(format!("retrying full upload for {}", locator));
                    }
                    0
                }
            };

            let mut file = fs::File::open(shard_path)
                .await
                .with_context(|| format!("opening shard {}", shard_path.display()))?;
            if resume_from > 0 {
                file.seek(SeekFrom::Start(resume_from)).await?;
                pb.set_position(resume_from);
            } else {
                pb.set_position(0);
            }

            let remaining = total - resume_from;
            let pb_clone = pb.clone();
            let mut transferred = resume_from;
            let stream = ReaderStream::new(file).map(move |chunk| {
                if let Ok(bytes) = &chunk {
                    transferred += bytes.len() as u64;
                    pb_clone.set_position(transferred);
                }
                chunk
            });

            let mut request = self
                .client
                .put(url.clone())
                .header(AUTHORIZATION, Self::bearer(&sess.token)?)
                .header(CONTENT_LENGTH, remaining)
                .header(CHECKSUM_HEADER, checksum.clone())
                .body(reqwest::Body::wrap_stream(stream));

            if resume_from > 0 {
                let range = format!("bytes {}-{}/{}", resume_from, total - 1, total);
                request = request.header("Content-Range", range);
            }

            let response = request.send().await.context("performing PUT")?;

            if response.status().is_success() {
                upload_etag = response
                    .headers()
                    .get(ETAG)
                    .and_then(|val| val.to_str().ok())
                    .map(|s| s.trim_matches('\"').to_string());
                break;
            }

            if resume_from == 0 {
                return Err(anyhow!(
                    "upload failed with status {}",
                    response.status()
                ));
            }

            attempt += 1;
            if attempt > 1 {
                return Err(anyhow!("failed to upload {} after retry", locator));
            }
        }

        pb.finish_with_message(format!(
            "upload {} complete ({})",
            &locator,
            HumanBytes(total)
        ));

        Ok(RemoteRef {
            backend: sess.backend.clone(),
            locator,
            etag: upload_etag,
        })
    }

    async fn download(&self, sess: &Session, remote: &RemoteRef, dst: &Path) -> Result<()> {
        let url = Self::object_url(&sess.endpoint, &remote.locator)?;
        let response = self
            .client
            .get(url)
            .header(AUTHORIZATION, Self::bearer(&sess.token)?)
            .send()
            .await
            .context("issuing GET request")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "download failed with status {}",
                response.status()
            ));
        }

        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("creating directory {}", parent.display()))?;
        }
        let tmp_path = dst.with_extension("part");
        let mut file = fs::File::create(&tmp_path)
            .await
            .with_context(|| format!("creating {}", tmp_path.display()))?;

        let total = response.content_length();
        let pb = Self::progress_bar("download", &remote.locator, total);

        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let bytes = chunk.context("reading download stream")?;
            file.write_all(&bytes).await?;
            pb.inc(bytes.len() as u64);
        }
        file.flush().await?;
        pb.finish_with_message(format!("download {} complete", &remote.locator));

        fs::rename(&tmp_path, dst)
            .await
            .with_context(|| format!("renaming {}", tmp_path.display()))?;
        Ok(())
    }

    async fn delete(&self, sess: &Session, remote: &RemoteRef) -> Result<()> {
        let url = Self::object_url(&sess.endpoint, &remote.locator)?;
        let response = self
            .client
            .delete(url)
            .header(AUTHORIZATION, Self::bearer(&sess.token)?)
            .send()
            .await
            .context("issuing DELETE request")?;

        if response.status().is_success() || response.status() == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(anyhow!(
                "delete failed with status {}",
                response.status()
            ))
        }
    }

    async fn stat(&self, sess: &Session, remote: &RemoteRef) -> Result<ObjectMeta> {
        self.try_stat_locator(sess, &remote.locator)
            .await?
            .ok_or_else(|| anyhow!("remote object {} not found", remote.locator))
    }
}
