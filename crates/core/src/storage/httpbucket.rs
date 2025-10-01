use std::path::Path;

use anyhow::{anyhow, Context, Result};
use blake3::Hasher;
use futures::StreamExt;
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
    /// Creates a new HTTP bucket storage client.
    ///
    /// # Errors
    /// Returns an error if the underlying HTTP client cannot be constructed.
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
                .map_err(|()| anyhow!("endpoint must be a base URL"))?;
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
        pb.set_message(format!("{action} {locator}"));
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
                ProgressStyle::with_template(
                    "{spinner:.green} {msg}: {bytes} ({binary_bytes_per_sec})",
                )
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
            status => Err(anyhow!("unexpected status {status} during HEAD")),
        }
    }

    fn bearer(token: &str) -> Result<HeaderValue> {
        let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
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

    #[allow(clippy::too_many_lines)]
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
                pb.finish_with_message(format!("upload {locator} skipped (already present)"));
                return Ok(RemoteRef {
                    backend: sess.backend.clone(),
                    locator,
                    etag: meta.etag.clone(),
                });
            }
            upload_etag.clone_from(&meta.etag);
        }

        let url = Self::object_url(&sess.endpoint, &locator)?;

        let mut attempt = 0;
        loop {
            let resume_from = match (attempt, existing.as_ref()) {
                (0, Some(meta)) if meta.size > 0 && meta.size < total => {
                    let resumed = HumanBytes(meta.size);
                    let total_bytes = HumanBytes(total);
                    pb.println(format!(
                        "resuming {locator} from {resumed} of {total_bytes}"
                    ));
                    meta.size
                }
                _ => {
                    if attempt > 0 {
                        pb.println(format!("retrying full upload for {locator}"));
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
                let end = total.saturating_sub(1);
                let range = format!("bytes {resume_from}-{end}/{total}");
                request = request.header("Content-Range", range);
            }

            let response = request.send().await.context("performing PUT")?;

            if response.status().is_success() {
                if let Some(val) = response
                    .headers()
                    .get(ETAG)
                    .and_then(|header| header.to_str().ok())
                {
                    upload_etag = Some(val.trim_matches('\"').to_string());
                }
                break;
            }

            if resume_from == 0 {
                return Err(anyhow!("upload failed with status {}", response.status()));
            }

            attempt += 1;
            if attempt > 1 {
                return Err(anyhow!("failed to upload {locator} after retry"));
            }
        }

        let total_bytes = HumanBytes(total);
        pb.finish_with_message(format!("upload {locator} complete ({total_bytes})"));

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
            return Err(anyhow!("download failed with status {}", response.status()));
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
        pb.finish_with_message(format!("download {} complete", remote.locator));

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
            Err(anyhow!("delete failed with status {}", response.status()))
        }
    }

    async fn stat(&self, sess: &Session, remote: &RemoteRef) -> Result<ObjectMeta> {
        self.try_stat_locator(sess, &remote.locator)
            .await?
            .ok_or_else(|| anyhow!("remote object {} not found", remote.locator))
    }
}

#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::CHECKSUM_HEADER;
    use blake3::hash;
    use bytes::Bytes;
    use http::{header::HeaderMap, Request, Response};
    use httptest::responders::Responder;
    use httptest::{matchers::request, Expectation, Server};
    use hyper::body;
    use reqwest::header;
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use url::Url;

    #[derive(Clone, Default)]
    pub struct BucketState {
        inner: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    }

    impl BucketState {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        pub async fn len(&self) -> usize {
            self.inner.lock().await.len()
        }

        pub async fn replace(&self, path: &str, data: Vec<u8>) {
            self.inner.lock().await.insert(path.to_string(), data);
        }

        pub async fn get(&self, path: &str) -> Option<Vec<u8>> {
            self.inner.lock().await.get(path).cloned()
        }

        pub async fn paths(&self) -> Vec<String> {
            self.inner.lock().await.keys().cloned().collect()
        }
    }

    #[derive(Clone, Copy)]
    enum BucketOp {
        Head,
        Put { fail_range: bool },
        Get,
        Delete,
    }

    #[derive(Clone)]
    struct BucketResponder {
        state: BucketState,
        op: BucketOp,
    }

    impl BucketResponder {
        fn new(state: BucketState, op: BucketOp) -> Self {
            Self { state, op }
        }
    }

    impl Responder for BucketResponder {
        fn respond<'a>(
            &mut self,
            req: &'a Request<Bytes>,
        ) -> Pin<Box<dyn Future<Output = Response<body::Bytes>> + Send + 'a>> {
            let path = req.uri().path().to_string();
            let headers = req.headers().clone();
            let body = req.body().clone();
            let state = self.state.clone();
            let op = self.op;

            Box::pin(async move { handle_request(op, state, path, headers, body).await })
        }
    }

    fn parse_content_range(headers: &HeaderMap) -> Option<u64> {
        let value = headers.get("content-range")?;
        let text = value.to_str().ok()?;
        let text = text.strip_prefix("bytes ")?;
        let (range, _) = text.split_once('/')?;
        let (start, _) = range.split_once('-')?;
        start.parse().ok()
    }

    async fn handle_request(
        op: BucketOp,
        state: BucketState,
        path: String,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response<body::Bytes> {
        match op {
            BucketOp::Head => {
                let objects = state.inner.lock().await;
                if let Some(data) = objects.get(&path) {
                    let checksum = hash(&data[..]).to_hex().to_string();
                    Response::builder()
                        .status(200)
                        .header(header::CONTENT_LENGTH, data.len().to_string())
                        .header(header::ETAG, format!("\"{checksum}\""))
                        .header(CHECKSUM_HEADER, checksum)
                        .body(body::Bytes::new())
                        .unwrap()
                } else {
                    Response::builder()
                        .status(404)
                        .body(body::Bytes::new())
                        .unwrap()
                }
            }
            BucketOp::Get => {
                let objects = state.inner.lock().await;
                if let Some(data) = objects.get(&path) {
                    let checksum = hash(&data[..]).to_hex().to_string();
                    Response::builder()
                        .status(200)
                        .header(header::CONTENT_LENGTH, data.len().to_string())
                        .header(CHECKSUM_HEADER, checksum)
                        .body(body::Bytes::from(data.clone()))
                        .unwrap()
                } else {
                    Response::builder()
                        .status(404)
                        .body(body::Bytes::new())
                        .unwrap()
                }
            }
            BucketOp::Put { fail_range } => {
                if fail_range && headers.contains_key("content-range") {
                    return Response::builder()
                        .status(308)
                        .body(body::Bytes::new())
                        .unwrap();
                }

                let mut objects = state.inner.lock().await;
                let entry = objects.entry(path.clone()).or_default();
                if let Some(start) = parse_content_range(&headers) {
                    let start = start as usize;
                    if entry.len() > start {
                        entry.truncate(start);
                    } else if entry.len() < start {
                        entry.resize(start, 0);
                    }
                } else {
                    entry.clear();
                }

                entry.extend_from_slice(&body);
                let checksum = hash(&entry[..]).to_hex().to_string();
                Response::builder()
                    .status(201)
                    .header(header::ETAG, format!("\"{checksum}\""))
                    .body(body::Bytes::new())
                    .unwrap()
            }
            BucketOp::Delete => {
                let mut objects = state.inner.lock().await;
                let existed = objects.remove(&path).is_some();
                Response::builder()
                    .status(if existed { 204 } else { 404 })
                    .body(body::Bytes::new())
                    .unwrap()
            }
        }
    }

    #[allow(clippy::module_name_repetitions)]
    pub fn configure_bucket(server: &Server, state: BucketState, fail_range: bool) {
        server.expect(
            Expectation::matching(request::method("HEAD"))
                .times(..)
                .respond_with(BucketResponder::new(state.clone(), BucketOp::Head)),
        );
        server.expect(
            Expectation::matching(request::method("GET"))
                .times(..)
                .respond_with(BucketResponder::new(state.clone(), BucketOp::Get)),
        );
        server.expect(
            Expectation::matching(request::method("PUT"))
                .times(..)
                .respond_with(BucketResponder::new(
                    state.clone(),
                    BucketOp::Put { fail_range },
                )),
        );
        server.expect(
            Expectation::matching(request::method("DELETE"))
                .times(..)
                .respond_with(BucketResponder::new(state, BucketOp::Delete)),
        );
    }

    #[must_use]
    pub fn object_path(endpoint: &str, locator: &str) -> String {
        let base = Url::parse(endpoint).expect("invalid endpoint");
        let joined = base
            .join(locator.trim_start_matches('/'))
            .expect("failed to join locator");
        joined.path().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Credential;
    use crate::storage::httpbucket::test_support::{configure_bucket, object_path, BucketState};
    use httptest::Server;
    use tempfile::tempdir;
    use tokio::fs;

    fn credential(endpoint: &str) -> Credential {
        Credential {
            account_id: 1,
            backend: BACKEND_ID.to_string(),
            endpoint: endpoint.to_string(),
            token: "secret".into(),
            token_ref: "vault:token".into(),
        }
    }

    #[tokio::test]
    async fn upload_download_delete_cycle() {
        let server = Server::run();
        let bucket_state = BucketState::new();
        configure_bucket(&server, bucket_state.clone(), false);
        let endpoint = server.url("/bucket/").to_string();

        let storage = HttpBucketStorage::new().unwrap();
        let session = storage.login(&credential(&endpoint)).await.unwrap();

        let data = b"remote-bytes".to_vec();
        let shard_dir = tempdir().unwrap();
        let shard_path = shard_dir.path().join("shard.bin");
        fs::write(&shard_path, &data).await.unwrap();

        let locator = "file/shard_000.bin";
        let remote = storage
            .upload(&session, &shard_path, Some(locator))
            .await
            .unwrap();
        assert_eq!(remote.locator, locator);

        let meta = storage.stat(&session, &remote).await.unwrap();
        assert_eq!(meta.size, data.len() as u64);

        let download_path = shard_dir.path().join("download.bin");
        storage
            .download(&session, &remote, &download_path)
            .await
            .unwrap();
        let downloaded = fs::read(&download_path).await.unwrap();
        assert_eq!(downloaded, data);

        storage.delete(&session, &remote).await.unwrap();
        assert!(bucket_state
            .get(&object_path(&endpoint, locator))
            .await
            .is_none());

        let err = storage.stat(&session, &remote).await.unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn resume_retries_when_ranges_fail() {
        let server = Server::run();
        let bucket_state = BucketState::new();
        configure_bucket(&server, bucket_state.clone(), true);
        let endpoint = server.url("/").to_string();

        let storage = HttpBucketStorage::new().unwrap();
        let session = storage.login(&credential(&endpoint)).await.unwrap();

        let full_data = b"abcdefghijklmnopqrstuvwxyz".to_vec();
        let shard_dir = tempdir().unwrap();
        let shard_path = shard_dir.path().join("resume.bin");
        fs::write(&shard_path, &full_data).await.unwrap();

        let locator = "resume/shard_000.bin";
        let remote_path = object_path(&endpoint, locator);
        bucket_state
            .replace(&remote_path, full_data[..8].to_vec())
            .await;

        let remote = storage
            .upload(&session, &shard_path, Some(locator))
            .await
            .unwrap();
        assert_eq!(remote.locator, locator);

        let stored = bucket_state.get(&remote_path).await.unwrap();
        assert_eq!(stored, full_data);
        let meta = storage.stat(&session, &remote).await.unwrap();
        assert_eq!(meta.size, full_data.len() as u64);
        assert!(remote.etag.is_some());
    }
}
