//! A stream under a prefix of an object-store bucket: S3, R2 and MinIO (Stable); Google Cloud
//! Storage and Azure Blob behind the `experimental` feature.

use std::fmt;
use std::io;
use std::sync::Arc;

use object_store::path::Path;
use object_store::{
    Error as OsError, ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload, UpdateVersion,
};

use crate::{Listed, Object, Put, Store, Swap, Version, check_key};

/// A stream's objects under `prefix` in a bucket.
///
/// - put-if-absent: `PUT` with `If-None-Match: *`; the store answers 412 if the key exists.
/// - compare-and-swap: `PUT` with `If-Match: <ETag>` (`If-None-Match: *` when creating).
/// - A write is durable when the store acknowledges it (S3, R2 and MinIO acknowledge after
///   storing the object redundantly).
///
/// Opening runs a canary ([`Bucket::new`]): a store that accepts a conflicting conditional write
/// instead of answering 412 is refused, because two writers could then both win a batch.
#[derive(Clone)]
pub struct Bucket {
    inner: Arc<dyn ObjectStore>,
    prefix: String,
}

impl fmt::Debug for Bucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bucket({}/{})", self.inner, self.prefix)
    }
}

impl Bucket {
    /// Opens `url` and runs the canary. Credentials and endpoints come from the environment, as
    /// the providers' own tools read them:
    ///
    /// - `s3://bucket/prefix`: AWS S3, or MinIO and other S3-compatible stores with
    ///   `AWS_ENDPOINT_URL` (and `AWS_ALLOW_HTTP=true` for plain HTTP). `AWS_ACCESS_KEY_ID`,
    ///   `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, and the other `AWS_*` variables.
    /// - `r2://bucket/prefix`: Cloudflare R2 at `https://$CLOUDFLARE_ACCOUNT_ID.r2.cloudflarestorage.com`
    ///   (or `AWS_ENDPOINT_URL`), with an R2 API token's `AWS_ACCESS_KEY_ID` and
    ///   `AWS_SECRET_ACCESS_KEY`.
    /// - `gs://bucket/prefix` and `az://container/prefix` (Experimental, `experimental` feature):
    ///   the `GOOGLE_*` and `AZURE_*` variables.
    pub async fn open(url: &str) -> io::Result<Bucket> {
        let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
        let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
        if bucket.is_empty() {
            return Err(invalid(format!("{url}: no bucket")));
        }
        let inner: Arc<dyn ObjectStore> = match scheme {
            "s3" => Arc::new(
                object_store::aws::AmazonS3Builder::from_env()
                    .with_bucket_name(bucket)
                    .build()
                    .map_err(other)?,
            ),
            "r2" => {
                let mut b = object_store::aws::AmazonS3Builder::from_env()
                    .with_bucket_name(bucket)
                    .with_region("auto");
                let endpoint = std::env::var("AWS_ENDPOINT_URL")
                    .or_else(|_| std::env::var("AWS_ENDPOINT"))
                    .ok();
                if endpoint.is_none() {
                    let account = std::env::var("CLOUDFLARE_ACCOUNT_ID").map_err(|_| {
                        invalid(format!(
                            "{url}: set CLOUDFLARE_ACCOUNT_ID (or AWS_ENDPOINT_URL) for R2"
                        ))
                    })?;
                    b = b.with_endpoint(format!("https://{account}.r2.cloudflarestorage.com"));
                }
                Arc::new(b.build().map_err(other)?)
            }
            #[cfg(feature = "experimental")]
            "gs" => Arc::new(
                object_store::gcp::GoogleCloudStorageBuilder::from_env()
                    .with_bucket_name(bucket)
                    .build()
                    .map_err(other)?,
            ),
            #[cfg(feature = "experimental")]
            "az" => Arc::new(
                object_store::azure::MicrosoftAzureBuilder::from_env()
                    .with_container_name(bucket)
                    .build()
                    .map_err(other)?,
            ),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "{url}: unknown store (s3:// and r2://; gs:// and az:// with the \
                         `experimental` feature)"
                    ),
                ));
            }
        };
        Bucket::new(inner, prefix).await
    }

    /// A stream under `prefix` in any [`ObjectStore`] (`""`: at the bucket's root), after the
    /// canary: a put-if-absent on a fresh key under `canary/` must succeed, a second one on the
    /// same key must be refused (412), and so must a compare-and-swap from a wrong ETag.
    /// Otherwise the store is refused with [`io::ErrorKind::Unsupported`].
    pub async fn new(inner: Arc<dyn ObjectStore>, prefix: &str) -> io::Result<Bucket> {
        let prefix = prefix.trim_matches('/');
        if !prefix.is_empty() {
            check_key(prefix)?;
        }
        let b = Bucket {
            inner,
            prefix: prefix.to_owned(),
        };
        b.canary().await?;
        Ok(b)
    }

    async fn canary(&self) -> io::Result<()> {
        let mut r = [0u8; 16];
        getrandom::fill(&mut r).map_err(|e| io::Error::other(e.to_string()))?;
        let key = format!(
            "canary/{}",
            r.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        let refuse = |what: &str| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "{self:?} does not enforce conditional writes: {what}. Tenbri needs a store \
                     that answers 412 to If-None-Match: * on an existing key and to If-Match with \
                     a stale ETag (AWS S3, Cloudflare R2, MinIO); refusing to open it"
                ),
            )
        };
        let unsupported = |e: io::Error| {
            if e.kind() == io::ErrorKind::Unsupported {
                refuse(&e.to_string())
            } else {
                e
            }
        };
        if self.put_if_absent(&key, b"1").await.map_err(unsupported)? != Put::Created {
            return Err(refuse("a put-if-absent on a fresh key found it taken"));
        }
        let second = self.put_if_absent(&key, b"2").await.map_err(unsupported);
        let stale = Version("\"tenbri-canary-stale-etag\"".into());
        let swap = self
            .compare_and_swap(&key, Some(&stale), b"3")
            .await
            .map_err(unsupported);
        let kept = self.get(&key).await;
        self.delete(&key).await?;
        if second? != Put::Exists {
            return Err(refuse("a second put-if-absent on the same key succeeded"));
        }
        if swap? != Swap::Mismatch {
            return Err(refuse("a compare-and-swap from a stale ETag succeeded"));
        }
        if kept?.map(|o| o.bytes) != Some(b"1".to_vec()) {
            return Err(refuse("a refused write changed the object"));
        }
        Ok(())
    }

    fn path(&self, key: &str) -> io::Result<Path> {
        check_key(key)?;
        let full = if self.prefix.is_empty() {
            key.to_owned()
        } else {
            format!("{}/{key}", self.prefix)
        };
        Path::parse(full).map_err(|e| invalid(e.to_string()))
    }

    async fn put(&self, key: &str, bytes: &[u8], mode: PutMode) -> object_store::Result<Version> {
        let opts = PutOptions {
            mode,
            ..Default::default()
        };
        let path = self.path(key).map_err(|e| OsError::Generic {
            store: "tenbri",
            source: e.into(),
        })?;
        let r = self
            .inner
            .put_opts(&path, PutPayload::from(bytes.to_vec()), opts)
            .await?;
        Ok(version(r.e_tag, r.version))
    }
}

impl Store for Bucket {
    async fn get(&self, key: &str) -> io::Result<Option<Object>> {
        match self.inner.get(&self.path(key)?).await {
            Ok(r) => {
                let meta = r.meta.clone();
                let bytes = r.bytes().await.map_err(other)?.to_vec();
                Ok(Some(Object {
                    bytes,
                    version: version(meta.e_tag, meta.version),
                }))
            }
            Err(OsError::NotFound { .. }) => Ok(None),
            Err(e) => Err(other(e)),
        }
    }

    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> io::Result<Put> {
        match self.put(key, bytes, PutMode::Create).await {
            Ok(_) => Ok(Put::Created),
            // 412, or 409 when another conditional write to the key is in flight (S3).
            Err(OsError::AlreadyExists { .. } | OsError::Precondition { .. }) => Ok(Put::Exists),
            Err(e) => Err(other(e)),
        }
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&Version>,
        bytes: &[u8],
    ) -> io::Result<Swap> {
        let mode = match expected {
            None => PutMode::Create,
            Some(v) => PutMode::Update(update_version(v)),
        };
        match self.put(key, bytes, mode).await {
            Ok(v) => Ok(Swap::Swapped(v)),
            Err(
                OsError::AlreadyExists { .. }
                | OsError::Precondition { .. }
                | OsError::NotFound { .. },
            ) => Ok(Swap::Mismatch),
            Err(e) => Err(other(e)),
        }
    }

    async fn list(&self, prefix: &str) -> io::Result<Vec<Listed>> {
        use futures_util::TryStreamExt;
        let dir = self.path(prefix.trim_end_matches('/'))?;
        let metas: Vec<_> = self
            .inner
            .list(Some(&dir))
            .try_collect()
            .await
            .map_err(other)?;
        let strip = if self.prefix.is_empty() {
            0
        } else {
            self.prefix.len() + 1
        };
        let mut out: Vec<Listed> = metas
            .into_iter()
            .map(|m| Listed {
                key: m.location.as_ref()[strip..].to_owned(),
                modified: m.last_modified.into(),
            })
            .collect();
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(out)
    }

    async fn delete(&self, key: &str) -> io::Result<()> {
        match self.inner.delete(&self.path(key)?).await {
            Ok(()) | Err(OsError::NotFound { .. }) => Ok(()),
            Err(e) => Err(other(e)),
        }
    }
}

/// A [`Version`] from an ETag and, where the store has one (GCS generations), an object version.
fn version(e_tag: Option<String>, version: Option<String>) -> Version {
    match version {
        Some(v) => Version(format!("{}\n{v}", e_tag.unwrap_or_default())),
        None => Version(e_tag.unwrap_or_default()),
    }
}

fn update_version(v: &Version) -> UpdateVersion {
    let (e_tag, version) = match v.0.split_once('\n') {
        Some((e, v)) => (e, Some(v.to_owned())),
        None => (v.0.as_str(), None),
    };
    UpdateVersion {
        e_tag: (!e_tag.is_empty()).then(|| e_tag.to_owned()),
        version,
    }
}

fn other(e: OsError) -> io::Error {
    match e {
        OsError::NotFound { .. } => io::Error::new(io::ErrorKind::NotFound, e),
        OsError::NotImplemented { .. } | OsError::NotSupported { .. } => {
            io::Error::new(io::ErrorKind::Unsupported, e)
        }
        e => io::Error::other(e),
    }
}

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;
    use object_store::{
        CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta,
        PutMultipartOptions, PutResult,
    };

    /// A store that takes every write unconditionally, as a store without conditional writes does.
    #[derive(Debug)]
    struct Lying(InMemory);

    impl fmt::Display for Lying {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Lying")
        }
    }

    #[async_trait::async_trait]
    impl ObjectStore for Lying {
        async fn put_opts(
            &self,
            location: &Path,
            payload: PutPayload,
            _: PutOptions,
        ) -> object_store::Result<PutResult> {
            self.0
                .put_opts(location, payload, PutOptions::default())
                .await
        }
        async fn put_multipart_opts(
            &self,
            location: &Path,
            opts: PutMultipartOptions,
        ) -> object_store::Result<Box<dyn MultipartUpload>> {
            self.0.put_multipart_opts(location, opts).await
        }
        async fn get_opts(
            &self,
            location: &Path,
            options: GetOptions,
        ) -> object_store::Result<GetResult> {
            self.0.get_opts(location, options).await
        }
        fn delete_stream(
            &self,
            locations: futures_util::stream::BoxStream<'static, object_store::Result<Path>>,
        ) -> futures_util::stream::BoxStream<'static, object_store::Result<Path>> {
            self.0.delete_stream(locations)
        }
        fn list(
            &self,
            prefix: Option<&Path>,
        ) -> futures_util::stream::BoxStream<'static, object_store::Result<ObjectMeta>> {
            self.0.list(prefix)
        }
        async fn list_with_delimiter(
            &self,
            prefix: Option<&Path>,
        ) -> object_store::Result<ListResult> {
            self.0.list_with_delimiter(prefix).await
        }
        async fn copy_opts(
            &self,
            from: &Path,
            to: &Path,
            options: CopyOptions,
        ) -> object_store::Result<()> {
            self.0.copy_opts(from, to, options).await
        }
    }

    #[tokio::test]
    async fn conditional_writes_and_canary() {
        let s = Bucket::new(Arc::new(InMemory::new()), "/team/support/")
            .await
            .unwrap();
        assert_eq!(s.prefix, "team/support");
        assert_eq!(
            s.put_if_absent("batches/1.jsonl", b"a").await.unwrap(),
            Put::Created
        );
        assert_eq!(
            s.put_if_absent("batches/1.jsonl", b"b").await.unwrap(),
            Put::Exists
        );
        assert_eq!(s.get("batches/1.jsonl").await.unwrap().unwrap().bytes, b"a");
        assert!(s.get("../x").await.is_err());
        assert!(s.get("HEAD").await.unwrap().is_none());

        let Swap::Swapped(v1) = s.compare_and_swap("HEAD", None, b"1").await.unwrap() else {
            panic!()
        };
        assert_eq!(
            s.compare_and_swap("HEAD", None, b"x").await.unwrap(),
            Swap::Mismatch
        );
        assert_eq!(s.get("HEAD").await.unwrap().unwrap().version, v1);
        let Swap::Swapped(v2) = s.compare_and_swap("HEAD", Some(&v1), b"2").await.unwrap() else {
            panic!()
        };
        assert_eq!(
            s.compare_and_swap("HEAD", Some(&v1), b"3").await.unwrap(),
            Swap::Mismatch
        );
        assert_eq!(
            s.get("HEAD").await.unwrap().unwrap(),
            Object {
                bytes: b"2".to_vec(),
                version: v2
            }
        );

        let keys = |l: Vec<Listed>| l.into_iter().map(|l| l.key).collect::<Vec<_>>();
        assert_eq!(keys(s.list("batches/").await.unwrap()), ["batches/1.jsonl"]);
        s.delete("batches/1.jsonl").await.unwrap();
        s.delete("batches/1.jsonl").await.unwrap();
        assert!(s.list("batches/").await.unwrap().is_empty());
        // The canary cleaned up after itself.
        assert!(s.list("canary/").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn canary_refuses_a_store_without_conditional_writes() {
        let e = Bucket::new(Arc::new(Lying(InMemory::new())), "")
            .await
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
        assert!(
            e.to_string()
                .contains("a second put-if-absent on the same key succeeded"),
            "{e}"
        );
    }

    #[test]
    fn versions_round_trip() {
        for (e, v) in [
            (Some("\"abc\""), None),
            (Some("\"abc\""), Some("17")),
            (None, Some("9")),
        ] {
            let u = update_version(&version(e.map(Into::into), v.map(Into::into)));
            assert_eq!((u.e_tag.as_deref(), u.version.as_deref()), (e, v));
        }
    }
}
