//! Blobs (§7.8): uploads, attachments and reads.
//!
//! Bytes live in R2 under `b/{bid}`: an id hashes its type, nonce and bytes
//! (§3.7), so the same id is always the same bytes and is stored once.
//! `res_blobs` holds the attachments: one attached row per (resource, blob),
//! with an empty `uploader`, and one pending row per uploader until a write
//! references the blob.

use super::*;
use patchlog_core::blob::{self, BlobRef};

/// `blobSize` (§12.2): 64 MiB by default; this deployment's maximum is 32
/// MiB, because an upload is held in memory while its id is checked.
pub(super) const BLOB_SIZE: u64 = 32 * 1024 * 1024;
/// `blobPending`, per uploader and namespace, counting at least 4 KiB a blob.
const BLOB_PENDING: u64 = 256 * 1024 * 1024;
/// `blobGrace`: pending entries older than this are ignored, and deleted
/// when their uploader next uploads.
const BLOB_GRACE_MS: i64 = 24 * 3600 * 1000;
/// `blobsPerDocument`.
const BLOBS_PER_DOCUMENT: usize = 1000;

pub(super) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS res_blobs (resource TEXT NOT NULL, bid TEXT NOT NULL, uploader TEXT NOT NULL, type TEXT NOT NULL, nonce TEXT, size INTEGER NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (resource, bid, uploader)) WITHOUT ROWID";

#[derive(Deserialize)]
struct BlobRow {
    uploader: String,
    #[serde(rename = "type")]
    media_type: String,
    nonce: Option<String>,
    size: i64,
}

fn r2_key(bid: &Id) -> String {
    format!("b/{bid}")
}

/// Headers every response to a blob URL carries (§7.8 Reading).
fn blob_headers(hd: &Headers, sandbox: bool) -> Res<()> {
    hd.set("X-Content-Type-Options", "nosniff")?;
    if sandbox {
        hd.set("Content-Security-Policy", "sandbox")?;
    }
    Ok(())
}

/// An error answer on a blob URL, with the headers §7.8 requires.
fn blob_err(e: Err) -> Res<Response> {
    let mut r = e.into_response(false).map_err(Err::from)?;
    let h = r.headers_mut();
    h.set("X-Content-Type-Options", "nosniff")?;
    h.set("Content-Security-Policy", "sandbox")?;
    Ok(r)
}

impl Namespace {
    /// Step 4 of §6.2 for blob references (§7.8): every reference in the
    /// resulting document must be well formed and name a blob available to
    /// the resource, with its type, size and nonce. Returns the statements
    /// that attach them at step 7.
    pub(super) fn check_blob_refs(&self, name: &str, doc: &Value, author: &str) -> Res<Vec<Stmt>> {
        let refs = blob::refs(doc).map_err(|m| Err::new(422, "blob", m))?;
        if refs.len() > BLOBS_PER_DOCUMENT {
            return Err(limit_err(
                422,
                "blobsPerDocument",
                refs.len() as u64,
                BLOBS_PER_DOCUMENT as u64,
            ));
        }
        let mut stmts = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for r in refs {
            if !seen.insert(r.bid) {
                continue;
            }
            let rows: Vec<BlobRow> = self.rows(
                "SELECT uploader, type, nonce, size FROM res_blobs WHERE resource = ?1 AND bid = ?2 AND (uploader = '' OR (uploader = ?3 AND created > ?4))",
                vec![name.into(), r.bid.text().into(), author.into(), (Date::now().as_millis() as i64 - BLOB_GRACE_MS).into()],
            )?;
            let row = rows
                .iter()
                .find(|x| x.uploader.is_empty())
                .or_else(|| rows.first());
            let Some(row) = row else {
                return Err(Err::new(
                    422,
                    "blob",
                    format!("blob {} isn't available to {name}", r.bid),
                ));
            };
            if row.media_type != r.media_type || row.size as u64 != r.size || row.nonce != r.nonce {
                return Err(Err::new(
                    422,
                    "blob",
                    format!(
                        "the reference to {} doesn't match the blob's type, size or nonce",
                        r.bid
                    ),
                ));
            }
            if !row.uploader.is_empty() {
                // Attached in the write's transaction, ending every pending entry.
                stmts.push((
                    "INSERT OR IGNORE INTO res_blobs (resource, bid, uploader, type, nonce, size, created) VALUES (?, ?, '', ?, ?, ?, ?)",
                    vec![name.into(), r.bid.text().into(), r.media_type.clone().into(), r.nonce.clone().into(), (r.size as i64).into(), (Date::now().as_millis() as i64).into()],
                ));
                stmts.push((
                    "DELETE FROM res_blobs WHERE resource = ? AND bid = ? AND uploader != ''",
                    vec![name.into(), r.bid.text().into()],
                ));
            }
        }
        Ok(stmts)
    }

    /// `PUT /r/{ns}/{name}/blob/{bid}`, in the order of checks §7.8 gives.
    pub(super) async fn put_blob(
        &self,
        ctx: &Ctx,
        name: &str,
        bid: &str,
        req: &mut Request,
    ) -> Res<Response> {
        match self.put_blob_inner(ctx, name, bid, req).await {
            Ok(r) => Ok(r),
            Err(e) => blob_err(e),
        }
    }

    async fn put_blob_inner(
        &self,
        ctx: &Ctx,
        name: &str,
        bid: &str,
        req: &mut Request,
    ) -> Res<Response> {
        let Some(bid) = Id::parse(bid) else {
            return Err(Err::bad("malformed blob id"));
        };
        let author = author(req.headers())?;
        // Checks 2 and 3: the namespace, frozen.
        let ns = self.existing()?;
        if ns.frozen {
            return Err(Err::new(409, "frozen", "the namespace is frozen"));
        }
        let hd = req.headers().clone();
        // Check 4: the type, the nonce, then a precondition.
        let copy_from = hd.get("Blob-From")?;
        let nonce = match hd.get("Blob-Nonce")? {
            None => None,
            Some(n) if patchlog_core::names::is_base32_26(&n) => Some(n),
            Some(_) => return Err(Err::bad("Blob-Nonce is 26 base32 characters")),
        };
        let media = match (&copy_from, hd.get("Content-Type")?) {
            (Some(_), _) => None,
            (None, Some(t)) => Some(
                blob::media_type(&t).ok_or_else(|| Err::bad("Content-Type isn't a media type"))?,
            ),
            (None, None) => return Err(Err::bad("an upload has a Content-Type")),
        };
        if hd.get("If-Match")?.is_some() || hd.get("If-None-Match")?.is_some() {
            return Err(Err::new(
                428,
                "precondition_required",
                "an upload takes no precondition",
            ));
        }
        if let Some(from) = copy_from {
            return self.copy_blob(ctx, name, &bid, &from, &author, req).await;
        }
        let media = media.unwrap();
        // Check 5: blobSize, then blobPending.
        if let Some(len) = hd
            .get("Content-Length")?
            .and_then(|l| l.parse::<u64>().ok())
        {
            if len > BLOB_SIZE {
                return Err(limit_err(413, "blobSize", len, BLOB_SIZE));
            }
        }
        let bytes = req.bytes().await?;
        let size = bytes.len() as u64;
        if size > BLOB_SIZE {
            return Err(limit_err(413, "blobSize", size, BLOB_SIZE));
        }
        self.check_pending(name, &bid, &author, size)?;
        // Check 6: the id over the body.
        if patchlog_core::id::blob_id(&media, nonce.as_deref().unwrap_or(""), &bytes) != bid {
            return Err(Err::new(
                422,
                "blob_mismatch",
                "the body doesn't hash to the blob id",
            ));
        }
        let bucket = self.env.bucket("BLOBS")?;
        if bucket.head(r2_key(&bid)).await?.is_none() {
            bucket
                .put(r2_key(&bid), bytes)
                .http_metadata(HttpMetadata {
                    content_type: Some(media.clone()),
                    ..Default::default()
                })
                .execute()
                .await?;
        }
        // Back in the object: the namespace may have changed while the body arrived.
        if self.existing()?.frozen {
            return Err(Err::new(409, "frozen", "the namespace is frozen"));
        }
        self.record_pending(ctx, name, &bid, &author, &media, nonce.as_deref(), size)?;
        let out = Headers::new();
        cache_headers(&out, Class::NoStore, false)?;
        blob_headers(&out, true)?;
        out.set("ETag", &quoted(&bid))?;
        http::respond(201, out, vec![])
    }

    fn check_pending(&self, name: &str, bid: &Id, author: &str, size: u64) -> Res<()> {
        #[derive(Deserialize)]
        struct Sum {
            n: Option<i64>,
        }
        let pending = self
            .one::<Sum>(
                "SELECT SUM(MAX(size, 4096)) AS n FROM res_blobs WHERE uploader = ?1 AND created > ?4 AND NOT (resource = ?2 AND bid = ?3)",
                vec![author.into(), name.into(), bid.text().into(), (Date::now().as_millis() as i64 - BLOB_GRACE_MS).into()],
            )?
            .and_then(|s| s.n)
            .unwrap_or(0) as u64;
        let with = pending + size.max(4096);
        if with > BLOB_PENDING {
            return Err(limit_err(413, "blobPending", with, BLOB_PENDING));
        }
        Ok(())
    }

    /// A pending entry for the uploader, unless the blob is attached to the
    /// resource already; uploading again restarts its time (§7.8).
    #[allow(clippy::too_many_arguments)]
    fn record_pending(
        &self,
        ctx: &Ctx,
        name: &str,
        bid: &Id,
        author: &str,
        media: &str,
        nonce: Option<&str>,
        size: u64,
    ) -> Res<()> {
        let attached: Option<BlobRow> = self.one(
            "SELECT uploader, type, nonce, size FROM res_blobs WHERE resource = ? AND bid = ? AND uploader = ''",
            vec![name.into(), bid.text().into()],
        )?;
        if attached.is_none() {
            self.commit(vec![
                (
                    "DELETE FROM res_blobs WHERE uploader = ? AND created <= ?",
                    vec![author.into(), (ctx.now - BLOB_GRACE_MS).into()],
                ),
                (
                "INSERT OR REPLACE INTO res_blobs (resource, bid, uploader, type, nonce, size, created) VALUES (?, ?, ?, ?, ?, ?, ?)",
                vec![name.into(), bid.text().into(), author.into(), media.into(), nonce.map(String::from).into(), (size as i64).into(), ctx.now.into()],
                ),
            ])?;
        }
        Ok(())
    }

    /// `Blob-From` (§7.8 Copying), within this namespace: the source must
    /// serve the blob; the copy is pending for the caller like an upload.
    async fn copy_blob(
        &self,
        ctx: &Ctx,
        name: &str,
        bid: &Id,
        from: &str,
        author: &str,
        req: &mut Request,
    ) -> Res<Response> {
        let body = req.bytes().await?;
        if !body.is_empty() {
            return Err(Err::bad("a copy has an empty body"));
        }
        let parts: Vec<&str> = from.split('/').collect();
        let (sns, sname, sbid) = match parts.as_slice() {
            ["", "r", sns, sname, "blob", sbid]
                if patchlog_core::names::is_namespace_name(sns)
                    && patchlog_core::names::is_resource_name(sname) =>
            {
                (*sns, *sname, *sbid)
            }
            _ => return Err(Err::bad("Blob-From is /r/{ns}/{name}/blob/{bid}")),
        };
        if Id::parse(sbid) != Some(*bid) {
            return Err(Err::new(422, "blob", "a copy keeps its blob id"));
        }
        if sns != ctx.ns {
            return Err(Err::not_offered(
                "copies from other namespaces aren't offered yet",
            ));
        }
        let src: Option<BlobRow> = self.one(
            "SELECT uploader, type, nonce, size FROM res_blobs WHERE resource = ? AND bid = ? AND uploader = ''",
            vec![sname.into(), bid.text().into()],
        )?;
        let Some(src) = src else {
            return Err(Err::not_found());
        };
        self.check_pending(name, bid, author, src.size as u64)?;
        self.record_pending(
            ctx,
            name,
            bid,
            author,
            &src.media_type,
            src.nonce.as_deref(),
            src.size as u64,
        )?;
        let out = Headers::new();
        cache_headers(&out, Class::NoStore, false)?;
        blob_headers(&out, true)?;
        out.set("ETag", &quoted(bid))?;
        http::respond(201, out, vec![])
    }

    /// `GET /r/{ns}/{name}/blob/{bid}` (§7.8 Reading), with ranges.
    pub(super) async fn get_blob(
        &self,
        ctx: &Ctx,
        name: &str,
        bid: &str,
        req: &Headers,
    ) -> Res<Response> {
        match self.get_blob_inner(ctx, name, bid, req).await {
            Ok(r) => Ok(r),
            Err(e) => blob_err(e),
        }
    }

    async fn get_blob_inner(
        &self,
        ctx: &Ctx,
        name: &str,
        bid: &str,
        req: &Headers,
    ) -> Res<Response> {
        let Some(bid) = Id::parse(bid) else {
            return Err(Err::bad("malformed blob id"));
        };
        let ns = self.existing()?;
        let row: Option<BlobRow> = self.one(
            "SELECT uploader, type, nonce, size FROM res_blobs WHERE resource = ? AND bid = ? AND uploader = ''",
            vec![name.into(), bid.text().into()],
        )?;
        // Pending and unknown blobs are 404.
        let Some(row) = row else {
            return Err(Err::not_found());
        };
        let hd = Headers::new();
        cache_headers(&hd, Class::Immutable, ns.public)?;
        tags(&hd, &ctx.ns, Some(name))?;
        let pdf = row.media_type == "application/pdf";
        blob_headers(&hd, !pdf)?;
        if pdf {
            hd.set("Content-Disposition", "attachment")?;
        }
        hd.set("ETag", &quoted(&bid))?;
        hd.set("Accept-Ranges", "bytes")?;
        let ctype = if row.media_type.starts_with("text/") {
            format!("{}; charset=utf-8", row.media_type)
        } else {
            row.media_type.clone()
        };
        hd.set("Content-Type", &ctype)?;
        if req.get("If-None-Match")?.is_some_and(|v| {
            v.split(',')
                .any(|t| t.trim() == quoted(&bid) || t.trim() == "*")
        }) {
            return http::respond(304, hd, vec![]);
        }
        let size = row.size as u64;
        let range = req.get("Range")?.and_then(|r| parse_range(&r, size));
        let bucket = self.env.bucket("BLOBS")?;
        let mut get = bucket.get(r2_key(&bid));
        let mut status = 200;
        match range {
            Some(Ok((start, end))) => {
                get = get.range(worker::Range::OffsetWithLength {
                    offset: start,
                    length: end - start + 1,
                });
                hd.set("Content-Range", &format!("bytes {start}-{end}/{size}"))?;
                status = 206;
            }
            Some(Err(())) => {
                hd.set("Content-Range", &format!("bytes */{size}"))?;
                return http::respond(416, hd, vec![]);
            }
            None => {}
        }
        let Some(obj) = get.execute().await? else {
            return Err(Err::new(500, "internal", "blob bytes missing from storage"));
        };
        let Some(body) = obj.body() else {
            return Err(Err::new(500, "internal", "no blob body"));
        };
        Ok(ResponseBuilder::new()
            .with_status(status)
            .with_headers(hd)
            .body(body.response_body()?))
    }

    /// `GET …/raw` and `…/rev/{id}/raw` (§7.1, §7.8 Files): a raw document's
    /// blob, by redirect; any other document is `404`.
    pub(super) fn get_raw(&self, ctx: &Ctx, name: &str, rev: Option<&str>) -> Res<Response> {
        let ns = self.existing()?;
        let (entry, class) = match rev {
            Some(id) => {
                let Some(id) = Id::parse(id) else {
                    return Err(Err::bad("malformed id"));
                };
                (
                    self.entry_by_id(name, &id)?.ok_or_else(Err::not_found)?,
                    Class::Immutable,
                )
            }
            None => {
                let head = self.resource(name)?.ok_or_else(Err::not_found)?;
                (self.entry_by_seq(name, head.seq)?, Class::HeadPointer)
            }
        };
        if entry.kind == TOMBSTONE {
            return Err(Err::new(410, "gone", "the resource is deleted").class(class));
        }
        let doc = self.doc_at(name, entry.seq, false)?;
        let Some(BlobRef { bid, .. }) = blob::raw(&doc) else {
            return Err(Err::not_found().with("message", s("not a raw document")));
        };
        let hd = Headers::new();
        cache_headers(&hd, class, ns.public)?;
        tags(&hd, &ctx.ns, Some(name))?;
        hd.set("Location", &format!("/r/{}/{}/blob/{}", ctx.ns, name, bid))?;
        http::respond(302, hd, vec![])
    }
}

/// A single `bytes=` range: `Ok((first, last))`, `Err` if unsatisfiable,
/// `None` if absent or not one this server serves (then the whole blob).
fn parse_range(h: &str, size: u64) -> Option<Result<(u64, u64), ()>> {
    let spec = h.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (a, b) = spec.split_once('-')?;
    let (a, b) = (a.trim(), b.trim());
    let r = if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        if n == 0 || size == 0 {
            return Some(Err(()));
        }
        (size.saturating_sub(n), size - 1)
    } else {
        let start: u64 = a.parse().ok()?;
        let end: u64 = if b.is_empty() {
            size.saturating_sub(1)
        } else {
            b.parse::<u64>().ok()?.min(size.saturating_sub(1))
        };
        if start >= size || end < start {
            return Some(Err(()));
        }
        (start, end)
    };
    Some(Ok(r))
}
