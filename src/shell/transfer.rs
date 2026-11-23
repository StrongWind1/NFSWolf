//! Pipelined file transfer for `get` and `put`, shared by every NFS version.
//!
//! A transfer that waits for each READ or WRITE reply before sending the next
//! request is bound by round-trip time, not bandwidth: at a few hundred
//! microseconds per round trip, 64 KiB at a time cannot pass a few hundred
//! MB/s no matter how fast the link is. Three things lift that ceiling:
//!
//! * **Several requests in flight.** Up to [`pipeline_depth`] calls run at
//!   once, each on its own pooled connection, and their results are consumed
//!   in file order.
//! * **The server's transfer size.** [`ShellOps::io_sizes`] reports what the
//!   server prefers (1 MiB on Linux) instead of a fixed 64 KiB.
//! * **Unstable writes.** A disk-backed server syncs on every `FILE_SYNC`
//!   write. Writing `UNSTABLE` and committing once at the end (RFC 1813
//!   sec. 3.3.7 and 3.3.21, RFC 7530 sec. 16.36) moves that cost to a single
//!   COMMIT, and the write verifiers prove nothing was lost in between.

use std::collections::VecDeque;
use std::future::poll_fn;
use std::pin::Pin;
use std::task::Poll;

use indicatif::ProgressBar;
use tokio::sync::Semaphore;
use tokio::sync::mpsc::Sender;

use super::ops::{READ_ALL_MAX, ReadReply, ShellHandle, ShellOps, WriteReply};

/// Bytes a transfer aims to keep in flight: enough to cover the
/// bandwidth-delay product of a fast LAN, so the link rather than the round
/// trip sets the pace.
const TARGET_IN_FLIGHT: u64 = 4 * 1024 * 1024;

/// Fewest calls a transfer keeps in flight, however large each one is.
const MIN_PIPELINE_DEPTH: usize = 4;

/// Most calls a transfer keeps in flight, however small each one is.
///
/// Each runs on its own pooled connection, so the shell's pool keeps this many
/// idle connections per identity: with fewer, the surplus would be closed when
/// handed back and reopened -- MOUNT included -- by the next transfer.
pub(crate) const MAX_PIPELINE_DEPTH: usize = 16;

/// Calls to keep in flight for `chunk`-byte transfers: about
/// [`TARGET_IN_FLIGHT`] bytes' worth, within
/// [`MIN_PIPELINE_DEPTH`]..=[`MAX_PIPELINE_DEPTH`]. 1 MiB chunks get 4;
/// NFSv2's 8 KiB chunks get 16.
pub(crate) fn pipeline_depth(chunk: u32) -> usize {
    let wanted = TARGET_IN_FLIGHT.div_ceil(u64::from(chunk.max(1)));
    usize::try_from(wanted).unwrap_or(MAX_PIPELINE_DEPTH).clamp(MIN_PIPELINE_DEPTH, MAX_PIPELINE_DEPTH)
}

/// How many decoded chunks may queue for the local writer before the
/// transfer waits for it.
pub(crate) const SINK_QUEUE: usize = MAX_PIPELINE_DEPTH;

/// A cap on READ and WRITE calls in flight, shared by every file of one
/// transfer.
///
/// A single file stays within [`pipeline_depth`] on its own, but a recursive
/// transfer moves several files at once, and their calls together must stay
/// within the pool's idle connections or the surplus is closed and reopened.
/// Every READ and WRITE takes a permit for exactly as long as it is in flight,
/// never while waiting on another, so permits cannot deadlock.
pub(crate) type Budget = Semaphore;

/// Files a recursive `get -r` or `put -r` moves at once.
///
/// Small files are mostly round trips -- a LOOKUP or CREATE, then a READ or
/// a WRITE -- so overlapping several hides the latency.
pub(crate) const TREE_PARALLEL_FILES: usize = 8;

/// A budget for a recursive transfer.
///
/// Leaves room within the pool's [`MAX_PIPELINE_DEPTH`] idle connections for
/// the LOOKUP or CREATE each of the [`TREE_PARALLEL_FILES`] files may have in
/// flight alongside the READs and WRITEs.
pub(crate) fn tree_budget() -> Budget {
    Semaphore::new(MAX_PIPELINE_DEPTH - TREE_PARALLEL_FILES)
}

/// A budget for one file: as many calls as any window would issue.
pub(crate) fn single_file_budget() -> Budget {
    Semaphore::new(MAX_PIPELINE_DEPTH)
}

/// Run `call` holding one permit of `budget`.
async fn limited<T>(budget: &Budget, call: impl Future<Output = T>) -> T {
    // The semaphore is never closed, so `acquire` cannot fail; if it somehow
    // did, running unthrottled is still correct.
    let _permit = budget.acquire().await.ok();
    call.await
}

/// Run `jobs` with up to `depth` at once and return their outputs in order.
pub(crate) async fn run_concurrently<T>(depth: usize, jobs: impl IntoIterator<Item = impl Future<Output = T> + Send + '_>) -> Vec<T> {
    let mut window = Window::new();
    let mut outputs = Vec::new();
    for job in jobs {
        if window.len() >= depth.max(1)
            && let Some(output) = window.next().await
        {
            outputs.push(output);
        }
        window.push(job);
    }
    while let Some(output) = window.next().await {
        outputs.push(output);
    }
    outputs
}

/// One in-flight call and, once it has finished, its output.
struct Slot<'a, T> {
    future: Option<Pin<Box<dyn Future<Output = T> + Send + 'a>>>,
    output: Option<T>,
}

/// Futures that run concurrently but hand back their outputs in the order
/// they were pushed.
///
/// Every unfinished future is polled whenever the task wakes, so all of them
/// make progress while the caller waits on the oldest.
struct Window<'a, T> {
    slots: VecDeque<Slot<'a, T>>,
}

impl<'a, T> Window<'a, T> {
    const fn new() -> Self {
        Self { slots: VecDeque::new() }
    }

    fn len(&self) -> usize {
        self.slots.len()
    }

    fn push(&mut self, future: impl Future<Output = T> + Send + 'a) {
        self.slots.push_back(Slot { future: Some(Box::pin(future)), output: None });
    }

    /// The oldest future's output, once it is ready; `None` when empty.
    async fn next(&mut self) -> Option<T> {
        poll_fn(|cx| {
            for slot in &mut self.slots {
                if let Some(future) = slot.future.as_mut()
                    && let Poll::Ready(output) = future.as_mut().poll(cx)
                {
                    slot.output = Some(output);
                    slot.future = None;
                }
            }
            if let Some(output) = self.slots.front_mut().and_then(|slot| slot.output.take()) {
                // The slot is spent: its future finished and its output was taken.
                drop(self.slots.pop_front());
                return Poll::Ready(Some(output));
            }
            if self.slots.is_empty() { Poll::Ready(None) } else { Poll::Pending }
        })
        .await
    }

    /// Let everything still in flight finish, discarding the results.
    ///
    /// Dropping a call mid-flight would make the pool discard its connection
    /// (the stream is out of step), so an early exit waits instead.
    async fn drain(&mut self) {
        while self.next().await.is_some() {}
    }
}

/// Read `fh` from the start, sending each piece of data to `out` in file
/// order. Returns the number of bytes read.
///
/// The data goes through a channel so the consumer -- hashing and writing a
/// local file, both slower than the network on a modest CPU -- runs on its
/// own thread while the next READs are in flight, instead of in series with
/// them. A full channel holds the transfer back.
///
/// `size_hint` is the file size from GETATTR. Reads are issued up to it in
/// parallel, then one past it if the server has not yet said end-of-file, so
/// a file that grew is still read to its end. A short reply mid-file is legal
/// (RFC 1813 sec. 3.3.6): the missing bytes are read again before anything
/// after them is passed on.
pub(crate) async fn download<O: ShellOps>(ops: &O, fh: &ShellHandle, size_hint: u64, out: &Sender<Vec<u8>>, progress: Option<&ProgressBar>, budget: &Budget) -> anyhow::Result<u64> {
    let chunk = ops.io_sizes(fh).await.read;
    let depth = pipeline_depth(chunk);
    tracing::debug!(chunk, size_hint, depth, "download");
    let mut delivered = 0u64;

    // The first READ goes alone: if the caller's identity is refused, the
    // credential ladder runs once and caches the identity that works, instead
    // of every parallel read walking it at the same time.
    let first = limited(budget, ops.read_at(fh, 0, chunk)).await?;
    let mut done = accept(ops, fh, 0, chunk, first, &mut delivered, out, budget).await?;
    report(progress, delivered);

    let mut window = Window::new();
    let mut next = delivered;
    while !done {
        let horizon = size_hint.max(delivered.saturating_add(u64::from(chunk)));
        while window.len() < depth && next < horizon {
            let offset = next;
            window.push(async move { (offset, limited(budget, ops.read_at(fh, offset, chunk)).await) });
            next = next.saturating_add(u64::from(chunk));
        }
        let Some((offset, reply)) = window.next().await else { break };
        let outcome = match reply {
            Ok(reply) => accept(ops, fh, offset, chunk, reply, &mut delivered, out, budget).await,
            Err(e) => Err(e),
        };
        done = match outcome {
            Ok(done) => done,
            Err(e) => {
                window.drain().await;
                return Err(e);
            },
        };
        report(progress, delivered);
        if delivered > READ_ALL_MAX {
            window.drain().await;
            anyhow::bail!("download aborted at {delivered} bytes: exceeds {READ_ALL_MAX}-byte cap (untrusted server returning endless non-EOF data)");
        }
    }
    window.drain().await;
    Ok(delivered)
}

/// Read all of `fh` into memory with [`download`].
///
/// `size_hint` comes from the server, so it only seeds the buffer's capacity
/// up to a bound; the buffer grows with the data actually received.
pub(crate) async fn read_whole<O: ShellOps>(ops: &O, fh: &ShellHandle, size_hint: u64) -> anyhow::Result<Vec<u8>> {
    const PREALLOC_LIMIT: u64 = 16 * 1024 * 1024;
    let budget = single_file_budget();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(SINK_QUEUE);
    let fetch = async move {
        let fetched = download(ops, fh, size_hint, &tx, None, &budget).await;
        // Closing the channel ends the collector below.
        drop(tx);
        fetched
    };
    let collect = async move {
        let mut buf = Vec::with_capacity(usize::try_from(size_hint.min(PREALLOC_LIMIT)).unwrap_or(0));
        while let Some(data) = rx.recv().await {
            buf.extend_from_slice(&data);
        }
        buf
    };
    let (fetched, buf) = tokio::join!(fetch, collect);
    let _ = fetched?;
    Ok(buf)
}

/// Pass on one READ reply for the `chunk` bytes at `offset`, first reading
/// whatever part of that range a short reply left out. Returns whether the
/// end of the file has been reached.
async fn accept<O: ShellOps>(ops: &O, fh: &ShellHandle, offset: u64, chunk: u32, mut reply: ReadReply, delivered: &mut u64, out: &Sender<Vec<u8>>, budget: &Budget) -> anyhow::Result<bool> {
    let end = offset.saturating_add(u64::from(chunk));
    loop {
        let len = reply.data.len();
        if len > 0 {
            out.send(reply.data).await.map_err(|_| anyhow::anyhow!("download destination closed"))?;
        }
        *delivered = delivered.saturating_add(len as u64);
        // An empty reply without the flag is treated as the end too: there is
        // no offset to make progress from.
        if reply.eof || len == 0 {
            return Ok(true);
        }
        if *delivered >= end {
            return Ok(false);
        }
        let missing = u32::try_from(end - *delivered).unwrap_or(chunk);
        reply = limited(budget, ops.read_at(fh, *delivered, missing)).await?;
    }
}

fn report(progress: Option<&ProgressBar>, position: u64) {
    if let Some(pb) = progress {
        pb.set_position(position);
    }
}

/// Write `data` to `fh` starting at `start_offset`. Returns the bytes
/// written.
///
/// Writes go out `UNSTABLE`, several at once, then one COMMIT makes them
/// durable; data that fits in a single WRITE is written durably instead. Each WRITE and the COMMIT return the server's write verifier; if
/// they do not all match, the server restarted in between and may have lost
/// cached data, so everything is written again durably. Versions without
/// unstable writes (NFSv2) write durably from the start.
pub(crate) async fn upload<O: ShellOps>(ops: &O, fh: &ShellHandle, data: &[u8], start_offset: u64, progress: Option<&ProgressBar>, budget: &Budget) -> anyhow::Result<u64> {
    let chunk = usize::try_from(ops.io_sizes(fh).await.write).unwrap_or(usize::MAX).max(1);
    tracing::debug!(chunk, len = data.len(), depth = pipeline_depth(u32::try_from(chunk).unwrap_or(u32::MAX)), "upload");
    // One WRITE's worth goes out durably: FILE_SYNC costs the server one
    // sync either way, and skips the COMMIT round trip an unstable write
    // would need -- which, across a tree of small files, is one round trip
    // per file.
    let stability = if data.len() <= chunk { Stability::Stable } else { Stability::Unstable };
    let verifiers = write_all(ops, fh, data, start_offset, chunk, stability, progress, budget).await?;
    if let Some(written) = verifiers {
        let committed = ops.write_verifier(fh).await?;
        if !written.matches(committed) {
            tracing::warn!("write verifier changed during upload (server restart); rewriting durably");
            let _ = write_all(ops, fh, data, start_offset, chunk, Stability::Stable, progress, budget).await?;
        }
    }
    Ok(data.len() as u64)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stability {
    /// `write_unstable`, to be followed by a COMMIT.
    Unstable,
    /// `write_chunk`: durable when the reply arrives.
    Stable,
}

/// The write verifiers seen across a transfer's unstable writes.
#[derive(Debug, Clone, Copy)]
struct Verifiers {
    first: [u8; 8],
    consistent: bool,
}

impl Verifiers {
    /// Whether the COMMIT verifier vouches for every unstable write.
    fn matches(self, committed: Option<[u8; 8]>) -> bool {
        self.consistent && committed == Some(self.first)
    }
}

/// Write all of `data` in `chunk`-sized pieces with up to
/// [`pipeline_depth`] in flight. Returns the verifiers of the writes the server left unstable,
/// or `None` when every byte is already durable.
async fn write_all<O: ShellOps>(ops: &O, fh: &ShellHandle, data: &[u8], start_offset: u64, chunk: usize, stability: Stability, progress: Option<&ProgressBar>, budget: &Budget) -> anyhow::Result<Option<Verifiers>> {
    let mut verifiers: Option<Verifiers> = None;
    let mut record = |reply: &WriteReply| {
        if reply.stable {
            return;
        }
        let verifier = reply.verifier.unwrap_or_default();
        match verifiers.as_mut() {
            None => verifiers = Some(Verifiers { first: verifier, consistent: true }),
            Some(v) => v.consistent &= v.first == verifier,
        }
    };

    let depth = pipeline_depth(u32::try_from(chunk).unwrap_or(u32::MAX));
    let mut window = Window::new();
    let mut issued = 0usize;
    let mut written = 0usize;
    while written < data.len() {
        while window.len() < depth && issued < data.len() {
            let end = issued.saturating_add(chunk).min(data.len());
            let piece = data.get(issued..end).unwrap_or_default();
            let at = issued;
            window.push(async move { (at, piece.len(), limited(budget, write_one(ops, fh, start_offset.saturating_add(at as u64), piece, stability)).await) });
            issued = end;
        }
        let Some((at, len, reply)) = window.next().await else { break };
        let outcome = match reply {
            Ok(reply) => {
                record(&reply);
                finish_short_write(ops, fh, data, start_offset, (at, len), &reply, stability, &mut record, budget).await
            },
            Err(e) => Err(e),
        };
        if let Err(e) = outcome {
            window.drain().await;
            return Err(e);
        }
        written = at.saturating_add(len);
        report(progress, written as u64);
    }
    window.drain().await;
    Ok(verifiers)
}

async fn write_one<O: ShellOps>(ops: &O, fh: &ShellHandle, offset: u64, piece: &[u8], stability: Stability) -> anyhow::Result<WriteReply> {
    match stability {
        Stability::Unstable => ops.write_unstable(fh, offset, piece).await,
        Stability::Stable => Ok(WriteReply { count: ops.write_chunk(fh, offset, piece).await?, stable: true, verifier: None }),
    }
}

/// After the WRITE of `data[at..at + len]` returned `reply`, write whatever
/// tail of that piece it did not accept. A short write is legal (RFC 1813
/// sec. 3.3.7); a write that accepts nothing is an error, since retrying it
/// would loop forever.
async fn finish_short_write<O: ShellOps>(ops: &O, fh: &ShellHandle, data: &[u8], start_offset: u64, (at, len): (usize, usize), reply: &WriteReply, stability: Stability, record: &mut impl FnMut(&WriteReply), budget: &Budget) -> anyhow::Result<()> {
    let end = at.saturating_add(len);
    let mut pos = at;
    let mut accepted = usize::try_from(reply.count).unwrap_or(usize::MAX).min(len);
    loop {
        if accepted == 0 {
            anyhow::bail!("WRITE at {}: server acknowledged 0 bytes (no progress)", start_offset.saturating_add(pos as u64));
        }
        pos = pos.saturating_add(accepted);
        if pos >= end {
            return Ok(());
        }
        let rest = data.get(pos..end).unwrap_or_default();
        let retry = limited(budget, write_one(ops, fh, start_offset.saturating_add(pos as u64), rest, stability)).await?;
        record(&retry);
        accepted = usize::try_from(retry.count).unwrap_or(usize::MAX).min(rest.len());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;
    use crate::shell::ops::{IoSizes, ShellDeviceType, ShellEntry, ShellFileInfo, ShellFsStat, ShellSetAttr};

    /// How the fake server behaves.
    #[derive(Debug, Clone, Copy)]
    struct Behaviour {
        /// Delay of every READ and WRITE, so concurrent calls overlap.
        latency: Duration,
        sizes: IoSizes,
        /// Most bytes one READ returns or one WRITE accepts: smaller than the
        /// transfer size simulates short replies.
        max_reply: usize,
        /// Whether READ reports end-of-file (NFSv3/v4 do; a missing flag is
        /// the fallback path).
        eof_flag: bool,
        /// Whether unstable writes exist (NFSv3/v4) or not (NFSv2).
        unstable: bool,
        /// Whether the server "restarts" before the first COMMIT, losing what
        /// was written unstably and changing its write verifier.
        restart_before_commit: bool,
    }

    impl Behaviour {
        const fn nfs3() -> Self {
            Self { latency: Duration::from_millis(2), sizes: IoSizes { read: 65_536, write: 65_536 }, max_reply: usize::MAX, eof_flag: true, unstable: true, restart_before_commit: false }
        }

        /// NFSv2: 8 KiB transfers, no unstable writes.
        const fn nfs2() -> Self {
            Self { sizes: IoSizes { read: 8192, write: 8192 }, unstable: false, ..Self::nfs3() }
        }
    }

    /// An in-memory file behind the `ShellOps` calls a transfer makes.
    struct FakeOps {
        behaviour: Behaviour,
        file: Mutex<Vec<u8>>,
        verifier: Mutex<[u8; 8]>,
        restarted: AtomicBool,
        in_flight: AtomicUsize,
        peak: AtomicUsize,
        commits: AtomicUsize,
        stable_writes: AtomicUsize,
        observed: crate::shell::ops::ObservedIdentities,
    }

    /// Counts a call as in flight for as long as it lives.
    struct InFlight<'a>(&'a FakeOps);

    impl Drop for InFlight<'_> {
        fn drop(&mut self) {
            let _ = self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl FakeOps {
        fn new(behaviour: Behaviour, contents: Vec<u8>) -> Self {
            Self {
                behaviour,
                file: Mutex::new(contents),
                verifier: Mutex::new([1; 8]),
                restarted: AtomicBool::new(false),
                in_flight: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                commits: AtomicUsize::new(0),
                stable_writes: AtomicUsize::new(0),
                observed: crate::shell::ops::ObservedIdentities::default(),
            }
        }

        async fn call(&self) -> InFlight<'_> {
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            let _ = self.peak.fetch_max(now, Ordering::SeqCst);
            let guard = InFlight(self);
            tokio::time::sleep(self.behaviour.latency).await;
            guard
        }

        fn store(&self, offset: u64, data: &[u8]) -> u32 {
            let accepted = &data[..data.len().min(self.behaviour.max_reply)];
            let mut file = self.file.lock().unwrap();
            let start = usize::try_from(offset).unwrap();
            if file.len() < start + accepted.len() {
                file.resize(start + accepted.len(), 0);
            }
            file[start..start + accepted.len()].copy_from_slice(accepted);
            u32::try_from(accepted.len()).unwrap()
        }

        fn contents(&self) -> Vec<u8> {
            self.file.lock().unwrap().clone()
        }
    }

    struct NoCompleter;

    impl crate::shell::complete::RemoteCompleter for NoCompleter {
        fn list_dir_entries(&self, _handle: &[u8]) -> Vec<String> {
            Vec::new()
        }

        fn resolve_path(&self, _start: &[u8], _path: &str) -> Option<Vec<u8>> {
            None
        }
    }

    impl ShellOps for FakeOps {
        async fn read_at(&self, _fh: &ShellHandle, offset: u64, count: u32) -> anyhow::Result<ReadReply> {
            let _call = self.call().await;
            let file = self.file.lock().unwrap();
            let start = usize::try_from(offset).unwrap().min(file.len());
            let end = start.saturating_add((count as usize).min(self.behaviour.max_reply)).min(file.len());
            let eof = self.behaviour.eof_flag && end == file.len();
            Ok(ReadReply { data: file[start..end].to_vec(), eof })
        }

        async fn write_chunk(&self, _fh: &ShellHandle, offset: u64, data: &[u8]) -> anyhow::Result<u32> {
            let _call = self.call().await;
            let _ = self.stable_writes.fetch_add(1, Ordering::SeqCst);
            Ok(self.store(offset, data))
        }

        async fn write_unstable(&self, fh: &ShellHandle, offset: u64, data: &[u8]) -> anyhow::Result<WriteReply> {
            if !self.behaviour.unstable {
                return Ok(WriteReply { count: self.write_chunk(fh, offset, data).await?, stable: true, verifier: None });
            }
            let _call = self.call().await;
            let count = self.store(offset, data);
            Ok(WriteReply { count, stable: false, verifier: Some(*self.verifier.lock().unwrap()) })
        }

        async fn write_verifier(&self, _fh: &ShellHandle) -> anyhow::Result<Option<[u8; 8]>> {
            if !self.behaviour.unstable {
                return Ok(None);
            }
            let _ = self.commits.fetch_add(1, Ordering::SeqCst);
            if self.behaviour.restart_before_commit && !self.restarted.swap(true, Ordering::SeqCst) {
                // The restart loses the unstable data and changes the verifier.
                self.file.lock().unwrap().fill(0);
                *self.verifier.lock().unwrap() = [2; 8];
            }
            Ok(Some(*self.verifier.lock().unwrap()))
        }

        async fn io_sizes(&self, _fh: &ShellHandle) -> IoSizes {
            self.behaviour.sizes
        }

        async fn lookup(&self, _dir: &ShellHandle, _name: &str) -> anyhow::Result<(ShellHandle, ShellFileInfo)> {
            anyhow::bail!("not used by transfers")
        }

        async fn lookup_path(&self, _start: &ShellHandle, _path: &str) -> anyhow::Result<(ShellHandle, ShellFileInfo)> {
            anyhow::bail!("not used by transfers")
        }

        async fn getattr(&self, _fh: &ShellHandle) -> anyhow::Result<ShellFileInfo> {
            anyhow::bail!("not used by transfers")
        }

        async fn list_dir(&self, _dir: &ShellHandle) -> anyhow::Result<Vec<ShellEntry>> {
            anyhow::bail!("not used by transfers")
        }

        async fn create_file(&self, _dir: &ShellHandle, _name: &str, _mode: u32) -> anyhow::Result<ShellHandle> {
            anyhow::bail!("not used by transfers")
        }

        async fn mkdir(&self, _dir: &ShellHandle, _name: &str, _mode: u32) -> anyhow::Result<ShellHandle> {
            anyhow::bail!("not used by transfers")
        }

        async fn remove(&self, _dir: &ShellHandle, _name: &str) -> anyhow::Result<()> {
            anyhow::bail!("not used by transfers")
        }

        async fn rmdir(&self, _dir: &ShellHandle, _name: &str) -> anyhow::Result<()> {
            anyhow::bail!("not used by transfers")
        }

        async fn rename(&self, _from_dir: &ShellHandle, _from: &str, _to_dir: &ShellHandle, _to: &str) -> anyhow::Result<()> {
            anyhow::bail!("not used by transfers")
        }

        async fn symlink(&self, _dir: &ShellHandle, _name: &str, _target: &str) -> anyhow::Result<()> {
            anyhow::bail!("not used by transfers")
        }

        async fn hard_link(&self, _fh: &ShellHandle, _dir: &ShellHandle, _name: &str) -> anyhow::Result<()> {
            anyhow::bail!("not used by transfers")
        }

        async fn mknod(&self, _dir: &ShellHandle, _name: &str, _dev_type: ShellDeviceType, _major: u32, _minor: u32, _mode: u32) -> anyhow::Result<ShellHandle> {
            anyhow::bail!("not used by transfers")
        }

        async fn readlink(&self, _fh: &ShellHandle) -> anyhow::Result<String> {
            anyhow::bail!("not used by transfers")
        }

        async fn set_mode(&self, _fh: &ShellHandle, _mode: u32) -> anyhow::Result<()> {
            anyhow::bail!("not used by transfers")
        }

        async fn set_owner(&self, _fh: &ShellHandle, _uid: Option<u32>, _gid: Option<u32>) -> anyhow::Result<()> {
            anyhow::bail!("not used by transfers")
        }

        fn uid(&self) -> u32 {
            0
        }

        fn gid(&self) -> u32 {
            0
        }

        fn machinename(&self) -> &'static str {
            "test"
        }

        fn identity(&self) -> crate::shell::ops::Identity {
            crate::shell::ops::Identity::new(0, 0, &[])
        }

        fn observed(&self) -> &crate::shell::ops::ObservedIdentities {
            &self.observed
        }

        fn change_identity(&mut self, _uid: u32, _gid: u32, _hostname: &str) -> anyhow::Result<()> {
            Ok(())
        }

        fn version_name(&self) -> &'static str {
            "fake"
        }

        fn supports_mknod(&self) -> bool {
            false
        }

        fn supports_identity_change(&self) -> bool {
            false
        }

        fn commands(&self) -> &'static [&'static str] {
            &[]
        }

        fn make_completer(&self) -> Box<dyn crate::shell::complete::RemoteCompleter> {
            Box::new(NoCompleter)
        }

        async fn setattr(&self, _fh: &ShellHandle, _attrs: ShellSetAttr) -> anyhow::Result<ShellFileInfo> {
            anyhow::bail!("not used by transfers")
        }

        async fn statfs(&self, _fh: &ShellHandle) -> anyhow::Result<ShellFsStat> {
            anyhow::bail!("not used by transfers")
        }

        fn with_credential(&self, _id: &crate::shell::ops::Identity, _hostname: &str) -> Self {
            Self::new(self.behaviour, self.contents())
        }
    }

    /// Bytes that differ at every offset, so a misplaced chunk shows up.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| u8::try_from((i * 31 + i / 251) % 256).unwrap()).collect()
    }

    fn fh() -> ShellHandle {
        ShellHandle(vec![1, 2, 3])
    }

    async fn fetch(ops: &FakeOps, size_hint: u64) -> Vec<u8> {
        read_whole(ops, &fh(), size_hint).await.expect("download")
    }

    #[tokio::test]
    async fn download_reassembles_in_order_with_reads_in_flight() {
        let want = pattern(1_048_576 + 12_345);
        let ops = FakeOps::new(Behaviour::nfs3(), want.clone());
        assert_eq!(fetch(&ops, want.len() as u64).await, want);
        assert_eq!(ops.peak.load(Ordering::SeqCst), pipeline_depth(65_536), "reads must overlap");
    }

    #[tokio::test]
    async fn download_refills_short_reads() {
        let want = pattern(300_000);
        let ops = FakeOps::new(Behaviour { max_reply: 20_000, ..Behaviour::nfs3() }, want.clone());
        assert_eq!(fetch(&ops, want.len() as u64).await, want);
    }

    #[tokio::test]
    async fn download_without_eof_flag_stops_on_empty_reply() {
        let want = pattern(200_000);
        let ops = FakeOps::new(Behaviour { eof_flag: false, ..Behaviour::nfs3() }, want.clone());
        assert_eq!(fetch(&ops, want.len() as u64).await, want);
    }

    /// A size hint that is too small (the file grew, or GETATTR said 0) must
    /// not truncate the download.
    #[tokio::test]
    async fn download_reads_past_a_stale_size_hint() {
        let want = pattern(500_000);
        let ops = FakeOps::new(Behaviour::nfs3(), want.clone());
        assert_eq!(fetch(&ops, 0).await, want);
        let ops = FakeOps::new(Behaviour::nfs3(), want.clone());
        assert_eq!(fetch(&ops, 100_000).await, want);
    }

    #[tokio::test]
    async fn download_of_empty_file() {
        let ops = FakeOps::new(Behaviour::nfs3(), Vec::new());
        assert!(fetch(&ops, 0).await.is_empty());
    }

    /// NFSv2's 8 KiB transfers get the deepest window.
    #[tokio::test]
    async fn nfs2_download_keeps_many_small_reads_in_flight() {
        let want = pattern(400_000);
        let ops = FakeOps::new(Behaviour::nfs2(), want.clone());
        assert_eq!(fetch(&ops, want.len() as u64).await, want);
        assert_eq!(ops.peak.load(Ordering::SeqCst), MAX_PIPELINE_DEPTH);
    }

    #[tokio::test]
    async fn upload_writes_unstably_then_commits_once() {
        // More chunks than the window holds, so the window fills.
        let data = pattern(2_097_153);
        let ops = FakeOps::new(Behaviour::nfs3(), Vec::new());
        assert_eq!(upload(&ops, &fh(), &data, 0, None, &single_file_budget()).await.expect("upload"), data.len() as u64);
        assert_eq!(ops.contents(), data);
        assert_eq!(ops.commits.load(Ordering::SeqCst), 1);
        assert_eq!(ops.stable_writes.load(Ordering::SeqCst), 0, "no FILE_SYNC write when the verifiers agree");
        assert_eq!(ops.peak.load(Ordering::SeqCst), pipeline_depth(65_536), "writes must overlap");
    }

    /// A verifier that changes between the writes and the COMMIT means the
    /// server restarted and dropped unstable data: everything is rewritten
    /// durably.
    #[tokio::test]
    async fn upload_rewrites_durably_when_the_server_restarts() {
        let data = pattern(300_000);
        let ops = FakeOps::new(Behaviour { restart_before_commit: true, ..Behaviour::nfs3() }, Vec::new());
        assert_eq!(upload(&ops, &fh(), &data, 0, None, &single_file_budget()).await.expect("upload"), data.len() as u64);
        assert_eq!(ops.contents(), data, "the rewrite must restore what the restart lost");
        assert!(ops.stable_writes.load(Ordering::SeqCst) >= 300_000 / 65_536);
    }

    #[tokio::test]
    async fn upload_resends_after_short_writes() {
        let data = pattern(250_000);
        let ops = FakeOps::new(Behaviour { max_reply: 10_000, ..Behaviour::nfs3() }, Vec::new());
        assert_eq!(upload(&ops, &fh(), &data, 0, None, &single_file_budget()).await.expect("upload"), data.len() as u64);
        assert_eq!(ops.contents(), data);
    }

    #[tokio::test]
    async fn upload_fails_when_a_write_makes_no_progress() {
        let ops = FakeOps::new(Behaviour { max_reply: 0, ..Behaviour::nfs3() }, Vec::new());
        let err = upload(&ops, &fh(), &pattern(100_000), 0, None, &single_file_budget()).await.expect_err("no progress");
        assert!(err.to_string().contains("acknowledged 0 bytes"), "{err}");
    }

    /// NFSv2 has no unstable writes: every write is durable, none is
    /// committed, and they still overlap.
    #[tokio::test]
    async fn nfs2_upload_writes_durably_without_commit() {
        let data = pattern(200_000);
        let ops = FakeOps::new(Behaviour::nfs2(), Vec::new());
        assert_eq!(upload(&ops, &fh(), &data, 0, None, &single_file_budget()).await.expect("upload"), data.len() as u64);
        assert_eq!(ops.contents(), data);
        assert_eq!(ops.commits.load(Ordering::SeqCst), 0);
        assert_eq!(ops.peak.load(Ordering::SeqCst), MAX_PIPELINE_DEPTH);
    }

    /// One WRITE's worth of data is written durably, with no COMMIT.
    #[tokio::test]
    async fn small_upload_writes_durably_without_commit() {
        let data = pattern(65_536);
        let ops = FakeOps::new(Behaviour::nfs3(), Vec::new());
        assert_eq!(upload(&ops, &fh(), &data, 0, None, &single_file_budget()).await.expect("upload"), data.len() as u64);
        assert_eq!(ops.contents(), data);
        assert_eq!(ops.commits.load(Ordering::SeqCst), 0);
        assert_eq!(ops.stable_writes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn upload_at_an_offset_appends() {
        let ops = FakeOps::new(Behaviour::nfs3(), b"head".to_vec());
        let _ = upload(&ops, &fh(), b"tail", 4, None, &single_file_budget()).await.expect("upload");
        assert_eq!(ops.contents(), b"headtail");
    }

    /// Outputs come back in submission order even when later jobs finish
    /// first, and no more than `depth` jobs run at once.
    #[tokio::test]
    async fn run_concurrently_keeps_order_and_limit() {
        let running = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let jobs = (0..10u64).map(|i| {
            let (running, peak) = (&running, &peak);
            async move {
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                let _ = peak.fetch_max(now, Ordering::SeqCst);
                // Later jobs sleep less, so they would finish first.
                tokio::time::sleep(Duration::from_millis(10 - i)).await;
                let _ = running.fetch_sub(1, Ordering::SeqCst);
                i
            }
        });
        assert_eq!(run_concurrently(3, jobs).await, (0..10).collect::<Vec<_>>());
        assert_eq!(peak.load(Ordering::SeqCst), 3);
    }

    /// A shared budget caps a transfer's calls below its own window depth.
    #[tokio::test]
    async fn budget_caps_calls_in_flight() {
        let want = pattern(1_048_576);
        let ops = FakeOps::new(Behaviour::nfs3(), want.clone());
        let budget = Semaphore::new(2);
        let (tx, mut rx) = tokio::sync::mpsc::channel(SINK_QUEUE);
        let fetch = async move {
            let fetched = download(&ops, &fh(), want.len() as u64, &tx, None, &budget).await;
            drop(tx);
            (fetched, ops.peak.load(Ordering::SeqCst))
        };
        let collect = async move {
            let mut buf = Vec::new();
            while let Some(d) = rx.recv().await {
                buf.extend_from_slice(&d);
            }
            buf
        };
        let ((fetched, peak), got) = tokio::join!(fetch, collect);
        assert_eq!(fetched.expect("download"), 1_048_576);
        assert_eq!(got, pattern(1_048_576));
        assert_eq!(peak, 2);
    }

    #[test]
    fn depth_tracks_transfer_size() {
        assert_eq!(pipeline_depth(1_048_576), MIN_PIPELINE_DEPTH);
        assert_eq!(pipeline_depth(524_288), 8);
        assert_eq!(pipeline_depth(65_536), MAX_PIPELINE_DEPTH);
        assert_eq!(pipeline_depth(8192), MAX_PIPELINE_DEPTH);
        assert_eq!(pipeline_depth(0), MAX_PIPELINE_DEPTH);
    }

    #[test]
    fn server_sizes_are_clamped() {
        assert_eq!(IoSizes::from_server(Some(1_048_576), Some(524_288)), IoSizes { read: 1_048_576, write: 524_288 });
        assert_eq!(IoSizes::from_server(Some(64 << 20), None), IoSizes { read: crate::shell::ops::MAX_IO_SIZE, write: crate::shell::ops::CHUNK_SIZE });
        assert_eq!(IoSizes::from_server(Some(512), Some(0)), IoSizes::DEFAULT, "implausibly small sizes are ignored");
    }
}
