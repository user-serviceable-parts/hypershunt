// Concurrency limiter: caps how many requests are in flight at once
// against a pool, optionally keyed on client IP, authenticated user,
// or a request header.
//
// One `ConcurrencyLimit` per configured `concurrency-limit` pool.  A
// pool declared by name in `server` is built once and shared (as one
// `Arc`) by every location that references it, which is what makes
// those locations draw on the same slots.
//
// Each key owns a `Slot` (a semaphore plus a waiter count).  Slots
// are created on demand and removed as soon as nothing is in flight
// or waiting on them, so a keyed pool's map is bounded by the number
// of requests it is currently handling and needs no sweep task.

use crate::error::{BoxBody, HttpResponse};
use crate::handler::cgi_util::InFlightGuard;
use crate::headers::RequestContext;
use crate::metrics::Metrics;
use crate::rate_limit::RateLimitKey;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::StatusCode;
use hyper::body::{Body, Frame, SizeHint};
use hyper::header::HeaderMap;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Opt-in waiting room for a pool that is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Queue {
    /// Most requests allowed to wait at once (per key).
    pub max_waiters: u32,
    /// Longest one request may wait for a slot.
    pub timeout: Duration,
}

/// One configured pool, with its live slot state.
pub struct ConcurrencyLimit {
    /// Human-readable name for logs.
    pub name: String,
    /// Slots per key.
    pub max: u32,
    /// How requests are split into separate pools; `None` is a
    /// single pool shared by every request.
    pub key: Option<RateLimitKey>,
    /// `None` rejects as soon as the pool is full.
    pub queue: Option<Queue>,
    /// Status sent to a rejected request.
    pub status: StatusCode,
    /// Report would-be rejections but admit the request anyway.
    pub dry_run: bool,
    slots: Mutex<HashMap<String, Arc<Slot>>>,
}

struct Slot {
    sem: Arc<Semaphore>,
    waiters: AtomicUsize,
}

/// Why a request was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejected {
    /// No free slot and no room (or no queue) to wait.
    Full,
    /// Waited `queue-timeout` without getting a slot.
    QueueTimeout,
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Rejected::Full => "full",
            Rejected::QueueTimeout => "queue-timeout",
        })
    }
}

/// A successful `acquire`.
pub enum Admission {
    /// A slot is held for as long as the `Permit` lives.
    Permit(Permit),
    /// The pool was full but is in dry-run mode: the request goes
    /// ahead without occupying a slot.
    DryRun,
}

/// Keeps a slot's map entry alive while a request holds or waits on
/// it, and removes the entry when the last such request goes away.
struct SlotRef {
    limit: Arc<ConcurrencyLimit>,
    key: String,
    slot: Arc<Slot>,
}

impl Drop for SlotRef {
    fn drop(&mut self) {
        let mut slots = self.limit.lock_slots();
        // Two references mean the map and us: nothing else is in
        // flight or waiting.  Every other holder took its clone under
        // this same lock, so the count cannot rise while we look.
        if Arc::strong_count(&self.slot) == 2
            && slots
                .get(&self.key)
                .is_some_and(|s| Arc::ptr_eq(s, &self.slot))
        {
            slots.remove(&self.key);
        }
    }
}

/// One held slot.  Dropping it frees the slot.
pub struct Permit {
    // Declaration order is drop order: the semaphore permit must go
    // back before `SlotRef` decides whether the slot is idle.
    _permit: OwnedSemaphorePermit,
    _in_flight: InFlightGuard,
    _slot: SlotRef,
}

/// The slots one request holds, across every pool on its location.
/// Shared so the response body and, for an upgraded connection, the
/// tunnel task can each keep the slots alive; they free when the last
/// clone drops.
pub type Held = Arc<Vec<Permit>>;

/// Request extension carrying the held slots to a handler that will
/// outlive the response (an upgraded tunnel).
#[derive(Clone)]
pub struct TunnelHold(#[allow(dead_code)] pub Held);

/// Counts one waiter against its slot for as long as it waits.
struct WaiterGuard<'a>(&'a Slot);

impl Drop for WaiterGuard<'_> {
    fn drop(&mut self) {
        self.0.waiters.fetch_sub(1, Ordering::Relaxed);
    }
}

impl ConcurrencyLimit {
    pub fn new(
        name: String,
        max: u32,
        key: Option<RateLimitKey>,
        queue: Option<Queue>,
        status: StatusCode,
        dry_run: bool,
    ) -> Self {
        ConcurrencyLimit {
            name,
            max,
            key,
            queue,
            status,
            dry_run,
            slots: Mutex::new(HashMap::new()),
        }
    }

    // The map is only ever mutated by whole-entry insert/remove, so a
    // panic elsewhere cannot leave it half-updated; recover the lock
    // rather than poisoning every later request on this location.
    fn lock_slots(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<String, Arc<Slot>>> {
        self.slots.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The pool a request belongs to.  Unkeyed limits put every
    /// request in the `""` pool.
    pub fn key_string(
        &self,
        ctx: &RequestContext<'_>,
        headers: &HeaderMap,
    ) -> String {
        self.key
            .as_ref()
            .map(|k| k.derive(ctx, headers))
            .unwrap_or_default()
    }

    fn slot_ref(self: &Arc<Self>, key: String) -> SlotRef {
        let slot = self
            .lock_slots()
            .entry(key.clone())
            .or_insert_with(|| {
                Arc::new(Slot {
                    sem: Arc::new(Semaphore::new(self.max as usize)),
                    waiters: AtomicUsize::new(0),
                })
            })
            .clone();
        SlotRef { limit: self.clone(), key, slot }
    }

    /// Take a slot in `key`'s pool, waiting in the queue when one is
    /// configured.  Takes the derived key rather than the request so
    /// the returned future borrows nothing from it.
    pub async fn acquire(
        self: &Arc<Self>,
        key: String,
        metrics: &Arc<Metrics>,
    ) -> Result<Admission, Rejected> {
        let slot_ref = self.slot_ref(key);
        let admit = |permit, slot_ref| {
            Admission::Permit(Permit {
                _permit: permit,
                _in_flight: InFlightGuard::new(metrics.clone(), |m| {
                    &m.concurrency_in_flight
                }),
                _slot: slot_ref,
            })
        };
        if let Ok(p) = slot_ref.slot.sem.clone().try_acquire_owned() {
            return Ok(admit(p, slot_ref));
        }
        if self.dry_run {
            metrics.concurrency_dry_run.fetch_add(1, Ordering::Relaxed);
            return Ok(Admission::DryRun);
        }
        let reject = |why| {
            metrics.concurrency_rejected.fetch_add(1, Ordering::Relaxed);
            Err(why)
        };
        let Some(queue) = self.queue else {
            return reject(Rejected::Full);
        };
        // Claim a queue place atomically so a burst cannot overshoot
        // `max_waiters`.
        let max_waiters = queue.max_waiters as usize;
        let waiters = &slot_ref.slot.waiters;
        let mut seen = waiters.load(Ordering::Relaxed);
        loop {
            if seen >= max_waiters {
                return reject(Rejected::Full);
            }
            match waiters.compare_exchange_weak(
                seen,
                seen + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(now) => seen = now,
            }
        }
        metrics.concurrency_queued.fetch_add(1, Ordering::Relaxed);
        let waited = {
            let _waiter = WaiterGuard(&slot_ref.slot);
            let _waiting = InFlightGuard::new(metrics.clone(), |m| {
                &m.concurrency_waiting
            });
            tokio::time::timeout(
                queue.timeout,
                slot_ref.slot.sem.clone().acquire_owned(),
            )
            .await
        };
        match waited {
            Ok(Ok(p)) => Ok(admit(p, slot_ref)),
            // The semaphore is never closed, so an acquire error
            // cannot happen; treat it like a full pool regardless.
            Ok(Err(_)) => reject(Rejected::Full),
            Err(_) => reject(Rejected::QueueTimeout),
        }
    }

    /// Number of keys with a live slot.
    #[cfg(test)]
    fn slot_count(&self) -> usize {
        self.lock_slots().len()
    }
}

/// Response body that keeps a request's slots until the body has
/// been sent in full, failed, or been dropped (client gone).  Without
/// it a slot would free as soon as the response head was ready, and a
/// long streamed response would stop counting against its pool.
struct PermitBody {
    inner: BoxBody,
    held: Option<Held>,
}

impl Body for PermitBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        let frame = Pin::new(&mut this.inner).poll_frame(cx);
        if matches!(frame, Poll::Ready(None | Some(Err(_)))) {
            this.held = None;
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Tie `held` to the lifetime of `resp`'s body.
pub fn hold(resp: HttpResponse, held: Held) -> HttpResponse {
    resp.map(|inner| PermitBody { inner, held: Some(held) }.boxed())
}

// -- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::bytes_body;

    fn limit(max: u32, queue: Option<Queue>) -> Arc<ConcurrencyLimit> {
        Arc::new(ConcurrencyLimit::new(
            "t".into(),
            max,
            None,
            queue,
            StatusCode::SERVICE_UNAVAILABLE,
            false,
        ))
    }

    fn queue(max_waiters: u32, secs: u64) -> Option<Queue> {
        Some(Queue { max_waiters, timeout: Duration::from_secs(secs) })
    }

    fn metrics() -> Arc<Metrics> {
        Arc::new(Metrics::new())
    }

    async fn permit(
        l: &Arc<ConcurrencyLimit>,
        key: &str,
        m: &Arc<Metrics>,
    ) -> Permit {
        match l.acquire(key.into(), m).await {
            Ok(Admission::Permit(p)) => p,
            Ok(Admission::DryRun) => panic!("unexpected dry run"),
            Err(e) => panic!("unexpected rejection: {e}"),
        }
    }

    async fn rejection(
        l: &Arc<ConcurrencyLimit>,
        key: &str,
        m: &Arc<Metrics>,
    ) -> Rejected {
        match l.acquire(key.into(), m).await {
            Err(e) => e,
            Ok(_) => panic!("expected a rejection"),
        }
    }

    fn load(a: &std::sync::atomic::AtomicI64) -> i64 {
        a.load(Ordering::Relaxed)
    }

    #[tokio::test]
    async fn admits_up_to_max_then_rejects() {
        let (l, m) = (limit(2, None), metrics());
        let _a = permit(&l, "", &m).await;
        let _b = permit(&l, "", &m).await;
        assert_eq!(rejection(&l, "", &m).await, Rejected::Full);
        assert_eq!(load(&m.concurrency_in_flight), 2);
        assert_eq!(m.concurrency_rejected.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn dropping_a_permit_frees_its_slot() {
        let (l, m) = (limit(1, None), metrics());
        let a = permit(&l, "", &m).await;
        drop(a);
        assert_eq!(load(&m.concurrency_in_flight), 0);
        let _b = permit(&l, "", &m).await;
    }

    #[tokio::test]
    async fn keys_have_separate_pools() {
        let (l, m) = (limit(1, None), metrics());
        let _a = permit(&l, "10.0.0.1", &m).await;
        let _b = permit(&l, "10.0.0.2", &m).await;
        assert_eq!(rejection(&l, "10.0.0.1", &m).await, Rejected::Full);
    }

    #[tokio::test]
    async fn idle_slot_is_removed_from_the_map() {
        let (l, m) = (limit(1, None), metrics());
        let a = permit(&l, "a", &m).await;
        let b = permit(&l, "b", &m).await;
        assert_eq!(l.slot_count(), 2);
        // A rejected request must not strand the entry either.
        assert_eq!(rejection(&l, "a", &m).await, Rejected::Full);
        drop(a);
        assert_eq!(l.slot_count(), 1);
        drop(b);
        assert_eq!(l.slot_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn queued_request_is_admitted_on_release() {
        let (l, m) = (limit(1, queue(1, 5)), metrics());
        let a = permit(&l, "", &m).await;
        let (l2, m2) = (l.clone(), m.clone());
        let waiter =
            tokio::spawn(async move { permit(&l2, "", &m2).await });
        tokio::task::yield_now().await;
        assert_eq!(load(&m.concurrency_waiting), 1);
        drop(a);
        let _b = waiter.await.expect("waiter task");
        assert_eq!(load(&m.concurrency_waiting), 0);
        assert_eq!(load(&m.concurrency_in_flight), 1);
        assert_eq!(m.concurrency_queued.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn waiters_are_served_in_arrival_order() {
        let (l, m) = (limit(1, queue(2, 5)), metrics());
        let a = permit(&l, "", &m).await;
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut tasks = Vec::new();
        for i in 0..2 {
            let (l, m, order) = (l.clone(), m.clone(), order.clone());
            tasks.push(tokio::spawn(async move {
                let _p = permit(&l, "", &m).await;
                order.lock().expect("order").push(i);
            }));
            tokio::task::yield_now().await;
        }
        drop(a);
        for t in tasks {
            t.await.expect("waiter task");
        }
        assert_eq!(*order.lock().expect("order"), vec![0, 1]);
    }

    #[tokio::test(start_paused = true)]
    async fn full_queue_rejects_immediately() {
        let (l, m) = (limit(1, queue(1, 5)), metrics());
        let _a = permit(&l, "", &m).await;
        let (l2, m2) = (l.clone(), m.clone());
        let _waiter =
            tokio::spawn(async move { permit(&l2, "", &m2).await });
        tokio::task::yield_now().await;
        assert_eq!(rejection(&l, "", &m).await, Rejected::Full);
    }

    #[tokio::test(start_paused = true)]
    async fn queue_wait_expires_with_timeout() {
        let (l, m) = (limit(1, queue(1, 5)), metrics());
        let _a = permit(&l, "", &m).await;
        let started = tokio::time::Instant::now();
        assert_eq!(rejection(&l, "", &m).await, Rejected::QueueTimeout);
        assert_eq!(started.elapsed(), Duration::from_secs(5));
        assert_eq!(load(&m.concurrency_waiting), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_waiter_gives_up_its_queue_place() {
        let (l, m) = (limit(1, queue(1, 5)), metrics());
        let a = permit(&l, "", &m).await;
        let (l2, m2) = (l.clone(), m.clone());
        let waiter =
            tokio::spawn(async move { permit(&l2, "", &m2).await });
        tokio::task::yield_now().await;
        waiter.abort();
        let _ = waiter.await;
        assert_eq!(load(&m.concurrency_waiting), 0);
        // The place is free again: a new request may queue.
        let (l3, m3) = (l.clone(), m.clone());
        let next =
            tokio::spawn(async move { permit(&l3, "", &m3).await });
        tokio::task::yield_now().await;
        drop(a);
        let _b = next.await.expect("waiter task");
    }

    #[tokio::test]
    async fn dry_run_admits_without_a_slot_and_never_waits() {
        let m = metrics();
        let l = Arc::new(ConcurrencyLimit::new(
            "t".into(),
            1,
            None,
            queue(1, 5),
            StatusCode::SERVICE_UNAVAILABLE,
            true,
        ));
        let _a = permit(&l, "", &m).await;
        assert!(matches!(
            l.acquire(String::new(), &m).await,
            Ok(Admission::DryRun)
        ));
        assert_eq!(load(&m.concurrency_in_flight), 1);
        assert_eq!(m.concurrency_dry_run.load(Ordering::Relaxed), 1);
        assert_eq!(m.concurrency_rejected.load(Ordering::Relaxed), 0);
        assert_eq!(m.concurrency_queued.load(Ordering::Relaxed), 0);
    }

    fn held_response(p: Permit) -> (HttpResponse, Held) {
        let held: Held = Arc::new(vec![p]);
        let resp = hyper::Response::new(bytes_body(Bytes::from_static(
            b"hello",
        )));
        (hold(resp, held.clone()), held)
    }

    #[tokio::test]
    async fn body_holds_the_slot_until_it_ends() {
        let (l, m) = (limit(1, None), metrics());
        let (resp, held) = held_response(permit(&l, "", &m).await);
        drop(held);
        assert_eq!(rejection(&l, "", &m).await, Rejected::Full);
        let mut body = resp.into_body();
        while let Some(frame) = body.frame().await {
            frame.expect("frame");
            // Mid-stream the slot is still taken.
            assert_eq!(load(&m.concurrency_in_flight), 1);
        }
        // End of stream released it, before the body is dropped.
        assert_eq!(load(&m.concurrency_in_flight), 0);
        let _b = permit(&l, "", &m).await;
    }

    #[tokio::test]
    async fn dropping_the_body_unread_frees_the_slot() {
        let (l, m) = (limit(1, None), metrics());
        let (resp, held) = held_response(permit(&l, "", &m).await);
        drop(held);
        drop(resp);
        let _b = permit(&l, "", &m).await;
    }

    #[tokio::test]
    async fn slot_is_held_until_the_last_clone_drops() {
        let (l, m) = (limit(1, None), metrics());
        let (resp, tunnel) = held_response(permit(&l, "", &m).await);
        drop(resp);
        assert_eq!(rejection(&l, "", &m).await, Rejected::Full);
        drop(tunnel);
        let _b = permit(&l, "", &m).await;
    }
}
