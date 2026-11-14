//! beacon-forward — TCP/UDP game forwarding lanes for Beacon v0.2.
//!
//! Each forward is a named lane: a public listener port on Beacon,
//! forwarded byte-for-byte to a target host:port. Lanes are managed
//! hot (add/remove/update without process restart) and expose
//! per-lane health + pass-through byte/connection metrics.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::RwLock;
use tokio::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GameForward {
    pub id: String,
    pub game_name: String,
    #[serde(default)]
    pub public_host: String,
    pub public_port: u16,
    pub protocol: Protocol,
    pub target_host: String,
    pub target_port: u16,
    #[serde(default)]
    pub forward_mode: ForwardMode,
    #[serde(default)]
    pub tunnel_path: Option<String>,
    #[serde(default = "default_owner")]
    pub owner: String,
}

fn default_owner() -> String {
    "beacon".into()
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ForwardMode {
    /// Live passthrough forwarding.
    #[default]
    Live,
    /// Modelled only — listener binds but traffic is refused.
    /// Matches the Explorer sandbox protocol ("sandbox forwards stay
    /// model_only until an owner migrate").
    ModelOnly,
}

/// Per-lane health derived from recent connect/packet outcomes.
#[derive(Debug, Clone, Serialize)]
pub struct LaneHealth {
    pub id: String,
    pub game_name: String,
    pub protocol: Protocol,
    pub mode: ForwardMode,
    pub state: LaneState,
    pub consecutive_failures: u32,
    pub last_failure_reason: Option<String>,
    pub last_ok: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LaneState {
    Unknown,
    Healthy,
    Degraded,
    Down,
}

/// Live per-lane counters (monotonic since process start).
#[derive(Debug, Default)]
pub struct LaneMetrics {
    pub connections_total: AtomicU64,
    pub connections_active: AtomicU64,
    pub connections_failed: AtomicU64,
    pub bytes_client_to_target: AtomicU64,
    pub bytes_target_to_client: AtomicU64,
}

#[derive(Debug, Default, Serialize)]
pub struct ForwardManagerStats {
    pub lanes: usize,
    pub tcp_lanes: usize,
    pub udp_lanes: usize,
}

#[derive(Debug, Serialize)]
pub struct LaneMetricsSnapshot {
    pub id: String,
    pub connections_total: u64,
    pub connections_active: u64,
    pub connections_failed: u64,
    pub bytes_client_to_target: u64,
    pub bytes_target_to_client: u64,
}

pub struct ForwardManager {
    lanes: RwLock<HashMap<String, Arc<LaneHandle>>>,
    reconciliation: tokio::sync::Mutex<()>,
    #[cfg(test)]
    fixture: bool,
}

struct LaneHandle {
    forward: GameForward,
    metrics: LaneMetrics,
    health: RwLock<LaneRuntimeHealth>,
    task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    stop: tokio::sync::watch::Sender<bool>,
}

#[derive(Debug, Default)]
struct LaneRuntimeHealth {
    consecutive_failures: u32,
    last_failure_reason: Option<String>,
    last_ok: Option<Instant>,
}

#[derive(Debug, Default, Serialize)]
pub struct ApplyOutcome {
    pub created: Vec<String>,
    pub updated: Vec<String>,
    pub removed: Vec<String>,
    pub errors: Vec<(String, String)>,
}

const FAILURE_THRESHOLD_DOWN: u32 = 5;
const FAILURE_THRESHOLD_DEGRADED: u32 = 2;

impl ForwardManager {
    pub fn new_shared() -> Arc<Self> {
        Arc::new(Self {
            lanes: RwLock::new(HashMap::new()),
            reconciliation: tokio::sync::Mutex::new(()),
            #[cfg(test)]
            fixture: false,
        })
    }

    #[cfg(test)]
    fn fixture() -> Arc<Self> {
        Arc::new(Self {
            lanes: RwLock::new(HashMap::new()),
            reconciliation: tokio::sync::Mutex::new(()),
            fixture: true,
        })
    }

    /// Reconcile desired forwards against running lanes:
    /// add new, swap changed, remove stale — no process restart.
    pub async fn apply(self: &Arc<Self>, desired: Vec<GameForward>) -> ApplyOutcome {
        let _guard = self.reconciliation.lock().await;
        self.apply_inner(desired).await
    }

    /// Acquire serialization before reading desired state. Never pass a
    /// snapshot loaded before this lock from a concurrent control path.
    pub async fn reconcile_from<F, Fut, E>(self: &Arc<Self>, load: F) -> Result<ApplyOutcome, E>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Vec<GameForward>, E>>,
    {
        let _guard = self.reconciliation.lock().await;
        let desired = load().await?;
        Ok(self.apply_inner(desired).await)
    }

    async fn apply_inner(self: &Arc<Self>, desired: Vec<GameForward>) -> ApplyOutcome {
        let mut outcome = ApplyOutcome::default();

        // Reject duplicate (port, protocol) binds before touching anything.
        let mut port_seen: HashMap<(u16, Protocol), String> = HashMap::new();
        for f in &desired {
            let key = (f.public_port, f.protocol);
            if let Some(other) = port_seen.get(&key) {
                outcome.errors.push((
                    f.id.clone(),
                    format!(
                        "public_port {} conflicts with lane '{}' (same protocol)",
                        f.public_port, other
                    ),
                ));
            } else {
                port_seen.insert(key, f.id.clone());
            }
        }
        let desired: Vec<GameForward> = desired
            .into_iter()
            .filter(|f| !outcome.errors.iter().any(|(id, _)| id == &f.id))
            .collect();

        // Pass 1: remove stale or config-changed lanes.
        let removed = {
            let mut lanes = self.lanes.write().await;
            let mut to_remove: Vec<String> = vec![];
            for (id, h) in lanes.iter() {
                let Some(f) = desired.iter().find(|f| &f.id == id) else {
                    to_remove.push(id.clone());
                    continue;
                };
                let needs_swap = h.forward.public_port != f.public_port
                    || h.forward.protocol != f.protocol
                    || h.forward.target_host != f.target_host
                    || h.forward.target_port != f.target_port
                    || h.forward.forward_mode != f.forward_mode;
                if needs_swap {
                    to_remove.push(id.clone());
                }
            }
            to_remove
                .into_iter()
                .filter_map(|id| lanes.remove(&id).map(|handle| (id, handle)))
                .collect::<Vec<_>>()
        };
        for (id, handle) in removed {
            if let Some(task) = handle.task.lock().await.take() {
                let _ = handle.stop.send(true);
                let _ = task.await;
            }
            outcome.removed.push(id);
        }

        // Pass 2: spawn missing lanes.
        {
            let mut lanes = self.lanes.write().await;
            for f in desired {
                if lanes.contains_key(&f.id) {
                    continue;
                }
                match Self::spawn_lane(Arc::clone(self), f.clone()).await {
                    Ok(h) => {
                        lanes.insert(f.id.clone(), h);
                        outcome.created.push(f.id.clone());
                    }
                    Err(e) => outcome.errors.push((f.id.clone(), e)),
                }
            }
        }

        outcome
    }

    async fn spawn_lane(
        mgr: Arc<ForwardManager>,
        f: GameForward,
    ) -> Result<Arc<LaneHandle>, String> {
        let (stop, stopped) = tokio::sync::watch::channel(false);
        #[cfg(test)]
        if mgr.fixture {
            let mut stopped = stopped;
            return Ok(Arc::new(LaneHandle {
                forward: f,
                metrics: LaneMetrics::default(),
                health: RwLock::new(LaneRuntimeHealth::default()),
                task: tokio::sync::Mutex::new(Some(tokio::spawn(async move {
                    let _ = stopped.changed().await;
                }))),
                stop,
            }));
        }
        // Bind BEFORE returning so (a) callers can connect immediately and
        // (b) bind errors surface in ApplyOutcome.errors instead of a dead task.
        let task = match f.protocol {
            Protocol::Tcp => {
                let listener = TcpListener::bind(("0.0.0.0", f.public_port))
                    .await
                    .map_err(|e| format!("bind tcp:{}: {e}", f.public_port))?;
                let mgr = Arc::clone(&mgr);
                let f = f.clone();
                tokio::spawn(async move {
                    run_tcp_lane(mgr, f, listener, stopped).await;
                })
            }
            Protocol::Udp => {
                let sock = Arc::new(
                    UdpSocket::bind(("0.0.0.0", f.public_port))
                        .await
                        .map_err(|e| format!("bind udp:{}: {e}", f.public_port))?,
                );
                let mgr = Arc::clone(&mgr);
                let f = f.clone();
                tokio::spawn(async move {
                    run_udp_lane(mgr, f, sock, stopped).await;
                })
            }
        };

        Ok(Arc::new(LaneHandle {
            forward: f,
            metrics: LaneMetrics::default(),
            health: RwLock::new(LaneRuntimeHealth::default()),
            task: tokio::sync::Mutex::new(Some(task)),
            stop,
        }))
    }

    pub async fn forwards(&self) -> Vec<GameForward> {
        let lanes = self.lanes.read().await;
        let mut out: Vec<GameForward> = lanes.values().map(|h| h.forward.clone()).collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    pub async fn list(&self) -> Vec<LaneHealth> {
        let lanes = self.lanes.read().await;
        let mut out = vec![];
        for h in lanes.values() {
            let rh = h.health.read().await;
            let state = if rh.consecutive_failures >= FAILURE_THRESHOLD_DOWN {
                LaneState::Down
            } else if rh.consecutive_failures >= FAILURE_THRESHOLD_DEGRADED {
                LaneState::Degraded
            } else if rh.last_ok.is_some() {
                LaneState::Healthy
            } else {
                LaneState::Unknown
            };
            out.push(LaneHealth {
                id: h.forward.id.clone(),
                game_name: h.forward.game_name.clone(),
                protocol: h.forward.protocol,
                mode: h.forward.forward_mode,
                state,
                consecutive_failures: rh.consecutive_failures,
                last_failure_reason: rh.last_failure_reason.clone(),
                last_ok: rh
                    .last_ok
                    .map(|i| format!("{}s ago", i.elapsed().as_secs())),
            });
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    pub async fn metrics_all(&self) -> Vec<LaneMetricsSnapshot> {
        let lanes = self.lanes.read().await;
        let mut out = vec![];
        for h in lanes.values() {
            out.push(snapshot(&h.forward.id, &h.metrics));
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    pub async fn stats(&self) -> ForwardManagerStats {
        let lanes = self.lanes.read().await;
        ForwardManagerStats {
            lanes: lanes.len(),
            tcp_lanes: lanes
                .values()
                .filter(|h| matches!(h.forward.protocol, Protocol::Tcp))
                .count(),
            udp_lanes: lanes
                .values()
                .filter(|h| matches!(h.forward.protocol, Protocol::Udp))
                .count(),
        }
    }

    // ---- recording hooks (called from lane tasks) ----

    async fn handle(&self, id: &str) -> Option<Arc<LaneHandle>> {
        self.lanes.read().await.get(id).cloned()
    }

    pub async fn record_connect_ok(&self, id: &str) {
        if let Some(h) = self.handle(id).await {
            h.metrics.connections_total.fetch_add(1, Ordering::Relaxed);
            let mut rh = h.health.write().await;
            rh.consecutive_failures = 0;
            rh.last_ok = Some(Instant::now());
        }
    }

    pub async fn record_connect_fail(&self, id: &str, reason: &str) {
        if let Some(h) = self.handle(id).await {
            h.metrics.connections_failed.fetch_add(1, Ordering::Relaxed);
            let mut rh = h.health.write().await;
            rh.consecutive_failures = rh.consecutive_failures.saturating_add(1);
            rh.last_failure_reason = Some(reason.to_string());
        }
    }

    pub async fn record_active(&self, id: &str, delta: i64) {
        if let Some(h) = self.handle(id).await {
            if delta >= 0 {
                h.metrics
                    .connections_active
                    .fetch_add(delta as u64, Ordering::Relaxed);
            } else {
                h.metrics
                    .connections_active
                    .fetch_sub((-delta) as u64, Ordering::Relaxed);
            }
        }
    }

    pub async fn add_bytes(&self, id: &str, c2t: u64, t2c: u64) {
        if let Some(h) = self.handle(id).await {
            if c2t > 0 {
                h.metrics
                    .bytes_client_to_target
                    .fetch_add(c2t, Ordering::Relaxed);
            }
            if t2c > 0 {
                h.metrics
                    .bytes_target_to_client
                    .fetch_add(t2c, Ordering::Relaxed);
            }
        }
    }
}

fn snapshot(id: &str, m: &LaneMetrics) -> LaneMetricsSnapshot {
    LaneMetricsSnapshot {
        id: id.to_string(),
        connections_total: m.connections_total.load(Ordering::Relaxed),
        connections_active: m.connections_active.load(Ordering::Relaxed),
        connections_failed: m.connections_failed.load(Ordering::Relaxed),
        bytes_client_to_target: m.bytes_client_to_target.load(Ordering::Relaxed),
        bytes_target_to_client: m.bytes_target_to_client.load(Ordering::Relaxed),
    }
}

async fn refuse_model_only(mgr: &ForwardManager, f: &GameForward) -> bool {
    if f.forward_mode == ForwardMode::ModelOnly {
        mgr.record_connect_fail(&f.id, "model_only").await;
        true
    } else {
        false
    }
}

// ---- TCP lane ----

async fn run_tcp_lane(
    mgr: Arc<ForwardManager>,
    f: GameForward,
    listener: TcpListener,
    mut stopped: tokio::sync::watch::Receiver<bool>,
) {
    tracing::info!(lane = %f.id, port = f.public_port, mode = ?f.forward_mode, "tcp game lane listening");
    let mut clients = tokio::task::JoinSet::new();
    loop {
        let accepted = tokio::select! {
            _ = stopped.changed() => break,
            accepted = listener.accept() => accepted,
            _ = clients.join_next(), if !clients.is_empty() => continue,
        };
        let Ok((client, _peer)) = accepted else {
            continue;
        };
        let _ = client.set_nodelay(true);
        let mgr = Arc::clone(&mgr);
        let f = f.clone();
        clients.spawn(async move {
            let target = (f.target_host.clone(), f.target_port);
            serve_tcp_client(&mgr, &f, client, async move {
                match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(target)).await
                {
                    Ok(Ok(stream)) => {
                        let _ = stream.set_nodelay(true);
                        Ok(stream)
                    }
                    Ok(Err(e)) => Err(format!("connect: {e}")),
                    Err(_) => Err("connect: timeout".to_string()),
                }
            })
            .await;
        });
    }
    shutdown_children(&mut clients).await;
}

async fn shutdown_children(children: &mut tokio::task::JoinSet<()>) {
    children.shutdown().await;
}

// The listener supplies the incoming stream; connection establishment is injected
// so the same policy, accounting, and pump can be exercised without sockets.
async fn serve_tcp_client<C, U, F>(mgr: &ForwardManager, f: &GameForward, mut client: C, connect: F)
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    F: std::future::Future<Output = Result<U, String>>,
{
    if refuse_model_only(mgr, f).await {
        return;
    }
    mgr.record_active(&f.id, 1).await;
    match connect.await {
        Ok(mut upstream) => match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
            Ok((c2t, t2c)) => {
                mgr.add_bytes(&f.id, c2t, t2c).await;
                mgr.record_connect_ok(&f.id).await;
            }
            Err(e) => mgr.record_connect_fail(&f.id, &format!("pump: {e}")).await,
        },
        Err(e) => mgr.record_connect_fail(&f.id, &e).await,
    }
    mgr.record_active(&f.id, -1).await;
}

// ---- UDP lane ----

// A session owns its reply task. Removing a session (or the whole lane)
// cancels the pump, releasing its socket and shared-listener reference.
struct OwnedTask(Option<tokio::task::JoinHandle<()>>);
impl OwnedTask {
    async fn stop(mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
            let _ = task.await;
        }
    }
}
impl Drop for OwnedTask {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}

struct SessionTable<S> {
    entries: HashMap<SocketAddr, (u64, S)>,
    generation: u64,
    capacity: usize,
}
impl<S> SessionTable<S> {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            generation: 0,
            capacity,
        }
    }
    fn can_admit(&self) -> bool {
        self.entries.len() < self.capacity
    }
    fn insert(&mut self, peer: SocketAddr, create: impl FnOnce(u64) -> S) -> bool {
        if self.entries.contains_key(&peer) || !self.can_admit() {
            return false;
        }
        self.generation += 1;
        self.entries
            .insert(peer, (self.generation, create(self.generation)));
        true
    }
    fn remove_if(&mut self, peer: SocketAddr, generation: u64) {
        if self
            .entries
            .get(&peer)
            .is_some_and(|(id, _)| *id == generation)
        {
            self.entries.remove(&peer);
        }
    }
}

struct UdpSession {
    socket: Arc<UdpSocket>,
    _pump: OwnedTask,
}

// The packet origin check is used by the actual pump and the in-process fake.
async fn relay_reply<F, Fut>(source: SocketAddr, target: SocketAddr, data: &[u8], send: F) -> bool
where
    F: FnOnce(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    if source != target {
        return false;
    }
    send(data.to_vec()).await
}

async fn run_udp_lane(
    mgr: Arc<ForwardManager>,
    f: GameForward,
    sock: Arc<UdpSocket>,
    mut stopped: tokio::sync::watch::Receiver<bool>,
) {
    let mut sessions: SessionTable<UdpSession> = SessionTable::new(4096);
    let (finished, mut completions) = tokio::sync::mpsc::unbounded_channel();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let packet = tokio::select! {
            _ = stopped.changed() => break,
            packet = sock.recv_from(&mut buf) => packet,
            Some((peer, generation)) = completions.recv() => {
                sessions.remove_if(peer, generation);
                continue;
            }
        };
        let Ok((n, peer)) = packet else {
            continue;
        };
        if refuse_model_only(&mgr, &f).await {
            continue;
        }
        if !sessions.entries.contains_key(&peer) {
            // Admission precedes socket creation; existing sessions keep their
            // owners and source tuples when the capacity is reached.
            if !sessions.can_admit() {
                continue;
            }
            let Some(target) = resolve_target(&f).await else {
                continue;
            };
            let bind = SocketAddr::new(
                if target.is_ipv4() {
                    std::net::Ipv4Addr::UNSPECIFIED.into()
                } else {
                    std::net::Ipv6Addr::UNSPECIFIED.into()
                },
                0,
            );
            let Ok(upstream) = UdpSocket::bind(bind).await else {
                continue;
            };
            if upstream.connect(target).await.is_err() {
                continue;
            }
            let upstream = Arc::new(upstream);
            let pump_sock = upstream.clone();
            let listener = sock.clone();
            let done = finished.clone();
            let metrics_mgr = mgr.clone();
            let id = f.id.clone();
            sessions.insert(peer, |generation| UdpSession {
                socket: upstream,
                _pump: OwnedTask(Some(tokio::spawn(async move {
                    let mut reply = vec![0u8; 64 * 1024];
                    loop {
                        let received = tokio::time::timeout(
                            Duration::from_secs(60),
                            pump_sock.recv_from(&mut reply),
                        )
                        .await;
                        let Ok(Ok((n, source))) = received else {
                            break;
                        };
                        if !relay_reply(source, target, &reply[..n], |data| {
                            let listener = &listener;
                            async move { listener.send_to(&data, peer).await.is_ok() }
                        })
                        .await
                        {
                            continue;
                        }
                        metrics_mgr.add_bytes(&id, 0, n as u64).await;
                    }
                    let _ = done.send((peer, generation));
                }))),
            });
        }
        if let Some((_, session)) = sessions.entries.get(&peer) {
            if session.socket.send(&buf[..n]).await.is_ok() {
                mgr.add_bytes(&f.id, n as u64, 0).await;
                mgr.record_connect_ok(&f.id).await;
            }
        }
    }
    for (_, (_, session)) in sessions.entries.drain() {
        session._pump.stop().await;
    }
}

async fn resolve_target(f: &GameForward) -> Option<SocketAddr> {
    use tokio::net::lookup_host;
    lookup_host((f.target_host.as_str(), f.target_port))
        .await
        .ok()
        .and_then(|mut addrs| addrs.next())
}

/// Proactive health probe for live TCP lanes (called on a timer).
pub async fn poll_tcp_health(mgr: Arc<ForwardManager>) {
    let forwards = mgr.forwards().await;
    for f in forwards {
        if f.protocol != Protocol::Tcp || f.forward_mode == ForwardMode::ModelOnly {
            continue;
        }
        let ok = matches!(
            tokio::time::timeout(
                Duration::from_secs(3),
                TcpStream::connect((f.target_host.as_str(), f.target_port))
            )
            .await,
            Ok(Ok(_))
        );
        if ok {
            mgr.record_connect_ok(&f.id).await;
        } else {
            mgr.record_connect_fail(&f.id, "health probe").await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Dropped(Arc<std::sync::atomic::AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    async fn pending_owner(flag: Arc<std::sync::atomic::AtomicBool>) -> OwnedTask {
        let (ready, started) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _guard = Dropped(flag);
            let _ = ready.send(());
            std::future::pending::<()>().await;
        });
        started.await.unwrap();
        OwnedTask(Some(task))
    }

    #[tokio::test]
    async fn session_owner_stop_joins_child_before_returning() {
        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        pending_owner(released.clone()).await.stop().await;
        assert!(released.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn tcp_children_are_joined_on_shutdown() {
        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = released.clone();
        let (ready, started) = tokio::sync::oneshot::channel();
        let mut children = tokio::task::JoinSet::new();
        children.spawn(async move {
            let _guard = Dropped(observed);
            let _ = ready.send(());
            std::future::pending::<()>().await;
        });
        started.await.unwrap();
        shutdown_children(&mut children).await;
        assert!(released.load(Ordering::SeqCst));
        assert!(children.is_empty());
    }

    #[tokio::test]
    async fn session_cap_preserves_owners_and_cleanup_matches_generation() {
        let peer: SocketAddr = "192.0.2.1:12001".parse().unwrap();
        let other: SocketAddr = "192.0.2.2:12001".parse().unwrap();
        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let owner = pending_owner(released.clone()).await;
        let mut table = SessionTable::new(1);
        assert!(table.insert(peer, |_| owner));
        let old = table.entries[&peer].0;
        assert!(!table.insert(other, |_| panic!("capacity must precede allocation")));
        assert_eq!(table.entries.len(), 1);
        assert!(!released.load(Ordering::SeqCst));
        table.remove_if(peer, old);
        tokio::task::yield_now().await;
        assert!(released.load(Ordering::SeqCst));
        let next = pending_owner(Arc::new(std::sync::atomic::AtomicBool::new(false))).await;
        table.insert(peer, |_| next);
        table.remove_if(peer, old);
        assert_eq!(table.entries.len(), 1);
    }

    #[tokio::test]
    async fn reply_relay_accepts_only_selected_responder() {
        let target = "192.0.2.1:12001".parse().unwrap();
        let foreign = "192.0.2.2:12001".parse().unwrap();
        let delivered = std::sync::Mutex::new(Vec::new());
        for source in [foreign, target] {
            let accepted = relay_reply(source, target, b"fixture", |data| {
                let delivered = &delivered;
                async move {
                    delivered.lock().unwrap().push(data);
                    true
                }
            })
            .await;
            assert_eq!(accepted, source == target);
        }
        assert_eq!(*delivered.lock().unwrap(), vec![b"fixture".to_vec()]);
    }

    #[tokio::test]
    async fn desired_read_and_apply_share_serialization() {
        let mgr = ForwardManager::fixture();
        let desired = Arc::new(RwLock::new(vec![fwd(
            &std::process::id().to_string(),
            12001,
            Protocol::Tcp,
            9,
        )]));
        let (read, loaded) = tokio::sync::oneshot::channel();
        let (release, wait) = tokio::sync::oneshot::channel();
        let first_mgr = mgr.clone();
        let first_state = desired.clone();
        let first = tokio::spawn(async move {
            first_mgr
                .reconcile_from(|| async {
                    let snapshot = first_state.read().await.clone();
                    read.send(()).unwrap();
                    wait.await.unwrap();
                    Ok::<_, ()>(snapshot)
                })
                .await
                .unwrap()
        });
        loaded.await.unwrap();
        desired.write().await.clear();
        let read_new = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = read_new.clone();
        let second_mgr = mgr.clone();
        let second = tokio::spawn(async move {
            second_mgr
                .reconcile_from(|| async {
                    observed.store(true, Ordering::SeqCst);
                    Ok::<_, ()>(desired.read().await.clone())
                })
                .await
                .unwrap()
        });
        tokio::task::yield_now().await;
        assert!(!read_new.load(Ordering::SeqCst));
        release.send(()).unwrap();
        first.await.unwrap();
        second.await.unwrap();
        assert!(mgr.forwards().await.is_empty());
        assert!(mgr
            .reconcile_from(|| async { Err::<Vec<GameForward>, _>(()) })
            .await
            .is_err());
    }

    #[tokio::test]
    async fn removal_releases_lane_map_before_joining_packet_bookkeeping() {
        let mgr = ForwardManager::fixture();
        let (stop, mut stopped) = tokio::sync::watch::channel(false);
        let (trigger, wait_for_trigger) = tokio::sync::oneshot::channel();
        let (started, wait_for_start) = tokio::sync::oneshot::channel();
        let task_mgr = mgr.clone();
        let task = tokio::spawn(async move {
            let _ = wait_for_trigger.await;
            let _ = started.send(());
            let _ = task_mgr.handle("race").await;
            let _ = stopped.changed().await;
        });
        let lane = Arc::new(LaneHandle {
            forward: fwd("race", 12001, Protocol::Udp, 12002),
            metrics: LaneMetrics::default(),
            health: RwLock::new(LaneRuntimeHealth::default()),
            task: tokio::sync::Mutex::new(Some(task)),
            stop,
        });
        mgr.lanes.write().await.insert("race".into(), lane);

        let map_guard = mgr.lanes.write().await;
        let remove_mgr = mgr.clone();
        let mut removal = tokio::spawn(async move { remove_mgr.apply(vec![]).await });
        tokio::task::yield_now().await;
        trigger.send(()).unwrap();
        wait_for_start.await.unwrap();
        drop(map_guard);

        let completed = tokio::time::timeout(Duration::from_millis(250), &mut removal)
            .await
            .is_ok();
        if !completed {
            removal.abort();
            let _ = removal.await;
        }
        assert!(completed, "lane removal waited for a task under the map lock");
        assert!(mgr.forwards().await.is_empty());
    }

    fn fwd(id: &str, port: u16, proto: Protocol, target_port: u16) -> GameForward {
        GameForward {
            id: id.into(),
            game_name: "test-game".into(),
            public_host: String::new(),
            public_port: port,
            protocol: proto,
            target_host: "127.0.0.1".into(),
            target_port,
            forward_mode: ForwardMode::Live,
            tunnel_path: None,
            owner: "test".into(),
        }
    }

    #[tokio::test]
    async fn apply_creates_lists_removes() {
        let mgr = ForwardManager::fixture();
        let forward = fwd("t1", 12001, Protocol::Tcp, 12002);
        let out = mgr.apply(vec![forward.clone()]).await;
        assert_eq!(out.created, vec!["t1"]);
        assert_eq!(mgr.list().await.len(), 1);
        let (mut client, proxy_client) = tokio::io::duplex(128);
        let (proxy_target, mut target) = tokio::io::duplex(128);
        let task_mgr = mgr.clone();
        let task_forward = forward.clone();
        let pump = tokio::spawn(async move {
            serve_tcp_client(&task_mgr, &task_forward, proxy_client, async move {
                Ok(proxy_target)
            })
            .await
        });
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0; 4];
        target.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        target.write_all(b"pong").await.unwrap();
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
        client.shutdown().await.unwrap();
        target.shutdown().await.unwrap();
        pump.await.unwrap();
        let metrics = mgr.metrics_all().await;
        assert_eq!(metrics[0].bytes_client_to_target, 4);
        assert_eq!(metrics[0].bytes_target_to_client, 4);
        assert_eq!(metrics[0].connections_total, 1);
        assert_eq!(metrics[0].connections_active, 0);
        let out = mgr.apply(vec![forward]).await;
        assert!(out.created.is_empty() && out.removed.is_empty() && out.updated.is_empty());
        assert_eq!(mgr.apply(vec![]).await.removed, vec!["t1"]);
        assert!(mgr.list().await.is_empty());
    }

    #[tokio::test]
    async fn duplicate_ports_rejected() {
        let mgr = ForwardManager::fixture();
        let out = mgr
            .apply(vec![
                fwd("a", 12001, Protocol::Tcp, 9),
                fwd("b", 12001, Protocol::Tcp, 9),
            ])
            .await;
        assert_eq!(out.errors.len(), 1);
        assert_eq!(out.created.len(), 1);
        mgr.apply(vec![]).await;
    }

    #[tokio::test]
    async fn model_only_refuses_traffic() {
        let mgr = ForwardManager::fixture();
        let mut f = fwd("m1", 12001, Protocol::Tcp, 9);
        f.forward_mode = ForwardMode::ModelOnly;
        assert_eq!(mgr.apply(vec![f.clone()]).await.created.len(), 1);
        let (mut client, incoming) = tokio::io::duplex(128);
        let (upstream, mut target) = tokio::io::duplex(128);
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = called.clone();
        serve_tcp_client(&mgr, &f, incoming, async move {
            observed.store(true, Ordering::SeqCst);
            Ok(upstream)
        })
        .await;
        assert!(!called.load(Ordering::SeqCst));
        let mut buf = [0; 1];
        assert_eq!(client.read(&mut buf).await.unwrap(), 0);
        assert_eq!(target.read(&mut buf).await.unwrap(), 0);
        let health = mgr.list().await;
        assert_eq!(health[0].consecutive_failures, 1);
        assert_eq!(health[0].last_failure_reason.as_deref(), Some("model_only"));
        mgr.apply(vec![]).await;
    }
}
