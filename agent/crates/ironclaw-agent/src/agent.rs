//! Main agent orchestrator.

use ironclaw_collector::{build_collectors, Collector};
use ironclaw_core::config::Config;
use ironclaw_core::event::Event;
use ironclaw_core::identity::{self, validate_role, Identity, RegisterRequest};
use ironclaw_core::policy::Policy;
use ironclaw_transport::buffer::EventBuffer;
use ironclaw_transport::http::{HeartbeatRequest, HttpClient};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{sleep, Duration, Instant};

pub struct AgentApp {
    config: Config,
    /// Immutable cached copy of the agent_id. Used on the hot event-tagging
    /// path so we never need to take the identity lock per event.
    agent_id: String,
    /// Shared identity. The heartbeat task may rewrite `role` at runtime.
    /// All other fields are effectively immutable after enrollment.
    identity: Arc<RwLock<Identity>>,
    http_client: HttpClient,
    buffer: Arc<EventBuffer>,
    policy: Arc<RwLock<Policy>>,
    collectors: Vec<Box<dyn Collector>>,
}

impl AgentApp {
    pub async fn new(config: Config) -> anyhow::Result<Self> {
        let http_client = HttpClient::new(config.backend.clone())?;

        // 1. Load or provision identity
        let identity = if let Some(id) = identity::load_identity(&config.paths.identity_path)? {
            log::info!(
                "Loaded existing identity for agent_id: {} (role: {})",
                id.agent_id,
                id.role
            );
            id
        } else {
            log::info!(
                "No existing identity found. Registering as role '{}'...",
                config.initial_role
            );
            Self::enroll(&config, &http_client).await?
        };

        // 2. Load policy
        let active_policy = if config.paths.policy_path.exists() {
            let p_json = std::fs::read_to_string(&config.paths.policy_path)?;
            serde_json::from_str(&p_json).unwrap_or_else(|_| identity.policy.clone())
        } else {
            // Explicitly save the initial policy to policy.json so it exists immediately
            if let Some(parent) = config.paths.policy_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(json) = serde_json::to_string_pretty(&identity.policy) {
                let _ = std::fs::write(&config.paths.policy_path, json);
            }
            identity.policy.clone()
        };
        let policy = Arc::new(RwLock::new(active_policy));

        // 3. Setup buffer
        let buffer = Arc::new(
            EventBuffer::new(
                config.buffer.memory_capacity,
                config.paths.spool_dir.clone(),
                config.buffer.spool_max_mb > 0,
            )
            .await?,
        );

        // 4. Setup collectors
        let collectors = build_collectors();

        let agent_id = identity.agent_id.clone();
        let identity = Arc::new(RwLock::new(identity));

        Ok(Self {
            config,
            agent_id,
            identity,
            http_client,
            buffer,
            policy,
            collectors,
        })
    }

    async fn enroll(config: &Config, http: &HttpClient) -> anyhow::Result<Identity> {
        let kp = identity::generate_keypair();
        let os_info = identity::collect_os_info();
        let hostname = hostname::get()?.to_string_lossy().to_string();

        let os_version = os_info.version.clone();
        let agent_version = env!("CARGO_PKG_VERSION").to_string();

        let req = RegisterRequest {
            hostname,
            os_info,
            public_key: kp.public_key_b64.clone(),
            os_version,
            agent_version,
            role: config.initial_role.clone(),
            group: config.group.clone(),
        };

        log::info!(
            "Registering with backend - role: '{}', group: '{}'",
            req.role,
            req.group
        );

        let mut backoff = config.backend.retry_delay_secs;
        let mut retries = 0;
        let res = loop {
            match http.register(&req).await {
                Ok(r) => break r,
                Err(e) => {
                    if retries >= config.backend.max_retries {
                        return Err(anyhow::anyhow!(
                            "Registration failed after {} retries: {}",
                            retries,
                            e
                        ));
                    }
                    log::warn!("Registration failed: {}. Retrying in {}s...", e, backoff);
                    sleep(Duration::from_secs(backoff)).await;
                    backoff *= 2;
                    retries += 1;
                }
            }
        };

        let identity = Identity {
            agent_id: res.agent_id.clone(),
            role: config.initial_role.clone(),
            private_key_b64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                kp.signing_key.as_bytes(),
            ),
            public_key_b64: kp.public_key_b64,
            backend_public_key_b64: res.backend_public_key,
            policy: res.policy,
        };

        identity::save_identity(&identity, &config.paths.identity_path)?;
        log::info!(
            "Successfully registered as agent_id: {} (role: {})",
            identity.agent_id,
            identity.role
        );
        Ok(identity)
    }

    /// Apply a role assignment received from the backend.
    ///
    /// Returns `Ok(true)` when the role actually changed and was persisted,
    /// `Ok(false)` when it was a no-op (same role, or backend sent the same
    /// value we already have), and `Err(_)` for validation or persistence
    /// failures. On persistence failure the in-memory role is reverted so
    /// disk and memory stay consistent — next heartbeat will report the
    /// pre-change role and the backend can re-issue the assignment.
    async fn apply_role_change(
        identity: &Arc<RwLock<Identity>>,
        identity_path: &std::path::Path,
        new_role: &str,
    ) -> Result<bool, String> {
        validate_role(new_role).map_err(|e| format!("backend sent invalid role: {}", e))?;

        let mut id = identity.write().await;
        if id.role == new_role {
            return Ok(false);
        }

        let old_role = std::mem::replace(&mut id.role, new_role.to_string());

        // Persist with the new role in place. save_identity does an atomic
        // tmp+rename so a crash mid-write cannot leave a corrupt file.
        match identity::save_identity(&id, identity_path) {
            Ok(()) => {
                log::warn!("[role] changed: '{}' -> '{}'", old_role, new_role);
                Ok(true)
            }
            Err(e) => {
                id.role = old_role.clone();
                Err(format!(
                    "persistence failed for role '{}' -> '{}': {}. Reverted in-memory.",
                    old_role, new_role, e
                ))
            }
        }
    }

    /// Evaluate detection filters from the policy against an event.
    /// Returns true if the event should be DROPPED (matched a "block" action).
    fn apply_detection_filters(
        event: &Event,
        filters: &[ironclaw_core::policy::DetectionFilter],
    ) -> bool {
        for filter in filters {
            let field_value = match filter.match_field.as_str() {
                "cmdline" | "CommandLine" => event
                    .payload
                    .get("CommandLine")
                    .or_else(|| event.payload.get("cmdline"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase(),
                "image" | "Image" => event
                    .payload
                    .get("Image")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase(),
                _ => String::new(),
            };

            if !field_value.is_empty() && field_value.contains(&filter.pattern.to_lowercase()) {
                match filter.action.as_str() {
                    "flag" => {
                        log::info!(
                            "[detection] Filter '{}' matched: field='{}' pattern='{}' on event_id={:?}",
                            filter.name, filter.match_field, filter.pattern, event.event_id
                        );
                        // "flag" = log and continue, don't drop
                    }
                    "block" => {
                        log::warn!(
                            "[detection] Filter '{}' BLOCKED event: field='{}' pattern='{}' on event_id={:?}",
                            filter.name, filter.match_field, filter.pattern, event.event_id
                        );
                        return true; // drop the event
                    }
                    _ => {}
                }
            }
        }
        false
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let (tx, mut rx) = mpsc::channel::<Event>(1000);

        // Shared counter for events shipped (reported in heartbeat)
        let events_shipped_counter = Arc::new(AtomicU64::new(0));

        // Start collectors
        let collectors = std::mem::take(&mut self.collectors);
        for collector in collectors {
            let tx_clone = tx.clone();
            let pol_clone = self.policy.clone();
            let name = collector.name().to_string();
            tokio::spawn(async move {
                log::info!("Spawning collector: {}", name);
                if let Err(e) = collector.run(tx_clone, pol_clone).await {
                    log::error!("Collector '{}' failed: {}", name, e);
                }
            });
        }

        // Start heartbeat loop
        let hb_client = self.http_client.clone();
        let hb_agent_id = self.agent_id.clone();
        let hb_identity = self.identity.clone();
        let hb_identity_path = self.config.paths.identity_path.clone();
        let hb_pol = self.policy.clone();
        let hb_interval = self.config.backend.heartbeat_interval_secs;
        let hb_buffer = self.buffer.clone();
        let hb_policy_path = self.config.paths.policy_path.clone();
        let hb_shipped_counter = events_shipped_counter.clone();
        let hb_config = self.config.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(hb_interval));
            let uptime_start = std::time::Instant::now();
            loop {
                interval.tick().await;
                let current_pol_ver = hb_pol.read().await.version;
                let current_role = hb_identity.read().await.role.clone();
                let req = HeartbeatRequest {
                    policy_version: current_pol_ver,
                    role: current_role,
                    group: hb_config.group.clone(),
                    uptime_secs: uptime_start.elapsed().as_secs(),
                    buffer_depth: hb_buffer.memory_depth().await,
                    events_shipped: hb_shipped_counter.load(Ordering::Relaxed),
                };

                log::info!(
                    "Sending heartbeat - role: '{}', group: '{}', policy_version: {}",
                    req.role,
                    req.group,
                    req.policy_version
                );

                match hb_client.heartbeat(&hb_agent_id, &req).await {
                    Ok(res) => {
                        log::info!(
                            "Heartbeat OK. Policy update available: {}",
                            res.policy_update.is_some()
                        );

                        // Apply role assignment FIRST (before the policy fetch
                        // below), so the backend serves the correct policy on
                        // the in-flight fetch. A role change also forces a
                        // policy refresh even if the backend didn't send
                        // a policy_update (defensive — the role's
                        // policy may differ from the current one).
                        let mut role_changed = false;
                        if let Some(new_role) = res.role_assignment {
                            match Self::apply_role_change(
                                &hb_identity,
                                &hb_identity_path,
                                &new_role,
                            )
                            .await
                            {
                                Ok(true) => role_changed = true,
                                Ok(false) => {} // unchanged or idempotent no-op
                                Err(e) => log::error!("[role] {}", e),
                            }
                        }

                        // Apply policy from heartbeat response if available
                        if let Some(new_pol) = res.policy_update {
                            log::info!(
                                "Received new policy version {} via heartbeat",
                                new_pol.version
                            );
                            if let Err(e) = new_pol.validate_hash() {
                                log::error!("Policy hash validation failed: {}", e);
                            } else {
                                let mut p = hb_pol.write().await;
                                // compute and log the diff before applying
                                let diff = p.diff_summary(&new_pol);
                                if diff.is_empty() {
                                    log::info!(
                                        "Policy v{} applied (no behavioral changes)",
                                        new_pol.version
                                    );
                                } else {
                                    for change in &diff {
                                        log::info!("Policy change: {}", change);
                                    }
                                }
                                *p = new_pol;
                                p.enforce_invariants();
                                // Phase 5: Policy persistence — atomic write
                                if let Ok(json) = serde_json::to_string_pretty(&*p) {
                                    let tmp = hb_policy_path.with_extension("tmp");
                                    if std::fs::write(&tmp, json).is_ok() {
                                        let _ = std::fs::rename(tmp, &hb_policy_path);
                                    }
                                }
                                log::info!(
                                    "Policy updated successfully to v{}",
                                    p.version
                                );
                            }
                        } else if role_changed {
                            // If role changed but no policy in heartbeat, fall back to GET /policy
                            match hb_client.fetch_policy(&hb_agent_id, current_pol_ver).await {
                                Ok(pol_res) => {
                                    if let Some(new_pol) = pol_res.policy {
                                        log::info!(
                                            "Received new policy version {} via GET /policy",
                                            new_pol.version
                                        );
                                        if let Err(e) = new_pol.validate_hash() {
                                            log::error!("Policy hash validation failed: {}", e);
                                        } else {
                                            let mut p = hb_pol.write().await;
                                            // compute and log the diff before applying
                                            let diff = p.diff_summary(&new_pol);
                                            if diff.is_empty() {
                                                log::info!(
                                                    "Policy v{} applied (no behavioral changes)",
                                                    new_pol.version
                                                );
                                            } else {
                                                for change in &diff {
                                                    log::info!("Policy change: {}", change);
                                                }
                                            }
                                            *p = new_pol;
                                            p.enforce_invariants();
                                            // Phase 5: Policy persistence — atomic write
                                            if let Ok(json) = serde_json::to_string_pretty(&*p) {
                                                let tmp = hb_policy_path.with_extension("tmp");
                                                if std::fs::write(&tmp, json).is_ok() {
                                                    let _ = std::fs::rename(tmp, &hb_policy_path);
                                                }
                                            }
                                            log::info!(
                                                "Policy updated successfully to v{}",
                                                p.version
                                            );
                                        }
                                    }
                                }
                                Err(e) => log::error!("Failed to fetch policy: {}", e),
                            }
                        }
                    }
                    Err(e) => log::warn!("Heartbeat failed: {}", e),
                }
            }
        });

        // Start shipper loop — respects rate limit from policy
        let ship_client = self.http_client.clone();
        let ship_agent_id = self.agent_id.clone();
        let ship_buffer = self.buffer.clone();
        let ship_pol = self.policy.clone();
        let batch_size = self.config.buffer.batch_size;
        let batch_timeout = self.config.buffer.batch_timeout_secs;
        let ship_shipped_counter = events_shipped_counter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(batch_timeout));
            // Token bucket state for rate limiting
            let mut tokens: f64 = 0.0;
            let mut last_refill = Instant::now();

            loop {
                interval.tick().await;

                // Refill tokens based on policy rate limit
                let max_eps = {
                    let pol = ship_pol.read().await;
                    pol.rate_limits.events_per_second as f64
                };
                let now = Instant::now();
                let elapsed = now.duration_since(last_refill).as_secs_f64();
                tokens = (tokens + elapsed * max_eps).min(max_eps * batch_timeout as f64);
                last_refill = now;

                if let Ok(batch) = ship_buffer.drain_batch(batch_size).await {
                    if !batch.is_empty() {
                        // Enforce rate limit: only ship up to token budget
                        let allowed = (tokens as usize).min(batch.len());
                        if allowed == 0 {
                            log::info!(
                                "[shipper] Rate limit reached, holding {} events",
                                batch.len()
                            );
                            let _ = ship_buffer.push_batch_back(batch).await;
                            continue;
                        }
                        let (to_ship, remainder): (Vec<_>, Vec<_>) = batch
                            .into_iter()
                            .enumerate()
                            .partition(|(i, _)| *i < allowed);
                        let to_ship: Vec<Event> = to_ship.into_iter().map(|(_, e)| e).collect();
                        let remainder: Vec<Event> = remainder.into_iter().map(|(_, e)| e).collect();

                        if !remainder.is_empty() {
                            let _ = ship_buffer.push_batch_back(remainder).await;
                        }
                        tokens -= to_ship.len() as f64;

                        let count = to_ship.len();
                        match ironclaw_transport::batch::Batcher::compress_batch(&to_ship) {
                            Ok(compressed) => {
                                if let Err(e) =
                                    ship_client.ship_events(&ship_agent_id, compressed).await
                                {
                                    log::error!(
                                        "Shipping failed: {}, returning events to buffer",
                                        e
                                    );
                                    let _ = ship_buffer.push_batch_back(to_ship).await;
                                } else {
                                    ship_shipped_counter.fetch_add(count as u64, Ordering::Relaxed);
                                    log::info!(
                                        "Shipped batch of {} events to backend (total shipped: {})",
                                        count,
                                        ship_shipped_counter.load(Ordering::Relaxed)
                                    );
                                }
                            }
                            Err(e) => log::error!("Compression failed: {}", e),
                        }
                    }
                }
            }
        });

        // Graceful shutdown listener (SIGTERM / SIGINT / Ctrl-C)
        let shutdown_buffer = self.buffer.clone();
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut sigterm =
                    signal(SignalKind::terminate()).expect("Failed to register SIGTERM");
                tokio::select! {
                    _ = sigterm.recv() => log::info!("[shutdown] SIGTERM received"),
                    _ = tokio::signal::ctrl_c() => log::info!("[shutdown] Ctrl-C received"),
                }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
                log::info!("[shutdown] Ctrl-C received");
            }

            log::info!("[shutdown] Flushing buffer before exit...");
            // Give in-flight events a moment to drain into the buffer
            tokio::time::sleep(Duration::from_millis(500)).await;
            // The disk spool is already persistent; in-memory events will be lost
            // but we log the depth so the operator knows.
            let depth = shutdown_buffer.memory_depth().await;
            if depth > 0 {
                log::warn!(
                    "[shutdown] {} in-memory events may be lost (not yet spooled to disk)",
                    depth
                );
            } else {
                log::info!("[shutdown] Buffer clean. Exiting.");
            }
            std::process::exit(0);
        });

        // Event intake loop
        log::info!("Agent running. Listening for events...");
        while let Some(event) = rx.recv().await {
            // M5: Evaluate detection filters from the live policy
            let (should_drop, filters_snapshot) = {
                let pol = self.policy.read().await;
                let drop = Self::apply_detection_filters(&event, &pol.detection_filters);
                (drop, pol.detection_filters.len())
            };
            if should_drop {
                continue;
            }
            let _ = filters_snapshot; // used for debug if needed

            let mut ev = event;
            ev.agent_id = self.agent_id.clone();
            if let Err(e) = self.buffer.push(ev).await {
                log::error!("Failed to buffer event: {}", e);
            }
        }

        Ok(())
    }
}
