# Ironclaw Agent Implementation Plan

**Version:** 2.0
**Date:** January 2026
**Status:** Implementation Blueprint

---

## Overview

The Ironclaw agent is a lightweight, cross-platform endpoint telemetry agent providing:
- DNS query logging with process context
- Network connection monitoring
- Process execution tracking
- File system monitoring
- Registry monitoring (Windows)
- Authentication event logging
- Local baseline engine with anomaly scoring
- Extended local retention for distributed hunting
- Forensic artifact collection
- Remote query execution

---

## Architecture

```
                        IRONCLAW AGENT ARCHITECTURE
  ┌──────────────────────────────────────────────────────────────────────────┐
  │                                                                          │
  │  SERVICE MANAGER                                                         │
  │  ═══════════════                                                         │
  │  ┌────────────────────────────────────────────────────────────────────┐ │
  │  │  • Lifecycle management (start, stop, restart)                     │ │
  │  │  • Component orchestration                                         │ │
  │  │  • Health monitoring & self-diagnostics                            │ │
  │  │  • Configuration management                                        │ │
  │  │  • Windows Service / systemd integration                           │ │
  │  └────────────────────────────────────────────────────────────────────┘ │
  │                                                                          │
  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                  │
  │  │  COLLECTION  │─▶│  PROCESSING  │─▶│   STORAGE    │                  │
  │  │   ENGINE     │  │    ENGINE    │  │   ENGINE     │                  │
  │  │              │  │              │  │              │                  │
  │  │  • ETW       │  │  • Normalize │  │  • SQLite    │                  │
  │  │  • eBPF      │  │  • Enrich    │  │  • Encryption│                  │
  │  │  • Sysmon    │  │  • Baseline  │  │  • Retention │                  │
  │  │  • EventLog  │  │  • Score     │  │              │                  │
  │  └──────────────┘  └──────────────┘  └──────────────┘                  │
  │                                                                          │
  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                  │
  │  │  TRANSPORT   │  │   BASELINE   │  │   FORENSIC   │                  │
  │  │   ENGINE     │  │    ENGINE    │  │  COLLECTOR   │                  │
  │  │              │  │              │  │              │                  │
  │  │  • HTTPS     │  │  • Frequency │  │  • Artifacts │                  │
  │  │  • Batching  │  │  • Statistics│  │  • Memory    │                  │
  │  │  • Buffering │  │  • Anomaly   │  │  • Files     │                  │
  │  └──────────────┘  └──────────────┘  └──────────────┘                  │
  │                                                                          │
  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                  │
  │  │    QUERY     │  │    UPDATE    │  │  PROTECTION  │                  │
  │  │   HANDLER    │  │   MANAGER    │  │    LAYER     │                  │
  │  │              │  │              │  │              │                  │
  │  │  • Parse     │  │  • Version   │  │  • Tamper    │                  │
  │  │  • Execute   │  │  • Download  │  │  • Integrity │                  │
  │  │  • Stream    │  │  • Apply     │  │  • Secrets   │                  │
  │  └──────────────┘  └──────────────┘  └──────────────┘                  │
  │                                                                          │
  └──────────────────────────────────────────────────────────────────────────┘
```

---

## Platform Support

| Platform | Priority | Collection Method | Status |
|----------|----------|-------------------|--------|
| Windows 10/11, Server 2016+ | P0 | ETW, Sysmon, EventLog | Phase 1 |
| Linux (Ubuntu 20.04+, RHEL 8+) | P1 | eBPF, auditd | Phase 2 |
| macOS 12+ | P2 | Network Extension, Endpoint Security | Phase 3 |

---

## Phase 1: Windows Agent (Weeks 1-16)

### 1.1 Core Framework

**Cargo Workspace Structure:**
```
agent/
├── Cargo.toml                    # Workspace
├── ironclaw-core/               # Shared types and utilities
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── config.rs            # Configuration loading
│       ├── error.rs             # Error types
│       └── event.rs             # Event definitions
├── ironclaw-collector/          # Collection engines
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── windows/
│       │   ├── mod.rs
│       │   ├── etw.rs           # ETW collection
│       │   ├── sysmon.rs        # Sysmon parsing
│       │   ├── eventlog.rs      # Security log
│       │   └── wmi.rs           # WMI queries
│       ├── linux/
│       │   ├── mod.rs
│       │   └── ebpf.rs
│       └── macos/
│           ├── mod.rs
│           └── es.rs
├── ironclaw-baseline/           # Baseline engine
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── counters.rs          # Frequency counters
│       ├── patterns.rs          # Pattern tracking
│       └── scorer.rs            # Anomaly scoring
├── ironclaw-storage/            # Local storage
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── stream.rs            # Outbound buffer
│       └── extended.rs          # Extended retention
├── ironclaw-transport/          # Network transport
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── http.rs              # HTTPS client
│       ├── batch.rs             # Event batching
│       └── buffer.rs            # Ring buffer
├── ironclaw-forensic/           # Forensic collection
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── artifacts/
│       │   ├── mod.rs
│       │   ├── system.rs
│       │   ├── persistence.rs
│       │   ├── execution.rs
│       │   ├── filesystem.rs
│       │   └── memory.rs
│       └── collector.rs
├── ironclaw-query/              # Remote query handler
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       └── executor.rs
└── ironclaw-agent/              # Main binary
    ├── Cargo.toml
    └── src/
        ├── main.rs
        ├── agent.rs             # Agent runtime
        └── service.rs           # Windows service
```

**Core Dependencies (Cargo.toml):**
```toml
[workspace]
members = [
    "ironclaw-core",
    "ironclaw-collector",
    "ironclaw-baseline",
    "ironclaw-storage",
    "ironclaw-transport",
    "ironclaw-forensic",
    "ironclaw-query",
    "ironclaw-agent",
]

[workspace.dependencies]
# Async runtime
tokio = { version = "1.35", features = ["full"] }

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
rmp-serde = "1.1"

# Database
rusqlite = { version = "0.30", features = ["bundled", "sqlcipher"] }

# Cryptography
ring = "0.17"
rustls = "0.22"
chacha20poly1305 = "0.10"

# Compression
zstd = "0.13"

# HTTP client
reqwest = { version = "0.11", features = ["rustls-tls", "json"] }

# Logging
tracing = "0.1"
tracing-subscriber = "0.3"

# Time
chrono = { version = "0.4", features = ["serde"] }

# UUID
uuid = { version = "1.6", features = ["v4", "serde"] }

# Windows
[target.'cfg(windows)'.dependencies]
windows = { version = "0.52", features = [
    "Win32_Foundation",
    "Win32_Security",
    "Win32_System_Diagnostics_Etw",
    "Win32_System_Threading",
    "Win32_System_Services",
    "Win32_NetworkManagement_IpHelper",
    "Win32_System_Registry",
]}
ferrisetw = "1.0"
windows-service = "0.6"
```

**Tasks:**
- [ ] Set up Cargo workspace
- [ ] Implement configuration loading
- [ ] Create error handling framework
- [ ] Define event types and schemas
- [ ] Implement structured logging

### 1.2 Windows Collection Engine

**ETW Providers:**

| Provider | GUID | Events |
|----------|------|--------|
| DNS-Client | 1C95126E-7EEA-49A9-A3FE-A378B03DDB4D | DNS queries |
| Kernel-Network | 7DD42A49-5329-4832-8DFD-43D979153A88 | TCP/UDP |
| Kernel-Process | 22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716 | Process |
| Kernel-File | EDD08927-9CC4-4E65-B970-C2560FB5C289 | File ops |
| Kernel-Registry | 70EB4F03-C1DE-4F73-A051-33D13D5413BD | Registry |
| Security-Auditing | 54849625-5478-4994-A5BA-3E3B0328C30D | Auth |

**ETW Collection:**
```rust
// ironclaw-collector/src/windows/etw.rs

use ferrisetw::prelude::*;
use windows::Win32::System::Diagnostics::Etw::*;

pub struct EtwCollector {
    sessions: Vec<UserTrace>,
    event_tx: mpsc::Sender<RawEvent>,
}

impl EtwCollector {
    pub fn new(event_tx: mpsc::Sender<RawEvent>) -> Self {
        Self {
            sessions: Vec::new(),
            event_tx,
        }
    }

    pub fn start_dns_collection(&mut self) -> Result<(), CollectorError> {
        let dns_provider = Provider::new()
            .by_guid("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D")
            .add_callback(move |record, schema| {
                self.handle_dns_event(record, schema);
            })
            .build()?;

        let trace = UserTrace::new()
            .named("IronclawDNS")
            .enable(dns_provider)
            .start()?;

        self.sessions.push(trace);
        Ok(())
    }

    fn handle_dns_event(&self, record: &EventRecord, schema: &Schema) {
        let event = DnsQueryEvent {
            timestamp: record.timestamp(),
            query_id: record.property("QueryName").unwrap_or_default(),
            query_name: record.property("QueryName").unwrap_or_default(),
            query_type: record.property("QueryType").unwrap_or(1),
            response_code: record.property("QueryStatus").unwrap_or(0),
            process_id: record.process_id(),
        };

        // Enrich with process context
        let process = self.get_process_context(event.process_id);

        let raw_event = RawEvent::Dns(DnsEvent {
            header: self.create_header(EventType::DnsQuery),
            query: event,
            process,
        });

        let _ = self.event_tx.blocking_send(raw_event);
    }

    fn get_process_context(&self, pid: u32) -> ProcessContext {
        // Get process name, path, command line, user
        // Use Windows API: OpenProcess, QueryFullProcessImageNameW, etc.
    }
}
```

**Sysmon Integration:**
```rust
// ironclaw-collector/src/windows/sysmon.rs

pub struct SysmonCollector {
    event_tx: mpsc::Sender<RawEvent>,
}

impl SysmonCollector {
    pub async fn start(&self) -> Result<(), CollectorError> {
        // Subscribe to Sysmon event log channel
        let query = "Microsoft-Windows-Sysmon/Operational";

        loop {
            let events = self.read_new_events(query).await?;

            for event in events {
                let parsed = self.parse_sysmon_event(&event)?;
                self.event_tx.send(parsed).await?;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn parse_sysmon_event(&self, event: &WinEvent) -> Result<RawEvent, ParseError> {
        match event.event_id {
            1 => self.parse_process_create(event),
            3 => self.parse_network_connect(event),
            5 => self.parse_process_terminate(event),
            7 => self.parse_image_load(event),
            11 => self.parse_file_create(event),
            12 | 13 | 14 => self.parse_registry_event(event),
            22 => self.parse_dns_query(event),
            _ => Ok(RawEvent::Unknown(event.clone())),
        }
    }

    fn parse_process_create(&self, event: &WinEvent) -> Result<RawEvent, ParseError> {
        Ok(RawEvent::Process(ProcessEvent {
            header: self.create_header(EventType::ProcessStart),
            process_id: event.field("ProcessId")?,
            process_name: event.field("Image")?,
            process_path: event.field("Image")?,
            command_line: event.field("CommandLine")?,
            sha256: event.field("Hashes")?.extract_sha256(),
            parent: ParentProcess {
                pid: event.field("ParentProcessId")?,
                name: event.field("ParentImage")?,
                command_line: event.field("ParentCommandLine")?,
            },
            user: UserContext {
                name: event.field("User")?,
                sid: event.field("UserSid")?,
            },
            integrity_level: event.field("IntegrityLevel").ok(),
        }))
    }
}
```

**Tasks:**
- [ ] Implement ETW session management
- [ ] Create DNS query collector (ETW)
- [ ] Create network connection collector (ETW)
- [ ] Implement Sysmon event parser
- [ ] Create Security event log collector
- [ ] Implement process context enrichment
- [ ] Add file hash calculation
- [ ] Implement signature verification

### 1.3 Event Processing

**Normalizer:**
```rust
// ironclaw-collector/src/processing/normalizer.rs

pub struct EventNormalizer {
    hostname: String,
    endpoint_id: String,
}

impl EventNormalizer {
    pub fn normalize(&self, raw: RawEvent) -> ProcessedEvent {
        let header = EventHeader {
            id: Uuid::new_v4(),
            timestamp: raw.timestamp(),
            endpoint_id: self.endpoint_id.clone(),
            event_type: raw.event_type(),
            schema_version: 1,
            anomaly_score: 0.0,  // Set by baseline
            anomaly_flags: vec![],
        };

        match raw {
            RawEvent::Dns(e) => ProcessedEvent::Dns(self.normalize_dns(header, e)),
            RawEvent::Network(e) => ProcessedEvent::Network(self.normalize_network(header, e)),
            RawEvent::Process(e) => ProcessedEvent::Process(self.normalize_process(header, e)),
            RawEvent::File(e) => ProcessedEvent::File(self.normalize_file(header, e)),
            RawEvent::Registry(e) => ProcessedEvent::Registry(self.normalize_registry(header, e)),
            RawEvent::Auth(e) => ProcessedEvent::Auth(self.normalize_auth(header, e)),
        }
    }
}
```

**Tasks:**
- [ ] Implement event normalization
- [ ] Add field validation
- [ ] Create event enrichment (process context)
- [ ] Implement schema versioning

### 1.4 Baseline Engine

**Frequency Counter (Count-Min Sketch):**
```rust
// ironclaw-baseline/src/counters.rs

pub struct FrequencyCounter<K: Hash + Eq> {
    sketch: CountMinSketch,
    exact: HashMap<K, CountEntry>,
    first_seen: HashMap<K, i64>,
    config: CounterConfig,
}

impl<K: Hash + Eq + Clone> FrequencyCounter<K> {
    pub fn increment(&mut self, key: &K) -> IncrementResult {
        let now = Utc::now().timestamp();
        let count = self.sketch.increment(key);

        // Track first seen
        if !self.first_seen.contains_key(key) {
            self.first_seen.insert(key.clone(), now);
            return IncrementResult::FirstSeen;
        }

        // Track exact count for frequent items
        if count > self.config.exact_threshold {
            self.exact
                .entry(key.clone())
                .or_insert(CountEntry::new())
                .increment();
        }

        IncrementResult::Incremented(count)
    }

    pub fn get_count(&self, key: &K) -> u64 {
        self.exact
            .get(key)
            .map(|e| e.count)
            .unwrap_or_else(|| self.sketch.query(key))
    }

    pub fn is_rare(&self, key: &K, threshold: u64) -> bool {
        self.get_count(key) < threshold
    }
}
```

**Anomaly Scorer:**
```rust
// ironclaw-baseline/src/scorer.rs

pub struct AnomalyScorer {
    config: ScorerConfig,
}

impl AnomalyScorer {
    pub fn score_dns(&self, event: &DnsQueryEvent, baseline: &BaselineEngine) -> AnomalyScore {
        let mut score = 0.0_f32;
        let mut flags = Vec::new();

        // First seen domain
        if baseline.domains.is_first_seen(&event.query_name) {
            score += self.config.first_seen_weight;
            flags.push(AnomalyFlag::FirstSeen);
        }

        // Rare domain
        if baseline.domains.is_rare(&event.query_name, self.config.rare_threshold) {
            score += self.config.rare_weight;
            flags.push(AnomalyFlag::Rare);
        }

        // High entropy domain
        let entropy = calculate_entropy(&event.query_name);
        if entropy > 4.0 {
            score += self.config.pattern_anomaly_weight * (entropy - 4.0) / 4.0;
            flags.push(AnomalyFlag::HighEntropy);
        }

        // First seen TLD
        let tld = extract_tld(&event.query_name);
        if baseline.tlds.is_first_seen(&tld) {
            score += self.config.first_seen_weight * 0.5;
            flags.push(AnomalyFlag::FirstSeenTld);
        }

        AnomalyScore {
            score: score.min(1.0),
            flags,
        }
    }

    pub fn score_network(&self, event: &NetworkEvent, baseline: &BaselineEngine) -> AnomalyScore {
        let mut score = 0.0_f32;
        let mut flags = Vec::new();

        // First seen IP
        if baseline.remote_ips.is_first_seen(&event.remote_ip) {
            score += self.config.first_seen_weight;
            flags.push(AnomalyFlag::FirstSeenIp);
        }

        // Rare destination
        if baseline.remote_ips.is_rare(&event.remote_ip, self.config.rare_threshold) {
            score += self.config.rare_weight;
            flags.push(AnomalyFlag::RareDestination);
        }

        // Check for beaconing pattern
        if let Some(pattern) = baseline.connection_patterns.get(&event.connection_key()) {
            if pattern.is_beaconing() {
                score += self.config.pattern_anomaly_weight;
                flags.push(AnomalyFlag::PotentialBeaconing);
            }
        }

        AnomalyScore {
            score: score.min(1.0),
            flags,
        }
    }
}
```

**Baseline Types:**

| Baseline | Scope | Data Structure |
|----------|-------|----------------|
| Domain frequency | Global | Count-Min Sketch |
| IP frequency | Global | Count-Min Sketch |
| Process frequency | Global | Count-Min Sketch |
| Process-domain pairs | Per-endpoint | HashMap |
| Parent-child patterns | Global | HashMap |
| Hourly activity | Per-endpoint | [u64; 24] |
| Connection patterns | Per-destination | CircularBuffer |

**Tasks:**
- [ ] Implement Count-Min Sketch
- [ ] Create frequency counters for each baseline type
- [ ] Implement first-seen tracking
- [ ] Build time histogram for activity patterns
- [ ] Create connection pattern tracker (beaconing)
- [ ] Implement anomaly scorer
- [ ] Add baseline persistence (save/load)
- [ ] Create baseline snapshot export

### 1.5 Storage Engine

**Stream Buffer (Outbound):**
```rust
// ironclaw-storage/src/stream.rs

pub struct StreamBuffer {
    db: Connection,
    max_size_bytes: u64,
    max_age_days: u32,
}

impl StreamBuffer {
    pub async fn push(&self, event: &ProcessedEvent) -> Result<(), StorageError> {
        let payload = rmp_serde::to_vec(event)?;

        self.db.execute(
            "INSERT INTO stream_buffer (id, event_type, timestamp, payload, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                event.id().to_string(),
                event.event_type().as_str(),
                event.timestamp(),
                payload,
                Utc::now().timestamp(),
            ],
        )?;

        // Check size limit
        self.enforce_limits().await?;

        Ok(())
    }

    pub async fn pop_batch(&self, max_count: usize) -> Result<Vec<ProcessedEvent>, StorageError> {
        let mut stmt = self.db.prepare(
            "SELECT id, payload FROM stream_buffer
             ORDER BY created_at ASC
             LIMIT ?1"
        )?;

        let events: Vec<ProcessedEvent> = stmt
            .query_map([max_count], |row| {
                let payload: Vec<u8> = row.get(1)?;
                let event: ProcessedEvent = rmp_serde::from_slice(&payload)?;
                Ok(event)
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(events)
    }

    pub async fn confirm(&self, event_ids: &[Uuid]) -> Result<(), StorageError> {
        let ids: Vec<String> = event_ids.iter().map(|id| id.to_string()).collect();
        let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");

        self.db.execute(
            &format!("DELETE FROM stream_buffer WHERE id IN ({})", placeholders),
            rusqlite::params_from_iter(ids),
        )?;

        Ok(())
    }
}
```

**Extended Store (Local Retention):**
```rust
// ironclaw-storage/src/extended.rs

pub struct ExtendedStore {
    db: Connection,
    max_size_bytes: u64,
    max_age_days: u32,
}

impl ExtendedStore {
    pub async fn store(&self, event: &ProcessedEvent) -> Result<(), StorageError> {
        let payload = rmp_serde::to_vec(event)?;

        // Store with denormalized fields for fast filtering
        self.db.execute(
            "INSERT INTO events (id, event_type, timestamp, process_name, query_name,
             remote_ip, file_path, registry_path, user_name, payload, anomaly_score, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                event.id().to_string(),
                event.event_type().as_str(),
                event.timestamp(),
                event.process_name(),
                event.query_name(),
                event.remote_ip(),
                event.file_path(),
                event.registry_path(),
                event.user_name(),
                payload,
                event.anomaly_score(),
                Utc::now().timestamp(),
            ],
        )?;

        Ok(())
    }

    pub async fn query(&self, query: &LocalQuery) -> Result<Vec<ProcessedEvent>, StorageError> {
        let sql = self.build_query_sql(query)?;
        let mut stmt = self.db.prepare(&sql)?;

        let events: Vec<ProcessedEvent> = stmt
            .query_map([], |row| {
                let payload: Vec<u8> = row.get("payload")?;
                rmp_serde::from_slice(&payload).map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                    0, rusqlite::types::Type::Blob, Box::new(e)
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(events)
    }

    pub async fn prune(&self) -> Result<u64, StorageError> {
        let cutoff = Utc::now().timestamp() - (self.max_age_days as i64 * 86400);

        let deleted = self.db.execute(
            "DELETE FROM events WHERE created_at < ?1",
            [cutoff],
        )?;

        // Also enforce size limit
        self.enforce_size_limit().await?;

        Ok(deleted as u64)
    }
}
```

**Encryption:**
```rust
// ironclaw-storage/src/encryption.rs

pub fn open_encrypted_db(path: &Path) -> Result<Connection, DbError> {
    let key = derive_db_key()?;

    let conn = Connection::open(path)?;
    conn.pragma_update(None, "key", &hex::encode(&key))?;
    conn.pragma_update(None, "cipher_page_size", &4096)?;
    conn.pragma_update(None, "kdf_iter", &256000)?;
    conn.pragma_update(None, "journal_mode", &"WAL")?;

    Ok(conn)
}

fn derive_db_key() -> Result<[u8; 32], KeyError> {
    // Derive key from machine-specific data
    let machine_id = get_machine_guid()?;
    let volume_serial = get_volume_serial()?;

    let salt = format!("{}:{}", machine_id, volume_serial);

    let mut key = [0u8; 32];
    ring::hkdf::Hkdf::<ring::hkdf::HkdfSha256>::new(
        Some(salt.as_bytes()),
        b"ironclaw-db-key",
    )
    .expand(&[], &mut key)?;

    Ok(key)
}
```

**Tasks:**
- [ ] Create SQLite database schema
- [ ] Implement stream buffer (outbound queue)
- [ ] Implement extended store (local retention)
- [ ] Add SQLCipher encryption
- [ ] Create key derivation
- [ ] Implement retention management (age/size limits)
- [ ] Add database vacuum/optimize

### 1.6 Transport Engine

**HTTP Client:**
```rust
// ironclaw-transport/src/http.rs

pub struct TransportEngine {
    config: TransportConfig,
    client: reqwest::Client,
    buffer: Arc<StreamBuffer>,
}

impl TransportEngine {
    pub async fn run(&self, mut shutdown: broadcast::Receiver<()>) -> Result<(), TransportError> {
        let mut interval = tokio::time::interval(Duration::from_secs(10));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.ship_batch().await {
                        tracing::warn!("Failed to ship batch: {}", e);
                    }
                }
                _ = shutdown.recv() => {
                    // Flush remaining events before shutdown
                    self.flush().await?;
                    break;
                }
            }
        }

        Ok(())
    }

    async fn ship_batch(&self) -> Result<(), TransportError> {
        let events = self.buffer.pop_batch(self.config.batch.max_events).await?;

        if events.is_empty() {
            return Ok(());
        }

        let batch = TelemetryBatch {
            batch_id: Uuid::new_v4(),
            endpoint_id: self.config.endpoint_id.clone(),
            client_id: self.config.client_id.clone(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: Utc::now().timestamp(),
            compression: Compression::Zstd,
            event_count: events.len() as u32,
            payload: self.compress_events(&events)?,
        };

        let response = self
            .client
            .post(&format!("{}/v1/telemetry", self.config.platform_url))
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .json(&batch)
            .send()
            .await?;

        if response.status().is_success() {
            let event_ids: Vec<Uuid> = events.iter().map(|e| e.id()).collect();
            self.buffer.confirm(&event_ids).await?;
            tracing::debug!("Shipped {} events", events.len());
        } else {
            tracing::warn!("Server returned {}: {:?}", response.status(), response.text().await);
        }

        Ok(())
    }

    fn compress_events(&self, events: &[ProcessedEvent]) -> Result<Vec<u8>, TransportError> {
        let json = serde_json::to_vec(events)?;
        let compressed = zstd::encode_all(&json[..], 3)?;
        Ok(compressed)
    }
}
```

**Tasks:**
- [ ] Implement HTTPS client with TLS
- [ ] Create event batching logic
- [ ] Add compression (zstd)
- [ ] Implement retry with exponential backoff
- [ ] Add certificate pinning
- [ ] Create heartbeat/registration

### 1.7 Forensic Collector

**Collection Profiles:**

| Profile | Artifacts | Size | Time |
|---------|-----------|------|------|
| triage | System state, persistence | 10-50 MB | <1 min |
| standard | + Execution evidence | 50-200 MB | 2-5 min |
| full | + Logs, filesystem | 500 MB-2 GB | 10-30 min |
| forensic | + MFT, memory | 2-10 GB | 30-60 min |

**Artifact Collectors:**
```rust
// ironclaw-forensic/src/artifacts/system.rs

pub struct SystemStateCollector;

impl ArtifactCollector for SystemStateCollector {
    fn name(&self) -> &str { "system_state" }

    fn artifact_type(&self) -> ArtifactType { ArtifactType::SystemState }

    async fn collect(&self, output: &mut CollectionOutput) -> Result<(), CollectorError> {
        // Running processes
        let processes = self.collect_processes().await?;
        output.add_artifact(processes, "system/processes.json")?;

        // Open network connections
        let connections = self.collect_connections().await?;
        output.add_artifact(connections, "system/connections.json")?;

        // Loaded modules
        let modules = self.collect_loaded_modules().await?;
        output.add_artifact(modules, "system/modules.json")?;

        // Services
        let services = self.collect_services().await?;
        output.add_artifact(services, "system/services.json")?;

        // Scheduled tasks
        let tasks = self.collect_scheduled_tasks().await?;
        output.add_artifact(tasks, "system/scheduled_tasks.json")?;

        Ok(())
    }
}

// ironclaw-forensic/src/artifacts/persistence.rs

pub struct PersistenceCollector;

impl ArtifactCollector for PersistenceCollector {
    async fn collect(&self, output: &mut CollectionOutput) -> Result<(), CollectorError> {
        // Registry run keys
        let run_keys = self.collect_run_keys().await?;
        output.add_artifact(run_keys, "persistence/run_keys.json")?;

        // Services (persistence)
        let services = self.collect_service_persistence().await?;
        output.add_artifact(services, "persistence/services.json")?;

        // WMI subscriptions
        let wmi = self.collect_wmi_persistence().await?;
        output.add_artifact(wmi, "persistence/wmi.json")?;

        // Browser extensions
        let extensions = self.collect_browser_extensions().await?;
        output.add_artifact(extensions, "persistence/browser_extensions.json")?;

        // Startup folder
        let startup = self.collect_startup_items().await?;
        output.add_artifact(startup, "persistence/startup.json")?;

        Ok(())
    }
}
```

**Collection Orchestrator:**
```rust
// ironclaw-forensic/src/collector.rs

pub struct ForensicCollector {
    collectors: HashMap<String, Box<dyn ArtifactCollector>>,
}

impl ForensicCollector {
    pub fn new() -> Self {
        let mut collectors: HashMap<String, Box<dyn ArtifactCollector>> = HashMap::new();

        collectors.insert("system_state".into(), Box::new(SystemStateCollector));
        collectors.insert("persistence".into(), Box::new(PersistenceCollector));
        collectors.insert("execution".into(), Box::new(ExecutionCollector));
        collectors.insert("filesystem".into(), Box::new(FilesystemCollector));
        collectors.insert("logs".into(), Box::new(LogCollector));
        collectors.insert("browser".into(), Box::new(BrowserCollector));
        collectors.insert("memory".into(), Box::new(MemoryCollector));

        Self { collectors }
    }

    pub async fn collect(&self, request: &CollectionRequest) -> Result<PackagedCollection, CollectorError> {
        let mut output = CollectionOutput::new(&request.request_id)?;

        // Get artifacts for profile
        let artifacts = self.get_profile_artifacts(&request.profile);

        for artifact_type in artifacts {
            if let Some(collector) = self.collectors.get(artifact_type) {
                tracing::info!("Collecting {}", artifact_type);
                collector.collect(&mut output).await?;
            }
        }

        // Collect custom artifacts
        if let Some(custom) = &request.custom_artifacts {
            for artifact_type in custom {
                if let Some(collector) = self.collectors.get(artifact_type.as_str()) {
                    collector.collect(&mut output).await?;
                }
            }
        }

        // Collect specific files
        if let Some(files) = &request.target_files {
            self.collect_files(files, &mut output).await?;
        }

        // Package and encrypt
        let package = output.package().await?;

        Ok(package)
    }
}
```

**Tasks:**
- [ ] Implement system state collector
- [ ] Implement persistence collector
- [ ] Implement execution evidence collector (Prefetch, Shimcache)
- [ ] Implement filesystem collector (MFT, USN)
- [ ] Implement log collector
- [ ] Implement browser history collector
- [ ] Implement memory acquisition
- [ ] Create collection packager (compress + encrypt)
- [ ] Add upload to backend

### 1.8 Query Handler

**Remote Query Execution:**
```rust
// ironclaw-query/src/executor.rs

pub struct QueryExecutor {
    extended_store: Arc<ExtendedStore>,
}

impl QueryExecutor {
    pub async fn execute(&self, query: &HuntQuery) -> Result<QueryResult, QueryError> {
        // Validate query
        self.validate_query(query)?;

        // Build local query
        let local_query = LocalQuery {
            time_range: query.time_range.clone(),
            data_sources: query.data_sources.clone(),
            filters: query.filters.clone(),
            limit: query.limit.unwrap_or(10000),
        };

        // Execute against extended store
        let events = self.extended_store.query(&local_query).await?;

        // Apply output formatting
        let formatted = match query.output_format {
            OutputFormat::Json => self.format_json(&events)?,
            OutputFormat::Csv => self.format_csv(&events)?,
            OutputFormat::Ndjson => self.format_ndjson(&events)?,
        };

        // Check size limit
        if formatted.len() as u64 > query.max_result_size {
            return Ok(QueryResult {
                query_id: query.query_id,
                status: QueryStatus::Truncated,
                data: formatted[..query.max_result_size as usize].to_vec(),
                total_matches: events.len(),
            });
        }

        Ok(QueryResult {
            query_id: query.query_id,
            status: QueryStatus::Complete,
            data: formatted,
            total_matches: events.len(),
        })
    }
}
```

**Tasks:**
- [ ] Implement query parser
- [ ] Create query executor
- [ ] Add result streaming
- [ ] Implement result size limiting
- [ ] Add query timeout handling

### 1.9 Windows Service

**Service Integration:**
```rust
// ironclaw-agent/src/service.rs

use windows_service::prelude::*;

const SERVICE_NAME: &str = "IronclawAgent";
const SERVICE_DISPLAY: &str = "Ironclaw Security Agent";

define_windows_service!(ffi_service_main, service_main);

fn service_main(arguments: Vec<OsString>) {
    if let Err(e) = run_service(arguments) {
        tracing::error!("Service failed: {}", e);
    }
}

fn run_service(_arguments: Vec<OsString>) -> Result<(), Error> {
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                shutdown_tx.send(()).ok();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    // Run the agent
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let mut agent = Agent::new().await?;
        agent.run(shutdown_rx).await
    })?;

    status_handle.set_service_status(ServiceStatus {
        current_state: ServiceState::Stopped,
        ..Default::default()
    })?;

    Ok(())
}

pub fn install_service() -> Result<(), Error> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        launch_arguments: vec![OsString::from("service")],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    let _service = manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;

    Ok(())
}
```

**Tasks:**
- [ ] Implement Windows service wrapper
- [ ] Add service install/uninstall commands
- [ ] Create service recovery options
- [ ] Implement graceful shutdown

---

## Phase 2: Linux Agent (Weeks 17-24)

### 2.1 eBPF Collection

```rust
// ironclaw-collector/src/linux/ebpf.rs

use aya::prelude::*;

pub struct EbpfCollector {
    bpf: Bpf,
    event_tx: mpsc::Sender<RawEvent>,
}

impl EbpfCollector {
    pub async fn new(event_tx: mpsc::Sender<RawEvent>) -> Result<Self, CollectorError> {
        let bpf = Bpf::load(include_bytes_aligned!("../../ebpf/target/dns_monitor.o"))?;

        Ok(Self { bpf, event_tx })
    }

    pub async fn start_dns_monitor(&mut self) -> Result<(), CollectorError> {
        let program: &mut Kprobe = self.bpf.program_mut("dns_query").unwrap().try_into()?;
        program.load()?;
        program.attach("udp_sendmsg", 0)?;

        // Set up ring buffer for events
        let ring_buf = RingBuf::try_from(self.bpf.map_mut("events")?)?;

        tokio::spawn(async move {
            loop {
                if let Some(event) = ring_buf.next() {
                    let dns_event = DnsQueryEvent::from_bytes(&event);
                    self.event_tx.send(RawEvent::Dns(dns_event)).await.ok();
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        Ok(())
    }
}
```

**eBPF Programs:**

| Program | Hook | Purpose |
|---------|------|---------|
| dns_monitor | udp_sendmsg | DNS queries |
| tcp_connect | tcp_v4_connect | Outbound TCP |
| process_exec | sched_process_exec | Process execution |
| process_exit | sched_process_exit | Process termination |
| file_open | security_file_open | File access |

**Tasks:**
- [ ] Implement eBPF DNS monitor
- [ ] Implement eBPF TCP connect monitor
- [ ] Implement eBPF process exec monitor
- [ ] Create ring buffer handler
- [ ] Add fallback to auditd

### 2.2 systemd Integration

```ini
# /etc/systemd/system/ironclaw.service

[Unit]
Description=Ironclaw Security Agent
After=network.target

[Service]
Type=notify
ExecStart=/usr/local/bin/ironclaw-agent
Restart=always
RestartSec=10
User=ironclaw
AmbientCapabilities=CAP_NET_ADMIN CAP_BPF CAP_PERFMON

[Install]
WantedBy=multi-user.target
```

**Tasks:**
- [ ] Create systemd service file
- [ ] Implement sd_notify integration
- [ ] Add signal handling (SIGTERM, SIGHUP)

---

## Phase 3: macOS Agent (Weeks 25-32)

### 3.1 Network Extension

```swift
// MacOS Network Extension for DNS monitoring

import NetworkExtension

class IronclawFilterDataProvider: NEFilterDataProvider {
    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        // Configure filter settings
        let settings = NEFilterSettings(rules: [], defaultAction: .filterData)
        apply(settings) { error in
            completionHandler(error)
        }
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        if let socketFlow = flow as? NEFilterSocketFlow,
           let remoteEndpoint = socketFlow.remoteEndpoint as? NWHostEndpoint {

            // Log DNS query
            if socketFlow.remotePort == "53" {
                // Extract DNS query from flow
                self.logDnsQuery(flow: socketFlow)
            }
        }

        return .allow()
    }
}
```

### 3.2 Endpoint Security Framework

```swift
// Endpoint Security for process monitoring

import EndpointSecurity

class IronclawEndpointSecurity {
    var client: OpaquePointer?

    func start() throws {
        var newClient: OpaquePointer?

        let result = es_new_client(&newClient) { [weak self] _, message in
            self?.handleEvent(message)
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS else {
            throw IronclawError.endpointSecurityInit
        }

        client = newClient

        // Subscribe to events
        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_OPEN,
            ES_EVENT_TYPE_NOTIFY_FORK,
        ]

        es_subscribe(client!, events, UInt32(events.count))
    }

    func handleEvent(_ message: UnsafePointer<es_message_t>) {
        switch message.pointee.event_type {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            handleExec(message)
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            handleFileOpen(message)
        default:
            break
        }
    }
}
```

**Tasks:**
- [ ] Create Network Extension for DNS
- [ ] Implement Endpoint Security handler
- [ ] Add notarization and code signing
- [ ] Create PKG installer

---

## Resource Limits

| Resource | Target | Maximum |
|----------|--------|---------|
| CPU (average) | <0.5% | 1% |
| CPU (peak) | <5% | 10% |
| Memory (working set) | <30 MB | 50 MB |
| Memory (peak) | <75 MB | 100 MB |
| Disk I/O (sustained) | <1 MB/s | 5 MB/s |
| Network (sustained) | <100 KB/s | 500 KB/s |
| Disk space | <500 MB | 2 GB |

---

## Build & Packaging

### Windows

```toml
# Cargo.toml release profile
[profile.release]
opt-level = 3
lto = "thin"
codegen-units = 1
panic = "abort"
strip = "symbols"
```

**Packaging:**
- WiX MSI installer
- EV code signing certificate
- Service registration

### Linux

**Packaging:**
- DEB package (Debian/Ubuntu)
- RPM package (RHEL/CentOS)
- Tarball with install script

### macOS

**Packaging:**
- PKG installer
- System Extension
- Notarization required
- Developer ID signing

---

## Testing

| Test Type | Coverage |
|-----------|----------|
| Unit tests | >80% |
| Integration tests | All collectors |
| Platform tests | Windows, Linux, macOS |
| Performance tests | Resource limits |
| Security tests | Memory safety, input validation |

---

*Document Version: 2.0 - January 2026*
