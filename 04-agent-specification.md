# IRONCLAW Requirements - Part 4: Agent Specification

## 4.1 Agent Overview

The Ironclaw agent is a lightweight Rust binary that:
- Collects security telemetry from Windows endpoints
- Performs local invariant checks
- Pre-classifies events with risk flags
- Ships events with end-to-end encryption
- Enforces policies from the backend

### 4.1.1 Design Goals

| Goal | Target |
|------|--------|
| Binary size | < 10 MB |
| Memory usage (idle) | < 50 MB |
| Memory usage (active) | < 150 MB |
| CPU usage (average) | < 2% |
| Event latency | < 30 seconds |
| Reliability | Zero event loss (buffered) |

## 4.2 Collection Sources

### 4.2.1 Primary Sources

| Source | Events | Priority |
|--------|--------|----------|
| **Sysmon** | Process, Network, File, Registry, DLL, DNS | Critical |
| **Windows Security** | Logon, Privilege, Object Access | High |
| **PowerShell** | Script block, module load | High |
| **Windows Defender** | Detections, scans | Medium |

### 4.2.2 Sysmon Event Coverage

| Event ID | Type | Collection |
|----------|------|------------|
| 1 | Process Create | Always |
| 2 | File creation time changed | Always |
| 3 | Network Connection | Always |
| 5 | Process Terminate | Configurable |
| 6 | Driver Load | Always |
| 7 | Image/DLL Load | Configurable |
| 8 | CreateRemoteThread | Always |
| 9 | RawAccessRead | Configurable |
| 10 | Process Access | Always |
| 11 | File Create | Configurable (by path) |
| 12-14 | Registry | Configurable (by key) |
| 15 | FileCreateStreamHash | Always |
| 17-18 | Pipe | Configurable |
| 19-21 | WMI | Always |
| 22 | DNS Query | Always |
| 23 | File Delete | Configurable |
| 24 | Clipboard | Never (privacy) |
| 25 | Process Tampering | Always |
| 26 | File Delete Logged | Configurable |

### 4.2.3 Windows Security Events

| Event ID | Type | Collection |
|----------|------|------------|
| 4624 | Successful Logon | Always |
| 4625 | Failed Logon | Always |
| 4634 | Logoff | Configurable |
| 4648 | Explicit Credential Logon | Always |
| 4656 | Object Handle Request | Configurable |
| 4657 | Registry Value Modified | Configurable |
| 4663 | Object Access Attempt | Configurable |
| 4672 | Special Privileges Assigned | Always |
| 4688 | Process Create (if Sysmon unavailable) | Fallback |
| 4697 | Service Installed | Always |
| 4698 | Scheduled Task Created | Always |
| 4720 | User Account Created | Always |
| 4732 | Member Added to Security Group | Always |

## 4.3 Agent Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            IRONCLAW AGENT                                   │
│                                                                             │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                        COLLECTOR LAYER                             │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │    │
│  │  │   Sysmon     │  │   Security   │  │  PowerShell  │             │    │
│  │  │  Collector   │  │  Collector   │  │  Collector   │             │    │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘             │    │
│  └─────────┼─────────────────┼─────────────────┼───────────────────────┘    │
│            │                 │                 │                            │
│            └─────────────────┼─────────────────┘                            │
│                              ▼                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                       PROCESSING LAYER                             │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │    │
│  │  │   Parser     │  │  Invariant   │  │    Risk      │             │    │
│  │  │              │──▶│   Checker    │──▶│   Flagger    │             │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │    │
│  └──────────────────────────────┬─────────────────────────────────────┘    │
│                                 │                                          │
│                                 ▼                                          │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                        BUFFER LAYER                                │    │
│  │  ┌──────────────────────────────────────────────────────────────┐ │    │
│  │  │                    Memory Ring Buffer                        │ │    │
│  │  │                    (10,000 events)                           │ │    │
│  │  └──────────────────────────┬───────────────────────────────────┘ │    │
│  │                             │ (overflow)                          │    │
│  │  ┌──────────────────────────▼───────────────────────────────────┐ │    │
│  │  │                    Disk Spool                                │ │    │
│  │  │                    (configurable size)                       │ │    │
│  │  └──────────────────────────────────────────────────────────────┘ │    │
│  └──────────────────────────────┬─────────────────────────────────────┘    │
│                                 │                                          │
│                                 ▼                                          │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                       TRANSPORT LAYER                              │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │    │
│  │  │    Batch     │  │   Encrypt    │  │    HTTP      │             │    │
│  │  │   Builder    │──▶│   (E2E)      │──▶│   Shipper    │             │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘             │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 4.4 Cryptographic Protocol

### 4.4.1 Key Management

```
Agent Installation:
┌─────────┐                                    ┌─────────┐
│  Agent  │                                    │ Backend │
└────┬────┘                                    └────┬────┘
     │                                              │
     │  1. Generate X25519 keypair                  │
     │     agent_private, agent_public              │
     │                                              │
     │  2. POST /api/v1/agents/register             │
     │     {hostname, os_info, agent_public}        │
     │─────────────────────────────────────────────▶│
     │                                              │
     │                            3. Verify request │
     │                               Store agent    │
     │                               Generate ID    │
     │                                              │
     │  4. Response                                 │
     │     {agent_id, backend_public, policy}       │
     │◀─────────────────────────────────────────────│
     │                                              │
     │  5. Store backend_public                     │
     │     Compute shared_secret = X25519(          │
     │       agent_private, backend_public)         │
     │                                              │
```

### 4.4.2 Message Encryption

```
Event Shipping:
┌─────────┐                                    ┌─────────┐
│  Agent  │                                    │ Backend │
└────┬────┘                                    └────┬────┘
     │                                              │
     │  1. Batch events (up to 1000 or 30s)        │
     │     events = [event1, event2, ...]          │
     │                                              │
     │  2. Generate ephemeral X25519 keypair       │
     │     ephemeral_private, ephemeral_public     │
     │                                              │
     │  3. Derive encryption key                   │
     │     shared = X25519(ephemeral_private,      │
     │                     backend_public)          │
     │     key = HKDF-SHA256(shared, salt, info)   │
     │                                              │
     │  4. Encrypt payload                         │
     │     nonce = random(12)                      │
     │     ciphertext = ChaCha20-Poly1305(         │
     │       key, nonce, compress(events))         │
     │                                              │
     │  5. Sign message                            │
     │     timestamp = now()                       │
     │     signature = Ed25519.sign(               │
     │       agent_private,                        │
     │       hash(agent_id | timestamp |           │
     │            ephemeral_public | ciphertext))  │
     │                                              │
     │  6. POST /api/v1/agents/{id}/events         │
     │     {ephemeral_public, nonce, ciphertext,   │
     │      timestamp, signature}                  │
     │─────────────────────────────────────────────▶│
     │                                              │
     │                         7. Verify signature │
     │                            Check timestamp  │
     │                            (replay window)  │
     │                                              │
     │                         8. Derive same key  │
     │                            shared = X25519( │
     │                              backend_priv,  │
     │                              ephemeral_pub) │
     │                            key = HKDF(...)  │
     │                                              │
     │                         9. Decrypt payload  │
     │                            decompress       │
     │                            validate events  │
     │                                              │
     │  10. Response {status: "ok", count: N}      │
     │◀─────────────────────────────────────────────│
```

### 4.4.3 Security Properties

| Property | Mechanism |
|----------|-----------|
| Confidentiality | ChaCha20-Poly1305 AEAD |
| Integrity | Poly1305 MAC + Ed25519 signature |
| Authentication | Ed25519 signature per message |
| Forward Secrecy | Ephemeral X25519 per batch |
| Replay Prevention | Timestamp + signature (5-minute window) |
| Proxy Transparency | TLS is transport only; payload encrypted |

## 4.5 Local Processing

### 4.5.1 Invariant Checks

The agent performs immediate invariant checks on certain events:

```rust
enum Invariant {
    // Process access to LSASS
    LsassAccess {
        source_process: String,
        access_mask: u32,
    },
    
    // Unsigned kernel driver load
    UnsignedDriver {
        driver_path: String,
        hash: String,
    },
    
    // Credential dumping patterns
    CredentialDumping {
        process: String,
        target: String,
        technique: String,
    },
    
    // Process injection
    ProcessInjection {
        source_process: String,
        target_process: String,
        technique: String,  // CreateRemoteThread, QueueAPC, etc.
    },
}
```

**Invariant behavior:**
- These events are **always** sent immediately (not batched)
- They are flagged as `invariant_violation: true`
- They can **never** become baselines
- Backend creates immediate findings

### 4.5.2 Risk Flagging

The agent adds risk flags to events based on local analysis:

```rust
enum RiskFlag {
    // Software identity
    UnsignedExecutable,
    SignerNotTrusted,
    PathUserWritable,    // Running from user-writable location
    PathNotStandard,     // Not in standard install locations
    
    // Process behavior
    EncodedCommandLine,  // Base64 or other encoding detected
    LongCommandLine,     // > 1000 characters
    SuspiciousArguments, // Contains known-bad patterns
    
    // Network behavior  
    RarePort,           // Port not commonly seen
    DirectIpConnection, // No DNS lookup first
    TorExitNode,        // Connects to known Tor exit
    
    // File behavior
    ExecutableInTemp,   // Executable written to temp
    AlternateDataStream,// ADS usage
    
    // Context
    FirstSeen,          // Never seen this on this host
    RareParentChild,    // Unusual process relationship
}
```

### 4.5.3 Pre-Classification

```rust
struct EventClassification {
    // Source event type
    event_type: EventType,
    
    // Risk assessment
    risk_flags: Vec<RiskFlag>,
    risk_score: u8,  // 0-100
    
    // Invariant status
    invariant_violation: Option<Invariant>,
    
    // Software identity (if determinable locally)
    software_identity: Option<SoftwareIdentity>,
}

struct SoftwareIdentity {
    name: String,
    version: Option<String>,
    signer: Option<String>,
    signer_thumbprint: Option<String>,
    product_code: Option<String>,  // MSI GUID
}
```

## 4.6 Configuration

### 4.6.1 Agent Configuration File

```yaml
# ironclaw-agent.yaml

agent:
  id: null  # Set after registration
  
backend:
  url: "https://ironclaw.example.com"
  verify_tls: true
  ca_cert: null  # Optional custom CA
  
collection:
  sysmon:
    enabled: true
    # Event IDs to collect (beyond mandatory)
    optional_events: [5, 7, 9, 11, 12, 13, 14, 17, 18, 23]
    # File event path filters
    file_paths:
      include:
        - "C:\\Users\\*\\Downloads\\*"
        - "C:\\Users\\*\\AppData\\*"
        - "C:\\Windows\\Temp\\*"
      exclude:
        - "C:\\Windows\\Prefetch\\*"
    # Registry key filters
    registry_keys:
      include:
        - "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*"
        - "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*"
        
  security_log:
    enabled: true
    event_ids: [4624, 4625, 4634, 4648, 4672, 4697, 4698, 4720, 4732]
    
  powershell:
    enabled: true
    script_block_logging: true
    module_logging: true
    
buffer:
  memory_events: 10000
  disk_spool_mb: 500
  disk_spool_path: "C:\\ProgramData\\Ironclaw\\spool"
  
transport:
  batch_size: 1000
  batch_timeout_seconds: 30
  retry_attempts: 5
  retry_backoff_seconds: [1, 5, 15, 60, 300]
  
logging:
  level: "info"  # debug, info, warn, error
  file: "C:\\ProgramData\\Ironclaw\\logs\\agent.log"
  max_size_mb: 100
  max_files: 5
```

### 4.6.2 Policy (Pushed from Backend)

```yaml
# Policy version 42
version: 42
hash: "sha256:abc123..."

# Invariants (cannot be overridden locally)
invariants:
  lsass_access:
    enabled: true
    allowed_processes: []  # No exceptions
    
  unsigned_drivers:
    enabled: true
    
  credential_dumping:
    enabled: true
    
# Collection tuning
collection:
  dll_events:
    enabled: true
    exclude_known_good: true  # Skip NSRL-known DLLs
    
  file_events:
    enabled: true
    paths:
      include:
        - "C:\\Users\\*\\Downloads\\*"
        
# Rate limiting
rate_limits:
  events_per_second: 1000
  network_events_per_second: 500
  
# Local detection rules (lightweight, pushed from backend)
detection_filters:
  - name: "encoded_powershell"
    event_type: "process_create"
    conditions:
      process_name: "powershell.exe"
      command_line_contains: ["-enc", "-encoded", "-e "]
    action: "flag"
    flag: "encoded_powershell"
```

## 4.7 Deployment

### 4.7.1 Installation

```powershell
# Silent installation
msiexec /i ironclaw-agent.msi /qn BACKEND_URL="https://ironclaw.example.com" REGISTRATION_TOKEN="abc123"

# With custom config
msiexec /i ironclaw-agent.msi /qn CONFIG_PATH="C:\path\to\config.yaml"
```

### 4.7.2 Service Management

```
Service Name: IronclawAgent
Display Name: Ironclaw Security Agent
Startup Type: Automatic (Delayed Start)
Recovery: Restart on failure (1min, 5min, 10min)
Dependencies: EventLog, Sysmon
```

### 4.7.3 File Locations

| Path | Purpose |
|------|---------|
| `C:\Program Files\Ironclaw\` | Agent binary and dependencies |
| `C:\ProgramData\Ironclaw\config\` | Configuration files |
| `C:\ProgramData\Ironclaw\keys\` | Cryptographic keys (ACL restricted) |
| `C:\ProgramData\Ironclaw\spool\` | Disk buffer for events |
| `C:\ProgramData\Ironclaw\logs\` | Agent logs |

---

*Previous: [Part 3: Data Architecture](03-data-architecture.md) | Next: [Part 5: Backend Services](05-backend-services.md)*
