//! Local risk classification and invariant detection.
//!
//! Implements §4.5 of the agent specification (Local Processing). The classifier
//! reads the parsed Sysmon/Security payload fields and attaches:
//!   - `risk_flags`     — qualitative signals (encoded PowerShell, exe in temp, …)
//!   - `risk_score`     — coarse 0..=100 aggregate of the flags
//!   - `invariant_violation` — fires on always-bad behaviors (LSASS access, etc.)
//!
//! The classifier is pure: it never performs IO and never depends on baseline
//! history, so it is safe to call on every event in the agent's intake loop.

use serde::{Deserialize, Serialize};

use crate::event::{Event, EventType};
use crate::policy::PolicyInvariants;

/// Risk indicators attached by the local classifier (§4.5.2 of the spec).
/// Variants are restricted to flags that can be computed from the parsed event
/// payload without any external lookup. Baseline/history-dependent flags
/// (`FirstSeen`, `RareParentChild`, `TorExitNode`, …) are intentionally omitted
/// until the baseline engine lands.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskFlag {
    UnsignedExecutable,
    EncodedCommandLine,
    LongCommandLine,
    SuspiciousArguments,
    ExecutableInTemp,
    PathUserWritable,
    PathNotStandard,
    RarePort,
}

impl RiskFlag {
    /// Weight contributed to `risk_score`. Sum is clamped to 100.
    fn weight(self) -> u8 {
        match self {
            RiskFlag::UnsignedExecutable => 25,
            RiskFlag::EncodedCommandLine => 35,
            RiskFlag::LongCommandLine => 10,
            RiskFlag::SuspiciousArguments => 30,
            RiskFlag::ExecutableInTemp => 30,
            RiskFlag::PathUserWritable => 15,
            RiskFlag::PathNotStandard => 15,
            RiskFlag::RarePort => 20,
        }
    }
}

/// Hard-rule violations (§4.5.1). When set, the event represents a behavior
/// that is "always bad" by policy and should be surfaced as a finding by HQ.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InvariantViolation {
    LsassAccess {
        source_process: String,
        access_mask: String,
    },
    UnsignedDriver {
        driver_path: String,
    },
    CredentialDumping {
        process: String,
        target: String,
        technique: String,
    },
    ProcessInjection {
        source_process: String,
        target_process: String,
        technique: String,
    },
}

/// Run the classifier against an event, populating its `risk_flags`,
/// `risk_score`, and `invariant_violation` fields. Existing values are
/// preserved (the classifier only adds, never clears).
pub fn classify(event: &mut Event, invariants: &PolicyInvariants) {
    let mut flags: Vec<RiskFlag> = Vec::new();

    detect_risk_flags(event, &mut flags);
    let violation = detect_invariant(event, invariants);

    if !flags.is_empty() {
        let mut score: u16 = event.risk_score as u16;
        for f in &flags {
            score = score.saturating_add(f.weight() as u16);
        }
        event.risk_score = score.min(100) as u8;
        for f in flags {
            if !event.risk_flags.contains(&f) {
                event.risk_flags.push(f);
            }
        }
    }

    if let Some(v) = violation {
        // Invariant trips are top-severity — pin the score at 100.
        event.risk_score = 100;
        event.invariant_violation = Some(v);
    }
}

// ---------------------------------------------------------------------------
// Risk flag detection
// ---------------------------------------------------------------------------

fn detect_risk_flags(event: &Event, flags: &mut Vec<RiskFlag>) {
    let payload = &event.payload;
    let cmdline = payload_str(payload, "CommandLine");
    let image = payload_str(payload, "Image");

    // --- Process-create style signals (Sysmon ID 1 and similar)
    if !cmdline.is_empty() {
        let lower = cmdline.to_lowercase();
        if cmdline.chars().count() > 1000 {
            flags.push(RiskFlag::LongCommandLine);
        }
        if has_encoded_powershell(&lower) {
            flags.push(RiskFlag::EncodedCommandLine);
        }
        if has_suspicious_arguments(&lower) {
            flags.push(RiskFlag::SuspiciousArguments);
        }
    }

    if !image.is_empty() {
        let lower = image.to_lowercase();
        if is_user_writable_path(&lower) {
            flags.push(RiskFlag::PathUserWritable);
        }
        if is_temp_executable(&lower) {
            flags.push(RiskFlag::ExecutableInTemp);
        }
        if is_nonstandard_path(&lower) {
            flags.push(RiskFlag::PathNotStandard);
        }
    }

    if is_unsigned(payload) {
        flags.push(RiskFlag::UnsignedExecutable);
    }

    // --- Network-connection signals (Sysmon ID 3)
    if event.event_type == EventType::Network {
        if let Some(port) = payload_u64(payload, "DestinationPort") {
            if is_rare_port(port as u16) {
                flags.push(RiskFlag::RarePort);
            }
        }
    }
}

/// `-EncodedCommand` / `-enc` / inline FromBase64String invocations are the
/// classic obfuscation pattern. Matched case-insensitively on a pre-lowered
/// command line.
fn has_encoded_powershell(cmdline_lc: &str) -> bool {
    cmdline_lc.contains(" -enc ")
        || cmdline_lc.contains(" -encodedcommand")
        || cmdline_lc.contains(" -e ")
        || cmdline_lc.contains("frombase64string")
}

/// Known living-off-the-land / loader patterns. Conservative list — we err on
/// false negatives over false positives because the score is *aggregate*.
fn has_suspicious_arguments(cmdline_lc: &str) -> bool {
    const NEEDLES: &[&str] = &[
        "invoke-expression",
        "iex(",
        "iex (",
        "downloadstring",
        "downloadfile",
        "-nop ",
        "-noprofile ",
        "-windowstyle hidden",
        "-w hidden",
        "bypass",
        "-exec bypass",
        "mimikatz",
        "rundll32",
        "regsvr32 /s /n /u /i:http",
        "certutil -urlcache",
        "certutil -decode",
        "bitsadmin /transfer",
    ];
    NEEDLES.iter().any(|n| cmdline_lc.contains(n))
}

fn is_user_writable_path(image_lc: &str) -> bool {
    image_lc.starts_with("c:\\users\\")
}

fn is_temp_executable(image_lc: &str) -> bool {
    (image_lc.contains("\\temp\\") || image_lc.contains("\\appdata\\local\\temp\\"))
        && image_lc.ends_with(".exe")
}

fn is_nonstandard_path(image_lc: &str) -> bool {
    if !image_lc.ends_with(".exe") {
        return false;
    }
    // Standard install locations — everything else is "non-standard"
    let standard = [
        "c:\\windows\\system32\\",
        "c:\\windows\\syswow64\\",
        "c:\\windows\\winsxs\\",
        "c:\\program files\\",
        "c:\\program files (x86)\\",
        "c:\\programdata\\",
    ];
    !standard.iter().any(|p| image_lc.starts_with(p))
        // Don't double-flag temp paths — ExecutableInTemp covers that.
        && !is_temp_executable(image_lc)
}

fn is_unsigned(payload: &serde_json::Value) -> bool {
    // Sysmon DriverLoad / ImageLoad / ProcessCreate populate `Signed` and
    // sometimes `Signature`. Treat anything that explicitly says "false" or
    // "(unsigned)" as unsigned. Missing signature data → not flagged.
    let signed = payload_str(payload, "Signed").to_ascii_lowercase();
    if signed == "false" {
        return true;
    }
    let signature = payload_str(payload, "Signature").to_ascii_lowercase();
    signature == "(unsigned)" || signature == "unsigned"
}

fn is_rare_port(port: u16) -> bool {
    const COMMON_PORTS: &[u16] = &[
        20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 137, 138, 139, 143, 161, 162, 389, 443, 445,
        465, 514, 587, 636, 853, 989, 990, 993, 995, 1433, 1521, 1701, 1723, 3306, 3389, 5060,
        5061, 5432, 5985, 5986, 8080, 8443,
    ];
    !COMMON_PORTS.contains(&port)
}

// ---------------------------------------------------------------------------
// Invariant detection (§4.5.1)
// ---------------------------------------------------------------------------

fn detect_invariant(event: &Event, invariants: &PolicyInvariants) -> Option<InvariantViolation> {
    let eid = event.event_id?;
    let payload = &event.payload;

    match eid {
        // ProcessAccess: source process opening a handle to lsass.exe with
        // memory-read or dup-handle access. Classic credential dumping setup.
        10 if invariants.lsass_access.enabled => {
            let target = payload_str(payload, "TargetImage").to_ascii_lowercase();
            if !target.ends_with("\\lsass.exe") {
                return None;
            }
            let access = payload_str(payload, "GrantedAccess");
            let access_lc = access.to_ascii_lowercase();
            // PROCESS_VM_READ (0x10) / PROCESS_DUP_HANDLE (0x40) / PROCESS_QUERY_INFORMATION (0x400) / FULL_ACCESS
            let dangerous = access_lc.contains("0x10")
                || access_lc.contains("0x40")
                || access_lc.contains("0x1410")
                || access_lc.contains("0x1010")
                || access_lc.contains("0x1fffff");
            if !dangerous {
                return None;
            }
            let source = payload_str(payload, "SourceImage");
            // Filter out a couple of obvious system noisy callers.
            let source_lc = source.to_ascii_lowercase();
            if source_lc.ends_with("\\wininit.exe") || source_lc.ends_with("\\csrss.exe") {
                return None;
            }
            Some(InvariantViolation::LsassAccess {
                source_process: source,
                access_mask: access,
            })
        }

        // DriverLoad: unsigned kernel driver. Sysmon ID 6.
        6 if invariants.unsigned_drivers.enabled && is_unsigned(payload) => {
            Some(InvariantViolation::UnsignedDriver {
                driver_path: payload_str(payload, "ImageLoaded"),
            })
        }

        // ProcessCreate with credential-dumping tool signatures. Sysmon ID 1.
        1 if invariants.credential_dumping.enabled => {
            let cmdline = payload_str(payload, "CommandLine").to_ascii_lowercase();
            let image = payload_str(payload, "Image");
            let image_lc = image.to_ascii_lowercase();

            let technique = if cmdline.contains("mimikatz") || image_lc.ends_with("\\mimikatz.exe")
            {
                Some("mimikatz")
            } else if cmdline.contains("procdump") && cmdline.contains("lsass") {
                Some("procdump_lsass")
            } else if cmdline.contains("comsvcs.dll") && cmdline.contains("minidump") {
                Some("comsvcs_minidump")
            } else if cmdline.contains("rundll32") && cmdline.contains("lsass") {
                Some("rundll32_lsass")
            } else {
                None
            };

            technique.map(|t| InvariantViolation::CredentialDumping {
                process: image,
                target: "lsass.exe".to_string(),
                technique: t.to_string(),
            })
        }

        // CreateRemoteThread: cross-process thread injection. Sysmon ID 8.
        // Not gated on a separate invariant; reuses lsass_access as the
        // "process integrity" switch since the invariants struct doesn't
        // model injection independently in the current policy schema.
        8 if invariants.lsass_access.enabled => {
            let source = payload_str(payload, "SourceImage");
            let target = payload_str(payload, "TargetImage");
            // Same-process thread creation is benign noise.
            if source.eq_ignore_ascii_case(&target) {
                return None;
            }
            Some(InvariantViolation::ProcessInjection {
                source_process: source,
                target_process: target,
                technique: "create_remote_thread".to_string(),
            })
        }

        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Payload helpers
// ---------------------------------------------------------------------------

fn payload_str(payload: &serde_json::Value, key: &str) -> String {
    payload
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn payload_u64(payload: &serde_json::Value, key: &str) -> Option<u64> {
    payload.get(key).and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, EventType};
    use crate::policy::PolicyInvariants;
    use serde_json::json;

    fn proc_event(payload: serde_json::Value) -> Event {
        Event::new("test-agent", EventType::Process, "sysmon", Some(1), payload)
    }

    #[test]
    fn flags_encoded_powershell() {
        let mut ev = proc_event(json!({
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAA="
        }));
        classify(&mut ev, &PolicyInvariants::default());
        assert!(ev.risk_flags.contains(&RiskFlag::EncodedCommandLine));
        assert!(ev.risk_flags.contains(&RiskFlag::SuspiciousArguments));
        assert!(ev.risk_score > 0);
    }

    #[test]
    fn flags_temp_executable() {
        let mut ev = proc_event(json!({
            "Image": "C:\\Users\\ahmed\\AppData\\Local\\Temp\\setup.exe",
            "CommandLine": "setup.exe"
        }));
        classify(&mut ev, &PolicyInvariants::default());
        assert!(ev.risk_flags.contains(&RiskFlag::ExecutableInTemp));
        assert!(ev.risk_flags.contains(&RiskFlag::PathUserWritable));
    }

    #[test]
    fn no_flags_for_signed_system_binary() {
        let mut ev = proc_event(json!({
            "Image": "C:\\Windows\\System32\\svchost.exe",
            "CommandLine": "svchost.exe -k netsvcs",
            "Signed": "true"
        }));
        classify(&mut ev, &PolicyInvariants::default());
        assert!(ev.risk_flags.is_empty());
        assert_eq!(ev.risk_score, 0);
    }

    #[test]
    fn invariant_lsass_access() {
        let mut ev = Event::new(
            "test-agent",
            EventType::ProcessAccess,
            "sysmon",
            Some(10),
            json!({
                "SourceImage": "C:\\Users\\ahmed\\Downloads\\tool.exe",
                "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                "GrantedAccess": "0x1410"
            }),
        );
        classify(&mut ev, &PolicyInvariants::default());
        assert_eq!(ev.risk_score, 100);
        assert!(matches!(
            ev.invariant_violation,
            Some(InvariantViolation::LsassAccess { .. })
        ));
    }

    #[test]
    fn invariant_unsigned_driver() {
        let mut ev = Event::new(
            "test-agent",
            EventType::DriverLoad,
            "sysmon",
            Some(6),
            json!({
                "ImageLoaded": "C:\\Windows\\Temp\\bad.sys",
                "Signed": "false"
            }),
        );
        classify(&mut ev, &PolicyInvariants::default());
        assert_eq!(ev.risk_score, 100);
        assert!(matches!(
            ev.invariant_violation,
            Some(InvariantViolation::UnsignedDriver { .. })
        ));
    }

    #[test]
    fn invariant_mimikatz_cmdline() {
        let mut ev = proc_event(json!({
            "Image": "C:\\Users\\ahmed\\Downloads\\m.exe",
            "CommandLine": "m.exe mimikatz sekurlsa::logonpasswords"
        }));
        classify(&mut ev, &PolicyInvariants::default());
        assert_eq!(ev.risk_score, 100);
        assert!(matches!(
            ev.invariant_violation,
            Some(InvariantViolation::CredentialDumping { .. })
        ));
    }

    #[test]
    fn rare_port_flagged() {
        let mut ev = Event::new(
            "test-agent",
            EventType::Network,
            "sysmon",
            Some(3),
            json!({
                "Image": "C:\\Windows\\System32\\svchost.exe",
                "DestinationPort": 4444
            }),
        );
        classify(&mut ev, &PolicyInvariants::default());
        assert!(ev.risk_flags.contains(&RiskFlag::RarePort));
    }

    #[test]
    fn common_port_not_flagged() {
        let mut ev = Event::new(
            "test-agent",
            EventType::Network,
            "sysmon",
            Some(3),
            json!({
                "Image": "C:\\Windows\\System32\\svchost.exe",
                "DestinationPort": 443
            }),
        );
        classify(&mut ev, &PolicyInvariants::default());
        assert!(!ev.risk_flags.contains(&RiskFlag::RarePort));
    }
}
