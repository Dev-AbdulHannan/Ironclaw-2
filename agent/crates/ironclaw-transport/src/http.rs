//! HTTP client for communicating with HQ.

use ironclaw_core::config::BackendConfig;
use ironclaw_core::identity::{RegisterRequest, RegisterResponse};
use ironclaw_core::policy::{Policy, PolicyFetchResponse};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct HttpClient {
    client: Client,
    config: BackendConfig,
}

impl HttpClient {
    pub fn new(config: BackendConfig) -> anyhow::Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()?;
        Ok(Self { client, config })
    }

    pub async fn register(&self, req: &RegisterRequest) -> anyhow::Result<RegisterResponse> {
        let res = self
            .client
            .post(self.config.register_url())
            .json(req)
            .send()
            .await?;

        let status = res.status();
        if status == StatusCode::CREATED || status == StatusCode::OK {
            Ok(res.json().await?)
        } else {
            let err_body = res
                .text()
                .await
                .unwrap_or_else(|_| "Could not read body".to_string());
            Err(anyhow::anyhow!(
                "Registration failed: {} - Response: {}",
                status,
                err_body
            ))
        }
    }

    pub async fn heartbeat(
        &self,
        agent_id: &str,
        req: &HeartbeatRequest,
    ) -> anyhow::Result<HeartbeatResponse> {
        let res = self
            .client
            .post(self.config.heartbeat_url(agent_id))
            .json(req)
            .send()
            .await?;

        let status = res.status();
        if status.is_success() {
            let body_text = res.text().await.unwrap_or_default();
            match serde_json::from_str::<HeartbeatResponse>(&body_text) {
                Ok(parsed) => Ok(parsed),
                Err(err) => Err(anyhow::anyhow!(
                    "Heartbeat decoding failed: {} - Response body was: {}",
                    err,
                    body_text
                )),
            }
        } else {
            let err_body = res
                .text()
                .await
                .unwrap_or_else(|_| "Could not read body".to_string());
            Err(anyhow::anyhow!(
                "Heartbeat failed: {} - Response: {}",
                status,
                err_body
            ))
        }
    }

    pub async fn fetch_policy(
        &self,
        agent_id: &str,
        current_version: u64,
    ) -> anyhow::Result<PolicyFetchResponse> {
        let res = self
            .client
            .get(self.config.policy_url(agent_id, current_version))
            .send()
            .await?;

        let status = res.status();
        if status.is_success() {
            let body_text = res.text().await.unwrap_or_default();
            match serde_json::from_str::<PolicyFetchResponse>(&body_text) {
                Ok(parsed) => Ok(parsed),
                Err(err) => Err(anyhow::anyhow!(
                    "Policy fetch decoding failed: {} - Response body was: {}",
                    err,
                    body_text
                )),
            }
        } else {
            let err_body = res
                .text()
                .await
                .unwrap_or_else(|_| "Could not read body".to_string());
            Err(anyhow::anyhow!(
                "Policy fetch failed: {} - Response: {}",
                status,
                err_body
            ))
        }
    }

    pub async fn ship_events(
        &self,
        agent_id: &str,
        compressed_events: Vec<u8>,
    ) -> anyhow::Result<()> {
        let res = self
            .client
            .post(self.config.events_url(agent_id))
            .header("Content-Encoding", "zstd")
            .header("Content-Type", "application/json")
            .body(compressed_events)
            .send()
            .await?;

        let status = res.status();
        if status.is_success() {
            Ok(())
        } else {
            let err_body = res
                .text()
                .await
                .unwrap_or_else(|_| "Could not read body".to_string());
            Err(anyhow::anyhow!(
                "Event shipping failed: {} - Response: {}",
                status,
                err_body
            ))
        }
    }
}

#[derive(Debug, Serialize)]
pub struct HeartbeatRequest {
    pub policy_version: u64,
    /// Current role of the agent. Sent on every heartbeat so the backend can
    /// detect drift and serve the correct policy.
    pub role: String,
    /// Group/department this agent belongs to (e.g., "hr", "engineering", "finance").
    /// Sent on every heartbeat so the backend can serve group-specific policies.
    pub group: String,
    pub uptime_secs: u64,
    pub buffer_depth: usize,
    pub events_shipped: u64,
}

#[derive(Debug, Deserialize)]
#[serde(from = "RawHeartbeatResponse")]
pub struct HeartbeatResponse {
    pub status: String,
    /// The full policy update from the backend, if available.
    /// If present, the agent should apply this directly without calling GET /policy.
    pub policy_update: Option<Policy>,
    /// New role assigned by the backend, if any. `None` means "no change".
    pub role_assignment: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawHeartbeatResponse {
    status: String,
    policy_update: Option<serde_json::Value>,
    #[serde(default)]
    role_assignment: Option<String>,
}

impl From<RawHeartbeatResponse> for HeartbeatResponse {
    fn from(raw: RawHeartbeatResponse) -> Self {
        let policy_update = raw.policy_update.and_then(|value| {
            if value.is_null() {
                None
            } else {
                serde_json::from_value(value).ok()
            }
        });
        Self {
            status: raw.status,
            policy_update,
            role_assignment: raw.role_assignment,
        }
    }
}
