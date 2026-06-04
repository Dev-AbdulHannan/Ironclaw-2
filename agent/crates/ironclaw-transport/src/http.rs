//! HTTP client for communicating with HQ.

use ironclaw_core::config::BackendConfig;
use ironclaw_core::event::Event;
use ironclaw_core::identity::{RegisterRequest, RegisterResponse};
use ironclaw_core::policy::PolicyFetchResponse;
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
        let res = self.client
            .post(self.config.register_url())
            .json(req)
            .send()
            .await?;

        let status = res.status();
        if status == StatusCode::CREATED || status == StatusCode::OK {
            Ok(res.json().await?)
        } else {
            let err_body = res.text().await.unwrap_or_else(|_| "Could not read body".to_string());
            Err(anyhow::anyhow!("Registration failed: {} - Response: {}", status, err_body))
        }
    }

    pub async fn heartbeat(&self, agent_id: &str, req: &HeartbeatRequest) -> anyhow::Result<HeartbeatResponse> {
        let res = self.client
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
            let err_body = res.text().await.unwrap_or_else(|_| "Could not read body".to_string());
            Err(anyhow::anyhow!("Heartbeat failed: {} - Response: {}", status, err_body))
        }
    }

    pub async fn fetch_policy(&self, agent_id: &str, current_version: u64) -> anyhow::Result<PolicyFetchResponse> {
        let res = self.client
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
            let err_body = res.text().await.unwrap_or_else(|_| "Could not read body".to_string());
            Err(anyhow::anyhow!("Policy fetch failed: {} - Response: {}", status, err_body))
        }
    }

    pub async fn ship_events(&self, agent_id: &str, compressed_events: Vec<u8>) -> anyhow::Result<()> {
        let res = self.client
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
            let err_body = res.text().await.unwrap_or_else(|_| "Could not read body".to_string());
            Err(anyhow::anyhow!("Event shipping failed: {} - Response: {}", status, err_body))
        }
    }
}

#[derive(Debug, Serialize)]
pub struct HeartbeatRequest {
    pub policy_version: u64,
    pub uptime_secs: u64,
    pub buffer_depth: usize,
    pub events_shipped: u64,
}

#[derive(Debug, Deserialize)]
#[serde(from = "RawHeartbeatResponse")]
pub struct HeartbeatResponse {
    pub status: String,
    pub policy_update_available: bool,
}

#[derive(Debug, Deserialize)]
struct RawHeartbeatResponse {
    status: String,
    policy_update_available: Option<bool>,
    policy_update: Option<serde_json::Value>,
}

impl From<RawHeartbeatResponse> for HeartbeatResponse {
    fn from(raw: RawHeartbeatResponse) -> Self {
        let update_available = if let Some(avail) = raw.policy_update_available {
            avail
        } else if let Some(ref update) = raw.policy_update {
            !update.is_null()
        } else {
            false
        };
        Self {
            status: raw.status,
            policy_update_available: update_available,
        }
    }
}
