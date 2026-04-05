use std::path::PathBuf;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use clap::Parser;
use crypto_box::aead::{Aead, OsRng};
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

mod config;
mod notifier;
mod tray;

#[derive(Parser)]
#[command(name = "behest-agent", about = "behest credential relay agent")]
struct Cli {
    /// Path to config file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Broker URL (overrides config)
    #[arg(short, long)]
    broker: Option<String>,

    /// Run in headless mode (no system tray, TUI only)
    #[arg(long)]
    headless: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentConfig {
    pub broker_url: String,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    pub on_request_hook: Option<String>,
}

fn default_poll_interval() -> u64 {
    2
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PendingRequest {
    pub id: String,
    pub service: String,
    pub message: String,
    pub hint: String,
    pub public_key: String,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug)]
pub enum AgentEvent {
    NewRequests(Vec<PendingRequest>),
    FulfillRequest { id: String, credential: String },
    Quit,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "behest_agent=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config = config::load(cli.config, cli.broker)?;

    info!(broker = %config.broker_url, "starting behest agent");

    if cli.headless {
        // Headless mode: tokio owns the main thread, no GUI
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(run_headless(config))?;
    } else {
        // GUI mode: main thread runs tao event loop (macOS AppKit requirement)
        // tokio runtime runs on background threads
        tray::run(config)?;
    }

    Ok(())
}

async fn run_headless(config: AgentConfig) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let interval = Duration::from_secs(config.poll_interval_secs);
    let mut known_ids = std::collections::HashSet::<String>::new();

    loop {
        match fetch_pending(&client, &config.broker_url).await {
            Ok(requests) => {
                // Prune known_ids: remove IDs no longer in the pending list
                let active_ids: std::collections::HashSet<&str> =
                    requests.iter().map(|r| r.id.as_str()).collect();
                known_ids.retain(|id| active_ids.contains(id.as_str()));

                let new = requests
                    .into_iter()
                    .filter(|r: &PendingRequest| !known_ids.contains(&r.id))
                    .collect::<Vec<PendingRequest>>();

                for req in &new {
                    known_ids.insert(req.id.clone());
                }

                for req in new {
                    println!(
                        "\n--- Credential request: {} ---\nService: {}\nMessage: {}\nHint: {}\nExpires: {}\n",
                        req.id, req.service, req.message, req.hint, req.expires_at
                    );

                    // Try hook first
                    if let Some(credential) = try_hook(&config, &req).await {
                        fulfill_request(
                            &client,
                            &config.broker_url,
                            &req.id,
                            credential.as_bytes(),
                            &req.public_key,
                        )
                        .await?;
                        continue;
                    }

                    // Interactive fallback
                    println!("Enter credential (or 'skip' to skip):");
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    let input = input.trim();

                    if input == "skip" {
                        println!("Skipped.");
                        continue;
                    }

                    fulfill_request(
                        &client,
                        &config.broker_url,
                        &req.id,
                        input.as_bytes(),
                        &req.public_key,
                    )
                    .await?;
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to poll broker");
            }
        }

        tokio::time::sleep(interval).await;
    }
}

pub async fn fetch_pending(
    client: &reqwest::Client,
    broker_url: &str,
) -> anyhow::Result<Vec<PendingRequest>> {
    let resp = client
        .get(format!("{}/v1/requests/pending", broker_url))
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("broker returned {}", resp.status());
    }

    #[derive(Deserialize)]
    struct PendingResponse {
        requests: Vec<PendingRequest>,
    }

    let body: PendingResponse = resp.json().await?;
    Ok(body.requests)
}

pub fn encrypt_credential(
    credential: &[u8],
    requester_public_key_b64: &str,
) -> anyhow::Result<(String, String, String)> {
    let requester_pub_bytes = URL_SAFE_NO_PAD.decode(requester_public_key_b64)?;
    if requester_pub_bytes.len() != 32 {
        anyhow::bail!("invalid public key length: expected 32, got {}", requester_pub_bytes.len());
    }

    let requester_pub = PublicKey::from_slice(&requester_pub_bytes)
        .map_err(|e| anyhow::anyhow!("invalid public key: {}", e))?;

    let agent_secret = SecretKey::generate(&mut OsRng);
    let agent_public = agent_secret.public_key();

    let salsa_box = SalsaBox::new(&requester_pub, &agent_secret);

    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = crypto_box::Nonce::from_slice(&nonce_bytes);
    let ciphertext = salsa_box
        .encrypt(nonce, credential)
        .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;

    Ok((
        URL_SAFE_NO_PAD.encode(nonce.as_slice()),
        URL_SAFE_NO_PAD.encode(&ciphertext),
        URL_SAFE_NO_PAD.encode(agent_public.as_bytes()),
    ))
}

pub async fn fulfill_request(
    client: &reqwest::Client,
    broker_url: &str,
    request_id: &str,
    credential: &[u8],
    requester_public_key: &str,
) -> anyhow::Result<()> {
    let (nonce, ciphertext, agent_pub) = encrypt_credential(credential, requester_public_key)?;

    let resp = client
        .post(format!(
            "{}/v1/requests/{}/fulfill",
            broker_url, request_id
        ))
        .json(&serde_json::json!({
            "nonce": nonce,
            "ciphertext": ciphertext,
            "agent_public_key": agent_pub,
        }))
        .send()
        .await?;

    if resp.status().as_u16() != 204 {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("fulfill failed: {}", body);
    }

    info!(request_id, "request fulfilled");
    Ok(())
}

pub async fn try_hook(config: &AgentConfig, request: &PendingRequest) -> Option<String> {
    let hook = config.on_request_hook.as_ref()?;
    let request_json = serde_json::to_string(request).ok()?;

    info!(hook, request_id = %request.id, "running on_request_hook");

    // Use tokio::process::Command for non-blocking subprocess execution
    let output = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(hook)
        .env("BEHEST_REQUEST_JSON", &request_json)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await;

    match output {
        Ok(out) if out.status.success() => {
            let credential = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if credential.is_empty() {
                warn!("hook exited 0 but produced no output");
                None
            } else {
                Some(credential)
            }
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            info!(exit_code = ?out.status.code(), %stderr, "hook exited non-zero, falling back to interactive");
            None
        }
        Err(e) => {
            warn!(error = %e, "failed to run hook");
            None
        }
    }
}
