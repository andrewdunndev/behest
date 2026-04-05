use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

pub mod broker;
mod config;
mod notifier;
mod tray;

#[derive(Parser)]
#[command(name = "behest-agent", version, about = "behest credential relay agent")]
struct Cli {
    /// Path to config file
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Broker URL (overrides config)
    #[arg(short, long, global = true)]
    broker: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the agent daemon (default if no subcommand given)
    Run {
        /// Run in headless mode (no system tray, TUI only)
        #[arg(long)]
        headless: bool,
    },
    /// List pending credential requests
    List,
    /// Fulfill a pending credential request
    Fulfill {
        /// Request ID to fulfill
        id: String,
        /// Credential value (reads from stdin if omitted)
        #[arg(short, long)]
        credential: Option<String>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentConfig {
    pub broker_url: String,
    pub auth_token: Option<String>,
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

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "behest_agent=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config = config::load(cli.config, cli.broker)?;

    match cli.command {
        Some(Command::List) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(cmd_list(config))
        }
        Some(Command::Fulfill { id, credential }) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(cmd_fulfill(config, id, credential))
        }
        Some(Command::Run { headless }) => {
            info!(broker = %config.broker_url, "starting behest agent");
            if headless {
                let rt = tokio::runtime::Runtime::new()?;
                rt.block_on(run_headless(config))
            } else {
                tray::run(config)
            }
        }
        None => {
            // Default: run as tray daemon
            info!(broker = %config.broker_url, "starting behest agent");
            tray::run(config)
        }
    }
}

// --- Subcommand: list ---

async fn cmd_list(config: AgentConfig) -> anyhow::Result<()> {
    let client = broker::BrokerClient::new(&config);
    let requests = client.fetch_pending().await?;

    if requests.is_empty() {
        println!("No pending requests.");
        return Ok(());
    }

    for req in &requests {
        println!(
            "{id}  {service:20}  {message}",
            id = req.id,
            service = req.service,
            message = req.message,
        );
        if !req.hint.is_empty() {
            println!("  hint: {}", req.hint);
        }
        println!("  expires: {}", req.expires_at);
        println!();
    }

    Ok(())
}

// --- Subcommand: fulfill ---

async fn cmd_fulfill(
    config: AgentConfig,
    id: String,
    credential: Option<String>,
) -> anyhow::Result<()> {
    let client = broker::BrokerClient::new(&config);

    // Find the request to get its public key
    let requests = client.fetch_pending().await?;
    let req = requests
        .iter()
        .find(|r| r.id == id)
        .ok_or_else(|| anyhow::anyhow!("request {} not found in pending list", id))?;

    let credential_bytes = match credential {
        Some(c) => c.into_bytes(),
        None => {
            println!("Service: {}", req.service);
            println!("Message: {}", req.message);
            if !req.hint.is_empty() {
                println!("Hint: {}", req.hint);
            }
            println!();
            eprint!("Enter credential: ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            input.trim().to_string().into_bytes()
        }
    };

    if credential_bytes.is_empty() {
        anyhow::bail!("credential cannot be empty");
    }

    client
        .fulfill(&id, &credential_bytes, &req.public_key)
        .await?;

    println!("Fulfilled request {}", id);
    Ok(())
}

// --- Daemon: headless ---

async fn run_headless(config: AgentConfig) -> anyhow::Result<()> {
    let client = broker::BrokerClient::new(&config);
    let interval = Duration::from_secs(config.poll_interval_secs);
    let mut known_ids = std::collections::HashSet::<String>::new();

    loop {
        match client.fetch_pending().await {
            Ok(requests) => {
                let active_ids: std::collections::HashSet<&str> =
                    requests.iter().map(|r| r.id.as_str()).collect();
                known_ids.retain(|id| active_ids.contains(id.as_str()));

                let new = requests
                    .into_iter()
                    .filter(|r: &PendingRequest| !known_ids.contains(&r.id))
                    .collect::<Vec<PendingRequest>>();

                for r in &new {
                    known_ids.insert(r.id.clone());
                }

                for req in new {
                    println!(
                        "\n--- Credential request: {} ---\nService: {}\nMessage: {}\nHint: {}\nExpires: {}\n",
                        req.id, req.service, req.message, req.hint, req.expires_at
                    );

                    if let Some(credential) = try_hook(&config, &req).await {
                        client
                            .fulfill(&req.id, credential.as_bytes(), &req.public_key)
                            .await?;
                        continue;
                    }

                    println!("Enter credential (or 'skip' to skip):");
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    let input = input.trim();

                    if input == "skip" {
                        println!("Skipped.");
                        continue;
                    }

                    client
                        .fulfill(&req.id, input.as_bytes(), &req.public_key)
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

pub async fn try_hook(config: &AgentConfig, request: &PendingRequest) -> Option<String> {
    let hook = config.on_request_hook.as_ref()?;
    let request_json = serde_json::to_string(request).ok()?;

    info!(hook, request_id = %request.id, "running on_request_hook");

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
