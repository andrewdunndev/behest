use std::path::PathBuf;

use crate::AgentConfig;

pub fn default_config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("behest")
        .join("agent.toml")
}

pub fn load(path: Option<PathBuf>, broker_override: Option<String>) -> anyhow::Result<AgentConfig> {
    let config_path = path.unwrap_or_else(default_config_path);

    let mut config = if config_path.exists() {
        let contents = std::fs::read_to_string(&config_path)?;
        toml::from_str::<AgentConfig>(&contents)?
    } else {
        // No config file; broker_url must come from CLI
        AgentConfig {
            broker_url: String::new(),
            auth_token: None,
            poll_interval_secs: 2,
            on_request_hook: None,
        }
    };

    if let Some(broker) = broker_override {
        config.broker_url = broker;
    }

    if config.broker_url.is_empty() {
        anyhow::bail!(
            "no broker URL configured. Set it in {} or pass --broker",
            config_path.display()
        );
    }

    // Strip trailing slash
    config.broker_url = config.broker_url.trim_end_matches('/').to_string();

    // Warn if broker URL is not HTTPS
    if !config.broker_url.starts_with("https://") && !config.broker_url.starts_with("http://localhost") {
        tracing::warn!("broker URL is not HTTPS — credentials in transit may be exposed");
    }

    Ok(config)
}
