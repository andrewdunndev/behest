use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use crypto_box::aead::{Aead, OsRng};
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use rand::RngCore;
use serde::Deserialize;
use tracing::info;

use crate::identity::AgentIdentity;
use crate::{AgentConfig, PendingRequest};

/// Authenticated HTTP client for the behest broker.
pub struct BrokerClient {
    client: reqwest::Client,
    pub broker_url: String,
    auth_token: Option<String>,
    identity: Option<AgentIdentity>,
}

impl BrokerClient {
    pub fn new(config: &AgentConfig) -> Self {
        let identity = match AgentIdentity::load() {
            Ok(id) => Some(id),
            Err(e) => {
                tracing::warn!(error = %e, "no agent identity loaded; fulfillment signing disabled");
                None
            }
        };

        Self {
            client: reqwest::Client::new(),
            broker_url: config.broker_url.clone(),
            auth_token: config.auth_token.clone(),
            identity,
        }
    }

    /// Create a client for enrollment (no identity loaded yet).
    pub fn for_enrollment(broker_url: &str, master_key: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            broker_url: broker_url.trim_end_matches('/').to_string(),
            auth_token: Some(master_key.to_string()),
            identity: None,
        }
    }

    fn auth_header(&self) -> Option<String> {
        self.auth_token
            .as_ref()
            .map(|t| format!("Bearer {}", t))
    }

    fn authed(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.auth_header() {
            Some(auth) => req.header("Authorization", auth),
            None => req,
        }
    }

    pub async fn fetch_pending(&self) -> anyhow::Result<Vec<PendingRequest>> {
        let req = self
            .client
            .get(format!("{}/v1/requests/pending", self.broker_url));
        let resp = self.authed(req).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("broker returned {}: {}", status, body);
        }

        #[derive(Deserialize)]
        struct PendingResponse {
            requests: Vec<PendingRequest>,
        }

        let body: PendingResponse = resp.json().await?;
        Ok(body.requests)
    }

    pub async fn fulfill(
        &self,
        request_id: &str,
        credential: &[u8],
        requester_public_key: &str,
    ) -> anyhow::Result<()> {
        let (nonce, ciphertext, agent_enc_pub) =
            encrypt_credential(credential, requester_public_key)?;

        let mut body = serde_json::json!({
            "nonce": nonce,
            "ciphertext": ciphertext,
            "agent_public_key": agent_enc_pub,
        });

        // Sign the fulfillment if we have an identity
        if let Some(identity) = &self.identity {
            let signature = identity.sign_fulfillment(request_id, &nonce, &ciphertext);
            body["signature"] = serde_json::Value::String(signature);
            body["signing_key"] = serde_json::Value::String(identity.public_key_b64());
        }

        let req = self
            .client
            .post(format!(
                "{}/v1/requests/{}/fulfill",
                self.broker_url, request_id
            ))
            .json(&body);
        let resp = self.authed(req).send().await?;

        if resp.status().as_u16() != 204 {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("fulfill failed: {}", body);
        }

        info!(request_id, "request fulfilled");
        Ok(())
    }

    /// Enroll this agent with the broker.
    pub async fn enroll(
        &self,
        identity: &AgentIdentity,
        name: &str,
    ) -> anyhow::Result<()> {
        let req = self
            .client
            .post(format!("{}/v1/agents/enroll", self.broker_url))
            .json(&serde_json::json!({
                "signing_key": identity.public_key_b64(),
                "name": name,
            }));
        let resp = self.authed(req).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("enrollment failed ({}): {}", status, body);
        }

        info!(name, "agent enrolled");
        Ok(())
    }
}

pub fn encrypt_credential(
    credential: &[u8],
    requester_public_key_b64: &str,
) -> anyhow::Result<(String, String, String)> {
    let requester_pub_bytes = URL_SAFE_NO_PAD.decode(requester_public_key_b64)?;
    if requester_pub_bytes.len() != 32 {
        anyhow::bail!(
            "invalid public key length: expected 32, got {}",
            requester_pub_bytes.len()
        );
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
