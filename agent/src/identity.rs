use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;

const KEYCHAIN_SERVICE: &str = "dev.behest.agent";
const KEYCHAIN_ACCOUNT: &str = "signing-key";

/// Agent identity: an Ed25519 signing keypair.
pub struct AgentIdentity {
    signing_key: SigningKey,
}

impl AgentIdentity {
    /// Generate a new identity (Ed25519 keypair).
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Load identity from macOS Keychain or a file fallback.
    pub fn load() -> anyhow::Result<Self> {
        // Try Keychain first (macOS)
        #[cfg(target_os = "macos")]
        {
            match load_from_keychain() {
                Ok(key) => return Ok(Self { signing_key: key }),
                Err(e) => {
                    tracing::debug!(error = %e, "keychain load failed, trying file");
                }
            }
        }

        // File fallback
        let path = key_file_path();
        if path.exists() {
            let bytes = std::fs::read(&path)?;
            if bytes.len() != 32 {
                anyhow::bail!("corrupt key file: expected 32 bytes, got {}", bytes.len());
            }
            let key_bytes: [u8; 32] = bytes.try_into().unwrap();
            Ok(Self {
                signing_key: SigningKey::from_bytes(&key_bytes),
            })
        } else {
            anyhow::bail!(
                "no agent identity found. Run `behest-agent enroll` first."
            )
        }
    }

    /// Save identity to macOS Keychain and file fallback.
    pub fn save(&self) -> anyhow::Result<()> {
        let key_bytes = self.signing_key.to_bytes();

        // macOS Keychain
        #[cfg(target_os = "macos")]
        {
            if let Err(e) = save_to_keychain(&key_bytes) {
                tracing::warn!(error = %e, "failed to save to Keychain, using file only");
            }
        }

        // File fallback (always, as backup)
        let path = key_file_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, &key_bytes)?;
        // Restrict permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    /// The public key as base64url (for enrollment and verification).
    pub fn public_key_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing_key.verifying_key().as_bytes())
    }

    /// Sign a message. Returns base64url-encoded signature.
    pub fn sign(&self, message: &[u8]) -> String {
        let signature = self.signing_key.sign(message);
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    }

    /// Build the signing payload for a fulfillment.
    /// Signs: request_id || nonce || ciphertext (all as raw bytes, || is concatenation)
    pub fn sign_fulfillment(&self, request_id: &str, nonce: &str, ciphertext: &str) -> String {
        let mut payload = Vec::new();
        payload.extend_from_slice(request_id.as_bytes());
        payload.extend_from_slice(nonce.as_bytes());
        payload.extend_from_slice(ciphertext.as_bytes());
        self.sign(&payload)
    }
}

fn key_file_path() -> std::path::PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("behest")
        .join("agent.key")
}

// --- macOS Keychain ---

#[cfg(target_os = "macos")]
fn save_to_keychain(key_bytes: &[u8; 32]) -> anyhow::Result<()> {
    use security_framework::passwords::set_generic_password;
    set_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, key_bytes)
        .map_err(|e| anyhow::anyhow!("keychain write failed: {}", e))
}

#[cfg(target_os = "macos")]
fn load_from_keychain() -> anyhow::Result<SigningKey> {
    use security_framework::passwords::{get_generic_password};
    let bytes = get_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
        .map_err(|e| anyhow::anyhow!("keychain read failed: {}", e))?;
    if bytes.len() != 32 {
        anyhow::bail!("keychain entry has wrong length: {}", bytes.len());
    }
    let key_bytes: [u8; 32] = bytes.try_into().unwrap();
    Ok(SigningKey::from_bytes(&key_bytes))
}
