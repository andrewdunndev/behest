# behest

Device Authorization Flow for services that don't implement it.

A self-hosted credential relay that lets headless systems request credentials
from human operators. Service-agnostic. Credential-agnostic. The broker never
sees plaintext.

## Architecture

```
[headless service]          [Cloudflare Worker]          [laptop agent]
  generates keypair              broker                   system tray daemon
  POST /v1/requests  ───────>  stores request  ────────>  notification
  polls GET /{id}               KV + TTL                  human fulfills
  decrypts locally   <───────  relays ciphertext <──────  encrypts + signs
                                                          with enrolled key
```

Both sides are outbound-only. No inbound connections. No NAT traversal.

## Components

| Directory | Language | Purpose |
|-----------|----------|---------|
| `worker/` | TypeScript | Cloudflare Worker broker |
| `agent/` | Rust | Laptop daemon (system tray, notifications, signing, encryption) |
| `sdk/` | Go | Client library for requesting services |
| `spec/` | Markdown | Wire protocol specification |

## Security Model

Three layers of protection:

| Layer | Purpose | Mechanism |
|-------|---------|-----------|
| **Bearer token** | API access control | Shared master key on all endpoints |
| **Agent identity** | Fulfillment authorization | Ed25519 signing (key in macOS Keychain) |
| **E2E encryption** | Credential confidentiality | X25519 + NaCl box (per-request ephemeral) |

A stolen bearer token lets an attacker create/poll requests but not fulfill
them (no Ed25519 private key). A compromised broker sees only ciphertext
(no plaintext credentials). Both requester and agent are outbound-only.

## Deploy

### 1. Broker (Cloudflare Worker)

```bash
cd worker && npm install

# Create KV namespace
npx wrangler kv namespace create REQUESTS
npx wrangler kv namespace create REQUESTS --preview
# Edit wrangler.toml: paste the namespace IDs

# Set the master key (used for auth + enrollment)
npx wrangler secret put AUTH_TOKEN

# Deploy
npx wrangler deploy
```

### 2. Enroll an agent (once per machine)

```bash
cd agent && cargo build --release

# One command, two args: broker URL + master key
./target/release/behest-agent enroll https://behest.you.workers.dev sk_your_master_key

# That's it. Config is written, signing key is in Keychain.
# Start the agent:
./target/release/behest-agent
```

### 3. Auto-start (macOS)

```bash
make install-service
```

### 4. Use from a Go service

```go
import "gitlab.com/dunn.dev/behest/behest/sdk"

client := behest.NewClient("https://behest.you.workers.dev")
client.AuthToken = os.Getenv("BEHEST_KEY")

req, err := client.CreateRequest(ctx, "my-app", "Need API token", "Go to Settings > API Keys")
credential, err := req.Wait(ctx, behest.DefaultPollInterval)
```

## Agent Commands

```
behest-agent                          # Run as system tray daemon (default)
behest-agent run --headless           # Run without GUI (terminal/SSH)
behest-agent enroll <url> <key>       # Enroll with a broker
behest-agent status                   # Check broker connectivity + identity
behest-agent list                     # Show pending requests
behest-agent fulfill <id>             # Fulfill a request interactively
behest-agent fulfill <id> -c "token"  # Fulfill with inline credential
behest-agent rotate-key               # Rotate signing key (re-enroll)
behest-agent --version                # Show version
```

In tray mode, pending requests appear as clickable menu items. Clicking one
opens Terminal with `behest-agent fulfill <id>` ready for input.

## License

MIT
