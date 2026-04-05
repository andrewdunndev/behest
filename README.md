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
  decrypts locally   <───────  relays ciphertext <──────  encrypts with
                                                          requester's pubkey
```

Both sides are outbound-only. No inbound connections. No NAT traversal.
All endpoints require bearer token authentication.

## Components

| Directory | Language | Purpose |
|-----------|----------|---------|
| `worker/` | TypeScript | Cloudflare Worker broker |
| `agent/` | Rust | Laptop daemon (system tray, notifications, encryption) |
| `sdk/` | Go | Client library for requesting services |
| `spec/` | Markdown | Wire protocol specification |

## Deploy

### 1. Broker (Cloudflare Worker)

```bash
cd worker && npm install

# Create KV namespace and note the ID
npx wrangler kv namespace create REQUESTS
npx wrangler kv namespace create REQUESTS --preview

# Edit wrangler.toml: paste the namespace IDs

# Set the shared auth token
npx wrangler secret put AUTH_TOKEN

# Optionally configure notifiers in wrangler.toml [vars] NOTIFIERS

# Deploy
npx wrangler deploy
```

### 2. Agent (laptop daemon)

```bash
cd agent && cargo build --release

# Create config
mkdir -p ~/.config/behest
cp agent.example.toml ~/.config/behest/agent.toml
# Edit: set broker_url and auth_token

# Run
./target/release/behest-agent
# Or headless: ./target/release/behest-agent --headless
```

### 3. SDK (in your Go service)

```go
import "gitlab.com/dunn.dev/behest/behest/sdk"

client := behest.NewClient("https://behest.your-account.workers.dev")
client.AuthToken = "your-shared-secret"

req, err := client.CreateRequest(ctx, "my-app", "Need API token", "Go to Settings > API Keys")
credential, err := req.Wait(ctx, behest.DefaultPollInterval)
```

## Security

- E2E encryption: X25519 + NaCl box (XSalsa20-Poly1305)
- Broker stores only ciphertext; never holds plaintext credentials
- Bearer token authentication on all endpoints
- Request IDs are UUIDv4, short TTL, single-use
- Both requester and agent are outbound-only

See [spec/protocol.md](spec/protocol.md) for the full wire protocol.

## License

MIT
