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

## Components

| Directory | Language | Purpose |
|-----------|----------|---------|
| `worker/` | TypeScript | Cloudflare Worker broker (~200 lines) |
| `agent/` | Rust | Laptop daemon (system tray, notifications, encryption) |
| `sdk/` | Go | Client library for requesting services |
| `spec/` | Markdown | Wire protocol specification |

## Quick Start

```bash
# Deploy the broker
cd worker && npx wrangler deploy

# Run the agent
cd agent && cargo run --release

# In your Go service
import "gitlab.com/dunn.dev/behest/behest/sdk"
```

## Security

- E2E encryption: X25519 + NaCl box (XSalsa20-Poly1305)
- Broker stores only ciphertext; never holds plaintext credentials
- Request IDs are UUIDv4, short TTL, single-use
- Both requester and agent are outbound-only

See [spec/protocol.md](spec/protocol.md) for the full wire protocol.

## License

MIT
