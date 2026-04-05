# Behest Wire Protocol v1

## Overview

Behest is a credential relay: a headless process (the **requester**) needs
a credential that only a human can obtain. The requester parks a request
with a **broker** (Cloudflare Worker), the broker notifies a **agent**
(laptop daemon), the human fulfills the request, and the credential
returns to the requester end-to-end encrypted.

The broker never holds plaintext credentials.

## Endpoints

Base URL: `https://<broker>/v1`

### POST /requests

Create a credential request.

**Request body:**

```json
{
  "service": "string",
  "message": "string",
  "hint": "string",
  "public_key": "string (base64url, 32 bytes raw X25519)"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `service` | yes | Identifier for the requesting service (e.g. `my-app`) |
| `message` | yes | Human-readable description of what's needed |
| `hint` | no | Instructions for the human (e.g. "Log in to X, copy the token from Settings") |
| `public_key` | yes | Requester's ephemeral X25519 public key, base64url-encoded (no padding) |

**Response: 201 Created**

```json
{
  "id": "string (UUIDv4)",
  "expires_at": "string (ISO 8601)",
  "status": "pending"
}
```

**Behavior:**
- Generates a UUIDv4 request ID.
- Stores request in KV with TTL (default: 600 seconds / 10 minutes).
- Fires all configured notifiers in parallel (non-blocking).
- Returns immediately after KV write.

### GET /requests/{id}

Poll for request status.

**Response: 200 OK (pending)**

```json
{
  "id": "string",
  "service": "string",
  "message": "string",
  "status": "pending",
  "expires_at": "string (ISO 8601)"
}
```

**Response: 200 OK (fulfilled)**

```json
{
  "id": "string",
  "service": "string",
  "message": "string",
  "status": "fulfilled",
  "expires_at": "string (ISO 8601)",
  "credential": {
    "nonce": "string (base64url, 24 bytes)",
    "ciphertext": "string (base64url)"
  }
}
```

**Response: 404 Not Found**

Request expired, was consumed, or never existed.

**Response: 410 Gone**

Request was fulfilled and already consumed (retrieved once after fulfillment).

**Behavior:**
- When status is `fulfilled` and the credential is returned, the broker
  deletes the KV entry (single-use). Subsequent GETs return 410.
- The requester decrypts the credential locally:
  `plaintext = nacl_box_open(nonce, ciphertext, agent_public_key, requester_private_key)`

### POST /requests/{id}/fulfill

Submit a credential for a pending request.

**Request body:**

```json
{
  "nonce": "string (base64url, 24 bytes)",
  "ciphertext": "string (base64url)",
  "agent_public_key": "string (base64url, 32 bytes raw X25519)"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `nonce` | yes | Random 24-byte nonce used for NaCl box encryption |
| `ciphertext` | yes | NaCl box ciphertext (XSalsa20-Poly1305) |
| `agent_public_key` | yes | Agent's ephemeral X25519 public key for this fulfillment |

**Response: 204 No Content**

**Response: 404 Not Found** — request expired or doesn't exist.

**Response: 409 Conflict** — request already fulfilled.

**Behavior:**
- Stores the encrypted credential blob in KV alongside the existing request.
- Updates status from `pending` to `fulfilled`.
- Does NOT extend the TTL; the original expiry still applies.

### GET /requests/pending

List pending requests (for agent polling).

**Response: 200 OK**

```json
{
  "requests": [
    {
      "id": "string",
      "service": "string",
      "message": "string",
      "hint": "string",
      "public_key": "string (base64url)",
      "created_at": "string (ISO 8601)",
      "expires_at": "string (ISO 8601)"
    }
  ]
}
```

**Behavior:**
- Returns all requests with status `pending`.
- Agent uses this to discover new requests when SSE is unavailable.
- The `public_key` is included so the agent can encrypt the credential.

### DELETE /requests/{id}

Cancel a pending request.

**Response: 204 No Content**

**Response: 404 Not Found**

## Encryption Protocol

### Key Exchange

1. **Requester** generates an ephemeral X25519 keypair per request.
2. Public key is sent with the request to the broker.
3. **Agent** generates an ephemeral X25519 keypair per fulfillment.
4. Agent performs NaCl box encryption:
   - Shared secret: X25519(agent_private, requester_public)
   - Generates random 24-byte nonce
   - Encrypts: `ciphertext = nacl_box(plaintext, nonce, requester_public, agent_private)`
5. Agent sends `{nonce, ciphertext, agent_public_key}` to broker.
6. **Requester** decrypts:
   - Shared secret: X25519(requester_private, agent_public)
   - Decrypts: `plaintext = nacl_box_open(ciphertext, nonce, agent_public, requester_private)`

### Wire Format

- All keys are raw 32-byte X25519 keys, base64url-encoded (no padding).
- Nonces are 24 bytes, base64url-encoded (no padding).
- Ciphertext includes the 16-byte Poly1305 MAC (appended by NaCl box).
- Base64url encoding follows RFC 4648 Section 5 (URL-safe, no padding).

### Interoperability

The encryption is standard NaCl `crypto_box`:
- Rust: `crypto_box` crate (RustCrypto)
- Go: `golang.org/x/crypto/nacl/box`
- TypeScript: `tweetnacl` (if needed; the Worker never encrypts/decrypts)
- Python: `PyNaCl`

All implementations produce identical ciphertext for the same inputs.

## Authentication

### v1 (MVP)

No authentication. Security relies on:
- Request IDs are UUIDv4 (128 bits of entropy)
- Short TTL (10 minutes default)
- Single-use (consumed on first retrieval after fulfillment)
- E2E encryption (even if intercepted, credential is encrypted)

### v2 (future)

Bearer token authentication for multi-user deployments. The broker
validates tokens on all endpoints. Token management is out of scope
for the protocol spec.

## Notification Protocol

When a request is created, the broker fires configured notifiers.
Notification payloads contain no credentials.

**Notification payload:**

```json
{
  "id": "string (request ID)",
  "service": "string",
  "message": "string",
  "broker": "string (broker base URL)",
  "created_at": "string (ISO 8601)",
  "expires_at": "string (ISO 8601)"
}
```

### Notifier types

| Type | Transport | Config |
|------|-----------|--------|
| `ntfy` | HTTP POST to ntfy topic | `{ "url": "https://ntfy.sh/mytopic" }` |
| `webhook` | HTTP POST to arbitrary URL | `{ "url": "https://...", "headers": {} }` |

Additional notifiers (Signal, Pushover, Telegram, email) are added
by implementing the notifier interface. The Worker dispatches all
configured notifiers in parallel using `Promise.allSettled`.

## Error Responses

All error responses use a consistent format:

```json
{
  "error": "string (machine-readable code)",
  "message": "string (human-readable description)"
}
```

| Code | HTTP | Meaning |
|------|------|---------|
| `not_found` | 404 | Request does not exist or has expired |
| `gone` | 410 | Request was already consumed |
| `conflict` | 409 | Request already fulfilled |
| `bad_request` | 400 | Invalid request body |
| `payload_too_large` | 413 | Credential exceeds size limit (default: 64 KiB) |

## Limits

| Parameter | Default | Configurable |
|-----------|---------|--------------|
| Request TTL | 600s (10 min) | Yes (Worker env var) |
| Max credential size | 64 KiB | Yes (Worker env var) |
| Max hint size | 4 KiB | No |
| Max message size | 1 KiB | No |
| Max service name | 128 chars | No |
| Poll interval (recommended) | 2s | Client-side |
