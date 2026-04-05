#!/usr/bin/env bash
set -euo pipefail

# behest broker setup — run this once after cloning.
# Creates KV namespace, generates a master key, deploys the Worker.

cd "$(dirname "$0")"

echo "=== behest broker setup ==="
echo

# Install deps
npm install --silent

# Create KV namespace
echo "Creating KV namespace..."
KV_OUTPUT=$(npx wrangler kv namespace create REQUESTS 2>&1)
KV_ID=$(echo "$KV_OUTPUT" | grep -o 'id = "[^"]*"' | head -1 | cut -d'"' -f2)

PREVIEW_OUTPUT=$(npx wrangler kv namespace create REQUESTS --preview 2>&1)
PREVIEW_ID=$(echo "$PREVIEW_OUTPUT" | grep -o 'id = "[^"]*"' | head -1 | cut -d'"' -f2)

if [ -z "$KV_ID" ] || [ -z "$PREVIEW_ID" ]; then
    echo "Failed to create KV namespace. Output:"
    echo "$KV_OUTPUT"
    echo "$PREVIEW_OUTPUT"
    exit 1
fi

# Patch wrangler.toml
sed -i.bak "s/^id = .*/id = \"${KV_ID}\"/" wrangler.toml
sed -i.bak "s/^preview_id = .*/preview_id = \"${PREVIEW_ID}\"/" wrangler.toml
rm -f wrangler.toml.bak

echo "KV namespace created: ${KV_ID}"
echo

# Generate master key
MASTER_KEY="sk_$(openssl rand -hex 24)"
echo "Generated master key: ${MASTER_KEY}"
echo
echo "Setting AUTH_TOKEN secret on Worker..."
echo "$MASTER_KEY" | npx wrangler secret put AUTH_TOKEN

echo
echo "Deploying..."
DEPLOY_OUTPUT=$(npx wrangler deploy 2>&1)
WORKER_URL=$(echo "$DEPLOY_OUTPUT" | grep -o 'https://[^ ]*\.workers\.dev' | head -1)

echo
echo "=== Broker deployed ==="
echo "URL:  ${WORKER_URL}"
echo "Key:  ${MASTER_KEY}"
echo
echo "Save these. To enroll an agent:"
echo "  behest-agent enroll ${WORKER_URL} ${MASTER_KEY}"
echo
echo "To run the smoke test:"
echo "  BEHEST_URL=${WORKER_URL} BEHEST_KEY=${MASTER_KEY} make smoke-test"
