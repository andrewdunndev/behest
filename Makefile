.PHONY: all worker agent sdk clean dev test

all: worker agent sdk

# --- Worker ---

worker:
	cd worker && npm run build

worker-dev:
	cd worker && npx wrangler dev

worker-deploy:
	cd worker && npx wrangler deploy

worker-test:
	cd worker && npm test

# --- Agent ---

agent:
	cd agent && cargo build --release

agent-dev:
	cd agent && cargo run

agent-test:
	cd agent && cargo test

# --- SDK ---

sdk:
	cd sdk && go build ./...

sdk-test:
	cd sdk && go test ./...

# --- Combined ---

test: worker-test agent-test sdk-test

clean:
	rm -rf worker/dist worker/node_modules agent/target
