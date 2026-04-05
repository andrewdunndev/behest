.PHONY: all worker agent sdk clean test \
	worker-dev worker-deploy worker-test worker-typecheck \
	agent-dev agent-test sdk-test \
	install-service uninstall-service

all: worker agent sdk

# --- Worker ---

worker: worker-typecheck

worker-dev:
	cd worker && npx wrangler dev

worker-deploy:
	cd worker && npx wrangler deploy

worker-test:
	cd worker && npm test

worker-typecheck:
	cd worker && npx tsc --noEmit

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

# --- Smoke test (requires deployed broker) ---
# BEHEST_URL=https://... BEHEST_KEY=... make smoke-test
smoke-test:
	cd sdk && go run ./cmd/behest-smoke --self-test

# Interactive smoke test (waits for you to fulfill from the agent)
smoke-test-interactive:
	cd sdk && go run ./cmd/behest-smoke

clean:
	rm -rf worker/dist worker/node_modules agent/target

# --- Setup ---

setup:
	cd worker && npm install
	cd agent && cargo fetch

# --- macOS Service ---

AGENT_BIN = $(shell pwd)/agent/target/release/behest-agent
PLIST_SRC = agent/dev.behest.agent.plist
PLIST_DST = $(HOME)/Library/LaunchAgents/dev.behest.agent.plist

install-service: agent
	@sed 's|AGENT_PATH|$(AGENT_BIN)|g' $(PLIST_SRC) > $(PLIST_DST)
	launchctl load $(PLIST_DST)
	@echo "Service installed. behest-agent will start at login."

uninstall-service:
	-launchctl unload $(PLIST_DST)
	rm -f $(PLIST_DST)
	@echo "Service removed."
