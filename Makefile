.PHONY: help build run test lint clean migrate-up migrate-down docker-up docker-down demo demo-gateway demo-conductor demo-honeytool demo-leash demo-charter demo-helpdesk demo-cloudops demo-twoasks demo-splice demo-driftstop demo-foureyes demo-blastdoor demo-protect demo-aisre demo-breach demo-copilot demos

BINARY=legant
VERSION?=0.1.0
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

.DEFAULT_GOAL := help

help:
	@echo "Legant make targets:"
	@echo ""
	@echo "  Build and run"
	@echo "    build            build the legant binary into bin/"
	@echo "    run              run the issuer (needs Postgres; see docs/GETTING_STARTED.md)"
	@echo "    test             go test -race -cover ./..."
	@echo ""
	@echo "  Try it (Go only, no database or Docker)"
	@echo "    demos            run every self-contained walkthrough back to back"
	@echo "    demo-driftstop   replay the Salesloft-Drift / UNC6395 breach on a survivable token"
	@echo "    demo-conductor   one agent across a fleet of MCP servers, with a flight recorder"
	@echo "    demo-leash       one-hour account access with an offline kill-switch"
	@echo "    (full gallery: grep '^demo' Makefile, or see the README)"
	@echo ""
	@echo "  Learn to use it"
	@echo "    docs/GETTING_STARTED.md   bound your first agent end to end (no database)"
	@echo ""
	@echo "  Run 'make <target>'."

build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/legant

run:
	go run ./cmd/legant serve

# demo runs the agent-on-behalf-of walkthrough — no database or Docker required.
demo:
	go run ./examples/agent-obo

# demo-gateway runs the MCP auth-gateway walkthrough — no database or Docker.
demo-gateway:
	go run ./examples/mcp-gateway

# demo-conductor runs the flagship: one agent across a fleet of MCP servers with
# a tamper-evident flight recorder — no database or Docker.
demo-conductor:
	go run ./examples/conductor

# demo-honeytool runs the intrusion-detection walkthrough — no database or Docker.
demo-honeytool:
	go run ./examples/honeytool

# demo-leash runs the consumer kill-switch walkthrough — no database or Docker.
demo-leash:
	go run ./examples/leash

# demo-charter runs the agent-run-company walkthrough — no database or Docker.
demo-charter:
	go run ./examples/charter

# demo-helpdesk runs the enterprise (non-coding) support-agent walkthrough.
demo-helpdesk:
	go run ./examples/helpdesk

# demo-cloudops runs the DevOps/infra (non-coding) ops-agent walkthrough.
demo-cloudops:
	go run ./examples/cloudops

# demo-twoasks — the confused-deputy / attribution demo (one shared agent, two humans).
demo-twoasks:
	go run ./examples/twoasks

# demo-splice — multi-hop attenuation: Legant refuses every dimension of widening.
demo-splice:
	go run ./examples/splice

# demo-driftstop — replays the Salesloft–Drift / UNC6395 OAuth theft on a survivable token.
demo-driftstop:
	go run ./examples/driftstop

# demo-foureyes — segregation of duties: execute needs a second distinct human.
demo-foureyes:
	go run ./examples/foureyes

# demo-blastdoor — k8s MCP gateway: filtered tools/list, change freeze, mid-loop kill.
demo-blastdoor:
	go run ./examples/blastdoor

# demo-protect — bound your own HTTP endpoint end to end: define a grant, mint a
# token, and watch allow / deny-by-constraint / deny-by-revocation. Go only.
demo-protect:
	./examples/protect-your-endpoint/run.sh

# demo-aisre — ENTERPRISE, INTEGRATED: a real kind cluster + real mcp-server-kubernetes
# behind a Legant-guarded proxy. Requires docker/kind/kubectl/npx. (Self-contained
# demos above need only Go; this one stands up real infra and tears it down.)
demo-aisre:
	./examples/enterprise/ai-sre-on-kubernetes/run.sh

# demo-breach — ENTERPRISE: replays the Salesloft–Drift/UNC6395 OAuth theft against
# real HTTP services guarded by the shipped Legant RS middleware (Go only).
demo-breach:
	go run ./examples/enterprise/oauth-breach-replay

# demo-copilot — ENTERPRISE, INTEGRATED: a shared analytics copilot over a REAL
# Postgres warehouse; per-user offline authz + the audit names the human. Needs docker.
demo-copilot:
	./examples/enterprise/entitlement-copilot/run.sh

# demos runs every self-contained walkthrough back to back (no Docker/k8s needed).
demos: demo demo-gateway demo-conductor demo-honeytool demo-leash demo-charter demo-helpdesk demo-cloudops demo-twoasks demo-splice demo-driftstop demo-foureyes demo-blastdoor

test:
	go test -race -cover ./...

clean:
	rm -rf bin/
	go clean

migrate-up:
	go run ./cmd/legant migrate up

migrate-down:
	go run ./cmd/legant migrate down

docker-up:
	docker compose -f deployments/docker-compose.yml up -d

docker-down:
	docker compose -f deployments/docker-compose.yml down

lint:
	golangci-lint run ./...
