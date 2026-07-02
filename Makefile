# AAuth .NET samples — common workflows.
#
# Targets are thin wrappers around `dotnet` invocations so contributors
# can run the suite without memorising paths. Run `make help` for a list.

DOTNET    ?= dotnet
SOLUTION  := AAuth.slnx

PROFILE_PROJECT  := samples/MockResourceServers/Profile/Profile.csproj
CALENDAR_PROJECT := samples/MockResourceServers/Calendar/Calendar.csproj
TRIPS_PROJECT    := samples/MockResourceServers/Trips/Trips.csproj
WALLET_PROJECT   := samples/MockResourceServers/Wallet/Wallet.csproj
INBOX_PROJECT    := samples/MockResourceServers/Inbox/Inbox.csproj
PS_PROJECT     := samples/MockPersonServer/MockPersonServer.csproj
AP_PROJECT     := samples/MockAgentProvider/MockAgentProvider.csproj
TOUR_PROJECT   := samples/GuidedTour/GuidedTour.csproj
AGENT_PROJECT  := samples/AgentConsole/AgentConsole.csproj
SAMPLE_PROJECT := samples/SampleApp/SampleApp.csproj
CONCIERGE_PROJECT   := samples/Concierge/Concierge.csproj
LIVE_PROJECT   := samples/LiveWhoAmITest/LiveWhoAmITest.csproj
MISSION_PROJECT := samples/MissionAgent/MissionAgent.csproj
AS_PROJECT     := samples/MockAccessServers/Federated/Federated.csproj

PROFILE_URL  := http://localhost:5000
CALENDAR_URL := http://localhost:5001
TRIPS_URL    := http://localhost:5002
WALLET_URL   := http://localhost:5003
INBOX_URL    := http://localhost:5004
PS_URL     := http://localhost:5100
AP_URL     := http://localhost:5301
CONCIERGE_URL   := http://localhost:5200
TOUR_URL   := http://localhost:5400
SAMPLE_URL := http://localhost:5240
AS_URL     := http://localhost:5500
KEYCLOAK_URL   := http://localhost:8080
KEYCLOAK_IMAGE := quay.io/keycloak/keycloak:26.0
KEYCLOAK_REALM := samples/MockAccessServers/Federated/keycloak

# AgentConsole persists its enrollment under $LocalApplicationData; the MockAgentProvider
# keeps its agent registry in memory, so the cache goes stale whenever the AP restarts.
AGENT_CACHE_DIR := $(or $(XDG_DATA_HOME),$(HOME)/.local/share)/aauth-agent-console
E2E_DIR := tests/e2e

# Environment that points the MockAccessServer at the live Keycloak policy engine.
KEYCLOAK_AS_ENV := AccessServer__PolicyProvider=keycloak \
	AccessServer__Keycloak__Authority=$(KEYCLOAK_URL)/realms/aauth \
	AccessServer__Keycloak__ClientId=aauth-access-server \
	AccessServer__Keycloak__ClientSecret=aauth-access-server-secret \
	AccessServer__Keycloak__ResourceServerAudience=aauth-access-server \
	AccessServer__Keycloak__ResourceName=wallet

# (Re)start the Keycloak container, wait for the realm to be ready, then build once.
define KEYCLOAK_BOOT
	docker rm -f aauth-keycloak >/dev/null 2>&1 || true
	docker run -d --name aauth-keycloak -p 8080:8080 \
	  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
	  -v "$(PWD)/$(KEYCLOAK_REALM):/opt/keycloak/data/import:ro" \
	  $(KEYCLOAK_IMAGE) start-dev --import-realm >/dev/null
	@echo "Waiting for Keycloak to become ready..."
	@until curl -sf $(KEYCLOAK_URL)/realms/aauth/.well-known/openid-configuration >/dev/null 2>&1; do sleep 2; done
	@echo "Keycloak ready."
	@echo "Building services (once) before launch..."
	$(DOTNET) build $(SOLUTION) -v q
endef

.DEFAULT_GOAL := help

.PHONY: help build restore test test-unit test-conformance format clean \
        resources ps ps-consent ap concierge tour sampleapp agent live \
        demo demo-mission agent-mission \
        keycloak access-server demo-keycloak \
        agent-federated agent-reset \
        e2e-install e2e e2e-tour e2e-sample e2e-report

help: ## List available targets
	@awk 'BEGIN { FS = ":.*##"; printf "Targets:\n" } \
	     /^[a-zA-Z0-9_-]+:.*##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 }' \
	     $(MAKEFILE_LIST)

# ----------------------------------------------------------------------------
# Build, test & housekeeping
# ----------------------------------------------------------------------------

restore: ## Restore NuGet packages
	$(DOTNET) restore $(SOLUTION)

build: ## Build the full solution
	$(DOTNET) build $(SOLUTION)

test: ## Run all tests (SDK + conformance)
	$(DOTNET) test $(SOLUTION)

test-unit: ## Run SDK unit + integration tests only
	$(DOTNET) test tests/AAuth.Tests/AAuth.Tests.csproj

test-conformance: ## Run spec conformance tests only
	$(DOTNET) test tests/AAuth.Conformance/AAuth.Conformance.csproj

format: ## Apply dotnet format to the solution
	$(DOTNET) format $(SOLUTION)

clean: ## dotnet clean + remove bin/ obj/ trees
	$(DOTNET) clean $(SOLUTION)
	find . -type d \( -name bin -o -name obj \) -prune -exec rm -rf {} +

# ----------------------------------------------------------------------------
# Individual services & apps
# ----------------------------------------------------------------------------

resources: ## Run all five Aria resource servers (Profile :5000, Calendar :5001, Trips :5002, Wallet :5003, Inbox :5004)
	@echo "Building services (once) before launch..."
	@$(DOTNET) build $(SOLUTION) -v q
	@trap 'trap - INT TERM; echo; echo "Stopping..."; kill 0' INT TERM; \
	$(DOTNET) run --no-build --project $(PROFILE_PROJECT) & \
	$(DOTNET) run --no-build --project $(CALENDAR_PROJECT) & \
	$(DOTNET) run --no-build --project $(TRIPS_PROJECT) & \
	$(DOTNET) run --no-build --project $(WALLET_PROJECT) & \
	$(DOTNET) run --no-build --project $(INBOX_PROJECT) & \
	wait

ps: ## Run the MockPersonServer (port 5100)
	$(DOTNET) run --project $(PS_PROJECT)

ps-consent: ## Run MockPersonServer with RequireConsent=true (deferred-flow demo)
	MockPersonServer__RequireConsent=true $(DOTNET) run --project $(PS_PROJECT)

ap: ## Run the MockAgentProvider (port 5301)
	$(DOTNET) run --project $(AP_PROJECT)

concierge: ## Run the Concierge service (port 5200)
	$(DOTNET) run --project $(CONCIERGE_PROJECT)

tour: ## Run the GuidedTour Blazor app (port 5400)
	$(DOTNET) run --project $(TOUR_PROJECT)

sampleapp: ## Run the SampleApp Blazor app (port 5240)
	$(DOTNET) run --project $(SAMPLE_PROJECT)

agent: ## Run AgentConsole against the Profile server (override URL=… for a different target)
	$(DOTNET) run --project $(AGENT_PROJECT) -- $(or $(URL),$(PROFILE_URL))

live: ## Run LiveWhoAmITest against whoami.aauth.dev (needs cloudflared + network)
	$(DOTNET) run --project $(LIVE_PROJECT)

# ----------------------------------------------------------------------------
# Demos — stub Access Server (all flows incl. four-party federated, no Docker)
# ----------------------------------------------------------------------------

demo: ## Start the full stack + stub Access Server + both UIs (all flows incl. four-party federated, stub AS — no Docker)
	@echo "Starting demo (all flows including call-chain + four-party federated, stub AS)..."
	@echo ""
	@echo "------------------------------------------------------------------"
	@echo " Backend services:"
	@echo "   Profile:            $(PROFILE_URL)         (identity resource server)"
	@echo "   Calendar:           $(CALENDAR_URL)         (three-party resource server)"
	@echo "   Trips:              $(TRIPS_URL)         (mission-aware resource server)"
	@echo "   Wallet:             $(WALLET_URL)         (four-party resource server)"
	@echo "   Inbox:              $(INBOX_URL)         (resource-managed two-party server)"
	@echo "   Concierge:       $(CONCIERGE_URL)         (mission concierge)"
	@echo "   MockPersonServer:   $(PS_URL)         (RequireConsent=true)"
	@echo "   MockAgentProvider:  $(AP_URL)         (agent registry)"
	@echo "   MockAccessServer:   $(AS_URL)         (stub, RequireConsent=true)"
	@echo ""
	@echo " Open in your browser:"
	@echo "   GuidedTour:         $(TOUR_URL)         (step-by-step walkthrough of every flow)"
	@echo "   SampleApp:          $(SAMPLE_URL)         (minimal app: /federated, /deferred, /callchain)"
	@echo "------------------------------------------------------------------"
	@echo ""
	@echo "Building services (once) before launch..."
	@$(DOTNET) build $(SOLUTION) -v q
	@trap 'trap - INT TERM; echo; echo "Stopping..."; kill 0' INT TERM; \
	MockPersonServer__RequireConsent=true $(DOTNET) run --no-build --project $(PS_PROJECT) & \
	$(DOTNET) run --no-build --project $(PROFILE_PROJECT) & \
	$(DOTNET) run --no-build --project $(CALENDAR_PROJECT) & \
	$(DOTNET) run --no-build --project $(TRIPS_PROJECT) & \
	$(DOTNET) run --no-build --project $(WALLET_PROJECT) & \
	$(DOTNET) run --no-build --project $(INBOX_PROJECT) & \
	$(DOTNET) run --no-build --project $(CONCIERGE_PROJECT) & \
	$(DOTNET) run --no-build --project $(AP_PROJECT) & \
	AccessServer__PolicyProvider=stub AccessServer__RequireConsent=true $(DOTNET) run --no-build --project $(AS_PROJECT) & \
	$(DOTNET) run --no-build --project $(TOUR_PROJECT) & \
	$(DOTNET) run --no-build --project $(SAMPLE_PROJECT) & \
	wait

# ----------------------------------------------------------------------------
# Federated demos & helpers — live Keycloak policy engine (Docker)
# ----------------------------------------------------------------------------

keycloak: ## Start Keycloak (port 8080) with the demo 'aauth' realm imported
	docker rm -f aauth-keycloak >/dev/null 2>&1 || true
	docker run --rm --name aauth-keycloak -p 8080:8080 \
	  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
	  -v "$(PWD)/$(KEYCLOAK_REALM):/opt/keycloak/data/import:ro" \
	  $(KEYCLOAK_IMAGE) start-dev --import-realm

access-server: ## Run the MockAccessServer with the Keycloak policy engine (port 5500)
	$(KEYCLOAK_AS_ENV) \
	$(DOTNET) run --project $(AS_PROJECT)

demo-keycloak: ## Four-party federated demo (both UIs) with the live Keycloak policy engine (Docker)
	@echo "Starting four-party federated demo (Keycloak as the policy engine)..."
	$(KEYCLOAK_BOOT)
	@echo ""
	@echo "------------------------------------------------------------------"
	@echo " Backend services:"
	@echo "   Keycloak:           $(KEYCLOAK_URL)         (admin/admin, realm 'aauth')"
	@echo "   Profile:            $(PROFILE_URL)         (identity resource server)"
	@echo "   Calendar:           $(CALENDAR_URL)         (three-party resource server)"
	@echo "   Trips:              $(TRIPS_URL)         (mission-aware resource server)"
	@echo "   Wallet:             $(WALLET_URL)         (four-party resource server, /wallet)"
	@echo "   Concierge:       $(CONCIERGE_URL)         (mission concierge)"
	@echo "   MockPersonServer:   $(PS_URL)         (RequireConsent=true)"
	@echo "   MockAgentProvider:  $(AP_URL)         (agent registry)"
	@echo "   MockAccessServer:   $(AS_URL)         (PolicyProvider=keycloak)"
	@echo ""
	@echo " Open in your browser:"
	@echo "   GuidedTour:         $(TOUR_URL)         (Federated mode → live Keycloak consent)"
	@echo "   SampleApp:          $(SAMPLE_URL)         (minimal app: /federated, /deferred, /callchain)"
	@echo ""
	@echo " Keycloak login users (use these when the browser prompts you):"
	@echo "   demo  / demo    (has the wallet.payer role -> full access)"
	@echo "   guest / guest   (no payer role -> limited access)"
	@echo ""
	@echo " Keycloak admin console:  $(KEYCLOAK_URL)  (admin / admin)"
	@echo "------------------------------------------------------------------"
	@echo " Or drive it from the CLI in another terminal with:  make agent-federated"
	@echo "------------------------------------------------------------------"
	@echo ""
	@trap 'trap - INT TERM EXIT; echo; echo "Stopping..."; docker rm -f aauth-keycloak >/dev/null 2>&1; kill 0' INT TERM EXIT; \
	$(DOTNET) run --no-build --project $(PROFILE_PROJECT) & \
	$(DOTNET) run --no-build --project $(CALENDAR_PROJECT) & \
	$(DOTNET) run --no-build --project $(TRIPS_PROJECT) & \
	$(DOTNET) run --no-build --project $(WALLET_PROJECT) & \
	$(DOTNET) run --no-build --project $(CONCIERGE_PROJECT) & \
	MockPersonServer__RequireConsent=true $(DOTNET) run --no-build --project $(PS_PROJECT) & \
	$(DOTNET) run --no-build --project $(AP_PROJECT) & \
	$(KEYCLOAK_AS_ENV) \
	$(DOTNET) run --no-build --project $(AS_PROJECT) & \
	$(DOTNET) run --no-build --project $(TOUR_PROJECT) & \
	$(DOTNET) run --no-build --project $(SAMPLE_PROJECT) & \
	wait

agent-federated: ## Drive AgentConsole through the four-party /federated flow (Keycloak login)
	@$(MAKE) --no-print-directory agent-reset
	@echo ""
	@echo "=================================================================="
	@echo " When the agent prints an interaction URL, open it in your browser"
	@echo " and sign in to Keycloak with one of these demo users:"
	@echo ""
	@echo "   demo  / demo    (has the wallet.payer role -> full access)"
	@echo "   guest / guest   (no payer role -> limited access)"
	@echo "=================================================================="
	@echo ""
	$(DOTNET) run --project $(AGENT_PROJECT) -- $(WALLET_URL)/wallet \
	  --ap $(AP_URL) --ps $(PS_URL) --signing-mode jwt --sub aauth:demo@ap.example

agent-reset: ## Clear the AgentConsole enrollment cache (stale after an AP restart)
	@rm -rf "$(AGENT_CACHE_DIR)" && echo "Cleared AgentConsole enrollment cache ($(AGENT_CACHE_DIR))."

# ----------------------------------------------------------------------------
# Mission demo — agent operating under a human-approved mission, PS as the
# policy-enforcement point (three mock servers, no Docker)
# ----------------------------------------------------------------------------

demo-mission: ## Start the mission stack (AP + PS + Trips) for the MissionAgent CLI
	@echo "Starting mission demo (agent operating under a human-approved mission)..."
	@echo ""
	@echo "------------------------------------------------------------------"
	@echo " Backend services:"
	@echo "   Trips:              $(TRIPS_URL)/trips   (mission-aware resource)"
	@echo "   MockPersonServer:   $(PS_URL)         (governs every step under the mission)"
	@echo "   MockAgentProvider:  $(AP_URL)         (agent registry)"
	@echo ""
	@echo " Drive it from another terminal with:  make agent-mission"
	@echo "   (the trips.read token gate is mission-approved by default, so it is silent;"
	@echo "    the elevated trips.book step is out of the mission and"
	@echo "    prompts on its own;"
	@echo "    add AUTO=1 to resolve prompts via the PS's scripted defaults;"
	@echo "    set MISSION_APPROVED to replace the default in-scope set, e.g."
	@echo "    MISSION_APPROVED='trips.read trips.book' to silence the elevated step too)"
	@echo "------------------------------------------------------------------"
	@echo ""
	@echo "Building services (once) before launch..."
	@$(DOTNET) build $(SOLUTION) -v q
	@trap 'trap - INT TERM; echo; echo "Stopping..."; kill 0' INT TERM; \
	$(DOTNET) run --no-build --project $(PS_PROJECT) & \
	$(DOTNET) run --no-build --project $(TRIPS_PROJECT) & \
	$(DOTNET) run --no-build --project $(AP_PROJECT) & \
	wait

agent-mission: ## Drive the MissionAgent CLI through the full mission lifecycle (AUTO=1 for scripted prompts; MISSION_APPROVED="<scope>..." to replace the default in-scope set)
	$(DOTNET) run --project $(MISSION_PROJECT) -- $(if $(AUTO),--auto,) $(foreach scope,$(MISSION_APPROVED),--mission-approved $(scope))

# ----------------------------------------------------------------------------
# End-to-end (Playwright)
# ----------------------------------------------------------------------------

e2e-install: ## Install the Playwright toolchain + Chromium (run once)
	cd $(E2E_DIR) && npm ci && npm run install-browsers

e2e: ## Run all Playwright E2E specs (boots backends + apps via webServer)
	cd $(E2E_DIR) && npm test

e2e-tour: ## Run the GuidedTour Playwright specs only
	cd $(E2E_DIR) && npm run test:tour

e2e-sample: ## Run the SampleApp Playwright specs only
	cd $(E2E_DIR) && npm run test:sample

e2e-report: ## Serve the last Playwright HTML report (Ctrl-C to stop)
	@echo "Serving report at http://localhost:9323 — open it in your browser, Ctrl-C to stop."
	cd $(E2E_DIR) && npm run report
