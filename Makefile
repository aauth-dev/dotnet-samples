# AAuth .NET samples — common workflows.
#
# Targets are thin wrappers around `dotnet` invocations so contributors
# can run the suite without memorising paths. Run `make help` for a list.

DOTNET    ?= dotnet
SOLUTION  := AAuth.slnx

WHOAMI_PROJECT := samples/WhoAmI/WhoAmI.csproj
PS_PROJECT     := samples/MockPersonServer/MockPersonServer.csproj
AP_PROJECT     := samples/MockAgentProvider/MockAgentProvider.csproj
TOUR_PROJECT   := samples/GuidedTour/GuidedTour.csproj
AGENT_PROJECT  := samples/AgentConsole/AgentConsole.csproj
SAMPLE_PROJECT := samples/SampleApp/SampleApp.csproj

WHOAMI_URL := http://localhost:5000
PS_URL     := http://localhost:5100
AP_URL     := http://localhost:5301
TOUR_URL   := http://localhost:5400
SAMPLE_URL := http://localhost:5240

.DEFAULT_GOAL := help

.PHONY: help build restore test test-unit test-conformance \
        whoami ps ap tour agent demo \
        clean format

help: ## List available targets
	@awk 'BEGIN { FS = ":.*##"; printf "Targets:\n" } \
	     /^[a-zA-Z0-9_-]+:.*##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 }' \
	     $(MAKEFILE_LIST)

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

whoami: ## Run the WhoAmI resource server (port 5000)
	$(DOTNET) run --project $(WHOAMI_PROJECT)

ps: ## Run the MockPersonServer (port 5100)
	$(DOTNET) run --project $(PS_PROJECT)

ps-consent: ## Run MockPersonServer with RequireConsent=true (deferred-flow demo)
	MockPersonServer__RequireConsent=true $(DOTNET) run --project $(PS_PROJECT)

ap: ## Run the MockAgentProvider (port 5301)
	$(DOTNET) run --project $(AP_PROJECT)

tour: ## Run the GuidedTour Blazor app (port 5400)
	$(DOTNET) run --project $(TOUR_PROJECT)

sampleapp: ## Run the SampleApp Blazor app (port 5240)
	$(DOTNET) run --project $(SAMPLE_PROJECT)

agent: ## Run AgentConsole against WhoAmI (override URL=… for a different target)
	$(DOTNET) run --project $(AGENT_PROJECT) -- $(or $(URL),$(WHOAMI_URL))

demo: ## Start WhoAmI + MockPersonServer + MockAgentProvider + GuidedTour in parallel
	@echo "Starting four-party demo (deferred / user-consent flow)..."
	@echo "  WhoAmI:             $(WHOAMI_URL)"
	@echo "  MockPersonServer:   $(PS_URL)  (RequireConsent=true)"
	@echo "  MockAgentProvider:  $(AP_URL)"
	@echo "  GuidedTour:         $(TOUR_URL)"
	@echo ""
	@trap 'echo; echo "Stopping..."; kill 0' INT TERM; \
	MockPersonServer__RequireConsent=true $(DOTNET) run --project $(PS_PROJECT) & \
	$(DOTNET) run --project $(WHOAMI_PROJECT) & \
	$(DOTNET) run --project $(AP_PROJECT) & \
	$(DOTNET) run --project $(TOUR_PROJECT) & \
	wait

demo-sample: ## Start WhoAmI + MockPersonServer + MockAgentProvider + SampleApp in parallel
	@echo "Starting demo with SampleApp..."
	@echo "  WhoAmI:             $(WHOAMI_URL)"
	@echo "  MockPersonServer:   $(PS_URL)"
	@echo "  MockAgentProvider:  $(AP_URL)"
	@echo "  SampleApp:          $(SAMPLE_URL)"
	@echo ""
	@trap 'echo; echo "Stopping..."; kill 0' INT TERM; \
	$(DOTNET) run --project $(PS_PROJECT) & \
	$(DOTNET) run --project $(WHOAMI_PROJECT) & \
	$(DOTNET) run --project $(AP_PROJECT) & \
	$(DOTNET) run --project $(SAMPLE_PROJECT) & \
	wait

clean: ## dotnet clean + remove bin/ obj/ trees
	$(DOTNET) clean $(SOLUTION)
	find . -type d \( -name bin -o -name obj \) -prune -exec rm -rf {} +

format: ## Apply dotnet format to the solution
	$(DOTNET) format $(SOLUTION)
