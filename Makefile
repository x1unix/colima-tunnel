GO ?= go
SUDO ?= sudo

.PHONY: run
run:
	@$(SUDO) $(GO) run ./cmd/colima-tun-agent
