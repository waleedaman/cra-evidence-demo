# SPDX-License-Identifier: Apache-2.0
#
# Single entry point for the CRA evidence demo. Run `make help`.
# Host requirements: GNU make, bash, Docker. On Windows run from a WSL2 shell.
#
# Network policy: only `pin-base`, `env`, `snapshot` and `fetch` use the network.
# Every other target runs its container with `--network none`.

SHELL := bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

include pins.env

IMAGE     ?= cra-evidence-demo:local
WS_VOLUME ?= cra-evidence-demo-ws
HOST_UID  := $(shell id -u)
HOST_GID  := $(shell id -g)
TTY_FLAG  := $(shell [ -t 0 ] && echo -it || echo -i)
PY        := /opt/cra-venv/bin/python

# The repo is bind-mounted at /ws/demo, inside the west workspace volume at /ws.
DOCKER_RUN = docker run --rm $(TTY_FLAG) \
	-u $(HOST_UID):$(HOST_GID) -e HOME=/tmp \
	-e CRA_IMAGE_ID="$$(docker image inspect -f '{{.Id}}' $(IMAGE))" \
	-v $(WS_VOLUME):/ws -v "$(CURDIR)":/ws/demo -w /ws/demo
RUN_OFFLINE = $(DOCKER_RUN) --network none $(IMAGE)
RUN_ONLINE  = $(DOCKER_RUN) $(IMAGE)

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[1m%-14s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- Phase 0

.PHONY: pin-base
pin-base: ## (network, once) Pull the ci-base image tag and record its digest in pins.env
	docker pull $(CI_BASE_IMAGE):$(CI_BASE_TAG)
	@digest="$$(docker image inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' \
		$(CI_BASE_IMAGE):$(CI_BASE_TAG) | grep '^$(CI_BASE_IMAGE)@' | head -n1 | cut -d@ -f2)"; \
	if [[ -z "$$digest" ]]; then echo "ERROR: no repo digest found" >&2; exit 1; fi; \
	sed -i "s|^CI_BASE_DIGEST=.*|CI_BASE_DIGEST=$$digest|; s|^CI_BASE_DIGEST_RECORDED=.*|CI_BASE_DIGEST_RECORDED=$$(date -u +%Y-%m-%d)|" pins.env; \
	echo "recorded $(CI_BASE_IMAGE)@$$digest in pins.env (commit it, then run: make env)"

.PHONY: check-base-pinned
check-base-pinned:
	@if [[ -z "$(CI_BASE_DIGEST)" ]]; then \
		echo "ERROR: CI_BASE_DIGEST is empty in pins.env. Run 'make pin-base' once." >&2; exit 1; fi

.PHONY: env
env: check-base-pinned ## (network) Build the pinned tooling image
	docker build -f docker/Dockerfile \
		--build-arg BASE_IMAGE=$(CI_BASE_IMAGE)@$(CI_BASE_DIGEST) \
		-t $(IMAGE) .

.PHONY: shell
shell: ## Interactive shell in the image (offline; NET=1 for network)
	$(if $(NET),$(RUN_ONLINE),$(RUN_OFFLINE)) bash

.PHONY: snapshot
snapshot: ## (network) Record a new DB snapshot: make snapshot NAME=baseline [FORCE=1]
	@if [[ -z "$(NAME)" ]]; then echo "usage: make snapshot NAME=<name>" >&2; exit 2; fi
	$(RUN_ONLINE) $(PY) -m pipeline.vulndb record $(NAME) $(if $(FORCE),--force,)
	$(RUN_OFFLINE) $(PY) -m pipeline.lockdoc

.PHONY: fetch
fetch: ## (network, once) West workspace + recorded DB snapshots, all verified
	$(RUN_ONLINE) bash -c '\
		if [[ ! -d /ws/.west ]]; then west init -l /ws/demo; fi; \
		west update --narrow -o=--depth=1; \
		$(PY) -m pipeline.vulndb fetch'

.PHONY: doctor
doctor: ## Check every tool version, pin and checksum (offline)
	$(RUN_OFFLINE) $(PY) -m pipeline.doctor

.PHONY: lock-doc
lock-doc: ## Regenerate versions.lock.md from pins.env, requirements.lock, snapshots
	$(RUN_OFFLINE) $(PY) -m pipeline.lockdoc

.PHONY: lint
lint: ## Type-check and syntax-check the pipeline code (offline)
	$(RUN_OFFLINE) bash -c '$(PY) -m mypy --strict pipeline && bash -n docker/install-tools.sh'

.PHONY: clean-ws
clean-ws: ## Delete the west workspace volume (next `make fetch` re-downloads)
	docker volume rm $(WS_VOLUME)
