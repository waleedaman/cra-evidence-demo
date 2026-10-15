# SPDX-License-Identifier: Apache-2.0
#
# Single entry point for the CRA evidence demo. Run `make help`.
# Host requirements: GNU make, bash, Docker. On Windows run from a WSL2 shell.
#
# Network policy: only `pin-base`, `pin-mosquitto`, `env`, `snapshot` and `fetch` use the
# network. Every other target runs its containers with `--network none`, except `make run`,
# which uses an *internal* Docker network (broker <-> device, no internet access).

SHELL := bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

include pins.env

IMAGE     ?= cra-evidence-demo:local
WS_VOLUME ?= cra-evidence-demo-ws
# Optional: directory holding previously recorded DB archives (same layout as
# vulndb/archives), e.g. another clone or a USB stick. Used by `make fetch`.
VULNDB_MIRROR ?=
HOST_UID  := $(shell id -u)
HOST_GID  := $(shell id -g)
TTY_FLAG  := $(shell [ -t 0 ] && echo -it || echo -i)
PY        := /opt/cra-venv/bin/python

# The repo is bind-mounted at /ws/demo, inside the west workspace volume at /ws.
DOCKER_RUN = docker run --rm $(TTY_FLAG) \
	-u $(HOST_UID):$(HOST_GID) -e HOME=/tmp \
	-e CRA_IMAGE_ID="$$(docker image inspect -f '{{.Id}}' $(IMAGE))" \
	-v $(WS_VOLUME):/ws -v "$(CURDIR)":/ws/demo -w /ws/demo \
	$(if $(VULNDB_MIRROR),-v "$(abspath $(VULNDB_MIRROR))":/mirror:ro -e CRA_VULNDB_MIRROR=/mirror)
RUN_OFFLINE = $(DOCKER_RUN) --network none $(IMAGE)
RUN_ONLINE  = $(DOCKER_RUN) $(IMAGE)

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[1m%-18s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- Phase 0

.PHONY: pin-base
pin-base: ## (network, once) Pull the ci-base image tag and record its digest in pins.env
	bash scripts/pin-image.sh $(CI_BASE_IMAGE) $(CI_BASE_TAG) CI_BASE
	@echo "next: make env"

.PHONY: check-base-pinned
check-base-pinned:
	@if [[ -z "$(CI_BASE_DIGEST)" ]]; then \
		echo "ERROR: CI_BASE_DIGEST is empty in pins.env. Run 'make pin-base' once." >&2; exit 1; fi

.PHONY: env
env: check-base-pinned ## (network) Build the pinned tooling image
	docker build -f docker/Dockerfile \
		--build-arg BASE_IMAGE=$(CI_BASE_IMAGE)@$(CI_BASE_DIGEST) \
		--build-arg ZEPHYR_SDK_VERSION=$(ZEPHYR_SDK_VERSION) \
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
fetch: ## (network, once) West workspace + recorded DB snapshots [VULNDB_MIRROR=dir]
	$(RUN_ONLINE) bash -c '\
		if [[ ! -d /ws/.west ]]; then west init -l /ws/demo; fi; \
		west update --narrow -o=--depth=1; \
		git -C /ws/zephyr fetch -q --depth=1 --no-tags "$$(west list -f "{url}" zephyr)" \
			"refs/tags/$(ZEPHYR_VERSION):refs/tags/$(ZEPHYR_VERSION)"; \
		$(PY) -m pipeline.vulndb fetch'
	@if [[ -n "$(MOSQUITTO_DIGEST)" ]]; then docker pull -q $(MOSQUITTO_IMAGE)@$(MOSQUITTO_DIGEST); fi

.PHONY: doctor
doctor: ## Check every tool version, pin and checksum (offline)
	$(RUN_OFFLINE) $(PY) -m pipeline.doctor

.PHONY: lock-doc
lock-doc: ## Regenerate versions.lock.md from pins.env, requirements.lock, snapshots
	$(RUN_OFFLINE) $(PY) -m pipeline.lockdoc

.PHONY: lint
lint: ## Type-check and syntax-check the pipeline code (offline)
	$(RUN_OFFLINE) bash -c '$(PY) -m mypy --strict pipeline && bash -n docker/install-tools.sh'

.PHONY: clean-clone-check
clean-clone-check: ## Phase 0 acceptance: fresh clone + fresh workspace volume -> fetch -> doctor
	@if [[ -n "$$(git status --porcelain)" ]]; then echo "ERROR: commit your changes first" >&2; exit 1; fi
	rm -rf /tmp/cra-clean-clone
	git clone -q "$(CURDIR)" /tmp/cra-clean-clone
	docker volume rm cra-clean-clone-ws >/dev/null 2>&1 || true
	$(MAKE) -C /tmp/cra-clean-clone fetch doctor WS_VOLUME=cra-clean-clone-ws \
		VULNDB_MIRROR="$(CURDIR)/vulndb/archives"
	docker volume rm cra-clean-clone-ws >/dev/null
	rm -rf /tmp/cra-clean-clone

.PHONY: clean-ws
clean-ws: ## Delete the west workspace volume (next `make fetch` re-downloads)
	docker volume rm $(WS_VOLUME)

# ---------------------------------------------------------------- Phase 1

# Firmware version comes from app/VERSION; `make build` requires VERSION=v<major>.<minor>
# and refuses to build if the two disagree.
APP_VERSION := v$(shell sed -n 's/^VERSION_MAJOR *= *//p' app/VERSION).$(shell sed -n 's/^VERSION_MINOR *= *//p' app/VERSION)
BOARD       ?= native_sim/native/64
BOARD_DIR   := $(subst /,_,$(BOARD))
TOOLCHAIN   := $(if $(filter native_sim%,$(BOARD)),host,zephyr)
MOSQUITTO_REF = $(MOSQUITTO_IMAGE)@$(MOSQUITTO_DIGEST)
RUN_SECONDS ?= 6
NET_NAME    ?= cra-demo-net
BROKER_NAME ?= cra-demo-mosquitto

.PHONY: pin-mosquitto
pin-mosquitto: ## (network, once) Pull the Mosquitto image tag and record its digest in pins.env
	bash scripts/pin-image.sh $(MOSQUITTO_IMAGE) $(MOSQUITTO_TAG) MOSQUITTO

.PHONY: check-mosquitto-pinned
check-mosquitto-pinned:
	@if [[ -z "$(MOSQUITTO_DIGEST)" ]]; then \
		echo "ERROR: MOSQUITTO_DIGEST is empty in pins.env. Run 'make pin-mosquitto' once." >&2; exit 1; fi

.PHONY: certs
certs: ## Generate the demo-only CA and broker certificate (FORCE=1 regenerates)
	$(DOCKER_RUN) -e FORCE=$(if $(FORCE),1,0) --network none $(IMAGE) bash scripts/gen-demo-certs.sh

.PHONY: check-version
check-version:
	@if [[ -z "$(VERSION)" ]]; then echo "usage: make build VERSION=$(APP_VERSION) [BOARD=...]" >&2; exit 2; fi
	@if [[ "$(VERSION)" != "$(APP_VERSION)" ]]; then \
		echo "ERROR: VERSION=$(VERSION) but app/VERSION is $(APP_VERSION)" >&2; exit 1; fi
	@if [[ ! -f certs/generated/demo-ca.der ]]; then echo "ERROR: run 'make certs' first" >&2; exit 1; fi

.PHONY: build
build: check-version ## Build firmware (offline): make build VERSION=v1.0 [BOARD=w5500_evb_pico2/rp2350a/m33]
	@echo "building $(VERSION) for $(BOARD) (toolchain: $(TOOLCHAIN)), log: out/$(VERSION)/$(BOARD_DIR)/build.log"
	@$(DOCKER_RUN) -e ZEPHYR_TOOLCHAIN_VARIANT=$(TOOLCHAIN) --network none $(IMAGE) \
		bash scripts/build-firmware.sh $(BOARD) $(VERSION) /ws/build/$(VERSION)/$(BOARD_DIR) out/$(VERSION)/$(BOARD_DIR)

.PHONY: run
run: check-mosquitto-pinned ## Run the native_sim firmware against local Mosquitto over TLS (internal network only)
	@exe=out/$(or $(VERSION),$(APP_VERSION))/native_sim_native_64/zephyr.exe; \
	if [[ ! -f "$$exe" ]]; then echo "ERROR: $$exe missing, run 'make build VERSION=$(APP_VERSION)'" >&2; exit 1; fi; \
	MOSQUITTO_REF=$(MOSQUITTO_REF) IMAGE=$(IMAGE) EXE="$$exe" NET_NAME=$(NET_NAME) \
	BROKER_NAME=$(BROKER_NAME) RUN_SECONDS=$(RUN_SECONDS) HOST_UID=$(HOST_UID) \
	HOST_GID=$(HOST_GID) REPO="$(CURDIR)" bash scripts/run-native.sh

# ---------------------------------------------------------------- Phase 2

SBOM_DIR = out/$(VERSION)/$(BOARD_DIR)/sbom

.PHONY: sbom
sbom: check-version ## SPDX 2.3 SBOM for a build (offline): make sbom VERSION=v1.0 [BOARD=...]
	$(DOCKER_RUN) --network none $(IMAGE) bash -c '\
		b=/ws/build/$(VERSION)/$(BOARD_DIR); \
		if [[ ! -f $$b/zephyr/zephyr.meta || ! -d $$b/.cmake/api/v1/reply ]]; then \
			echo "ERROR: no SBOM-ready build for $(VERSION) $(BOARD); run: make build VERSION=$(VERSION) BOARD=$(BOARD)" >&2; exit 1; fi; \
		rm -rf $(SBOM_DIR); \
		west spdx -d $$b -s $(SBOM_DIR) --spdx-version 2.3 --analyze-includes --include-sdk \
			-n "https://spdx.org/spdxdocs/cra-evidence-demo/$(VERSION)/$(BOARD_DIR)/$$(sha256sum out/$(VERSION)/$(BOARD_DIR)/zephyr.elf | cut -c1-16)" \
			> out/$(VERSION)/$(BOARD_DIR)/sbom.log 2>&1 \
			|| { tail -n 20 out/$(VERSION)/$(BOARD_DIR)/sbom.log; exit 1; }; \
		$(PY) -m pipeline.sbom_report --sbom-dir $(SBOM_DIR) --build-dir $$b'

# ---------------------------------------------------------------- Phase 3

OUT_BOARD     = out/$(VERSION)/$(BOARD_DIR)
# Offline, key-based signing: no TUF signing config, no transparency log upload.
COSIGN_SIGN   = --use-signing-config=false --tlog-upload=false --yes
COSIGN_ENV    = -e COSIGN_PASSWORD="$${COSIGN_PASSWORD:-}"

.PHONY: keys
keys: ## Generate the local cosign key pair (keys/cosign.key is git-ignored)
	@if [[ -f keys/cosign.key ]]; then echo "keys/cosign.key exists; refusing to overwrite" >&2; exit 1; fi
	@mkdir -p keys
	@$(DOCKER_RUN) $(COSIGN_ENV) --network none $(IMAGE) cosign generate-key-pair --output-key-prefix keys/cosign
	@echo "commit keys/cosign.pub; keys/cosign.key stays private (git-ignored)"

.PHONY: provenance
provenance: check-version ## Signed SLSA provenance (offline): make provenance VERSION=v1.0 [BOARD=...]
	@if [[ ! -f keys/cosign.key ]]; then echo "ERROR: run 'make keys' first" >&2; exit 1; fi
	@$(DOCKER_RUN) $(COSIGN_ENV) --network none $(IMAGE) bash -c 'set -euo pipefail; \
		$(PY) -m pipeline.provenance generate --version $(VERSION) --board $(BOARD); \
		cosign attest-blob --key keys/cosign.key --statement $(OUT_BOARD)/provenance.intoto.json \
			--bundle $(OUT_BOARD)/provenance.sigstore.json $(COSIGN_SIGN) 2>&1 | grep -v -e deprecated -e "Using statement"; \
		$(PY) -m pipeline.provenance summary --version $(VERSION) --board $(BOARD)'

.PHONY: verify
verify: check-version ## Verify provenance signature, digests and pins (offline)
	@$(RUN_OFFLINE) $(PY) -m pipeline.provenance verify --version $(VERSION) --board $(BOARD)

.PHONY: reproduce-check
reproduce-check: check-version ## Two clean builds in fresh containers, different paths: compare hashes
	@echo "build A and build B of $(VERSION) for $(BOARD): fresh containers, different build paths"
	@$(DOCKER_RUN) -e ZEPHYR_TOOLCHAIN_VARIANT=$(TOOLCHAIN) -e QUIET=1 --network none $(IMAGE) \
		bash scripts/build-firmware.sh $(BOARD) $(VERSION) /ws/build/repro-a/$(VERSION)/$(BOARD_DIR) $(OUT_BOARD)/repro/a
	@$(DOCKER_RUN) -e ZEPHYR_TOOLCHAIN_VARIANT=$(TOOLCHAIN) -e QUIET=1 --network none $(IMAGE) \
		bash scripts/build-firmware.sh $(BOARD) $(VERSION) /ws/build/repro-b/another/path/$(VERSION)/$(BOARD_DIR) $(OUT_BOARD)/repro/b
	@$(RUN_OFFLINE) $(PY) -m pipeline.repro --a $(OUT_BOARD)/repro/a --b $(OUT_BOARD)/repro/b \
		--release $(OUT_BOARD) --report $(OUT_BOARD)/repro/report.json

# ---------------------------------------------------------------- Phase 4

.PHONY: validate
validate: check-version ## Check SBOM documents: SPDX, NTIA, FSCT3, CPE/PURL (offline)
	@$(RUN_OFFLINE) $(PY) -m pipeline.validate --out-dir $(OUT_BOARD) --board $(BOARD) --version $(VERSION)

.PHONY: normalize
normalize: check-version ## One component SBOM from west spdx + identifiers/component-map.yaml (offline)
	@$(RUN_OFFLINE) $(PY) -m pipeline.normalize --out-dir $(OUT_BOARD) --board $(BOARD) --version $(VERSION)

# ---------------------------------------------------------------- Phase 5

SNAPSHOT ?= baseline
ROWS     ?= 15

.PHONY: scan
scan: check-version ## Grype + OSV-Scanner on the normalized SBOM, offline [SNAPSHOT=baseline]
	@$(RUN_OFFLINE) $(PY) -m pipeline.scan --out-dir $(OUT_BOARD) --board $(BOARD) --version $(VERSION) --snapshot $(SNAPSHOT)

.PHONY: queue
queue: check-version ## Review queue: findings without a decision for this firmware hash [ROWS=15]
	@$(RUN_OFFLINE) $(PY) -m pipeline.queue --out-dir $(OUT_BOARD) --board $(BOARD) --version $(VERSION) --rows $(ROWS)
