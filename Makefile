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
	-v $(WS_VOLUME):/ws -v "$(CURDIR)":/ws/demo -w /ws/demo $(DOCKER_ENV) \
	$(if $(VULNDB_MIRROR),-v "$(abspath $(VULNDB_MIRROR))":/mirror:ro -e CRA_VULNDB_MIRROR=/mirror)
# Settings passed into every container (decisions folder for the scenarios, gate date).
DOCKER_ENV = -e CRA_DECISIONS_DIR="$(DECISIONS)" $(if $(GATE_DATE),-e GATE_DATE="$(GATE_DATE)") \
	$(if $(REVIEWER),-e REVIEWER="$(REVIEWER)")
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
fetch: ## (network, once) West workspace + recorded DB snapshots [VULNDB_MIRROR=dir] [SNAPSHOTS=a,b]
	$(RUN_ONLINE) bash -c '\
		if [[ ! -d /ws/.west ]]; then west init -l /ws/demo; fi; \
		west update --narrow -o=--depth=1; \
		git -C /ws/zephyr fetch -q --depth=1 --no-tags "$$(west list -f "{url}" zephyr)" \
			"refs/tags/$(ZEPHYR_VERSION):refs/tags/$(ZEPHYR_VERSION)"; \
		$(PY) -m pipeline.vulndb fetch $(if $(SNAPSHOTS),--only $(SNAPSHOTS))'
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

# Firmware version comes from app/VERSION, or releases/<VERSION>/VERSION for a later
# release (see scripts/build-firmware.sh); `make build` requires VERSION=v<major>.<minor>
# and refuses to build if the two disagree.
version_of = v$(shell sed -n 's/^VERSION_MAJOR *= *//p' $(1)).$(shell sed -n 's/^VERSION_MINOR *= *//p' $(1))
APP_VERSION := $(call version_of,app/VERSION)
VERSION_FILE = $(if $(wildcard releases/$(VERSION)/VERSION),releases/$(VERSION)/VERSION,app/VERSION)
BOARD       ?= native_sim/native/64
BOARD_DIR   := $(subst /,_,$(BOARD))
TOOLCHAIN   := $(if $(filter native_sim%,$(BOARD)),host,zephyr)
MOSQUITTO_REF = $(MOSQUITTO_IMAGE)@$(MOSQUITTO_DIGEST)
RUN_SECONDS ?= 6
NET_NAME    ?= cra-demo-net
BROKER_NAME ?= cra-demo-mosquitto
# Where results go and which decisions/map apply. The scenarios (Phase 8) point these
# at their own copies under out/scenarios/, so they never change tracked files.
OUT_ROOT    ?= out
DECISIONS   ?= decisions
MAP         ?= identifiers/component-map.yaml
OUT_BOARD    = $(OUT_ROOT)/$(VERSION)/$(BOARD_DIR)

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
	@if [[ "$(VERSION)" != "$(call version_of,$(VERSION_FILE))" ]]; then \
		echo "ERROR: VERSION=$(VERSION) but $(VERSION_FILE) is $(call version_of,$(VERSION_FILE))" >&2; exit 1; fi
	@if [[ ! -f certs/generated/demo-ca.der ]]; then echo "ERROR: run 'make certs' first" >&2; exit 1; fi

.PHONY: build
build: check-version ## Build firmware (offline): make build VERSION=v1.0 [BOARD=w5500_evb_pico2/rp2350a/m33]
	@echo "building $(VERSION) for $(BOARD) (toolchain: $(TOOLCHAIN)), log: $(OUT_BOARD)/build.log"
	@$(DOCKER_RUN) -e ZEPHYR_TOOLCHAIN_VARIANT=$(TOOLCHAIN) --network none $(IMAGE) \
		bash scripts/build-firmware.sh $(BOARD) $(VERSION) /ws/build/$(VERSION)/$(BOARD_DIR) $(OUT_BOARD)

.PHONY: run
run: check-mosquitto-pinned ## Run the native_sim firmware against local Mosquitto over TLS (internal network only)
	@exe=out/$(or $(VERSION),$(APP_VERSION))/native_sim_native_64/zephyr.exe; \
	if [[ ! -f "$$exe" ]]; then echo "ERROR: $$exe missing, run 'make build VERSION=$(APP_VERSION)'" >&2; exit 1; fi; \
	MOSQUITTO_REF=$(MOSQUITTO_REF) IMAGE=$(IMAGE) EXE="$$exe" NET_NAME=$(NET_NAME) \
	BROKER_NAME=$(BROKER_NAME) RUN_SECONDS=$(RUN_SECONDS) HOST_UID=$(HOST_UID) \
	HOST_GID=$(HOST_GID) REPO="$(CURDIR)" bash scripts/run-native.sh

# ---------------------------------------------------------------- Phase 2

SBOM_DIR = $(OUT_BOARD)/sbom

.PHONY: sbom
sbom: check-version ## SPDX 2.3 SBOM for a build (offline): make sbom VERSION=v1.0 [BOARD=...]
	$(DOCKER_RUN) --network none $(IMAGE) bash -c '\
		b=/ws/build/$(VERSION)/$(BOARD_DIR); \
		if [[ ! -f $$b/zephyr/zephyr.meta || ! -d $$b/.cmake/api/v1/reply ]]; then \
			echo "ERROR: no SBOM-ready build for $(VERSION) $(BOARD); run: make build VERSION=$(VERSION) BOARD=$(BOARD)" >&2; exit 1; fi; \
		rm -rf $(SBOM_DIR); \
		west spdx -d $$b -s $(SBOM_DIR) --spdx-version 2.3 --analyze-includes --include-sdk \
			-n "https://spdx.org/spdxdocs/cra-evidence-demo/$(VERSION)/$(BOARD_DIR)/$$(sha256sum $(OUT_BOARD)/zephyr.elf | cut -c1-16)" \
			> $(OUT_BOARD)/sbom.log 2>&1 \
			|| { tail -n 20 $(OUT_BOARD)/sbom.log; exit 1; }; \
		$(PY) -m pipeline.sbom_report --sbom-dir $(SBOM_DIR) --build-dir $$b'

# ---------------------------------------------------------------- Phase 3

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
		$(PY) -m pipeline.provenance generate --version $(VERSION) --board $(BOARD) --out-root $(OUT_ROOT); \
		cosign attest-blob --key keys/cosign.key --statement $(OUT_BOARD)/provenance.intoto.json \
			--bundle $(OUT_BOARD)/provenance.sigstore.json $(COSIGN_SIGN) 2>&1 | grep -v -e deprecated -e "Using statement"; \
		$(PY) -m pipeline.provenance summary --version $(VERSION) --board $(BOARD) --out-root $(OUT_ROOT)'

.PHONY: verify
verify: check-version ## Verify provenance signature, digests and pins (offline)
	@$(RUN_OFFLINE) $(PY) -m pipeline.provenance verify --version $(VERSION) --board $(BOARD) --out-root $(OUT_ROOT)

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
	@$(RUN_OFFLINE) $(PY) -m pipeline.normalize --out-dir $(OUT_BOARD) --board $(BOARD) --version $(VERSION) --map $(MAP)

# ---------------------------------------------------------------- Phase 5

SNAPSHOT ?= baseline
ROWS     ?= 15

.PHONY: scan
scan: check-version ## Grype + OSV-Scanner on the normalized SBOM, offline [SNAPSHOT=baseline]
	@$(RUN_OFFLINE) $(PY) -m pipeline.scan --out-dir $(OUT_BOARD) --board $(BOARD) --version $(VERSION) --snapshot $(SNAPSHOT) \
		$(if $(OSV_EXTRA),--osv-extra $(OSV_EXTRA),)

.PHONY: queue
queue: check-version ## Review queue: findings without a decision for this firmware hash [ROWS=15]
	@$(RUN_OFFLINE) $(PY) -m pipeline.queue --out-dir $(OUT_BOARD) --board $(BOARD) --version $(VERSION) --rows $(ROWS)

# ---------------------------------------------------------------- Phase 6

.PHONY: decide
decide: check-version ## Draft decision file(s): VULN=<id>|open [COMPONENT=..] [FORCE=1] [FROM=<release>]
	@if [[ -z "$(VULN)" ]]; then echo "usage: make decide VERSION=$(VERSION) VULN=<id>|open [COMPONENT=<name>]" >&2; exit 2; fi
	@$(RUN_OFFLINE) $(PY) -m pipeline.decide --out-dir $(OUT_BOARD) --board $(BOARD) --version $(VERSION) \
		--vuln "$(VULN)" $(if $(COMPONENT),--component "$(COMPONENT)",) $(if $(FORCE),--force,) \
		$(if $(FROM),--from $(FROM),)

.PHONY: vex
vex: check-version ## OpenVEX from the decisions of this firmware (vexctl), offline [SIGN=1]
	@$(DOCKER_RUN) $(COSIGN_ENV) --network none $(IMAGE) $(PY) -m pipeline.vex \
		--out-dir $(OUT_BOARD) --board $(BOARD) --version $(VERSION) $(if $(SIGN),--sign,)

.PHONY: evidence
evidence: check-version ## Is a source file in this firmware? FILE=subsys/net/ip/icmpv6.c [SYMBOL=..] [KCONFIG=..]
	@if [[ -z "$(FILE)" ]]; then echo "usage: make evidence VERSION=$(VERSION) FILE=<path> [SYMBOL=f1,f2] [KCONFIG=CONFIG_X]" >&2; exit 2; fi
	@$(RUN_OFFLINE) \
		$(PY) -m pipeline.evidence_compiled --out-dir $(OUT_BOARD) --file "$(FILE)" \
		$(if $(SYMBOL),--symbol "$(SYMBOL)",) $(if $(KCONFIG),--kconfig "$(KCONFIG)",)

# ---------------------------------------------------------------- Phase 7

POLICY ?= policy/gate.yaml

.PHONY: gate
gate: check-version ## Release gate, PASS/FAIL per rule of policy/gate.yaml [GATE_DATE=YYYY-MM-DD]
	@$(RUN_OFFLINE) $(PY) -m pipeline.gate --out-dir $(OUT_BOARD) --board $(BOARD) --version $(VERSION) \
		--policy $(POLICY) $(if $(SOFT),--soft,) --rows $(or $(GATE_ROWS),8)

.PHONY: pipeline
pipeline: check-version ## Build -> SBOM -> provenance -> normalize -> scan -> VEX -> gate, one release
	@$(MAKE) --no-print-directory build
	@$(MAKE) --no-print-directory sbom
	@$(MAKE) --no-print-directory provenance
	@$(MAKE) --no-print-directory normalize
	@$(MAKE) --no-print-directory scan
	@$(MAKE) --no-print-directory vex SIGN=1 || echo "(no VEX: decisions incomplete, see make queue)"
	@$(MAKE) --no-print-directory gate

.PHONY: cjson-test
cjson-test: ## Scenario 2 evidence: CVE-2024-31755 test against upstream and patched cJSON (host gcc)
	@$(RUN_OFFLINE) bash scripts/cjson-patch-test.sh

.PHONY: review
review: check-version ## Review and sign decision drafts, one by one: REVIEWER="<your name>" [VULN=<id>]
	@$(RUN_OFFLINE) $(PY) -m pipeline.review --out-dir $(OUT_BOARD) --board $(BOARD) --version $(VERSION) \
		--reviewer "$(REVIEWER)" $(if $(VULN),--vuln "$(VULN)",)

# ---------------------------------------------------------------- Phase 8

A ?= v1.0
B ?= v1.1

.PHONY: diff
diff: ## What changed between two releases, which decisions it breaks: make diff A=v1.0 B=v1.1
	@$(RUN_OFFLINE) $(PY) -m pipeline.diff --out-root $(OUT_ROOT) --board $(BOARD) --a $(A) --b $(B)

.PHONY: finding decision vex-statement map-entry triage
finding: check-version ## Show one finding of the last scan: VULN=<id>
	@$(RUN_OFFLINE) $(PY) -m pipeline.scenario show-finding --out-dir $(OUT_BOARD) --vuln "$(VULN)"
decision: check-version ## Show the decision file(s) for VULN=<id> (short form)
	@f=($(wildcard $(DECISIONS)/$(VERSION)/$(BOARD_DIR)/$(VULN)--*.yaml)); \
	if [[ $${#f[@]} -eq 0 ]]; then echo "no decision for $(VULN) in $(DECISIONS)/$(VERSION)/$(BOARD_DIR)" >&2; exit 1; fi; \
	for x in "$${f[@]}"; do $(RUN_OFFLINE) $(PY) -m pipeline.scenario show-decision --file "$$x"; done
vex-statement: check-version ## Show the OpenVEX statement for VULN=<id>
	@$(RUN_OFFLINE) $(PY) -m pipeline.scenario show-vex --out-dir $(OUT_BOARD) --vuln "$(VULN)"
map-entry: ## Show one entry of the identifier map: ID=cjson
	@$(RUN_OFFLINE) $(PY) -m pipeline.scenario show-map --map $(MAP) --id "$(ID)"
triage: check-version ## Open an investigation for the first new finding [VULN=] [DAYS=14], REVIEWER="<name>"
	@$(RUN_OFFLINE) $(PY) -m pipeline.scenario triage --out-dir $(OUT_BOARD) --board $(BOARD) \
		--version $(VERSION) --days $(or $(DAYS),14) $(if $(VULN),--vuln "$(VULN)",)

# Internal: helper commands for scenarios/*/run.sh (ARGS without spaces)
.PHONY: scenario-helper
scenario-helper:
	@$(RUN_OFFLINE) $(PY) -m pipeline.scenario $(ARGS)

SCENARIO_BOARD ?= w5500_evb_pico2/rp2350a/m33

.PHONY: scenario-1 scenario-2 scenario-3 scenario-4 scenario-5
scenario-1: ## Scenario 1: vendored cJSON, invisible until identified (AUTO=1: no pauses)
	@BOARD=$(SCENARIO_BOARD) bash scenarios/1-identifiers/run.sh
scenario-2: ## Scenario 2: supplier backport, version unchanged, scanners still report it
	@BOARD=$(SCENARIO_BOARD) bash scenarios/2-supplier-patch/run.sh
scenario-3: ## Scenario 3: ICMPv6 CVE, IPv6 disabled: evidence that the code is not compiled
	@BOARD=$(SCENARIO_BOARD) bash scenarios/3-config-dependent/run.sh
scenario-4: ## Scenario 4: v1.1 enables IPv6: decisions of v1.0 no longer hold
	@BOARD=$(SCENARIO_BOARD) bash scenarios/4-config-change/run.sh
scenario-5: ## Scenario 5: new advisory after release: rescan, gate, triage, updated VEX
	@BOARD=$(SCENARIO_BOARD) bash scenarios/5-new-cve/run.sh

# ---------------------------------------------------------------- Phase 9

.PHONY: prepare
prepare: ## Before the talk: build + scan v1.0 and v1.1, VEX + gate v1.0, readiness check (slow)
	@$(MAKE) --no-print-directory pipeline VERSION=v1.0 BOARD=$(SCENARIO_BOARD)
	@for t in build sbom provenance normalize scan; do \
		$(MAKE) --no-print-directory $$t VERSION=v1.1 BOARD=$(SCENARIO_BOARD) || exit 1; done
	@$(MAKE) --no-print-directory diff A=v1.0 B=v1.1 BOARD=$(SCENARIO_BOARD) > /dev/null
	@$(MAKE) --no-print-directory gate VERSION=v1.1 BOARD=$(SCENARIO_BOARD) SOFT=1 > /dev/null
	@$(MAKE) --no-print-directory cjson-test
	@$(MAKE) --no-print-directory ready

.PHONY: ready
ready: ## Readiness check for the scenarios (fast) [REVIEWER=...]
	@$(RUN_OFFLINE) $(PY) -m pipeline.scenario check --board $(SCENARIO_BOARD)

.PHONY: reset
reset: ## Delete all scenario workspaces (out/scenarios); release outputs stay
	@rm -rf out/scenarios
	@echo "scenario workspaces deleted; release outputs in out/v1.0, out/v1.1 kept"

.PHONY: demo
demo: ## Presenter menu: pick a scenario
	@BOARD=$(SCENARIO_BOARD) bash scenarios/menu.sh

REC_DIR ?= recordings

.PHONY: record-1 record-2 record-3 record-4 record-5
record-%: ## Record scenario N as fallback (util-linux script): make record-3
	@mkdir -p $(REC_DIR)
	@script -q --log-timing $(REC_DIR)/scenario-$*.timing --log-out $(REC_DIR)/scenario-$*.log \
		-c "AUTO=1 PAUSE_SECONDS=$${PAUSE_SECONDS:-3} $(MAKE) --no-print-directory scenario-$*"
	@echo "recorded -> $(REC_DIR)/scenario-$*.log (+ .timing); play: make play-$*"

.PHONY: play-1 play-2 play-3 play-4 play-5
play-%: ## Replay a recorded scenario (no Docker, no network): make play-3 [SPEED=2]
	@if [[ ! -f $(REC_DIR)/scenario-$*.timing ]]; then echo "no recording: make record-$*" >&2; exit 1; fi
	@scriptreplay --log-timing $(REC_DIR)/scenario-$*.timing --log-out $(REC_DIR)/scenario-$*.log \
		--divisor $${SPEED:-1}

# ---------------------------------------------------------------- Phase 10

.PHONY: samples
samples: ## Copy the v1.0/v1.1 evidence outputs into samples/ (commit them; run after make prepare)
	@bash scripts/make-samples.sh $(SCENARIO_BOARD)
