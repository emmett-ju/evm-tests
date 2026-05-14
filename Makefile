PYTHON ?= python3
PROFILE ?= profiles/juchain.toml
STATE_DIR ?= .state
REPORT_DIR ?= reports/rpc
FAMILY ?=
MANIFEST ?=
REPORT ?=
SUMMARY ?=
SYNC_CHECK_ONLY ?= 0

UPSTREAM_FAMILIES := account_query arithmetic bitwise block_context call_context comparison control_flow keccak log memory precompile stack storage system tx_context

.PHONY: help rpc-all rpc-subset sync-upstream

help:
	@printf '%s\n' \
		'Targets:' \
		'  make rpc-all                         - run every upstream-mapped manifest against PROFILE (default: profiles/juchain.toml)' \
		'  make rpc-subset FAMILY=bitwise        - run one upstream family manifest against PROFILE' \
		'  make rpc-subset MANIFEST=path.json    - run an explicit manifest against PROFILE' \
		'  make sync-upstream                    - safely regenerate upstream-derived artifacts and run regression' \
		'' \
		'Variables:' \
		'  PROFILE=profiles/juchain.toml         - chain profile for rpc-all/rpc-subset' \
		'  STATE_DIR=.state                      - harness state directory' \
		'  REPORT_DIR=reports/rpc                - per-family report directory' \
		'  FAMILY=bitwise                        - family slug for rpc-subset; hyphen or underscore accepted' \
		'  MANIFEST=suites/manifests/foo.json    - explicit manifest for rpc-subset' \
		'  SUMMARY=reports/rpc/summary.json      - summary output path; defaults per target' \
		'  SYNC_CHECK_ONLY=1                     - validate sync generation without applying artifacts'

rpc-all:
	@mkdir -p $(REPORT_DIR)
	@set -e; \
	for family in $(UPSTREAM_FAMILIES); do \
		manifest="suites/manifests/upstream_$${family}_mapped.json"; \
		report="$(REPORT_DIR)/$${family}.json"; \
		echo "==> $$manifest"; \
		$(PYTHON) -m adapter.cli run --profile $(PROFILE) --manifest "$$manifest" --state-dir $(STATE_DIR) --report "$$report"; \
		$(PYTHON) scripts/assert_report_success.py "$$report"; \
	done; \
	summary="$(SUMMARY)"; \
	if [ -z "$$summary" ]; then summary="$(REPORT_DIR)/summary.json"; fi; \
	$(PYTHON) scripts/summarize_rpc_reports.py --report-dir $(REPORT_DIR) --inventory-dir suites/templates --output "$$summary"

rpc-subset:
	@mkdir -p $(REPORT_DIR)
	@if [ -n "$(MANIFEST)" ]; then \
		manifest="$(MANIFEST)"; \
		name=$$(basename "$$manifest" .json); \
	elif [ -n "$(FAMILY)" ]; then \
		family=$$(printf '%s' "$(FAMILY)" | tr '-' '_'); \
		manifest="suites/manifests/upstream_$${family}_mapped.json"; \
		name="$${family}"; \
	else \
		echo "Set FAMILY=<family> or MANIFEST=<path>" >&2; \
		exit 2; \
	fi; \
	test -f "$$manifest" || { echo "Manifest not found: $$manifest" >&2; exit 2; }; \
	report="$(REPORT)"; \
	if [ -z "$$report" ]; then report="$(REPORT_DIR)/$${name}.json"; fi; \
	echo "==> $$manifest"; \
	$(PYTHON) -m adapter.cli run --profile $(PROFILE) --manifest "$$manifest" --state-dir $(STATE_DIR) --report "$$report"; \
	$(PYTHON) scripts/assert_report_success.py "$$report"; \
	summary="$(SUMMARY)"; \
	if [ -z "$$summary" ]; then summary="$(REPORT_DIR)/$${name}-summary.json"; fi; \
	$(PYTHON) scripts/summarize_rpc_reports.py --report "$$report" --inventory-dir suites/templates --output "$$summary"

sync-upstream:
	@if [ "$(SYNC_CHECK_ONLY)" = "1" ]; then \
		$(PYTHON) scripts/sync_upstream_artifacts.py --check-only; \
	else \
		$(PYTHON) scripts/sync_upstream_artifacts.py --check-only; \
		$(PYTHON) scripts/sync_upstream_artifacts.py; \
		$(PYTHON) -m unittest discover -s tests -v; \
		git diff --check; \
	fi
