PYTHON ?= python3
PROFILE ?= profiles/mock.toml
STATE_DIR ?= .state
REPORT ?= reports/latest.json
MANIFEST ?= suites/manifests/custom_storage_smoke.json
UPSTREAM_MANIFEST ?= suites/manifests/upstream_storage_mapped.json
UPSTREAM_TEMPLATE ?= suites/templates/upstream_storage_templates.json
UPSTREAM_INVENTORY ?= suites/templates/upstream_storage_inventory.json
UPSTREAM_MEMORY_MANIFEST ?= suites/manifests/upstream_memory_mapped.json
UPSTREAM_MEMORY_TEMPLATE ?= suites/templates/upstream_memory_templates.json
UPSTREAM_MEMORY_INVENTORY ?= suites/templates/upstream_memory_inventory.json
UPSTREAM_CALL_CONTEXT_MANIFEST ?= suites/manifests/upstream_call_context_mapped.json
UPSTREAM_CALL_CONTEXT_TEMPLATE ?= suites/templates/upstream_call_context_templates.json
UPSTREAM_CALL_CONTEXT_INVENTORY ?= suites/templates/upstream_call_context_inventory.json
UPSTREAM_TX_CONTEXT_MANIFEST ?= suites/manifests/upstream_tx_context_mapped.json
UPSTREAM_TX_CONTEXT_TEMPLATE ?= suites/templates/upstream_tx_context_templates.json
UPSTREAM_TX_CONTEXT_INVENTORY ?= suites/templates/upstream_tx_context_inventory.json

.PHONY: help test test-mock test-juchain test-upstream-storage test-upstream-memory test-upstream-call-context test-upstream-tx-context bootstrap list scan-upstream-storage scan-upstream-memory scan-upstream-call-context scan-upstream-tx-context generate-storage-manifest generate-memory-manifest generate-call-context-manifest generate-tx-context-manifest

help:
	@printf '%s\n' \
		'Targets:' \
		'  make test                    - run the Python test suite' \
		'  make test-mock               - run the mock storage smoke manifest' \
		'  make test-juchain            - run the juchain storage smoke manifest' \
		'  make test-upstream-storage   - run the upstream-mapped storage manifest' \
		'  make test-upstream-memory    - run the upstream-mapped memory manifest' \
		'  make test-upstream-call-context - run the upstream-mapped call-context manifest' \
		'  make test-upstream-tx-context - run the upstream-mapped tx-context manifest' \
		'  make bootstrap               - bootstrap profile state' \
		'  make list                    - list cases in the default manifest' \
		'  make scan-upstream-storage   - rescan execution-specs storage cases into local templates' \
		'  make scan-upstream-memory    - rescan execution-specs memory cases into local templates' \
		'  make scan-upstream-call-context - rescan execution-specs call-context cases into local templates' \
		'  make scan-upstream-tx-context - rescan execution-specs tx-context cases into local templates' \
		'  make generate-storage-manifest - regenerate suites/manifests/upstream_storage_mapped.json' \
		'  make generate-memory-manifest - regenerate suites/manifests/upstream_memory_mapped.json' \
		'  make generate-call-context-manifest - regenerate suites/manifests/upstream_call_context_mapped.json' \
		'  make generate-tx-context-manifest - regenerate suites/manifests/upstream_tx_context_mapped.json'

test:
	$(PYTHON) -m unittest discover -s tests -v

test-mock:
	$(PYTHON) -m adapter.cli run --profile profiles/mock.toml --manifest $(MANIFEST) --state-dir $(STATE_DIR) --report $(REPORT)

test-juchain:
	$(PYTHON) -m adapter.cli run --profile profiles/juchain.toml --manifest suites/manifests/juchain_storage_smoke.json --state-dir $(STATE_DIR) --report $(REPORT)

test-upstream-storage:
	$(PYTHON) -m adapter.cli run --profile profiles/juchain.toml --manifest $(UPSTREAM_MANIFEST) --state-dir $(STATE_DIR) --report $(REPORT)

test-upstream-memory:
	$(PYTHON) -m adapter.cli run --profile profiles/juchain.toml --manifest $(UPSTREAM_MEMORY_MANIFEST) --state-dir $(STATE_DIR) --report $(REPORT)

test-upstream-call-context:
	$(PYTHON) -m adapter.cli run --profile profiles/juchain.toml --manifest $(UPSTREAM_CALL_CONTEXT_MANIFEST) --state-dir $(STATE_DIR) --report $(REPORT)

test-upstream-tx-context:
	$(PYTHON) -m adapter.cli run --profile profiles/juchain.toml --manifest $(UPSTREAM_TX_CONTEXT_MANIFEST) --state-dir $(STATE_DIR) --report $(REPORT)

bootstrap:
	$(PYTHON) -m adapter.cli bootstrap --profile $(PROFILE) --state-dir $(STATE_DIR)

list:
	$(PYTHON) -m adapter.cli list --manifest $(MANIFEST)

scan-upstream-storage:
	$(PYTHON) -m adapter.cli scan-upstream-storage --template-output $(UPSTREAM_TEMPLATE) --inventory-output $(UPSTREAM_INVENTORY)

scan-upstream-memory:
	$(PYTHON) -m adapter.cli scan-upstream-memory --template-output $(UPSTREAM_MEMORY_TEMPLATE) --inventory-output $(UPSTREAM_MEMORY_INVENTORY)

scan-upstream-call-context:
	$(PYTHON) -m adapter.cli scan-upstream-call-context --template-output $(UPSTREAM_CALL_CONTEXT_TEMPLATE) --inventory-output $(UPSTREAM_CALL_CONTEXT_INVENTORY)

scan-upstream-tx-context:
	$(PYTHON) -m adapter.cli scan-upstream-tx-context --template-output $(UPSTREAM_TX_CONTEXT_TEMPLATE) --inventory-output $(UPSTREAM_TX_CONTEXT_INVENTORY)

generate-storage-manifest:
	$(PYTHON) -m adapter.cli generate-storage-manifest --template $(UPSTREAM_TEMPLATE) --output $(UPSTREAM_MANIFEST)

generate-memory-manifest:
	$(PYTHON) -m adapter.cli generate-memory-manifest --template $(UPSTREAM_MEMORY_TEMPLATE) --output $(UPSTREAM_MEMORY_MANIFEST)

generate-call-context-manifest:
	$(PYTHON) -m adapter.cli generate-call-context-manifest --template $(UPSTREAM_CALL_CONTEXT_TEMPLATE) --output $(UPSTREAM_CALL_CONTEXT_MANIFEST)

generate-tx-context-manifest:
	$(PYTHON) -m adapter.cli generate-tx-context-manifest --template $(UPSTREAM_TX_CONTEXT_TEMPLATE) --output $(UPSTREAM_TX_CONTEXT_MANIFEST)
