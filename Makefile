PYTHON ?= python3
PROFILE ?= profiles/mock.toml
STATE_DIR ?= .state
REPORT ?= reports/latest.json
MANIFEST ?= suites/manifests/custom_storage_smoke.json
UPSTREAM_MANIFEST ?= suites/manifests/upstream_storage_mapped.json
UPSTREAM_TEMPLATE ?= suites/templates/upstream_storage_templates.json

.PHONY: help test test-mock test-juchain test-upstream-storage bootstrap list generate-storage-manifest

help:
	@printf '%s\n' \
		'Targets:' \
		'  make test                    - run the Python test suite' \
		'  make test-mock               - run the mock storage smoke manifest' \
		'  make test-juchain            - run the juchain storage smoke manifest' \
		'  make test-upstream-storage   - run the upstream-mapped storage manifest' \
		'  make bootstrap               - bootstrap profile state' \
		'  make list                    - list cases in the default manifest' \
		'  make generate-storage-manifest - regenerate suites/manifests/upstream_storage_mapped.json'

test:
	$(PYTHON) -m unittest discover -s tests -v

test-mock:
	$(PYTHON) -m adapter.cli run --profile profiles/mock.toml --manifest $(MANIFEST) --state-dir $(STATE_DIR) --report $(REPORT)

test-juchain:
	$(PYTHON) -m adapter.cli run --profile profiles/juchain.toml --manifest suites/manifests/juchain_storage_smoke.json --state-dir $(STATE_DIR) --report $(REPORT)

test-upstream-storage:
	$(PYTHON) -m adapter.cli run --profile profiles/juchain.toml --manifest $(UPSTREAM_MANIFEST) --state-dir $(STATE_DIR) --report $(REPORT)

bootstrap:
	$(PYTHON) -m adapter.cli bootstrap --profile $(PROFILE) --state-dir $(STATE_DIR)

list:
	$(PYTHON) -m adapter.cli list --manifest $(MANIFEST)

generate-storage-manifest:
	$(PYTHON) -m adapter.cli generate-storage-manifest --template $(UPSTREAM_TEMPLATE) --output $(UPSTREAM_MANIFEST)
