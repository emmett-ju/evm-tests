from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

from adapter.models import ChainProfile, NamespaceRecord, TestCase


class StateBootstrapper:
    def __init__(self, profile: ChainProfile, state_dir: str | Path) -> None:
        self.profile = profile
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.registry_path = self.state_dir / "namespaces.json"

    def bootstrap_global(self) -> dict[str, object]:
        registry = self._load_registry()
        changed = False
        if "_global" not in registry:
            registry["_global"] = {
                "admin_account": self.profile.admin_account,
                "chain_id": self.profile.chain_id,
                "hardfork": self.profile.hardfork,
            }
            changed = True
        if changed:
            self._save_registry(registry)
        return registry["_global"]

    def prepare_case_namespace(self, case: TestCase) -> NamespaceRecord:
        registry = self._load_registry()
        namespace = self._namespace_for_seed(case.namespace_seed)
        record = registry.get(namespace)
        if record is None:
            record = {
                "namespace": namespace,
                "seed": case.namespace_seed,
                "created_by": self.profile.name,
                "resources": {
                    "admin_account": self.profile.admin_account,
                    "case_id": case.case_id,
                    "family": case.family,
                },
            }
            registry[namespace] = record
            self._save_registry(registry)
        return NamespaceRecord(**record)

    def _namespace_for_seed(self, seed: str) -> str:
        digest = sha256(seed.encode()).hexdigest()[:10]
        prefix = self.profile.namespace_policy.prefix
        if self.profile.namespace_policy.reuse_strategy == "always_new":
            suffix = sha256(f"{seed}:{self.profile.name}:{digest}".encode()).hexdigest()[:6]
            return f"{prefix}-{digest}-{suffix}"
        return f"{prefix}-{digest}"

    def _load_registry(self) -> dict[str, object]:
        if not self.registry_path.exists():
            return {}
        return json.loads(self.registry_path.read_text())

    def _save_registry(self, registry: dict[str, object]) -> None:
        self.registry_path.write_text(json.dumps(registry, indent=2, sort_keys=True))

