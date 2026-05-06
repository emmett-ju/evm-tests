from __future__ import annotations

import tomllib
from pathlib import Path

from adapter.env import load_dotenv
from adapter.models import ChainProfile, GasPolicy, NamespacePolicy


def load_chain_profile(path: str | Path) -> ChainProfile:
    load_dotenv()
    profile_path = Path(path)
    data = tomllib.loads(profile_path.read_text())
    backend = data.get("backend")
    if backend is None:
        backend = "mock" if data["rpc_url"].startswith("http://127.0.0.1") else "jsonrpc"
    profile = ChainProfile(
        name=data["name"],
        rpc_url=data["rpc_url"],
        chain_id=int(data["chain_id"]),
        hardfork=data["hardfork"],
        feature_flags=dict(data.get("feature_flags", {})),
        gas_policy=GasPolicy(**data["gas_policy"]),
        namespace_policy=NamespacePolicy(**data["namespace_policy"]),
        admin_account=data["admin_account"],
        admin_key_source=data.get("admin_key_source"),
        trace_support=bool(data.get("trace_support", False)),
        predeployed_allowlist=list(data.get("predeployed_allowlist", [])),
        backend=backend,
    )
    profile.validate()
    return profile


def describe_admin_key_source(profile: ChainProfile) -> str:
    if not profile.admin_key_source:
        return "rpc_unlocked"
    if profile.admin_key_source == "rpc_unlocked":
        return "rpc_unlocked"
    if profile.admin_key_source.startswith("env:"):
        return "env_private_key"
    if profile.admin_key_source.startswith("file:"):
        return "file_private_key"
    return "custom"
