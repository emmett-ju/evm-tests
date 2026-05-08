from __future__ import annotations

import json
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol

from adapter.models import ChainProfile, ExecutionResult, TestCase
from adapter.profile import describe_admin_key_source
from adapter.signer import load_private_key, private_key_to_address, sign_type_2_transaction

ZERO_STORAGE_WORD = "0x0000000000000000000000000000000000000000000000000000000000000000"
WORD_01 = "0x0000000000000000000000000000000000000000000000000000000000000001"
WORD_05 = "0x0000000000000000000000000000000000000000000000000000000000000005"
WORD_20 = "0x0000000000000000000000000000000000000000000000000000000000000020"
WORD_2A = "0x000000000000000000000000000000000000000000000000000000000000002a"
WORD_2A_BYTE_AT_31 = "0x2a00000000000000000000000000000000000000000000000000000000000000"
CALLDATA_WORD_PATTERN = "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
SELFBALANCE_RUNTIME = "0x4760005500"
CODESIZE_RUNTIME = "0x3860005500"
BALANCE_RUNTIME = "0x5f353160005500"


class Backend(Protocol):
    def execute_case(
        self,
        case: TestCase,
        namespace: str,
    ) -> tuple[list[str], dict[str, Any], dict[str, Any]]:
        ...


@dataclass(slots=True)
class MockBackend:
    admin_account: str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    state: dict[str, dict[str, Any]] = field(default_factory=dict)

    def execute_case(
        self,
        case: TestCase,
        namespace: str,
    ) -> tuple[list[str], dict[str, Any], dict[str, Any]]:
        namespace_state = self.state.setdefault(namespace, {})
        contracts = namespace_state.setdefault("contracts", {})
        tx_hashes: list[str] = []
        last_receipt: dict[str, Any] | None = None
        last_contract_address: str | None = None
        admin_state = self._address_state(contracts, self.admin_account)
        admin_state.setdefault("balance", ZERO_STORAGE_WORD)
        for idx, step in enumerate(case.steps):
            action = step["action"]
            if action == "set_storage":
                target_address = case.observe.get("storage_address", case.observe.get("address", "default"))
                slot = step["slot"]
                value = step["value"]
                self._address_state(contracts, target_address).setdefault("storage", {})[slot] = value
                tx_hashes.append(f"0xmock{idx:02x}{len(namespace):04x}")
            elif action == "set_balance":
                target_address = case.observe.get("balance_address", case.observe.get("address", "default"))
                self._address_state(contracts, target_address)["balance"] = self._hex_to_word(step["value"])
                tx_hashes.append(f"0xmock{idx:02x}{len(case.case_id):04x}")
            elif action == "set_code":
                target_address = case.observe.get("code_address", case.observe.get("address", "default"))
                self._address_state(contracts, target_address)["code"] = step["value"]
                tx_hashes.append(f"0xmock{idx:02x}{len(case.family):04x}")
            elif action == "transfer_native":
                tx_hash = f"0xmock{idx:02x}{len(case.namespace_seed):04x}"
                tx_hashes.append(tx_hash)
                recipient_state = self._address_state(contracts, step["to"])
                recipient_state["balance"] = self._hex_to_word(step["value"])
                last_receipt = {"transactionHash": tx_hash, "status": "0x1"}
            elif action == "deploy_contract":
                tx_hash = f"0xmock{idx:02x}{len(case.case_id):04x}"
                tx_hashes.append(tx_hash)
                contract_address = "0xcccccccccccccccccccccccccccccccccccccccc"
                last_contract_address = contract_address
                last_receipt = {
                    "transactionHash": tx_hash,
                    "status": "0x1",
                    "contractAddress": contract_address,
                }
                contract_state = self._address_state(contracts, contract_address)
                contract_state["code"] = step["bytecode_runtime"]
                contract_state["balance"] = self._hex_to_word(step.get("value", "0x0"))
                if "initial_storage" in step:
                    contract_state["storage"] = dict(step["initial_storage"])
            elif action == "invoke_contract":
                target_address = step["to"]
                if target_address == "$last_contract":
                    target_address = last_contract_address
                if not target_address:
                    raise ValueError("invoke_contract requires a concrete target contract address")
                tx_hash = f"0xmock{idx:02x}{len(case.family):04x}"
                tx_hashes.append(tx_hash)
                receipt_status = step.get("expected_receipt_status", "0x1")
                gas_price = step.get("gas_price") or "0x" + format(1_000_000_000, "x")
                last_receipt = {
                    "transactionHash": tx_hash,
                    "status": receipt_status,
                    "effectiveGasPrice": gas_price,
                }
                contract_state = self._address_state(contracts, target_address)
                data = step.get("data", "0x")
                code = contract_state.get("code")
                if receipt_status == "0x0":
                    continue
                storage = contract_state.setdefault("storage", {})
                
                memory_probe = case.observe.get("memory_probe")
                if memory_probe is not None:
                    from adapter.memory_generator import _simulate_memory_access_case, _simulate_msize_case, _word_hex
                    if memory_probe["mode"] == "msize":
                        storage["0x00"] = _word_hex(_simulate_msize_case(memory_probe["mem_size"]))
                    else:
                        slot0, slot1 = _simulate_memory_access_case(
                            memory_probe["opcode"],
                            memory_probe["offset"],
                            memory_probe["offset_initialized"],
                            memory_probe["mem_size"],
                        )
                        storage["0x00"] = _word_hex(slot0)
                        storage["0x01"] = _word_hex(slot1)
                    continue

                arithmetic_probe = case.observe.get("arithmetic_probe")
                if arithmetic_probe is not None:
                    from adapter.assembler import _word_hex
                    storage["0x00"] = _word_hex(arithmetic_probe["expected_result"])
                    continue

                bitwise_probe = case.observe.get("bitwise_probe")
                if bitwise_probe is not None:
                    from adapter.assembler import _word_hex
                    storage["0x00"] = _word_hex(bitwise_probe["expected_result"])
                    continue

                comparison_probe = case.observe.get("comparison_probe")
                if comparison_probe is not None:
                    from adapter.assembler import _word_hex
                    storage["0x00"] = _word_hex(comparison_probe["expected_result"])
                    continue

                stack_probe = case.observe.get("stack_probe")
                if stack_probe is not None:
                    from adapter.assembler import _word_hex
                    from adapter.stack_generator import _build_stack_runtime

                    expected_runtime = _build_stack_runtime(stack_probe["opcode"])
                    if code != expected_runtime:
                        raise ValueError(f"unsupported mock contract code path: {code}")
                    storage["0x00"] = _word_hex(stack_probe["expected_result"])
                    continue
                
                if code in {"0x60003560005500", "0x60003560005560006000fd"}:
                    padded = data[2:] if data.startswith("0x") else data
                    storage["0x00"] = "0x" + padded.rjust(64, "0")
                elif code == "0x60005460005500":
                    storage["0x00"] = storage.get("0x00", ZERO_STORAGE_WORD)
                elif code == "0x60005460015500":
                    storage["0x01"] = storage.get("0x00", ZERO_STORAGE_WORD)
                elif code == "0x602b60005500":
                    storage["0x00"] = "0x000000000000000000000000000000000000000000000000000000000000002b"
                elif code == "0x602a600052600051600055595560015500":
                    storage["0x00"] = WORD_2A
                    storage["0x01"] = WORD_20
                elif code == "0x602a601f53602051600055595960015500":
                    storage["0x00"] = WORD_2A_BYTE_AT_31
                    storage["0x01"] = WORD_20
                elif code == "0x5960005500":
                    storage["0x00"] = ZERO_STORAGE_WORD
                elif code == "0x5f515960005500":
                    storage["0x00"] = WORD_20
                elif code == "0x5f525f515f5200":
                    storage["0x00"] = WORD_2A
                    storage["0x01"] = WORD_20
                elif code == "0x5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f":
                    storage["0x00"] = WORD_400
                elif code == "0x3460005500":
                    value = step.get("value", "0x0")
                    storage["0x00"] = self._hex_to_word(value)
                elif code == "0x3060005500":
                    if not target_address.startswith("0x"):
                        raise ValueError(f"invalid target address for ADDRESS mock path: {target_address!r}")
                    storage["0x00"] = "0x" + target_address[2:].lower().rjust(64, "0")
                elif code == "0x3360005500":
                    storage["0x00"] = "0x" + self.admin_account[2:].lower().rjust(64, "0")
                elif code == "0x3260005500":
                    storage["0x00"] = "0x" + self.admin_account[2:].lower().rjust(64, "0")
                elif code == "0x3660005500":
                    calldata_hex = data[2:] if data.startswith("0x") else data
                    storage["0x00"] = "0x" + hex(len(calldata_hex) // 2)[2:].rjust(64, "0")
                elif code == "0x3a60005500":
                    gas_price = last_receipt.get("effectiveGasPrice") if last_receipt is not None else None
                    if gas_price is None:
                        raise ValueError("GASPRICE mock path requires receipt effectiveGasPrice")
                    storage["0x00"] = self._hex_to_word(gas_price)
                elif code == "0x5f3560005500":
                    calldata_hex = data[2:] if data.startswith("0x") else data
                    if not calldata_hex:
                        storage["0x00"] = ZERO_STORAGE_WORD
                    else:
                        storage["0x00"] = "0x" + calldata_hex[:64].ljust(64, "0")
                elif code == SELFBALANCE_RUNTIME:
                    storage["0x00"] = contract_state.get("balance", ZERO_STORAGE_WORD)
                elif code == CODESIZE_RUNTIME:
                    storage["0x00"] = WORD_05
                elif code == BALANCE_RUNTIME:
                    query_address = self._decode_address_word(data)
                    query_state = self._address_state(contracts, query_address)
                    storage["0x00"] = query_state.get("balance", ZERO_STORAGE_WORD)
                else:
                    raise ValueError(f"unsupported mock contract code path: {code}")
            elif action == "wait_receipt":
                continue
            else:
                raise ValueError(f"unsupported mock action: {action}")
        observed = self._mock_observe(case, contracts, last_receipt, last_contract_address)
        context = {
            "$admin_account": self.admin_account,
        }
        if last_contract_address is not None:
            context["$last_contract"] = last_contract_address
        if last_receipt is not None and last_receipt.get("effectiveGasPrice") is not None:
            context["$gas_price"] = last_receipt["effectiveGasPrice"]
        if "receipt_status" in case.expected:
            observed["receipt_status"] = None if last_receipt is None else last_receipt.get("status")
        if "receipt_contract_address" in case.expected:
            observed["receipt_contract_address"] = (
                None if last_receipt is None else last_receipt.get("contractAddress")
            )
        return tx_hashes, observed, context

    def _mock_observe(
        self,
        case: TestCase,
        contracts: dict[str, dict[str, Any]],
        last_receipt: dict[str, Any] | None,
        last_contract_address: str | None,
    ) -> dict[str, Any]:
        target_address = case.observe.get("address", "default")
        balance_address = case.observe.get("balance_address", target_address)
        code_address = case.observe.get("code_address", target_address)
        storage_address = case.observe.get("storage_address", target_address)
        if code_address == "$last_contract":
            code_address = last_contract_address
        if storage_address == "$last_contract":
            storage_address = last_contract_address
        observed: dict[str, Any] = {}
        if "balance" in case.expected:
            raw_balance = self._address_state(contracts, balance_address).get("balance", ZERO_STORAGE_WORD)
            observed["balance"] = self._word_to_quantity(raw_balance)
        if "code" in case.expected:
            observed["code"] = self._address_state(contracts, code_address).get("code")
        if "storage" in case.expected:
            observed["storage"] = {}
            storage = self._address_state(contracts, storage_address).get("storage", {})
            for slot in case.expected["storage"]:
                observed["storage"][slot] = storage.get(slot, ZERO_STORAGE_WORD)
        return observed

    def _address_state(
        self,
        contracts: dict[str, dict[str, Any]],
        address: str | None,
    ) -> dict[str, Any]:
        key = address or "default"
        return contracts.setdefault(key, {})

    def _hex_to_word(self, value: str) -> str:
        if not isinstance(value, str) or not value.startswith("0x"):
            raise ValueError(f"unsupported hex word literal: {value!r}")
        normalized = value[2:].lower()
        if len(normalized) > 64:
            raise ValueError(f"hex word too large for mock balance/storage: {value}")
        return "0x" + normalized.rjust(64, "0")

    def _word_to_quantity(self, value: str) -> str:
        if not isinstance(value, str) or not value.startswith("0x"):
            raise ValueError(f"unsupported hex quantity literal: {value!r}")
        normalized = value[2:].lower().lstrip("0")
        return "0x0" if not normalized else f"0x{normalized}"

    def _decode_address_word(self, value: str) -> str:
        if not isinstance(value, str) or not value.startswith("0x"):
            raise ValueError(f"BALANCE mock path requires hex calldata word, got: {value!r}")
        normalized = value[2:].lower()
        if len(normalized) != 64:
            raise ValueError(
                f"BALANCE mock path requires 32-byte calldata word, got {len(normalized) // 2} bytes"
            )
        return "0x" + normalized[-40:]


class JsonRpcBackend:
    def __init__(self, profile: ChainProfile) -> None:
        self.profile = profile
        self.request_id = 0

    def execute_case(
        self,
        case: TestCase,
        namespace: str,
    ) -> tuple[list[str], dict[str, Any], dict[str, Any]]:
        tx_hashes: list[str] = []
        last_receipt: dict[str, Any] | None = None
        last_contract_address: str | None = None
        for step in case.steps:
            action = step["action"]
            if action == "rpc_call":
                self._rpc(step["method"], step.get("params", []))
            elif action == "eth_sendRawTransaction":
                tx_hashes.append(self._rpc("eth_sendRawTransaction", [step["raw_transaction"]]))
            elif action == "eth_sendTransaction":
                tx_hashes.append(self._send_transaction(step["transaction"]))
            elif action == "transfer_native":
                tx_hashes.append(
                    self._send_transaction(
                        {
                            "to": step["to"],
                            "value": step["value"],
                            "data": step.get("data", "0x"),
                            "gas": step.get("gas"),
                        }
                    )
                )
            elif action == "deploy_contract":
                tx_hashes.append(
                    self._send_transaction(
                        {
                            "data": step["bytecode_init"],
                            "gas": step.get("gas"),
                            "value": step.get("value", "0x0"),
                        }
                    )
                )
            elif action == "invoke_contract":
                tx_hashes.append(
                    self._send_transaction(
                        {
                            "to": self._resolve_address(step["to"], last_contract_address),
                            "data": step["data"],
                            "gas": step.get("gas"),
                            "value": step.get("value", "0x0"),
                        }
                    )
                )
            elif action == "wait_receipt":
                tx_hash = step["tx_hash"]
                if tx_hash == "$last":
                    if not tx_hashes:
                        raise ValueError("wait_receipt requested $last but no prior transaction exists")
                    tx_hash = tx_hashes[-1]
                last_receipt = self._wait_for_receipt(
                    tx_hash,
                    timeout_seconds=step.get("timeout_seconds", 60),
                )
                if last_receipt.get("contractAddress"):
                    last_contract_address = last_receipt["contractAddress"]
            else:
                raise ValueError(f"unsupported jsonrpc action: {action}")
        observed = self._observe(case, last_receipt, last_contract_address)
        context = {
            "$admin_account": self.profile.admin_account,
        }
        if last_contract_address is not None:
            context["$last_contract"] = last_contract_address
        if last_receipt is not None and last_receipt.get("effectiveGasPrice") is not None:
            context["$gas_price"] = last_receipt["effectiveGasPrice"]
        return tx_hashes, observed, context

    def _observe(
        self,
        case: TestCase,
        last_receipt: dict[str, Any] | None = None,
        last_contract_address: str | None = None,
    ) -> dict[str, Any]:
        expected_shape = case.expected
        observe_config = case.observe
        target_address = observe_config.get("address", self.profile.admin_account)
        observed: dict[str, Any] = {}
        if "balance" in expected_shape:
            balance_address = observe_config.get("balance_address", target_address)
            observed["balance"] = self._rpc("eth_getBalance", [balance_address, "latest"])
        if "code" in expected_shape:
            code_address = observe_config.get("code_address")
            if code_address == "$last_contract":
                code_address = last_contract_address
            if code_address is None:
                code_address = target_address
            observed["code"] = self._rpc("eth_getCode", [code_address, "latest"])
        if "storage" in expected_shape:
            storage_address = observe_config.get("storage_address", target_address)
            if storage_address == "$last_contract":
                storage_address = last_contract_address
            observed["storage"] = {}
            for slot in expected_shape["storage"]:
                observed["storage"][slot] = self._rpc(
                    "eth_getStorageAt",
                    [storage_address, slot, "latest"],
                )
        if "receipt_status" in expected_shape:
            observed["receipt_status"] = None if last_receipt is None else last_receipt.get("status")
        if "receipt_contract_address" in expected_shape:
            observed["receipt_contract_address"] = (
                None if last_receipt is None else last_receipt.get("contractAddress")
            )
        return observed

    def _resolve_address(self, value: str, last_contract_address: str | None) -> str:
        if value == "$last_contract":
            address = last_contract_address
            if not address:
                raise ValueError("no prior contractAddress available for $last_contract")
            return address
        return value

    def _send_transaction(self, transaction: dict[str, Any]) -> str:
        source = describe_admin_key_source(self.profile)
        if source == "rpc_unlocked":
            prepared = self._prepare_transaction(transaction)
            return self._rpc("eth_sendTransaction", [prepared])
        if source in {"env_private_key", "file_private_key"}:
            private_key = load_private_key(self.profile)
            derived_address = private_key_to_address(private_key)
            if derived_address.lower() != self.profile.admin_account.lower():
                raise ValueError(
                    "admin_account does not match the address derived from admin_key_source"
                )
            prepared = self._prepare_transaction(transaction)
            raw_transaction = sign_type_2_transaction(self.profile, private_key, prepared)
            return self._rpc("eth_sendRawTransaction", [raw_transaction])
        raise NotImplementedError(
            "unsupported admin_key_source; use rpc_unlocked, env:VAR, file:/path, "
            "or provide pre-signed raw transactions"
        )

    def _prepare_transaction(self, transaction: dict[str, Any]) -> dict[str, Any]:
        prepared = dict(transaction)
        prepared.setdefault("from", self.profile.admin_account)
        prepared.setdefault("chainId", hex(self.profile.chain_id))
        prepared.setdefault("gas", hex(self.profile.gas_policy.gas_limit))
        if self.profile.gas_policy.max_fee_per_gas is not None:
            prepared.setdefault("maxFeePerGas", hex(self.profile.gas_policy.max_fee_per_gas))
        if self.profile.gas_policy.max_priority_fee_per_gas is not None:
            prepared.setdefault(
                "maxPriorityFeePerGas",
                hex(self.profile.gas_policy.max_priority_fee_per_gas),
            )
        prepared.setdefault("value", "0x0")
        prepared.setdefault("data", "0x")
        if "nonce" not in prepared:
            prepared["nonce"] = self._rpc("eth_getTransactionCount", [prepared["from"], "pending"])
        return prepared

    def _wait_for_receipt(self, tx_hash: str, timeout_seconds: int = 60) -> dict[str, Any]:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            receipt = self._rpc("eth_getTransactionReceipt", [tx_hash])
            if receipt is not None:
                return receipt
            time.sleep(1)
        raise TimeoutError(f"timed out waiting for receipt: {tx_hash}")

    def _rpc(self, method: str, params: list[Any]) -> Any:
        self.request_id += 1
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": self.request_id, "method": method, "params": params}
        ).encode()
        request = urllib.request.Request(
            self.profile.rpc_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "evm-rpc-tests/0.1",
            },
        )
        with urllib.request.urlopen(request) as response:
            body = json.loads(response.read().decode())
        if "error" in body:
            raise RuntimeError(f"rpc error for {method}: {body['error']}")
        return body["result"]


class RpcExecutor:
    def __init__(self, backend: Backend) -> None:
        self.backend = backend

    def run_case(
        self,
        case: TestCase,
        namespace: str,
    ) -> tuple[list[str], dict[str, Any], dict[str, Any]]:
        return self.backend.execute_case(case, namespace)


def result_from_execution(
    case: TestCase,
    namespace: str,
    tx_hashes: list[str],
    context: dict[str, Any],
    observed: dict[str, Any],
    diffs: list[str],
) -> ExecutionResult:
    return ExecutionResult(
        case_id=case.case_id,
        namespace=namespace,
        success=not diffs,
        tx_hashes=tx_hashes,
        context=context,
        observed=observed,
        expected=case.expected,
        diffs=diffs,
    )
