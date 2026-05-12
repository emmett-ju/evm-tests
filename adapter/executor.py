from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlsplit

from adapter.block_context_generator import (
    BLOCK_CONTEXT_BASEFEE_RUNTIME,
    BLOCK_CONTEXT_BLOCKHASH_CURRENT_RUNTIME,
    BLOCK_CONTEXT_CHAINID_RUNTIME,
    BLOCK_CONTEXT_COINBASE_RUNTIME,
    BLOCK_CONTEXT_GASLIMIT_RUNTIME,
    BLOCK_CONTEXT_NUMBER_RUNTIME,
    BLOCK_CONTEXT_PREVRANDAO_RUNTIME,
    BLOCK_CONTEXT_TIMESTAMP_RUNTIME,
)
from adapter.control_flow_generator import (
    _build_gas_runtime,
    _build_jump_runtime,
    _build_jump_pc_relative_runtime,
    _build_jumpdest_runtime,
    _build_jumpi_fallthrough_runtime,
    _build_jumpi_taken_runtime,
    _build_pc_runtime,
)
from adapter.keccak_generator import (
    _build_basic_keccak_runtime,
    _build_diff_mem_msg_sizes_runtime,
    _build_max_permutations_runtime,
    simulate_basic_keccak_case,
    simulate_diff_mem_msg_sizes_case,
)
from adapter.log_generator import (
    _build_log_runtime,
    _payload_bytes,
    build_validated_log_probe_template,
    derive_receipt_log_expectation,
)
from adapter.models import ChainProfile, ExecutionResult, TestCase
from adapter.profile import describe_admin_key_source
from adapter.signer import keccak256, load_private_key, private_key_to_address, sign_type_2_transaction
from adapter.system_witness import (
    _create_child_code_payload,
    collect_system_witness_from_storage,
    system_witness_storage_slots,
)
from adapter.system_generator import _build_create_child_code_runtime, _build_create_collision_runtime, _build_create_empty_child_runtime, _build_selfdestruct_created_runtime

ZERO_STORAGE_WORD = "0x0000000000000000000000000000000000000000000000000000000000000000"
WORD_01 = "0x0000000000000000000000000000000000000000000000000000000000000001"
WORD_05 = "0x0000000000000000000000000000000000000000000000000000000000000005"
WORD_20 = "0x0000000000000000000000000000000000000000000000000000000000000020"
WORD_2A = "0x000000000000000000000000000000000000000000000000000000000000002a"
WORD_400 = "0x0000000000000000000000000000000000000000000000000000000000000400"
WORD_2A_BYTE_AT_31 = "0x2a00000000000000000000000000000000000000000000000000000000000000"
CALLDATA_WORD_PATTERN = "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
SELFBALANCE_RUNTIME = "0x4760005500"
CODESIZE_RUNTIME = "0x3860005500"
BALANCE_RUNTIME = "0x5f353160005500"
SYSTEM_SELF_CALL_WRAPPER_SUFFIX = bytes.fromhex("5b5f5f60015f5f305af15f553d80600155805f5f3e5f2060025500")
SYSTEM_ADMITTED_MAX_RETURNDATA_BYTES = 1024 * 1024
SYSTEM_RUNTIME_HEADER = bytes.fromhex("365f14")
SYSTEM_FILL_FF_WORD = bytes.fromhex("7f" + "ff" * 32)


class SystemExecutionError(ValueError):
    """Raised when an admitted-system runtime looks intentional but is malformed."""


@dataclass(frozen=True, slots=True)
class SystemSelfCallWitness:
    success: bool
    returndata_size: int
    returndata_word: bytes


class Backend(Protocol):
    def execute_case(
        self,
        case: TestCase,
        namespace: str,
    ) -> tuple[list[str], dict[str, Any], dict[str, Any]]:
        ...


def _validate_case_for_backend(case: TestCase, backend: str) -> None:
    case.validate(backend)


def _safe_rpc_endpoint_label(rpc_url: str) -> str:
    parts = urlsplit(rpc_url)
    if parts.scheme and parts.netloc:
        return f"{parts.scheme}://{parts.hostname or parts.netloc}"
    return "<redacted-rpc-endpoint>"


@dataclass(slots=True)
class MockBackend:
    admin_account: str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    chain_id: int = 1337
    block_context_config: dict[str, Any] = field(default_factory=dict)
    state: dict[str, dict[str, Any]] = field(default_factory=dict)

    def execute_case(
        self,
        case: TestCase,
        namespace: str,
    ) -> tuple[list[str], dict[str, Any], dict[str, Any]]:
        _validate_case_for_backend(case, "mock")
        namespace_state = self.state.setdefault(namespace, {})
        contracts = namespace_state.setdefault("contracts", {})
        tx_hashes: list[str] = []
        last_receipt: dict[str, Any] | None = None
        last_contract_address: str | None = None
        admin_state = self._address_state(contracts, self.admin_account)
        admin_state.setdefault("balance", ZERO_STORAGE_WORD)
        block_context: dict[str, str] | None = None
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
                self._address_state(contracts, target_address)["balance"] = step["value"].lower()
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
                contract_state["balance"] = step.get("value", "0x0").lower()
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
                    "logs": [],
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
                    from adapter.bitwise_generator import _build_bitwise_runtime, _build_shift_witness_runtime

                    mode = bitwise_probe.get("mode")
                    opcode = bitwise_probe["opcode"]
                    if mode == "test_shifts":
                        expected_runtime = _build_shift_witness_runtime(opcode)
                    else:
                        expected_runtime = _build_bitwise_runtime(opcode, tuple(bitwise_probe["args"]))
                    if code != expected_runtime:
                        raise ValueError(f"unsupported mock contract code path: {code}")
                    storage["0x00"] = _word_hex(bitwise_probe["expected_result"])
                    continue

                comparison_probe = case.observe.get("comparison_probe")
                if comparison_probe is not None:
                    from adapter.assembler import _word_hex
                    from adapter.comparison_generator import _build_comparison_runtime

                    expected_runtime = _build_comparison_runtime(
                        comparison_probe["opcode"],
                        tuple(comparison_probe["args"]),
                    )
                    if code != expected_runtime:
                        raise ValueError(f"unsupported mock contract code path: {code}")
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

                control_flow_probe = case.observe.get("control_flow_probe")
                if control_flow_probe is not None:
                    mode = control_flow_probe.get("mode")
                    storage["0x00"] = self._simulate_control_flow_probe(mode, code)
                    continue

                block_context_probe = case.observe.get("block_context_probe")
                if block_context_probe is not None:
                    if block_context is None:
                        block_context = self._build_mock_block_context()
                    mode = block_context_probe.get("mode")
                    storage["0x00"] = self._simulate_block_context_probe(mode, code, block_context)
                    continue

                keccak_probe = case.observe.get("keccak_probe")
                if keccak_probe is not None:
                    self._simulate_keccak_probe(storage, keccak_probe, code, data)
                    continue

                log_probe = case.observe.get("log_probe")
                if log_probe is not None:
                    self._simulate_log_probe(last_receipt, log_probe, code)
                    continue

                system_witness = case.observe.get("system_witness")
                if system_witness is not None and system_witness.get("shape") == "create_empty_child":
                    self._simulate_create_empty_child_probe(storage, system_witness, code)
                    continue
                if system_witness is not None and system_witness.get("shape") == "create_child_code":
                    self._simulate_create_child_code_probe(storage, system_witness, code)
                    continue
                if system_witness is not None and system_witness.get("shape") == "create_collision":
                    self._simulate_create_collision_probe(storage, system_witness, code)
                    continue
                if system_witness is not None and system_witness.get("shape") == "selfdestruct_single":
                    self._simulate_selfdestruct_single_probe(storage, system_witness, code)
                    continue

                if self._is_system_self_call_runtime(code):
                    self._simulate_system_self_call_probe(storage, code)
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
                    storage["0x00"] = self._address_to_word(target_address)
                elif code == "0x3360005500":
                    storage["0x00"] = self._address_to_word(self.admin_account)
                elif code == "0x3660005500":
                    calldata = data[2:] if data.startswith("0x") else data
                    storage["0x00"] = self._hex_to_word(hex(len(calldata) // 2))
                elif code == "0x5f3560005500":
                    calldata = data[2:] if data.startswith("0x") else data
                    storage["0x00"] = "0x" + calldata[:64].ljust(64, "0").lower()
                elif code == "0x3260005500":
                    storage["0x00"] = self._address_to_word(self.admin_account)
                elif code == "0x3a60005500":
                    storage["0x00"] = self._hex_to_word(gas_price)
                elif code == SELFBALANCE_RUNTIME:
                    contract_balance = contract_state.get("balance", ZERO_STORAGE_WORD)
                    storage["0x00"] = self._hex_to_word(contract_balance)
                elif code == CODESIZE_RUNTIME:
                    storage["0x00"] = WORD_05
                elif code == BALANCE_RUNTIME:
                    payload = data[2:] if data.startswith("0x") else data
                    if len(payload) > 64:
                        raise ValueError(f"unsupported balance calldata payload: {data!r}")
                    balance_address = "0x" + payload[-40:].rjust(40, "0")
                    balance_state = self._address_state(contracts, balance_address)
                    balance_value = balance_state.get("balance", "0x0")
                    storage["0x00"] = self._hex_to_word(balance_value)
                else:
                    raise ValueError(f"unsupported mock contract code path: {code}")
            elif action == "wait_receipt":
                continue
            else:
                raise ValueError(f"unsupported mock action: {action}")
        observed = self._observe(case, contracts, last_receipt, last_contract_address)
        context = {
            "$admin_account": self.admin_account,
            "$chain_id": hex(self.chain_id),
        }
        if last_contract_address is not None:
            context["$last_contract"] = last_contract_address
        if last_receipt is not None and last_receipt.get("effectiveGasPrice") is not None:
            context["$gas_price"] = last_receipt["effectiveGasPrice"]
        if block_context is not None:
            context.update(self._block_context_to_placeholders(block_context))
        return tx_hashes, observed, context

    def _observe(
        self,
        case: TestCase,
        contracts: dict[str, Any],
        last_receipt: dict[str, Any] | None = None,
        last_contract_address: str | None = None,
    ) -> dict[str, Any]:
        expected_shape = case.expected
        observe_config = case.observe
        target_address = observe_config.get("address", self.admin_account)
        observed: dict[str, Any] = {}
        if "balance" in expected_shape:
            balance_address = observe_config.get("balance_address", target_address)
            observed["balance"] = self._address_state(contracts, balance_address).get("balance", "0x0")
        if "code" in expected_shape:
            code_address = observe_config.get("code_address")
            if code_address == "$last_contract":
                code_address = last_contract_address
            if code_address is None:
                code_address = target_address
            observed["code"] = self._address_state(contracts, code_address).get("code", "0x")
        if "storage" in expected_shape:
            storage_address = observe_config.get("storage_address", target_address)
            if storage_address == "$last_contract":
                storage_address = last_contract_address
            observed["storage"] = {}
            storage = self._address_state(contracts, storage_address).get("storage", {})
            for slot in expected_shape["storage"]:
                observed["storage"][slot] = storage.get(slot, ZERO_STORAGE_WORD)
        if "system_witness" in expected_shape:
            witness_config = observe_config.get("system_witness")
            if witness_config is None:
                raise ValueError("expected.system_witness requires observe.system_witness")
            subject = witness_config.get("subject", target_address)
            if subject == "$last_contract":
                subject = last_contract_address
            if not subject:
                raise ValueError("system witness subject $last_contract is unavailable")
            storage = self._address_state(contracts, subject).get("storage", {})
            transport = {slot: storage.get(slot, ZERO_STORAGE_WORD) for slot in system_witness_storage_slots(witness_config)}
            observed["system_witness"] = collect_system_witness_from_storage(
                witness_config=witness_config,
                storage=transport,
            )
        if "receipt_status" in expected_shape:
            observed["receipt_status"] = None if last_receipt is None else last_receipt.get("status")
        if "receipt_contract_address" in expected_shape:
            observed["receipt_contract_address"] = (
                None if last_receipt is None else last_receipt.get("contractAddress")
            )
        if "receipt_logs" in expected_shape or observe_config.get("log_probe") is not None:
            observed["receipt_logs"] = self._normalize_receipt_logs(
                [] if last_receipt is None else last_receipt.get("logs")
            )
        return observed

    def _address_state(self, contracts: dict[str, Any], address: str) -> dict[str, Any]:
        return contracts.setdefault(address, {})

    def _build_mock_block_context(self) -> dict[str, str]:
        required = {
            "coinbase": "coinbase",
            "timestamp": "timestamp",
            "number": "number",
            "prevrandao": "prevrandao",
            "gaslimit": "gas_limit",
            "basefee": "base_fee",
        }
        context = {"chainid": hex(self.chain_id)}
        for output_key, config_key in required.items():
            value = self.block_context_config.get(config_key)
            if value is None:
                raise ValueError(
                    f"missing mock block-context witness config: block_context.{config_key} is required"
                )
            if output_key in {"coinbase", "prevrandao"}:
                context[output_key] = str(value)
            else:
                context[output_key] = hex(int(value))
        return context

    def _simulate_control_flow_probe(self, mode: str | None, code: str | None) -> str:
        if mode == "gas":
            if code != _build_gas_runtime():
                raise ValueError(f"unsupported mock contract code path: {code}")
            return WORD_01
        if mode == "jump":
            if code != _build_jump_runtime():
                raise ValueError(f"unsupported mock contract code path: {code}")
            return WORD_01
        if mode == "jump_pc_relative":
            if code != _build_jump_pc_relative_runtime():
                raise ValueError(f"unsupported mock contract code path: {code}")
            return WORD_01
        if mode == "jumpdest":
            if code != _build_jumpdest_runtime():
                raise ValueError(f"unsupported mock contract code path: {code}")
            return WORD_01
        if mode == "jumpi_fallthrough":
            if code != _build_jumpi_fallthrough_runtime():
                raise ValueError(f"unsupported mock contract code path: {code}")
            return ZERO_STORAGE_WORD
        if mode == "jumpi_taken":
            if code != _build_jumpi_taken_runtime():
                raise ValueError(f"unsupported mock contract code path: {code}")
            return WORD_01
        if mode == "pc":
            if code != _build_pc_runtime():
                raise ValueError(f"unsupported mock contract code path: {code}")
            return WORD_01
        raise ValueError(f"unsupported control-flow probe mode: {mode}")

    def _simulate_block_context_probe(
        self,
        mode: str | None,
        code: str | None,
        block_context: dict[str, str],
    ) -> str:
        if mode == "basefee":
            if code != BLOCK_CONTEXT_BASEFEE_RUNTIME:
                raise ValueError(f"unsupported mock contract code path: {code}")
            return self._hex_to_word(block_context["basefee"])
        if mode == "blockhash_current":
            if code != BLOCK_CONTEXT_BLOCKHASH_CURRENT_RUNTIME:
                raise ValueError(f"unsupported mock contract code path: {code}")
            return ZERO_STORAGE_WORD
        if mode == "chainid":
            if code != BLOCK_CONTEXT_CHAINID_RUNTIME:
                raise ValueError(f"unsupported mock contract code path: {code}")
            return self._hex_to_word(block_context["chainid"])
        if mode == "coinbase":
            if code != BLOCK_CONTEXT_COINBASE_RUNTIME:
                raise ValueError(f"unsupported mock contract code path: {code}")
            return self._address_to_word(block_context["coinbase"])
        if mode == "gaslimit":
            if code != BLOCK_CONTEXT_GASLIMIT_RUNTIME:
                raise ValueError(f"unsupported mock contract code path: {code}")
            return self._hex_to_word(block_context["gaslimit"])
        if mode == "number":
            if code != BLOCK_CONTEXT_NUMBER_RUNTIME:
                raise ValueError(f"unsupported mock contract code path: {code}")
            return self._hex_to_word(block_context["number"])
        if mode == "prevrandao":
            if code != BLOCK_CONTEXT_PREVRANDAO_RUNTIME:
                raise ValueError(f"unsupported mock contract code path: {code}")
            return block_context["prevrandao"]
        if mode == "timestamp":
            if code != BLOCK_CONTEXT_TIMESTAMP_RUNTIME:
                raise ValueError(f"unsupported mock contract code path: {code}")
            return self._hex_to_word(block_context["timestamp"])
        raise ValueError(f"unsupported block-context probe mode: {mode}")

    def _simulate_keccak_probe(
        self,
        storage: dict[str, str],
        keccak_probe: dict[str, Any],
        code: str | None,
        data: str,
    ) -> None:
        mode = keccak_probe.get("mode")
        if mode in {"basic", "keccak"}:
            expected_runtime = _build_basic_keccak_runtime(
                offset=keccak_probe["offset"],
                mem_update=keccak_probe["mem_update"],
            )
            if code != expected_runtime:
                raise ValueError(f"unsupported mock contract code path: {code}")
            calldata = bytes.fromhex((data[2:] if data.startswith("0x") else data) or "")
            digest, memory_witness_word, pre_witness_msize = simulate_basic_keccak_case(
                calldata=calldata,
                offset=keccak_probe["offset"],
                mem_update=keccak_probe["mem_update"],
            )
            storage["0x00"] = digest
            storage["0x01"] = self._hex_to_word(hex(memory_witness_word))
            storage["0x02"] = self._hex_to_word(hex(pre_witness_msize))
            return
        if mode == "diff_mem_msg_sizes":
            expected_runtime = _build_diff_mem_msg_sizes_runtime(
                mem_size=keccak_probe["mem_size"],
                msg_size=keccak_probe["msg_size"],
            )
            if code != expected_runtime:
                raise ValueError(f"unsupported mock contract code path: {code}")
            digest, pre_witness_msize = simulate_diff_mem_msg_sizes_case(
                mem_size=keccak_probe["mem_size"],
                msg_size=keccak_probe["msg_size"],
            )
            storage["0x00"] = digest
            storage["0x01"] = self._hex_to_word(hex(keccak_probe["msg_size"]))
            storage["0x02"] = self._hex_to_word(hex(pre_witness_msize))
            return
        if mode == "max_permutations":
            witness_input_length = keccak_probe.get("witness_input_length", keccak_probe.get("input_length"))
            if witness_input_length is None:
                raise ValueError("keccak max_permutations probe is missing witness_input_length")
            expected_runtime = _build_max_permutations_runtime(witness_input_length)
            if code != expected_runtime:
                raise ValueError(f"unsupported mock contract code path: {code}")
            payload = data[2:] if data.startswith("0x") else data
            digest = "0x" + keccak256(b"\x00" * witness_input_length).hex()
            rounded_memory_size = ((witness_input_length + 31) // 32) * 32
            storage["0x00"] = digest
            storage["0x01"] = self._hex_to_word(hex(witness_input_length))
            storage["0x02"] = self._hex_to_word(hex(rounded_memory_size))
            return
        raise ValueError(f"unsupported keccak probe mode: {mode}")

    def _simulate_log_probe(
        self,
        last_receipt: dict[str, Any] | None,
        log_probe: dict[str, Any],
        code: str | None,
    ) -> None:
        template = build_validated_log_probe_template(log_probe)
        expected_runtime = _build_log_runtime(template)
        if code != expected_runtime:
            raise ValueError(f"unsupported mock contract code path: {code}")
        if last_receipt is None:
            raise ValueError("log probe requires a receipt context")
        topics = [] if template.topic_word is None else [template.topic_word] * template.topic_count
        payload = _payload_bytes(template)
        last_receipt["logs"] = [
            {
                "topics": topics,
                "data": "0x" + payload.hex(),
            }
        ]

    def _simulate_create_empty_child_probe(
        self,
        storage: dict[str, str],
        witness_config: dict[str, Any],
        code: str | None,
    ) -> None:
        expected_runtime = _build_create_empty_child_runtime(
            witness_config["opcode"],
            value=int(witness_config.get("value", 0)),
        )
        if code != expected_runtime:
            raise ValueError(f"unsupported mock contract code path: {code}")
        storage["0x00"] = WORD_01
        storage["0x01"] = self._address_to_word("0xdddddddddddddddddddddddddddddddddddddddd")
        storage["0x02"] = ZERO_STORAGE_WORD
        if int(witness_config.get("value", 0)) > 0:
            storage["0x03"] = self._hex_to_word(hex(int(witness_config["value"])))

    def _simulate_create_child_code_probe(
        self,
        storage: dict[str, str],
        witness_config: dict[str, Any],
        code: str | None,
    ) -> None:
        initcode_size = int(witness_config["initcode_size"])
        data_kind = str(witness_config["data_kind"])
        expected_runtime = _build_create_child_code_runtime(
            witness_config["opcode"],
            initcode_size=initcode_size,
            data_kind=data_kind,
        )
        if code != expected_runtime:
            raise ValueError(f"unsupported mock contract code path: {code}")
        code_payload = _create_child_code_payload(initcode_size=initcode_size, data_kind=data_kind)
        storage["0x00"] = WORD_01
        storage["0x01"] = self._address_to_word("0xdddddddddddddddddddddddddddddddddddddddd")
        storage["0x02"] = self._hex_to_word(hex(initcode_size))
        storage["0x03"] = "0x" + keccak256(code_payload).hex()

    def _simulate_create_collision_probe(
        self,
        storage: dict[str, str],
        witness_config: dict[str, Any],
        code: str | None,
    ) -> None:
        expected_runtime = _build_create_collision_runtime(
            witness_config["opcode"],
            proxy_call_gas=int(witness_config["proxy_call_gas"]),
        )
        if code != expected_runtime:
            raise ValueError(f"unsupported mock contract code path: {code}")
        storage["0x00"] = WORD_01
        storage["0x01"] = WORD_01
        storage["0x02"] = self._address_to_word("0xdddddddddddddddddddddddddddddddddddddddd")
        storage["0x03"] = ZERO_STORAGE_WORD
        storage["0x04"] = ZERO_STORAGE_WORD
        storage["0x05"] = ZERO_STORAGE_WORD


    def _simulate_selfdestruct_single_probe(
        self,
        storage: dict[str, str],
        witness_config: dict[str, Any],
        code: str | None,
    ) -> None:
        if witness_config.get("scenario") != "created":
            raise ValueError(f"unsupported selfdestruct_single scenario: {witness_config.get('scenario')!r}")
        value = int(witness_config.get("value", 0))
        expected_runtime = _build_selfdestruct_created_runtime(value=value)
        if code != expected_runtime:
            raise ValueError(f"unsupported mock contract code path: {code}")
        storage["0x00"] = WORD_01
        storage["0x01"] = self._address_to_word("0xdddddddddddddddddddddddddddddddddddddddd")
        storage["0x02"] = WORD_01
        storage["0x03"] = ZERO_STORAGE_WORD
        if value > 0:
            storage["0x04"] = self._hex_to_word(hex(value))


    def _is_system_self_call_runtime(self, code: str | None) -> bool:
        try:
            self._parse_system_self_call_witness(code)
        except SystemExecutionError:
            return True
        except ValueError:
            return False
        return True

    def _simulate_system_self_call_probe(self, storage: dict[str, str], code: str | None) -> None:
        witness = self._parse_system_self_call_witness(code)
        payload = witness.returndata_word * witness.returndata_size
        storage["0x00"] = WORD_01 if witness.success else ZERO_STORAGE_WORD
        storage["0x01"] = self._hex_to_word(hex(witness.returndata_size))
        storage["0x02"] = "0x" + keccak256(payload).hex()

    def _parse_system_self_call_witness(self, code: str | None) -> SystemSelfCallWitness:
        if code is None or not isinstance(code, str) or not code.startswith("0x"):
            raise ValueError(f"unsupported mock contract code path: {code}")
        try:
            raw = bytes.fromhex(code[2:])
        except ValueError as exc:
            raise SystemExecutionError("malformed system runtime hex") from exc
        if len(raw) < len(SYSTEM_RUNTIME_HEADER) + len(SYSTEM_SELF_CALL_WRAPPER_SUFFIX):
            raise ValueError(f"unsupported mock contract code path: {code}")
        if not raw.startswith(SYSTEM_RUNTIME_HEADER) or not raw.endswith(SYSTEM_SELF_CALL_WRAPPER_SUFFIX):
            raise ValueError(f"unsupported mock contract code path: {code}")

        inner = raw[: len(raw) - len(SYSTEM_SELF_CALL_WRAPPER_SUFFIX)]
        jump_opcode_index = len(SYSTEM_RUNTIME_HEADER) + 2
        if inner[jump_opcode_index] != 0x57:
            raise SystemExecutionError("malformed system wrapper shape: missing canonical wrapper JUMPI")
        child_start = jump_opcode_index + 1
        child = inner[child_start:]
        if not child:
            raise SystemExecutionError("malformed system wrapper shape: empty child branch")

        if child[-1] == 0xF3:
            success = True
        elif child[-1] == 0xFD:
            success = False
        else:
            raise SystemExecutionError("malformed system wrapper shape: child branch must terminate in RETURN or REVERT")

        child_prefix = child[:-1]
        returndata_size, size_opcode_index = self._decode_system_child_returndata_size(child_prefix)
        if returndata_size > SYSTEM_ADMITTED_MAX_RETURNDATA_BYTES:
            raise SystemExecutionError(
                f"system returndata declaration exceeds admitted maximum: {returndata_size} > {SYSTEM_ADMITTED_MAX_RETURNDATA_BYTES}"
            )

        child_body = child_prefix[:size_opcode_index]
        returndata_word = b"\xff" if child_body else b"\x00"
        if returndata_size == 0 and child_body:
            raise SystemExecutionError(
                "malformed system wrapper shape: zero-length returndata declaration must not include a fill prefix"
            )
        return SystemSelfCallWitness(
            success=success,
            returndata_size=returndata_size,
            returndata_word=returndata_word,
        )

    def _decode_system_child_returndata_size(self, child: bytes) -> tuple[int, int]:
        if len(child) < 2 or child[-1] != 0x5F:
            raise SystemExecutionError(
                "malformed system wrapper shape: child branch must end with canonical PUSH-size/PUSH0 sequence"
            )
        size_end = len(child) - 1
        size_opcode_index = self._find_system_size_push_start(child, size_end - 1)
        size_opcode = child[size_opcode_index]
        if size_opcode == 0x5F:
            return 0, size_opcode_index
        push_len = size_opcode - 0x5F
        size_bytes = child[size_opcode_index + 1 : size_opcode_index + 1 + push_len]
        return int.from_bytes(size_bytes, "big"), size_opcode_index

    def _find_system_size_push_start(self, code: bytes, push_end: int) -> int:
        for start in range(max(0, push_end - 32), push_end + 1):
            opcode = code[start]
            if opcode == 0x5F and start == push_end:
                return start
            if 0x60 <= opcode <= 0x7F and start + (opcode - 0x5F) == push_end:
                return start
        raise SystemExecutionError(
            "malformed system wrapper shape: could not decode canonical returndata size operand"
        )

    def _hex_to_word(self, value: str) -> str:
        if isinstance(value, str) and value.startswith("0x"):
            return "0x" + value[2:].lower().rjust(64, "0")
        raise ValueError(f"unsupported hex word literal: {value!r}")

    def _hex_to_quantity(self, value: str) -> int:
        if isinstance(value, str) and value.startswith("0x"):
            return int(value, 16)
        raise ValueError(f"unsupported hex quantity literal: {value!r}")

    def _address_to_word(self, value: str) -> str:
        if isinstance(value, str) and value.startswith("0x") and len(value) == 42:
            return "0x" + value[2:].lower().rjust(64, "0")
        raise ValueError(f"unsupported address literal for word conversion: {value!r}")

    def _block_context_to_placeholders(self, block_context: dict[str, str]) -> dict[str, str]:
        return {
            "$block_coinbase": block_context["coinbase"],
            "$block_timestamp": block_context["timestamp"],
            "$block_number": block_context["number"],
            "$block_prevrandao": block_context["prevrandao"],
            "$block_gaslimit": block_context["gaslimit"],
            "$chain_id": block_context["chainid"],
            "$block_basefee": block_context["basefee"],
            "$block_coinbase_word": self._address_to_word(block_context["coinbase"]),
            "$block_timestamp_word": self._hex_to_word(block_context["timestamp"]),
            "$block_number_word": self._hex_to_word(block_context["number"]),
            "$block_gaslimit_word": self._hex_to_word(block_context["gaslimit"]),
            "$chain_id_word": self._hex_to_word(block_context["chainid"]),
            "$block_basefee_word": self._hex_to_word(block_context["basefee"]),
        }

    def _normalize_receipt_logs(self, logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for log in logs:
            topics = log.get("topics", [])
            data = log.get("data", "0x")
            normalized.append(
                {
                    "topics": [str(topic).lower() for topic in topics],
                    "topic_count": len(topics),
                    "data": data.lower(),
                    "data_length_bytes": self._hex_data_length_bytes(data),
                }
            )
        return normalized

    def _hex_data_length_bytes(self, value: str) -> int:
        if not value.startswith("0x"):
            raise ValueError(f"receipt log data must be hex-prefixed, got: {value!r}")
        normalized = value[2:]
        if len(normalized) % 2 != 0:
            raise ValueError(f"receipt log data must contain whole bytes, got: {value!r}")
        return len(normalized) // 2


class JsonRpcBackend:
    def __init__(self, profile: ChainProfile) -> None:
        self.profile = profile
        self.request_id = 0
        self.rpc_timeout_seconds = 10

    def execute_case(
        self,
        case: TestCase,
        namespace: str,
    ) -> tuple[list[str], dict[str, Any], dict[str, Any]]:
        _validate_case_for_backend(case, "jsonrpc")
        tx_hashes: list[str] = []
        last_receipt: dict[str, Any] | None = None
        last_contract_address: str | None = None
        block_context: dict[str, str] | None = None
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
                if case.observe.get("block_context_probe") is not None:
                    block_context = self._load_block_context(last_receipt)
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
        if block_context is not None:
            context.update(self._block_context_to_placeholders(block_context))
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
            storage_block_tag = "latest"
            if observe_config.get("block_context_probe") is not None and last_receipt is not None:
                storage_block_tag = last_receipt.get("blockNumber") or self.profile.block_context.rpc_block_tag
            observed["storage"] = {}
            for slot in expected_shape["storage"]:
                observed["storage"][slot] = self._rpc(
                    "eth_getStorageAt",
                    [storage_address, slot, storage_block_tag],
                )
        if "system_witness" in expected_shape:
            witness_config = observe_config.get("system_witness")
            if witness_config is None:
                raise ValueError("expected.system_witness requires observe.system_witness")
            subject = witness_config.get("subject", target_address)
            if subject == "$last_contract":
                subject = last_contract_address
            if not subject:
                raise ValueError("system witness subject $last_contract is unavailable")
            storage_block_tag = "latest"
            if last_receipt is not None:
                storage_block_tag = last_receipt.get("blockNumber") or self.profile.block_context.rpc_block_tag
            transport = {
                slot: self._rpc("eth_getStorageAt", [subject, slot, storage_block_tag])
                for slot in system_witness_storage_slots(witness_config)
            }
            observed["system_witness"] = collect_system_witness_from_storage(
                witness_config=witness_config,
                storage=transport,
            )
        if "receipt_status" in expected_shape:
            observed["receipt_status"] = None if last_receipt is None else last_receipt.get("status")
        if "receipt_contract_address" in expected_shape:
            observed["receipt_contract_address"] = (
                None if last_receipt is None else last_receipt.get("contractAddress")
            )
        if "receipt_logs" in expected_shape or observe_config.get("log_probe") is not None:
            observed["receipt_logs"] = MockBackend()._normalize_receipt_logs(
                [] if last_receipt is None else last_receipt.get("logs")
            )
        return observed

    def _resolve_address(self, value: str, last_contract_address: str | None) -> str:
        if value == "$last_contract":
            address = last_contract_address
            if not address:
                raise ValueError("no prior contractAddress available for $last_contract")
            return address
        return value

    def _load_block_context(self, last_receipt: dict[str, Any]) -> dict[str, str]:
        block_number = last_receipt.get("blockNumber")
        block_tag = block_number or self.profile.block_context.rpc_block_tag
        block_source = "receipt-block" if block_number else "rpc-block-tag"
        block = self._rpc("eth_getBlockByNumber", [block_tag, False])
        if block is None:
            raise ValueError(
                f"block context {block_source} {block_tag!r} returned no block from eth_getBlockByNumber"
            )
        required_fields = {
            "coinbase": "miner",
            "timestamp": "timestamp",
            "number": "number",
            "prevrandao": "mixHash",
            "gaslimit": "gasLimit",
            "basefee": "baseFeePerGas",
        }
        context: dict[str, str] = {"chainid": hex(self.profile.chain_id)}
        for context_key, block_key in required_fields.items():
            value = block.get(block_key)
            if value in (None, ""):
                raise ValueError(
                    f"block context {block_source} {block_tag!r} missing required field {block_key} for {context_key}"
                )
            context[context_key] = value
        return context

    def _block_context_to_placeholders(self, block_context: dict[str, str]) -> dict[str, str]:
        return {
            "$block_coinbase": block_context["coinbase"],
            "$block_timestamp": block_context["timestamp"],
            "$block_number": block_context["number"],
            "$block_prevrandao": block_context["prevrandao"],
            "$block_gaslimit": block_context["gaslimit"],
            "$chain_id": block_context["chainid"],
            "$block_basefee": block_context["basefee"],
        }

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
        attempts = 0
        while time.time() < deadline:
            attempts += 1
            receipt = self._rpc("eth_getTransactionReceipt", [tx_hash])
            if receipt is not None:
                return receipt
            time.sleep(1)
        raise TimeoutError(
            f"timed out waiting for receipt after {timeout_seconds}s and {attempts} polls: {tx_hash}"
        )

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
        endpoint_label = _safe_rpc_endpoint_label(self.profile.rpc_url)
        try:
            with urllib.request.urlopen(request, timeout=self.rpc_timeout_seconds) as response:
                body = json.loads(response.read().decode())
        except TimeoutError as exc:
            raise TimeoutError(
                f"rpc timeout for {method} after {self.rpc_timeout_seconds}s against {endpoint_label}"
            ) from exc
        except socket.timeout as exc:
            raise TimeoutError(
                f"rpc timeout for {method} after {self.rpc_timeout_seconds}s against {endpoint_label}"
            ) from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise TimeoutError(
                    f"rpc timeout for {method} after {self.rpc_timeout_seconds}s against {endpoint_label}"
                ) from exc
            if isinstance(exc.reason, socket.timeout):
                raise TimeoutError(
                    f"rpc timeout for {method} after {self.rpc_timeout_seconds}s against {endpoint_label}"
                ) from exc
            raise RuntimeError(
                f"rpc transport error for {method} against {endpoint_label}: {exc.reason}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"rpc decode error for {method}: {exc}") from exc
        if not isinstance(body, dict):
            raise RuntimeError(f"rpc response for {method} must be a JSON object")
        if "error" in body:
            raise RuntimeError(f"rpc error for {method}: {self._format_rpc_error(body['error'])}")
        if "result" not in body:
            raise RuntimeError(f"rpc response for {method} missing result field")
        return body["result"]

    def _format_rpc_error(self, error: Any) -> str:
        if isinstance(error, dict):
            code = error.get("code", "<missing-code>")
            message = error.get("message", "<missing-message>")
            return f"code={code} message={message!r}"
        return repr(error)


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
    expected: dict[str, Any] | None = None,
) -> ExecutionResult:
    return ExecutionResult(
        case_id=case.case_id,
        namespace=namespace,
        success=not diffs,
        tx_hashes=tx_hashes,
        context=context,
        observed=observed,
        expected=case.expected if expected is None else expected,
        diffs=diffs,
    )
