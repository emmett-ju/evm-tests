from __future__ import annotations

import json
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol

from adapter.block_context_generator import (
    BLOCK_CONTEXT_BASEFEE_RUNTIME,
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
from adapter.log_generator import _build_log_runtime
from adapter.models import ChainProfile, ExecutionResult, TestCase
from adapter.profile import describe_admin_key_source
from adapter.signer import keccak256, load_private_key, private_key_to_address, sign_type_2_transaction

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
    chain_id: int = 1337
    block_context_config: dict[str, Any] = field(default_factory=dict)
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
        block_context = self._build_mock_block_context()
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
        context.update(self._block_context_to_placeholders(block_context))
        if "receipt_status" in case.expected:
            observed["receipt_status"] = None if last_receipt is None else last_receipt.get("status")
        if "receipt_contract_address" in case.expected:
            observed["receipt_contract_address"] = (
                None if last_receipt is None else last_receipt.get("contractAddress")
            )
        if "receipt_logs" in case.expected:
            observed["receipt_logs"] = self._normalize_receipt_logs(
                [] if last_receipt is None else last_receipt.get("logs")
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
        if "receipt_logs" in case.expected:
            observed["receipt_logs"] = self._normalize_receipt_logs(
                [] if last_receipt is None else last_receipt.get("logs")
            )
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

    def _simulate_control_flow_probe(self, mode: Any, code: Any) -> str:
        expected_runtimes = {
            "gas": (_build_gas_runtime(), WORD_01),
            "pc": (_build_pc_runtime(), WORD_01),
            "jump": (_build_jump_runtime(), WORD_01),
            "jump_pc_relative": (_build_jump_pc_relative_runtime(), WORD_01),
            "jumpi_fallthrough": (_build_jumpi_fallthrough_runtime(), ZERO_STORAGE_WORD),
            "jumpi_taken": (_build_jumpi_taken_runtime(), WORD_01),
            "jumpdest": (_build_jumpdest_runtime(), WORD_01),
        }
        if mode not in expected_runtimes:
            raise ValueError(f"missing control-flow probe mode: {mode!r}")
        expected_runtime, expected_storage = expected_runtimes[mode]
        if code != expected_runtime:
            raise ValueError(f"unsupported mock contract code path: {code}")
        return expected_storage

    def _build_mock_block_context(self) -> dict[str, str]:
        configured = self.block_context_config
        coinbase = self._require_mock_block_context_field(configured, "coinbase")
        timestamp = int(self._require_mock_block_context_field(configured, "timestamp"))
        number = int(self._require_mock_block_context_field(configured, "number"))
        prevrandao = self._require_mock_block_context_field(configured, "prevrandao")
        gas_limit = int(self._require_mock_block_context_field(configured, "gas_limit"))
        base_fee = int(self._require_mock_block_context_field(configured, "base_fee"))
        return {
            "coinbase": coinbase.lower(),
            "timestamp": hex(timestamp),
            "number": hex(number),
            "prevrandao": prevrandao.lower(),
            "gaslimit": hex(gas_limit),
            "chainid": hex(self.chain_id),
            "basefee": hex(base_fee),
        }

    def _require_mock_block_context_field(self, configured: dict[str, Any], field_name: str) -> Any:
        value = configured.get(field_name)
        if value is None:
            raise ValueError(
                f"missing mock block-context witness config: block_context.{field_name} is required"
            )
        return value

    def _simulate_block_context_probe(
        self,
        mode: Any,
        code: Any,
        block_context: dict[str, str],
    ) -> str:
        expected_runtimes = {
            "basefee": (BLOCK_CONTEXT_BASEFEE_RUNTIME, "basefee"),
            "chainid": (BLOCK_CONTEXT_CHAINID_RUNTIME, "chainid"),
            "coinbase": (BLOCK_CONTEXT_COINBASE_RUNTIME, "coinbase"),
            "gaslimit": (BLOCK_CONTEXT_GASLIMIT_RUNTIME, "gaslimit"),
            "number": (BLOCK_CONTEXT_NUMBER_RUNTIME, "number"),
            "prevrandao": (BLOCK_CONTEXT_PREVRANDAO_RUNTIME, "prevrandao"),
            "timestamp": (BLOCK_CONTEXT_TIMESTAMP_RUNTIME, "timestamp"),
        }
        if mode not in expected_runtimes:
            raise ValueError(f"missing block-context probe mode: {mode!r}")
        expected_runtime, field_name = expected_runtimes[mode]
        if code != expected_runtime:
            raise ValueError(f"unsupported mock contract code path: {code}")
        value = block_context[field_name]
        if field_name == "coinbase":
            return self._address_to_word(value)
        return self._hex_to_word(value)

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

    def _int_to_word(self, value: int) -> str:
        return self._hex_to_word(hex(value))

    def _address_to_word(self, value: str) -> str:
        if not isinstance(value, str) or not value.startswith("0x"):
            raise ValueError(f"unsupported address literal for word conversion: {value!r}")
        normalized = value[2:].lower()
        if len(normalized) != 40:
            raise ValueError(f"address must be 20 bytes, got: {value}")
        return "0x" + normalized.rjust(64, "0")

    def _simulate_keccak_probe(
        self,
        storage: dict[str, Any],
        keccak_probe: dict[str, Any],
        code: Any,
        data: str,
    ) -> None:
        mode = keccak_probe.get("mode")
        calldata_hex = data[2:] if isinstance(data, str) and data.startswith("0x") else data
        calldata = bytes.fromhex(calldata_hex or "")
        if mode == "max_permutations":
            witness_input_length = keccak_probe.get("witness_input_length")
            if witness_input_length is None:
                raise ValueError("missing keccak probe mode data: witness_input_length")
            expected_runtime = _build_max_permutations_runtime(witness_input_length)
            if code != expected_runtime:
                raise ValueError(f"unsupported mock contract code path: {code}")
            storage["0x00"] = "0x" + keccak256(b"\x00" * witness_input_length).hex()
            storage["0x01"] = self._hex_to_word(hex(witness_input_length))
            rounded = ((witness_input_length + 31) // 32) * 32 if witness_input_length > 0 else 0
            storage["0x02"] = self._hex_to_word(hex(rounded))
            return
        if mode == "keccak":
            mem_alloc_hex = keccak_probe.get("mem_alloc_hex")
            offset = keccak_probe.get("offset")
            mem_update = keccak_probe.get("mem_update")
            if mem_alloc_hex is None or offset is None or mem_update is None:
                raise ValueError("missing keccak probe mode data for basic keccak case")
            expected_runtime = _build_basic_keccak_runtime(offset=offset, mem_update=mem_update)
            if code != expected_runtime:
                raise ValueError(f"unsupported mock contract code path: {code}")
            digest, memory_witness_word, pre_witness_msize = simulate_basic_keccak_case(
                calldata=calldata,
                offset=offset,
                mem_update=mem_update,
            )
            storage["0x00"] = digest
            storage["0x01"] = self._hex_to_word(hex(memory_witness_word))
            storage["0x02"] = self._hex_to_word(hex(pre_witness_msize))
            return
        if mode == "diff_mem_msg_sizes":
            mem_size = keccak_probe.get("mem_size")
            msg_size = keccak_probe.get("msg_size")
            if mem_size is None or msg_size is None:
                raise ValueError("missing keccak probe mode data for diff_mem_msg_sizes case")
            expected_runtime = _build_diff_mem_msg_sizes_runtime(mem_size=mem_size, msg_size=msg_size)
            if code != expected_runtime:
                raise ValueError(f"unsupported mock contract code path: {code}")
            digest, pre_witness_msize = simulate_diff_mem_msg_sizes_case(mem_size=mem_size, msg_size=msg_size)
            storage["0x00"] = digest
            storage["0x01"] = self._hex_to_word(hex(msg_size))
            storage["0x02"] = self._hex_to_word(hex(pre_witness_msize))
            return
        raise ValueError(f"missing keccak probe mode: {mode!r}")

    def _simulate_log_probe(
        self,
        last_receipt: dict[str, Any] | None,
        log_probe: dict[str, Any],
        code: Any,
    ) -> None:
        if last_receipt is None:
            raise ValueError("log probe requires a receipt context")
        mode = log_probe.get("mode")
        if mode != "parametric_log":
            raise ValueError(f"missing log probe mode: {mode!r}")

        opcode = log_probe.get("opcode")
        topic_count = log_probe.get("topic_count")
        topic_word = log_probe.get("topic_word")
        log_size = log_probe.get("log_size")
        memory_seed_kind = log_probe.get("memory_seed_kind")
        memory_seed_size = log_probe.get("memory_seed_size")
        witness_mode = log_probe.get("witness_mode")

        expected_runtime = _build_log_runtime(
            template=type("InlineLogTemplate", (), {
                "opcode": opcode,
                "topic_count": topic_count,
                "topic_word": topic_word,
                "log_size": log_size,
                "memory_seed_kind": memory_seed_kind,
                "memory_seed_size": memory_seed_size,
                "witness_mode": witness_mode,
            })()
        )
        if code != expected_runtime:
            raise ValueError(f"unsupported mock contract code path: {code}")

        filled = 0
        if memory_seed_kind == "ff" and isinstance(memory_seed_size, int):
            filled = min(int(log_size or 0), memory_seed_size)
        payload = (b"\xff" * filled) + (b"\x00" * max(0, int(log_size or 0) - filled))
        topics = [] if topic_word is None else [topic_word] * int(topic_count or 0)
        last_receipt["logs"] = [
            {
                "address": "0xcccccccccccccccccccccccccccccccccccccccc",
                "topics": topics,
                "data": "0x" + payload.hex(),
            }
        ]

    def _is_system_self_call_runtime(self, code: Any) -> bool:
        if not isinstance(code, str) or not code.startswith("0x"):
            return False
        runtime = bytes.fromhex(code[2:])
        return runtime.endswith(SYSTEM_SELF_CALL_WRAPPER_SUFFIX)

    def _simulate_system_self_call_probe(
        self,
        storage: dict[str, Any],
        code: str,
    ) -> None:
        runtime = bytes.fromhex(code[2:])
        prefix = runtime[: -len(SYSTEM_SELF_CALL_WRAPPER_SUFFIX)]
        return_size, return_non_zero_data, child_succeeds = self._decode_system_self_call_prefix(prefix, code)
        payload = (b"\xff" if return_non_zero_data else b"\x00") * return_size
        storage["0x00"] = WORD_01 if child_succeeds else ZERO_STORAGE_WORD
        storage["0x01"] = self._hex_to_word(hex(return_size))
        storage["0x02"] = "0x" + keccak256(payload).hex()

    def _decode_system_self_call_prefix(
        self,
        prefix: bytes,
        code: str,
    ) -> tuple[int, bool, bool]:
        if len(prefix) < 8 or prefix[0] != 0x36 or prefix[1] != 0x5F or prefix[2] != 0x14:
            raise ValueError(f"unsupported mock contract code path: {code}")
        wrapper_label, jump_index = self._read_push_int(prefix, 3)
        if jump_index >= len(prefix) or prefix[jump_index] != 0x57:
            raise ValueError(f"unsupported mock contract code path: {code}")
        if prefix[-1] not in {0xF3, 0xFD} or prefix[-2] != 0x5F:
            raise ValueError(f"unsupported mock contract code path: {code}")
        child_succeeds = prefix[-1] == 0xF3
        push_size_start = self._find_terminal_push_start(prefix)
        return_size, after_size = self._read_push_int(prefix, push_size_start)
        if after_size != len(prefix) - 2:
            raise ValueError(f"unsupported mock contract code path: {code}")
        middle = prefix[jump_index + 1 : push_size_start]
        return_non_zero_data = len(middle) > 0
        if not return_non_zero_data and wrapper_label != len(prefix):
            raise ValueError(f"unsupported mock contract code path: {code}")
        return return_size, return_non_zero_data, child_succeeds

    def _find_terminal_push_start(self, data: bytes) -> int:
        search_start = max(0, len(data) - 34)
        for index in range(search_start, len(data) - 2):
            try:
                _, next_index = self._read_push_int(data, index)
            except ValueError:
                continue
            if next_index == len(data) - 2:
                return index
        raise ValueError("could not locate terminal PUSH operand in system runtime")

    def _read_push_int(self, data: bytes, index: int) -> tuple[int, int]:
        if index >= len(data):
            raise ValueError("unexpected end of bytecode while decoding PUSH")
        opcode = data[index]
        if opcode == 0x5F:
            return 0, index + 1
        if not 0x60 <= opcode <= 0x7F:
            raise ValueError(f"expected PUSH opcode, got 0x{opcode:02x}")
        length = opcode - 0x5F
        end = index + 1 + length
        if end > len(data):
            raise ValueError("truncated PUSH operand in bytecode")
        return int.from_bytes(data[index + 1:end], "big"), end

    def _normalize_receipt_logs(self, logs: Any) -> list[dict[str, Any]]:
        if logs is None:
            return []
        if not isinstance(logs, list):
            raise ValueError(f"receipt logs must be a list, got {type(logs).__name__}")
        normalized: list[dict[str, Any]] = []
        for index, entry in enumerate(logs):
            if not isinstance(entry, dict):
                raise ValueError(f"receipt log {index} must be an object")
            topics = entry.get("topics")
            if not isinstance(topics, list):
                raise ValueError(f"receipt log {index}.topics must be a list")
            data = entry.get("data")
            if not isinstance(data, str):
                raise ValueError(f"receipt log {index}.data must be a hex string")
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

    def execute_case(
        self,
        case: TestCase,
        namespace: str,
    ) -> tuple[list[str], dict[str, Any], dict[str, Any]]:
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
        if "receipt_logs" in expected_shape:
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
        block = self._rpc("eth_getBlockByNumber", [block_tag, False])
        if block is None:
            raise ValueError(f"could not load block context for block tag {block_tag!r}")
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
                raise ValueError(f"block context missing required field {block_key} for {context_key}")
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
