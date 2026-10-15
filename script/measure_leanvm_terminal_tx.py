#!/usr/bin/env python3
"""Measure complete terminal transactions on an owned local Cancun Anvil instance."""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import time
import urllib.request

from leanvm_terminal_fixture_codec import keccak256


def validate_compiled_sources(project, artifact, contract):
    metadata = artifact["metadata"]
    assert contract in metadata["settings"]["compilationTarget"].values(), "artifact target differs"
    for name, source in metadata["sources"].items():
        relative = Path(name)
        assert not relative.is_absolute() and ".." not in relative.parts, f"invalid compiled source path: {name}"
        actual = "0x" + keccak256((project / relative).read_bytes()).hex()
        assert actual == source["keccak256"], f"compiled artifact is stale: {name}; run forge build --offline --force"
    configured = json.loads(subprocess.check_output(["forge", "config", "--json"], cwd=project, text=True))
    settings = metadata["settings"]
    assert settings["optimizer"]["enabled"] == configured["optimizer"], "compiled optimizer setting differs"
    assert settings["optimizer"]["runs"] == configured["optimizer_runs"], "compiled optimizer runs differ"
    assert settings.get("viaIR", False) == configured["via_ir"], "compiled via_ir setting differs"
    assert settings["evmVersion"] == configured["evm_version"], "compiled EVM version differs"
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("label")
    parser.add_argument("output", type=Path)
    parser.add_argument("--reject-calldata", action="append", type=Path, default=[])
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    root = project.parent
    fixture = project / "testdata/leanvm_terminal" / args.label
    manifest = json.loads((fixture / "manifest.json").read_text())
    for name, expected in manifest["source_sha256"].items():
        relative = Path(name)
        assert not relative.is_absolute() and ".." not in relative.parts, f"invalid source path: {name}"
        # Generators use project-relative paths; archived snapshots may include
        # the project directory. Both must identify the same local source files.
        source = root / relative if relative.parts[0] == project.name else project / relative
        assert hashlib.sha256(source.read_bytes()).hexdigest() == expected, f"source changed: {name}"
    name = manifest["contract"]
    artifact_path = project / "out" / (name + ".sol") / (name + ".json")
    artifact = json.loads(artifact_path.read_text())
    metadata = validate_compiled_sources(project, artifact, name)
    initcode = artifact["bytecode"]["object"]
    runtime = artifact["deployedBytecode"]["object"]
    calldata = (fixture / "calldata.bin").read_bytes()
    assert len(calldata) == manifest["calldata_bytes"]
    assert hashlib.sha256(calldata).hexdigest() == manifest["calldata_sha256"], "calldata differs from fixture manifest"
    assert hashlib.sha256((fixture / "proof.abi").read_bytes()).hexdigest() == manifest["proof_abi_sha256"], "proof ABI differs from fixture manifest"
    calldata_gas = sum(4 if value == 0 else 16 for value in calldata)
    assert calldata_gas == manifest["calldata_gas_4_16"], "calldata gas differs from fixture manifest"
    runtime_bytes = len(runtime.removeprefix("0x")) // 2
    initcode_bytes = len(initcode.removeprefix("0x")) // 2
    args.output.mkdir(parents=True, exist_ok=False)
    run_info = {
        "contract": name,
        "hardfork": "cancun",
        "anvil_runtime_size_allowance": 65536,
        "anvil_block_gas_limit": 1_000_000_000,
        "deployment_transaction_gas_limit": 25_000_000,
        "verification_transaction_gas_limit": 900_000_000,
        "runtime_bytes": runtime_bytes,
        "initcode_bytes": initcode_bytes,
        "runtime_within_eip170_limit": runtime_bytes <= 24576,
        "initcode_within_eip3860_limit": initcode_bytes <= 49152,
        "calldata_bytes": len(calldata),
        "calldata_gas_4_16": calldata_gas,
        "calldata_sha256": hashlib.sha256(calldata).hexdigest(),
        "artifact_sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
        "root_profile": manifest.get("root_profile"),
    }
    (args.output / "run-info.json").write_text(json.dumps(run_info, indent=2) + "\n")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    url = f"http://127.0.0.1:{port}"

    def rpc(method, params):
        request = urllib.request.Request(url, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=120) as response:
            result = json.load(response)
        if "error" in result:
            raise RuntimeError(result["error"])
        return result["result"]

    def receipt(transaction_hash):
        deadline = time.monotonic() + 30
        while True:
            value = rpc("eth_getTransactionReceipt", [transaction_hash])
            if value is not None:
                return value
            if time.monotonic() >= deadline:
                raise RuntimeError("transaction receipt timeout")
            time.sleep(0.1)

    command = ["anvil", "--silent", "--host", "127.0.0.1", "--port", str(port), "--hardfork", "cancun", "--code-size-limit", "65536", "--gas-limit", "1000000000"]
    with (args.output / "anvil.log").open("w") as log:
        node = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while True:
                assert node.poll() is None, "Anvil exited during startup"
                try:
                    accounts = rpc("eth_accounts", [])
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.1)
            sender = accounts[0]
            gas_price = rpc("eth_gasPrice", [])
            creation_hash = rpc("eth_sendTransaction", [{"from": sender, "data": initcode, "gas": hex(run_info["deployment_transaction_gas_limit"]), "gasPrice": gas_price}])
            creation = receipt(creation_hash)
            (args.output / "deployment-receipt.json").write_text(json.dumps(creation, indent=2) + "\n")
            assert int(creation["status"], 16) == 1, "deployment reverted"
            address = creation["contractAddress"]
            assert rpc("eth_getCode", [address, "latest"]) == runtime, "deployed bytecode differs from artifact"
            proof_hash = rpc("eth_sendTransaction", [{"from": sender, "to": address, "data": "0x" + calldata.hex(), "gas": hex(run_info["verification_transaction_gas_limit"]), "gasPrice": gas_price}])
            verified = receipt(proof_hash)
            (args.output / "verification-receipt.json").write_text(json.dumps(verified, indent=2) + "\n")
            assert int(verified["status"], 16) == 1, "complete verification transaction reverted"
            rejected = []
            for index, path in enumerate(args.reject_calldata):
                invalid = path.read_bytes()
                invalid_hash = rpc("eth_sendTransaction", [{"from": sender, "to": address, "data": "0x" + invalid.hex(), "gas": hex(run_info["verification_transaction_gas_limit"]), "gasPrice": gas_price}])
                invalid_receipt = receipt(invalid_hash)
                receipt_file = f"rejected-proof-{index}-receipt.json"
                (args.output / receipt_file).write_text(json.dumps(invalid_receipt, indent=2) + "\n")
                assert int(invalid_receipt["status"], 16) == 0, f"expected invalid proof was accepted: {path}"
                rejected.append({"calldata_sha256": hashlib.sha256(invalid).hexdigest(), "receipt_file": receipt_file, "status": 0, "transaction_gas": int(invalid_receipt["gasUsed"], 16)})
            used = int(verified["gasUsed"], 16)
            result = {
                **run_info,
                "chain_id": int(rpc("eth_chainId", []), 16),
                "deployment_transaction_gas": int(creation["gasUsed"], 16),
                "verification_transaction_gas": used,
                "transaction_base_gas": 21000,
                "execution_remainder_gas": used - 21000 - calldata_gas,
                "runtime_sha256": hashlib.sha256(bytes.fromhex(runtime.removeprefix("0x"))).hexdigest(),
                "source_sha256": manifest["source_sha256"],
                "anvil_version": subprocess.check_output(["anvil", "--version"], text=True).strip(),
                "forge_version": subprocess.check_output(["forge", "--version"], text=True).strip(),
                "verification_boundary": "complete LeanVM root IOP and WHIR, node public digest, and three authenticated fixed bytecode oracle WHIR openings",
            }
            result["verification_boundary"] = manifest.get("verification_boundary", result["verification_boundary"])
            result["measurement_script_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            result["artifact_sha256"] = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
            result["fixture_manifest_sha256"] = hashlib.sha256((fixture / "manifest.json").read_bytes()).hexdigest()
            result["compiler"] = metadata["compiler"]
            result["compiler_settings"] = metadata["settings"]
            result["rejected_proofs"] = rejected
            if "source_provenance" in manifest:
                provenance = manifest["source_provenance"]
                result["native_source_provenance_sha256"] = hashlib.sha256(json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                result["native_sources"] = {
                    repository: {key: value for key, value in record.items() if key != "files"}
                    for repository, record in provenance["repositories"].items()
                }
                result["native_proof_sha256"] = provenance["native_proof_sha256"]
            (args.output / "metrics.json").write_text(json.dumps(result, indent=2) + "\n")
            print(json.dumps({k: v for k, v in result.items() if k != "source_sha256"}, indent=2))
        finally:
            if node.poll() is None:
                node.terminate()
                try:
                    node.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    node.kill()
                    node.wait()


if __name__ == "__main__":
    main()
