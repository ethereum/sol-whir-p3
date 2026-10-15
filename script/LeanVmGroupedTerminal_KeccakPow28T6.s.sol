// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";
import { LeanVmGroupedTerminalVerifier } from "../src/leanvm/LeanVmGroupedTerminalVerifier.sol";
import {
    LeanVmGroupedTerminal_KeccakPow28T6
} from "../src/leanvm/generated/LeanVmGroupedTerminal_KeccakPow28T6.sol";

contract LeanVmGroupedTerminal_KeccakPow28T6TxBenchmark is Script {
    function run() external {
        bytes memory encoded =
            vm.readFileBinary("testdata/leanvm_terminal/GroupedLogupKeccakPow28T6/proof.abi");
        LeanVmGroupedTerminalVerifier.Proof memory proof =
            abi.decode(encoded, (LeanVmGroupedTerminalVerifier.Proof));
        bytes memory data =
            vm.readFileBinary("testdata/leanvm_terminal/GroupedLogupKeccakPow28T6/calldata.bin");
        require(
            keccak256(data)
                == keccak256(
                    abi.encodeCall(LeanVmGroupedTerminalVerifier.verifyGroupedLogupV1, (proof))
                ),
            "CALLDATA_ENCODING"
        );
        vm.startBroadcast();
        LeanVmGroupedTerminal_KeccakPow28T6 verifier = new LeanVmGroupedTerminal_KeccakPow28T6();
        (bool ok, bytes memory result) = address(verifier).call(data);
        require(ok && abi.decode(result, (bool)), "VERIFY_FAILED");
        vm.stopBroadcast();
        console2.log("complete grouped terminal verifier", address(verifier));
        console2.log("complete verification calldata bytes", data.length);
    }
}
