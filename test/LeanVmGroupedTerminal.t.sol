// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { LeanVmGroupedTerminalVerifier } from "../src/leanvm/LeanVmGroupedTerminalVerifier.sol";
import {
    LeanVmGroupedTerminal_KeccakPow28T6
} from "../src/leanvm/generated/LeanVmGroupedTerminal_KeccakPow28T6.sol";

/// @dev Historical proofs are explicit rejection cases for the selected verifier.
contract LeanVmGroupedTerminalHistoricalTest is Test {
    LeanVmGroupedTerminal_KeccakPow28T6 private verifier;

    function setUp() external {
        verifier = new LeanVmGroupedTerminal_KeccakPow28T6();
    }

    function loadProof() internal view returns (LeanVmGroupedTerminalVerifier.Proof memory) {
        return abi.decode(
            vm.readFileBinary("testdata/grouped_logup/proof.abi"),
            (LeanVmGroupedTerminalVerifier.Proof)
        );
    }

    function testRejectHistoricalGroupedProof() external {
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(loadProof());
    }

    function testCalldataMatchesHistoricalExport() external view {
        assertEq(
            abi.encodeCall(verifier.verifyGroupedLogupV1, (loadProof())),
            vm.readFileBinary("testdata/grouped_logup/calldata.bin")
        );
    }

    function testRejectHistoricalC1Proof() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = abi.decode(
            vm.readFileBinary("testdata/grouped_logup/historical-c1-proof.abi"),
            (LeanVmGroupedTerminalVerifier.Proof)
        );
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }
}
