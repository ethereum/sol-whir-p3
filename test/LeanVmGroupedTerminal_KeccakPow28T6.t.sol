// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test, console2 } from "forge-std/Test.sol";
import { LeanVmGroupedTerminalVerifier } from "../src/leanvm/LeanVmGroupedTerminalVerifier.sol";
import {
    LeanVmTwoCommitmentExecution as Execution
} from "../src/leanvm/LeanVmTwoCommitmentExecution.sol";
import {
    LeanVmGroupedTerminal_KeccakPow28T6
} from "../src/leanvm/generated/LeanVmGroupedTerminal_KeccakPow28T6.sol";

contract LeanVmGroupedTerminal_KeccakPow28T6WrongRoot is LeanVmGroupedTerminal_KeccakPow28T6 {
    function fixedProgramConfig()
        internal
        pure
        override
        returns (Execution.TwoCommitmentConfig memory config)
    {
        config = super.fixedProgramConfig();
        config.expectedSecondaryRoot[0] ^= 1;
    }
}

contract LeanVmGroupedTerminal_KeccakPow28T6Test is Test {
    LeanVmGroupedTerminal_KeccakPow28T6 private verifier;

    function setUp() external {
        verifier = new LeanVmGroupedTerminal_KeccakPow28T6();
    }

    function loadProof() internal view returns (LeanVmGroupedTerminalVerifier.Proof memory) {
        return abi.decode(
            vm.readFileBinary("testdata/leanvm_terminal/GroupedLogupKeccakPow28T6/proof.abi"),
            (LeanVmGroupedTerminalVerifier.Proof)
        );
    }

    function testCompleteGroupedTerminal() external view {
        uint256 beforeGas = gasleft();
        require(verifier.verifyGroupedLogupV1(loadProof()), "VERIFY");
        console2.log("complete grouped terminal call gas", beforeGas - gasleft());
    }

    function testRejectApplicationRoot() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.applicationRoot[0] ^= 1;
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectSparkPoint() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.sparkPoint[0] ^= uint256(1) << 224;
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectSparkValue() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.sparkValue ^= uint256(1) << 224;
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectLiftPoint() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.liftPoint[0] ^= uint256(1) << 224;
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectLiftValue() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.liftValue ^= uint256(1) << 224;
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectRootValue() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.rootValue ^= uint256(1) << 224;
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectPrimaryCommitment() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.transcript[32] ^= bytes1(0x01);
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectSecondaryCommitment() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.transcript[64] ^= bytes1(0x01);
        vm.expectRevert("FIXED_PROGRAM_ROOT");
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectPrimaryInitialOpening() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.openings[3] ^= bytes1(uint8(1));
        vm.expectRevert("MERKLE_ROOT");
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectSecondaryInitialOpening() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.openings[17_153] ^= bytes1(uint8(1));
        vm.expectRevert("MERKLE_ROOT");
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectCrossValue() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.transcript[9696] ^= bytes1(uint8(1));
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectCombinedOodValue() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.transcript[9856] ^= bytes1(uint8(1));
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectWrongTrustedRoot() external {
        LeanVmGroupedTerminal_KeccakPow28T6WrongRoot wrong =
            new LeanVmGroupedTerminal_KeccakPow28T6WrongRoot();
        vm.expectRevert("FIXED_PROGRAM_ROOT");
        wrong.verifyGroupedLogupV1(loadProof());
    }

    function testRejectTrailingTranscript() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.transcript = bytes.concat(proof.transcript, new bytes(32));
        vm.expectRevert("UNUSED_TRANSCRIPT");
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectTrailingOpenings() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.openings = bytes.concat(proof.openings, new bytes(32));
        vm.expectRevert("UNUSED_OPENINGS");
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectHelperCommitment() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.transcript[96] ^= bytes1(0x01);
        vm.expectRevert();
        verifier.verifyGroupedLogupV1(proof);
    }

    function testRejectHelperInitialOpening() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        proof.openings[34_303] ^= bytes1(uint8(1));
        vm.expectRevert("MERKLE_ROOT");
        verifier.verifyGroupedLogupV1(proof);
    }

    function testCalldataMatchesExport() external view {
        assertEq(
            abi.encodeCall(verifier.verifyGroupedLogupV1, (loadProof())),
            vm.readFileBinary("testdata/leanvm_terminal/GroupedLogupKeccakPow28T6/calldata.bin")
        );
    }

    function testRejectEveryMemoryClaim() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        uint256[21] memory masks = [
            uint256(1), 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
        ];
        for (uint256 i; i < 21; ++i) {
            proof.transcript[5024 + 20 * i] ^= bytes1(uint8(masks[i]));
            vm.expectRevert();
            verifier.verifyGroupedLogupV1(proof);
            proof.transcript[5024 + 20 * i] ^= bytes1(uint8(masks[i]));
        }
    }

    function testRejectEveryBytecodeClaim() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        uint256[21] memory masks = [
            uint256(1), 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
        ];
        for (uint256 i; i < 21; ++i) {
            proof.transcript[6528 + 20 * i] ^= bytes1(uint8(masks[i]));
            vm.expectRevert();
            verifier.verifyGroupedLogupV1(proof);
            proof.transcript[6528 + 20 * i] ^= bytes1(uint8(masks[i]));
        }
    }

    function testRejectEveryExecutionClaim() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        uint256[27] memory masks = [
            uint256(1), 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
        ];
        for (uint256 i; i < 27; ++i) {
            proof.transcript[4480 + 20 * i] ^= bytes1(uint8(masks[i]));
            vm.expectRevert();
            verifier.verifyGroupedLogupV1(proof);
            proof.transcript[4480 + 20 * i] ^= bytes1(uint8(masks[i]));
        }
    }

    function testRejectEveryExtensionClaim() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        uint256[52] memory masks = [
            uint256(1),
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1
        ];
        for (uint256 i; i < 52; ++i) {
            proof.transcript[5472 + 20 * i] ^= bytes1(uint8(masks[i]));
            vm.expectRevert();
            verifier.verifyGroupedLogupV1(proof);
            proof.transcript[5472 + 20 * i] ^= bytes1(uint8(masks[i]));
        }
    }

    function testRejectEveryPoseidonClaim() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        uint256[135] memory masks = [
            uint256(1),
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1
        ];
        for (uint256 i; i < 135; ++i) {
            proof.transcript[6976 + 20 * i] ^= bytes1(uint8(masks[i]));
            vm.expectRevert();
            verifier.verifyGroupedLogupV1(proof);
            proof.transcript[6976 + 20 * i] ^= bytes1(uint8(masks[i]));
        }
    }

    function testRejectEveryCrossClaim() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        uint256[6] memory masks = [uint256(1), 1, 1, 1, 1, 1];
        for (uint256 i; i < 6; ++i) {
            proof.transcript[9696 + 20 * i] ^= bytes1(uint8(masks[i]));
            vm.expectRevert();
            verifier.verifyGroupedLogupV1(proof);
            proof.transcript[9696 + 20 * i] ^= bytes1(uint8(masks[i]));
        }
    }

    function testRejectEveryOpeningBatch() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        uint256[6] memory starts = [uint256(0), 17_150, 34_300, 51_450, 64_620, 75_180];
        uint256[6] memory masks = [uint256(1), 1, 1, 1, 1, 1];
        for (uint256 i; i < 6; ++i) {
            proof.openings[starts[i] + 3] ^= bytes1(uint8(masks[i]));
            vm.expectRevert("MERKLE_ROOT");
            verifier.verifyGroupedLogupV1(proof);
            proof.openings[starts[i] + 3] ^= bytes1(uint8(masks[i]));
        }
    }

    function testRejectEveryOpeningFrontier() external {
        LeanVmGroupedTerminalVerifier.Proof memory proof = loadProof();
        uint256[6] memory ends = [uint256(17_150), 34_300, 51_450, 64_620, 75_180, 83_930];
        for (uint256 i; i < 6; ++i) {
            proof.openings[ends[i] - 1] ^= bytes1(0x01);
            vm.expectRevert();
            verifier.verifyGroupedLogupV1(proof);
            proof.openings[ends[i] - 1] ^= bytes1(0x01);
        }
    }
}
