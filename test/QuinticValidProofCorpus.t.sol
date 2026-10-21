// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { WhirStructs } from "../src/whir/WhirStructs.sol";
import { KeccakChallenger } from "../src/transcript/KeccakChallenger.sol";
import {
    WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28 as Native
} from "../src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol";
import {
    WhirVerifier5_k22_jb100_ext5_lir4_ff4_rsv3_pow28 as Typed
} from "../src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirVerifier5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol";

contract QuinticValidProofCorpusTest is Test {
    using KeccakChallenger for KeccakChallenger.State;

    struct TranscriptEvent {
        uint8 op;
        bytes observedBytes;
        uint256 arg0;
        uint256 arg1;
    }

    struct TranscriptTrace {
        TranscriptEvent[] proverEvents;
        TranscriptEvent[] verifierEvents;
        uint256[] checkpointProver;
        uint256[] checkpointVerifier;
        bool checkpointMatch;
    }

    string internal constant STEM = "quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_success";
    uint256 internal constant MODULUS = 0x7f000001;
    uint8 internal constant OP_OBSERVE_BYTES = 0;
    uint8 internal constant OP_SAMPLE_BASE = 1;
    uint8 internal constant OP_SAMPLE_BITS = 2;
    uint8 internal constant OP_GRIND = 3;
    Native internal nativeVerifier;
    Typed internal typedVerifier;

    function setUp() public {
        nativeVerifier = Native(
            deployCode(
                "WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol:WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28"
            )
        );
        typedVerifier = Typed(
            deployCode(
                "WhirVerifier5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol:WhirVerifier5_k22_jb100_ext5_lir4_ff4_rsv3_pow28"
            )
        );
    }

    function testSeed1NativeAndTypedAccept() public view {
        _acceptNativeAndTyped("seed-1");
    }

    function testSeed2NativeAndTypedAccept() public view {
        _acceptNativeAndTyped("seed-2");
    }

    function testSeed1AllTransportsAccept() public view {
        _acceptTransports("seed-1");
    }

    function testSeed2AllTransportsAccept() public view {
        _acceptTransports("seed-2");
    }

    function testSeed1GeneralExtensionRows() public view {
        _assertGeneralExtensionRows("seed-1");
    }

    function testSeed2GeneralExtensionRows() public view {
        _assertGeneralExtensionRows("seed-2");
    }

    function testSeed1ReplayProverAndVerifierTranscripts() public view {
        _replayTranscripts("seed-1");
    }

    function testSeed2ReplayProverAndVerifierTranscripts() public view {
        _replayTranscripts("seed-2");
    }

    function testSeed1RejectCanonicalMutations() public view {
        _rejectCanonicalMutations("seed-1");
    }

    function testSeed2RejectCanonicalMutations() public view {
        _rejectCanonicalMutations("seed-2");
    }

    function testSeed1RejectRootSiblingAndLengths() public view {
        _rejectRootSiblingAndLengths("seed-1");
    }

    function testSeed2RejectRootSiblingAndLengths() public view {
        _rejectRootSiblingAndLengths("seed-2");
    }

    function _directory(string memory seed) internal pure returns (string memory) {
        return string.concat("testdata/quintic_valid_proofs/", seed, "/");
    }

    function _load(string memory seed)
        internal
        view
        returns (
            bytes memory blob,
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        )
    {
        string memory directory = _directory(seed);
        blob = vm.readFileBinary(string.concat(directory, STEM, ".blob"));
        statement = abi.decode(
            vm.readFileBinary(string.concat(directory, STEM, "_statement.abi")),
            (WhirStructs.WhirStatement)
        );
        proof = abi.decode(
            vm.readFileBinary(string.concat(directory, STEM, "_proof.abi")), (WhirStructs.WhirProof)
        );
    }

    function _acceptNativeAndTyped(string memory seed) internal view {
        (
            bytes memory blob,
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _load(seed);
        assertTrue(nativeVerifier.verify(proof.initialCommitment, blob));
        assertTrue(typedVerifier.verify(proof.initialCommitment, statement, proof));
    }

    function _acceptTransports(string memory seed) internal view {
        (,, WhirStructs.WhirProof memory proof) = _load(seed);
        string memory directory = _directory(seed);
        string[3] memory names = ["success.raw.whrc", "success.whrc", "success.dfs.whrc"];
        for (uint256 i; i < names.length; ++i) {
            bytes memory encoded = vm.readFileBinary(string.concat(directory, names[i]));
            if (i != 0) {
                assertEq(uint8(encoded[5]), 1, "force mode 1 for dense proofs");
            }
            assertTrue(nativeVerifier.verifyCompressed(proof.initialCommitment, encoded));
        }
        assertTrue(
            nativeVerifier.verify(
                proof.initialCommitment,
                vm.readFileBinary(string.concat(directory, "success.dfs.blob"))
            )
        );
    }

    function _assertGeneralExtensionRows(string memory seed) internal view {
        (,, WhirStructs.WhirProof memory proof) = _load(seed);
        for (uint256 round = 1; round < 3; ++round) {
            WhirStructs.QueryBatchOpening memory batch = proof.rounds[round].queryBatch;
            assertEq(batch.rowLen, 16);
            assertGt(batch.numQueries, 0);
            assertEq(batch.values.length, batch.rowLen * batch.numQueries);
            for (uint256 row; row < batch.numQueries; ++row) {
                _assertVaryingCoordinates(batch.values, row * batch.rowLen, batch.rowLen);
            }
        }
        assertEq(proof.finalPoly.length, 64);
        _assertVaryingCoordinates(proof.finalPoly, 0, proof.finalPoly.length);
        for (uint256 row; row < 4; ++row) {
            _assertVaryingCoordinates(proof.finalPoly, row * 16, 16);
        }
        WhirStructs.QueryBatchOpening memory finalBatch = proof.finalQueryBatch;
        assertEq(finalBatch.rowLen, 16);
        assertGt(finalBatch.numQueries, 0);
        assertEq(finalBatch.values.length, finalBatch.rowLen * finalBatch.numQueries);
        for (uint256 row; row < finalBatch.numQueries; ++row) {
            _assertVaryingCoordinates(finalBatch.values, row * finalBatch.rowLen, finalBatch.rowLen);
        }
    }

    function _assertVaryingCoordinates(uint256[] memory values, uint256 start, uint256 length)
        internal
        pure
    {
        for (uint256 coordinate = 1; coordinate < 5; ++coordinate) {
            uint256 shift = 224 - 32 * coordinate;
            uint32 first = uint32(values[start] >> shift);
            bool varied;
            for (uint256 element = 1; element < length; ++element) {
                if (uint32(values[start + element] >> shift) != first) {
                    varied = true;
                    break;
                }
            }
            assertTrue(varied, "extension coordinate is constant across the row");
        }
    }

    function _replayTranscripts(string memory seed) internal view {
        TranscriptTrace memory trace = abi.decode(
            vm.readFileBinary(
                string.concat(
                    _directory(seed),
                    "transcript_trace_quintic_k22_jb100_ext5_lir4_ff4_rsv3_pow28.abi"
                )
            ),
            (TranscriptTrace)
        );
        assertTrue(trace.checkpointMatch);
        assertGt(trace.proverEvents.length, 0);
        assertGt(trace.verifierEvents.length, 0);
        KeccakChallenger.State memory prover = _replay(trace.proverEvents);
        KeccakChallenger.State memory verifier = _replay(trace.verifierEvents);
        uint256[5] memory proverCheckpoint = prover.sampleExt5Coeffs();
        uint256[5] memory verifierCheckpoint = verifier.sampleExt5Coeffs();
        assertEq(trace.checkpointProver.length, 5);
        assertEq(trace.checkpointVerifier.length, 5);
        for (uint256 i; i < 5; ++i) {
            assertEq(proverCheckpoint[i], trace.checkpointProver[i]);
            assertEq(verifierCheckpoint[i], trace.checkpointVerifier[i]);
            assertEq(proverCheckpoint[i], verifierCheckpoint[i]);
        }
    }

    function _replay(TranscriptEvent[] memory events)
        internal
        pure
        returns (KeccakChallenger.State memory challenger)
    {
        for (uint256 i; i < events.length; ++i) {
            TranscriptEvent memory entry = events[i];
            if (entry.op == OP_OBSERVE_BYTES) {
                challenger.observeBytes(entry.observedBytes);
            } else if (entry.op == OP_SAMPLE_BASE) {
                assertEq(challenger.sampleBase(), entry.arg0);
            } else if (entry.op == OP_SAMPLE_BITS) {
                assertEq(challenger.sampleBits(entry.arg0), entry.arg1);
            } else if (entry.op == OP_GRIND) {
                assertTrue(challenger.checkWitness(entry.arg0, entry.arg1));
            } else {
                revert("BAD_TRANSCRIPT_OP");
            }
        }
    }

    function _rejectCanonicalMutations(string memory seed) internal view {
        for (uint256 mutation; mutation < 3; ++mutation) {
            (
                bytes memory blob,
                WhirStructs.WhirStatement memory statement,
                WhirStructs.WhirProof memory proof
            ) = _load(seed);
            (uint256 row1, uint256 finalPoly,) = _offsets(blob);
            if (mutation == 0) {
                _incrementWord(blob, 498, true);
                proof.initialOodAnswers[0] = _incrementPacked(proof.initialOodAnswers[0]);
            } else if (mutation == 1) {
                _incrementWord(blob, row1, false);
                proof.rounds[1].queryBatch.values[0] =
                    _incrementPacked(proof.rounds[1].queryBatch.values[0]);
            } else {
                _incrementWord(blob, finalPoly, false);
                proof.finalPoly[0] = _incrementPacked(proof.finalPoly[0]);
            }
            _rejectBlob(proof.initialCommitment, blob);
            _assertRevert(
                address(typedVerifier),
                abi.encodeCall(typedVerifier.verify, (proof.initialCommitment, statement, proof))
            );
        }
    }

    function _rejectRootSiblingAndLengths(string memory seed) internal view {
        (
            bytes memory blob,
            WhirStructs.WhirStatement memory statement,
            WhirStructs.WhirProof memory proof
        ) = _load(seed);
        bytes32 badRoot = proof.initialCommitment ^ bytes32(uint256(1) << 255);
        _rejectBlob(badRoot, blob);
        _assertRevert(
            address(typedVerifier),
            abi.encodeCall(typedVerifier.verify, (badRoot, statement, proof))
        );
        (,, uint256 sibling) = _offsets(blob);
        blob[sibling] ^= 0x01;
        proof.rounds[0].queryBatch.decommitments[0] ^= bytes32(uint256(1) << 248);
        _rejectBlob(proof.initialCommitment, blob);
        _assertRevert(
            address(typedVerifier),
            abi.encodeCall(typedVerifier.verify, (proof.initialCommitment, statement, proof))
        );
        (blob,, proof) = _load(seed);
        assembly ("memory-safe") { mstore(blob, sub(mload(blob), 1)) }
        _rejectBlob(proof.initialCommitment, blob);
        bytes memory encoded = vm.readFileBinary(string.concat(_directory(seed), "success.whrc"));
        assembly ("memory-safe") { mstore(encoded, sub(mload(encoded), 1)) }
        _assertRevert(
            address(nativeVerifier),
            abi.encodeCall(nativeVerifier.verifyCompressed, (proof.initialCommitment, encoded))
        );
    }

    function _rejectBlob(bytes32 root, bytes memory blob) internal view {
        _assertRevert(address(nativeVerifier), abi.encodeCall(nativeVerifier.verify, (root, blob)));
        bytes memory envelope = abi.encodePacked(
            bytes4(0x57485243), uint8(1), uint8(0), uint32(blob.length), uint32(blob.length), blob
        );
        _assertRevert(
            address(nativeVerifier),
            abi.encodeCall(nativeVerifier.verifyCompressed, (root, envelope))
        );
    }

    function _assertRevert(address target, bytes memory data) internal view {
        (bool success, bytes memory result) = target.staticcall{ gas: 15_000_000 }(data);
        assertFalse(success, "mutated proof accepted");
        assertGe(result.length, 4, "require a contract revert with error data");
    }

    function _incrementPacked(uint256 packed) internal pure returns (uint256) {
        uint256 coefficient = (uint256(uint32(packed >> 224)) + 1) % MODULUS;
        uint256 mask = uint256(type(uint32).max) << 224;
        return (packed & ~mask) | (coefficient << 224);
    }

    function _incrementWord(bytes memory blob, uint256 offset, bool littleEndian) internal pure {
        uint256 value;
        for (uint256 i; i < 4; ++i) {
            value |= uint256(uint8(blob[offset + i])) << ((littleEndian ? i : 3 - i) * 8);
        }
        value = (value + 1) % MODULUS;
        for (uint256 i; i < 4; ++i) {
            blob[offset + i] = bytes1(uint8(value >> ((littleEndian ? i : 3 - i) * 8)));
        }
    }

    function _offsets(bytes memory blob)
        internal
        pure
        returns (uint256 row1, uint256 finalPoly, uint256 sibling0)
    {
        uint256 cursor = 694;
        uint256[3] memory rowBytes = [uint256(38 * 16 * 4), 31 * 16 * 20, 19 * 16 * 20];
        for (uint256 round; round < 3; ++round) {
            cursor += 44;
            if (round == 1) {
                row1 = cursor;
            }
            cursor += rowBytes[round];
            if (round == 0) {
                sibling0 = cursor;
            }
            uint256 count =
                (uint256(uint8(blob[10 + 2 * round])) << 8) | uint256(uint8(blob[11 + 2 * round]));
            cursor += count * 20 + 176;
        }
        finalPoly = cursor;
    }
}
