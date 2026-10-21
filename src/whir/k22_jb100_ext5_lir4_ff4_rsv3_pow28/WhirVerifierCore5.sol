// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { QuinticTransportCodec } from "./QuinticTransportCodec.sol";
import { KoalaBearPackedField } from "../../field/KoalaBearPackedField.sol";

import { KoalaBear } from "../../field/KoalaBear.sol";
import { KoalaBearExt5 } from "../../field/KoalaBearExt5.sol";
import { MerkleVerifier } from "../../merkle/MerkleVerifier.sol";
import { KeccakChallenger } from "../../transcript/KeccakChallenger.sol";
import { WhirStructs } from "../WhirStructs.sol";
import { WhirBlobCodec5 } from "./WhirBlobCodec5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol";
import { WhirVerifierUtils5 } from "./WhirVerifierUtils5.sol";

library WhirVerifierCore5 {
    using KeccakChallenger for KeccakChallenger.State;

    bytes private constant POW_TABLE_ROUND0 =
        hex"00000001205d63c3484ef19b7c72a143514ddcad4ec6c539534ef3a93787f990143ef8990986b2321e3f974a2e1e79003440651f421a291e4fe17621510d61d1000000016c4a8a45163bd49958ff6e906e2f4d7a65d3aa2e57421f5d71352c4c45a60e616428b7e3665070516566002c4cd7bb26247e1bfa75386aad37c43dd9000000013e687d4d303964b2300ba3ce768fc6fa2cb3f80a3f56e3af3446e3ab7744959c3b725f621e9330746107e94c437ce0a445b5bd2e7e77ea690409289300000001334d48c727ad539b54d7833617668b8a540363e73546ad0e0b4d176329b75a801da1678948d2e0073f9e4a46654a8bad7d598a0369af7ef41ed33131000000015c4a5b990a28f03164a0e08708dbd69c4154af7e5af0e6ec6931c06d6832fe4a4489a82a226210df1d14ebfe27ae21e2309bb4e5433bb7737348d2db000000017e0100027f00000000feffff000000017e0100027f00000000feffff000000017e0100027f00000000feffff000000017e0100027f00000000feffff";
    bytes private constant POW_TABLE_ROUND1 =
        hex"00000001143ef8996c4a8a452af20850163bd4994e38e75058ff6e90197482136e2f4d7a5f4ec37265d3aa2e4c45a35957421f5d1283c20671352c4c010d00af0000000145a60e613e687d4d4625f2a2303964b27e3a7e88300ba3ce5f9907a9768fc6fa3172b4f92cb3f80a6bb97d963f56e3af6b1d5bd03446e3ab11863e84000000017744959c334d48c775227a3327ad539b32313d6e54d78336425d36ed17668b8a466286e4540363e713ac5cf73546ad0e377a49320b4d17634145eb850000000129b75a805c4a5b99586ff04e0a28f0315599fb2c64a0e08700d2f0dd08dbd69c41f938d84154af7e36a66a455af0e6ec717740f96931c06d0fe3cde7000000016832fe4a7e010002174e36507f00000016cd01b700feffff67b1c9b1000000016832fe4a7e010002174e36507f00000016cd01b700feffff67b1c9b1";
    bytes private constant POW_TABLE_ROUND2 =
        hex"000000016c4a8a45163bd49958ff6e906e2f4d7a65d3aa2e57421f5d71352c4c45a60e616428b7e3665070516566002c4cd7bb26247e1bfa75386aad37c43dd9000000013e687d4d303964b2300ba3ce768fc6fa2cb3f80a3f56e3af3446e3ab7744959c3b725f621e9330746107e94c437ce0a445b5bd2e7e77ea690409289300000001334d48c727ad539b54d7833617668b8a540363e73546ad0e0b4d176329b75a801da1678948d2e0073f9e4a46654a8bad7d598a0369af7ef41ed33131000000015c4a5b990a28f03164a0e08708dbd69c4154af7e5af0e6ec6931c06d6832fe4a4489a82a226210df1d14ebfe27ae21e2309bb4e5433bb7737348d2db000000017e0100027f00000000feffff000000017e0100027f00000000feffff000000017e0100027f00000000feffff000000017e0100027f00000000feffff";
    bytes private constant POW_TABLE_FINAL =
        hex"00000001163bd4996e2f4d7a57421f5d45a60e61665070514cd7bb2675386aad3e687d4d1908abb42a79b9947e1ad39c4625f2a217aa4b5f2cf219ca03bc565600000001303964b2768fc6fa3f56e3af7744959c1e933074437ce0a47e77ea69334d48c740fe646a100753d77ca12bf875227a3325957b534451b86f52a36f8f0000000127ad539b17668b8a3546ad0e29b75a8048d2e007654a8bad69af7ef45c4a5b995b47c55d3cc6248a171639a5586ff04e04c4aab70a9a56263bbe793a000000010a28f03108dbd69c5af0e6ec6832fe4a226210df27ae21e2433bb7737e0100026d6e568d3a89a0253893800a174e365063861a5027dfce221335b668000000017f000000000000017f000000000000017f000000000000017f000000000000017f000000000000017f000000000000017f000000000000017f000000";

    struct EqStatement {
        uint256 numVariables;
        uint256[] flatPoints;
        uint256[] evaluations;
    }

    struct SelectStatement {
        uint256 numVariables;
        uint256[] vars;
    }

    struct Constraint {
        uint256 challenge;
        EqStatement eqStatement;
        SelectStatement selStatement;
    }

    struct ParsedCommitment {
        bytes32 root;
        EqStatement oodStatement;
    }

    struct FixedParsedCommitment {
        bytes32 root;
        uint256[] oodFlatPoints;
        uint256 oodEvaluation;
    }

    error CommitmentMismatch(bytes32 expected, bytes32 actual);
    error ProofRoundCountMismatch(uint256 expected, uint256 actual);
    error StatementLengthMismatch(uint256 points, uint256 evaluations);
    error StatementPointArityMismatch(uint256 index, uint256 expected, uint256 actual);
    error OodAnswerCountMismatch(uint256 expected, uint256 actual);
    error FinalPolyLengthMismatch(uint256 expected, uint256 actual);
    error FinalQueryBatchPresenceMismatch(bool expected, bool actual);
    error FinalSumcheckPresenceMismatch(bool expected, bool actual);
    error QueryBatchKindMismatch(uint8 expected, uint8 actual);
    error QueryBatchCountMismatch(uint256 expected, uint256 actual);
    error QueryBatchRowLengthMismatch(uint256 expected, uint256 actual);
    error MerkleRootMismatch(bytes32 expected, bytes32 actual);
    error InvalidPowWitness();
    error SumcheckPolynomialLengthMismatch(uint256 expected, uint256 actual);
    error SumcheckPowWitnessLengthMismatch(uint256 expected, uint256 actual);
    error StirConstraintFailed(uint256 index);
    error FinalConstraintMismatch(uint256 expected, uint256 actual);
    error InconsistentConstraintArity(uint256 eqNumVariables, uint256 selNumVariables);
    error RandomnessLengthMismatch(uint256 expected, uint256 actual);

    function _powBatch10(
        uint256 base,
        uint256 e0,
        uint256 e1,
        uint256 e2,
        uint256 e3,
        uint256 e4,
        uint256 e5,
        uint256 e6,
        uint256 e7,
        uint256 e8,
        uint256 e9
    )
        private
        pure
        returns (
            uint256 p0,
            uint256 p1,
            uint256 p2,
            uint256 p3,
            uint256 p4,
            uint256 p5,
            uint256 p6,
            uint256 p7,
            uint256 p8,
            uint256 p9
        )
    {
        p0 = 1;
        p1 = 1;
        p2 = 1;
        p3 = 1;
        p4 = 1;
        p5 = 1;
        p6 = 1;
        p7 = 1;
        p8 = 1;
        p9 = 1;

        unchecked {
            while (true) {
                if ((e0 & 1) != 0) p0 = KoalaBear.mul(p0, base);
                if ((e1 & 1) != 0) p1 = KoalaBear.mul(p1, base);
                if ((e2 & 1) != 0) p2 = KoalaBear.mul(p2, base);
                if ((e3 & 1) != 0) p3 = KoalaBear.mul(p3, base);
                if ((e4 & 1) != 0) p4 = KoalaBear.mul(p4, base);
                if ((e5 & 1) != 0) p5 = KoalaBear.mul(p5, base);
                if ((e6 & 1) != 0) p6 = KoalaBear.mul(p6, base);
                if ((e7 & 1) != 0) p7 = KoalaBear.mul(p7, base);
                if ((e8 & 1) != 0) p8 = KoalaBear.mul(p8, base);
                if ((e9 & 1) != 0) p9 = KoalaBear.mul(p9, base);

                e0 >>= 1;
                e1 >>= 1;
                e2 >>= 1;
                e3 >>= 1;
                e4 >>= 1;
                e5 >>= 1;
                e6 >>= 1;
                e7 >>= 1;
                e8 >>= 1;
                e9 >>= 1;

                if ((e0 | e1 | e2 | e3 | e4 | e5 | e6 | e7 | e8 | e9) == 0) break;

                base = KoalaBear.mul(base, base);
            }
        }
    }

    function _fillSelVarsPow(uint256[] memory selVars, uint256 base, uint256 count) internal pure {
        uint256 freePtr;
        assembly ("memory-safe") {
            freePtr := mload(0x40)
        }

        // STIR indices are sampled below each folded-domain size, so the fixed bases below receive
        // exponents of at most 22, 19, 18, and 17 bits. A regenerated schedule must update both the
        // generator dispatch and its matching table; an unknown generator uses the general path.
        bytes memory table;
        if (base == 542_991_299) {
            table = POW_TABLE_ROUND0;
        } else if (base == 339_671_193) {
            table = POW_TABLE_ROUND1;
        } else if (base == 1_816_824_389) {
            table = POW_TABLE_ROUND2;
        } else if (base == 373_019_801) {
            table = POW_TABLE_FINAL;
        } else {
            unchecked {
                for (uint256 i = 0; i < count; ++i) {
                    selVars[i] = KoalaBear.pow(base, selVars[i]);
                }
            }
            return;
        }

        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let tableStart := add(table, 0x20)
            let tableEnd := add(tableStart, mload(table))
            let values := add(selVars, 0x20)
            let valuesEnd := add(values, shl(5, count))
            for { let valuePtr := values } lt(valuePtr, valuesEnd) {
                valuePtr := add(valuePtr, 0x20)
            } {
                let exponent := mload(valuePtr)
                // Every fixed-base table has five or six nibble windows. The first
                // multiplication by one and the per-window loop machinery are unnecessary.
                let result := shr(224, mload(add(tableStart, shl(2, and(exponent, 0x0f)))))
                result := mulmod(
                    result,
                    shr(224, mload(add(add(tableStart, 64), shl(2, and(shr(4, exponent), 0x0f))))),
                    modulus
                )
                result := mulmod(
                    result,
                    shr(224, mload(add(add(tableStart, 128), shl(2, and(shr(8, exponent), 0x0f))))),
                    modulus
                )
                result := mulmod(
                    result,
                    shr(
                        224,
                        mload(add(add(tableStart, 192), shl(2, and(shr(12, exponent), 0x0f))))
                    ),
                    modulus
                )
                result := mulmod(
                    result,
                    shr(
                        224,
                        mload(add(add(tableStart, 256), shl(2, and(shr(16, exponent), 0x0f))))
                    ),
                    modulus
                )
                if eq(sub(tableEnd, tableStart), 384) {
                    result := mulmod(
                        result,
                        shr(
                            224,
                            mload(add(add(tableStart, 320), shl(2, and(shr(20, exponent), 0x0f))))
                        ),
                        modulus
                    )
                }
                mstore(valuePtr, result)
            }
            mstore(0x40, freePtr)
        }
    }

    function _computeExtension5RootAndEvalsBlob16(
        uint256[] memory indices,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 depth,
        uint256 decommOffset,
        uint256 decommLen,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3,
        uint256[] memory compactOffsets
    ) private pure returns (bytes32 root, uint256[] memory rowEvals) {
        uint256 count = indices.length;
        if (count == 0) {
            revert MerkleVerifier.EmptyIndices();
        }

        uint256[] memory frontierEntries;
        assembly ("memory-safe") {
            frontierEntries := mload(0x40)
            mstore(frontierEntries, count)
            rowEvals := add(add(frontierEntries, 0x20), shl(5, count))
            mstore(rowEvals, count)
            mstore(0x40, add(add(rowEvals, 0x20), shl(5, count)))
        }

        uint256 eqWeightsPtr = WhirVerifierUtils5._computeDim4EqWeightsUnpacked(p0, p1, p2, p3);

        unchecked {
            uint256 prevIdx;
            for (uint256 i = 0; i < count; ++i) {
                uint256 idx = indices[i];
                if (i != 0 && prevIdx >= idx) {
                    revert MerkleVerifier.IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                uint256 rowOffset = valuesOffset + i * 320;
                bytes32 hash;
                uint256 evalValue;
                if (compactOffsets.length != 0) {
                    (hash, evalValue) = WhirVerifierUtils5._hashAndEvaluateCompactRow16(
                        blob, compactOffsets[i], eqWeightsPtr
                    );
                } else {
                    (hash, evalValue) = WhirVerifierUtils5._hashAndEvaluateExtensionRow16Blob(
                        blob, rowOffset, eqWeightsPtr
                    );
                }
                rowEvals[i] = evalValue;

                assembly ("memory-safe") {
                    mstore(add(add(frontierEntries, 0x20), shl(5, i)), or(hash, idx))
                }
            }
        }

        root = MerkleVerifier.computeRootFromPackedFrontier20BlobTransport(
            frontierEntries, count, depth, blob, decommOffset, decommLen
        );
    }

    function _computeBaseRootAndEvals16(
        uint256[] memory indices,
        uint256[] calldata flatValues,
        uint256 depth,
        bytes32[] calldata decommitments,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) private pure returns (bytes32 root, uint256[] memory rowEvals) {
        uint256 count = indices.length;
        if (count == 0) {
            revert MerkleVerifier.EmptyIndices();
        }

        uint256[] memory frontierEntries;
        assembly ("memory-safe") {
            frontierEntries := mload(0x40)
            mstore(frontierEntries, count)
            rowEvals := add(add(frontierEntries, 0x20), shl(5, count))
            mstore(rowEvals, count)
            mstore(0x40, add(add(rowEvals, 0x20), shl(5, count)))
        }

        unchecked {
            uint256 prevIdx;
            for (uint256 i = 0; i < count; ++i) {
                uint256 idx = indices[i];
                if (i != 0 && prevIdx >= idx) {
                    revert MerkleVerifier.IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                (bytes32 hash, uint256 evalValue) = WhirVerifierUtils5._hashAndEvaluateBaseRowDim4PackedPoints(
                    flatValues, i * 16, p0, p1, p2, p3
                );
                rowEvals[i] = evalValue;

                assembly ("memory-safe") {
                    mstore(add(add(frontierEntries, 0x20), shl(5, i)), or(hash, idx))
                }
            }
        }

        root = MerkleVerifier.computeRootFromPackedFrontier20(
            frontierEntries, count, depth, decommitments
        );
    }

    function _computeExtension5RootAndEvals16(
        uint256[] memory indices,
        uint256[] calldata flatValues,
        uint256 depth,
        bytes32[] calldata decommitments,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) private pure returns (bytes32 root, uint256[] memory rowEvals) {
        uint256 count = indices.length;
        if (count == 0) {
            revert MerkleVerifier.EmptyIndices();
        }

        uint256[] memory frontierEntries;
        assembly ("memory-safe") {
            frontierEntries := mload(0x40)
            mstore(frontierEntries, count)
            rowEvals := add(add(frontierEntries, 0x20), shl(5, count))
            mstore(rowEvals, count)
            mstore(0x40, add(add(rowEvals, 0x20), shl(5, count)))
        }

        uint256[] memory point = new uint256[](4);
        point[0] = p0;
        point[1] = p1;
        point[2] = p2;
        point[3] = p3;

        unchecked {
            uint256 prevIdx;
            for (uint256 i = 0; i < count; ++i) {
                uint256 idx = indices[i];
                if (i != 0 && prevIdx >= idx) {
                    revert MerkleVerifier.IndicesNotStrictlyIncreasing(prevIdx, idx);
                }
                prevIdx = idx;

                uint256 rowStart = i * 16;
                bytes32 hash = MerkleVerifier.hashLeafExtension5Slice20(flatValues, rowStart, 16);
                rowEvals[i] = WhirVerifierUtils5.evaluateExtensionRowAsExt5(
                    flatValues, rowStart, 16, point
                );

                assembly ("memory-safe") {
                    mstore(add(add(frontierEntries, 0x20), shl(5, i)), or(hash, idx))
                }
            }
        }

        root = MerkleVerifier.computeRootFromPackedFrontier20(
            frontierEntries, count, depth, decommitments
        );
    }

    function _verifyFinalStirChallengesBlob16(
        bytes32 expectedRoot,
        uint256 numQueries,
        uint256 depth,
        uint256 foldedDomainGen,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 decommOffset,
        uint256 decommLen,
        uint256[] memory indices,
        uint256[] memory allRandomness,
        uint256 randomnessOffset,
        uint256 finalPolyOffset,
        uint256 finalPolyLength,
        uint256[] memory compactOffsets,
        bytes memory finalPolyMemory
    ) private pure returns (uint256 packedFinalPtr) {
        uint256 pointBase;
        assembly ("memory-safe") {
            pointBase := add(add(allRandomness, 0x20), shl(5, randomnessOffset))
        }
        uint256 p0;
        uint256 p1;
        uint256 p2;
        uint256 p3;
        assembly ("memory-safe") {
            p0 := mload(pointBase)
            p1 := mload(add(pointBase, 0x20))
            p2 := mload(add(pointBase, 0x40))
            p3 := mload(add(pointBase, 0x60))
        }

        bytes32 computedRoot;
        uint256[] memory rowEvals;
        (computedRoot, rowEvals) = _computeExtension5RootAndEvalsBlob16(
            indices,
            blob,
            valuesOffset,
            depth,
            decommOffset,
            decommLen,
            p0,
            p1,
            p2,
            p3,
            compactOffsets
        );

        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        unchecked {
            if (finalPolyLength == 64 && numQueries == 14) {
                packedFinalPtr = finalPolyMemory.length == 0
                    ? WhirVerifierUtils5._prepareHornerRadix64(blob, finalPolyOffset)
                    : WhirVerifierUtils5._prepareHornerRadix64Memory(finalPolyMemory);
                _fillSelVarsPow(indices, foldedDomainGen, numQueries);
                uint256 point0;
                uint256 point1;
                uint256 point2;
                uint256 point3;
                uint256 point4;
                uint256 point5;
                uint256 point6;
                uint256 point7;
                uint256 point8;
                uint256 point9;
                assembly ("memory-safe") {
                    let indicesBase := add(indices, 0x20)
                    point0 := mload(indicesBase)
                    point1 := mload(add(indicesBase, 0x20))
                    point2 := mload(add(indicesBase, 0x40))
                    point3 := mload(add(indicesBase, 0x60))
                    point4 := mload(add(indicesBase, 0x80))
                    point5 := mload(add(indicesBase, 0xa0))
                    point6 := mload(add(indicesBase, 0xc0))
                    point7 := mload(add(indicesBase, 0xe0))
                    point8 := mload(add(indicesBase, 0x100))
                    point9 := mload(add(indicesBase, 0x120))
                }

                uint256 rowEvalsBase;
                assembly ("memory-safe") {
                    rowEvalsBase := add(rowEvals, 0x20)
                }
                uint256 mismatchPlusOne = WhirVerifierUtils5._checkHornerRadix64(
                    packedFinalPtr, point0, point1, point2, point3, point4, rowEvalsBase, 0
                );
                if (mismatchPlusOne != 0) {
                    revert StirConstraintFailed(mismatchPlusOne - 1);
                }
                mismatchPlusOne = WhirVerifierUtils5._checkHornerRadix64(
                    packedFinalPtr, point5, point6, point7, point8, point9, rowEvalsBase, 5
                );
                if (mismatchPlusOne != 0) {
                    revert StirConstraintFailed(mismatchPlusOne + 4);
                }

                for (uint256 i = 10; i < 14; ++i) {
                    uint256 point = indices[i];
                    if (WhirVerifierUtils5._hornerRadix64(packedFinalPtr, point) != rowEvals[i]) {
                        revert StirConstraintFailed(i);
                    }
                }
                return packedFinalPtr;
            }

            for (uint256 i = 0; i < numQueries; ++i) {
                uint256 point = KoalaBear.pow(foldedDomainGen, indices[i]);
                if (
                    WhirVerifierUtils5.hornerBaseBlob(blob, finalPolyOffset, finalPolyLength, point)
                        != rowEvals[i]
                ) {
                    revert StirConstraintFailed(i);
                }
            }
        }
    }

    function _verifyStirAndCombineConstraintBlob16NativeFused(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        uint256 numQueries,
        uint256 depth,
        uint256 foldedDomainGen,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 decommOffset,
        uint256 decommLen,
        uint256[] memory indices,
        uint256[] memory allRandomness,
        uint256 randomnessOffset,
        uint8 expectedKind,
        uint256 oodAnswer,
        uint256[] memory compactOffsets
    )
        private
        pure
        returns (uint256 challenge, uint256 claimedContribution, uint256[] memory selVars)
    {
        uint256 pointBase;
        assembly ("memory-safe") {
            pointBase := add(add(allRandomness, 0x20), shl(5, randomnessOffset))
        }
        uint256 p0;
        uint256 p1;
        uint256 p2;
        uint256 p3;
        assembly ("memory-safe") {
            p0 := mload(pointBase)
            p1 := mload(add(pointBase, 0x20))
            p2 := mload(add(pointBase, 0x40))
            p3 := mload(add(pointBase, 0x60))
        }
        challenge = WhirVerifierUtils5.sampleExt5(challenger);
        selVars = indices;

        uint256[] memory frontierEntries;
        assembly ("memory-safe") {
            frontierEntries := mload(0x40)
            mstore(frontierEntries, numQueries)
            mstore(0x40, add(add(frontierEntries, 0x20), shl(5, numQueries)))
        }

        unchecked {
            uint256 rowOffset;
            uint256 frontierPtr;
            assembly ("memory-safe") {
                frontierPtr := add(add(frontierEntries, 0x20), shl(5, numQueries))
            }

            if (expectedKind == 0) {
                uint256 eqWeightsPtr = WhirVerifierUtils5._prepareBaseRadix64(
                    WhirVerifierUtils5._computeDim4EqWeights(p0, p1, p2, p3)
                );
                rowOffset = valuesOffset + numQueries * 64;
                uint256 nextHigher;
                for (uint256 i = numQueries; i > 0; --i) {
                    uint256 pos = i - 1;
                    uint256 idx = indices[pos];
                    if (i != numQueries && idx >= nextHigher) {
                        revert MerkleVerifier.IndicesNotStrictlyIncreasing(idx, nextHigher);
                    }
                    nextHigher = idx;
                    rowOffset -= 64;

                    (bytes32 hash, uint256 evalValue) = WhirVerifierUtils5._hashAndEvaluateBaseRow16Blob(
                        blob, rowOffset, eqWeightsPtr
                    );
                    claimedContribution = _hornerStep(claimedContribution, challenge, evalValue);

                    assembly ("memory-safe") {
                        frontierPtr := sub(frontierPtr, 0x20)
                        mstore(frontierPtr, or(hash, idx))
                    }
                }
            } else {
                uint256 eqWeightsPtr =
                    WhirVerifierUtils5._computeDim4EqWeightsUnpacked(p0, p1, p2, p3);
                rowOffset = valuesOffset + numQueries * 320;
                uint256 nextHigher;
                for (uint256 i = numQueries; i > 0; --i) {
                    uint256 pos = i - 1;
                    uint256 idx = indices[pos];
                    if (i != numQueries && idx >= nextHigher) {
                        revert MerkleVerifier.IndicesNotStrictlyIncreasing(idx, nextHigher);
                    }
                    nextHigher = idx;
                    rowOffset -= 320;

                    bytes32 hash;
                    uint256 evalValue;
                    if (compactOffsets.length != 0) {
                        (hash, evalValue) = WhirVerifierUtils5._hashAndEvaluateCompactRow16(
                            blob, compactOffsets[pos], eqWeightsPtr
                        );
                    } else {
                        (hash, evalValue) = WhirVerifierUtils5._hashAndEvaluateExtensionRow16Blob(
                            blob, rowOffset, eqWeightsPtr
                        );
                    }
                    claimedContribution = _hornerStep(claimedContribution, challenge, evalValue);

                    assembly ("memory-safe") {
                        frontierPtr := sub(frontierPtr, 0x20)
                        mstore(frontierPtr, or(hash, idx))
                    }
                }
            }
        }

        bytes32 computedRoot = MerkleVerifier.computeRootFromPackedFrontier20BlobTransport(
            frontierEntries, numQueries, depth, blob, decommOffset, decommLen
        );
        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        _fillSelVarsPow(selVars, foldedDomainGen, numQueries);
        claimedContribution = _hornerStep(claimedContribution, challenge, oodAnswer);
    }

    function _verifyRoundStirAndCombineConstraintBlob(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 decommLen,
        uint256 powWitnessOffset,
        uint256[] memory allRandomness,
        uint256 randomnessOffset,
        uint256 oodAnswer,
        uint256 powBits,
        uint256 domainSize,
        uint256 numQueries,
        uint256 depth,
        uint256 foldedDomainGen,
        uint8 expectedKind,
        uint256 valuesByteLen
    )
        internal
        pure
        returns (
            uint256 challenge,
            uint256 claimedContribution,
            uint256[] memory selVars,
            uint256 nextOffset
        )
    {
        return _verifyRoundStirAndCombineConstraintBlobTransport(
            challenger,
            expectedRoot,
            blob,
            valuesOffset,
            decommLen,
            powWitnessOffset,
            allRandomness,
            randomnessOffset,
            oodAnswer,
            powBits,
            domainSize,
            numQueries,
            depth,
            foldedDomainGen,
            expectedKind,
            valuesByteLen,
            false
        );
    }

    function _verifyRoundStirAndCombineConstraintBlobTransport(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 decommLen,
        uint256 powWitnessOffset,
        uint256[] memory allRandomness,
        uint256 randomnessOffset,
        uint256 oodAnswer,
        uint256 powBits,
        uint256 domainSize,
        uint256 numQueries,
        uint256 depth,
        uint256 foldedDomainGen,
        uint8 expectedKind,
        uint256 valuesByteLen,
        bool compact
    )
        internal
        pure
        returns (
            uint256 challenge,
            uint256 claimedContribution,
            uint256[] memory selVars,
            uint256 nextOffset
        )
    {
        _checkWitnessBaseLeBlob(challenger, powBits, blob, powWitnessOffset);
        challenger.sampleBase();

        uint256[] memory indices =
            WhirVerifierUtils5.sampleStirQueries(challenger, domainSize, 4, numQueries);
        if (indices.length != numQueries) {
            revert QueryBatchCountMismatch(numQueries, indices.length);
        }

        uint256 decommOffset = valuesOffset + valuesByteLen;
        uint256[] memory compactOffsets;
        if (compact && expectedKind != 0) {
            (compactOffsets, decommOffset) =
                QuinticTransportCodec.rowOffsets(blob, valuesOffset, numQueries, 16);
        }
        nextOffset = decommOffset + decommLen * 20;

        (challenge, claimedContribution, selVars) = _verifyStirAndCombineConstraintBlob16NativeFused(
            challenger,
            expectedRoot,
            numQueries,
            depth,
            foldedDomainGen,
            blob,
            valuesOffset,
            decommOffset,
            decommLen,
            indices,
            allRandomness,
            randomnessOffset,
            expectedKind,
            oodAnswer,
            compactOffsets
        );
    }

    function _verifyFinalStirChallengesBlobFixed(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 decommLen,
        uint256 powWitnessOffset,
        uint256[] memory allRandomness,
        uint256 randomnessOffset,
        uint256 finalPolyOffset
    ) internal pure returns (uint256 nextOffset) {
        bytes memory empty;
        return _verifyFinalStirChallengesBlobFixedTransport(
            challenger,
            expectedRoot,
            blob,
            valuesOffset,
            decommLen,
            powWitnessOffset,
            allRandomness,
            randomnessOffset,
            finalPolyOffset,
            false,
            empty
        );
    }

    function _verifyFinalStirChallengesBlobFixedTransport(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 decommLen,
        uint256 powWitnessOffset,
        uint256[] memory allRandomness,
        uint256 randomnessOffset,
        uint256 finalPolyOffset,
        bool compact,
        bytes memory finalPolyMemory
    ) internal pure returns (uint256 nextOffset) {
        (nextOffset,) = _verifyFinalStirChallengesBlobFixedTransportCached(
                challenger,
                expectedRoot,
                blob,
                valuesOffset,
                decommLen,
                powWitnessOffset,
                allRandomness,
                randomnessOffset,
                finalPolyOffset,
                compact,
                finalPolyMemory
            );
    }

    function _verifyFinalStirChallengesBlobFixedTransportCached(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        bytes calldata blob,
        uint256 valuesOffset,
        uint256 decommLen,
        uint256 powWitnessOffset,
        uint256[] memory allRandomness,
        uint256 randomnessOffset,
        uint256 finalPolyOffset,
        bool compact,
        bytes memory finalPolyMemory
    ) internal pure returns (uint256 nextOffset, uint256 packedFinalPtr) {
        _checkWitnessBaseLeBlob(challenger, 24, blob, powWitnessOffset);

        uint256[] memory indices =
            WhirVerifierUtils5.sampleStirQueries(challenger, 2_097_152, 4, 14);
        if (indices.length != 14) {
            revert QueryBatchCountMismatch(14, indices.length);
        }

        uint256 decommOffset = valuesOffset + 14 * 16 * 20;
        uint256[] memory compactOffsets;
        if (compact) {
            (compactOffsets, decommOffset) =
                QuinticTransportCodec.rowOffsets(blob, valuesOffset, 14, 16);
        }
        nextOffset = decommOffset + decommLen * 20;

        packedFinalPtr = _verifyFinalStirChallengesBlob16(
            expectedRoot,
            14,
            17,
            373_019_801,
            blob,
            valuesOffset,
            decommOffset,
            decommLen,
            indices,
            allRandomness,
            randomnessOffset,
            finalPolyOffset,
            64,
            compactOffsets,
            finalPolyMemory
        );
        return (nextOffset, packedFinalPtr);
    }

    function _parseCommitment(
        KeccakChallenger.State memory challenger,
        bytes32 root,
        uint256[] calldata oodAnswers,
        uint256 numVariables,
        uint256 oodSamples
    ) internal pure returns (ParsedCommitment memory parsed) {
        if (oodAnswers.length != oodSamples) {
            revert OodAnswerCountMismatch(oodSamples, oodAnswers.length);
        }

        challenger.observeHashU64Digest(root);

        parsed.root = root;
        parsed.oodStatement.numVariables = numVariables;
        parsed.oodStatement.flatPoints = new uint256[](oodSamples * numVariables);
        parsed.oodStatement.evaluations = new uint256[](oodSamples);

        unchecked {
            for (uint256 i = 0; i < oodSamples; ++i) {
                uint256 point = WhirVerifierUtils5.sampleExt5(challenger);
                WhirVerifierUtils5.expandFromUnivariateExtInto(
                    parsed.oodStatement.flatPoints, i * numVariables, point, numVariables
                );

                uint256 evalValue = oodAnswers[i];
                WhirVerifierUtils5.observeValidatedExt5(challenger, evalValue);
                parsed.oodStatement.evaluations[i] = evalValue;
            }
        }
    }

    function _parseFixedCommitment22x1Blob(
        KeccakChallenger.State memory challenger,
        bytes calldata blob,
        uint256 offset
    )
        internal
        pure
        returns (bytes32 root, uint256 oodPoint, uint256 oodEvaluation, uint256 nextOffset)
    {
        return _parseFixedCommitmentPointBlob(challenger, blob, offset);
    }

    function _parseFixedCommitment18x1Blob(
        KeccakChallenger.State memory challenger,
        bytes calldata blob,
        uint256 offset
    )
        internal
        pure
        returns (bytes32 root, uint256 oodPoint, uint256 oodEvaluation, uint256 nextOffset)
    {
        return _parseFixedCommitmentPointBlob(challenger, blob, offset);
    }

    function _parseFixedCommitment14x1Blob(
        KeccakChallenger.State memory challenger,
        bytes calldata blob,
        uint256 offset
    )
        internal
        pure
        returns (bytes32 root, uint256 oodPoint, uint256 oodEvaluation, uint256 nextOffset)
    {
        return _parseFixedCommitmentPointBlob(challenger, blob, offset);
    }

    function _parseFixedCommitment10x1Blob(
        KeccakChallenger.State memory challenger,
        bytes calldata blob,
        uint256 offset
    )
        internal
        pure
        returns (bytes32 root, uint256 oodPoint, uint256 oodEvaluation, uint256 nextOffset)
    {
        return _parseFixedCommitmentPointBlob(challenger, blob, offset);
    }

    function _parseFixedCommitmentPointBlob(
        KeccakChallenger.State memory challenger,
        bytes calldata blob,
        uint256 offset
    )
        private
        pure
        returns (bytes32 root, uint256 oodPoint, uint256 oodEvaluation, uint256 nextOffset)
    {
        (root, offset) = WhirBlobCodec5.readDigest20(blob, offset);
        challenger.observeHashU64Digest(root);
        oodPoint = WhirVerifierUtils5.sampleExt5(challenger);
        oodEvaluation = challenger.observeReadValidatedPackedExt5Le(blob, offset);
        nextOffset = offset + 20;
    }

    function _checkWitnessBaseLeBlob(
        KeccakChallenger.State memory challenger,
        uint256 bits,
        bytes calldata blob,
        uint256 offset
    ) internal pure {
        if (bits == 0) {
            return;
        }

        challenger.observeBytesCalldata(blob, offset, 4);
        if (challenger.sampleBitsUnchecked(bits) != 0) {
            revert InvalidPowWitness();
        }
    }

    function _verifySumcheck(
        WhirStructs.SumcheckData calldata sumcheck,
        KeccakChallenger.State memory challenger,
        uint256 claimedEval,
        uint256 expectedRounds,
        uint256 powBits,
        uint256[] memory allRandomness,
        uint256 randomnessCursor
    )
        internal
        pure
        returns (
            uint256 updatedClaimedEval,
            uint256[] memory foldingRandomness,
            uint256 updatedCursor
        )
    {
        uint256 expectedPolyEvals = expectedRounds * 2;
        if (sumcheck.polynomialEvals.length != expectedPolyEvals) {
            revert SumcheckPolynomialLengthMismatch(
                expectedPolyEvals, sumcheck.polynomialEvals.length
            );
        }

        uint256 expectedWitnesses = powBits > 0 ? expectedRounds : 0;
        if (sumcheck.powWitnesses.length != expectedWitnesses) {
            revert SumcheckPowWitnessLengthMismatch(expectedWitnesses, sumcheck.powWitnesses.length);
        }

        updatedClaimedEval = claimedEval;
        updatedCursor = randomnessCursor;
        foldingRandomness = new uint256[](expectedRounds);

        unchecked {
            for (uint256 i = 0; i < expectedRounds; ++i) {
                uint256 c0 = sumcheck.polynomialEvals[2 * i];
                uint256 c2 = sumcheck.polynomialEvals[2 * i + 1];

                challenger.observeValidatedPackedExt5Pair(c0, c2);

                if (powBits > 0) {
                    if (!challenger.checkWitness(powBits, sumcheck.powWitnesses[i])) {
                        revert InvalidPowWitness();
                    }
                }

                uint256 r = WhirVerifierUtils5.sampleExt5(challenger);
                foldingRandomness[i] = r;
                allRandomness[updatedCursor] = r;
                updatedCursor += 1;
                updatedClaimedEval = KoalaBearExt5.extrapolate_012(
                    c0, KoalaBearExt5.sub(updatedClaimedEval, c0), c2, r
                );
            }
        }
    }

    function _verifySumcheckBlob(
        bytes calldata blob,
        uint256 offset,
        KeccakChallenger.State memory challenger,
        uint256 claimedEval,
        uint256 expectedRounds,
        uint256 powBits,
        uint256[] memory allRandomness,
        uint256 randomnessCursor
    )
        internal
        pure
        returns (uint256 updatedClaimedEval, uint256 updatedCursor, uint256 nextOffset)
    {
        updatedClaimedEval = claimedEval;
        updatedCursor = randomnessCursor;
        nextOffset = offset;

        unchecked {
            for (uint256 i = 0; i < expectedRounds; ++i) {
                (uint256 c0, uint256 c2) =
                    challenger.observeReadValidatedPackedExt5LePair(blob, nextOffset);
                nextOffset += 40;

                if (powBits > 0) {
                    _checkWitnessBaseLeBlob(
                        challenger, powBits, blob, offset + expectedRounds * 40 + i * 4
                    );
                }

                uint256 r = WhirVerifierUtils5.sampleExt5(challenger);
                allRandomness[updatedCursor] = r;
                updatedCursor += 1;
                updatedClaimedEval =
                    KoalaBearExt5.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);
            }
        }

        if (powBits > 0) {
            nextOffset = offset + expectedRounds * 40 + expectedRounds * 4;
        }
    }

    function _verifySumcheckBlob6NoPow(
        bytes calldata blob,
        uint256 offset,
        KeccakChallenger.State memory challenger,
        uint256 claimedEval,
        uint256[] memory allRandomness,
        uint256 randomnessCursor
    )
        internal
        pure
        returns (uint256 updatedClaimedEval, uint256 updatedCursor, uint256 nextOffset)
    {
        updatedClaimedEval = claimedEval;
        updatedCursor = randomnessCursor;
        nextOffset = offset;

        (uint256 c0, uint256 c2) = challenger.observeReadValidatedPackedExt5LePair(blob, nextOffset);
        nextOffset += 40;
        uint256 r = WhirVerifierUtils5.sampleExt5(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            KoalaBearExt5.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt5LePair(blob, nextOffset);
        nextOffset += 40;
        r = WhirVerifierUtils5.sampleExt5(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            KoalaBearExt5.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt5LePair(blob, nextOffset);
        nextOffset += 40;
        r = WhirVerifierUtils5.sampleExt5(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            KoalaBearExt5.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt5LePair(blob, nextOffset);
        nextOffset += 40;
        r = WhirVerifierUtils5.sampleExt5(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            KoalaBearExt5.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt5LePair(blob, nextOffset);
        nextOffset += 40;
        r = WhirVerifierUtils5.sampleExt5(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            KoalaBearExt5.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);

        (c0, c2) = challenger.observeReadValidatedPackedExt5LePair(blob, nextOffset);
        nextOffset += 40;
        r = WhirVerifierUtils5.sampleExt5(challenger);
        allRandomness[updatedCursor] = r;
        updatedCursor += 1;
        updatedClaimedEval =
            KoalaBearExt5.extrapolate_012_from_sumcheck(c0, updatedClaimedEval, c2, r);
    }

    function _verifyStirAndCombineConstraint(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        uint256 powBits,
        uint256 numQueries,
        uint256,
        uint256 foldingFactor,
        uint256 domainSize,
        uint256 foldedDomainGen,
        WhirStructs.QueryBatchOpening calldata queryBatch,
        bool queryBatchPresent,
        uint256 powWitness,
        uint256[] memory foldingRandomness,
        uint8 expectedKind,
        uint256[] calldata oodAnswers
    )
        internal
        pure
        returns (uint256 challenge, uint256 claimedContribution, uint256[] memory selVars)
    {
        if (powBits > 0 && !challenger.checkWitness(powBits, powWitness)) {
            revert InvalidPowWitness();
        }

        challenger.sampleBase();

        if (!queryBatchPresent) {
            if (numQueries != 0) {
                revert FinalQueryBatchPresenceMismatch(true, false);
            }
            challenge = WhirVerifierUtils5.sampleExt5(challenger);
            unchecked {
                for (uint256 i = oodAnswers.length; i > 0; --i) {
                    claimedContribution =
                        _hornerStep(claimedContribution, challenge, oodAnswers[i - 1]);
                }
            }
            selVars = new uint256[](0);
            return (challenge, claimedContribution, selVars);
        }

        uint256[] memory indices = WhirVerifierUtils5.sampleStirQueries(
            challenger, domainSize, foldingFactor, numQueries
        );

        if (queryBatch.kind != expectedKind) {
            revert QueryBatchKindMismatch(expectedKind, queryBatch.kind);
        }
        if (queryBatch.numQueries != indices.length) {
            revert QueryBatchCountMismatch(indices.length, queryBatch.numQueries);
        }

        uint256 expectedRowLen = uint256(1) << foldingFactor;
        if (queryBatch.rowLen != expectedRowLen) {
            revert QueryBatchRowLengthMismatch(expectedRowLen, queryBatch.rowLen);
        }

        uint256 depth = WhirVerifierUtils5.log2Strict(domainSize >> foldingFactor);

        if (expectedRowLen == 16 && foldingFactor == 4) {
            bytes32 fastRoot;
            uint256[] memory rowEvals;
            if (expectedKind == 0) {
                (fastRoot, rowEvals) = _computeBaseRootAndEvals16(
                    indices,
                    queryBatch.values,
                    depth,
                    queryBatch.decommitments,
                    foldingRandomness[0],
                    foldingRandomness[1],
                    foldingRandomness[2],
                    foldingRandomness[3]
                );
            } else {
                (fastRoot, rowEvals) = _computeExtension5RootAndEvals16(
                    indices,
                    queryBatch.values,
                    depth,
                    queryBatch.decommitments,
                    foldingRandomness[0],
                    foldingRandomness[1],
                    foldingRandomness[2],
                    foldingRandomness[3]
                );
            }

            if (fastRoot != expectedRoot) {
                revert MerkleRootMismatch(expectedRoot, fastRoot);
            }

            challenge = WhirVerifierUtils5.sampleExt5(challenger);
            selVars = indices;

            unchecked {
                for (uint256 i = indices.length; i > 0; --i) {
                    uint256 idx = i - 1;
                    selVars[idx] = KoalaBear.pow(foldedDomainGen, indices[idx]);
                    claimedContribution = _hornerStep(claimedContribution, challenge, rowEvals[idx]);
                }

                for (uint256 i = oodAnswers.length; i > 0; --i) {
                    claimedContribution =
                        _hornerStep(claimedContribution, challenge, oodAnswers[i - 1]);
                }
            }
            return (challenge, claimedContribution, selVars);
        }

        bytes32 computedRoot = expectedKind == 0
            ? MerkleVerifier.computeRootFromFlatBaseRows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            )
            : MerkleVerifier.computeRootFromFlatExtension5Rows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            );

        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        challenge = WhirVerifierUtils5.sampleExt5(challenger);
        selVars = indices;

        unchecked {
            for (uint256 i = indices.length; i > 0; --i) {
                uint256 idx = i - 1;
                selVars[idx] = KoalaBear.pow(foldedDomainGen, indices[idx]);

                uint256 rowStart = idx * queryBatch.rowLen;
                uint256 evalValue = expectedKind == 0
                    ? WhirVerifierUtils5.evaluateBaseRowAsExt5(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    )
                    : WhirVerifierUtils5.evaluateExtensionRowAsExt5(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    );
                claimedContribution = _hornerStep(claimedContribution, challenge, evalValue);
            }

            for (uint256 i = oodAnswers.length; i > 0; --i) {
                claimedContribution = _hornerStep(claimedContribution, challenge, oodAnswers[i - 1]);
            }
        }
    }

    function _verifyFinalStirChallengesRaw(
        KeccakChallenger.State memory challenger,
        bytes32 expectedRoot,
        uint256 powBits,
        uint256 numQueries,
        uint256 foldingFactor,
        uint256 domainSize,
        uint256 foldedDomainGen,
        WhirStructs.QueryBatchOpening calldata queryBatch,
        bool queryBatchPresent,
        uint256 powWitness,
        uint256[] memory foldingRandomness,
        uint8 expectedKind,
        uint256[] calldata finalPoly
    ) internal pure {
        if (powBits > 0 && !challenger.checkWitness(powBits, powWitness)) {
            revert InvalidPowWitness();
        }

        if (!queryBatchPresent) {
            if (numQueries != 0) {
                revert FinalQueryBatchPresenceMismatch(true, false);
            }
            return;
        }

        uint256[] memory indices = WhirVerifierUtils5.sampleStirQueries(
            challenger, domainSize, foldingFactor, numQueries
        );

        if (queryBatch.kind != expectedKind) {
            revert QueryBatchKindMismatch(expectedKind, queryBatch.kind);
        }
        if (queryBatch.numQueries != indices.length) {
            revert QueryBatchCountMismatch(indices.length, queryBatch.numQueries);
        }

        uint256 expectedRowLen = uint256(1) << foldingFactor;
        if (queryBatch.rowLen != expectedRowLen) {
            revert QueryBatchRowLengthMismatch(expectedRowLen, queryBatch.rowLen);
        }

        uint256 depth = WhirVerifierUtils5.log2Strict(domainSize >> foldingFactor);

        if (expectedRowLen == 16 && foldingFactor == 4) {
            bytes32 fastRoot;
            uint256[] memory rowEvals;
            if (expectedKind == 0) {
                (fastRoot, rowEvals) = _computeBaseRootAndEvals16(
                    indices,
                    queryBatch.values,
                    depth,
                    queryBatch.decommitments,
                    foldingRandomness[0],
                    foldingRandomness[1],
                    foldingRandomness[2],
                    foldingRandomness[3]
                );
            } else {
                (fastRoot, rowEvals) = _computeExtension5RootAndEvals16(
                    indices,
                    queryBatch.values,
                    depth,
                    queryBatch.decommitments,
                    foldingRandomness[0],
                    foldingRandomness[1],
                    foldingRandomness[2],
                    foldingRandomness[3]
                );
            }

            if (fastRoot != expectedRoot) {
                revert MerkleRootMismatch(expectedRoot, fastRoot);
            }

            if (indices.length == 10) {
                uint256 idx0;
                uint256 idx1;
                uint256 idx2;
                uint256 idx3;
                uint256 idx4;
                uint256 idx5;
                uint256 idx6;
                uint256 idx7;
                uint256 idx8;
                uint256 idx9;
                assembly ("memory-safe") {
                    let indicesBase := add(indices, 0x20)
                    idx0 := mload(indicesBase)
                    idx1 := mload(add(indicesBase, 0x20))
                    idx2 := mload(add(indicesBase, 0x40))
                    idx3 := mload(add(indicesBase, 0x60))
                    idx4 := mload(add(indicesBase, 0x80))
                    idx5 := mload(add(indicesBase, 0xa0))
                    idx6 := mload(add(indicesBase, 0xc0))
                    idx7 := mload(add(indicesBase, 0xe0))
                    idx8 := mload(add(indicesBase, 0x100))
                    idx9 := mload(add(indicesBase, 0x120))
                }
                (
                    uint256 point0,
                    uint256 point1,
                    uint256 point2,
                    uint256 point3,
                    uint256 point4,
                    uint256 point5,
                    uint256 point6,
                    uint256 point7,
                    uint256 point8,
                    uint256 point9
                ) = _powBatch10(
                    foldedDomainGen, idx0, idx1, idx2, idx3, idx4, idx5, idx6, idx7, idx8, idx9
                );

                if (WhirVerifierUtils5.hornerBase(finalPoly, point0) != rowEvals[0]) {
                    revert StirConstraintFailed(0);
                }
                if (WhirVerifierUtils5.hornerBase(finalPoly, point1) != rowEvals[1]) {
                    revert StirConstraintFailed(1);
                }
                if (WhirVerifierUtils5.hornerBase(finalPoly, point2) != rowEvals[2]) {
                    revert StirConstraintFailed(2);
                }
                if (WhirVerifierUtils5.hornerBase(finalPoly, point3) != rowEvals[3]) {
                    revert StirConstraintFailed(3);
                }
                if (WhirVerifierUtils5.hornerBase(finalPoly, point4) != rowEvals[4]) {
                    revert StirConstraintFailed(4);
                }
                if (WhirVerifierUtils5.hornerBase(finalPoly, point5) != rowEvals[5]) {
                    revert StirConstraintFailed(5);
                }
                if (WhirVerifierUtils5.hornerBase(finalPoly, point6) != rowEvals[6]) {
                    revert StirConstraintFailed(6);
                }
                if (WhirVerifierUtils5.hornerBase(finalPoly, point7) != rowEvals[7]) {
                    revert StirConstraintFailed(7);
                }
                if (WhirVerifierUtils5.hornerBase(finalPoly, point8) != rowEvals[8]) {
                    revert StirConstraintFailed(8);
                }
                if (WhirVerifierUtils5.hornerBase(finalPoly, point9) != rowEvals[9]) {
                    revert StirConstraintFailed(9);
                }
                return;
            }

            unchecked {
                for (uint256 i = 0; i < indices.length; ++i) {
                    uint256 point = KoalaBear.pow(foldedDomainGen, indices[i]);
                    if (WhirVerifierUtils5.hornerBase(finalPoly, point) != rowEvals[i]) {
                        revert StirConstraintFailed(i);
                    }
                }
            }
            return;
        }

        bytes32 computedRoot = expectedKind == 0
            ? MerkleVerifier.computeRootFromFlatBaseRows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            )
            : MerkleVerifier.computeRootFromFlatExtension5Rows20(
                indices, queryBatch.values, queryBatch.rowLen, depth, queryBatch.decommitments
            );

        if (computedRoot != expectedRoot) {
            revert MerkleRootMismatch(expectedRoot, computedRoot);
        }

        unchecked {
            for (uint256 i = 0; i < indices.length; ++i) {
                uint256 point = KoalaBear.pow(foldedDomainGen, indices[i]);
                uint256 rowStart = i * queryBatch.rowLen;
                uint256 expectedEval = expectedKind == 0
                    ? WhirVerifierUtils5.evaluateBaseRowAsExt5(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    )
                    : WhirVerifierUtils5.evaluateExtensionRowAsExt5(
                        queryBatch.values, rowStart, queryBatch.rowLen, foldingRandomness
                    );
                if (WhirVerifierUtils5.hornerBase(finalPoly, point) != expectedEval) {
                    revert StirConstraintFailed(i);
                }
            }
        }
    }

    function _combineInitialConstraintEvalsSingleRaw(
        uint256 challenge,
        uint256 statementEval,
        uint256 oodEval
    ) internal pure returns (uint256 total) {
        total = _hornerStep(total, challenge, oodEval);
        total = _hornerStep(total, challenge, statementEval);
    }

    function _evaluateFixedEqTermsBlobRaw(
        bytes calldata blob,
        uint256 statementPointOffset,
        uint256 initialOodPoint,
        uint256 round0OodPoint,
        uint256 round1OodPoint,
        uint256 round2OodPoint,
        uint256[] memory fullPoint
    )
        internal
        pure
        returns (
            uint256 statementEq,
            uint256 initialEq,
            uint256 round0Eq,
            uint256 round1Eq,
            uint256 round2Eq
        )
    {
        uint256 initialCurrent = initialOodPoint;
        uint256 round0Current = round0OodPoint;
        uint256 round1Current = round1OodPoint;
        uint256 round2Current = round2OodPoint;
        uint256 pointBase;
        uint256[10] memory state;
        uint256[4] memory cache;
        assembly ("memory-safe") {
            pointBase := add(fullPoint, 0x20)
        }

        unchecked {
            {
                uint256 q;
                uint256 statementPointValue;
                assembly ("memory-safe") {
                    q := mload(add(pointBase, 672))
                    statementPointValue := and(
                        calldataload(add(add(blob.offset, statementPointOffset), 420)),
                        not(sub(shl(96, 1), 1))
                    )
                }
                _prepareEqTermForms(q, cache);
                _initialEqAt(_eqAccumulatorPtr(state, 0), statementPointValue, cache);
                _initialEqAt(_eqAccumulatorPtr(state, 1), initialCurrent, cache);
                _initialEqAt(_eqAccumulatorPtr(state, 2), round0Current, cache);
                _initialEqAt(_eqAccumulatorPtr(state, 3), round1Current, cache);
                _initialEqAt(_eqAccumulatorPtr(state, 4), round2Current, cache);
                initialCurrent = KoalaBearExt5.square(initialCurrent);
                round0Current = KoalaBearExt5.square(round0Current);
                round1Current = KoalaBearExt5.square(round1Current);
                round2Current = KoalaBearExt5.square(round2Current);
            }
            for (uint256 i = 21; i > 0; --i) {
                uint256 q;
                uint256 statementPointValue;
                assembly ("memory-safe") {
                    let idx := sub(i, 1)
                    q := mload(add(pointBase, shl(5, idx)))
                    statementPointValue := and(
                        calldataload(add(add(blob.offset, statementPointOffset), mul(20, idx))),
                        not(sub(shl(96, 1), 1))
                    )
                }

                _prepareEqTermForms(q, cache);
                _accEqAt(_eqAccumulatorPtr(state, 0), statementPointValue, cache);
                _accEqAt(_eqAccumulatorPtr(state, 1), initialCurrent, cache);
                initialCurrent = KoalaBearExt5.square(initialCurrent);

                if (i > 4) {
                    _accEqAt(_eqAccumulatorPtr(state, 2), round0Current, cache);
                    round0Current = KoalaBearExt5.square(round0Current);
                    if (i > 8) {
                        _accEqAt(_eqAccumulatorPtr(state, 3), round1Current, cache);
                        round1Current = KoalaBearExt5.square(round1Current);
                        if (i > 12) {
                            _accEqAt(_eqAccumulatorPtr(state, 4), round2Current, cache);
                            round2Current = KoalaBearExt5.square(round2Current);
                        }
                    }
                }
            }
        }
        statementEq = _packEqAccumulatorAt(_eqAccumulatorPtr(state, 0));
        initialEq = _packEqAccumulatorAt(_eqAccumulatorPtr(state, 1));
        round0Eq = _packEqAccumulatorAt(_eqAccumulatorPtr(state, 2));
        round1Eq = _packEqAccumulatorAt(_eqAccumulatorPtr(state, 3));
        round2Eq = _packEqAccumulatorAt(_eqAccumulatorPtr(state, 4));
    }

    function _evaluateInitialConstraintSingleCalldataRaw(
        uint256 challenge,
        uint256[] calldata statementPoint,
        uint256[] memory oodFlatPoints,
        uint256[] memory fullPoint
    ) internal pure returns (uint256 total) {
        uint256 numVariables = statementPoint.length;
        uint256 pointOffset = fullPoint.length - numVariables;

        total = _hornerStep(
            total, challenge, _eqPolyEvalAt(oodFlatPoints, 0, fullPoint, pointOffset, numVariables)
        );
        total = _hornerStep(
            total,
            challenge,
            _eqPolyEvalAtCalldata(statementPoint, fullPoint, pointOffset, numVariables)
        );
    }

    function _evaluateConstraintSelectRaw(
        uint256 challenge,
        uint256[] memory eqFlatPoints,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal pure returns (uint256 total) {
        uint256 numVariables = eqFlatPoints.length;
        uint256 pointOffset = fullPoint.length - numVariables;

        unchecked {
            for (uint256 i = selVars.length; i > 0; --i) {
                total = _hornerStep(
                    total,
                    challenge,
                    WhirVerifierUtils5.selectPolyEval(
                        selVars[i - 1], fullPoint, pointOffset, numVariables
                    )
                );
            }
        }

        total = _hornerStep(
            total, challenge, _eqPolyEvalAt(eqFlatPoints, 0, fullPoint, pointOffset, numVariables)
        );
    }

    function _evaluateConstraintCubicRaw18WithPrecomputedEq(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal pure returns (uint256) {
        return _evaluateConstraintCubicFused(challenge, eqEval, selVars, fullPoint, 18);
    }

    function _evaluateConstraintCubicRaw14WithPrecomputedEq(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal pure returns (uint256) {
        return _evaluateConstraintCubicFused(challenge, eqEval, selVars, fullPoint, 14);
    }

    function _evaluateConstraintCubicRaw10WithPrecomputedEq(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory fullPoint
    ) internal pure returns (uint256) {
        return _evaluateConstraintCubicFused(challenge, eqEval, selVars, fullPoint, 10);
    }

    /// @dev Native fixed schedule only: each select has 10, 14, or 18 coordinates
    /// ending at point[21]. Keep E=a4+a2*2^64+a0*2^128 and O=a3+a1*2^64
    /// throughout select multiplication and Horner accumulation. All coefficients
    /// are canonical. Even and odd convolutions have at most three terms per lane;
    /// the direct cross product has at most four, and 4*(p-1)^2 < 2^64.
    /// The E*E coefficient discarded above bit 255 is recovered as a0*b0.
    /// Reduction uses X^5=1-X^2; the p*2^40 bias prevents unsigned underflow.
    /// Biased reduction numerators, including a Horner weight, are below 2^72.
    function _evaluateConstraintCubicFused(
        uint256 challenge,
        uint256 eqEval,
        uint256[] memory selVars,
        uint256[] memory cache,
        uint256 dimensions
    ) private pure returns (uint256 out) {
        assembly ("memory-safe") {
            function forms(packed) -> even, odd {
                even := and(shr(96, packed), 0xffffffff00000000ffffffff00000000ffffffff)
                odd := and(shr(128, packed), 0xffffffff00000000ffffffff)
            }
            function cubic(ptr, x) -> lowOut, revOut, x2 {
                let M := 0x7f000001
                x2 := mulmod(x, x, M)
                let x3 := mulmod(x2, x, M)
                // The transposed cache stores (a,b,c,d) per coefficient.
                // The high lane is a+b*x+c*x^2+d*x^3; its four terms fit in 64 bits.
                let powers := or(or(x3, shl(64, x2)), or(shl(128, x), shl(192, 1)))
                lowOut := or(
                    or(
                        mod(shr(192, mul(mload(add(ptr, 128)), powers)), M),
                        shl(64, mod(shr(192, mul(mload(add(ptr, 64)), powers)), M))
                    ),
                    shl(128, mod(shr(192, mul(mload(ptr), powers)), M))
                )
                revOut := or(
                    mod(shr(192, mul(mload(add(ptr, 96)), powers)), M),
                    shl(64, mod(shr(192, mul(mload(add(ptr, 32)), powers)), M))
                )
            }
            function multiply(aLow, aRev, bLow, bRev) -> lowOut, revOut {
                let M := 0x7f000001
                let even := mul(aLow, bLow)
                let odd := mul(aRev, bRev)
                let cross := add(mul(aLow, bRev), mul(aRev, bLow))
                let c0 := mul(shr(128, aLow), shr(128, bLow))
                let laneMask := 0xffffffffffffffff
                let c1 := shr(192, cross)
                let c2 := add(shr(192, even), shr(128, odd))
                let c3 := and(shr(128, cross), laneMask)
                let c4 := add(and(shr(128, even), laneMask), and(shr(64, odd), laneMask))
                let c5 := and(shr(64, cross), laneMask)
                let c6 := add(and(shr(64, even), laneMask), and(odd, laneMask))
                let c7 := and(cross, laneMask)
                let c8 := and(even, laneMask)
                let bias := shl(40, M)
                let o0 := mod(add(add(c0, c5), sub(bias, c8)), M)
                let o1 := mod(add(c1, c6), M)
                let o2 := mod(add(add(add(c2, sub(bias, c5)), c7), c8), M)
                let o3 := mod(add(add(c3, sub(bias, c6)), c8), M)
                let o4 := mod(add(c4, sub(bias, c7)), M)
                lowOut := or(or(o4, shl(64, o2)), shl(128, o0))
                revOut := or(o3, shl(64, o1))
            }
            function multiplyAdd(aLow, aRev, bLow, bRev, wLow, wRev) -> lowOut, revOut {
                let M := 0x7f000001
                let even := mul(aLow, bLow)
                let odd := mul(aRev, bRev)
                let cross := add(mul(aLow, bRev), mul(aRev, bLow))
                let c0 := mul(shr(128, aLow), shr(128, bLow))
                let laneMask := 0xffffffffffffffff
                let c1 := shr(192, cross)
                let c2 := add(shr(192, even), shr(128, odd))
                let c3 := and(shr(128, cross), laneMask)
                let c4 := add(and(shr(128, even), laneMask), and(shr(64, odd), laneMask))
                let c5 := and(shr(64, cross), laneMask)
                let c6 := add(and(shr(64, even), laneMask), and(odd, laneMask))
                let c7 := and(cross, laneMask)
                let c8 := and(even, laneMask)
                let bias := shl(40, M)
                let o0 := mod(add(add(add(c0, c5), sub(bias, c8)), shr(128, wLow)), M)
                let o1 := mod(add(add(c1, c6), shr(64, wRev)), M)
                let o2 :=
                    mod(
                        add(
                            add(add(add(c2, sub(bias, c5)), c7), c8),
                            and(shr(64, wLow), 0xffffffff)
                        ),
                        M
                    )
                let o3 := mod(add(add(add(c3, sub(bias, c6)), c8), and(wRev, 0xffffffff)), M)
                let o4 := mod(add(add(c4, sub(bias, c7)), and(wLow, 0xffffffff)), M)
                lowOut := or(or(o4, shl(64, o2)), shl(128, o0))
                revOut := or(o3, shl(64, o1))
            }
            // Two extension products reduced together: A*B + C*D.
            // Each extracted convolution lane is < 2^64 before summing.
            // The coefficient sums fit in 66 bits; biased numerators < 2^73.
            function multiplyProducts(aLow, aRev, bLow, bRev, cLow, cRev, dLow, dRev) ->
                lowOut,
                revOut
            {
                let M := 0x7f000001
                let laneMask := 0xffffffffffffffff
                let evenA := mul(aLow, bLow)
                let oddA := mul(aRev, bRev)
                let crossA := add(mul(aLow, bRev), mul(aRev, bLow))
                let evenB := mul(cLow, dLow)
                let oddB := mul(cRev, dRev)
                let crossB := add(mul(cLow, dRev), mul(cRev, dLow))
                let bias := shl(41, M)
                let c0 :=
                    add(mul(shr(128, aLow), shr(128, bLow)), mul(shr(128, cLow), shr(128, dLow)))
                let c5 := add(and(shr(64, crossA), laneMask), and(shr(64, crossB), laneMask))
                let c8 := add(and(evenA, laneMask), and(evenB, laneMask))
                let o0 := mod(add(add(c0, c5), sub(bias, c8)), M)
                let c1 := add(shr(192, crossA), shr(192, crossB))
                let c6 :=
                    add(
                        add(and(shr(64, evenA), laneMask), and(oddA, laneMask)),
                        add(and(shr(64, evenB), laneMask), and(oddB, laneMask))
                    )
                let o1 := mod(add(c1, c6), M)
                let c2 :=
                    add(add(shr(192, evenA), shr(128, oddA)), add(shr(192, evenB), shr(128, oddB)))
                let c7 := add(and(crossA, laneMask), and(crossB, laneMask))
                let o2 := mod(add(add(add(c2, sub(bias, c5)), c7), c8), M)
                let c3 := add(and(shr(128, crossA), laneMask), and(shr(128, crossB), laneMask))
                let o3 := mod(add(add(c3, sub(bias, c6)), c8), M)
                let c4 :=
                    add(
                        add(and(shr(128, evenA), laneMask), and(shr(64, oddA), laneMask)),
                        add(and(shr(128, evenB), laneMask), and(shr(64, oddB), laneMask))
                    )
                let o4 := mod(add(c4, sub(bias, c7)), M)
                lowOut := or(or(o4, shl(64, o2)), shl(128, o0))
                revOut := or(o3, shl(64, o1))
            }
            let queryBase := add(selVars, 32)
            let queryPtr := add(queryBase, shl(5, mload(selVars)))
            let cacheEnd := add(cache, 1312)
            let lastPair := sub(cacheEnd, sub(mul(dimensions, 80), 160))
            let challengeLow, challengeRev := forms(challenge)
            let totalLow := 0
            let totalRev := 0
            for { } gt(queryPtr, queryBase) { } {
                queryPtr := sub(queryPtr, 32)
                // Common five pairs cover 10 coordinates. The only other callers
                // request 14 or 18, adding two or four pairs in the original order.
                let low, rev, x2 := cubic(cacheEnd, mload(queryPtr))
                {
                    let bLow, bRev, bX2 := cubic(sub(cacheEnd, 160), mulmod(x2, x2, 0x7f000001))
                    x2 := bX2
                    low, rev := multiply(low, rev, bLow, bRev)
                }
                {
                    let bLow, bRev, bX2 := cubic(sub(cacheEnd, 320), mulmod(x2, x2, 0x7f000001))
                    x2 := bX2
                    low, rev := multiply(low, rev, bLow, bRev)
                }
                {
                    let bLow, bRev, bX2 := cubic(sub(cacheEnd, 480), mulmod(x2, x2, 0x7f000001))
                    x2 := bX2
                    low, rev := multiply(low, rev, bLow, bRev)
                }
                if gt(dimensions, 10) {
                    {
                        let bLow, bRev, bX2 := cubic(sub(cacheEnd, 640), mulmod(x2, x2, 0x7f000001))
                        x2 := bX2
                        low, rev := multiply(low, rev, bLow, bRev)
                    }
                    {
                        let bLow, bRev, bX2 := cubic(sub(cacheEnd, 800), mulmod(x2, x2, 0x7f000001))
                        x2 := bX2
                        low, rev := multiply(low, rev, bLow, bRev)
                    }
                }
                if gt(dimensions, 14) {
                    {
                        let bLow, bRev, bX2 := cubic(sub(cacheEnd, 960), mulmod(x2, x2, 0x7f000001))
                        x2 := bX2
                        low, rev := multiply(low, rev, bLow, bRev)
                    }
                    {
                        let bLow, bRev, bX2 :=
                            cubic(sub(cacheEnd, 1120), mulmod(x2, x2, 0x7f000001))
                        x2 := bX2
                        low, rev := multiply(low, rev, bLow, bRev)
                    }
                }
                let bLow, bRev, unusedX2 := cubic(lastPair, mulmod(x2, x2, 0x7f000001))
                switch or(totalLow, totalRev)
                case 0 {
                    totalLow, totalRev := multiply(low, rev, bLow, bRev)
                }
                default {
                    totalLow, totalRev :=
                        multiplyProducts(
                        totalLow,
                        totalRev,
                        challengeLow,
                        challengeRev,
                        low,
                        rev,
                        bLow,
                        bRev
                    )
                }
            }
            let eqLow, eqRev := forms(eqEval)
            totalLow, totalRev :=
                multiplyAdd(totalLow, totalRev, challengeLow, challengeRev, eqLow, eqRev)
            out := or(shl(96, totalLow), shl(128, totalRev))
        }
    }

    function _eqPolyEvalAt(
        uint256[] memory point,
        uint256 pointStart,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) internal pure returns (uint256 acc) {
        acc = KoalaBearExt5.ONE;
        unchecked {
            for (uint256 i = 0; i < numVariables; ++i) {
                acc = KoalaBearExt5.mul(
                    acc, _eqTerm(point[pointStart + i], fullPoint[pointOffset + i])
                );
            }
        }
    }

    function _eqPolyEvalAtCalldata(
        uint256[] calldata point,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) internal pure returns (uint256 acc) {
        if (point.length != numVariables) {
            revert StatementPointArityMismatch(0, numVariables, point.length);
        }

        acc = KoalaBearExt5.ONE;
        unchecked {
            for (uint256 i = 0; i < numVariables; ++i) {
                acc = KoalaBearExt5.mul(acc, _eqTerm(point[i], fullPoint[pointOffset + i]));
            }
        }
    }

    function _evaluateFinalValue(
        uint256[] calldata finalPoly,
        uint256[] memory finalSumcheckRandomness
    ) internal pure returns (uint256) {
        if (finalSumcheckRandomness.length == 0) {
            return finalPoly[0];
        }

        uint256[] memory evals = new uint256[](finalPoly.length);
        unchecked {
            for (uint256 i = 0; i < finalPoly.length; ++i) {
                uint256 value = finalPoly[i];
                WhirVerifierUtils5.validatePackedExt5(value);
                evals[i] = value;
            }
        }
        return WhirVerifierUtils5.evaluateHypercubeMemory(evals, finalSumcheckRandomness);
    }

    function _evaluateFinalValueBlob(
        bytes calldata blob,
        uint256 offset,
        uint256 polyLen,
        uint256[] memory allRandomness,
        uint256 pointOffset,
        uint256 pointLen
    ) internal pure returns (uint256) {
        if (polyLen == 64 && pointLen == 6) {
            return WhirVerifierUtils5.evaluateFinalValueBlob64Dim6(
                blob, offset, allRandomness, pointOffset
            );
        }
        return WhirVerifierUtils5.evaluateExtensionRowAsExt5Blob(
            blob, offset, polyLen, allRandomness, pointOffset, pointLen
        );
    }

    function _selectCubicPolyEvalFixed(
        uint256 current,
        uint256[] memory cache,
        uint256 pointOffset,
        uint256 n
    ) internal pure returns (uint256) {
        if (n == 0) return uint256(1) << 224;
        unchecked {
            // `_prepareSelectCubicPairs` stores pairs (4,5), (6,7), ... at 160-byte strides.
            // Start from the pair ending at `pointOffset + n - 1` and walk backwards.
            uint256 pairIndex = (pointOffset + n - 6) / 2;
            uint256 ptr;
            assembly ("memory-safe") { ptr := add(add(cache, 32), mul(pairIndex, 160)) }
            (uint256 low, uint256 rev, uint256 next) = _evaluateSelectCubicPair(ptr, current);
            for (uint256 i = n / 2 - 1; i > 0; --i) {
                ptr -= 160;
                uint256 bLow;
                uint256 bRev;
                (bLow, bRev, next) = _evaluateSelectCubicPair(ptr, next);
                (low, rev) = _mulSelectCubicForms(low, rev, bLow, bRev);
            }
            return _packSelectCubicForms(low, rev);
        }
    }

    function _selectCubicPolyEvalFixedPair(
        uint256 a,
        uint256 b,
        uint256[] memory cache,
        uint256 offset,
        uint256 n
    ) internal pure returns (uint256, uint256) {
        return (
            _selectCubicPolyEvalFixed(a, cache, offset, n),
            _selectCubicPolyEvalFixed(b, cache, offset, n)
        );
    }

    function _hornerStep(uint256 total, uint256 challenge, uint256 weight)
        internal
        pure
        returns (uint256)
    {
        return KoalaBearPackedField.add(KoalaBearPackedField.mul(total, challenge), weight);
    }

    function _eqTerm(uint256 p, uint256 q) internal pure returns (uint256) {
        uint256 out;
        assembly ("memory-safe") {
            let M := 0x7f000001
            let mask := 0xffffffff

            let p0 := shr(224, p)
            let p1 := and(shr(192, p), mask)
            let p2 := and(shr(160, p), mask)
            let p3 := and(shr(128, p), mask)
            let p4 := and(shr(96, p), mask)

            let q0 := shr(224, q)
            let q1 := and(shr(192, q), mask)
            let q2 := and(shr(160, q), mask)
            let q3 := and(shr(128, q), mask)
            let q4 := and(shr(96, q), mask)

            let c0 := mul(p0, q0)
            let c1 := add(mul(p0, q1), mul(p1, q0))
            let c2 := add(add(mul(p0, q2), mul(p1, q1)), mul(p2, q0))
            let c3 := add(add(add(mul(p0, q3), mul(p1, q2)), mul(p2, q1)), mul(p3, q0))
            let c4 :=
                add(add(add(add(mul(p0, q4), mul(p1, q3)), mul(p2, q2)), mul(p3, q1)), mul(p4, q0))
            let c5 := add(add(add(mul(p1, q4), mul(p2, q3)), mul(p3, q2)), mul(p4, q1))
            let c6 := add(add(mul(p2, q4), mul(p3, q3)), mul(p4, q2))
            let c7 := add(mul(p3, q4), mul(p4, q3))
            let c8 := mul(p4, q4)
            let bias := shl(35, M)

            let m0 := add(add(c0, c5), sub(bias, c8))
            let m1 := add(c1, c6)
            let m2 := add(add(add(c2, sub(bias, c5)), c7), c8)
            let m3 := add(add(c3, sub(bias, c6)), c8)
            let m4 := add(c4, sub(bias, c7))

            let b := shl(2, M)
            let o0 := mod(add(add(add(1, shl(1, m0)), b), sub(0, add(p0, q0))), M)
            let o1 := mod(add(add(shl(1, m1), b), sub(0, add(p1, q1))), M)
            let o2 := mod(add(add(shl(1, m2), b), sub(0, add(p2, q2))), M)
            let o3 := mod(add(add(shl(1, m3), b), sub(0, add(p3, q3))), M)
            let o4 := mod(add(add(shl(1, m4), b), sub(0, add(p4, q4))), M)

            out := or(
                or(or(shl(224, o0), shl(192, o1)), or(shl(160, o2), shl(128, o3))),
                shl(96, o4)
            )
        }
        return out;
    }

    function _prepareSelectCubicPairs(uint256[] memory point)
        internal
        pure
        returns (uint256[] memory cache)
    {
        // All 45 words are assigned below before the cache can escape.
        assembly ("memory-safe") {
            cache := mload(0x40)
            mstore(cache, 45)
            mstore(0x40, add(cache, 1472))
        }
        for (uint256 i; i < 9; ++i) {
            uint256 r = point[2 * i + 5];
            uint256 s = point[2 * i + 4];
            uint256 d = KoalaBearExt5.mul(r, s);
            uint256 b = KoalaBearExt5.sub(r, d);
            uint256 cc = KoalaBearExt5.sub(s, d);
            uint256 a =
                KoalaBearExt5.add(KoalaBearExt5.sub(KoalaBearExt5.sub(uint256(1) << 224, r), s), d);
            uint256 ptr;
            assembly ("memory-safe") { ptr := add(add(cache, 32), mul(i, 160)) }
            assembly ("memory-safe") {
                // One radix-64 word per extension coefficient, ordered a,b,c,d.
                // Its product with (x^3,x^2,x,1) exposes the cubic value in lane 3.
                mstore(
                    add(ptr, 0),
                    or(
                        or(and(shr(224, a), 0xffffffff), shl(64, and(shr(224, b), 0xffffffff))),
                        or(
                            shl(128, and(shr(224, cc), 0xffffffff)),
                            shl(192, and(shr(224, d), 0xffffffff))
                        )
                    )
                )
                mstore(
                    add(ptr, 32),
                    or(
                        or(and(shr(192, a), 0xffffffff), shl(64, and(shr(192, b), 0xffffffff))),
                        or(
                            shl(128, and(shr(192, cc), 0xffffffff)),
                            shl(192, and(shr(192, d), 0xffffffff))
                        )
                    )
                )
                mstore(
                    add(ptr, 64),
                    or(
                        or(and(shr(160, a), 0xffffffff), shl(64, and(shr(160, b), 0xffffffff))),
                        or(
                            shl(128, and(shr(160, cc), 0xffffffff)),
                            shl(192, and(shr(160, d), 0xffffffff))
                        )
                    )
                )
                mstore(
                    add(ptr, 96),
                    or(
                        or(and(shr(128, a), 0xffffffff), shl(64, and(shr(128, b), 0xffffffff))),
                        or(
                            shl(128, and(shr(128, cc), 0xffffffff)),
                            shl(192, and(shr(128, d), 0xffffffff))
                        )
                    )
                )
                mstore(
                    add(ptr, 128),
                    or(
                        or(and(shr(96, a), 0xffffffff), shl(64, and(shr(96, b), 0xffffffff))),
                        or(
                            shl(128, and(shr(96, cc), 0xffffffff)),
                            shl(192, and(shr(96, d), 0xffffffff))
                        )
                    )
                )
            }
        }
    }

    function _mulSelectCubicForms(uint256 aLow, uint256 aRev, uint256 bLow, uint256 bRev)
        private
        pure
        returns (uint256 lowOut, uint256 revOut)
    {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let c4 :=
                add(
                    shr(192, mul(aLow, or(shr(64, bLow), shl(192, and(bRev, 0xffffffff))))),
                    mul(and(aRev, 0xffffffff), and(bLow, 0xffffffff))
                )
            let low := mul(aLow, bLow)
            let high := mul(aRev, bRev)
            let c0 := and(low, 0xffffffffffffffff)
            let c1 := and(shr(64, low), 0xffffffffffffffff)
            let c2 := and(shr(128, low), 0xffffffffffffffff)
            let c3 := shr(192, low)
            let c5 := shr(192, high)
            let c6 := and(shr(128, high), 0xffffffffffffffff)
            let c7 := and(shr(64, high), 0xffffffffffffffff)
            let c8 := and(high, 0xffffffffffffffff)
            let bias := shl(40, M)
            let o0 := mod(add(add(c0, c5), sub(bias, c8)), M)
            let o1 := mod(add(c1, c6), M)
            let o2 := mod(add(add(add(c2, sub(bias, c5)), c7), c8), M)
            let o3 := mod(add(add(c3, sub(bias, c6)), c8), M)
            let o4 := mod(add(c4, sub(bias, c7)), M)
            lowOut := or(or(o0, shl(64, o1)), or(shl(128, o2), shl(192, o3)))
            revOut := or(or(o4, shl(64, o3)), or(shl(128, o2), shl(192, o1)))
        }
    }

    function _packSelectCubicForms(uint256 low, uint256 rev) private pure returns (uint256 out) {
        assembly ("memory-safe") {
            out := or(
                or(
                    or(shl(224, and(low, 0xffffffff)), shl(192, and(shr(64, low), 0xffffffff))),
                    or(shl(160, and(shr(128, low), 0xffffffff)), shl(128, shr(192, low)))
                ),
                shl(96, and(rev, 0xffffffff))
            )
        }
    }

    function _evaluateSelectCubicPair(uint256 ptr, uint256 x)
        private
        pure
        returns (uint256 lowOut, uint256 revOut, uint256 next)
    {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let x2 := mulmod(x, x, M)
            let x3 := mulmod(x2, x, M)
            next := mulmod(x2, x2, M)
            let powers := or(or(x3, shl(64, x2)), or(shl(128, x), shl(192, 1)))
            let o0 := mod(shr(192, mul(mload(add(ptr, 0)), powers)), M)
            let o1 := mod(shr(192, mul(mload(add(ptr, 32)), powers)), M)
            let o2 := mod(shr(192, mul(mload(add(ptr, 64)), powers)), M)
            let o3 := mod(shr(192, mul(mload(add(ptr, 96)), powers)), M)
            let o4 := mod(shr(192, mul(mload(add(ptr, 128)), powers)), M)
            lowOut := or(or(o0, shl(64, o1)), or(shl(128, o2), shl(192, o3)))
            revOut := or(or(o4, shl(64, o3)), or(shl(128, o2), shl(192, o1)))
        }
    }

    /// @dev EQ accumulators keep E=a4+a2*2^64+a0*2^128 and O=a3+a1*2^64.
    /// Both inputs are first shifted by -1/2 in their constant coefficient.
    /// Thus eq(a,q)=2*(a-1/2)*(q-1/2)+1/2. The cache stores E(q),O(q),E(q)+O(q).
    /// Karatsuba lane/carry bounds are identical to KoalaBearExt5._mulPacked.
    /// After doubling and the p*2^40 bias, every numerator is below 2^73.
    function _eqTermForms(uint256 acc, uint256[4] memory cache)
        internal
        pure
        returns (uint256 outLow, uint256 outRev)
    {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let ae :=
                or(
                    and(shr(96, acc), 0xffffffff00000000ffffffff),
                    shl(128, mod(add(shr(224, acc), shr(1, M)), M))
                )
            let ao := and(shr(128, acc), 0xffffffff00000000ffffffff)
            let be := mload(cache)
            let bo := mload(add(cache, 32))
            let even := mul(ae, be)
            let odd := mul(ao, bo)
            let cross := sub(sub(mul(add(ae, ao), mload(add(cache, 64))), even), odd)
            let c0 := mul(shr(128, ae), shr(128, be))
            let laneMask := 0xffffffffffffffff
            let c1 := shr(192, cross)
            let c2 := add(shr(192, even), shr(128, odd))
            let c3 := and(shr(128, cross), laneMask)
            let c4 := add(and(shr(128, even), laneMask), and(shr(64, odd), laneMask))
            let c5 := and(shr(64, cross), laneMask)
            let c6 := add(and(shr(64, even), laneMask), and(odd, laneMask))
            let c7 := and(cross, laneMask)
            let c8 := and(even, laneMask)
            let bias := shl(40, M)
            let o0 := mod(add(shl(1, add(add(c0, c5), sub(bias, c8))), add(shr(1, M), 1)), M)
            let o1 := mod(shl(1, add(c1, c6)), M)
            let o2 := mod(shl(1, add(add(add(c2, sub(bias, c5)), c7), c8)), M)
            let o3 := mod(shl(1, add(add(c3, sub(bias, c6)), c8)), M)
            let o4 := mod(shl(1, add(c4, sub(bias, c7))), M)
            outLow := or(or(o4, shl(64, o2)), shl(128, o0))
            outRev := or(o3, shl(64, o1))
        }
    }

    /// @dev Multiply two canonical even/odd accumulators without repacking transport words.
    function _mulEqTermForms(uint256 ae, uint256 ao, uint256 be, uint256 bo)
        internal
        pure
        returns (uint256 outLow, uint256 outRev)
    {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let even := mul(ae, be)
            let odd := mul(ao, bo)
            let cross := sub(sub(mul(add(ae, ao), add(be, bo)), even), odd)
            let c0 := mul(shr(128, ae), shr(128, be))
            let laneMask := 0xffffffffffffffff
            let c1 := shr(192, cross)
            let c2 := add(shr(192, even), shr(128, odd))
            let c3 := and(shr(128, cross), laneMask)
            let c4 := add(and(shr(128, even), laneMask), and(shr(64, odd), laneMask))
            let c5 := and(shr(64, cross), laneMask)
            let c6 := add(and(shr(64, even), laneMask), and(odd, laneMask))
            let c7 := and(cross, laneMask)
            let c8 := and(even, laneMask)
            let bias := shl(40, M)
            let o0 := mod(add(add(c0, c5), sub(bias, c8)), M)
            let o1 := mod(add(c1, c6), M)
            let o2 := mod(add(add(add(c2, sub(bias, c5)), c7), c8), M)
            let o3 := mod(add(add(c3, sub(bias, c6)), c8), M)
            let o4 := mod(add(c4, sub(bias, c7)), M)
            outLow := or(or(o4, shl(64, o2)), shl(128, o0))
            outRev := or(o3, shl(64, o1))
        }
    }

    function _eqAccumulatorPtr(uint256[10] memory state, uint256 index)
        private
        pure
        returns (uint256 ptr)
    {
        assembly ("memory-safe") { ptr := add(state, shl(6, index)) }
    }

    function _initialEqAt(uint256 ptr, uint256 a, uint256[4] memory cache) private pure {
        (uint256 low, uint256 rev) = _eqTermForms(a, cache);
        assembly ("memory-safe") {
            mstore(ptr, low)
            mstore(add(ptr, 32), rev)
        }
    }

    function _accEqAt(uint256 ptr, uint256 a, uint256[4] memory cache) private pure {
        (uint256 low, uint256 rev) = _eqTermForms(a, cache);
        uint256 aLow;
        uint256 aRev;
        assembly ("memory-safe") {
            aLow := mload(ptr)
            aRev := mload(add(ptr, 32))
        }
        (low, rev) = _mulEqTermForms(aLow, aRev, low, rev);
        assembly ("memory-safe") {
            mstore(ptr, low)
            mstore(add(ptr, 32), rev)
        }
    }

    function _packEqAccumulatorAt(uint256 ptr) private pure returns (uint256) {
        uint256 low;
        uint256 rev;
        assembly ("memory-safe") {
            low := mload(ptr)
            rev := mload(add(ptr, 32))
        }
        return _packEqTermForms(low, rev);
    }

    function _packEqTermForms(uint256 even, uint256 odd) private pure returns (uint256 out) {
        assembly ("memory-safe") {
            out := or(shl(96, even), shl(128, odd))
        }
    }

    function _prepareEqTermForms(uint256 q, uint256[4] memory cache) internal pure {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let even :=
                or(
                    and(shr(96, q), 0xffffffff00000000ffffffff),
                    shl(128, mod(add(shr(224, q), shr(1, M)), M))
                )
            let odd := and(shr(128, q), 0xffffffff00000000ffffffff)
            mstore(cache, even)
            mstore(add(cache, 32), odd)
            mstore(add(cache, 64), add(even, odd))
        }
    }
}
