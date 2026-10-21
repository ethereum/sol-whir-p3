// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { QuinticTransportCodec } from "./QuinticTransportCodec.sol";

import { SmallQuerySort } from "./SmallQuerySort.sol";

import { KoalaBear } from "../../field/KoalaBear.sol";
import { KoalaBearExt5 } from "../../field/KoalaBearExt5.sol";
import { KeccakChallenger } from "../../transcript/KeccakChallenger.sol";

library WhirVerifierUtils5 {
    using KeccakChallenger for KeccakChallenger.State;

    error BaseFieldElementOutOfRange(uint256 value);
    error PackedExtensionElementOutOfRange(uint256 value);
    error NotPowerOfTwo(uint256 value);

    function observeValidatedExt5(KeccakChallenger.State memory challenger, uint256 packed)
        internal
        pure
    {
        challenger.observeValidatedPackedExt5(packed);
    }

    function sampleExt5(KeccakChallenger.State memory challenger) internal pure returns (uint256) {
        unchecked {
            return (challenger.sampleBase() << 224) | (challenger.sampleBase() << 192)
                | (challenger.sampleBase() << 160) | (challenger.sampleBase() << 128)
                | (challenger.sampleBase() << 96);
        }
    }

    function _computeDim4EqWeights(uint256 p0, uint256 p1, uint256 p2, uint256 p3)
        internal
        pure
        returns (uint256 weightsPtr)
    {
        uint256 a11 = KoalaBearExt5.mul(p0, p1);
        uint256 a10 = KoalaBearExt5.sub(p0, a11);
        uint256 a01 = KoalaBearExt5.sub(p1, a11);
        uint256 a00 = KoalaBearExt5.sub(KoalaBearExt5.sub(KoalaBearExt5.ONE, p0), a01);
        uint256 b001 = KoalaBearExt5.mul(a00, p2);
        uint256 b000 = KoalaBearExt5.sub(a00, b001);
        uint256 b011 = KoalaBearExt5.mul(a01, p2);
        uint256 b010 = KoalaBearExt5.sub(a01, b011);
        uint256 b101 = KoalaBearExt5.mul(a10, p2);
        uint256 b100 = KoalaBearExt5.sub(a10, b101);
        uint256 b111 = KoalaBearExt5.mul(a11, p2);
        uint256 b110 = KoalaBearExt5.sub(a11, b111);

        assembly ("memory-safe") {
            weightsPtr := mload(0x40)
            mstore(0x40, add(weightsPtr, 0x200))
        }

        _storeDim4EqWeightPair(weightsPtr, 0x000, b000, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x040, b001, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x080, b010, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x0c0, b011, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x100, b100, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x140, b101, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x180, b110, p3);
        _storeDim4EqWeightPair(weightsPtr, 0x1c0, b111, p3);
    }

    function _storeDim4EqWeightPair(uint256 weightsPtr, uint256 offset, uint256 prefix, uint256 p3)
        private
        pure
    {
        uint256 w1 = KoalaBearExt5.mul(prefix, p3);
        uint256 w0 = KoalaBearExt5.sub(prefix, w1);
        assembly ("memory-safe") {
            mstore(add(weightsPtr, offset), w0)
            mstore(add(add(weightsPtr, offset), 0x20), w1)
        }
    }

    function _computeDim4EqWeightsUnpacked(uint256 p0, uint256 p1, uint256 p2, uint256 p3)
        internal
        pure
        returns (uint256)
    {
        return _prepareRowWeightsLazy(_computeDim4EqWeights(p0, p1, p2, p3));
    }

    function validateBase(uint256 value) internal pure {
        if (value >= KoalaBear.MODULUS) {
            revert BaseFieldElementOutOfRange(value);
        }
    }

    function validatePackedExt5Calldata(uint256[] calldata values) internal pure {
        unchecked {
            for (uint256 i = 0; i < values.length; ++i) {
                validatePackedExt5(values[i]);
            }
        }
    }

    function validatePackedExt5(uint256 packed) internal pure {
        KoalaBearExt5.validatePacked(packed);
    }

    function expandFromUnivariateExtInto(
        uint256[] memory dst,
        uint256 dstOffset,
        uint256 value,
        uint256 numVariables
    ) internal pure {
        uint256 current = value;

        unchecked {
            for (uint256 i = numVariables; i > 0; --i) {
                dst[dstOffset + i - 1] = current;
                current = KoalaBearExt5.square(current);
            }
        }
    }

    function sampleStirQueries(
        KeccakChallenger.State memory challenger,
        uint256 domainSize,
        uint256 foldingFactor,
        uint256 numQueries
    ) internal pure returns (uint256[] memory queries) {
        uint256 foldedDomainSize = domainSize >> foldingFactor;
        uint256 domainBits = log2Strict(foldedDomainSize);
        return sampleStirQueriesPow2(challenger, domainBits, numQueries);
    }

    function sampleStirQueriesPow2(
        KeccakChallenger.State memory challenger,
        uint256 domainBits,
        uint256 numQueries
    ) internal pure returns (uint256[] memory queries) {
        uint256 maxBitsPerCall = 20;
        uint256 totalBitsNeeded = numQueries * domainBits;

        queries = new uint256[](numQueries);

        if (totalBitsNeeded <= maxBitsPerCall) {
            uint256 allBits = challenger.sampleBitsUnchecked(totalBitsNeeded);
            uint256 mask = domainBits == 0 ? 0 : ((uint256(1) << domainBits) - 1);
            unchecked {
                for (uint256 i = 0; i < numQueries; ++i) {
                    queries[i] = allBits & mask;
                    allBits >>= domainBits;
                }
            }
        } else {
            uint256 queriesPerBatch = maxBitsPerCall / domainBits;
            if (queriesPerBatch >= 2) {
                uint256 remaining = numQueries;
                uint256 cursor = 0;
                uint256 mask = (uint256(1) << domainBits) - 1;
                while (remaining > 0) {
                    uint256 batchSize = remaining < queriesPerBatch ? remaining : queriesPerBatch;
                    uint256 batchBits = batchSize * domainBits;
                    uint256 allBits = challenger.sampleBitsUnchecked(batchBits);

                    unchecked {
                        for (uint256 i = 0; i < batchSize; ++i) {
                            queries[cursor] = allBits & mask;
                            allBits >>= domainBits;
                            cursor += 1;
                        }
                    }

                    remaining -= batchSize;
                }
            } else {
                unchecked {
                    for (uint256 i = 0; i < numQueries; ++i) {
                        queries[i] = challenger.sampleBitsUnchecked(domainBits);
                    }
                }
            }
        }

        if (queries.length > 1) {
            SmallQuerySort.sortUnique(queries);
        }
    }

    function log2Strict(uint256 value) internal pure returns (uint256 exponent) {
        if (value == 0 || (value & (value - 1)) != 0) {
            revert NotPowerOfTwo(value);
        }

        while (value > 1) {
            value >>= 1;
            exponent += 1;
        }
    }

    function hornerBase(uint256[] calldata coeffs, uint256 var_)
        internal
        pure
        returns (uint256 acc)
    {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff
            let src := add(coeffs.offset, shl(5, coeffs.length))
            let end := coeffs.offset

            for { } gt(src, end) { } {
                src := sub(src, 0x20)
                let packed := calldataload(src)

                let a0 := shr(224, acc)
                let a1 := and(shr(192, acc), mask)
                let a2 := and(shr(160, acc), mask)
                let a3 := and(shr(128, acc), mask)
                let a4 := and(shr(96, acc), mask)

                let c0 := shr(224, packed)
                let c1 := and(shr(192, packed), mask)
                let c2 := and(shr(160, packed), mask)
                let c3 := and(shr(128, packed), mask)
                let c4 := and(shr(96, packed), mask)

                let r0 := mod(add(mulmod(a0, var_, modulus), c0), modulus)
                let r1 := mod(add(mulmod(a1, var_, modulus), c1), modulus)
                let r2 := mod(add(mulmod(a2, var_, modulus), c2), modulus)
                let r3 := mod(add(mulmod(a3, var_, modulus), c3), modulus)
                let r4 := mod(add(mulmod(a4, var_, modulus), c4), modulus)

                acc := or(
                    or(or(shl(224, r0), shl(192, r1)), or(shl(160, r2), shl(128, r3))),
                    shl(96, r4)
                )
            }
        }
    }

    function hornerBaseBlob(bytes calldata blob, uint256 offset, uint256 coeffCount, uint256 var_)
        internal
        pure
        returns (uint256 acc)
    {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff
            let low96Mask := sub(shl(96, 1), 1)

            let src := add(add(blob.offset, offset), mul(20, coeffCount))
            let end := add(blob.offset, offset)

            for { } gt(src, end) { } {
                src := sub(src, 20)
                let packed := and(calldataload(src), not(low96Mask))

                let a0 := shr(224, acc)
                let a1 := and(shr(192, acc), mask)
                let a2 := and(shr(160, acc), mask)
                let a3 := and(shr(128, acc), mask)
                let a4 := and(shr(96, acc), mask)

                let c0 := shr(224, packed)
                let c1 := and(shr(192, packed), mask)
                let c2 := and(shr(160, packed), mask)
                let c3 := and(shr(128, packed), mask)
                let c4 := and(shr(96, packed), mask)

                let r0 := mod(add(mulmod(a0, var_, modulus), c0), modulus)
                let r1 := mod(add(mulmod(a1, var_, modulus), c1), modulus)
                let r2 := mod(add(mulmod(a2, var_, modulus), c2), modulus)
                let r3 := mod(add(mulmod(a3, var_, modulus), c3), modulus)
                let r4 := mod(add(mulmod(a4, var_, modulus), c4), modulus)

                acc := or(
                    or(or(shl(224, r0), shl(192, r1)), or(shl(160, r2), shl(128, r3))),
                    shl(96, r4)
                )
            }
        }
    }

    function hornerBaseBlob64Pairwise(bytes calldata blob, uint256 offset, uint256 var_)
        internal
        pure
        returns (uint256 acc)
    {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff
            let low96Mask := sub(shl(96, 1), 1)
            let var2 := mulmod(var_, var_, modulus)

            let src := add(add(blob.offset, offset), 1280)
            let end := add(blob.offset, offset)

            for { } gt(src, end) { } {
                src := sub(src, 20)
                let hi := and(calldataload(src), not(low96Mask))
                src := sub(src, 20)
                let lo := and(calldataload(src), not(low96Mask))

                let a0 := shr(224, acc)
                let a1 := and(shr(192, acc), mask)
                let a2 := and(shr(160, acc), mask)
                let a3 := and(shr(128, acc), mask)
                let a4 := and(shr(96, acc), mask)

                let h0 := shr(224, hi)
                let h1 := and(shr(192, hi), mask)
                let h2 := and(shr(160, hi), mask)
                let h3 := and(shr(128, hi), mask)
                let h4 := and(shr(96, hi), mask)

                let l0 := shr(224, lo)
                let l1 := and(shr(192, lo), mask)
                let l2 := and(shr(160, lo), mask)
                let l3 := and(shr(128, lo), mask)
                let l4 := and(shr(96, lo), mask)

                let r0 :=
                    mod(add(add(mulmod(a0, var2, modulus), mulmod(h0, var_, modulus)), l0), modulus)
                let r1 :=
                    mod(add(add(mulmod(a1, var2, modulus), mulmod(h1, var_, modulus)), l1), modulus)
                let r2 :=
                    mod(add(add(mulmod(a2, var2, modulus), mulmod(h2, var_, modulus)), l2), modulus)
                let r3 :=
                    mod(add(add(mulmod(a3, var2, modulus), mulmod(h3, var_, modulus)), l3), modulus)
                let r4 :=
                    mod(add(add(mulmod(a4, var2, modulus), mulmod(h4, var_, modulus)), l4), modulus)

                acc := or(
                    or(or(shl(224, r0), shl(192, r1)), or(shl(160, r2), shl(128, r3))),
                    shl(96, r4)
                )
            }
        }
    }

    function checkHornerBaseBlob64Matches5Raw(
        bytes calldata blob,
        uint256 offset,
        uint256 v0,
        uint256 v1,
        uint256 v2,
        uint256 v3,
        uint256 v4,
        uint256 rowEvalsBase,
        uint256 rowOffset
    ) internal pure returns (uint256 mismatchPlusOne) {
        uint256 expected0;
        uint256 expected1;
        uint256 expected2;
        uint256 expected3;
        uint256 expected4;
        assembly ("memory-safe") {
            let evalBase := add(rowEvalsBase, shl(5, rowOffset))
            expected0 := mload(evalBase)
            expected1 := mload(add(evalBase, 0x20))
            expected2 := mload(add(evalBase, 0x40))
            expected3 := mload(add(evalBase, 0x60))
            expected4 := mload(add(evalBase, 0x80))
        }
        if (hornerBaseBlob64Pairwise(blob, offset, v0) != expected0) return 1;
        if (hornerBaseBlob64Pairwise(blob, offset, v1) != expected1) return 2;
        if (hornerBaseBlob64Pairwise(blob, offset, v2) != expected2) return 3;
        if (hornerBaseBlob64Pairwise(blob, offset, v3) != expected3) return 4;
        if (hornerBaseBlob64Pairwise(blob, offset, v4) != expected4) return 5;
    }

    function _prepareHornerRadix64(bytes calldata blob, uint256 offset)
        internal
        pure
        returns (uint256 ptr)
    {
        uint256 source;
        assembly ("memory-safe") { source := add(blob.offset, offset) }
        return _prepareHornerRadix64Source(source, false);
    }

    function _prepareHornerRadix64Memory(bytes memory polynomial)
        internal
        pure
        returns (uint256 ptr)
    {
        uint256 source;
        assembly ("memory-safe") { source := add(polynomial, 32) }
        return _prepareHornerRadix64Source(source, true);
    }

    function _prepareHornerRadix64Source(uint256 src, bool inMemory)
        private
        pure
        returns (uint256 ptr)
    {
        assembly ("memory-safe") {
            function loadWord(source, memoryInput) -> word {
                switch memoryInput
                case 0 { word := calldataload(source) }
                default { word := mload(source) }
            }
            ptr := mload(0x40)
            let first := loadWord(src, inMemory)
            let mask := 0x00000000ffffffffffffffffffffffffffffffff000000000000000000000000
            let common := iszero(and(xor(first, loadWord(add(src, 20), inMemory)), mask))
            if common {
                let different := 0
                for { let i := 0 } lt(i, 64) { i := add(i, 8) } {
                    let source := add(src, mul(i, 20))
                    let word := 0
                    {
                        let value := loadWord(add(source, 0), inMemory)
                        different := or(different, xor(first, value))
                        word := or(word, shl(224, shr(224, value)))
                    }
                    {
                        let value := loadWord(add(source, 20), inMemory)
                        different := or(different, xor(first, value))
                        word := or(word, shl(192, shr(224, value)))
                    }
                    {
                        let value := loadWord(add(source, 40), inMemory)
                        different := or(different, xor(first, value))
                        word := or(word, shl(160, shr(224, value)))
                    }
                    {
                        let value := loadWord(add(source, 60), inMemory)
                        different := or(different, xor(first, value))
                        word := or(word, shl(128, shr(224, value)))
                    }
                    {
                        let value := loadWord(add(source, 80), inMemory)
                        different := or(different, xor(first, value))
                        word := or(word, shl(96, shr(224, value)))
                    }
                    {
                        let value := loadWord(add(source, 100), inMemory)
                        different := or(different, xor(first, value))
                        word := or(word, shl(64, shr(224, value)))
                    }
                    {
                        let value := loadWord(add(source, 120), inMemory)
                        different := or(different, xor(first, value))
                        word := or(word, shl(32, shr(224, value)))
                    }
                    {
                        let value := loadWord(add(source, 140), inMemory)
                        different := or(different, xor(first, value))
                        word := or(word, shl(0, shr(224, value)))
                    }
                    mstore(add(add(ptr, 64), mul(i, 4)), word)
                }
                common := iszero(and(different, mask))
            }
            mstore(ptr, common)
            mstore(add(ptr, 32), and(first, mask))
            switch common
            case 1 { mstore(0x40, add(ptr, 320)) }
            default {
                mstore(0x40, add(ptr, 4160))
                for { let i := 0 } lt(i, 64) { i := add(i, 1) } {
                    let w := loadWord(add(src, mul(i, 20)), inMemory)
                    let dst := add(add(ptr, 64), shl(6, i))
                    mstore(
                        dst,
                        or(
                            or(shr(224, w), shl(64, and(shr(192, w), 0xffffffff))),
                            or(
                                shl(128, and(shr(160, w), 0xffffffff)),
                                shl(192, and(shr(128, w), 0xffffffff))
                            )
                        )
                    )
                    mstore(add(dst, 32), and(shr(96, w), 0xffffffff))
                }
            }
        }
    }

    /// @dev Each 64-bit lane is bounded by
    /// `4 * (p - 1)^2 + (p - 1) = 18159639599595388928 < 2^64`.
    function _hornerRadix64(uint256 ptr, uint256 x) internal pure returns (uint256 out) {
        bool commonColumns;
        uint256 common;
        assembly ("memory-safe") {
            commonColumns := mload(ptr)
            common := mload(add(ptr, 32))
        }
        if (commonColumns) {
            uint256 scalar;
            uint256 geometric;
            assembly ("memory-safe") {
                let M := 0x7f000001
                let x2 := mulmod(x, x, M)
                let x3 := mulmod(x2, x, M)
                let x4 := mulmod(x2, x2, M)
                let base := add(ptr, 64)
                for { let src := add(ptr, 320) } gt(src, base) { } {
                    src := sub(src, 16)
                    let word := mload(src)
                    scalar := mod(
                        add(
                            add(
                                add(
                                    add(mul(scalar, x4), mul(and(shr(128, word), 0xffffffff), x3)),
                                    mul(and(shr(160, word), 0xffffffff), x2)
                                ),
                                mul(and(shr(192, word), 0xffffffff), x)
                            ),
                            shr(224, word)
                        ),
                        M
                    )
                }
                geometric := mulmod(add(1, x), add(1, x2), M)
                geometric := mulmod(geometric, add(1, x4), M)
                let power := mulmod(x4, x4, M)
                geometric := mulmod(geometric, add(1, power), M)
                power := mulmod(power, power, M)
                geometric := mulmod(geometric, add(1, power), M)
                power := mulmod(power, power, M)
                geometric := mulmod(geometric, add(1, power), M)
            }
            return KoalaBearExt5.add(
                KoalaBearExt5.fromBase(scalar), KoalaBearExt5.mulBase(common, geometric)
            );
        }
        assembly ("memory-safe") {
            ptr := add(ptr, 64)
            let M := 0x7f000001
            let mask := 0xffffffffffffffff
            let a := 0
            let b := 0
            let x2 := mulmod(x, x, M)
            let x3 := mulmod(x2, x, M)
            let x4 := mulmod(x2, x2, M)
            for { let src := add(ptr, 4096) } gt(src, ptr) { } {
                src := sub(src, 256)
                let v :=
                    add(
                        add(
                            add(
                                add(mul(a, x4), mul(mload(add(src, 192)), x3)),
                                mul(mload(add(src, 128)), x2)
                            ),
                            mul(mload(add(src, 64)), x)
                        ),
                        mload(src)
                    )
                b := mod(
                    add(
                        add(
                            add(
                                add(mul(b, x4), mul(mload(add(src, 224)), x3)),
                                mul(mload(add(src, 160)), x2)
                            ),
                            mul(mload(add(src, 96)), x)
                        ),
                        mload(add(src, 32))
                    ),
                    M
                )
                a := or(
                    or(mod(and(v, mask), M), shl(64, mod(and(shr(64, v), mask), M))),
                    or(shl(128, mod(and(shr(128, v), mask), M)), shl(192, mod(shr(192, v), M)))
                )
            }
            out := or(
                or(
                    or(shl(224, and(a, 0xffffffff)), shl(192, and(shr(64, a), 0xffffffff))),
                    or(shl(160, and(shr(128, a), 0xffffffff)), shl(128, shr(192, a)))
                ),
                shl(96, b)
            )
        }
    }

    function _checkHornerRadix64(
        uint256 ptr,
        uint256 v0,
        uint256 v1,
        uint256 v2,
        uint256 v3,
        uint256 v4,
        uint256 rowEvalsBase,
        uint256 rowOffset
    ) internal pure returns (uint256 mismatchPlusOne) {
        uint256 expected0;
        uint256 expected1;
        uint256 expected2;
        uint256 expected3;
        uint256 expected4;
        assembly ("memory-safe") {
            let evalBase := add(rowEvalsBase, shl(5, rowOffset))
            expected0 := mload(evalBase)
            expected1 := mload(add(evalBase, 0x20))
            expected2 := mload(add(evalBase, 0x40))
            expected3 := mload(add(evalBase, 0x60))
            expected4 := mload(add(evalBase, 0x80))
        }
        if (_hornerRadix64(ptr, v0) != expected0) return 1;
        if (_hornerRadix64(ptr, v1) != expected1) return 2;
        if (_hornerRadix64(ptr, v2) != expected2) return 3;
        if (_hornerRadix64(ptr, v3) != expected3) return 4;
        if (_hornerRadix64(ptr, v4) != expected4) return 5;
    }

    function selectPolyEval(
        uint256 var_,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 numVariables
    ) internal pure returns (uint256 acc) {
        acc = KoalaBearExt5.ONE;
        uint256[] memory expanded = new uint256[](numVariables);
        uint256 current = var_;

        unchecked {
            for (uint256 i = numVariables; i > 0; --i) {
                expanded[i - 1] = current;
                current = KoalaBear.mul(current, current);
            }
            for (uint256 i = 0; i < numVariables; ++i) {
                uint256 value = expanded[i];
                uint256 scalar = value == 0 ? KoalaBear.MODULUS - 1 : value - 1;
                uint256 term = KoalaBearExt5.add(
                    KoalaBearExt5.ONE, KoalaBearExt5.mulBase(fullPoint[pointOffset + i], scalar)
                );
                acc = KoalaBearExt5.mul(acc, term);
            }
        }
    }

    function evaluateBaseRowAsExt5(
        uint256[] calldata flatValues,
        uint256 start,
        uint256 rowLen,
        uint256[] memory point
    ) internal pure returns (uint256) {
        if (point.length == 4 && rowLen == 16) {
            return _evaluateBaseRowDim4(flatValues, start, point);
        }

        uint256[] memory evals = new uint256[](rowLen);
        unchecked {
            for (uint256 i = 0; i < rowLen; ++i) {
                uint256 value = flatValues[start + i];
                validateBase(value);
                evals[i] = KoalaBearExt5.fromBase(value);
            }
        }
        if (point.length == 0) {
            return evals[0];
        }
        return evaluateHypercubeMemory(evals, point);
    }

    function evaluateExtensionRowAsExt5(
        uint256[] calldata flatValues,
        uint256 start,
        uint256 rowLen,
        uint256[] memory point
    ) internal pure returns (uint256) {
        if (point.length == 4 && rowLen == 16) {
            return _evaluateExtensionRowDim4(flatValues, start, point);
        }

        uint256[] memory evals = new uint256[](rowLen);
        unchecked {
            for (uint256 i = 0; i < rowLen; ++i) {
                uint256 value = flatValues[start + i];
                validatePackedExt5(value);
                evals[i] = value;
            }
        }
        if (point.length == 0) {
            return evals[0];
        }
        return evaluateHypercubeMemory(evals, point);
    }

    function evaluateExtensionRowAsExt5Blob(
        bytes calldata blob,
        uint256 offset,
        uint256 rowLen,
        uint256[] memory fullPoint,
        uint256 pointOffset,
        uint256 pointLen
    ) internal pure returns (uint256) {
        if (pointLen == 4 && rowLen == 16) {
            return _evaluateExtensionRowDim4BlobWindow(blob, offset, fullPoint, pointOffset);
        }

        uint256[] memory evals = new uint256[](rowLen);
        uint256[] memory point = _slicePoint(fullPoint, pointOffset, pointLen);

        unchecked {
            for (uint256 i = 0; i < rowLen; ++i) {
                uint256 value;
                assembly ("memory-safe") {
                    value := and(
                        calldataload(add(add(blob.offset, offset), mul(20, i))),
                        not(sub(shl(96, 1), 1))
                    )
                }
                validatePackedExt5(value);
                evals[i] = value;
            }
        }

        if (point.length == 0) {
            return evals[0];
        }
        return evaluateHypercubeMemory(evals, point);
    }

    function evaluateFinalValueBlob64Dim6(
        bytes calldata blob,
        uint256 offset,
        uint256[] memory fullPoint,
        uint256 pointOffset
    ) internal pure returns (uint256) {
        uint256 weights = _computeDim4EqWeightsUnpacked(
            fullPoint[pointOffset + 2],
            fullPoint[pointOffset + 3],
            fullPoint[pointOffset + 4],
            fullPoint[pointOffset + 5]
        );
        uint256 a = _evaluateFinalRow16(blob, offset, weights);
        uint256 b = _evaluateFinalRow16(blob, offset + 320, weights);
        uint256 d = _evaluateFinalRow16(blob, offset + 640, weights);
        uint256 e = _evaluateFinalRow16(blob, offset + 960, weights);
        uint256 p1 = fullPoint[pointOffset + 1];
        uint256 left = KoalaBearExt5.add(a, KoalaBearExt5.mul(KoalaBearExt5.sub(b, a), p1));
        uint256 right = KoalaBearExt5.add(d, KoalaBearExt5.mul(KoalaBearExt5.sub(e, d), p1));
        return KoalaBearExt5.add(
            left, KoalaBearExt5.mul(KoalaBearExt5.sub(right, left), fullPoint[pointOffset])
        );
    }

    /// @dev Only a live cache from _prepareHornerRadix64[Memory] may be passed.
    /// The producer checks all 64 common-column tuples. Noncommon input returns
    /// false so the caller uses the general final-value evaluator.
    function evaluateFinalValueHornerCache64Dim6(
        uint256 ptr,
        uint256[] memory fullPoint,
        uint256 pointOffset
    ) internal pure returns (bool reused, uint256 value) {
        uint256 common;
        assembly ("memory-safe") {
            reused := mload(ptr)
            common := mload(add(ptr, 32))
        }
        if (!reused) return (false, 0);
        // These exact equality weights sum to ONE: every split replaces w with
        // (w - w*r, w*r). No assumption is made about arbitrary caller weights.
        uint256 weights = _prepareBaseRadix64(
            _computeDim4EqWeights(
                fullPoint[pointOffset + 2],
                fullPoint[pointOffset + 3],
                fullPoint[pointOffset + 4],
                fullPoint[pointOffset + 5]
            )
        );
        // One loop call site avoids cloning the full scalar kernel four times.
        uint256[4] memory scalarRows;
        unchecked {
            for (uint256 i = 0; i < 4; ++i) {
                scalarRows[i] = _evaluateCachedScalarRow16(ptr + 64 + 64 * i, weights);
            }
        }
        uint256 a = scalarRows[0];
        uint256 b = scalarRows[1];
        uint256 d = scalarRows[2];
        uint256 e = scalarRows[3];
        uint256 p1 = fullPoint[pointOffset + 1];
        uint256 left = KoalaBearExt5.add(a, KoalaBearExt5.mul(KoalaBearExt5.sub(b, a), p1));
        uint256 right = KoalaBearExt5.add(d, KoalaBearExt5.mul(KoalaBearExt5.sub(e, d), p1));
        // The two remaining multilinear splits also preserve the common term.
        value = KoalaBearExt5.add(
            common,
            KoalaBearExt5.add(
                left, KoalaBearExt5.mul(KoalaBearExt5.sub(right, left), fullPoint[pointOffset])
            )
        );
    }

    function _evaluateCachedScalarRow16(uint256 ptr, uint256 weights)
        private
        pure
        returns (uint256)
    {
        uint256 w0;
        uint256 w1;
        assembly ("memory-safe") {
            w0 := mload(ptr)
            w1 := mload(add(ptr, 32))
        }
        return _dotBaseRadix64(weights, w0, w1);
    }

    function evaluateFinalValueMemory64Dim6(
        bytes memory blob,
        uint256 offset,
        uint256[] memory fullPoint,
        uint256 pointOffset
    ) internal pure returns (uint256) {
        uint256 weights = _computeDim4EqWeightsUnpacked(
            fullPoint[pointOffset + 2],
            fullPoint[pointOffset + 3],
            fullPoint[pointOffset + 4],
            fullPoint[pointOffset + 5]
        );
        uint256 a = _evaluateFinalRow16Memory(blob, offset, weights);
        uint256 b = _evaluateFinalRow16Memory(blob, offset + 320, weights);
        uint256 d = _evaluateFinalRow16Memory(blob, offset + 640, weights);
        uint256 e = _evaluateFinalRow16Memory(blob, offset + 960, weights);
        uint256 p1 = fullPoint[pointOffset + 1];
        uint256 left = KoalaBearExt5.add(a, KoalaBearExt5.mul(KoalaBearExt5.sub(b, a), p1));
        uint256 right = KoalaBearExt5.add(d, KoalaBearExt5.mul(KoalaBearExt5.sub(e, d), p1));
        return KoalaBearExt5.add(
            left, KoalaBearExt5.mul(KoalaBearExt5.sub(right, left), fullPoint[pointOffset])
        );
    }

    function evaluateHypercubeMemory(uint256[] memory evals, uint256[] memory point)
        internal
        pure
        returns (uint256)
    {
        return KoalaBearExt5.evaluate_hypercube(evals, point);
    }

    function _slicePoint(uint256[] memory fullPoint, uint256 pointOffset, uint256 pointLen)
        private
        pure
        returns (uint256[] memory point)
    {
        point = new uint256[](pointLen);
        unchecked {
            for (uint256 i = 0; i < pointLen; ++i) {
                point[i] = fullPoint[pointOffset + i];
            }
        }
    }

    function _evaluateBaseRowDim4(
        uint256[] calldata flatValues,
        uint256 start,
        uint256[] memory point
    ) private pure returns (uint256) {
        uint256 src;
        assembly ("memory-safe") {
            src := add(flatValues.offset, shl(5, start))
        }

        uint256 v0;
        uint256 v1;
        uint256 v2;
        uint256 v3;
        uint256 v4;
        uint256 v5;
        uint256 v6;
        uint256 v7;
        uint256 v8;
        uint256 v9;
        uint256 v10;
        uint256 v11;
        uint256 v12;
        uint256 v13;
        uint256 v14;
        uint256 v15;
        assembly ("memory-safe") {
            v0 := calldataload(src)
            v1 := calldataload(add(src, 0x20))
            v2 := calldataload(add(src, 0x40))
            v3 := calldataload(add(src, 0x60))
            v4 := calldataload(add(src, 0x80))
            v5 := calldataload(add(src, 0xa0))
            v6 := calldataload(add(src, 0xc0))
            v7 := calldataload(add(src, 0xe0))
            v8 := calldataload(add(src, 0x100))
            v9 := calldataload(add(src, 0x120))
            v10 := calldataload(add(src, 0x140))
            v11 := calldataload(add(src, 0x160))
            v12 := calldataload(add(src, 0x180))
            v13 := calldataload(add(src, 0x1a0))
            v14 := calldataload(add(src, 0x1c0))
            v15 := calldataload(add(src, 0x1e0))
        }

        validateBase(v0);
        validateBase(v1);
        validateBase(v2);
        validateBase(v3);
        validateBase(v4);
        validateBase(v5);
        validateBase(v6);
        validateBase(v7);
        validateBase(v8);
        validateBase(v9);
        validateBase(v10);
        validateBase(v11);
        validateBase(v12);
        validateBase(v13);
        validateBase(v14);
        validateBase(v15);

        (uint256 r00, uint256 r01, uint256 r02, uint256 r03, uint256 r04) = _unpackCoeffs(point[0]);
        (uint256 r10, uint256 r11, uint256 r12, uint256 r13, uint256 r14) = _unpackCoeffs(point[1]);
        (uint256 r20, uint256 r21, uint256 r22, uint256 r23, uint256 r24) = _unpackCoeffs(point[2]);
        (uint256 r30, uint256 r31, uint256 r32, uint256 r33, uint256 r34) = _unpackCoeffs(point[3]);

        uint256 l0 = _foldOnceBase(v0, v8, r00, r01, r02, r03, r04);
        uint256 l1 = _foldOnceBase(v1, v9, r00, r01, r02, r03, r04);
        uint256 l2 = _foldOnceBase(v2, v10, r00, r01, r02, r03, r04);
        uint256 l3 = _foldOnceBase(v3, v11, r00, r01, r02, r03, r04);
        uint256 l4 = _foldOnceBase(v4, v12, r00, r01, r02, r03, r04);
        uint256 l5 = _foldOnceBase(v5, v13, r00, r01, r02, r03, r04);
        uint256 l6 = _foldOnceBase(v6, v14, r00, r01, r02, r03, r04);
        uint256 l7 = _foldOnceBase(v7, v15, r00, r01, r02, r03, r04);
        uint256 m0 = _foldOnceWithCoeffs(l0, l4, r10, r11, r12, r13, r14);
        uint256 m1 = _foldOnceWithCoeffs(l1, l5, r10, r11, r12, r13, r14);
        uint256 m2 = _foldOnceWithCoeffs(l2, l6, r10, r11, r12, r13, r14);
        uint256 m3 = _foldOnceWithCoeffs(l3, l7, r10, r11, r12, r13, r14);
        uint256 n0 = _foldOnceWithCoeffs(m0, m2, r20, r21, r22, r23, r24);
        uint256 n1 = _foldOnceWithCoeffs(m1, m3, r20, r21, r22, r23, r24);
        return _foldOnceWithCoeffs(n0, n1, r30, r31, r32, r33, r34);
    }

    function _hashAndEvaluateBaseRowDim4PackedPoints(
        uint256[] calldata flatValues,
        uint256 start,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) internal pure returns (bytes32 digest, uint256 evalValue) {
        uint256 src;
        assembly ("memory-safe") {
            src := add(flatValues.offset, shl(5, start))
        }

        uint256 v0;
        uint256 v1;
        uint256 v2;
        uint256 v3;
        uint256 v4;
        uint256 v5;
        uint256 v6;
        uint256 v7;
        uint256 v8;
        uint256 v9;
        uint256 v10;
        uint256 v11;
        uint256 v12;
        uint256 v13;
        uint256 v14;
        uint256 v15;
        assembly ("memory-safe") {
            v0 := calldataload(src)
            v1 := calldataload(add(src, 0x20))
            v2 := calldataload(add(src, 0x40))
            v3 := calldataload(add(src, 0x60))
            v4 := calldataload(add(src, 0x80))
            v5 := calldataload(add(src, 0xa0))
            v6 := calldataload(add(src, 0xc0))
            v7 := calldataload(add(src, 0xe0))
            v8 := calldataload(add(src, 0x100))
            v9 := calldataload(add(src, 0x120))
            v10 := calldataload(add(src, 0x140))
            v11 := calldataload(add(src, 0x160))
            v12 := calldataload(add(src, 0x180))
            v13 := calldataload(add(src, 0x1a0))
            v14 := calldataload(add(src, 0x1c0))
            v15 := calldataload(add(src, 0x1e0))
        }

        validateBase(v0);
        validateBase(v1);
        validateBase(v2);
        validateBase(v3);
        validateBase(v4);
        validateBase(v5);
        validateBase(v6);
        validateBase(v7);
        validateBase(v8);
        validateBase(v9);
        validateBase(v10);
        validateBase(v11);
        validateBase(v12);
        validateBase(v13);
        validateBase(v14);
        validateBase(v15);

        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore8(ptr, 0x00)
            mstore(add(ptr, 0x01), shl(224, v0))
            mstore(add(ptr, 0x05), shl(224, v1))
            mstore(add(ptr, 0x09), shl(224, v2))
            mstore(add(ptr, 0x0d), shl(224, v3))
            mstore(add(ptr, 0x11), shl(224, v4))
            mstore(add(ptr, 0x15), shl(224, v5))
            mstore(add(ptr, 0x19), shl(224, v6))
            mstore(add(ptr, 0x1d), shl(224, v7))
            mstore(add(ptr, 0x21), shl(224, v8))
            mstore(add(ptr, 0x25), shl(224, v9))
            mstore(add(ptr, 0x29), shl(224, v10))
            mstore(add(ptr, 0x2d), shl(224, v11))
            mstore(add(ptr, 0x31), shl(224, v12))
            mstore(add(ptr, 0x35), shl(224, v13))
            mstore(add(ptr, 0x39), shl(224, v14))
            mstore(add(ptr, 0x3d), shl(224, v15))
            digest := and(keccak256(ptr, 65), not(sub(shl(96, 1), 1)))
        }

        (uint256 r00, uint256 r01, uint256 r02, uint256 r03, uint256 r04) = _unpackCoeffs(p0);
        (uint256 r10, uint256 r11, uint256 r12, uint256 r13, uint256 r14) = _unpackCoeffs(p1);
        (uint256 r20, uint256 r21, uint256 r22, uint256 r23, uint256 r24) = _unpackCoeffs(p2);
        (uint256 r30, uint256 r31, uint256 r32, uint256 r33, uint256 r34) = _unpackCoeffs(p3);

        uint256 l0 = _foldOnceBase(v0, v8, r00, r01, r02, r03, r04);
        uint256 l1 = _foldOnceBase(v1, v9, r00, r01, r02, r03, r04);
        uint256 l2 = _foldOnceBase(v2, v10, r00, r01, r02, r03, r04);
        uint256 l3 = _foldOnceBase(v3, v11, r00, r01, r02, r03, r04);
        uint256 l4 = _foldOnceBase(v4, v12, r00, r01, r02, r03, r04);
        uint256 l5 = _foldOnceBase(v5, v13, r00, r01, r02, r03, r04);
        uint256 l6 = _foldOnceBase(v6, v14, r00, r01, r02, r03, r04);
        uint256 l7 = _foldOnceBase(v7, v15, r00, r01, r02, r03, r04);
        uint256 m0 = _foldOnceWithCoeffs(l0, l4, r10, r11, r12, r13, r14);
        uint256 m1 = _foldOnceWithCoeffs(l1, l5, r10, r11, r12, r13, r14);
        uint256 m2 = _foldOnceWithCoeffs(l2, l6, r10, r11, r12, r13, r14);
        uint256 m3 = _foldOnceWithCoeffs(l3, l7, r10, r11, r12, r13, r14);
        uint256 n0 = _foldOnceWithCoeffs(m0, m2, r20, r21, r22, r23, r24);
        uint256 n1 = _foldOnceWithCoeffs(m1, m3, r20, r21, r22, r23, r24);
        evalValue = _foldOnceWithCoeffs(n0, n1, r30, r31, r32, r33, r34);
    }

    function _evaluateExtensionRowDim4(
        uint256[] calldata flatValues,
        uint256 start,
        uint256[] memory point
    ) private pure returns (uint256) {
        uint256 src;
        assembly ("memory-safe") {
            src := add(flatValues.offset, shl(5, start))
        }

        uint256 v0;
        uint256 v1;
        uint256 v2;
        uint256 v3;
        uint256 v4;
        uint256 v5;
        uint256 v6;
        uint256 v7;
        uint256 v8;
        uint256 v9;
        uint256 v10;
        uint256 v11;
        uint256 v12;
        uint256 v13;
        uint256 v14;
        uint256 v15;
        assembly ("memory-safe") {
            v0 := calldataload(src)
            v1 := calldataload(add(src, 0x20))
            v2 := calldataload(add(src, 0x40))
            v3 := calldataload(add(src, 0x60))
            v4 := calldataload(add(src, 0x80))
            v5 := calldataload(add(src, 0xa0))
            v6 := calldataload(add(src, 0xc0))
            v7 := calldataload(add(src, 0xe0))
            v8 := calldataload(add(src, 0x100))
            v9 := calldataload(add(src, 0x120))
            v10 := calldataload(add(src, 0x140))
            v11 := calldataload(add(src, 0x160))
            v12 := calldataload(add(src, 0x180))
            v13 := calldataload(add(src, 0x1a0))
            v14 := calldataload(add(src, 0x1c0))
            v15 := calldataload(add(src, 0x1e0))

            function validateExt5(packed) {
                let highBitMask :=
                    0x8000000080000000800000008000000080000000000000000000000000000000
                let low31Mask := 0x7fffffff7fffffff7fffffff7fffffff7fffffff000000000000000000000000
                let bias := 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000
                if or(
                    or(and(packed, sub(shl(96, 1), 1)), and(packed, highBitMask)),
                    and(add(and(packed, low31Mask), bias), highBitMask)
                ) {
                    mstore(0x00, 0xd53cfe5c00000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, packed)
                    revert(0x00, 0x24)
                }
            }

            validateExt5(v0)
            validateExt5(v1)
            validateExt5(v2)
            validateExt5(v3)
            validateExt5(v4)
            validateExt5(v5)
            validateExt5(v6)
            validateExt5(v7)
            validateExt5(v8)
            validateExt5(v9)
            validateExt5(v10)
            validateExt5(v11)
            validateExt5(v12)
            validateExt5(v13)
            validateExt5(v14)
            validateExt5(v15)
        }

        (uint256 r00, uint256 r01, uint256 r02, uint256 r03, uint256 r04) = _unpackCoeffs(point[0]);
        (uint256 r10, uint256 r11, uint256 r12, uint256 r13, uint256 r14) = _unpackCoeffs(point[1]);
        (uint256 r20, uint256 r21, uint256 r22, uint256 r23, uint256 r24) = _unpackCoeffs(point[2]);
        (uint256 r30, uint256 r31, uint256 r32, uint256 r33, uint256 r34) = _unpackCoeffs(point[3]);

        uint256 l0 = _foldOnceWithCoeffs(v0, v8, r00, r01, r02, r03, r04);
        uint256 l1 = _foldOnceWithCoeffs(v1, v9, r00, r01, r02, r03, r04);
        uint256 l2 = _foldOnceWithCoeffs(v2, v10, r00, r01, r02, r03, r04);
        uint256 l3 = _foldOnceWithCoeffs(v3, v11, r00, r01, r02, r03, r04);
        uint256 l4 = _foldOnceWithCoeffs(v4, v12, r00, r01, r02, r03, r04);
        uint256 l5 = _foldOnceWithCoeffs(v5, v13, r00, r01, r02, r03, r04);
        uint256 l6 = _foldOnceWithCoeffs(v6, v14, r00, r01, r02, r03, r04);
        uint256 l7 = _foldOnceWithCoeffs(v7, v15, r00, r01, r02, r03, r04);
        uint256 m0 = _foldOnceWithCoeffs(l0, l4, r10, r11, r12, r13, r14);
        uint256 m1 = _foldOnceWithCoeffs(l1, l5, r10, r11, r12, r13, r14);
        uint256 m2 = _foldOnceWithCoeffs(l2, l6, r10, r11, r12, r13, r14);
        uint256 m3 = _foldOnceWithCoeffs(l3, l7, r10, r11, r12, r13, r14);
        uint256 n0 = _foldOnceWithCoeffs(m0, m2, r20, r21, r22, r23, r24);
        uint256 n1 = _foldOnceWithCoeffs(m1, m3, r20, r21, r22, r23, r24);
        return _foldOnceWithCoeffs(n0, n1, r30, r31, r32, r33, r34);
    }

    function _hashAndEvaluateBaseRow16Blob(bytes calldata blob, uint256 offset, uint256 weightsPtr)
        internal
        pure
        returns (bytes32 digest, uint256 evalValue)
    {
        uint256 src;
        assembly ("memory-safe") {
            src := add(blob.offset, offset)
        }

        uint256 w0;
        uint256 w1;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            function revertField(x) {
                mstore(0x00, 0xf512b67800000000000000000000000000000000000000000000000000000000)
                mstore(0x04, x)
                revert(0x00, 0x24)
            }

            w0 := calldataload(src)
            w1 := calldataload(add(src, 0x20))

            // Any high bit is noncanonical; otherwise adding 2^24-1 cannot
            // carry across a 32-bit lane and sets its high bit iff c >= p.
            let laneHighBits := 0x8000000080000000800000008000000080000000800000008000000080000000
            let laneBias := 0x00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff
            if and(or(w0, add(w0, laneBias)), laneHighBits) { revertField(w0) }
            if and(or(w1, add(w1, laneBias)), laneHighBits) { revertField(w1) }

            mstore8(ptr, 0x00)
            calldatacopy(add(ptr, 0x01), src, 0x40)
            digest := and(keccak256(ptr, 65), not(sub(shl(96, 1), 1)))
        }

        evalValue = _dotBaseRadix64(weightsPtr, w0, w1);
    }

    function _evaluateExtensionRowDim4BlobWindow(
        bytes calldata blob,
        uint256 offset,
        uint256[] memory fullPoint,
        uint256 pointOffset
    ) private pure returns (uint256) {
        uint256 p0;
        uint256 p1;
        uint256 p2;
        uint256 p3;
        assembly ("memory-safe") {
            let pointBase := add(add(fullPoint, 0x20), shl(5, pointOffset))
            p0 := mload(pointBase)
            p1 := mload(add(pointBase, 0x20))
            p2 := mload(add(pointBase, 0x40))
            p3 := mload(add(pointBase, 0x60))
        }

        return _evaluateExtensionRowDim4BlobPackedPoints(blob, offset, p0, p1, p2, p3);
    }

    function _evaluateExtensionRowDim4BlobPackedPoints(
        bytes calldata blob,
        uint256 offset,
        uint256 p0,
        uint256 p1,
        uint256 p2,
        uint256 p3
    ) internal pure returns (uint256) {
        uint256 src;
        assembly ("memory-safe") {
            src := add(blob.offset, offset)
        }

        uint256 v0;
        uint256 v1;
        uint256 v2;
        uint256 v3;
        uint256 v4;
        uint256 v5;
        uint256 v6;
        uint256 v7;
        uint256 v8;
        uint256 v9;
        uint256 v10;
        uint256 v11;
        uint256 v12;
        uint256 v13;
        uint256 v14;
        uint256 v15;
        assembly ("memory-safe") {
            v0 := calldataload(src)
            v1 := calldataload(add(src, 0x20))
            v2 := calldataload(add(src, 0x40))
            v3 := calldataload(add(src, 0x60))
            v4 := calldataload(add(src, 0x80))
            v5 := calldataload(add(src, 0xa0))
            v6 := calldataload(add(src, 0xc0))
            v7 := calldataload(add(src, 0xe0))
            v8 := calldataload(add(src, 0x100))
            v9 := calldataload(add(src, 0x120))
            v10 := calldataload(add(src, 0x140))
            v11 := calldataload(add(src, 0x160))
            v12 := calldataload(add(src, 0x180))
            v13 := calldataload(add(src, 0x1a0))
            v14 := calldataload(add(src, 0x1c0))
            v15 := calldataload(add(src, 0x1e0))

            function validateExt5(packed) {
                let highBitMask :=
                    0x8000000080000000800000008000000080000000000000000000000000000000
                let low31Mask := 0x7fffffff7fffffff7fffffff7fffffff7fffffff000000000000000000000000
                let bias := 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000
                if or(
                    or(and(packed, sub(shl(96, 1), 1)), and(packed, highBitMask)),
                    and(add(and(packed, low31Mask), bias), highBitMask)
                ) {
                    mstore(0x00, 0xd53cfe5c00000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, packed)
                    revert(0x00, 0x24)
                }
            }

            validateExt5(v0)
            validateExt5(v1)
            validateExt5(v2)
            validateExt5(v3)
            validateExt5(v4)
            validateExt5(v5)
            validateExt5(v6)
            validateExt5(v7)
            validateExt5(v8)
            validateExt5(v9)
            validateExt5(v10)
            validateExt5(v11)
            validateExt5(v12)
            validateExt5(v13)
            validateExt5(v14)
            validateExt5(v15)
        }

        (uint256 r00, uint256 r01, uint256 r02, uint256 r03, uint256 r04) = _unpackCoeffs(p0);
        (uint256 r10, uint256 r11, uint256 r12, uint256 r13, uint256 r14) = _unpackCoeffs(p1);
        (uint256 r20, uint256 r21, uint256 r22, uint256 r23, uint256 r24) = _unpackCoeffs(p2);
        (uint256 r30, uint256 r31, uint256 r32, uint256 r33, uint256 r34) = _unpackCoeffs(p3);

        uint256 l0 = _foldOnceWithCoeffs(v0, v8, r00, r01, r02, r03, r04);
        uint256 l1 = _foldOnceWithCoeffs(v1, v9, r00, r01, r02, r03, r04);
        uint256 l2 = _foldOnceWithCoeffs(v2, v10, r00, r01, r02, r03, r04);
        uint256 l3 = _foldOnceWithCoeffs(v3, v11, r00, r01, r02, r03, r04);
        uint256 l4 = _foldOnceWithCoeffs(v4, v12, r00, r01, r02, r03, r04);
        uint256 l5 = _foldOnceWithCoeffs(v5, v13, r00, r01, r02, r03, r04);
        uint256 l6 = _foldOnceWithCoeffs(v6, v14, r00, r01, r02, r03, r04);
        uint256 l7 = _foldOnceWithCoeffs(v7, v15, r00, r01, r02, r03, r04);
        uint256 m0 = _foldOnceWithCoeffs(l0, l4, r10, r11, r12, r13, r14);
        uint256 m1 = _foldOnceWithCoeffs(l1, l5, r10, r11, r12, r13, r14);
        uint256 m2 = _foldOnceWithCoeffs(l2, l6, r10, r11, r12, r13, r14);
        uint256 m3 = _foldOnceWithCoeffs(l3, l7, r10, r11, r12, r13, r14);
        uint256 n0 = _foldOnceWithCoeffs(m0, m2, r20, r21, r22, r23, r24);
        uint256 n1 = _foldOnceWithCoeffs(m1, m3, r20, r21, r22, r23, r24);
        return _foldOnceWithCoeffs(n0, n1, r30, r31, r32, r33, r34);
    }

    function _hashAndEvaluateCompactRow16(bytes calldata blob, uint256 offset, uint256 weightsPtr)
        internal
        pure
        returns (bytes32 digest, uint256 evalValue)
    {
        uint256 mask;
        uint256 source;
        assembly ("memory-safe") {
            source := add(blob.offset, offset)
            mask := byte(0, calldataload(source))
        }
        if (mask == 0) {
            return _hashAndEvaluateExtensionRow16Blob(blob, offset + 1, weightsPtr);
        }
        if (mask == 30) {
            uint256 common;
            uint256 w0;
            uint256 w1;
            // The bounds were checked by rowOffsets. Validate the actual
            // reconstructed packed elements before hashing or arithmetic.
            assembly ("memory-safe") {
                source := add(source, 1)
                w0 := calldataload(source)
                w1 := calldataload(add(source, 32))
                common := and(
                    shr(32, calldataload(add(source, 64))),
                    0x00000000ffffffffffffffffffffffffffffffff000000000000000000000000
                )
            }
            validatePackedExt5(common | ((w0 >> 224) << 224));
            uint256 invalidBits;
            assembly ("memory-safe") {
                let bias := 0x00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff00ffffff
                invalidBits := and(
                    or(or(w0, add(w0, bias)), or(w1, add(w1, bias))),
                    0x8000000080000000800000008000000080000000800000008000000080000000
                )
            }
            if (invalidBits != 0) {
                for (uint256 i = 1; i < 16; ++i) {
                    uint256 value;
                    assembly ("memory-safe") {
                        value := or(
                            common,
                            shl(224, shr(224, calldataload(add(source, mul(i, 4)))))
                        )
                    }
                    validatePackedExt5(value);
                }
            }
            assembly ("memory-safe") {
                let ptr := mload(0x40)
                mstore8(ptr, 0)
                mstore(add(ptr, 1), or(common, shl(224, shr(224, calldataload(add(source, 0))))))
                mstore(add(ptr, 21), or(common, shl(224, shr(224, calldataload(add(source, 4))))))
                mstore(add(ptr, 41), or(common, shl(224, shr(224, calldataload(add(source, 8))))))
                mstore(add(ptr, 61), or(common, shl(224, shr(224, calldataload(add(source, 12))))))
                mstore(add(ptr, 81), or(common, shl(224, shr(224, calldataload(add(source, 16))))))
                mstore(add(ptr, 101), or(common, shl(224, shr(224, calldataload(add(source, 20))))))
                mstore(add(ptr, 121), or(common, shl(224, shr(224, calldataload(add(source, 24))))))
                mstore(add(ptr, 141), or(common, shl(224, shr(224, calldataload(add(source, 28))))))
                mstore(add(ptr, 161), or(common, shl(224, shr(224, calldataload(add(source, 32))))))
                mstore(add(ptr, 181), or(common, shl(224, shr(224, calldataload(add(source, 36))))))
                mstore(add(ptr, 201), or(common, shl(224, shr(224, calldataload(add(source, 40))))))
                mstore(add(ptr, 221), or(common, shl(224, shr(224, calldataload(add(source, 44))))))
                mstore(add(ptr, 241), or(common, shl(224, shr(224, calldataload(add(source, 48))))))
                mstore(add(ptr, 261), or(common, shl(224, shr(224, calldataload(add(source, 52))))))
                mstore(add(ptr, 281), or(common, shl(224, shr(224, calldataload(add(source, 56))))))
                mstore(add(ptr, 301), or(common, shl(224, shr(224, calldataload(add(source, 60))))))
                digest := and(keccak256(ptr, 321), not(sub(shl(96, 1), 1)))
            }
            (uint256 baseWeights, uint256 weightSum) = _constantRowWeights(weightsPtr);
            evalValue = KoalaBearExt5.add(
                _dotBaseRadix64(baseWeights, w0, w1),
                weightSum == KoalaBearExt5.ONE ? common : KoalaBearExt5.mul(common, weightSum)
            );
            return (digest, evalValue);
        }
        // All other masks retain the generic field kernel. Reconstruct one row
        // only, keep it live through the dot product, and hash the original bytes.
        bytes memory row = new bytes(352);
        uint256 ptr;
        assembly ("memory-safe") { ptr := add(row, 32) }
        QuinticTransportCodec.decodeRowInto(blob, offset, ptr + 1, 16);
        for (uint256 i; i < 16; ++i) {
            uint256 value;
            assembly ("memory-safe") {
                value := and(mload(add(add(ptr, 1), mul(i, 20))), not(sub(shl(96, 1), 1)))
            }
            validatePackedExt5(value);
        }
        assembly ("memory-safe") { digest := and(keccak256(ptr, 321), not(sub(shl(96, 1), 1))) }
        evalValue = _evaluateFinalRow16Memory(row, 1, weightsPtr);
    }

    function _hashAndEvaluateExtensionRow16Blob(
        bytes calldata blob,
        uint256 offset,
        uint256 weightsPtr
    ) internal pure returns (bytes32 digest, uint256 evalValue) {
        uint256 src;
        uint256 v0;
        uint256 v1;
        uint256 v2;
        uint256 v3;
        uint256 v4;
        uint256 v5;
        uint256 v6;
        uint256 v7;
        uint256 v8;
        uint256 v9;
        uint256 v10;
        uint256 v11;
        uint256 v12;
        uint256 v13;
        uint256 v14;
        uint256 v15;
        bool commonColumns;
        uint256 common;
        assembly ("memory-safe") {
            src := add(blob.offset, offset)
            let lowMask := not(sub(shl(96, 1), 1))
            let ptr := mload(0x40)
            v0 := and(calldataload(src), lowMask)
            v1 := and(calldataload(add(src, 20)), lowMask)
            v2 := and(calldataload(add(src, 40)), lowMask)
            v3 := and(calldataload(add(src, 60)), lowMask)
            v4 := and(calldataload(add(src, 80)), lowMask)
            v5 := and(calldataload(add(src, 100)), lowMask)
            v6 := and(calldataload(add(src, 120)), lowMask)
            v7 := and(calldataload(add(src, 140)), lowMask)
            v8 := and(calldataload(add(src, 160)), lowMask)
            v9 := and(calldataload(add(src, 180)), lowMask)
            v10 := and(calldataload(add(src, 200)), lowMask)
            v11 := and(calldataload(add(src, 220)), lowMask)
            v12 := and(calldataload(add(src, 240)), lowMask)
            v13 := and(calldataload(add(src, 260)), lowMask)
            v14 := and(calldataload(add(src, 280)), lowMask)
            v15 := and(calldataload(add(src, 300)), lowMask)

            function validateExt5(packed) {
                let highBitMask :=
                    0x8000000080000000800000008000000080000000000000000000000000000000
                let low31Mask := 0x7fffffff7fffffff7fffffff7fffffff7fffffff000000000000000000000000
                let bias := 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000
                if or(
                    and(packed, highBitMask),
                    and(add(and(packed, low31Mask), bias), highBitMask)
                ) {
                    mstore(0x00, 0xd53cfe5c00000000000000000000000000000000000000000000000000000000)
                    mstore(0x04, packed)
                    revert(0x00, 0x24)
                }
            }

            let invalidBits := 0
            invalidBits := or(
                invalidBits,
                or(v0, add(v0, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v1, add(v1, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v2, add(v2, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v3, add(v3, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v4, add(v4, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v5, add(v5, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v6, add(v6, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v7, add(v7, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v8, add(v8, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(v9, add(v9, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000))
            )
            invalidBits := or(
                invalidBits,
                or(
                    v10,
                    add(v10, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000)
                )
            )
            invalidBits := or(
                invalidBits,
                or(
                    v11,
                    add(v11, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000)
                )
            )
            invalidBits := or(
                invalidBits,
                or(
                    v12,
                    add(v12, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000)
                )
            )
            invalidBits := or(
                invalidBits,
                or(
                    v13,
                    add(v13, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000)
                )
            )
            invalidBits := or(
                invalidBits,
                or(
                    v14,
                    add(v14, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000)
                )
            )
            invalidBits := or(
                invalidBits,
                or(
                    v15,
                    add(v15, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000)
                )
            )
            if and(
                invalidBits,
                0x8000000080000000800000008000000080000000000000000000000000000000
            ) {
                validateExt5(v0)
                validateExt5(v1)
                validateExt5(v2)
                validateExt5(v3)
                validateExt5(v4)
                validateExt5(v5)
                validateExt5(v6)
                validateExt5(v7)
                validateExt5(v8)
                validateExt5(v9)
                validateExt5(v10)
                validateExt5(v11)
                validateExt5(v12)
                validateExt5(v13)
                validateExt5(v14)
                validateExt5(v15)
            }

            // Most generic rows fail the first equality check. Only scan the
            // remaining columns when the first two elements actually match.
            let commonMask := 0x00000000ffffffffffffffffffffffffffffffff000000000000000000000000
            commonColumns := iszero(and(xor(v0, v1), commonMask))
            if commonColumns {
                let difference := 0
                difference := or(difference, xor(v0, v2))
                difference := or(difference, xor(v0, v3))
                difference := or(difference, xor(v0, v4))
                difference := or(difference, xor(v0, v5))
                difference := or(difference, xor(v0, v6))
                difference := or(difference, xor(v0, v7))
                difference := or(difference, xor(v0, v8))
                difference := or(difference, xor(v0, v9))
                difference := or(difference, xor(v0, v10))
                difference := or(difference, xor(v0, v11))
                difference := or(difference, xor(v0, v12))
                difference := or(difference, xor(v0, v13))
                difference := or(difference, xor(v0, v14))
                difference := or(difference, xor(v0, v15))
                commonColumns := iszero(and(difference, commonMask))
            }
            common := and(v0, commonMask)

            mstore8(ptr, 0x00)
            calldatacopy(add(ptr, 0x01), src, 320)
            digest := and(keccak256(ptr, 321), lowMask)
        }

        if (commonColumns) {
            return (digest, _evaluateConstantColumnRow(src, weightsPtr, common));
        }

        evalValue = _dotExt5Weights16Unpacked(
            weightsPtr, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15
        );
    }

    function _dotExt5Weights16Unpacked(
        uint256 weightsPtr,
        uint256 v0,
        uint256 v1,
        uint256 v2,
        uint256 v3,
        uint256 v4,
        uint256 v5,
        uint256 v6,
        uint256 v7,
        uint256 v8,
        uint256 v9,
        uint256 v10,
        uint256 v11,
        uint256 v12,
        uint256 v13,
        uint256 v14,
        uint256 v15
    ) internal pure returns (uint256 out) {
        weightsPtr = _genericRowWeights(weightsPtr);
        assembly ("memory-safe") {
            let M := 0x7f000001
            let c0 := 0
            let c1 := 0
            function accumulate(a, b, w, d0, d1) -> e0, e1 {
                let u :=
                    or(
                        and(shr(224, a), 0xffffffff),
                        or(
                            shl(51, and(shr(192, a), 0xffffffff)),
                            or(
                                shl(102, and(shr(160, a), 0xffffffff)),
                                or(
                                    shl(153, and(shr(128, a), 0xffffffff)),
                                    shl(204, and(shr(96, a), 0xffffffff))
                                )
                            )
                        )
                    )
                e0 := addmod(
                    d0,
                    mulmod(
                        u,
                        mload(w),
                        0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                    ),
                    0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                )
                e1 := addmod(
                    d1,
                    mulmod(
                        and(shr(11, u), 0xfffff00000001ffffe00000003ffffc00000007ffff80000000fffff),
                        mload(add(w, 32)),
                        0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                    ),
                    0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                )

                u := or(
                    and(shr(224, b), 0xffffffff),
                    or(
                        shl(51, and(shr(192, b), 0xffffffff)),
                        or(
                            shl(102, and(shr(160, b), 0xffffffff)),
                            or(
                                shl(153, and(shr(128, b), 0xffffffff)),
                                shl(204, and(shr(96, b), 0xffffffff))
                            )
                        )
                    )
                )
                e0 := addmod(
                    e0,
                    mulmod(
                        u,
                        mload(add(w, 64)),
                        0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                    ),
                    0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                )
                e1 := addmod(
                    e1,
                    mulmod(
                        and(shr(11, u), 0xfffff00000001ffffe00000003ffffc00000007ffff80000000fffff),
                        mload(add(w, 96)),
                        0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                    ),
                    0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                )
            }
            c0, c1 := accumulate(v0, v1, add(weightsPtr, 0), c0, c1)
            c0, c1 := accumulate(v2, v3, add(weightsPtr, 128), c0, c1)
            c0, c1 := accumulate(v4, v5, add(weightsPtr, 256), c0, c1)
            c0, c1 := accumulate(v6, v7, add(weightsPtr, 384), c0, c1)
            c0, c1 := accumulate(v8, v9, add(weightsPtr, 512), c0, c1)
            c0, c1 := accumulate(v10, v11, add(weightsPtr, 640), c0, c1)
            c0, c1 := accumulate(v12, v13, add(weightsPtr, 768), c0, c1)
            c0, c1 := accumulate(v14, v15, add(weightsPtr, 896), c0, c1)
            // Full/high products obey polynomial reduction modulo N=Q^5+Q^2-1.
            // Subtracting the high20-bit product times2^22 leaves low11-bit
            // cross terms. Per term R<=8723116322817. Across16products, each
            // reduced coefficient lies in[-64R,96R]. B=P*2^18 makes both this
            // remainder and the high-product digits strictly within[0,Q),Q=2^51.
            // Recombination modulo P cancels B; no radix carry information is lost.
            c0 := addmod(
                c0,
                sub(
                    0x800000000000000000000000000000000000003fffffffffffffffffffffffff,
                    mulmod(
                        c1,
                        0x400000,
                        0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                    )
                ),
                0x800000000000000000000000000000000000003fffffffffffffffffffffffff
            )
            c0 := addmod(
                c0,
                0x1fc00000400003f800000800007f00000100000fe00000200001fc0000040000,
                0x800000000000000000000000000000000000003fffffffffffffffffffffffff
            )
            c1 := addmod(
                c1,
                0x1fc00000400003f800000800007f00000100000fe00000200001fc0000040000,
                0x800000000000000000000000000000000000003fffffffffffffffffffffffff
            )
            let r0 :=
                mod(
                    add(
                        and(shr(0, c0), 0x7ffffffffffff),
                        shl(22, and(shr(0, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r1 :=
                mod(
                    add(
                        and(shr(51, c0), 0x7ffffffffffff),
                        shl(22, and(shr(51, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r2 :=
                mod(
                    add(
                        and(shr(102, c0), 0x7ffffffffffff),
                        shl(22, and(shr(102, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r3 :=
                mod(
                    add(
                        and(shr(153, c0), 0x7ffffffffffff),
                        shl(22, and(shr(153, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r4 :=
                mod(
                    add(
                        and(shr(204, c0), 0x7ffffffffffff),
                        shl(22, and(shr(204, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            out := or(
                shl(224, r0),
                or(shl(192, r1), or(shl(160, r2), or(shl(128, r3), shl(96, r4))))
            )
        }
    }

    function _dotBaseRowWeights16Packed(uint256 weightsPtr, uint256 w0, uint256 w1)
        private
        pure
        returns (uint256 out)
    {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let mask := 0xffffffff
            function accumulate(scalar, weight, c0, c1, c2, c3, c4) -> d0, d1, d2, d3, d4 {
                d0 := add(c0, mul(scalar, shr(224, weight)))
                d1 := add(c1, mul(scalar, and(shr(192, weight), 0xffffffff)))
                d2 := add(c2, mul(scalar, and(shr(160, weight), 0xffffffff)))
                d3 := add(c3, mul(scalar, and(shr(128, weight), 0xffffffff)))
                d4 := add(c4, mul(scalar, and(shr(96, weight), 0xffffffff)))
            }

            let c0 := 0
            let c1 := 0
            let c2 := 0
            let c3 := 0
            let c4 := 0

            c0, c1, c2, c3, c4 := accumulate(shr(224, w0), mload(weightsPtr), c0, c1, c2, c3, c4)
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(192, w0), mask),
                mload(add(weightsPtr, 0x020)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(160, w0), mask),
                mload(add(weightsPtr, 0x040)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(128, w0), mask),
                mload(add(weightsPtr, 0x060)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(96, w0), mask),
                mload(add(weightsPtr, 0x080)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(64, w0), mask),
                mload(add(weightsPtr, 0x0a0)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(32, w0), mask),
                mload(add(weightsPtr, 0x0c0)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(and(w0, mask), mload(add(weightsPtr, 0x0e0)), c0, c1, c2, c3, c4)
            c0, c1, c2, c3, c4 :=
                accumulate(shr(224, w1), mload(add(weightsPtr, 0x100)), c0, c1, c2, c3, c4)
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(192, w1), mask),
                mload(add(weightsPtr, 0x120)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(160, w1), mask),
                mload(add(weightsPtr, 0x140)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(128, w1), mask),
                mload(add(weightsPtr, 0x160)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(96, w1), mask),
                mload(add(weightsPtr, 0x180)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(64, w1), mask),
                mload(add(weightsPtr, 0x1a0)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(
                and(shr(32, w1), mask),
                mload(add(weightsPtr, 0x1c0)),
                c0,
                c1,
                c2,
                c3,
                c4
            )
            c0, c1, c2, c3, c4 :=
                accumulate(and(w1, mask), mload(add(weightsPtr, 0x1e0)), c0, c1, c2, c3, c4)

            out := or(
                or(or(shl(224, mod(c0, M)), shl(192, mod(c1, M))), shl(160, mod(c2, M))),
                or(shl(128, mod(c3, M)), shl(96, mod(c4, M)))
            )
        }
    }

    function _foldOnceBase(
        uint256 a0,
        uint256 a1,
        uint256 r0,
        uint256 r1,
        uint256 r2,
        uint256 r3,
        uint256 r4
    ) private pure returns (uint256 out) {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let d := sub(add(a1, M), a0)
            let c0 := mod(add(a0, mul(r0, d)), M)
            let c1 := mod(mul(r1, d), M)
            let c2 := mod(mul(r2, d), M)
            let c3 := mod(mul(r3, d), M)
            let c4 := mod(mul(r4, d), M)
            out := or(
                or(or(shl(224, c0), shl(192, c1)), or(shl(160, c2), shl(128, c3))),
                shl(96, c4)
            )
        }
    }

    function _foldOnceWithCoeffs(
        uint256 a0,
        uint256 a1,
        uint256 r0,
        uint256 r1,
        uint256 r2,
        uint256 r3,
        uint256 r4
    ) private pure returns (uint256 out) {
        unchecked {
            uint256 a00 = a0 >> 224;
            uint256 a01 = (a0 >> 192) & 0xffffffff;
            uint256 a02 = (a0 >> 160) & 0xffffffff;
            uint256 a03 = (a0 >> 128) & 0xffffffff;
            uint256 a04 = (a0 >> 96) & 0xffffffff;

            uint256 d0 = (a1 >> 224) + KoalaBear.MODULUS - a00;
            uint256 d1 = ((a1 >> 192) & 0xffffffff) + KoalaBear.MODULUS - a01;
            uint256 d2 = ((a1 >> 160) & 0xffffffff) + KoalaBear.MODULUS - a02;
            uint256 d3 = ((a1 >> 128) & 0xffffffff) + KoalaBear.MODULUS - a03;
            uint256 d4 = ((a1 >> 96) & 0xffffffff) + KoalaBear.MODULUS - a04;

            uint256 c0 = r0 * d0;
            uint256 c1 = r0 * d1 + r1 * d0;
            uint256 c2 = r0 * d2 + r1 * d1 + r2 * d0;
            uint256 c3 = r0 * d3 + r1 * d2 + r2 * d1 + r3 * d0;
            uint256 c4 = r0 * d4 + r1 * d3 + r2 * d2 + r3 * d1 + r4 * d0;
            uint256 c5 = r1 * d4 + r2 * d3 + r3 * d2 + r4 * d1;
            uint256 c6 = r2 * d4 + r3 * d3 + r4 * d2;
            uint256 c7 = r3 * d4 + r4 * d3;
            uint256 c8 = r4 * d4;
            uint256 bias = KoalaBear.MODULUS << 35;

            uint256 rOut0 = (a00 + c0 + c5 + bias - c8) % KoalaBear.MODULUS;
            uint256 rOut1 = (a01 + c1 + c6) % KoalaBear.MODULUS;
            uint256 rOut2 = (a02 + c2 + bias - c5 + c7 + c8) % KoalaBear.MODULUS;
            uint256 rOut3 = (a03 + c3 + bias - c6 + c8) % KoalaBear.MODULUS;
            uint256 rOut4 = (a04 + c4 + bias - c7) % KoalaBear.MODULUS;

            out = (rOut0 << 224) | (rOut1 << 192) | (rOut2 << 160) | (rOut3 << 128) | (rOut4 << 96);
        }
    }

    function _unpackCoeffs(uint256 packed)
        internal
        pure
        returns (uint256 c0, uint256 c1, uint256 c2, uint256 c3, uint256 c4)
    {
        c0 = packed >> 224;
        c1 = (packed >> 192) & 0xffffffff;
        c2 = (packed >> 160) & 0xffffffff;
        c3 = (packed >> 128) & 0xffffffff;
        c4 = (packed >> 96) & 0xffffffff;
    }

    // A complemented pointer distinguishes the lazy descriptor from a matrix.
    // Valid EVM allocations have bit 255 clear; complementing also works when a
    // legacy caller leaves the free pointer unaligned. Never dereference a tag.
    // The descriptor owns four initialized words: the borrowed
    // immutable packed weights, generic matrix, quartet cache, and packed sum.
    // The packed buffer must remain live and unchanged while this handle is used.
    function _prepareRowWeightsLazy(uint256 packedPtr) internal pure returns (uint256 ptr) {
        assembly ("memory-safe") {
            let descriptor := mload(0x40)
            mstore(0x40, add(descriptor, 128))
            mstore(descriptor, packedPtr)
            mstore(add(descriptor, 32), 0)
            mstore(add(descriptor, 64), 0)
            mstore(add(descriptor, 96), 0)
            ptr := not(descriptor)
        }
    }

    function _genericRowWeights(uint256 ptr) private pure returns (uint256 matrix) {
        if ((ptr >> 255) == 0) return ptr;
        uint256 packedPtr;
        assembly ("memory-safe") {
            ptr := not(ptr)
            packedPtr := mload(ptr)
            matrix := mload(add(ptr, 32))
        }
        if (matrix == 0) {
            matrix = _prepareRowWeights(packedPtr);
            assembly ("memory-safe") { mstore(add(ptr, 32), matrix) }
        }
    }

    function _prepareRowWeights(uint256 packedPtr) internal pure returns (uint256 ptr) {
        assembly ("memory-safe") {
            ptr := mload(0x40)
            mstore(0x40, add(ptr, 1088))
            mstore(add(ptr, 1024), 0)
            mstore(add(ptr, 1056), 0)
            for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                let a := mload(add(packedPtr, shl(5, i)))
                let dst := add(ptr, mul(i, 64))
                let u :=
                    or(
                        and(shr(224, a), 0xffffffff),
                        or(
                            shl(51, and(shr(192, a), 0xffffffff)),
                            or(
                                shl(102, and(shr(160, a), 0xffffffff)),
                                or(
                                    shl(153, and(shr(128, a), 0xffffffff)),
                                    shl(204, and(shr(96, a), 0xffffffff))
                                )
                            )
                        )
                    )
                // Full radix51 coefficients and their high20-bit parts.
                mstore(dst, u)
                mstore(
                    add(dst, 32),
                    and(shr(11, u), 0xfffff00000001ffffe00000003ffffc00000007ffff80000000fffff)
                )
            }
        }
    }

    function _evaluateConstantColumnRow(uint256 src, uint256 weightsPtr, uint256 common)
        private
        pure
        returns (uint256)
    {
        (uint256 baseWeights, uint256 weightSum) = _constantRowWeights(weightsPtr);
        uint256 w0;
        uint256 w1;
        assembly ("memory-safe") {
            w0 := or(w0, shl(224, shr(224, calldataload(add(src, 0)))))
            w0 := or(w0, shl(192, shr(224, calldataload(add(src, 20)))))
            w0 := or(w0, shl(160, shr(224, calldataload(add(src, 40)))))
            w0 := or(w0, shl(128, shr(224, calldataload(add(src, 60)))))
            w0 := or(w0, shl(96, shr(224, calldataload(add(src, 80)))))
            w0 := or(w0, shl(64, shr(224, calldataload(add(src, 100)))))
            w0 := or(w0, shl(32, shr(224, calldataload(add(src, 120)))))
            w0 := or(w0, shl(0, shr(224, calldataload(add(src, 140)))))
            w1 := or(w1, shl(224, shr(224, calldataload(add(src, 160)))))
            w1 := or(w1, shl(192, shr(224, calldataload(add(src, 180)))))
            w1 := or(w1, shl(160, shr(224, calldataload(add(src, 200)))))
            w1 := or(w1, shl(128, shr(224, calldataload(add(src, 220)))))
            w1 := or(w1, shl(96, shr(224, calldataload(add(src, 240)))))
            w1 := or(w1, shl(64, shr(224, calldataload(add(src, 260)))))
            w1 := or(w1, shl(32, shr(224, calldataload(add(src, 280)))))
            w1 := or(w1, shl(0, shr(224, calldataload(add(src, 300)))))
        }
        uint256 baseValue = _dotBaseRadix64(baseWeights, w0, w1);
        return KoalaBearExt5.add(
            baseValue,
            weightSum == KoalaBearExt5.ONE ? common : KoalaBearExt5.mul(common, weightSum)
        );
    }

    function _evaluateConstantColumnRowMemory(uint256 src, uint256 weightsPtr, uint256 common)
        private
        pure
        returns (uint256)
    {
        (uint256 baseWeights, uint256 weightSum) = _constantRowWeights(weightsPtr);
        uint256 w0;
        uint256 w1;
        assembly ("memory-safe") {
            w0 := or(w0, shl(224, shr(224, mload(add(src, 0)))))
            w0 := or(w0, shl(192, shr(224, mload(add(src, 20)))))
            w0 := or(w0, shl(160, shr(224, mload(add(src, 40)))))
            w0 := or(w0, shl(128, shr(224, mload(add(src, 60)))))
            w0 := or(w0, shl(96, shr(224, mload(add(src, 80)))))
            w0 := or(w0, shl(64, shr(224, mload(add(src, 100)))))
            w0 := or(w0, shl(32, shr(224, mload(add(src, 120)))))
            w0 := or(w0, shl(0, shr(224, mload(add(src, 140)))))
            w1 := or(w1, shl(224, shr(224, mload(add(src, 160)))))
            w1 := or(w1, shl(192, shr(224, mload(add(src, 180)))))
            w1 := or(w1, shl(160, shr(224, mload(add(src, 200)))))
            w1 := or(w1, shl(128, shr(224, mload(add(src, 220)))))
            w1 := or(w1, shl(96, shr(224, mload(add(src, 240)))))
            w1 := or(w1, shl(64, shr(224, mload(add(src, 260)))))
            w1 := or(w1, shl(32, shr(224, mload(add(src, 280)))))
            w1 := or(w1, shl(0, shr(224, mload(add(src, 300)))))
        }
        uint256 baseValue = _dotBaseRadix64(baseWeights, w0, w1);
        return KoalaBearExt5.add(
            baseValue,
            weightSum == KoalaBearExt5.ONE ? common : KoalaBearExt5.mul(common, weightSum)
        );
    }

    // Cache metadata stays at offsets 1024/1056 in the radix-2^51 weight matrix.
    // The lazy cache stores five coordinates, each with four reversed quartets
    // of canonical coefficients in 64-bit lanes: cache[4 * coordinate + group].
    function _constantRowWeights(uint256 ptr)
        private
        pure
        returns (uint256 baseWeights, uint256 weightSum)
    {
        if ((ptr >> 255) != 0) return _constantRowWeightsPacked(~ptr);
        assembly ("memory-safe") {
            baseWeights := mload(add(ptr, 1024))
            weightSum := mload(add(ptr, 1056))
            if iszero(baseWeights) {
                baseWeights := mload(0x40)
                mstore(0x40, add(baseWeights, 640))
                let total := 0
                for { let group := 0 } lt(group, 4) { group := add(group, 1) } {
                    let src := add(ptr, shl(8, group))
                    let w0 := mload(src)
                    let w1 := mload(add(src, 64))
                    let w2 := mload(add(src, 128))
                    let w3 := mload(add(src, 192))
                    total := add(total, add(add(w0, w1), add(w2, w3)))
                    for { let c := 0 } lt(c, 5) { c := add(c, 1) } {
                        let shift := mul(51, c)
                        let w :=
                            or(
                                or(
                                    and(shr(shift, w0), 0xffffffff),
                                    shl(64, and(shr(shift, w1), 0xffffffff))
                                ),
                                or(
                                    shl(128, and(shr(shift, w2), 0xffffffff)),
                                    shl(192, and(shr(shift, w3), 0xffffffff))
                                )
                            )
                        mstore(add(baseWeights, add(shl(7, c), shl(5, group))), w)
                    }
                }
                // Summing sixteen radix51 canonical weights cannot carry:
                // every lane is below 16*p < 2^35 < 2^51.
                for { let c := 0 } lt(c, 5) { c := add(c, 1) } {
                    weightSum := or(
                        weightSum,
                        shl(
                            sub(224, shl(5, c)),
                            mod(and(shr(mul(51, c), total), 0x7ffffffffffff), 0x7f000001)
                        )
                    )
                }
                mstore(add(ptr, 1024), baseWeights)
                mstore(add(ptr, 1056), weightSum)
            }
        }
    }

    // Build only the representation needed by a constant-column row. Each
    // coordinate sum is below 16*p < 2^35, so no packed-lane carry is involved.
    // The arbitrary canonical weight sum is retained, including zero and ONE.
    function _constantRowWeightsPacked(uint256 descriptor)
        private
        pure
        returns (uint256 baseWeights, uint256 weightSum)
    {
        assembly ("memory-safe") {
            baseWeights := mload(add(descriptor, 64))
            weightSum := mload(add(descriptor, 96))
            if iszero(baseWeights) {
                baseWeights := mload(0x40)
                mstore(0x40, add(baseWeights, 640))
                let packedPtr := mload(descriptor)
                for { let c := 0 } lt(c, 5) { c := add(c, 1) } {
                    let shift := sub(224, shl(5, c))
                    let total := 0
                    for { let group := 0 } lt(group, 4) { group := add(group, 1) } {
                        let src := add(packedPtr, shl(7, group))
                        let w0 := and(shr(shift, mload(src)), 0xffffffff)
                        let w1 := and(shr(shift, mload(add(src, 32))), 0xffffffff)
                        let w2 := and(shr(shift, mload(add(src, 64))), 0xffffffff)
                        let w3 := and(shr(shift, mload(add(src, 96))), 0xffffffff)
                        total := add(total, add(add(w0, w1), add(w2, w3)))
                        mstore(
                            add(baseWeights, add(shl(7, c), shl(5, group))),
                            or(or(w0, shl(64, w1)), or(shl(128, w2), shl(192, w3)))
                        )
                    }
                    weightSum := or(weightSum, shl(shift, mod(total, 0x7f000001)))
                }
                mstore(add(descriptor, 64), baseWeights)
                mstore(add(descriptor, 96), weightSum)
            }
        }
    }

    // Four-term reversed Kronecker dot products. Each convolution coefficient is
    // at most 4*(p-1)^2 < 2^64. The top 64 bits of low-256 MUL therefore contain
    // the exact four-term dot; no lower lane carries into it. Four group dots
    // sum below 2^66 before the final modular reduction for each coordinate.
    function _prepareBaseRadix64(uint256 packedPtr) internal pure returns (uint256 ptr) {
        assembly ("memory-safe") {
            ptr := mload(0x40)
            mstore(0x40, add(ptr, 640))
            for { let group := 0 } lt(group, 4) { group := add(group, 1) } {
                let src := add(packedPtr, shl(7, group))
                let w0 := mload(src)
                let w1 := mload(add(src, 32))
                let w2 := mload(add(src, 64))
                let w3 := mload(add(src, 96))
                for { let c := 0 } lt(c, 5) { c := add(c, 1) } {
                    let shift := sub(224, shl(5, c))
                    let w :=
                        or(
                            or(
                                and(shr(shift, w0), 0xffffffff),
                                shl(64, and(shr(shift, w1), 0xffffffff))
                            ),
                            or(
                                shl(128, and(shr(shift, w2), 0xffffffff)),
                                shl(192, and(shr(shift, w3), 0xffffffff))
                            )
                        )
                    mstore(add(ptr, add(shl(7, c), shl(5, group))), w)
                }
            }
        }
    }

    function _dotBaseRadix64(uint256 ptr, uint256 w0, uint256 w1)
        internal
        pure
        returns (uint256 out)
    {
        assembly ("memory-safe") {
            // Keep the four fixed spreads explicit: a Yul helper remains four
            // runtime calls under the selected optimizer and adds stack traffic.
            let s0 := and(shr(128, w0), 0xffffffffffffffffffffffffffffffff)
            s0 := and(
                or(s0, shl(64, s0)),
                0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff
            )
            s0 := and(
                or(s0, shl(32, s0)),
                0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff
            )
            let s1 := and(w0, 0xffffffffffffffffffffffffffffffff)
            s1 := and(
                or(s1, shl(64, s1)),
                0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff
            )
            s1 := and(
                or(s1, shl(32, s1)),
                0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff
            )
            let s2 := and(shr(128, w1), 0xffffffffffffffffffffffffffffffff)
            s2 := and(
                or(s2, shl(64, s2)),
                0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff
            )
            s2 := and(
                or(s2, shl(32, s2)),
                0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff
            )
            let s3 := and(w1, 0xffffffffffffffffffffffffffffffff)
            s3 := and(
                or(s3, shl(64, s3)),
                0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff
            )
            s3 := and(
                or(s3, shl(32, s3)),
                0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff
            )
            out := or(
                out,
                shl(
                    224,
                    mod(
                        add(
                            add(
                                shr(192, mul(s0, mload(add(ptr, 0)))),
                                shr(192, mul(s1, mload(add(ptr, 32))))
                            ),
                            add(
                                shr(192, mul(s2, mload(add(ptr, 64)))),
                                shr(192, mul(s3, mload(add(ptr, 96))))
                            )
                        ),
                        0x7f000001
                    )
                )
            )
            out := or(
                out,
                shl(
                    192,
                    mod(
                        add(
                            add(
                                shr(192, mul(s0, mload(add(ptr, 128)))),
                                shr(192, mul(s1, mload(add(ptr, 160))))
                            ),
                            add(
                                shr(192, mul(s2, mload(add(ptr, 192)))),
                                shr(192, mul(s3, mload(add(ptr, 224))))
                            )
                        ),
                        0x7f000001
                    )
                )
            )
            out := or(
                out,
                shl(
                    160,
                    mod(
                        add(
                            add(
                                shr(192, mul(s0, mload(add(ptr, 256)))),
                                shr(192, mul(s1, mload(add(ptr, 288))))
                            ),
                            add(
                                shr(192, mul(s2, mload(add(ptr, 320)))),
                                shr(192, mul(s3, mload(add(ptr, 352))))
                            )
                        ),
                        0x7f000001
                    )
                )
            )
            out := or(
                out,
                shl(
                    128,
                    mod(
                        add(
                            add(
                                shr(192, mul(s0, mload(add(ptr, 384)))),
                                shr(192, mul(s1, mload(add(ptr, 416))))
                            ),
                            add(
                                shr(192, mul(s2, mload(add(ptr, 448)))),
                                shr(192, mul(s3, mload(add(ptr, 480))))
                            )
                        ),
                        0x7f000001
                    )
                )
            )
            out := or(
                out,
                shl(
                    96,
                    mod(
                        add(
                            add(
                                shr(192, mul(s0, mload(add(ptr, 512)))),
                                shr(192, mul(s1, mload(add(ptr, 544))))
                            ),
                            add(
                                shr(192, mul(s2, mload(add(ptr, 576)))),
                                shr(192, mul(s3, mload(add(ptr, 608))))
                            )
                        ),
                        0x7f000001
                    )
                )
            )
        }
    }

    function _evaluateFinalRow16(bytes calldata blob, uint256 offset, uint256 weightsPtr)
        private
        pure
        returns (uint256 out)
    {
        // Final coefficients were canonically validated while observing the
        // transcript. This optional specialization changes only their dot product.
        uint256 src;
        uint256 common;
        bool commonColumns;
        assembly ("memory-safe") {
            src := add(blob.offset, offset)
            let first := calldataload(src)
            let mask := 0x00000000ffffffffffffffffffffffffffffffff000000000000000000000000
            commonColumns := iszero(and(xor(first, calldataload(add(src, 20))), mask))
            if commonColumns {
                let different := 0
                different := or(different, xor(first, calldataload(add(src, 40))))
                different := or(different, xor(first, calldataload(add(src, 60))))
                different := or(different, xor(first, calldataload(add(src, 80))))
                different := or(different, xor(first, calldataload(add(src, 100))))
                different := or(different, xor(first, calldataload(add(src, 120))))
                different := or(different, xor(first, calldataload(add(src, 140))))
                different := or(different, xor(first, calldataload(add(src, 160))))
                different := or(different, xor(first, calldataload(add(src, 180))))
                different := or(different, xor(first, calldataload(add(src, 200))))
                different := or(different, xor(first, calldataload(add(src, 220))))
                different := or(different, xor(first, calldataload(add(src, 240))))
                different := or(different, xor(first, calldataload(add(src, 260))))
                different := or(different, xor(first, calldataload(add(src, 280))))
                different := or(different, xor(first, calldataload(add(src, 300))))
                commonColumns := iszero(and(different, mask))
            }
            common := and(first, mask)
        }
        if (commonColumns) {
            return _evaluateConstantColumnRow(src, weightsPtr, common);
        }
        weightsPtr = _genericRowWeights(weightsPtr);
        assembly ("memory-safe") {
            let M := 0x7f000001
            let c0 := 0
            let c1 := 0
            function accumulate(a, b, w, d0, d1) -> e0, e1 {
                let u :=
                    or(
                        and(shr(224, a), 0xffffffff),
                        or(
                            shl(51, and(shr(192, a), 0xffffffff)),
                            or(
                                shl(102, and(shr(160, a), 0xffffffff)),
                                or(
                                    shl(153, and(shr(128, a), 0xffffffff)),
                                    shl(204, and(shr(96, a), 0xffffffff))
                                )
                            )
                        )
                    )
                e0 := addmod(
                    d0,
                    mulmod(
                        u,
                        mload(w),
                        0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                    ),
                    0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                )
                e1 := addmod(
                    d1,
                    mulmod(
                        and(shr(11, u), 0xfffff00000001ffffe00000003ffffc00000007ffff80000000fffff),
                        mload(add(w, 32)),
                        0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                    ),
                    0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                )

                u := or(
                    and(shr(224, b), 0xffffffff),
                    or(
                        shl(51, and(shr(192, b), 0xffffffff)),
                        or(
                            shl(102, and(shr(160, b), 0xffffffff)),
                            or(
                                shl(153, and(shr(128, b), 0xffffffff)),
                                shl(204, and(shr(96, b), 0xffffffff))
                            )
                        )
                    )
                )
                e0 := addmod(
                    e0,
                    mulmod(
                        u,
                        mload(add(w, 64)),
                        0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                    ),
                    0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                )
                e1 := addmod(
                    e1,
                    mulmod(
                        and(shr(11, u), 0xfffff00000001ffffe00000003ffffc00000007ffff80000000fffff),
                        mload(add(w, 96)),
                        0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                    ),
                    0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                )
            }
            c0, c1 :=
                accumulate(
                calldataload(add(src, 0)),
                calldataload(add(src, 20)),
                add(weightsPtr, 0),
                c0,
                c1
            )
            c0, c1 :=
                accumulate(
                calldataload(add(src, 40)),
                calldataload(add(src, 60)),
                add(weightsPtr, 128),
                c0,
                c1
            )
            c0, c1 :=
                accumulate(
                calldataload(add(src, 80)),
                calldataload(add(src, 100)),
                add(weightsPtr, 256),
                c0,
                c1
            )
            c0, c1 :=
                accumulate(
                calldataload(add(src, 120)),
                calldataload(add(src, 140)),
                add(weightsPtr, 384),
                c0,
                c1
            )
            c0, c1 :=
                accumulate(
                calldataload(add(src, 160)),
                calldataload(add(src, 180)),
                add(weightsPtr, 512),
                c0,
                c1
            )
            c0, c1 :=
                accumulate(
                calldataload(add(src, 200)),
                calldataload(add(src, 220)),
                add(weightsPtr, 640),
                c0,
                c1
            )
            c0, c1 :=
                accumulate(
                calldataload(add(src, 240)),
                calldataload(add(src, 260)),
                add(weightsPtr, 768),
                c0,
                c1
            )
            c0, c1 :=
                accumulate(
                calldataload(add(src, 280)),
                calldataload(add(src, 300)),
                add(weightsPtr, 896),
                c0,
                c1
            )
            // Full/high products obey polynomial reduction modulo N=Q^5+Q^2-1.
            // Subtracting the high20-bit product times2^22 leaves low11-bit
            // cross terms. Per term R<=8723116322817. Across16products, each
            // reduced coefficient lies in[-64R,96R]. B=P*2^18 makes both this
            // remainder and the high-product digits strictly within[0,Q),Q=2^51.
            // Recombination modulo P cancels B; no radix carry information is lost.
            c0 := addmod(
                c0,
                sub(
                    0x800000000000000000000000000000000000003fffffffffffffffffffffffff,
                    mulmod(
                        c1,
                        0x400000,
                        0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                    )
                ),
                0x800000000000000000000000000000000000003fffffffffffffffffffffffff
            )
            c0 := addmod(
                c0,
                0x1fc00000400003f800000800007f00000100000fe00000200001fc0000040000,
                0x800000000000000000000000000000000000003fffffffffffffffffffffffff
            )
            c1 := addmod(
                c1,
                0x1fc00000400003f800000800007f00000100000fe00000200001fc0000040000,
                0x800000000000000000000000000000000000003fffffffffffffffffffffffff
            )
            let r0 :=
                mod(
                    add(
                        and(shr(0, c0), 0x7ffffffffffff),
                        shl(22, and(shr(0, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r1 :=
                mod(
                    add(
                        and(shr(51, c0), 0x7ffffffffffff),
                        shl(22, and(shr(51, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r2 :=
                mod(
                    add(
                        and(shr(102, c0), 0x7ffffffffffff),
                        shl(22, and(shr(102, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r3 :=
                mod(
                    add(
                        and(shr(153, c0), 0x7ffffffffffff),
                        shl(22, and(shr(153, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r4 :=
                mod(
                    add(
                        and(shr(204, c0), 0x7ffffffffffff),
                        shl(22, and(shr(204, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            out := or(
                shl(224, r0),
                or(shl(192, r1), or(shl(160, r2), or(shl(128, r3), shl(96, r4))))
            )
        }
    }

    function _evaluateFinalRow16Memory(bytes memory blob, uint256 offset, uint256 weightsPtr)
        private
        pure
        returns (uint256 out)
    {
        // Final coefficients were canonically validated while observing the
        // transcript. This optional specialization changes only their dot product.
        uint256 src;
        uint256 common;
        bool commonColumns;
        assembly ("memory-safe") {
            src := add(add(blob, 32), offset)
            let first := mload(src)
            let mask := 0x00000000ffffffffffffffffffffffffffffffff000000000000000000000000
            commonColumns := iszero(and(xor(first, mload(add(src, 20))), mask))
            if commonColumns {
                let different := 0
                different := or(different, xor(first, mload(add(src, 40))))
                different := or(different, xor(first, mload(add(src, 60))))
                different := or(different, xor(first, mload(add(src, 80))))
                different := or(different, xor(first, mload(add(src, 100))))
                different := or(different, xor(first, mload(add(src, 120))))
                different := or(different, xor(first, mload(add(src, 140))))
                different := or(different, xor(first, mload(add(src, 160))))
                different := or(different, xor(first, mload(add(src, 180))))
                different := or(different, xor(first, mload(add(src, 200))))
                different := or(different, xor(first, mload(add(src, 220))))
                different := or(different, xor(first, mload(add(src, 240))))
                different := or(different, xor(first, mload(add(src, 260))))
                different := or(different, xor(first, mload(add(src, 280))))
                different := or(different, xor(first, mload(add(src, 300))))
                commonColumns := iszero(and(different, mask))
            }
            common := and(first, mask)
        }
        if (commonColumns) {
            return _evaluateConstantColumnRowMemory(src, weightsPtr, common);
        }
        weightsPtr = _genericRowWeights(weightsPtr);
        assembly ("memory-safe") {
            let M := 0x7f000001
            let c0 := 0
            let c1 := 0
            function accumulate(a, b, w, d0, d1) -> e0, e1 {
                let u :=
                    or(
                        and(shr(224, a), 0xffffffff),
                        or(
                            shl(51, and(shr(192, a), 0xffffffff)),
                            or(
                                shl(102, and(shr(160, a), 0xffffffff)),
                                or(
                                    shl(153, and(shr(128, a), 0xffffffff)),
                                    shl(204, and(shr(96, a), 0xffffffff))
                                )
                            )
                        )
                    )
                e0 := addmod(
                    d0,
                    mulmod(
                        u,
                        mload(w),
                        0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                    ),
                    0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                )
                e1 := addmod(
                    d1,
                    mulmod(
                        and(shr(11, u), 0xfffff00000001ffffe00000003ffffc00000007ffff80000000fffff),
                        mload(add(w, 32)),
                        0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                    ),
                    0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                )

                u := or(
                    and(shr(224, b), 0xffffffff),
                    or(
                        shl(51, and(shr(192, b), 0xffffffff)),
                        or(
                            shl(102, and(shr(160, b), 0xffffffff)),
                            or(
                                shl(153, and(shr(128, b), 0xffffffff)),
                                shl(204, and(shr(96, b), 0xffffffff))
                            )
                        )
                    )
                )
                e0 := addmod(
                    e0,
                    mulmod(
                        u,
                        mload(add(w, 64)),
                        0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                    ),
                    0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                )
                e1 := addmod(
                    e1,
                    mulmod(
                        and(shr(11, u), 0xfffff00000001ffffe00000003ffffc00000007ffff80000000fffff),
                        mload(add(w, 96)),
                        0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                    ),
                    0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                )
            }
            c0, c1 :=
                accumulate(mload(add(src, 0)), mload(add(src, 20)), add(weightsPtr, 0), c0, c1)
            c0, c1 :=
                accumulate(mload(add(src, 40)), mload(add(src, 60)), add(weightsPtr, 128), c0, c1)
            c0, c1 :=
                accumulate(mload(add(src, 80)), mload(add(src, 100)), add(weightsPtr, 256), c0, c1)
            c0, c1 :=
                accumulate(mload(add(src, 120)), mload(add(src, 140)), add(weightsPtr, 384), c0, c1)
            c0, c1 :=
                accumulate(mload(add(src, 160)), mload(add(src, 180)), add(weightsPtr, 512), c0, c1)
            c0, c1 :=
                accumulate(mload(add(src, 200)), mload(add(src, 220)), add(weightsPtr, 640), c0, c1)
            c0, c1 :=
                accumulate(mload(add(src, 240)), mload(add(src, 260)), add(weightsPtr, 768), c0, c1)
            c0, c1 :=
                accumulate(mload(add(src, 280)), mload(add(src, 300)), add(weightsPtr, 896), c0, c1)
            // Full/high products obey polynomial reduction modulo N=Q^5+Q^2-1.
            // Subtracting the high20-bit product times2^22 leaves low11-bit
            // cross terms. Per term R<=8723116322817. Across16products, each
            // reduced coefficient lies in[-64R,96R]. B=P*2^18 makes both this
            // remainder and the high-product digits strictly within[0,Q),Q=2^51.
            // Recombination modulo P cancels B; no radix carry information is lost.
            c0 := addmod(
                c0,
                sub(
                    0x800000000000000000000000000000000000003fffffffffffffffffffffffff,
                    mulmod(
                        c1,
                        0x400000,
                        0x800000000000000000000000000000000000003fffffffffffffffffffffffff
                    )
                ),
                0x800000000000000000000000000000000000003fffffffffffffffffffffffff
            )
            c0 := addmod(
                c0,
                0x1fc00000400003f800000800007f00000100000fe00000200001fc0000040000,
                0x800000000000000000000000000000000000003fffffffffffffffffffffffff
            )
            c1 := addmod(
                c1,
                0x1fc00000400003f800000800007f00000100000fe00000200001fc0000040000,
                0x800000000000000000000000000000000000003fffffffffffffffffffffffff
            )
            let r0 :=
                mod(
                    add(
                        and(shr(0, c0), 0x7ffffffffffff),
                        shl(22, and(shr(0, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r1 :=
                mod(
                    add(
                        and(shr(51, c0), 0x7ffffffffffff),
                        shl(22, and(shr(51, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r2 :=
                mod(
                    add(
                        and(shr(102, c0), 0x7ffffffffffff),
                        shl(22, and(shr(102, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r3 :=
                mod(
                    add(
                        and(shr(153, c0), 0x7ffffffffffff),
                        shl(22, and(shr(153, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            let r4 :=
                mod(
                    add(
                        and(shr(204, c0), 0x7ffffffffffff),
                        shl(22, and(shr(204, c1), 0x7ffffffffffff))
                    ),
                    M
                )
            out := or(
                shl(224, r0),
                or(shl(192, r1), or(shl(160, r2), or(shl(128, r3), shl(96, r4))))
            )
        }
    }
}
