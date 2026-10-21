// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as F } from "../src/field/KoalaBearExt5.sol";
import {
    WhirVerifierUtils5 as U
} from "../src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirVerifierUtils5.sol";
import {
    QuinticTransportCodec as C
} from "../src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/QuinticTransportCodec.sol";

contract QuinticQuartetCacheHarness {
    function rows(bytes[] calldata encoded, uint256[16] memory weights)
        external
        pure
        returns (bytes32[] memory digests, uint256[] memory values)
    {
        uint256 ptr = U._prepareRowWeights(_copyWeightsUnaligned(weights));
        digests = new bytes32[](encoded.length);
        values = new uint256[](encoded.length);
        for (uint256 i; i < encoded.length; ++i) {
            (uint256[] memory offsets, uint256 end) = C.rowOffsets(encoded[i], 0, 1, 16);
            require(end == encoded[i].length);
            (digests[i], values[i]) = U._hashAndEvaluateCompactRow16(encoded[i], offsets[0], ptr);
        }
    }

    function rowsLazy(bytes[] calldata encoded, uint256[16] memory weights)
        external
        pure
        returns (bytes32[] memory digests, uint256[] memory values, uint256[] memory states)
    {
        uint256 packedPtr = _copyWeightsUnaligned(weights);
        // Dirty temporary memory makes initialization independent of fresh zeros.
        assembly ("memory-safe") {
            let free := or(mload(0x40), 1)
            mstore(0x40, free)
            for { let i := 0 } lt(i, 1024) { i := add(i, 32) } {
                mstore(add(free, i), not(0))
            }
        }
        uint256 ptr = U._prepareRowWeightsLazy(packedPtr);
        uint256 descriptor = ~ptr;
        digests = new bytes32[](encoded.length);
        values = new uint256[](encoded.length);
        states = new uint256[](encoded.length + 1);
        for (uint256 i; i < encoded.length; ++i) {
            uint256 matrixBefore;
            uint256 cacheBefore;
            assembly ("memory-safe") {
                matrixBefore := mload(add(descriptor, 32))
                cacheBefore := mload(add(descriptor, 64))
            }
            if (i == 0) require(matrixBefore == 0 && cacheBefore == 0, "INIT");
            (uint256[] memory offsets, uint256 end) = C.rowOffsets(encoded[i], 0, 1, 16);
            require(end == encoded[i].length);
            (digests[i], values[i]) = U._hashAndEvaluateCompactRow16(encoded[i], offsets[0], ptr);
            uint256 matrixAfter;
            uint256 cacheAfter;
            assembly ("memory-safe") {
                matrixAfter := mload(add(descriptor, 32))
                cacheAfter := mload(add(descriptor, 64))
            }
            require(matrixBefore == 0 || matrixBefore == matrixAfter, "MATRIX_REUSE");
            require(cacheBefore == 0 || cacheBefore == cacheAfter, "CACHE_REUSE");
            states[i + 1] = (matrixAfter != 0 ? 1 : 0) | (cacheAfter != 0 ? 2 : 0);
        }
    }

    function _copyWeightsUnaligned(uint256[16] memory weights) private pure returns (uint256 ptr) {
        assembly ("memory-safe") {
            ptr := or(mload(0x40), 1)
            mstore(0x40, add(ptr, 512))
            for { let i := 0 } lt(i, 512) { i := add(i, 32) } {
                mstore(add(ptr, i), mload(add(weights, i)))
            }
        }
    }

    function finalBoth(bytes calldata blob, uint256[] memory point)
        external
        pure
        returns (uint256 calldataValue, uint256 memoryValue)
    {
        require(blob.length == 1283 && point.length == 6);
        calldataValue = U.evaluateFinalValueBlob64Dim6(blob, 3, point, 0);
        bytes memory copied = blob;
        memoryValue = U.evaluateFinalValueMemory64Dim6(copied, 3, point, 0);
    }
}

contract QuinticQuartetCacheTest is Test {
    uint256 private constant P = 0x7f000001;
    QuinticQuartetCacheHarness private h;

    function setUp() external {
        h = new QuinticQuartetCacheHarness();
    }

    function testFuzzMixedRowsShareQuartetCache(bytes32 seed) external view {
        uint256[16] memory weights;
        for (uint256 i; i < 16; ++i) {
            weights[i] = _element(seed, 1000 + i);
        }
        _checkMixed(seed, weights, false, false);
        _checkMixed(seed, weights, false, true);
    }

    function testMixedRowsMaximumAndZeroWeights() external view {
        uint256[16] memory weights;
        for (uint256 i; i < 16; ++i) {
            weights[i] = _maximum();
        }
        _checkMixed(bytes32(uint256(1)), weights, true, false);
        _checkMixed(bytes32(uint256(1)), weights, true, true);
        for (uint256 i; i < 16; ++i) {
            weights[i] = 0;
        }
        _checkMixed(bytes32(uint256(2)), weights, false, false);
        _checkMixed(bytes32(uint256(2)), weights, false, true);
    }

    function testFuzzMixedRowsUnitWeightSum(bytes32 seed) external view {
        uint256[16] memory weights;
        uint256 sum;
        for (uint256 i; i < 15; ++i) {
            weights[i] = _element(seed, 1000 + i);
            sum = F.add(sum, weights[i]);
        }
        weights[15] = F.sub(F.ONE, sum);
        _checkMixed(seed, weights, false, false);
        _checkMixed(seed, weights, false, true);
    }

    function testFuzzFinalMixedBlocksBothCallers(bytes32 seed) external view {
        uint256[] memory point = new uint256[](6);
        for (uint256 i; i < 6; ++i) {
            point[i] = _element(seed, 1000 + i);
        }
        uint256 lower = (uint256(1) << 224) - (uint256(1) << 96);
        for (uint256 genericBlock; genericBlock < 4; ++genericBlock) {
            uint256[] memory values = new uint256[](64);
            for (uint256 i; i < 64; ++i) {
                uint256 blockIndex = i / 16;
                values[i] = _element(seed, i);
                if (blockIndex != genericBlock) {
                    values[i] = (values[i] & ~lower) | (_element(seed, 100 + blockIndex) & lower);
                }
            }
            _checkFinal(values, point);
        }
    }

    function testFinalBothCallersAllMaximumAndZero() external view {
        uint256[] memory values = new uint256[](64);
        uint256[] memory point = new uint256[](6);
        for (uint256 i; i < 6; ++i) {
            point[i] = _maximum();
        }
        for (uint256 i; i < 64; ++i) {
            values[i] = _maximum();
        }
        _checkFinal(values, point);
        for (uint256 i; i < 64; ++i) {
            values[i] = 0;
        }
        _checkFinal(values, point);
    }

    function _checkMixed(bytes32 seed, uint256[16] memory weights, bool maximum, bool constantFirst)
        private
        view
    {
        uint256[8] memory masks = constantFirst
            ? [uint256(30), 30, 31, 0, 0, 7, 0, 15]
            : [uint256(0), 30, 0, 7, 31, 30, 0, 15];
        uint256[] memory expectedStates = new uint256[](9);
        bytes[] memory rows = new bytes[](8);
        bytes32[] memory expectedHashes = new bytes32[](8);
        uint256[] memory expected = new uint256[](8);
        for (uint256 r; r < 8; ++r) {
            uint256 mask = masks[r];
            uint256 valueMask = r == 2 && mask == 0 ? 30 : mask;
            uint256 common = maximum ? _maximum() : _element(seed, 200 + r);
            uint256[] memory values = new uint256[](16);
            bytes memory raw = hex"00";
            for (uint256 i; i < 16; ++i) {
                values[i] = maximum ? _maximum() : _element(seed, 16 * r + i);
                for (uint256 c; c < 5; ++c) {
                    if ((valueMask >> c) & 1 != 0) {
                        uint256 lane = uint256(0xffffffff) << (224 - 32 * c);
                        values[i] = (values[i] & ~lane) | (common & lane);
                    }
                }
                expected[r] = F.add(expected[r], F.mulReference(weights[i], values[i]));
                raw = bytes.concat(raw, bytes20(bytes32(values[i])));
            }
            bool constantColumns = true;
            uint256 lower = (uint256(1) << 224) - (uint256(1) << 96);
            for (uint256 i = 1; i < 16; ++i) {
                if ((values[0] & lower) != (values[i] & lower)) constantColumns = false;
            }
            expectedStates[r + 1] = expectedStates[r] | (constantColumns ? 2 : 1);
            rows[r] = _encode(values, mask);
            expectedHashes[r] = bytes32(bytes20(keccak256(raw)));
        }
        (bytes32[] memory hashes, uint256[] memory actual) = h.rows(rows, weights);
        (bytes32[] memory lazyHashes, uint256[] memory lazyActual, uint256[] memory states) =
            h.rowsLazy(rows, weights);
        assertEq(states, expectedStates);
        for (uint256 i; i < 8; ++i) {
            assertEq(actual[i], expected[i]);
            assertEq(hashes[i], expectedHashes[i]);
            assertEq(lazyActual[i], expected[i]);
            assertEq(lazyHashes[i], expectedHashes[i]);
            F.validatePacked(actual[i]);
            F.validatePacked(lazyActual[i]);
        }
    }

    function _checkFinal(uint256[] memory values, uint256[] memory point) private view {
        bytes memory blob = hex"123456";
        for (uint256 i; i < 64; ++i) {
            blob = bytes.concat(blob, bytes20(bytes32(values[i])));
        }
        (uint256 a, uint256 b) = h.finalBoth(blob, point);
        uint256 size = 64;
        for (uint256 d; d < 6; ++d) {
            size >>= 1;
            for (uint256 i; i < size; ++i) {
                values[i] =
                    F.add(values[i], F.mulReference(point[d], F.sub(values[i + size], values[i])));
            }
        }
        assertEq(a, values[0]);
        assertEq(b, values[0]);
        F.validatePacked(a);
        F.validatePacked(b);
    }

    function _encode(uint256[] memory values, uint256 mask)
        private
        pure
        returns (bytes memory out)
    {
        out = abi.encodePacked(uint8(mask));
        if (mask == 0) {
            for (uint256 i; i < values.length; ++i) {
                out = bytes.concat(out, bytes20(bytes32(values[i])));
            }
        } else {
            for (uint256 c; c < 5; ++c) {
                uint256 count = (mask >> c) & 1 != 0 ? 1 : values.length;
                for (uint256 i; i < count; ++i) {
                    out = bytes.concat(out, bytes4(uint32(values[i] >> (224 - 32 * c))));
                }
            }
        }
    }

    function _element(bytes32 seed, uint256 i) private pure returns (uint256 value) {
        for (uint256 c; c < 5; ++c) {
            value |= (uint256(keccak256(abi.encode(seed, i, c))) % P) << (224 - 32 * c);
        }
    }

    function _maximum() private pure returns (uint256 value) {
        for (uint256 c; c < 5; ++c) {
            value |= (P - 1) << (224 - 32 * c);
        }
    }
}
