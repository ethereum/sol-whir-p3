// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as F } from "../src/field/KoalaBearExt5.sol";
import {
    WhirVerifierUtils5 as U
} from "../src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirVerifierUtils5.sol";

contract QuinticHighProductRowHarness {
    function evaluateFinal(bytes calldata blob, uint256[] memory point)
        external
        pure
        returns (uint256)
    {
        require(blob.length == 1283 && point.length == 6);
        return U.evaluateFinalValueBlob64Dim6(blob, 3, point, 0);
    }

    function evaluate(bytes calldata blob, uint256[16] memory weights)
        external
        pure
        returns (bytes32 digest, uint256 value)
    {
        require(blob.length == 323, "ROW_LENGTH");
        uint256 wp;
        assembly ("memory-safe") { wp := weights }
        return _evaluatePrepared(blob, U._prepareRowWeights(wp));
    }

    function evaluateTwice(bytes calldata first, bytes calldata second, uint256[16] memory weights)
        external
        pure
        returns (uint256 a, uint256 b)
    {
        require(first.length == 323 && second.length == 323);
        uint256 wp;
        assembly ("memory-safe") { wp := weights }
        uint256 prepared = U._prepareRowWeights(wp);
        (, a) = _evaluatePrepared(first, prepared);
        (, b) = _evaluatePrepared(second, prepared);
    }

    function _evaluatePrepared(bytes calldata blob, uint256 prepared)
        private
        pure
        returns (bytes32, uint256)
    {
        return U._hashAndEvaluateExtensionRow16Blob(blob, 3, prepared);
    }
}

contract QuinticHighProductRowTest is Test {
    uint256 private constant P = 0x7f000001;
    QuinticHighProductRowHarness private h;

    function setUp() external {
        h = new QuinticHighProductRowHarness();
    }

    function testFuzzStreamingRow(bytes32 seed) external view {
        uint256[16] memory weights;
        uint256[16] memory values;
        for (uint256 i; i < 16; ++i) {
            weights[i] = _element(seed, i);
            values[i] = _element(seed, i + 16);
        }
        _check(weights, values);
    }

    function testFuzzConstantColumnRows(bytes32 seed) external view {
        uint256[16] memory weights;
        uint256[16] memory values;
        uint256 common = _element(seed, 100) & ((uint256(1) << 224) - (uint256(1) << 96));
        for (uint256 i; i < 16; ++i) {
            weights[i] = _element(seed, i);
            values[i] = common | ((_element(seed, i + 16) >> 224) << 224);
        }
        _check(weights, values);
        // Break just one common column and require the generic path to agree.
        uint256 position = uint256(seed) % 16;
        values[position] ^= uint256(1) << 96;
        if (((values[position] >> 96) & 0xffffffff) < P) _check(weights, values);
    }

    function testFuzzConstantColumnsUnitWeightSum(bytes32 seed) external view {
        uint256[16] memory weights;
        uint256[16] memory values;
        uint256 sum;
        uint256 common = _element(seed, 100) & ((uint256(1) << 224) - (uint256(1) << 96));
        for (uint256 i; i < 15; ++i) {
            weights[i] = _element(seed, i);
            sum = F.add(sum, weights[i]);
        }
        weights[15] = F.sub(F.ONE, sum);
        for (uint256 i; i < 16; ++i) {
            values[i] = common | ((_element(seed, i + 16) >> 224) << 224);
        }
        _check(weights, values);
    }

    function testFuzzSharedConstantColumnCache(bytes32 seed) external view {
        uint256[16] memory weights;
        uint256[16] memory first;
        uint256[16] memory second;
        uint256 mask = (uint256(1) << 224) - (uint256(1) << 96);
        uint256 c0 = _element(seed, 100) & mask;
        uint256 c1 = _element(seed, 101) & mask;
        uint256 expected0;
        uint256 expected1;
        for (uint256 i; i < 16; ++i) {
            weights[i] = _element(seed, i);
            first[i] = c0 | ((_element(seed, i + 16) >> 224) << 224);
            second[i] = c1 | ((_element(seed, i + 32) >> 224) << 224);
            expected0 = F.add(expected0, F.mulReference(weights[i], first[i]));
            expected1 = F.add(expected1, F.mulReference(weights[i], second[i]));
        }
        (uint256 a, uint256 b) = h.evaluateTwice(_blob(first), _blob(second), weights);
        assertEq(a, expected0);
        assertEq(b, expected1);
    }

    function testStreamingMaximumAndZero() external view {
        uint256[16] memory weights;
        uint256[16] memory values;
        uint256 maximum;
        for (uint256 j; j < 5; ++j) {
            maximum |= (P - 1) << (224 - 32 * j);
        }
        for (uint256 i; i < 16; ++i) {
            weights[i] = maximum;
            values[i] = maximum;
        }
        _check(weights, values);
        for (uint256 i; i < 16; ++i) {
            values[i] = 0;
        }
        _check(weights, values);
    }

    function testStreamingEveryBasisPair() external view {
        uint256[16] memory weights;
        uint256[16] memory values;
        for (uint256 a; a < 5; ++a) {
            for (uint256 b; b < 5; ++b) {
                for (uint256 i; i < 16; ++i) {
                    weights[i] = (P - 1) << (224 - 32 * a);
                    values[i] = (P - 1) << (224 - 32 * b);
                }
                _check(weights, values);
            }
        }
    }

    function testStreamingRejectsEveryLaneAndPosition() external {
        uint256[16] memory weights;
        uint256[16] memory values;
        for (uint256 i; i < 16; ++i) {
            for (uint256 j; j < 5; ++j) {
                for (uint256 k; k < 3; ++k) {
                    uint256 bad = (k == 0 ? P : k == 1 ? uint256(0x80000000) : uint256(0xffffffff))
                        << (224 - 32 * j);
                    values[i] = bad;
                    bytes memory blob = _blob(values);
                    vm.expectRevert(abi.encodeWithSelector(bytes4(0xd53cfe5c), bad));
                    h.evaluate(blob, weights);
                }
            }
            values[i] = 0;
        }
    }

    function testHighProductCarryBoundaries() external view {
        uint256[16] memory weights;
        uint256[16] memory values;
        uint256[5] memory edges = [
            uint256(P - 2), uint256(2047), uint256(2048), uint256((1 << 22) - 1), uint256(1 << 22)
        ];
        for (uint256 a; a < 5; ++a) {
            for (uint256 b; b < 5; ++b) {
                for (uint256 i; i < 16; ++i) {
                    weights[i] = edges[a] << (224 - 32 * (i % 5));
                    values[i] = edges[b] << (224 - 32 * ((i + 2) % 5));
                }
                _check(weights, values);
            }
        }
        for (uint256 a; a < 5; ++a) {
            for (uint256 b; b < 5; ++b) {
                for (uint256 i; i < 16; ++i) {
                    weights[i] = (P - 2) << (224 - 32 * a);
                    values[i] = (P - 2) << (224 - 32 * b);
                }
                _check(weights, values);
            }
        }
    }

    function testFuzzFinal64ConstantColumns(bytes32 seed) external view {
        uint256[] memory point = new uint256[](6);
        uint256[] memory values = new uint256[](64);
        bytes memory blob = hex"123456";
        uint256 mask = (uint256(1) << 224) - (uint256(1) << 96);
        for (uint256 i; i < 6; ++i) {
            point[i] = _element(seed, i);
        }
        for (uint256 i; i < 64; ++i) {
            // Distinct common columns per 16-value block cover lazy-cache reuse.
            values[i] =
                (_element(seed, 100 + i / 16) & mask) | ((_element(seed, i + 6) >> 224) << 224);
            blob = bytes.concat(blob, bytes20(bytes32(values[i])));
        }
        uint256 actual = h.evaluateFinal(blob, point);
        uint256 size = 64;
        for (uint256 dimension; dimension < 6; ++dimension) {
            size >>= 1;
            for (uint256 i; i < size; ++i) {
                values[i] = F.add(
                    values[i], F.mulReference(point[dimension], F.sub(values[i + size], values[i]))
                );
            }
        }
        assertEq(actual, values[0]);
    }

    function testFuzzFinal64Values(bytes32 seed) external view {
        uint256[] memory point = new uint256[](6);
        uint256[] memory values = new uint256[](64);
        bytes memory blob = hex"123456";
        for (uint256 i; i < 6; ++i) {
            point[i] = _element(seed, i);
        }
        for (uint256 i; i < 64; ++i) {
            values[i] = _element(seed, i + 6);
            blob = bytes.concat(blob, bytes20(bytes32(values[i])));
        }
        uint256 actual = h.evaluateFinal(blob, point);
        uint256 size = 64;
        for (uint256 dimension; dimension < 6; ++dimension) {
            size >>= 1;
            for (uint256 i; i < size; ++i) {
                values[i] = F.add(
                    values[i], F.mulReference(point[dimension], F.sub(values[i + size], values[i]))
                );
            }
        }
        assertEq(actual, values[0]);
        F.validatePacked(actual);
    }

    function _check(uint256[16] memory weights, uint256[16] memory values) private view {
        bytes memory blob = _blob(values);
        bytes memory hashed = hex"00";
        uint256 expected;
        for (uint256 i; i < 16; ++i) {
            expected = F.add(expected, F.mulReference(values[i], weights[i]));
            hashed = bytes.concat(hashed, bytes20(bytes32(values[i])));
        }
        (bytes32 digest, uint256 result) = h.evaluate(blob, weights);
        assertEq(digest, bytes32(bytes20(keccak256(hashed))));
        assertEq(result, expected);
        F.validatePacked(result);
    }

    function _blob(uint256[16] memory values) private pure returns (bytes memory blob) {
        blob = hex"123456";
        for (uint256 i; i < 16; ++i) {
            blob = bytes.concat(blob, bytes20(bytes32(values[i])));
        }
    }

    function _element(bytes32 seed, uint256 i) private pure returns (uint256 value) {
        for (uint256 j; j < 5; ++j) {
            value |= (uint256(keccak256(abi.encode(seed, i, j))) % P) << (224 - 32 * j);
        }
    }
}
