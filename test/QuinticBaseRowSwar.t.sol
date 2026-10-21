// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as F } from "../src/field/KoalaBearExt5.sol";
import {
    WhirVerifierUtils5 as U
} from "../src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirVerifierUtils5.sol";

contract QuinticBaseRowSwarHarness {
    function evaluate(bytes calldata blob, uint256[16] memory weights)
        external
        pure
        returns (bytes32 digest, uint256 value)
    {
        require(blob.length == 67);
        uint256 wp;
        assembly ("memory-safe") { wp := weights }
        return U._hashAndEvaluateBaseRow16Blob(blob, 3, U._prepareBaseRadix64(wp));
    }
}

contract QuinticBaseRowSwarTest is Test {
    uint256 constant P = 0x7f000001;
    QuinticBaseRowSwarHarness h;

    function setUp() external {
        h = new QuinticBaseRowSwarHarness();
    }

    function testFuzzBaseRowDot(bytes32 seed) external view {
        uint256[16] memory weights;
        uint256[16] memory values;
        for (uint256 i; i < 16; ++i) {
            for (uint256 j; j < 5; ++j) {
                weights[i] |= (uint256(keccak256(abi.encode(seed, i, j))) % P) << (224 - 32 * j);
            }
            values[i] = uint256(keccak256(abi.encode(seed, i))) % P;
        }
        _check(weights, values);
    }

    function testFuzzBaseRowCanonicalPredicate(uint256 first, uint256 second) external {
        uint256[16] memory weights;
        bytes memory data = abi.encodePacked(hex"123456", first, second);
        uint256 invalid;
        for (uint256 word; word < 2; ++word) {
            uint256 w = word == 0 ? first : second;
            for (uint256 lane; lane < 8; ++lane) {
                if ((w >> (32 * lane)) & 0xffffffff >= P) {
                    invalid = word + 1;
                    break;
                }
            }
            if (invalid != 0) break;
        }
        if (invalid != 0) {
            vm.expectRevert(
                abi.encodeWithSelector(bytes4(0xf512b678), invalid == 1 ? first : second)
            );
            h.evaluate(data, weights);
        } else {
            (bytes32 digest, uint256 value) = h.evaluate(data, weights);
            assertEq(digest, bytes32(bytes20(keccak256(abi.encodePacked(hex"00", first, second)))));
            assertEq(value, 0);
        }
    }

    function testBaseRowEveryInvalidLaneAndBoundary() external {
        uint256[16] memory weights;
        uint256[16] memory values;
        for (uint256 i; i < 16; ++i) {
            values[i] = P - 1;
        }
        _check(weights, values);
        for (uint256 i; i < 16; ++i) {
            for (uint256 k; k < 4; ++k) {
                values[i] = k == 0 ? P : k == 1 ? 0x80000000 : k == 2 ? 0xffffffff : P + 1;
                bytes memory blob = _blob(values);
                uint256 word;
                assembly ("memory-safe") { word := mload(add(add(blob, 35), mul(div(i, 8), 32))) }
                vm.expectRevert(abi.encodeWithSelector(bytes4(0xf512b678), word));
                h.evaluate(blob, weights);
            }
            values[i] = P - 1;
        }
    }

    function testBaseRowMaximumAndZero() external view {
        uint256[16] memory weights;
        uint256[16] memory values;
        for (uint256 i; i < 16; ++i) {
            values[i] = P - 1;
            for (uint256 j; j < 5; ++j) {
                weights[i] |= (P - 1) << (224 - 32 * j);
            }
        }
        _check(weights, values);
        for (uint256 i; i < 16; ++i) {
            values[i] = 0;
        }
        _check(weights, values);
    }

    function _check(uint256[16] memory weights, uint256[16] memory values) private view {
        uint256 expected;
        bytes memory hashed = hex"00";
        for (uint256 i; i < 16; ++i) {
            expected = F.add(expected, F.mulReference(weights[i], values[i] << 224));
            hashed = bytes.concat(hashed, bytes4(uint32(values[i])));
        }
        (bytes32 digest, uint256 value) = h.evaluate(_blob(values), weights);
        assertEq(digest, bytes32(bytes20(keccak256(hashed))));
        assertEq(value, expected);
    }

    function _blob(uint256[16] memory values) private pure returns (bytes memory blob) {
        blob = hex"123456";
        for (uint256 i; i < 16; ++i) {
            blob = bytes.concat(blob, bytes4(uint32(values[i])));
        }
    }
}
