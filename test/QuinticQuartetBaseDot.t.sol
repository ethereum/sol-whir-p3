// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as F } from "../src/field/KoalaBearExt5.sol";
import {
    WhirVerifierUtils5 as U
} from "../src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirVerifierUtils5.sol";

contract QuartetBaseDotHarness {
    function evaluate(uint256[16] memory weights, uint256 w0, uint256 w1)
        external
        pure
        returns (uint256)
    {
        uint256 ptr;
        assembly ("memory-safe") { ptr := weights }
        return U._dotBaseRadix64(U._prepareBaseRadix64(ptr), w0, w1);
    }
}

contract QuinticQuartetBaseDotTest is Test {
    uint256 constant P = 0x7f000001;
    QuartetBaseDotHarness h;

    function setUp() external {
        h = new QuartetBaseDotHarness();
    }

    function testFuzzQuartetIndependentSchoolbook(bytes32 seed) external view {
        (uint256[16] memory weights, uint256[16] memory scalars) = _inputs(seed);
        _check(weights, scalars);
    }

    function testQuartetBasisZeroAndMax() external view {
        uint256[16] memory weights;
        uint256[16] memory scalars;
        _check(weights, scalars);
        for (uint256 i; i < 16; ++i) {
            scalars[i] = P - 1;
            for (uint256 c; c < 5; ++c) {
                weights[i] |= (P - 1) << (224 - 32 * c);
            }
        }
        _check(weights, scalars);
        for (uint256 i; i < 16; ++i) {
            for (uint256 c; c < 5; ++c) {
                uint256[16] memory basis;
                basis[i] = (P - 1) << (224 - 32 * c);
                _check(basis, scalars);
            }
        }
    }

    function _inputs(bytes32 seed)
        private
        pure
        returns (uint256[16] memory weights, uint256[16] memory scalars)
    {
        for (uint256 i; i < 16; ++i) {
            scalars[i] = uint256(keccak256(abi.encode(seed, i))) % P;
            for (uint256 c; c < 5; ++c) {
                weights[i] |= (uint256(keccak256(abi.encode(seed, i, c))) % P) << (224 - 32 * c);
            }
        }
    }

    function _pack(uint256[16] memory scalars) private pure returns (uint256 w0, uint256 w1) {
        for (uint256 i; i < 8; ++i) {
            w0 |= scalars[i] << (224 - 32 * i);
            w1 |= scalars[8 + i] << (224 - 32 * i);
        }
    }

    function _check(uint256[16] memory weights, uint256[16] memory scalars) private view {
        uint256 expected;
        for (uint256 c; c < 5; ++c) {
            uint256 acc;
            for (uint256 i; i < 16; ++i) {
                acc = addmod(
                    acc, mulmod((weights[i] >> (224 - 32 * c)) & 0xffffffff, scalars[i], P), P
                );
            }
            expected |= acc << (224 - 32 * c);
        }
        (uint256 w0, uint256 w1) = _pack(scalars);
        uint256 actual = h.evaluate(weights, w0, w1);
        assertEq(actual, expected);
        F.validatePacked(actual);
    }
}
