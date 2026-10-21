// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 } from "../src/field/KoalaBearExt5.sol";
import {
    WhirVerifierCore5
} from "../src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirVerifierCore5.sol";

contract QuinticSelectFusedTest is Test {
    uint256 private constant P = 0x7f000001;
    uint256 private constant ONE = uint256(1) << 224;

    function testFuzzFull38Query18VariableChain(bytes32 seed) external pure {
        _check(seed, 38, 18, 0);
    }

    function testFuzzFull31Query14VariableChain(bytes32 seed) external pure {
        _check(seed, 31, 14, 0);
    }

    function testFuzzFull19Query10VariableChain(bytes32 seed) external pure {
        _check(seed, 19, 10, 0);
    }

    function testFuzzDeduplicatedQueryCounts(bytes32 seed, uint8 count) external pure {
        _check(seed, uint256(count) % 39, 18, 0);
        _check(seed, uint256(count) % 32, 14, 0);
        _check(seed, uint256(count) % 20, 10, 0);
    }

    function testEmptyAndSingletonQueryCounts() external pure {
        for (uint256 mode; mode <= 3; ++mode) {
            for (uint256 count; count <= 1; ++count) {
                _check(bytes32(mode), count, 18, mode);
                _check(bytes32(mode), count, 14, mode);
                _check(bytes32(mode), count, 10, mode);
            }
        }
    }

    function testZeroAccumulatorAfterNonFirstQuery() external pure {
        // point=1, challenge=1 and queries [0,1,-1,0,1]. Reverse Horner
        // visits select values [1,0,-1,1,0], so the accumulator becomes
        // zero after its third query and must recover to one on the fourth.
        _check(bytes32(uint256(2)), 5, 18, 2);
        _check(bytes32(uint256(2)), 5, 14, 2);
        _check(bytes32(uint256(2)), 5, 10, 2);
    }

    function testFullChainBoundaryCoefficients() external pure {
        for (uint256 mode = 1; mode <= 3; ++mode) {
            _check(bytes32(mode), 38, 18, mode);
            _check(bytes32(mode), 31, 14, mode);
            _check(bytes32(mode), 19, 10, mode);
        }
    }

    function testFullChainBasisCoefficients() external pure {
        for (uint256 mode = 4; mode < 9; ++mode) {
            _check(bytes32(mode), 38, 18, mode);
            _check(bytes32(mode), 31, 14, mode);
            _check(bytes32(mode), 19, 10, mode);
        }
    }

    function _check(bytes32 seed, uint256 count, uint256 dimensions, uint256 mode) private pure {
        uint256[] memory point = new uint256[](22);
        for (uint256 i; i < 22; ++i) {
            point[i] = _element(seed, i);
            if (mode == 1) point[i] = 0;
            else if (mode == 2) point[i] = ONE;
            else if (mode == 3) point[i] = _maximum();
            else if (mode >= 4) point[i] = (P - 1) << (224 - 32 * (mode - 4));
        }
        uint256 challenge = _element(seed, 22);
        uint256 eqEval = _element(seed, 23);
        if (mode == 1) challenge = 0;
        if (mode == 2) challenge = ONE;
        if (mode == 3) {
            challenge = _maximum();
            eqEval = _maximum();
        }
        uint256[] memory vars = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            vars[i] = uint256(keccak256(abi.encode(seed, i, uint256(100)))) % P;
            if (mode != 0) vars[i] = i % 3 == 0 ? 0 : (i % 3 == 1 ? 1 : P - 1);
        }
        uint256[] memory cache = WhirVerifierCore5._prepareSelectCubicPairs(point);
        uint256 actual;
        if (dimensions == 18) {
            actual = WhirVerifierCore5._evaluateConstraintCubicRaw18WithPrecomputedEq(
                challenge, eqEval, vars, cache
            );
        }
        if (dimensions == 14) {
            actual = WhirVerifierCore5._evaluateConstraintCubicRaw14WithPrecomputedEq(
                challenge, eqEval, vars, cache
            );
        }
        if (dimensions == 10) {
            actual = WhirVerifierCore5._evaluateConstraintCubicRaw10WithPrecomputedEq(
                challenge, eqEval, vars, cache
            );
        }
        uint256 expected;
        for (uint256 i = count; i > 0; --i) {
            expected = KoalaBearExt5.add(
                KoalaBearExt5.mulReference(expected, challenge),
                _selectReference(point, vars[i - 1], dimensions)
            );
        }
        expected = KoalaBearExt5.add(KoalaBearExt5.mulReference(expected, challenge), eqEval);
        KoalaBearExt5.validatePacked(actual);
        assertEq(actual, expected);
    }

    // Independent factor-by-factor oracle. It does not consume cubic-cache
    // coefficients, radix-64 forms, or the production multiplication/reduction.
    function _selectReference(uint256[] memory point, uint256 x, uint256 dimensions)
        private
        pure
        returns (uint256 product)
    {
        product = ONE;
        for (uint256 i = 22; i > 22 - dimensions; --i) {
            uint256[5] memory coefficient;
            uint256 scalar = x == 0 ? P - 1 : x - 1;
            for (uint256 j; j < 5; ++j) {
                coefficient[j] = mulmod((point[i - 1] >> (224 - 32 * j)) & 0xffffffff, scalar, P);
            }
            coefficient[0] = addmod(coefficient[0], 1, P);
            product = KoalaBearExt5.mulReference(product, KoalaBearExt5.pack(coefficient));
            x = mulmod(x, x, P);
        }
    }

    function _element(bytes32 seed, uint256 salt) private pure returns (uint256 out) {
        for (uint256 i; i < 5; ++i) {
            out |= (uint256(keccak256(abi.encode(seed, salt, i))) % P) << (224 - 32 * i);
        }
    }

    function _maximum() private pure returns (uint256 out) {
        for (uint256 i; i < 5; ++i) {
            out |= (P - 1) << (224 - 32 * i);
        }
    }
}
