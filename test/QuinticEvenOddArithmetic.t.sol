// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 } from "../src/field/KoalaBearExt5.sol";
import { KoalaBearPackedField } from "../src/field/KoalaBearPackedField.sol";

contract QuinticEvenOddArithmeticTest is Test {
    uint256 constant P = 0x7f000001;

    // This oracle deliberately does not call any optimized field helper.
    // Accumulate nine schoolbook coefficients modulo p, then reduce each
    // high monomial using X^5 = 1 - X^2.
    function oracle(uint256 a, uint256 b) internal pure returns (uint256 result) {
        uint256[9] memory c;
        for (uint256 i; i < 5; ++i) {
            uint256 ai = (a >> (224 - 32 * i)) & 0xffffffff;
            for (uint256 j; j < 5; ++j) {
                uint256 bj = (b >> (224 - 32 * j)) & 0xffffffff;
                c[i + j] = addmod(c[i + j], mulmod(ai, bj, P), P);
            }
        }
        for (uint256 k = 9; k > 5;) {
            --k;
            c[k - 5] = addmod(c[k - 5], c[k], P);
            c[k - 3] = addmod(c[k - 3], P - c[k], P);
        }
        for (uint256 i; i < 5; ++i) {
            result |= c[i] << (224 - 32 * i);
        }
    }

    function canonical(uint256 seed) internal pure returns (uint256 out) {
        for (uint256 i; i < 5; ++i) {
            out |= (((seed >> (32 * i)) & 0xffffffff) % P) << (224 - 32 * i);
        }
    }

    function check(uint256 a, uint256 b) internal pure {
        uint256 expected = oracle(a, b);
        uint256 actual = KoalaBearExt5.mul(a, b);
        assertEq(actual, expected, "mul");
        assertEq(KoalaBearPackedField.mul(a, b), expected, "packed mul");
        KoalaBearExt5.validatePacked(actual);
        uint256 squared = KoalaBearExt5.square(a);
        assertEq(squared, oracle(a, a), "square");
        KoalaBearExt5.validatePacked(squared);
    }

    function testBasisAndEdges() public pure {
        uint256 allMax;
        uint256 allOne;
        for (uint256 i; i < 5; ++i) {
            allMax |= (P - 1) << (224 - 32 * i);
            allOne |= uint256(1) << (224 - 32 * i);
            for (uint256 j; j < 5; ++j) {
                check(uint256(1) << (224 - 32 * i), uint256(1) << (224 - 32 * j));
                check((P - 1) << (224 - 32 * i), (P - 1) << (224 - 32 * j));
            }
        }
        uint256[7] memory edges = [
            uint256(0),
            uint256(1) << 224,
            (P - 1) << 224,
            allMax,
            allOne,
            canonical(type(uint256).max),
            canonical(0x003fffffff400000007effffff7f00000000000001)
        ];
        for (uint256 i; i < edges.length; ++i) {
            for (uint256 j; j < edges.length; ++j) {
                check(edges[i], edges[j]);
            }
        }
    }

    function testFuzzSchoolbook(uint256 a, uint256 b) public pure {
        check(canonical(a), canonical(b));
    }

    function testFuzzRepeatedChain(uint256 seedA, uint256 seedB) public pure {
        uint256 a = canonical(seedA);
        uint256 b = canonical(seedB);
        uint256 expected = a;
        for (uint256 i; i < 20; ++i) {
            a = KoalaBearExt5.mul(a, b);
            expected = oracle(expected, b);
            assertEq(a, expected, "multiply chain");
            a = KoalaBearExt5.square(a);
            expected = oracle(expected, expected);
            assertEq(a, expected, "square chain");
            KoalaBearExt5.validatePacked(a);
            b = oracle(b, canonical(uint256(keccak256(abi.encode(seedA, seedB, i)))));
        }
    }

    function oracleAdd(uint256 a, uint256 b) internal pure returns (uint256 out) {
        for (uint256 i; i < 5; ++i) {
            uint256 shift = 224 - 32 * i;
            out |= addmod((a >> shift) & 0xffffffff, (b >> shift) & 0xffffffff, P) << shift;
        }
    }

    function oracleSub(uint256 a, uint256 b) internal pure returns (uint256 out) {
        for (uint256 i; i < 5; ++i) {
            uint256 shift = 224 - 32 * i;
            out |= addmod((a >> shift) & 0xffffffff, P - ((b >> shift) & 0xffffffff), P) << shift;
        }
    }

    function checkExtrapolate(uint256 e0, uint256 e1, uint256 e2, uint256 r) internal pure {
        uint256 one = uint256(1) << 224;
        uint256 two = uint256(2) << 224;
        uint256 inverseTwo = uint256(1_065_353_217) << 224;
        uint256 l0 = oracle(oracle(oracleSub(r, one), oracleSub(r, two)), inverseTwo);
        uint256 l1 = oracle(r, oracleSub(two, r));
        uint256 l2 = oracle(oracle(r, oracleSub(r, one)), inverseTwo);
        uint256 expected = oracleAdd(oracleAdd(oracle(e0, l0), oracle(e1, l1)), oracle(e2, l2));
        uint256 actual = KoalaBearExt5.extrapolate_012(e0, e1, e2, r);
        assertEq(actual, expected, "Lagrange interpolation");
        KoalaBearExt5.validatePacked(actual);
    }

    function testFuzzExtrapolationSchoolbook(uint256 e0, uint256 e1, uint256 e2, uint256 r)
        public
        pure
    {
        checkExtrapolate(canonical(e0), canonical(e1), canonical(e2), canonical(r));
    }

    function testExtrapolationEdges() public pure {
        uint256 maximum;
        for (uint256 i; i < 5; ++i) {
            maximum |= (P - 1) << (224 - 32 * i);
        }
        uint256[6] memory edges = [
            uint256(0),
            uint256(1) << 224,
            uint256(2) << 224,
            (P - 1) << 224,
            maximum,
            canonical(type(uint256).max)
        ];
        for (uint256 i; i < 6; ++i) {
            for (uint256 j; j < 6; ++j) {
                checkExtrapolate(edges[i], edges[j], edges[(i + j) % 6], edges[(2 * i + j) % 6]);
            }
        }
    }
}
