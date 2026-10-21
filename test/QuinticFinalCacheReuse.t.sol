// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as F } from "../src/field/KoalaBearExt5.sol";
import { KeccakChallenger } from "../src/transcript/KeccakChallenger.sol";
import {
    WhirVerifierUtils5 as U
} from "../src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirVerifierUtils5.sol";
import {
    WhirVerifierCore5 as Core
} from "../src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirVerifierCore5.sol";

contract QuinticFinalCacheReuseHarness {
    using KeccakChallenger for KeccakChallenger.State;

    function evaluateBoth(bytes calldata polynomial, uint256[] memory point, uint256 x)
        external
        pure
        returns (bool reused, uint256 actual, uint256 horner, bytes32 allocationDigest)
    {
        require(polynomial.length == 1283 && point.length == 22, "SHAPE");
        bytes memory copied = polynomial[3:];
        for (uint256 i; i < 64; ++i) {
            uint256 value;
            assembly ("memory-safe") {
                value := and(mload(add(add(copied, 32), mul(i, 20))), not(sub(shl(96, 1), 1)))
            }
            F.validatePacked(value);
        }
        uint256 callCache = U._prepareHornerRadix64(polynomial, 3);
        uint256 memoryCache = U._prepareHornerRadix64Memory(copied);
        bytes32 callHash = _hashCache(callCache);
        bytes32 memoryHash = _hashCache(memoryCache);
        horner = U._hornerRadix64(callCache, x);
        require(horner == U._hornerRadix64(memoryCache, x), "HORNER_PARITY");

        // Exercise the real post-cache temporary allocation/restoration helper.
        uint256[] memory indices = new uint256[](14);
        for (uint256 i; i < 14; ++i) {
            indices[i] = i * 1234;
        }
        Core._fillSelVarsPow(indices, 373_019_801, 14);
        allocationDigest = keccak256(abi.encode(_interveningAllocations(point), indices));
        require(_hashCache(callCache) == callHash, "CALL_CACHE_LIFETIME");
        require(_hashCache(memoryCache) == memoryHash, "MEMORY_CACHE_LIFETIME");

        (reused, actual) = U.evaluateFinalValueHornerCache64Dim6(callCache, point, 16);
        (bool memoryReused, uint256 memoryValue) =
            U.evaluateFinalValueHornerCache64Dim6(memoryCache, point, 16);
        require(reused == memoryReused && actual == memoryValue, "CACHE_PARITY");
        uint256 calldataGeneric = U.evaluateFinalValueBlob64Dim6(polynomial, 3, point, 16);
        uint256 memoryGeneric = U.evaluateFinalValueMemory64Dim6(copied, 0, point, 16);
        require(calldataGeneric == memoryGeneric, "FALLBACK_PARITY");
        if (reused) {
            require(actual == calldataGeneric, "FAST_PARITY");
        } else {
            actual = memoryGeneric;
        }
        require(_hashCache(callCache) == callHash, "CALL_CACHE_MUTATION");
        require(_hashCache(memoryCache) == memoryHash, "MEMORY_CACHE_MUTATION");
        F.validatePacked(actual);
    }

    function _interveningAllocations(uint256[] memory point) private pure returns (bytes32) {
        // Match the production sumcheck/constraint allocation families, including
        // challenger growth, fixed eq buffers and the select-pair allocation.
        bytes memory canary = new bytes(4097);
        for (uint256 i; i < canary.length; ++i) {
            canary[i] = bytes1(uint8(i));
        }
        bytes32 canaryHash = keccak256(canary);
        KeccakChallenger.State memory challenger;
        for (uint256 i; i < 6; ++i) {
            challenger.observeValidatedPackedExt5Pair(point[i], point[i + 6]);
            U.sampleExt5(challenger);
        }
        bytes memory statement = new bytes(440);
        bytes32 statementHash = keccak256(statement);
        uint256[] memory pairs = Core._prepareSelectCubicPairs(point);
        uint256[] memory variables = new uint256[](14);
        for (uint256 i; i < 14; ++i) {
            variables[i] = i + 1;
        }
        uint256 a = Core._evaluateConstraintCubicRaw18WithPrecomputedEq(
            point[0], point[1], variables, pairs
        );
        uint256 b = Core._evaluateConstraintCubicRaw14WithPrecomputedEq(
            point[2], point[3], variables, pairs
        );
        uint256 c = Core._evaluateConstraintCubicRaw10WithPrecomputedEq(
            point[4], point[5], variables, pairs
        );
        require(keccak256(canary) == canaryHash && keccak256(statement) == statementHash, "CANARY");
        require(pairs.length == 45 && indicesAllocated(point), "ALLOCATED");
        return keccak256(abi.encode(a, b, c, pairs, challenger));
    }

    function indicesAllocated(uint256[] memory point) private pure returns (bool result) {
        assembly ("memory-safe") { result := lt(add(point, 736), mload(0x40)) }
    }

    function _hashCache(uint256 ptr) private pure returns (bytes32 digest) {
        assembly ("memory-safe") {
            let size := 4160
            if mload(ptr) { size := 320 }
            if gt(add(ptr, size), mload(0x40)) { revert(0, 0) }
            digest := keccak256(ptr, size)
        }
    }
}

contract QuinticFinalCacheReuseTest is Test {
    uint256 constant P = 0x7f000001;
    uint256 constant COMMON = 0x00000000ffffffffffffffffffffffffffffffff000000000000000000000000;
    QuinticFinalCacheReuseHarness h;

    function setUp() public {
        h = new QuinticFinalCacheReuseHarness();
    }

    function testFuzzCommonPolynomial(bytes32 seed, uint32 scalar) public view {
        _check(_values(seed, true), _point(seed), scalar % P, true);
    }

    function testFuzzArbitraryPolynomial(bytes32 seed, uint32 scalar) public view {
        _check(_values(seed, false), _point(seed), scalar % P, false);
    }

    function testEveryLateCommonColumnMismatch() public view {
        uint256[] memory point = _point(bytes32(uint256(99)));
        for (uint256 position = 1; position < 64; ++position) {
            for (uint256 column = 1; column < 5; ++column) {
                uint256[] memory values = _values(bytes32(uint256(position)), true);
                uint256 shift = 224 - 32 * column;
                uint256 lane = uint256(0xffffffff) << shift;
                uint256 old = (values[position] >> shift) & 0xffffffff;
                values[position] = (values[position] & ~lane) | (((old + 1) % P) << shift);
                this.checkCase(values, point, P - 1, false);
            }
        }
    }

    function testZeroMaximumAndBooleanPoints() public view {
        uint256[] memory values = new uint256[](64);
        uint256[] memory point = new uint256[](22);
        uint256 maximum;
        for (uint256 c; c < 5; ++c) {
            maximum |= (P - 1) << (224 - c * 32);
        }
        _check(values, point, 0, true);
        for (uint256 i; i < 64; ++i) {
            values[i] = maximum;
        }
        for (uint256 i; i < 22; ++i) {
            point[i] = maximum;
        }
        _check(values, point, P - 1, true);
        for (uint256 i; i < 64; ++i) {
            values[i] = (maximum & COMMON) | ((i % 2 == 0 ? P - 1 : 0) << 224);
        }
        for (uint256 i; i < 22; ++i) {
            point[i] = i % 2 == 0 ? F.ONE : 0;
        }
        _check(values, point, 1, true);
    }

    function testExactNoncanonicalRejectionsEveryCoefficientAndLane() public {
        uint256[] memory values = new uint256[](64);
        uint256[] memory point = new uint256[](22);
        for (uint256 i; i < 64; ++i) {
            for (uint256 c; c < 5; ++c) {
                uint256 invalid = P << (224 - c * 32);
                values[i] = invalid;
                vm.expectRevert(
                    abi.encodeWithSelector(F.PackedExtensionElementOutOfRange.selector, invalid)
                );
                h.evaluateBoth(_bytes(values), point, 0);
                values[i] = 0;
            }
        }
    }

    function checkCase(
        uint256[] memory values,
        uint256[] memory point,
        uint256 x,
        bool expectedReuse
    ) external view {
        _check(values, point, x, expectedReuse);
    }

    function _check(uint256[] memory values, uint256[] memory point, uint256 x, bool expectedReuse)
        private
        view
    {
        (bool reused, uint256 actual, uint256 horner, bytes32 allocationDigest) =
            h.evaluateBoth(_bytes(values), point, x);
        assertTrue(allocationDigest != bytes32(0));
        assertEq(reused, expectedReuse);
        uint256 expectedHorner;
        for (uint256 i = 64; i > 0; --i) {
            expectedHorner = F.add(F.mulReference(expectedHorner, x << 224), values[i - 1]);
        }
        assertEq(horner, expectedHorner);
        uint256 size = 64;
        for (uint256 dim; dim < 6; ++dim) {
            size >>= 1;
            for (uint256 i; i < size; ++i) {
                values[i] = F.add(
                    values[i], F.mulReference(point[16 + dim], F.sub(values[i + size], values[i]))
                );
            }
        }
        assertEq(actual, values[0]);
    }

    function _values(bytes32 seed, bool common) private pure returns (uint256[] memory values) {
        values = new uint256[](64);
        uint256 columns = _element(seed, 100) & COMMON;
        for (uint256 i; i < 64; ++i) {
            values[i] = _element(seed, i);
            if (common) {
                values[i] = (values[i] & ~COMMON) | columns;
            }
        }
    }

    function _point(bytes32 seed) private pure returns (uint256[] memory point) {
        point = new uint256[](22);
        for (uint256 i; i < 22; ++i) {
            point[i] = _element(seed, 1000 + i);
        }
    }

    function _element(bytes32 seed, uint256 i) private pure returns (uint256 value) {
        for (uint256 c; c < 5; ++c) {
            value |= (uint256(keccak256(abi.encode(seed, i, c))) % P) << (224 - c * 32);
        }
    }

    function _bytes(uint256[] memory values) private pure returns (bytes memory out) {
        out = new bytes(1283);
        assembly ("memory-safe") {
            mstore(add(out, 32), shl(232, 0xabcdef))
            for { let i := 0 } lt(i, 64) { i := add(i, 1) } {
                mstore(add(add(out, 35), mul(i, 20)), mload(add(add(values, 32), mul(i, 32))))
            }
        }
    }
}
