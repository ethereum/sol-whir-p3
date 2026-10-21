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

contract QuinticDirectCompactHarness {
    function row(bytes calldata encoded, uint256[16] memory weights)
        external
        pure
        returns (bytes32 digest, uint256 value)
    {
        (uint256[] memory offsets, uint256 end) = C.rowOffsets(encoded, 0, 1, 16);
        require(end == encoded.length);
        uint256 ptr;
        assembly ("memory-safe") { ptr := weights }
        return U._hashAndEvaluateCompactRow16(encoded, offsets[0], U._prepareRowWeights(ptr));
    }

    function rowLazy(bytes calldata encoded, uint256[16] memory weights)
        external
        pure
        returns (bytes32 digest, uint256 value)
    {
        (uint256[] memory offsets, uint256 end) = C.rowOffsets(encoded, 0, 1, 16);
        require(end == encoded.length);
        uint256 ptr;
        assembly ("memory-safe") { ptr := weights }
        return U._hashAndEvaluateCompactRow16(encoded, offsets[0], U._prepareRowWeightsLazy(ptr));
    }

    function poly(bytes calldata encoded, uint256[] memory point)
        external
        pure
        returns (uint256 value, bytes32 decodedHash)
    {
        (bytes memory decoded, uint256 end) = C.decodePolynomial(encoded, 0);
        require(end == encoded.length && point.length == 6);
        value = U.evaluateFinalValueMemory64Dim6(decoded, 0, point, 0);
        decodedHash = keccak256(decoded);
    }
}

contract QuinticDirectCompactTest is Test {
    uint256 constant P = 0x7f000001;
    QuinticDirectCompactHarness h;

    function setUp() public {
        h = new QuinticDirectCompactHarness();
    }

    function testFuzzEveryRowMask(bytes32 seed, uint8 rawMask) public view {
        uint256 mask = rawMask & 31;
        uint256[] memory values = _values(seed, 16, mask);
        _checkRow(seed, values, mask);
    }

    function testFuzzFastRow(bytes32 seed) public view {
        _checkRow(seed, _values(seed, 16, 30), 30);
    }

    function testAllMasksAndExtremes() public view {
        for (uint256 mask; mask < 32; ++mask) {
            bytes32 seed = bytes32(mask + 1000);
            _checkRow(seed, _values(seed, 16, mask), mask);
            uint256[] memory values = new uint256[](16);
            for (uint256 i; i < 16; ++i) {
                for (uint256 c; c < 5; ++c) {
                    values[i] |= (P - 1) << (224 - 32 * c);
                }
            }
            _checkRow(bytes32(0), values, mask);
            for (uint256 i; i < 16; ++i) {
                values[i] = 0;
            }
            _checkRow(bytes32(uint256(1)), values, mask);
        }
    }

    function testNoncanonicalFastScalarsAllPositions() public {
        uint256[16] memory weights;
        for (uint256 i; i < 16; ++i) {
            for (uint256 k; k < 3; ++k) {
                uint256[] memory values = new uint256[](16);
                uint256 bad =
                    (k == 0 ? P : k == 1 ? uint256(0x80000000) : uint256(0xffffffff)) << 224;
                values[i] = bad;
                bytes memory encoded = _encode(values, 30);
                vm.expectRevert(abi.encodeWithSelector(bytes4(0xd53cfe5c), bad));
                h.row(encoded, weights);
                vm.expectRevert(abi.encodeWithSelector(bytes4(0xd53cfe5c), bad));
                h.rowLazy(encoded, weights);
            }
        }
    }

    function testNoncanonicalCommonColumns() public {
        uint256[16] memory weights;
        for (uint256 c = 1; c < 5; ++c) {
            uint256[] memory values = new uint256[](16);
            uint256 bad = P << (224 - 32 * c);
            for (uint256 i; i < 16; ++i) {
                values[i] = bad;
            }
            bytes memory encoded = _encode(values, 30);
            vm.expectRevert(abi.encodeWithSelector(bytes4(0xd53cfe5c), bad));
            h.row(encoded, weights);
            vm.expectRevert(abi.encodeWithSelector(bytes4(0xd53cfe5c), bad));
            h.rowLazy(encoded, weights);
        }
    }

    function testFuzzMemoryPolynomial(bytes32 seed, uint8 rawMask) public view {
        uint256 mask = rawMask & 31;
        uint256[] memory values = _values(seed, 64, mask);
        uint256[] memory point = new uint256[](6);
        bytes memory decoded;
        for (uint256 i; i < 64; ++i) {
            decoded = bytes.concat(decoded, bytes20(bytes32(values[i])));
        }
        for (uint256 i; i < 6; ++i) {
            point[i] = _element(seed, i + 100);
        }
        (uint256 value, bytes32 digest) = h.poly(_encode(values, mask), point);
        assertEq(digest, keccak256(decoded));
        uint256 size = 64;
        for (uint256 dim; dim < 6; ++dim) {
            size >>= 1;
            for (uint256 i; i < size; ++i) {
                values[i] = F.add(
                    values[i], F.mulReference(point[dim], F.sub(values[i + size], values[i]))
                );
            }
        }
        assertEq(value, values[0]);
        F.validatePacked(value);
    }

    function testTruncationAndReservedMask() public {
        uint256[16] memory weights;
        bytes memory encoded = _encode(_values(bytes32(0), 16, 30), 30);
        encoded[0] = 0x20;
        vm.expectRevert(C.InvalidTransportEncoding.selector);
        h.row(encoded, weights);
        vm.expectRevert(C.InvalidTransportEncoding.selector);
        h.rowLazy(encoded, weights);
        encoded[0] = 0x1e;
        assembly ("memory-safe") { mstore(encoded, sub(mload(encoded), 1)) }
        vm.expectRevert(C.InvalidTransportEncoding.selector);
        h.row(encoded, weights);
        vm.expectRevert(C.InvalidTransportEncoding.selector);
        h.rowLazy(encoded, weights);
    }

    function _checkRow(bytes32 seed, uint256[] memory values, uint256 mask) private view {
        uint256[16] memory weights;
        uint256 expected;
        bytes memory hashed = hex"00";
        for (uint256 i; i < 16; ++i) {
            weights[i] = _element(seed, i + 100);
            expected = F.add(expected, F.mulReference(values[i], weights[i]));
            hashed = bytes.concat(hashed, bytes20(bytes32(values[i])));
        }
        (bytes32 digest, uint256 actual) = h.row(_encode(values, mask), weights);
        assertEq(digest, bytes32(bytes20(keccak256(hashed))));
        assertEq(actual, expected);
        F.validatePacked(actual);
        (bytes32 lazyDigest, uint256 lazyActual) = h.rowLazy(_encode(values, mask), weights);
        assertEq(lazyDigest, digest);
        assertEq(lazyActual, expected);
        F.validatePacked(lazyActual);
    }

    function _values(bytes32 seed, uint256 count, uint256 mask)
        private
        pure
        returns (uint256[] memory values)
    {
        values = new uint256[](count);
        uint256 common = _element(seed, 99);
        for (uint256 i; i < count; ++i) {
            values[i] = _element(seed, i);
            for (uint256 c; c < 5; ++c) {
                if ((mask >> c) & 1 != 0) {
                    uint256 lane = uint256(0xffffffff) << (224 - 32 * c);
                    values[i] = (values[i] & ~lane) | (common & lane);
                }
            }
        }
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
}
