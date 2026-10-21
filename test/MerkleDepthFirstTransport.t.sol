// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { MerkleVerifier } from "../src/merkle/MerkleVerifier.sol";
import {
    ReferencePackedFrontierHarness,
    PackedFrontierHarness
} from "./PackedFrontierRegression.t.sol";

contract MerkleTransportHarness {
    function run(
        uint256[] memory entries,
        uint256 count,
        uint256 depth,
        bytes calldata blob,
        uint256 offset,
        uint256 proofCount
    ) external pure returns (bytes32 root) {
        uint256 beforePointer;
        uint256 reservedBytes;
        assembly ("memory-safe") {
            beforePointer := mload(0x40)
            if eq(shr(240, calldataload(add(blob.offset, 4))), 0x0101) {
                reservedBytes := shl(5, add(count, 1))
            }
        }
        root = MerkleVerifier.computeRootFromPackedFrontier20BlobTransport(
            entries, count, depth, blob, offset, proofCount
        );
        uint256 afterPointer;
        uint256 zeroSlot;
        assembly ("memory-safe") {
            afterPointer := mload(0x40)
            zeroSlot := mload(0x60)
        }
        require(afterPointer == beforePointer + reservedBytes, "unexpected memory allocation");
        require(zeroSlot == 0, "zero slot changed");
    }

    function runWithLiveMemory(
        uint256[] memory entries,
        uint256 depth,
        bytes calldata blob,
        uint256 proofCount,
        bytes memory preserved
    ) external pure returns (bytes32 root, bytes memory allocated) {
        bytes32 preservedHash = keccak256(preserved);
        uint256[] memory empty;
        root = MerkleVerifier.computeRootFromPackedFrontier20BlobTransport(
            entries, entries.length, depth, blob, 11, proofCount
        );
        require(keccak256(preserved) == preservedHash, "live memory changed");
        require(empty.length == 0, "empty array changed");
        allocated = abi.encode(root, preserved, empty);
    }
}

contract MerkleDepthFirstTransportTest is Test {
    ReferencePackedFrontierHarness oracle;
    MerkleTransportHarness transport;
    uint256 constant MASK = type(uint96).max;

    function setUp() external {
        oracle = new ReferencePackedFrontierHarness();
        transport = new MerkleTransportHarness();
    }

    function _layout(uint256[] memory entries, uint256 depth)
        internal
        pure
        returns (uint256 count, uint256[] memory offsets)
    {
        uint256 n = entries.length;
        uint256[] memory ids = new uint256[](n);
        offsets = new uint256[](depth);
        for (uint256 i; i < n; ++i) {
            ids[i] = entries[i] & MASK;
        }
        for (uint256 h; h < depth; ++h) {
            offsets[h] = count;
            uint256 next;
            for (uint256 i; i < n;) {
                uint256 x = ids[i++];
                if (x & 1 == 0 && i < n && ids[i] == x + 1) {
                    ++i;
                } else {
                    ++count;
                }
                ids[next++] = x >> 1;
            }
            n = next;
        }
    }

    function _transport(
        uint256[] memory entries,
        uint256 depth,
        bytes memory input,
        uint256[] memory offsets
    ) internal pure returns (bytes memory out) {
        out = new bytes(input.length);
        for (uint256 j; j < input.length; ++j) {
            out[j] = input[j];
        }
        out[4] = 0x01;
        out[5] = 0x01;
        uint256 occupied;
        uint256 target;
        for (uint256 i; i < entries.length; ++i) {
            uint256 node = entries[i] & MASK;
            uint256 stopLevel = depth;
            if (i + 1 < entries.length) {
                uint256 diff = node ^ (entries[i + 1] & MASK);
                stopLevel = 0;
                while (diff > 1) {
                    diff >>= 1;
                    ++stopLevel;
                }
            }
            for (uint256 h; h < stopLevel; ++h) {
                if (occupied & (1 << h) != 0) {
                    occupied ^= 1 << h;
                } else {
                    uint256 source = offsets[h]++;
                    for (uint256 j; j < 20; ++j) {
                        out[11 + target * 20 + j] = input[11 + source * 20 + j];
                    }
                    ++target;
                }
                node >>= 1;
            }
            occupied |= 1 << stopLevel;
        }
    }

    function _compare(
        uint256[] memory entries,
        uint256 depth,
        bytes memory bfsBlob,
        bytes memory dfsBlob,
        uint256 count
    ) internal view {
        (bool bfsOk, bytes memory bfsResult) = address(oracle)
            .staticcall(
                abi.encodeCall(oracle.run, (entries, entries.length, depth, bfsBlob, 11, count))
            );
        (bool dfsOk, bytes memory dfsResult) = address(transport)
            .staticcall(
                abi.encodeCall(transport.run, (entries, entries.length, depth, dfsBlob, 11, count))
            );
        assertEq(bfsOk, dfsOk, "acceptance differs");
        assertEq(bfsResult, dfsResult, "root/revert differs");
    }

    function _check(uint256[] memory entries, uint256 depth, uint256 seed) internal view {
        (uint256 n, uint256[] memory offsets) = _layout(entries, depth);
        bytes memory blob = new bytes(11 + (n + 1) * 20);
        for (uint256 i; i < blob.length; i += 32) {
            bytes32 word = keccak256(abi.encode(seed, i));
            assembly ("memory-safe") {
                mstore(add(add(blob, 32), i), word)
            }
        }
        blob[4] = 0;
        blob[5] = 0x01;
        bytes memory encoded = _transport(entries, depth, blob, offsets);
        _compare(entries, depth, blob, encoded, n);
        if (n > 0) {
            _compare(entries, depth, blob, encoded, n - 1);
        }
        _compare(entries, depth, blob, encoded, n + 1);
    }

    function testFuzzTransportRootsAndCounts(uint256 seed, uint8 countRaw, uint8 depthRaw)
        external
        view
    {
        uint256 depth = uint256(depthRaw) % 97;
        uint256 n = uint256(countRaw) % 17 + 1;
        uint256 mask = depth == 96 ? MASK : (uint256(1) << depth) - 1;
        if (n > mask + 1) {
            n = mask + 1;
        }
        uint256[] memory entries = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            uint256 idx = uint256(keccak256(abi.encode(seed, i))) & mask;
            bool used = true;
            while (used) {
                used = false;
                for (uint256 j; j < i; ++j) {
                    if ((entries[j] & MASK) == idx) {
                        used = true;
                        idx = (idx + 1) & mask;
                        break;
                    }
                }
            }
            entries[i] = (uint256(keccak256(abi.encode(i, seed))) & ~MASK) | idx;
        }
        for (uint256 i = 1; i < n; ++i) {
            uint256 x = entries[i];
            uint256 j = i;
            while (j > 0 && (entries[j - 1] & MASK) > (x & MASK)) {
                entries[j] = entries[j - 1];
                --j;
            }
            entries[j] = x;
        }
        _check(entries, depth, seed);
    }

    function testDenseSingletonAnd96BitBoundary() external view {
        uint256[] memory entries = new uint256[](32);
        for (uint256 i; i < 32; ++i) {
            entries[i] = (uint256(keccak256(abi.encode(i))) & ~MASK) | i;
        }
        _check(entries, 5, 1);
        _check(entries, 8, 2);
        entries = new uint256[](1);
        entries[0] = (uint256(keccak256("max")) & ~MASK) | MASK;
        _check(entries, 96, 3);
        entries[0] = uint256(keccak256("zero")) & ~MASK;
        _check(entries, 0, 4);
    }

    function testBfsEntryDoesNotInterpretPrefix() external {
        PackedFrontierHarness bfs = new PackedFrontierHarness();
        uint256[] memory entries = new uint256[](2);
        entries[0] = uint256(keccak256("leaf0")) & ~MASK;
        entries[1] = (uint256(keccak256("leaf8")) & ~MASK) | 8;
        bytes memory blob = new bytes(11 + 6 * 20);
        for (uint256 i; i < blob.length; ++i) {
            blob[i] = bytes1(uint8(i + 1));
        }
        blob[4] = 0x01;
        blob[5] = 0x01;
        bytes32 expected = oracle.run(entries, 2, 4, blob, 11, 6);
        assertEq(bfs.run(entries, 2, 4, blob, 11, 6), expected);
    }

    function testInvalidOrderingRangeFallback() external view {
        uint256[] memory entries = new uint256[](2);
        entries[0] = 9;
        entries[1] = 9;
        bytes memory blob = new bytes(5000);
        blob[4] = 0x01;
        blob[5] = 0x01;
        (uint256 n,) = _layout(entries, 8);
        _compare(entries, 8, blob, blob, n);
        entries[0] = 11;
        entries[1] = 3;
        (n,) = _layout(entries, 8);
        _compare(entries, 8, blob, blob, n);
        entries = new uint256[](1);
        entries[0] = MASK;
        (n,) = _layout(entries, 95);
        _compare(entries, 95, blob, blob, n);
        entries = new uint256[](0);
        _compare(entries, 96, blob, blob, 0);
    }

    function testRejectsIndicesAboveDeclaredDepth() external {
        uint256[] memory entries = new uint256[](1);
        for (uint256 depth; depth < 96; ++depth) {
            entries[0] = (uint256(keccak256(abi.encode(depth))) & ~MASK) | (uint256(1) << depth);
            bytes memory blob = new bytes(11 + depth * 20);
            blob[4] = 0x01;
            blob[5] = 0x01;
            vm.expectRevert(abi.encodeWithSelector(MerkleVerifier.InvalidFinalLayer.selector, 1, 1));
            transport.run(entries, 1, depth, blob, 11, depth);
        }
    }

    function testLiveMemoryAndAllocationAfterTraversal() external view {
        bytes memory preserved = new bytes(129);
        for (uint256 i; i < preserved.length; ++i) {
            preserved[i] = bytes1(uint8(i + 1));
        }
        for (uint256 pass; pass < 2; ++pass) {
            uint256 depth = pass == 0 ? 4 : 97;
            uint256[] memory entries = new uint256[](pass == 0 ? 4 : 1);
            for (uint256 i; i < entries.length; ++i) {
                uint256 index = i == 0 ? 0 : i == 1 ? 4 : i == 2 ? 11 : 15;
                entries[i] = (uint256(keccak256(abi.encode(depth, i))) & ~MASK) | index;
            }
            (uint256 count, uint256[] memory offsets) = _layout(entries, depth);
            bytes memory blob = new bytes(11 + count * 20);
            for (uint256 i; i < blob.length; ++i) {
                blob[i] = bytes1(uint8(i + 1));
            }
            bytes memory encoded = _transport(entries, depth, blob, offsets);
            bytes32 expected = oracle.run(entries, entries.length, depth, blob, 11, count);
            (bytes32 root, bytes memory allocated) =
                transport.runWithLiveMemory(entries, depth, encoded, count, preserved);
            assertEq(root, expected);
            assertEq(allocated, abi.encode(expected, preserved, new uint256[](0)));
        }
    }

    function testFuzzLargerFrontier(uint256 seed, uint8 countRaw, uint8 depthRaw) external view {
        uint256 depth = 7 + uint256(depthRaw) % 90;
        uint256 n = 1 + uint256(countRaw) % 64;
        uint256 mask = depth == 96 ? MASK : (uint256(1) << depth) - 1;
        uint256[] memory entries = new uint256[](n);
        // Disjoint low-bit slots give canonical strictly increasing indices
        // while the high prefix exercises the full 96-bit index boundary.
        uint256 prefix = (uint256(keccak256(abi.encode(seed, depth))) & mask) >> 6 << 6;
        for (uint256 i; i < n; ++i) {
            entries[i] = (uint256(keccak256(abi.encode(seed, i))) & ~MASK) | (prefix + i);
        }
        _check(entries, depth, seed);
    }

    function testEveryBitBoundary() external view {
        for (uint256 depth = 1; depth <= 96; ++depth) {
            uint256[] memory entries = new uint256[](2);
            entries[0] = uint256(keccak256(abi.encode(depth, "left"))) & ~MASK;
            entries[1] = (uint256(keccak256(abi.encode(depth, "right"))) & ~MASK)
                | (uint256(1) << (depth - 1));
            _check(entries, depth, depth);
        }
    }

    function testFallbackAtLargeDepthAndEmpty() external view {
        bytes memory blob = new bytes(11 + 600 * 20);
        blob[4] = 0x01;
        blob[5] = 0x01;
        uint256[] memory entries = new uint256[](0);
        _compare(entries, 97, blob, blob, 0);
        _compare(entries, 256, blob, blob, 0);
        entries = new uint256[](2);
        entries[0] = MASK;
        entries[1] = MASK;
        _compare(entries, 97, blob, blob, 194);
        entries[1] = 0;
        _compare(entries, 96, blob, blob, 192);
    }
}
