// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test } from "forge-std/Test.sol";
import { MerkleVerifier } from "../src/merkle/MerkleVerifier.sol";

// Independent breadth-first implementation used as a differential oracle.
contract ReferencePackedFrontierHarness {
    function run(
        uint256[] memory frontierEntries,
        uint256 frontierLen,
        uint256 depth,
        bytes calldata blob,
        uint256 decommOffset,
        uint256 decommLen
    ) external pure returns (bytes32 root) {
        assembly ("memory-safe") {
            let digestMask := not(sub(shl(96, 1), 1))
            let indexMask := sub(shl(96, 1), 1)
            let entrySize := 0x20
            let bufBytes := mul(entrySize, frontierLen)
            let frontier := add(frontierEntries, 0x20)
            let nextBuf := mload(0x40)
            let scratch := add(nextBuf, bufBytes)
            mstore(0x40, add(scratch, 65))
            mstore8(scratch, 0x01)

            let decommBase := add(blob.offset, decommOffset)
            let decommPtr := decommBase
            let decommEnd := add(decommBase, mul(decommLen, 20))

            for {
                let level := 0
            } lt(level, depth) {
                level := add(level, 1)
            } {
                let nextLen := 0
                let ep := frontier
                let frontierEnd := add(frontier, mul(frontierLen, entrySize))
                let nextPtr := nextBuf
                for { } lt(ep, frontierEnd) { } {
                    let packed := mload(ep)
                    let node := and(packed, indexMask)
                    let hash := and(packed, digestMask)
                    let nodeIsRight := and(node, 1)
                    let nextReadPtr := add(ep, entrySize)
                    let parentHash

                    switch nodeIsRight
                    case 0 {
                        let nextPacked := 0
                        if lt(nextReadPtr, frontierEnd) { nextPacked := mload(nextReadPtr) }
                        switch eq(and(nextPacked, indexMask), add(node, 1))
                        case 1 {
                            mstore(add(scratch, 1), hash)
                            mstore(add(scratch, 0x21), and(nextPacked, digestMask))
                            parentHash := and(keccak256(scratch, 65), digestMask)
                            nextReadPtr := add(nextReadPtr, entrySize)
                        }
                        default {
                            if iszero(lt(decommPtr, decommEnd)) {
                                mstore(
                                    0x00,
                                    0x90196ee300000000000000000000000000000000000000000000000000000000
                                )
                                mstore(0x04, add(div(sub(decommPtr, decommBase), 20), 1))
                                mstore(0x24, decommLen)
                                revert(0x00, 0x44)
                            }
                            let sibling := and(calldataload(decommPtr), digestMask)
                            decommPtr := add(decommPtr, 20)
                            mstore(add(scratch, 1), hash)
                            mstore(add(scratch, 0x21), sibling)
                            parentHash := and(keccak256(scratch, 65), digestMask)
                        }
                    }
                    default {
                        if iszero(lt(decommPtr, decommEnd)) {
                            mstore(
                                0x00,
                                0x90196ee300000000000000000000000000000000000000000000000000000000
                            )
                            mstore(0x04, add(div(sub(decommPtr, decommBase), 20), 1))
                            mstore(0x24, decommLen)
                            revert(0x00, 0x44)
                        }
                        let sibling := and(calldataload(decommPtr), digestMask)
                        decommPtr := add(decommPtr, 20)
                        mstore(add(scratch, 1), sibling)
                        mstore(add(scratch, 0x21), hash)
                        parentHash := and(keccak256(scratch, 65), digestMask)
                    }

                    ep := nextReadPtr
                    let parentIndex := shr(1, node)
                    // The function precondition makes every emitted parent index greater than the last.
                    mstore(nextPtr, or(parentHash, parentIndex))
                    nextPtr := add(nextPtr, entrySize)
                    nextLen := add(nextLen, 1)
                }

                let tmp := frontier
                frontier := nextBuf
                nextBuf := tmp
                frontierLen := nextLen
            }

            if iszero(eq(decommPtr, decommEnd)) {
                mstore(0x00, 0xb48ec3d200000000000000000000000000000000000000000000000000000000)
                mstore(0x04, div(sub(decommPtr, decommBase), 20))
                mstore(0x24, decommLen)
                revert(0x00, 0x44)
            }

            let finalPacked := 0
            if gt(frontierLen, 0) {
                finalPacked := mload(frontier)
            }
            if or(iszero(eq(frontierLen, 1)), iszero(iszero(and(finalPacked, indexMask)))) {
                let idx := sub(0, 1)
                if gt(frontierLen, 0) {
                    idx := and(finalPacked, indexMask)
                }
                mstore(0x00, 0x1d72965600000000000000000000000000000000000000000000000000000000)
                mstore(0x04, frontierLen)
                mstore(0x24, idx)
                revert(0x00, 0x44)
            }

            root := and(finalPacked, digestMask)
        }
    }
}

contract PackedFrontierHarness {
    function run(
        uint256[] memory entries,
        uint256 count,
        uint256 depth,
        bytes calldata blob,
        uint256 offset,
        uint256 proofCount
    ) external pure returns (bytes32) {
        uint256 beforePointer;
        assembly ("memory-safe") { beforePointer := mload(0x40) }
        bytes32 root = MerkleVerifier.computeRootFromPackedFrontier20BlobInPlace(
            entries, count, depth, blob, offset, proofCount
        );
        uint256 afterPointer;
        uint256 zeroSlot;
        assembly ("memory-safe") {
            afterPointer := mload(0x40)
            zeroSlot := mload(0x60)
        }
        require(beforePointer == afterPointer, "free memory pointer changed");
        require(zeroSlot == 0, "zero slot changed");
        return root;
    }
}

contract PackedFrontierRegressionTest is Test {
    ReferencePackedFrontierHarness oracle;
    PackedFrontierHarness frontier;
    uint256 constant IM = type(uint96).max;

    function setUp() external {
        oracle = new ReferencePackedFrontierHarness();
        frontier = new PackedFrontierHarness();
    }

    function _compare(
        uint256[] memory entries,
        uint256 depth,
        bytes memory blob,
        uint256 offset,
        uint256 proofCount
    ) internal view {
        bytes memory data = abi.encodeWithSelector(
            oracle.run.selector, entries, entries.length, depth, blob, offset, proofCount
        );
        (bool a, bytes memory ar) = address(oracle).staticcall(data);
        (bool b, bytes memory br) = address(frontier).staticcall(data);
        assertEq(a, b, "acceptance differs");
        assertEq(ar, br, "root or revert differs");
    }

    function _proofCount(uint256[] memory entries, uint256 depth)
        internal
        pure
        returns (uint256 count)
    {
        uint256 n = entries.length;
        uint256[] memory ids = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            ids[i] = entries[i] & IM;
        }
        for (uint256 d; d < depth; ++d) {
            uint256 out;
            for (uint256 i; i < n;) {
                uint256 x = ids[i++];
                if (x & 1 == 0 && i < n && ids[i] == x + 1) ++i;
                else ++count;
                ids[out++] = x >> 1;
            }
            n = out;
        }
    }

    function _exercise(uint256[] memory entries, uint256 depth, uint256 seed) internal view {
        uint256 n = _proofCount(entries, depth);
        bytes memory blob = new bytes(11 + (n + 1) * 20);
        for (uint256 i; i < blob.length; ++i) {
            blob[i] = bytes1(uint8(uint256(keccak256(abi.encode(seed, i)))));
        }
        _compare(entries, depth, blob, 11, n);
        if (n > 0) _compare(entries, depth, blob, 11, n - 1);
        _compare(entries, depth, blob, 11, n + 1);
    }

    function testFuzzPackedFrontierParity(uint256 seed, uint8 countRaw, uint8 depthRaw)
        external
        view
    {
        uint256 n = uint256(countRaw) % 13;
        uint256 depth = uint256(depthRaw) % 98;
        uint256[] memory entries = new uint256[](n);
        uint256 mask = depth >= 96 ? IM : (uint256(1) << depth) - 1;
        if (n > mask + 1) n = mask + 1;
        assembly ("memory-safe") { mstore(entries, n) }
        for (uint256 i; i < n; ++i) {
            uint256 idx = uint256(keccak256(abi.encode(seed, i))) & mask;
            bool used = true;
            while (used) {
                used = false;
                for (uint256 j; j < i; ++j) {
                    if ((entries[j] & IM) == idx) {
                        used = true;
                        idx = (idx + 1) & mask;
                        break;
                    }
                }
            }
            entries[i] = (uint256(keccak256(abi.encode(i, seed))) & ~IM) | idx;
        }
        for (uint256 i = 1; i < n; ++i) {
            uint256 x = entries[i];
            uint256 j = i;
            while (j > 0 && (entries[j - 1] & IM) > (x & IM)) {
                entries[j] = entries[j - 1];
                --j;
            }
            entries[j] = x;
        }
        _exercise(entries, depth, seed);
    }

    function testHigh96BitSingletonAndAdjacentSiblings() external view {
        uint256[] memory entries = new uint256[](1);
        entries[0] = (uint256(keccak256("high")) & ~IM) | IM;
        _exercise(entries, 96, 1);
        _exercise(entries, 95, 2);
        entries = new uint256[](2);
        entries[0] = (uint256(keccak256("left")) & ~IM) | (IM - 1);
        entries[1] = (uint256(keccak256("right")) & ~IM) | IM;
        _exercise(entries, 96, 3);
    }

    function testEmptyFrontierAndDepthZero() external view {
        _exercise(new uint256[](0), 0, 0);
        _exercise(new uint256[](0), 96, 0);
        uint256[] memory entries = new uint256[](1);
        entries[0] = uint256(keccak256("root")) & ~IM;
        _exercise(entries, 0, 1);
        entries[0] |= 1;
        _exercise(entries, 0, 2);
    }

    function testDenseFrontierMergeAndOddLastNode() external view {
        uint256[] memory entries = new uint256[](32);
        for (uint256 i; i < 32; ++i) {
            entries[i] = (uint256(keccak256(abi.encode(i))) & ~IM) | i;
        }
        _exercise(entries, 5, 3);
        _exercise(entries, 8, 4);
        assembly ("memory-safe") { mstore(entries, 31) }
        _exercise(entries, 5, 5);
    }
}
