// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { LibSort } from "solady/utils/LibSort.sol";
import { KeccakChallenger } from "../src/transcript/KeccakChallenger.sol";
import {
    WhirVerifierUtils5
} from "../src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirVerifierUtils5.sol";
import { SmallQuerySort } from "../src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/SmallQuerySort.sol";

contract QuinticQuerySortTest is Test {
    using KeccakChallenger for KeccakChallenger.State;

    function _copy(uint256[] memory a) private pure returns (uint256[] memory b) {
        b = new uint256[](a.length);
        for (uint256 i; i < a.length; ++i) {
            b[i] = a[i];
        }
    }

    function _check(uint256[] memory input) private pure {
        uint256[] memory expected = _copy(input);
        LibSort.sort(expected);
        LibSort.uniquifySorted(expected);
        uint256[] memory actual;
        uint256 beforePtr;
        uint256 afterPtr;
        uint256 oldLength = input.length;
        assembly ("memory-safe") {
            beforePtr := mload(0x40)
            mstore(beforePtr, 0xdeadbeef)
            mstore(add(beforePtr, 32), not(0))
            actual := add(beforePtr, 64)
            mstore(actual, oldLength)
            mcopy(add(actual, 32), add(input, 32), shl(5, oldLength))
            afterPtr := add(add(actual, 32), shl(5, oldLength))
            mstore(afterPtr, 0xcafebabe)
            mstore(add(afterPtr, 32), not(0))
            mstore(0x40, add(afterPtr, 64))
        }
        uint256 beforeFree;
        uint256 afterFree;
        uint256 guard0;
        uint256 guard1;
        uint256 guard2;
        uint256 guard3;
        uint256 zeroSlot;
        assembly ("memory-safe") { beforeFree := mload(0x40) }
        SmallQuerySort.sortUnique(actual);
        assembly ("memory-safe") {
            afterFree := mload(0x40)
            guard0 := mload(beforePtr)
            guard1 := mload(add(beforePtr, 32))
            guard2 := mload(afterPtr)
            guard3 := mload(add(afterPtr, 32))
            zeroSlot := mload(0x60)
        }
        assertEq(actual, expected);
        assertEq(beforeFree, afterFree);
        assertEq(guard0, 0xdeadbeef);
        assertEq(guard1, type(uint256).max);
        assertEq(guard2, 0xcafebabe);
        assertEq(guard3, type(uint256).max);
        assertEq(zeroSlot, 0);
        for (uint256 i = 1; i < actual.length; ++i) {
            assertLt(actual[i - 1], actual[i]);
        }
    }

    function testFuzzFullWidthAndFallback(bytes32 seed, uint8 count) external pure {
        uint256[] memory values = new uint256[](count);
        for (uint256 i; i < values.length; ++i) {
            values[i] = uint256(keccak256(abi.encode(seed, i)));
        }
        _check(values);
    }

    function testFuzzSmallIntegers(bytes32 seed, uint8 count, uint8 bits) external pure {
        uint256 mask = type(uint256).max >> (255 - uint256(bits));
        uint256[] memory values = new uint256[](uint256(count) % 65);
        for (uint256 i; i < values.length; ++i) {
            values[i] = uint256(keccak256(abi.encode(seed, i))) & mask;
        }
        _check(values);
    }

    function testFuzzDuplicates(bytes32 seed, uint8 count) external pure {
        uint256[] memory values = new uint256[](uint256(count) % 97);
        for (uint256 i; i < values.length; ++i) {
            uint256 v = uint256(keccak256(abi.encode(seed, i))) % 7;
            values[i] = v == 6 ? type(uint256).max : v;
        }
        _check(values);
    }

    function testAllBoundaryLengthsAndPatterns() external pure {
        for (uint256 n; n <= 65; ++n) {
            uint256[] memory values = new uint256[](n);
            _check(values);
            for (uint256 i; i < n; ++i) {
                values[i] = type(uint256).max;
            }
            _check(values);
            for (uint256 i; i < n; ++i) {
                values[i] = n - i;
            }
            _check(values);
            for (uint256 i; i < n; ++i) {
                values[i] = i;
            }
            _check(values);
            for (uint256 i; i < n; ++i) {
                values[i] = i % 2 == 0 ? 0 : type(uint256).max;
            }
            _check(values);
        }
    }

    function testExhaustiveTernaryArraysThroughLength8() external pure {
        uint256 cases = 1;
        for (uint256 n; n <= 8; ++n) {
            for (uint256 pattern; pattern < cases; ++pattern) {
                uint256[] memory values = new uint256[](n);
                uint256 remaining = pattern;
                for (uint256 i; i < n; ++i) {
                    uint256 digit = remaining % 3;
                    remaining /= 3;
                    values[i] = digit == 2 ? type(uint256).max : digit;
                }
                _check(values);
            }
            cases *= 3;
        }
    }

    function _snapshot(KeccakChallenger.State memory state, uint256[] memory queries)
        private
        pure
        returns (bytes memory)
    {
        // Capacity padding is deliberately uninitialized in KeccakChallenger;
        // only the live prefix, length, output block and index are semantic.
        bytes memory live = new bytes(state.inputLen);
        for (uint256 i; i < live.length; ++i) {
            live[i] = state.inputBuffer[i];
        }
        bytes memory snapshot =
            abi.encode(queries, live, state.inputLen, state.outputBlock, state.outputIndex);
        uint256[10] memory next;
        for (uint256 i; i < next.length; ++i) {
            next[i] = state.sampleBase();
        }
        return abi.encode(snapshot, next);
    }

    function sampleReference(bytes32 seed, uint256 bits, uint256 count)
        external
        pure
        returns (bytes memory)
    {
        KeccakChallenger.State memory state;
        state.observeBytes(abi.encodePacked(seed));
        return _snapshot(state, _referenceSample(state, bits, count));
    }

    function sampleQueries(bytes32 seed, uint256 bits, uint256 count)
        external
        pure
        returns (bytes memory)
    {
        KeccakChallenger.State memory state;
        state.observeBytes(abi.encodePacked(seed));
        return _snapshot(state, WhirVerifierUtils5.sampleStirQueriesPow2(state, bits, count));
    }

    function _checkSample(bytes32 seed, uint256 bits, uint256 count) private view {
        (bool expectedOk, bytes memory expected) =
            address(this).staticcall(abi.encodeCall(this.sampleReference, (seed, bits, count)));
        (bool actualOk, bytes memory actual) =
            address(this).staticcall(abi.encodeCall(this.sampleQueries, (seed, bits, count)));
        // Compare exact reverts as well: the reference sampler rejects e.g.
        // bits >= 256 with zero queries at its checked mask subtraction.
        assertEq(actualOk, expectedOk);
        assertEq(actual, expected);
    }

    function testFuzzSamplingAndTranscriptParity(bytes32 seed, uint16 bits, uint8 count)
        external
        view
    {
        _checkSample(seed, bits, count);
    }

    function testSamplingBoundaries() external view {
        uint256[15] memory bits =
            [uint256(0), 1, 2, 3, 10, 17, 18, 19, 20, 22, 31, 32, 255, 256, 257];
        uint256[12] memory counts = [uint256(0), 1, 2, 8, 14, 19, 31, 38, 63, 64, 65, 128];
        for (uint256 i; i < bits.length; ++i) {
            for (uint256 j; j < counts.length; ++j) {
                _checkSample(bytes32(uint256(i * 100 + j)), bits[i], counts[j]);
            }
        }
    }

    // Reference query sampling uses LibSort and records the complete semantic
    // challenger state, including subsequent sampled challenges.
    function _referenceSample(
        KeccakChallenger.State memory challenger,
        uint256 domainBits,
        uint256 numQueries
    ) private pure returns (uint256[] memory queries) {
        uint256 maxBitsPerCall = 20;
        uint256 totalBitsNeeded = numQueries * domainBits;

        queries = new uint256[](numQueries);

        if (totalBitsNeeded <= maxBitsPerCall) {
            uint256 allBits = challenger.sampleBitsUnchecked(totalBitsNeeded);
            uint256 mask = domainBits == 0 ? 0 : ((uint256(1) << domainBits) - 1);
            unchecked {
                for (uint256 i = 0; i < numQueries; ++i) {
                    queries[i] = allBits & mask;
                    allBits >>= domainBits;
                }
            }
        } else {
            uint256 queriesPerBatch = maxBitsPerCall / domainBits;
            if (queriesPerBatch >= 2) {
                uint256 remaining = numQueries;
                uint256 cursor = 0;
                uint256 mask = (uint256(1) << domainBits) - 1;
                while (remaining > 0) {
                    uint256 batchSize = remaining < queriesPerBatch ? remaining : queriesPerBatch;
                    uint256 batchBits = batchSize * domainBits;
                    uint256 allBits = challenger.sampleBitsUnchecked(batchBits);

                    unchecked {
                        for (uint256 i = 0; i < batchSize; ++i) {
                            queries[cursor] = allBits & mask;
                            allBits >>= domainBits;
                            cursor += 1;
                        }
                    }

                    remaining -= batchSize;
                }
            } else {
                unchecked {
                    for (uint256 i = 0; i < numQueries; ++i) {
                        queries[i] = challenger.sampleBitsUnchecked(domainBits);
                    }
                }
            }
        }

        if (queries.length > 1) {
            LibSort.sort(queries);
            LibSort.uniquifySorted(queries);
        }
    }
}
