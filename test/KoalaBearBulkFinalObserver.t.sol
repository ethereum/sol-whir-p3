// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KeccakChallenger } from "../src/transcript/KeccakChallenger.sol";

/// @dev The reference observes 32 masked pairs. Neither
/// the independent byte-order oracle nor the reference calls the bulk helper.
contract KoalaBearBulkFinalObserverHarness {
    using KeccakChallenger for KeccakChallenger.State;

    bytes32 private constant BEFORE = keccak256("bulk observer: before allocation");
    bytes32 private constant AFTER = keccak256("bulk observer: after allocation");

    struct Observation {
        bytes input;
        uint256 inputLen;
        bytes32 outputBlock;
        uint256 outputIndex;
        uint256[24] challenges;
        bytes sampledInput;
        uint256 sampledInputLen;
        bytes32 sampledOutputBlock;
        uint256 sampledOutputIndex;
    }

    function observe(
        bytes calldata values,
        bytes calldata prefix,
        uint256 capacity,
        bytes32 outputBlock,
        uint256 outputIndex,
        bytes32 poison,
        bool bulk
    ) external pure returns (Observation memory result) {
        require(capacity >= prefix.length, "HARNESS_CAPACITY");
        KeccakChallenger.State memory state;
        (bytes memory buffer, bytes memory bufferOwner) = _guardedAllocation(capacity);
        assembly ("memory-safe") {
            calldatacopy(add(buffer, 32), prefix.offset, prefix.length)
        }
        state.inputBuffer = buffer;
        state.inputLen = prefix.length;
        state.outputBlock = outputBlock;
        state.outputIndex = outputIndex;

        (bytes memory source, bytes memory sourceOwner) = _guardedSource(values, poison);
        bytes32 originalSource = keccak256(sourceOwner);
        if (bulk) {
            state.observeValidatedPackedExt5Memory64(source);
        } else {
            _observePairs(state, source);
        }

        // Source headers, all source bytes, padding and both guard regions must
        // survive. Destination guards are outside capacity, never inside unused
        // capacity: the pair and bulk observers may legally fill that
        // capacity differently or choose different allocation sizes.
        require(keccak256(sourceOwner) == originalSource, "SOURCE_CHANGED");
        _assertGuards(bufferOwner, capacity);
        require(state.inputLen <= state.inputBuffer.length, "INPUT_OVER_CAPACITY");
        _assertAllocated(state.inputBuffer);
        result.input = _inputBytes(state);
        result.inputLen = state.inputLen;
        result.outputBlock = state.outputBlock;
        result.outputIndex = state.outputIndex;

        for (uint256 i; i < result.challenges.length; ++i) {
            result.challenges[i] = state.sampleBase();
        }
        result.sampledInput = _inputBytes(state);
        result.sampledInputLen = state.inputLen;
        result.sampledOutputBlock = state.outputBlock;
        result.sampledOutputIndex = state.outputIndex;
        require(keccak256(sourceOwner) == originalSource, "SOURCE_CHANGED_AFTER_SAMPLE");
        _assertGuards(bufferOwner, capacity);
    }

    function observeOnly(bytes calldata values, bool bulk, bytes32 poison) external pure {
        KeccakChallenger.State memory state;
        (bytes memory source, bytes memory owner) = _guardedSource(values, poison);
        bytes32 originalSource = keccak256(owner);
        if (bulk) {
            state.observeValidatedPackedExt5Memory64(source);
        } else {
            _observePairs(state, source);
        }
        require(keccak256(owner) == originalSource, "SOURCE_CHANGED");
    }

    function _observePairs(KeccakChallenger.State memory state, bytes memory values) private pure {
        require(values.length == 1280, "REFERENCE_LENGTH");
        for (uint256 i; i < 64; i += 2) {
            uint256 first;
            uint256 second;
            assembly ("memory-safe") {
                let src := add(add(values, 32), mul(i, 20))
                let mask := not(sub(shl(96, 1), 1))
                first := and(mload(src), mask)
                second := and(mload(add(src, 20)), mask)
            }
            state.observeValidatedPackedExt5Pair(first, second);
        }
    }

    function _guardedSource(bytes calldata values, bytes32 poison)
        private
        pure
        returns (bytes memory source, bytes memory owner)
    {
        (source, owner) = _guardedAllocation(values.length);
        // The complete trailing word is deliberately poisoned. For 1280-byte
        // inputs the pair observer's final 20-byte mload reads its first twelve bytes.
        assembly ("memory-safe") {
            calldatacopy(add(source, 32), values.offset, values.length)
            let end := add(add(source, 32), and(add(values.length, 31), not(31)))
            mstore(end, poison)
            mstore(add(end, 32), not(poison))
        }
    }

    function _guardedAllocation(uint256 length)
        private
        pure
        returns (bytes memory value, bytes memory owner)
    {
        uint256 rounded = (length + 31) & ~uint256(31);
        // owner payload: before guard | bytes header | padded bytes | two guards.
        owner = new bytes(rounded + 128);
        bytes32 before = BEFORE;
        bytes32 afterGuard = AFTER;
        assembly ("memory-safe") {
            mstore(add(owner, 32), before)
            value := add(owner, 64)
            mstore(value, length)
            let start := add(value, 32)
            let end := add(start, rounded)
            for { let p := start } lt(p, end) { p := add(p, 32) } {
                mstore(p, 0xa5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5)
            }
            mstore(end, afterGuard)
            mstore(add(end, 32), not(afterGuard))
        }
    }

    function _assertGuards(bytes memory owner, uint256 length) private pure {
        uint256 rounded = (length + 31) & ~uint256(31);
        bytes32 before;
        bytes32 afterGuard;
        bytes32 after2;
        uint256 valueLength;
        assembly ("memory-safe") {
            before := mload(add(owner, 32))
            valueLength := mload(add(owner, 64))
            let end := add(add(owner, 96), rounded)
            afterGuard := mload(end)
            after2 := mload(add(end, 32))
        }
        require(before == BEFORE && valueLength == length, "DEST_BEFORE_GUARD");
        require(afterGuard == AFTER && after2 == ~AFTER, "DEST_AFTER_GUARD");
    }

    function _assertAllocated(bytes memory buffer) private pure {
        uint256 free;
        uint256 end;
        assembly ("memory-safe") {
            free := mload(64)
            end := add(add(buffer, 32), and(add(mload(buffer), 31), not(31)))
        }
        require(end <= free && free % 32 == 0, "BAD_FREE_MEMORY_POINTER");
    }

    function _inputBytes(KeccakChallenger.State memory state)
        private
        pure
        returns (bytes memory input)
    {
        input = new bytes(state.inputLen);
        for (uint256 i; i < input.length; ++i) {
            input[i] = state.inputBuffer[i];
        }
    }
}

contract KoalaBearBulkFinalObserverTest is Test {
    uint256 private constant MODULUS = 0x7f000001;
    bytes4 private constant PACKED_RANGE_ERROR = 0xd53cfe5c;
    KoalaBearBulkFinalObserverHarness private harness;

    function setUp() external {
        harness = new KoalaBearBulkFinalObserverHarness();
    }

    function testZeroAndMaximumCanonicalValues() external view {
        bytes memory zeros = new bytes(1280);
        bytes memory maxima = new bytes(1280);
        for (uint256 i; i < 320; ++i) {
            _writeLimb(maxima, i, MODULUS - 1);
        }
        _assertParity(zeros, hex"010203", 3, bytes32(uint256(1)), 32, bytes32(0));
        _assertParity(maxima, hex"9988776655", 1320, ~bytes32(0), type(uint256).max, ~bytes32(0));
        _assertParity(zeros, new bytes(0), 0, bytes32(0), 0, ~bytes32(0));
    }

    function testEveryDestinationAlignmentAndCapacityBoundary() external view {
        bytes memory values = _canonicalValues(bytes32(uint256(0xdecaf)));
        for (uint256 alignment; alignment < 32; ++alignment) {
            bytes memory prefix = _prefix(alignment, bytes32(uint256(alignment + 1)));
            uint256 total = prefix.length + 1280;
            // Exact capacity catches accidental trailing stores from the
            // tightly packed 40-word write strategy.
            uint256[6] memory capacities =
                [prefix.length, total - 1, total, total + 11, total + 12, total + 24];
            for (uint256 i; i < capacities.length; ++i) {
                _assertParity(values, prefix, capacities[i], keccak256(prefix), i * 4, ~bytes32(0));
            }
        }
    }

    function testLargerPrefixesAndExcessCapacity() external view {
        bytes memory values = _canonicalValues(bytes32(uint256(123)));
        uint256[9] memory lengths = [uint256(32), 33, 39, 40, 63, 64, 127, 255, 1023];
        for (uint256 i; i < lengths.length; ++i) {
            bytes memory prefix = _prefix(lengths[i], bytes32(i));
            _assertParity(values, prefix, lengths[i] + 4096, bytes32(i + 7), 31, bytes32(i + 1));
        }
    }

    function testFuzzCanonicalStateAndChallengeParity(
        bytes32 seed,
        uint16 rawPrefixLength,
        uint16 rawCapacity,
        bytes32 outputBlock,
        uint256 outputIndex,
        bytes32 poison
    ) external view {
        uint256 prefixLength = uint256(rawPrefixLength) % 1025;
        uint256 capacity = prefixLength + uint256(rawCapacity) % 4097;
        _assertParity(
            _canonicalValues(seed),
            _prefix(prefixLength, seed),
            capacity,
            outputBlock,
            outputIndex,
            poison
        );
    }

    function testRejectModulusAtEveryLimb() external view {
        _assertAllInvalidPositions(MODULUS);
    }

    function testRejectHighBitAtEveryLimb() external view {
        _assertAllInvalidPositions(0x80000000);
    }

    function testRejectUint32MaximumAtEveryLimb() external view {
        _assertAllInvalidPositions(type(uint32).max);
    }

    function testFirstInvalidExtensionWinsAcrossEveryBoundary() external view {
        bytes memory values = _canonicalValues(bytes32(uint256(0xcafe)));
        // Invalid neighboring extensions straddle every possible 32-byte chunk
        // boundary. Return the whole first extension, with its low 96 bits zero.
        for (uint256 extension; extension < 63; ++extension) {
            uint256 firstLimb = extension * 5 + 4;
            uint256 secondLimb = firstLimb + 1;
            uint256 savedFirst = _readLimb(values, firstLimb);
            uint256 savedSecond = _readLimb(values, secondLimb);
            _writeLimb(values, firstLimb, MODULUS);
            _writeLimb(values, secondLimb, type(uint32).max);
            bytes memory expected =
                abi.encodeWithSelector(PACKED_RANGE_ERROR, _packedExtension(values, extension));
            _assertExactRevert(values, false, expected);
            _assertExactRevert(values, true, expected);
            _writeLimb(values, firstLimb, savedFirst);
            _writeLimb(values, secondLimb, savedSecond);
        }
    }

    function testEntireFirstInvalidExtensionIsReported() external view {
        bytes memory values = _canonicalValues(bytes32(uint256(0xbad)));
        _writeLimb(values, 157, MODULUS);
        _writeLimb(values, 159, type(uint32).max);
        _writeLimb(values, 160, 0x80000000);
        _writeLimb(values, 319, MODULUS);
        bytes memory expected =
            abi.encodeWithSelector(PACKED_RANGE_ERROR, _packedExtension(values, 31));
        _assertExactRevert(values, false, expected);
        _assertExactRevert(values, true, expected);
    }

    function testRejectTruncationAndWrongLengthsBeforeReading() external view {
        uint256[15] memory lengths =
            [uint256(0), 1, 19, 20, 31, 32, 40, 1260, 1279, 1281, 1291, 1292, 1300, 1312, 2560];
        bytes memory expected = abi.encodeWithSignature("Error(string)", "BULK_EXT5_LENGTH");
        for (uint256 i; i < lengths.length; ++i) {
            bytes memory values = new bytes(lengths[i]);
            if (values.length != 0) {
                values[0] = 0xff;
            }
            _assertExactRevert(values, true, expected);
        }
    }

    function testFuzzRejectEveryWrongLength(uint16 rawLength) external view {
        uint256 length = uint256(rawLength) % 2561;
        if (length == 1280) {
            length = 1281;
        }
        _assertExactRevert(
            new bytes(length), true, abi.encodeWithSignature("Error(string)", "BULK_EXT5_LENGTH")
        );
    }

    function _assertParity(
        bytes memory values,
        bytes memory prefix,
        uint256 capacity,
        bytes32 outputBlock,
        uint256 outputIndex,
        bytes32 poison
    ) private view {
        KoalaBearBulkFinalObserverHarness.Observation memory pairs = harness.observe(
            values, prefix, capacity, outputBlock, outputIndex, poison, false
        );
        KoalaBearBulkFinalObserverHarness.Observation memory actual =
            harness.observe(values, prefix, capacity, outputBlock, outputIndex, poison, true);
        assertEq(abi.encode(actual), abi.encode(pairs), "bulk versus pair semantic state");
        assertEq(
            actual.input, bytes.concat(prefix, _littleEndian(values)), "independent LE encoding"
        );
        assertEq(actual.inputLen, prefix.length + 1280, "input length");
        assertEq(actual.outputIndex, 0, "output index reset");
        assertEq(actual.outputBlock, outputBlock, "output block retained before sampling");
        for (uint256 i; i < actual.challenges.length; ++i) {
            assertLt(actual.challenges[i], MODULUS, "challenge canonicality");
        }
    }

    function _assertAllInvalidPositions(uint256 invalid) private view {
        bytes memory values = _canonicalValues(bytes32(uint256(0x12345678)));
        for (uint256 limb; limb < 320; ++limb) {
            uint256 saved = _readLimb(values, limb);
            _writeLimb(values, limb, invalid);
            bytes memory expected =
                abi.encodeWithSelector(PACKED_RANGE_ERROR, _packedExtension(values, limb / 5));
            _assertExactRevert(values, false, expected);
            _assertExactRevert(values, true, expected);
            _writeLimb(values, limb, saved);
        }
    }

    function _assertExactRevert(bytes memory values, bool bulk, bytes memory expected)
        private
        view
    {
        (bool success, bytes memory reason) = address(harness)
            .staticcall(abi.encodeCall(harness.observeOnly, (values, bulk, ~bytes32(0))));
        assertFalse(success, "malformed input accepted");
        assertEq(reason, expected, "exact first invalid packed value or length reason");
    }

    function _canonicalValues(bytes32 seed) private pure returns (bytes memory values) {
        values = new bytes(1280);
        for (uint256 i; i < 320; ++i) {
            // Every lane varies independently of the production packing helpers.
            uint256 value = uint256(keccak256(abi.encode(seed, i))) % MODULUS;
            _writeLimb(values, i, value);
        }
    }

    function _prefix(uint256 length, bytes32 seed) private pure returns (bytes memory prefix) {
        prefix = new bytes(length);
        for (uint256 i; i < length; ++i) {
            unchecked {
                prefix[i] = bytes1(uint8(uint256(seed) + i * 13));
            }
        }
    }

    function _writeLimb(bytes memory values, uint256 limb, uint256 value) private pure {
        uint256 offset = limb * 4;
        values[offset] = bytes1(uint8(value >> 24));
        values[offset + 1] = bytes1(uint8(value >> 16));
        values[offset + 2] = bytes1(uint8(value >> 8));
        values[offset + 3] = bytes1(uint8(value));
    }

    function _readLimb(bytes memory values, uint256 limb) private pure returns (uint256 value) {
        for (uint256 i; i < 4; ++i) {
            value = (value << 8) | uint8(values[limb * 4 + i]);
        }
    }

    function _packedExtension(bytes memory values, uint256 extension)
        private
        pure
        returns (uint256 packed)
    {
        for (uint256 i; i < 20; ++i) {
            packed |= uint256(uint8(values[extension * 20 + i])) << (248 - i * 8);
        }
    }

    function _littleEndian(bytes memory values) private pure returns (bytes memory encoded) {
        encoded = new bytes(values.length);
        for (uint256 offset; offset < values.length; offset += 4) {
            encoded[offset] = values[offset + 3];
            encoded[offset + 1] = values[offset + 2];
            encoded[offset + 2] = values[offset + 1];
            encoded[offset + 3] = values[offset];
        }
    }
}
