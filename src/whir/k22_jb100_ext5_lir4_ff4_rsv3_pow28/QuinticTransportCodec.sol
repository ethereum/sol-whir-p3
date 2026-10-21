// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Lossless WHRC transport for quintic WHRB proofs.
library QuinticTransportCodec {
    error InvalidTransportEncoding();

    uint256 internal constant MAX_DECODED_BYTES = 5_268_590;

    /// @dev Check envelope bounds without allocating or expanding the full proof.
    function inspect(bytes calldata encoded)
        internal
        pure
        returns (bytes calldata payload, bool structured)
    {
        if (encoded.length < 14) revert InvalidTransportEncoding();
        uint256 prefix;
        uint256 mode;
        uint256 decodedLength;
        uint256 payloadLength;
        assembly ("memory-safe") {
            let word := calldataload(encoded.offset)
            prefix := shr(216, word)
            mode := byte(5, word)
            decodedLength := and(shr(176, word), 0xffffffff)
            payloadLength := and(shr(144, word), 0xffffffff)
        }
        if (
            prefix != 0x5748524301 || decodedLength > MAX_DECODED_BYTES
                || payloadLength != encoded.length - 14
        ) revert InvalidTransportEncoding();
        payload = encoded[14:];
        if (mode == 0) {
            if (decodedLength != payloadLength) revert InvalidTransportEncoding();
            return (payload, false);
        }
        if (mode != 1 || payloadLength < 18) revert InvalidTransportEncoding();
        uint256 whirPrefix;
        uint256 count;
        assembly ("memory-safe") {
            let word := calldataload(payload.offset)
            whirPrefix := shr(176, word)
            count := add(
                add(and(shr(160, word), 0xffff), and(shr(144, word), 0xffff)),
                add(and(shr(128, word), 0xffff), and(shr(112, word), 0xffff))
            )
        }
        if (
            (whirPrefix != 0x57485242000114050303 && whirPrefix != 0x57485242010114050303)
                || decodedLength != 25_790 + 20 * count || payloadLength < decodedLength - 20_395
                || payloadLength > decodedLength + 65
        ) revert InvalidTransportEncoding();
        return (payload, true);
    }

    /// @dev Validate every encoded row range and record offsets for reverse Horner order.
    function rowOffsets(bytes calldata blob, uint256 offset, uint256 count, uint256 n)
        internal
        pure
        returns (uint256[] memory offsets, uint256 next)
    {
        offsets = new uint256[](count);
        assembly ("memory-safe") {
            function badEncoding() {
                mstore(0, shl(224, 0xb750bb09))
                revert(0, 4)
            }
            let ptr := add(blob.offset, offset)
            let end := add(blob.offset, blob.length)
            for { let i := 0 } lt(i, count) { i := add(i, 1) } {
                if iszero(lt(ptr, end)) { badEncoding() }
                mstore(add(add(offsets, 32), mul(i, 32)), sub(ptr, blob.offset))
                let mask := byte(0, calldataload(ptr))
                if and(mask, 0xe0) { badEncoding() }
                let width := mul(n, 20)
                switch mask
                case 0 { }
                case 30 { width := add(mul(n, 4), 16) }
                case 31 { width := 20 }
                default {
                    let bits :=
                        add(
                            add(and(mask, 1), and(shr(1, mask), 1)),
                            add(
                                add(and(shr(2, mask), 1), and(shr(3, mask), 1)),
                                and(shr(4, mask), 1)
                            )
                        )
                    width := sub(width, mul(mul(bits, 4), sub(n, 1)))
                }
                ptr := add(ptr, add(1, width))
                if gt(ptr, end) { badEncoding() }
            }
            next := sub(ptr, blob.offset)
        }
    }

    /// @dev Caller reserves 20*n+12 writable bytes; returned offset is exact.
    function decodeRowInto(bytes calldata blob, uint256 input, uint256 output, uint256 n)
        internal
        pure
        returns (uint256 next)
    {
        (next,) = _rows(blob, input, output, 1, n);
    }

    function decodePolynomial(bytes calldata blob, uint256 input)
        internal
        pure
        returns (bytes memory polynomial, uint256 next)
    {
        // Extra padding contains the last overlapping 32-byte element store.
        polynomial = new bytes(1312);
        uint256 output;
        assembly ("memory-safe") {
            mstore(polynomial, 1280)
            output := add(polynomial, 32)
        }
        (next,) = _rows(blob, input, output, 1, 64);
    }

    function decode(bytes calldata encoded) internal pure returns (bytes memory decoded) {
        if (encoded.length < 14) revert InvalidTransportEncoding();
        uint256 prefix;
        uint256 mode;
        uint256 decodedLength;
        uint256 payloadLength;
        assembly ("memory-safe") {
            let word := calldataload(encoded.offset)
            prefix := shr(216, word)
            mode := byte(5, word)
            decodedLength := and(shr(176, word), 0xffffffff)
            payloadLength := and(shr(144, word), 0xffffffff)
        }
        if (
            prefix != 0x5748524301 || decodedLength > MAX_DECODED_BYTES
                || payloadLength != encoded.length - 14
        ) revert InvalidTransportEncoding();
        if (mode == 0) {
            if (decodedLength != payloadLength) revert InvalidTransportEncoding();
            return encoded[14:];
        }
        if (mode != 1 || payloadLength < 18) revert InvalidTransportEncoding();
        uint256 whirPrefix;
        uint256 d0;
        uint256 d1;
        uint256 d2;
        uint256 df;
        assembly ("memory-safe") {
            let word := calldataload(add(encoded.offset, 14))
            whirPrefix := shr(176, word)
            d0 := and(shr(160, word), 0xffff)
            d1 := and(shr(144, word), 0xffff)
            d2 := and(shr(128, word), 0xffff)
            df := and(shr(112, word), 0xffff)
        }
        // BFS and DFS sibling orders share the same section shapes. Preserve
        // the version and sibling bytes for the selected Merkle traversal.
        if (
            (whirPrefix != 0x57485242000114050303 && whirPrefix != 0x57485242010114050303)
                || decodedLength != 25_790 + 20 * (d0 + d1 + d2 + df)
                || payloadLength < decodedLength - 20_395 || payloadLength > decodedLength + 65
        ) revert InvalidTransportEncoding();
        decoded = new bytes(decodedLength);
        uint256 output;
        assembly ("memory-safe") { output := add(decoded, 32) }
        uint256 input = 14;
        (input, output) = _copy(encoded, input, output, 3390 + 20 * d0);
        (input, output) = _rows(encoded, input, output, 31, 16);
        (input, output) = _copy(encoded, input, output, 220 + 20 * d1);
        (input, output) = _rows(encoded, input, output, 19, 16);
        (input, output) = _copy(encoded, input, output, 176 + 20 * d2);
        (input, output) = _rows(encoded, input, output, 1, 64);
        (input, output) = _copy(encoded, input, output, 4);
        (input, output) = _rows(encoded, input, output, 14, 16);
        (input, output) = _copy(encoded, input, output, 240 + 20 * df);
        if (input != encoded.length) revert InvalidTransportEncoding();
        assembly ("memory-safe") {
            if iszero(eq(output, add(add(decoded, 32), decodedLength))) {
                mstore(0, shl(224, 0xb750bb09))
                revert(0, 4)
            }
        }
    }

    function _copy(bytes calldata encoded, uint256 input, uint256 output, uint256 length)
        private
        pure
        returns (uint256 nextInput, uint256 nextOutput)
    {
        if (input > encoded.length || length > encoded.length - input) {
            revert InvalidTransportEncoding();
        }
        assembly ("memory-safe") { calldatacopy(output, add(encoded.offset, input), length) }
        return (input + length, output + length);
    }

    function _rows(bytes calldata encoded, uint256 input, uint256 output, uint256 count, uint256 n)
        private
        pure
        returns (uint256 nextInput, uint256 nextOutput)
    {
        // MSTORE reconstructs a 20-byte element with a 32-byte store, so the
        // final store in a row writes 12 bytes past that row. All such writes
        // remain inside the decoded allocation: the last compressed region
        // has at least the 240-byte final-sumcheck tail. The next row or copy
        // restores every overwritten following byte before decoded is used.
        // This layer preserves arbitrary 32-bit words. The WHIR verifier
        // performs canonical field validation after reconstruction.
        assembly ("memory-safe") {
            function badEncoding() {
                mstore(0, shl(224, 0xb750bb09))
                revert(0, 4)
            }
            function expandOne(ptr, out, elements, c, end) -> nextPtr, nextOut {
                nextPtr := add(ptr, add(mul(elements, 4), 16))
                if gt(nextPtr, end) { badEncoding() }
                let before := mul(c, 32)
                let variable := add(ptr, mul(c, 4))
                let variableEnd := add(variable, mul(elements, 4))
                let prefixMask := not(sub(shl(sub(256, before), 1), 1))
                let constantWord :=
                    or(
                        and(calldataload(ptr), prefixMask),
                        and(
                            shr(add(before, 32), calldataload(variableEnd)),
                            not(sub(shl(96, 1), 1))
                        )
                    )
                let shift := sub(224, before)
                // Both supported row lengths are multiples of four.
                for { } lt(variable, variableEnd) { variable := add(variable, 16) } {
                    mstore(out, or(constantWord, shl(shift, shr(224, calldataload(variable)))))
                    mstore(
                        add(out, 20),
                        or(constantWord, shl(shift, shr(224, calldataload(add(variable, 4)))))
                    )
                    mstore(
                        add(out, 40),
                        or(constantWord, shl(shift, shr(224, calldataload(add(variable, 8)))))
                    )
                    mstore(
                        add(out, 60),
                        or(constantWord, shl(shift, shr(224, calldataload(add(variable, 12)))))
                    )
                    out := add(out, 80)
                }
                nextOut := out
            }
            let ptr := add(encoded.offset, input)
            let end := add(encoded.offset, encoded.length)
            let width := mul(n, 20)
            for { let row := 0 } lt(row, count) { row := add(row, 1) } {
                if iszero(lt(ptr, end)) { badEncoding() }
                let mask := byte(0, calldataload(ptr))
                ptr := add(ptr, 1)
                if and(mask, 0xe0) { badEncoding() }
                switch mask
                case 0 {
                    if gt(add(ptr, width), end) { badEncoding() }
                    calldatacopy(output, ptr, width)
                    ptr := add(ptr, width)
                    output := add(output, width)
                }
                // All five orientations of one variable coordinate are supported.
                case 30 { ptr, output := expandOne(ptr, output, n, 0, end) }
                case 29 { ptr, output := expandOne(ptr, output, n, 1, end) }
                case 27 { ptr, output := expandOne(ptr, output, n, 2, end) }
                case 23 { ptr, output := expandOne(ptr, output, n, 3, end) }
                case 15 { ptr, output := expandOne(ptr, output, n, 4, end) }
                case 31 {
                    if gt(add(ptr, 20), end) { badEncoding() }
                    let word := and(calldataload(ptr), not(sub(shl(96, 1), 1)))
                    ptr := add(ptr, 20)
                    let outputEnd := add(output, width)
                    for { } lt(output, outputEnd) { output := add(output, 20) } {
                        mstore(output, word)
                    }
                }
                default {
                    let constantWord := 0
                    let variableCount := 0
                    let variableShift := 0
                    let variablePtr := 0
                    // Five packed relative offsets (32 bits each) avoid allocating a pointer array.
                    let columnOffsets := 0
                    for { let c := 0 } lt(c, 5) { c := add(c, 1) } {
                        let shift := sub(224, mul(c, 32))
                        switch and(shr(c, mask), 1)
                        case 1 {
                            if gt(add(ptr, 4), end) { badEncoding() }
                            let value := shr(224, calldataload(ptr))
                            constantWord := or(constantWord, shl(shift, value))
                            ptr := add(ptr, 4)
                        }
                        default {
                            if gt(add(ptr, mul(n, 4)), end) { badEncoding() }
                            columnOffsets := or(
                                columnOffsets,
                                shl(mul(c, 32), sub(ptr, encoded.offset))
                            )
                            variableCount := add(variableCount, 1)
                            variableShift := shift
                            variablePtr := ptr
                            ptr := add(ptr, mul(n, 4))
                        }
                    }
                    switch variableCount
                    case 0 {
                        for { let r := 0 } lt(r, n) { r := add(r, 1) } {
                            mstore(output, constantWord)
                            output := add(output, 20)
                        }
                    }
                    case 1 {
                        for { let r := 0 } lt(r, n) { r := add(r, 1) } {
                            let value := shr(224, calldataload(variablePtr))
                            mstore(output, or(constantWord, shl(variableShift, value)))
                            variablePtr := add(variablePtr, 4)
                            output := add(output, 20)
                        }
                    }
                    default {
                        for { let r := 0 } lt(r, n) { r := add(r, 1) } {
                            let word := constantWord
                            for { let c := 0 } lt(c, 5) { c := add(c, 1) } {
                                if iszero(and(shr(c, mask), 1)) {
                                    let offset := and(shr(mul(c, 32), columnOffsets), 0xffffffff)
                                    let value :=
                                        shr(
                                            224,
                                            calldataload(
                                                add(add(encoded.offset, offset), mul(r, 4))
                                            )
                                        )
                                    word := or(word, shl(sub(224, mul(c, 32)), value))
                                }
                            }
                            mstore(output, word)
                            output := add(output, 20)
                        }
                    }
                }
            }
            nextInput := sub(ptr, encoded.offset)
            nextOutput := output
        }
    }
}
