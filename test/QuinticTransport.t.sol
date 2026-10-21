// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test } from "forge-std/Test.sol";
import {
    QuinticTransportCodec
} from "../src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/QuinticTransportCodec.sol";
import {
    WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28 as Native
} from "../src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol";

contract QuinticTransportHarness {
    function decode(bytes calldata encoded) external pure returns (bytes memory) {
        return QuinticTransportCodec.decode(encoded);
    }
}

contract QuinticTransportTest is Test {
    QuinticTransportHarness internal decoder;
    Native internal verifier;
    bytes32 internal constant ROOT =
        0xf69b4bb68df98445e815d84e921ea43e28423545000000000000000000000000;
    string internal constant STEM = "quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_";

    function setUp() public {
        decoder = new QuinticTransportHarness();
        verifier = new Native();
    }

    function testDecodeSuccessExact() public view {
        assertEq(
            decoder.decode(vm.readFileBinary("testdata/transport/success.whrc")),
            vm.readFileBinary(string.concat("testdata/", STEM, "success.blob"))
        );
    }

    function testDecodeDfsTransportExact() public view {
        assertEq(
            decoder.decode(vm.readFileBinary("testdata/transport/success.dfs.whrc")),
            vm.readFileBinary("testdata/transport/success.dfs.blob")
        );
    }

    function testVerifyCompressedSuccess() public view {
        assertTrue(
            verifier.verifyCompressed(ROOT, vm.readFileBinary("testdata/transport/success.whrc"))
        );
    }

    function testVerifyRawTransportSuccess() public view {
        assertTrue(
            verifier.verifyCompressed(
                ROOT, vm.readFileBinary("testdata/transport/success.raw.whrc")
            )
        );
    }

    function testAllMaskAndRawParity() public view {
        string[4] memory names = ["all_masks", "invalid_field", "raw_random", "noncanonical_masks"];
        for (uint256 i; i < names.length; ++i) {
            assertEq(
                decoder.decode(
                    vm.readFileBinary(string.concat("testdata/transport/", names[i], ".whrc"))
                ),
                vm.readFileBinary(string.concat("testdata/transport/", names[i], ".blob"))
            );
        }
    }

    function testInvalidProofExactDecodedAndRevertParity() public {
        string[3] memory kinds =
            ["bad_commitment", "bad_ood_or_transcript_mismatch", "bad_stir_query"];
        for (uint256 i; i < kinds.length; ++i) {
            bytes memory blob =
                vm.readFileBinary(string.concat("testdata/", STEM, "failure_", kinds[i], ".blob"));
            bytes memory encoded = vm.readFileBinary(
                string.concat("testdata/transport/", STEM, "failure_", kinds[i], ".whrc")
            );
            assertEq(decoder.decode(encoded), blob);
            (bool nativeOk, bytes memory nativeReturn) =
                address(verifier).staticcall(abi.encodeCall(verifier.verify, (ROOT, blob)));
            (bool compactOk, bytes memory compactReturn) = address(verifier)
                .staticcall(abi.encodeCall(verifier.verifyCompressed, (ROOT, encoded)));
            assertFalse(nativeOk);
            assertFalse(compactOk);
            assertEq(compactReturn, nativeReturn);
        }
    }

    function testRejectMaskReservedBits() public {
        bytes memory encoded = vm.readFileBinary("testdata/transport/success.whrc");
        encoded[15_564] = 0x20;
        vm.expectRevert(QuinticTransportCodec.InvalidTransportEncoding.selector);
        decoder.decode(encoded);
    }

    function testNoncanonicalCompressedRevertParity() public {
        bytes memory encoded = vm.readFileBinary("testdata/transport/success.whrc");
        encoded[15_565] = 0xff;
        bytes memory decoded = decoder.decode(encoded);
        assertEq(uint8(decoded[15_550]), uint8(0xff));
        (bool nativeOk, bytes memory nativeReturn) =
            address(verifier).staticcall(abi.encodeCall(verifier.verify, (ROOT, decoded)));
        (bool compactOk, bytes memory compactReturn) =
            address(verifier).staticcall(abi.encodeCall(verifier.verifyCompressed, (ROOT, encoded)));
        assertFalse(nativeOk);
        assertFalse(compactOk);
        assertEq(compactReturn, nativeReturn);
    }

    function testRejectHugeLengthBeforeAllocation() public {
        bytes memory encoded = vm.readFileBinary("testdata/transport/success.whrc");
        encoded[6] = 0xff;
        vm.expectRevert(QuinticTransportCodec.InvalidTransportEncoding.selector);
        decoder.decode(encoded);
    }

    function testRejectDeclaredDecodedLengthMismatch() public {
        uint32 decodedLength =
            uint32(vm.readFileBinary(string.concat("testdata/", STEM, "success.blob")).length);
        string[3] memory names = ["success", "success.dfs", "success.raw"];
        for (uint256 i; i < names.length; ++i) {
            bytes memory encoded =
                vm.readFileBinary(string.concat("testdata/transport/", names[i], ".whrc"));
            _writeUint32(encoded, 6, decodedLength - 1);
            _expectTransportRejection(encoded);
            _writeUint32(encoded, 6, decodedLength + 1);
            _expectTransportRejection(encoded);
        }
    }

    function testRejectTruncationAndTrailing() public {
        bytes memory encoded = vm.readFileBinary("testdata/transport/success.whrc");
        bytes memory extra = bytes.concat(encoded, hex"00");
        _expectTransportRejection(extra);
        // Change declared payload length too, so the inner exact-consumption check is tested.
        _writeUint32(extra, 10, uint32(extra.length - 14));
        _expectTransportRejection(extra);
        assembly ("memory-safe") { mstore(encoded, sub(mload(encoded), 1)) }
        _expectTransportRejection(encoded);
        _writeUint32(encoded, 10, uint32(encoded.length - 14));
        vm.expectRevert(QuinticTransportCodec.InvalidTransportEncoding.selector);
        decoder.decode(encoded);
        (bool ok, bytes memory errorData) = address(verifier)
            .staticcall(abi.encodeCall(verifier.verifyCompressed, (ROOT, encoded)));
        assertFalse(ok);
        assertGe(errorData.length, 4, "require a verifier error");
    }

    function testRawArbitraryBytes() public view {
        assertEq(decoder.decode(hex"5748524301000000000300000003616263"), hex"616263");
        assertEq(decoder.decode(hex"5748524301000000000000000000"), hex"");
    }

    function testFuzzRawRoundTrip(bytes calldata blob) public view {
        bytes memory encoded = abi.encodePacked(
            bytes4(0x57485243), uint8(1), uint8(0), uint32(blob.length), uint32(blob.length), blob
        );
        assertEq(decoder.decode(encoded), blob);
    }

    function _expectTransportRejection(bytes memory encoded) private {
        vm.expectRevert(QuinticTransportCodec.InvalidTransportEncoding.selector);
        decoder.decode(encoded);
        vm.expectRevert(QuinticTransportCodec.InvalidTransportEncoding.selector);
        verifier.verifyCompressed(ROOT, encoded);
    }

    function _writeUint32(bytes memory encoded, uint256 offset, uint32 value) private pure {
        for (uint256 i; i < 4; ++i) {
            encoded[offset + i] = bytes1(uint8(value >> ((3 - i) * 8)));
        }
    }
}
