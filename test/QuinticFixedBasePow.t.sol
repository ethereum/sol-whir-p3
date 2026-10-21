// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import { Test } from "forge-std/Test.sol";
import { KoalaBear } from "../src/field/KoalaBear.sol";
import {
    WhirVerifierCore5 as C
} from "../src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirVerifierCore5.sol";

contract QuinticFixedBasePowHarness {
    function powers(uint256[] memory values, uint256 base, uint256 count)
        external
        pure
        returns (uint256[] memory)
    {
        require(count <= values.length);
        C._fillSelVarsPow(values, base, count);
        return values;
    }
}

contract QuinticFixedBasePowTest is Test {
    QuinticFixedBasePowHarness private h;

    function setUp() external {
        h = new QuinticFixedBasePowHarness();
    }

    function testFuzzAllFourTables(bytes32 seed) external view {
        uint256[4] memory bases = [uint256(542_991_299), 339_671_193, 1_816_824_389, 373_019_801];
        uint256[4] memory widths = [uint256(22), 19, 18, 17];
        for (uint256 t; t < 4; ++t) {
            uint256[] memory values = new uint256[](18);
            uint256[] memory expected = new uint256[](18);
            for (uint256 i; i < 18; ++i) {
                uint256 e = i == 0
                    ? 0
                    : i == 1
                        ? (1 << widths[t]) - 1
                        : uint256(keccak256(abi.encode(seed, t, i))) % (1 << widths[t]);
                values[i] = e;
                expected[i] = _pow(bases[t], e);
            }
            assertEq(h.powers(values, bases[t], values.length), expected);
        }
    }

    function testEmptyAndPrefixAndFallback() external view {
        uint256[] memory values = new uint256[](4);
        values[0] = 0;
        values[1] = 1;
        values[2] = 12_345;
        values[3] = 5;
        uint256[] memory actual = h.powers(values, 542_991_299, 2);
        assertEq(actual[0], 1);
        assertEq(actual[1], 542_991_299);
        assertEq(actual[2], 12_345);
        assertEq(actual[3], 5);
        assertEq(h.powers(new uint256[](0), 542_991_299, 0).length, 0);
        actual = h.powers(values, 7, 4);
        for (uint256 i; i < 4; ++i) {
            assertEq(actual[i], _pow(7, values[i]));
        }
    }

    function _pow(uint256 base, uint256 e) private pure returns (uint256 r) {
        r = 1;
        while (e != 0) {
            if (e & 1 != 0) r = mulmod(r, base, 0x7f000001);
            base = mulmod(base, base, 0x7f000001);
            e >>= 1;
        }
    }
}
