// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { LeanVmGroupedExecution as Execution } from "../src/leanvm/LeanVmGroupedExecution.sol";
import { LeanVmGroupedLogUp as Grouped } from "../src/leanvm/LeanVmGroupedLogUp.sol";
import {
    LeanVmTwoCommitmentExecution as Core
} from "../src/leanvm/LeanVmTwoCommitmentExecution.sol";
import { LeanVmWhir as Whir } from "../src/leanvm/LeanVmWhir.sol";

contract LeanVmGroupedStatementsTest is Test {
    uint256 private constant ONE = uint256(1) << 224;

    function checkProgramStatements(uint256 variables) internal pure {
        uint256 padding = variables - 23;
        uint256[] memory dimensions = new uint256[](5);
        dimensions[0] = 6;
        dimensions[1] = 19 + padding;
        dimensions[2] = 17 + padding;
        dimensions[3] = 15 + padding;
        dimensions[4] = 13 + padding;
        Grouped.Layout memory layout = Grouped.layout(dimensions, 17, variables);
        Grouped.Claims memory claims;
        for (uint256 kind; kind < 5; ++kind) {
            claims.points[kind] = new uint256[](layout.heights[kind]);
            claims.values[kind] = new uint256[](Grouped.claimCount(kind));
        }
        Core.FixedProgramClaims memory fixedClaims;
        fixedClaims.sparkPoint = new uint256[](22);
        fixedClaims.liftPoint = new uint256[](21);
        for (uint256 i; i < 22; ++i) {
            fixedClaims.sparkPoint[i] = (i + 2) << 224;
        }
        for (uint256 i; i < 21; ++i) {
            fixedClaims.liftPoint[i] = (i + 25) << 224;
        }
        Core.TwoCommitmentConfig memory fixedConfig;
        fixedConfig.secondaryStatementPointPrefixLengths = [padding + 1, padding + 2];
        fixedConfig.secondaryStatementPointPrefixes = new uint256[](2 * padding + 3);
        fixedConfig.secondaryStatementPointPrefixes[2 * padding + 1] = ONE;
        Whir.Statement memory unused;
        Whir.Statement[][3] memory statements = Execution.buildStatements(
            layout, claims, new uint256[](4), fixedClaims, fixedConfig, unused, unused, 131_071
        );
        assertEq(statements[1][0].point.length, variables);
        assertEq(statements[1][1].point.length, variables);
        for (uint256 i; i < variables; ++i) {
            uint256 expectedSpark = i <= padding ? 0 : fixedClaims.sparkPoint[i - padding - 1];
            uint256 expectedLift = i < padding
                ? 0
                : (i == padding
                        ? ONE
                        : (i == padding + 1 ? 0 : fixedClaims.liftPoint[i - padding - 2]));
            assertEq(statements[1][0].point[i], expectedSpark);
            assertEq(statements[1][1].point[i], expectedLift);
        }
        // Every root instruction slice retains its physical address when the
        // polynomial gains a leading zero coordinate.
        Whir.Statement memory root = statements[1][2];
        assertEq(root.variables, variables);
        assertEq(root.point.length, 18);
        assertEq(root.selectors.length, 8);
        for (uint256 i; i < 8; ++i) {
            assertEq(root.selectors[i], 24 + i);
            assertEq(root.selectors[i] << root.point.length, (uint256(3) << 21) + (i << 18));
        }
    }

    function testUnpaddedProgramStatements() external pure {
        checkProgramStatements(23);
    }

    function testPaddedProgramStatements() external pure {
        checkProgramStatements(24);
    }
}
