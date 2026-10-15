// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/Test.sol";
import { KoalaBearExt5 as EF } from "../src/field/KoalaBearExt5.sol";
import { LeanVmTranscript as Transcript } from "../src/leanvm/LeanVmTranscript.sol";
import { LeanVmWhir as Whir } from "../src/leanvm/LeanVmWhir.sol";

contract LeanVmWhirContinuationBatchingHarness {
    function combine(
        Whir.Statement[] memory statements,
        uint256 carried,
        uint256[] memory queries,
        bool continuation
    ) external pure returns (uint256 gamma, uint256 target) {
        uint256[8] memory capacity;
        Transcript.State memory state = Transcript.initialize(capacity);
        Whir.Constraints memory constraints;
        if (continuation) {
            (constraints, target) = Whir.combineContinuation(state, statements, carried, queries);
        } else {
            require(carried == 0, "INITIAL_TARGET");
            (constraints, target) = Whir.combine(state, statements, 0, queries);
        }
        gamma = constraints.gamma;
    }

    function weights(Whir.Constraints memory constraints, uint256[] memory point)
        external
        pure
        returns (uint256 initial, uint256 genericContinuation, uint256 denseContinuation)
    {
        initial = Whir.evaluateConstraintWeights(constraints, point, false);
        genericContinuation = Whir.evaluateConstraintWeights(constraints, point, true);
        denseContinuation = Whir.evaluateContinuationWeights(constraints, point);
    }
}

contract LeanVmWhirContinuationBatchingTest is Test {
    uint256 private constant P = 2_130_706_433;
    uint256 private constant ONE = uint256(1) << 224;
    LeanVmWhirContinuationBatchingHarness private harness;

    function setUp() external {
        harness = new LeanVmWhirContinuationBatchingHarness();
    }

    function testOppositeCarriedAndFreshErrorsDoNotCancel() external view {
        Whir.Statement[] memory statements = new Whir.Statement[](1);
        uint256 delta = EF.pack([uint256(7), 11, 13, 17, 19]);
        statements[0] = Whir.dense(0, new uint256[](0), EF.sub(0, delta));
        (uint256 gamma, uint256 target) = harness.combine(statements, delta, new uint256[](0), true);
        assertNotEq(gamma, ONE);
        assertNotEq(target, 0);
        assertEq(target, EF.mulReference(delta, EF.sub(ONE, gamma)));
    }

    function testFuzzInitialAndContinuationClaimCoefficients(uint256 seed) external view {
        Whir.Statement[] memory statements = new Whir.Statement[](2);
        statements[0] = Whir.dense(0, new uint256[](0), _word(seed, 0));
        statements[1] = Whir.dense(0, new uint256[](0), _word(seed, 1));
        uint256[] memory queries = new uint256[](2);
        queries[0] = _word(seed, 2);
        queries[1] = _word(seed, 3);
        uint256 carried = _word(seed, 4);
        (uint256 gamma, uint256 initial) = harness.combine(statements, 0, queries, false);
        (uint256 continuationGamma, uint256 continuation) =
            harness.combine(statements, carried, queries, true);
        assertEq(continuationGamma, gamma);
        uint256 expected;
        uint256 power = ONE;
        for (uint256 i; i < 4; ++i) {
            expected = EF.add(expected, EF.mulReference(power, _word(seed, i)));
            power = EF.mulReference(power, gamma);
        }
        assertEq(initial, expected);
        assertEq(continuation, EF.add(carried, EF.mulReference(gamma, expected)));
    }

    function testFuzzContinuationWeightParity(uint256 seed) external view {
        uint256[] memory point = new uint256[](3);
        Whir.Statement[] memory statements = new Whir.Statement[](2);
        for (uint256 i; i < point.length; ++i) {
            point[i] = _word(seed, i);
        }
        for (uint256 i; i < statements.length; ++i) {
            uint256[] memory claimPoint = new uint256[](point.length);
            for (uint256 j; j < point.length; ++j) {
                claimPoint[j] = _word(seed, 3 + i * 3 + j);
            }
            statements[i] = Whir.dense(point.length, claimPoint, 0);
        }
        uint256[] memory basePoints = new uint256[](2);
        basePoints[0] = seed % P;
        basePoints[1] = uint256(keccak256(abi.encode(seed))) % P;
        uint256 gamma = _word(seed, 9);
        Whir.Constraints memory constraints = Whir.Constraints(gamma, statements, basePoints);
        (uint256 initial, uint256 genericContinuation, uint256 denseContinuation) =
            harness.weights(constraints, point);
        uint256 expected;
        uint256 power = ONE;
        for (uint256 i; i < statements.length + basePoints.length; ++i) {
            uint256[] memory claimPoint;
            if (i < statements.length) {
                claimPoint = statements[i].point;
            } else {
                claimPoint = new uint256[](point.length);
                uint256 x = basePoints[i - statements.length];
                for (uint256 j; j < point.length; ++j) {
                    claimPoint[j] = EF.fromBase(x);
                    x = mulmod(x, x, P);
                }
            }
            expected = EF.add(expected, EF.mulReference(power, _eq(claimPoint, point)));
            power = EF.mulReference(power, gamma);
        }
        assertEq(initial, expected);
        assertEq(genericContinuation, EF.mulReference(gamma, expected));
        assertEq(denseContinuation, genericContinuation);
    }

    function _eq(uint256[] memory a, uint256[] memory b) private pure returns (uint256 value) {
        value = ONE;
        for (uint256 i; i < a.length; ++i) {
            uint256 equal = EF.add(
                EF.mulReference(a[i], b[i]), EF.mulReference(EF.sub(ONE, a[i]), EF.sub(ONE, b[i]))
            );
            value = EF.mulReference(value, equal);
        }
    }

    function _word(uint256 seed, uint256 index) private pure returns (uint256) {
        uint256[5] memory coefficients;
        for (uint256 i; i < coefficients.length; ++i) {
            coefficients[i] = uint256(keccak256(abi.encode(seed, index, i))) % P;
        }
        return EF.pack(coefficients);
    }
}
