// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { LeanVmGroupedTerminalVerifier } from "../LeanVmGroupedTerminalVerifier.sol";
import { LeanVmTwoCommitmentExecution as Execution } from "../LeanVmTwoCommitmentExecution.sol";
import { LeanVmWhir as Whir } from "../LeanVmWhir.sol";

contract LeanVmGroupedTerminal_KeccakPow28T6 is LeanVmGroupedTerminalVerifier {
    function rootConfig() internal pure virtual override returns (Execution.Config memory config) {
        config.bytecodeLog = 17;
        config.endingPc = 131_071;
        config.rate = 6;
        config.capacity = [
            uint256(75_907_950),
            145_299_416,
            283_012_356,
            2_002_785_192,
            1_938_527_388,
            1_074_857_094,
            1_241_171_420,
            995_158_161
        ];
        config.whir.variables = 23;
        config.whir.firstFold = 5;
        config.whir.nextFold = 4;
        config.whir.commitmentOod = 1;
        config.whir.firstPow = 0;
        config.whir.finalRounds = 6;
        config.whir.rounds = new Whir.Round[](3);
        config.whir.rounds[0] = Whir.Round(18, 5, 536_870_912, 1_791_270_792, 25, 1, 28, 0);
        config.whir.rounds[1] = Whir.Round(14, 4, 268_435_456, 1_791_270_792, 15, 1, 28, 0);
        config.whir.rounds[2] = Whir.Round(10, 4, 134_217_728, 1_760_025_929, 12, 1, 25, 4);
        config.whir.finalRound = Whir.Round(6, 4, 67_108_864, 542_991_299, 10, 1, 23, 0);
        config.whir.openingsCodec = 1;
    }

    function fixedProgramConfig()
        internal
        pure
        virtual
        override
        returns (Execution.TwoCommitmentConfig memory config)
    {
        config.modeTag = 844_562_433;
        config.batchingPowBits = 2;
        config.programDimensions = [uint256(22), 21, 21];
        config.secondaryActualDataLength = 8_388_608;
        config.secondaryStatementPublicMemoryOffsets = [uint256(128), 8];
        config.secondaryStatementPointPrefixLengths = [uint256(1), 2];
        config.secondaryStatementPointPrefixes = new uint256[](3);
        config.secondaryStatementPointPrefixes[1] =
        26_959_946_667_150_639_794_667_015_087_019_630_673_637_144_422_540_572_481_103_610_249_216;
        config.executionBytecodePointPrefix = new uint256[](2);
        config.executionBytecodePointPrefix[0] =
        26_959_946_667_150_639_794_667_015_087_019_630_673_637_144_422_540_572_481_103_610_249_216;
        config.executionBytecodePointPrefix[1] =
        26_959_946_667_150_639_794_667_015_087_019_630_673_637_144_422_540_572_481_103_610_249_216;
        config.expectedSecondaryRoot = [
            uint256(886_056_696),
            330_162_236,
            800_875_885,
            974_140_987,
            978_542_848,
            459_213_441,
            133_560_788,
            798_226_065
        ];
    }

    function liftedCapacity() internal pure virtual override returns (uint256[8] memory) {
        return [
            uint256(2_050_310_400),
            335_847_278,
            1_979_180_525,
            1_713_299_977,
            979_133_116,
            1_107_287_738,
            206_966_687,
            2_025_698_229
        ];
    }
}
