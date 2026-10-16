# sol-spartan-whir

Solidity verifiers for standalone WHIR polynomial openings over KoalaBear and BabyBear. The repository also includes a grouped LeanVM terminal verifier for recursively verified Spartan-WHIR proofs.

The Rust [`spartan-whir`](https://github.com/ethereum/spartan-whir) implementation is the protocol source of truth. [`spartan-whir-export`](https://github.com/Client-Side-Proving/spartan-whir-export) generates Solidity-compatible standalone-WHIR fixtures.

## Build and test

```sh
forge build
forge test --offline --isolate --threads 1
```

Runtime fixtures are checked in under [`testdata/`](testdata/), so the test suite does not require the Rust exporter. Regenerate the default KoalaBear fixtures with:

```sh
cargo run --release \
  --manifest-path "$SPARTAN_WHIR_EXPORT_DIR/Cargo.toml" \
  --bin export-fixtures -- testdata
```

See [AGENTS.md](AGENTS.md) for schedule-specific export, gas measurement, compiler analysis, and precompile-runner commands.

## Verifiers

| Target                                                             | Contract                                                                                                                                                                                            | Public entrypoint             |
| ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| KoalaBear quartic, `lir6_ff5_rsv1` (80-bit target, `2^16` entries) | [`WhirBlobVerifierNative4`](src/whir/lir6/WhirBlobVerifierNative4_lir6_ff5_rsv1.sol)                                                                                                                | `verify(bytes32,bytes)`       |
| KoalaBear quintic, `k22_jb100_ext5_lir4_ff4_rsv3_pow28`            | [`WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28`](src/whir/k22_jb100_ext5_lir4_ff4_rsv3_pow28/WhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol)                          | `verify(bytes32,bytes)`       |
| BabyBear quintic, `k22_jb100_ext5_lir4_ff4_rsv3_pow28`             | [`BabyBearWhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28`](src/whir/babybear_k22_jb100_ext5_lir4_ff4_rsv3_pow28/BabyBearWhirBlobVerifierNative5_k22_jb100_ext5_lir4_ff4_rsv3_pow28.sol) | `verify(bytes32,bytes)`       |
| KoalaBear octic, `k22_jb100_lir6_ff4_rsv1`                         | [`WhirBlobVerifierNative8_k22_jb100_lir6_ff4_rsv1`](src/whir/k22_jb100_lir6_ff4_rsv1/WhirBlobVerifierNative8_k22_jb100_lir6_ff4_rsv1.sol)                                                           | `verify(bytes32,bytes)`       |
| LeanVM grouped terminal, `GroupedLogupKeccakPow28T6`               | [`LeanVmGroupedTerminal_KeccakPow28T6`](src/leanvm/generated/LeanVmGroupedTerminal_KeccakPow28T6.sol)                                                                                               | `verifyGroupedLogupV1(Proof)` |

### Standalone WHIR API

The native blob contracts expose:

```solidity
function verify(bytes32 expectedCommitment, bytes calldata blob)
    external
    pure
    returns (bool);
```

`expectedCommitment` is the Merkle root bound by the opening claim. `blob` contains the statement and proof in the schedule-specific compact format. The blob header does not identify the field; callers must select the contract matching the proof source.

Each standalone target also provides:

- a typed verifier with `verify(bytes32, WhirStructs.WhirStatement, WhirStructs.WhirProof)`;
- a decode-and-delegate blob wrapper constructed with the typed verifier address;
- a native blob verifier that parses and verifies in one contract.

### LeanVM terminal API

The generated contract pins the proof parameters and program commitment, and verifies the application root and recursive claims supplied in `Proof`. See the [checked-in fixture](testdata/leanvm_terminal/GroupedLogupKeccakPow28T6/) and [terminal workflow](AGENTS.md#leanvm-terminal-workflow) for generation and validation.

## Latest measurements

| Verifier                                          | Foundry gas | Transaction gas | Execution gas |   Calldata |    Runtime / initcode |
| ------------------------------------------------- | ----------: | --------------: | ------------: | ---------: | --------------------: |
| KoalaBear quartic (80-bit target, `2^16` entries) |   `824,084` |       `899,380` |     `718,740` | `10,276` B | `23,306` / `23,332` B |
| KoalaBear quintic                                 | `3,518,733` |     `3,637,880` |   `2,760,544` | `54,436` B | `34,898` / `34,924` B |
| BabyBear quintic                                  | `3,240,976` |     `3,364,794` |   `2,489,346` | `54,084` B | `33,780` / `33,806` B |
| KoalaBear octic                                   | `5,356,053` |     `5,637,745` |   `4,862,945` | `47,780` B | `36,710` / `36,736` B |
| LeanVM grouped terminal                           |           - |    `10,666,368` |   `9,127,132` | `99,044` B | `62,623` / `62,649` B |

Transaction gas is measured from Anvil receipts. Execution gas is `transaction gas - 21,000 - calldata gas`. The standalone measurements use `solc 0.8.28`, `via_ir`, 833 optimizer runs, and the Prague EVM target.

The LeanVM measurement uses the same compiler settings and a Cancun Anvil transaction with a 1,000,000,000-gas block limit. Its calldata costs `1,518,236` gas under the 4/16-byte schedule.

The quartic comparison baseline uses `lir6_ff5_rsv1` and a polynomial with 16 variables and 65,536 entries. Its 23,306-byte runtime fits the 24,576-byte EIP-170 runtime limit.

The quintic, octic, and LeanVM contracts exceed the 24,576-byte EIP-170 runtime limit. The project measures them with a 65,536-byte runtime limit and 131,072-byte initcode limit. Deployment on a network enforcing EIP-170 requires a split verifier or another architecture.

Detailed measurement provenance and optimization records are in [the verifier optimization audit](docs/verifier-optimization-audit.md), [the BabyBear verifier results](docs/babybear-verifier-optimization-loop.md), and [the test-data retention guide](testdata/README.md).

## License

MIT
