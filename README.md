# sol-spartan-whir

Solidity verifiers for standalone WHIR polynomial openings over KoalaBear and BabyBear. The repository also includes a grouped LeanVM terminal verifier for recursively verified Spartan-WHIR proofs.

The Rust [`spartan-whir`](https://github.com/ethereum/spartan-whir) implementation is the protocol source of truth. [`spartan-whir-export`](https://github.com/Client-Side-Proving/spartan-whir-export) generates Solidity-compatible standalone-WHIR fixtures.

## Build and test

```sh
forge build
forge test --offline --isolate --threads 1 --evm-version prague \
  --code-size-limit 1048576
```

The 1,048,576-byte test allowance accommodates harnesses that embed several verifiers. Gas measurements record their runtime and initcode limits separately.

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

The KoalaBear quintic native verifier uses depth-first Merkle sibling order for the lowest measured gas. It also exposes `verifyCompressed(bytes32,bytes)` for proofs with repeated coefficient columns, which can be stored once per row. Dense proofs use `verify` without compression. Both entrypoints accept breadth-first and depth-first sibling order. The [codec comments](script/quintic_transport.py) describe the binary layout; [AGENTS.md](AGENTS.md#quintic-validation) lists the validation commands.

Convert exported siblings to depth-first order using the proof's transcript trace, then optionally compress the result:

```sh
python3 script/merkle_dfs_transport.py proof.blob transcript.json proof.dfs.blob
python3 script/quintic_transport.py compress proof.dfs.blob proof.compressed.blob
python3 script/quintic_transport.py inspect proof.compressed.blob
python3 script/quintic_transport.py decompress proof.compressed.blob decoded.blob
```

A proof has multiple accepted byte encodings. Applications should key replay protection to an identifier bound to the verified statement, rather than a hash of the proof calldata.

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
| KoalaBear quintic, dense `seed-1`                  |           - |     `2,972,399` |   `2,081,471` | `54,660` B | `35,671` / `35,697` B |
| KoalaBear quintic, dense `seed-2`                  |           - |     `2,964,662` |   `2,079,026` | `54,276` B | `35,671` / `35,697` B |
| BabyBear quintic                                  | `3,240,976` |     `3,364,794` |   `2,489,346` | `54,084` B | `33,780` / `33,806` B |
| KoalaBear octic                                   | `5,356,053` |     `5,637,745` |   `4,862,945` | `47,780` B | `36,710` / `36,736` B |
| LeanVM grouped terminal                           |           - |    `10,666,368` |   `9,127,132` | `99,044` B | `62,623` / `62,649` B |

Foundry gas is omitted for the dense quintic rows because each corpus acceptance test includes fixture loading, ABI decoding, and both native and typed verification. The transaction and execution columns measure one native verification.

Transaction gas is measured from Anvil receipts. Execution gas is `transaction gas - 21,000 - calldata gas`. The standalone measurements use `solc 0.8.28`, `via_ir`, 833 optimizer runs, and the Prague EVM target. The KoalaBear quintic rows use two Rust-generated dense proofs with independent extension opening points and depth-first Merkle sibling order. Their total transaction gas reductions against baseline revision `8e57573` with breadth-first sibling order are 18.66% and 18.50%. Neither dense proof benefits from compression.

The `quintic_gas` profile uses 1,000,000 optimizer runs: the same dense proofs cost 2,771,989 and 2,764,347 transaction gas, with a 64,696-byte runtime and 64,722-byte initcode.

The structured success fixture has repeated coefficients in all 65 eligible rows and favors the specialized arithmetic and compression. Its proof compresses from 54,330 to 37,921 bytes and costs 2,457,362 transaction gas with depth-first sibling order at 833 optimizer runs. The dense proofs have no compressible rows; wrapping them adds 545 and 673 gas at 833 runs.

The LeanVM measurement uses the same compiler settings and a Cancun Anvil transaction with a 1,000,000,000-gas block limit. Its calldata costs `1,518,236` gas under the 4/16-byte schedule.

The quartic comparison baseline uses `lir6_ff5_rsv1` and a polynomial with 16 variables and 65,536 entries. Its 23,306-byte runtime fits the 24,576-byte EIP-170 runtime limit.

The quintic, octic, and LeanVM contracts exceed the 24,576-byte EIP-170 runtime limit. The project's size targets are 65,536 runtime bytes and 131,072 initcode bytes. The quintic baseline comparison uses a 131,072-byte runtime allowance because the baseline at 1,000,000 optimizer runs exceeds 65,536 bytes; both current profiles fit the project targets. Deployment on a network enforcing EIP-170 requires a split verifier or another architecture.

Historical optimization measurements are in [the verifier optimization audit](docs/verifier-optimization-audit.md) and [the BabyBear verifier results](docs/babybear-verifier-optimization-loop.md). The [test-data retention guide](testdata/README.md) describes the retained fixtures and measurement evidence.

## License

MIT
