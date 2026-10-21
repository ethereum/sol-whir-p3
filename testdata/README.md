# Test data

This directory contains checked-in verifier inputs and the evidence needed to reproduce documented measurements. It is not a general output directory.

#### Runtime fixtures

Foundry tests read the field, Merkle, transcript, WHIR, BabyBear, and LeanVM fixtures directly. These files keep the offline test suite independent of the Rust exporter and LeanVM workspace. The grouped LogUp algebra vectors, three-root Merkle vectors, and `GroupedLogupKeccakPow28T6` proof and calldata are retained because the experimental grouped terminal tests and transaction measurement consume them directly.

The dense KoalaBear quintic proofs in `quintic_valid_proofs/` use polynomial/opening-point seed pairs `(1, 101)` and `(2, 202)`. Regeneration requires the seeded generator in [spartan-whir-export](https://github.com/Client-Side-Proving/spartan-whir-export), which is currently uncommitted. Set `SPARTAN_WHIR_EXPORT_DIR` to a checkout containing that generator and use an empty output directory for each seed pair:

```sh
cargo run --release --manifest-path "$SPARTAN_WHIR_EXPORT_DIR/Cargo.toml" \
  --bin export_seeded_quintic_k22_jb100_ext5_lir4_ff4_rsv3_pow28 \
  -- <empty-output-directory> 1 101
```

Use `2 202` for the second proof. `python3 script/generate_quintic_transport_vectors.py` generates the alternate encodings from the retained proofs and transcript traces. Generated fixture inventories are optional local output and are ignored by Git.

#### Schedule inputs

Schedule microbenchmarks, prover timings, calibration references, and score reports are CI-regenerable outputs and are ignored. The commands in `AGENTS.md` reproduce them.

The quintic shortlist proof, statement, and blob fixtures remain checked in because active Foundry tests read them directly. Shortlist measurements and transaction receipts are ignored. The Rust schedule exporter can regenerate the proof and statement, but CI must gain a native-blob export step before all shortlist fixtures can be omitted safely.

#### Measurement evidence

Recorded gas results and calibration data support the figures cited by the repository documentation. Compiler snapshots, transaction snapshots, profiles, plots, and raw logs are CI-regenerable and ignored. Historical exploration belongs in the workspace-level `research/` archive.

Generated score directories, temporary `*_tmp.json` files, build output, and operating-system metadata must not be committed.
