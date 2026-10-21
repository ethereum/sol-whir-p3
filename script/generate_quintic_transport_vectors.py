#!/usr/bin/env python3
"""Regenerate deterministic WHRC conformance vectors and valid-proof transports."""

import argparse
import hashlib
import json
import random
from pathlib import Path

import quintic_transport as codec
from merkle_dfs_transport import fixture_queries, transform

PREFIX = "quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_"


def identities(files):
    return {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in sorted(files.items())}


def proof_transports(directory, force_structured=False):
    blob = (directory / (PREFIX + "success.blob")).read_bytes()
    queries = fixture_queries(directory)
    dfs = transform(blob, queries)
    if transform(dfs, queries, inverse=True) != blob:
        raise ValueError("DFS conversion is not reversible")
    return {
        "success.raw.whrc": codec.wrap_raw(blob),
        "success.whrc": codec.compress(blob, force_structured=force_structured),
        "success.dfs.blob": dfs,
        "success.dfs.whrc": codec.compress(dfs, force_structured=force_structured),
    }


def conformance_vectors(directory):
    generated = proof_transports(directory)
    for path in sorted(directory.glob(PREFIX + "failure_*.blob")):
        blob = path.read_bytes()
        encoded = codec.compress(blob)
        if codec.decompress(encoded) != blob:
            raise ValueError(f"Codec roundtrip differs for {path.name}")
        generated[path.stem + ".whrc"] = encoded
    blob = (directory / (PREFIX + "success.blob")).read_bytes()
    rng = random.Random(6423)
    varying = bytearray(blob)
    index = 0
    for section in codec.parse_blob(blob):
        if section.kind == "rows":
            for row in range(section.rows):
                mask = index % 32
                index += 1
                constants = [rng.randrange(codec.MODULUS) for _ in range(5)]
                values = b"".join(
                    (constants[c] if mask >> c & 1 else rng.randrange(codec.MODULUS)).to_bytes(4, "big")
                    for _ in range(section.row_elements) for c in range(5))
                offset = section.offset + row * section.row_elements * 20
                varying[offset:offset + len(values)] = values
    generated["all_masks.blob"] = bytes(varying)
    generated["all_masks.whrc"] = codec.compress(
        bytes(varying), force_structured=True, allow_generic_masks=True)
    bad = bytearray(blob)
    section = next(section for section in codec.parse_blob(blob) if section.kind == "rows")
    bad[section.offset:section.offset + 4] = bytes.fromhex("ffffffff")
    generated["invalid_field.blob"] = bytes(bad)
    generated["invalid_field.whrc"] = codec.compress(bytes(bad))
    # Arbitrary bytes exercise the codec independently of proof verification.
    raw = rng.randbytes(len(blob))
    generated["raw_random.blob"] = raw
    generated["raw_random.whrc"] = codec.compress(raw)
    encoded = bytearray(generated["all_masks.whrc"])
    for section in codec.section_table(generated["all_masks.blob"], bytes(encoded)):
        if section["kind"] == "rows":
            position = section["encoded_envelope_offset"]
            for _ in range(section["rows"]):
                _, end = codec.decode_row(bytes(encoded), position, section["row_elements"])
                for offset in range(position + 1, end, 12):
                    encoded[offset:offset + 4] = bytes.fromhex("ffffffff")
                position = end
    generated["noncanonical_masks.whrc"] = bytes(encoded)
    generated["noncanonical_masks.blob"] = codec.decompress(bytes(encoded))
    return generated


def write_files(directory, files):
    directory.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (directory / name).write_bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path, nargs="?", default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    data = args.repository.resolve() / "testdata"
    generated = conformance_vectors(data)
    output = data / "transport"
    write_files(output, generated)
    (output / "manifest.json").write_text(json.dumps(identities(generated), indent=2) + "\n")
    corpus = data / "quintic_valid_proofs"
    seed_directories = sorted(corpus.glob("seed-*"))
    for directory in seed_directories:
        write_files(directory, proof_transports(directory, force_structured=True))
    print(json.dumps({"transport_vectors": len(generated),
                      "valid_proof_directories": [directory.name for directory in seed_directories]}, indent=2))


if __name__ == "__main__":
    main()
