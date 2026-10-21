#!/usr/bin/env python3
"""Convert fixed-schedule WHRB Merkle siblings between breadth-first and DFS order.

Query indices come from the proof's Rust transcript. The conversion preserves
all proof values and sibling digests; the verifier authenticates them.
"""

import argparse
import json
from pathlib import Path

import quintic_transport as codec

TRACE_NAME = "transcript_trace_quintic_k22_jb100_ext5_lir4_ff4_rsv3_pow28.json"
QUERY_SHAPES = ((22, 38), (19, 31), (18, 19), (17, 14))


def order(indices, depth):
    """Return breadth-first sibling positions in the DFS consumption order."""
    if not isinstance(depth, int) or not 0 <= depth <= 96:
        raise ValueError("Merkle depth must be between 0 and 96")
    if not indices or any(type(index) is not int or not 0 <= index < 1 << depth
                          for index in indices):
        raise ValueError("Merkle query indices are empty or outside the tree")
    indices = sorted(set(indices))
    active = indices.copy()
    lookup = {}
    offset = 0
    for height in range(depth):
        parents = []
        position = 0
        while position < len(active):
            node = active[position]
            position += 1
            if node & 1 == 0 and position < len(active) and active[position] == node + 1:
                position += 1
            else:
                lookup[height, node] = offset
                offset += 1
            parents.append(node >> 1)
        active = parents
    if active != [0]:
        raise ValueError("Merkle queries do not reduce to one root")
    occupied = 0
    result = []
    for position, node in enumerate(indices):
        stop = ((node ^ indices[position + 1]).bit_length() - 1
                if position + 1 < len(indices) else depth)
        for height in range(stop):
            if occupied & (1 << height):
                occupied ^= 1 << height
            else:
                result.append(lookup[height, node])
            node >>= 1
        occupied |= 1 << stop
    if sorted(result) != list(range(offset)):
        raise ValueError("Merkle sibling order is not a permutation")
    return result


def queries_from_trace(path):
    trace = json.loads(Path(path).read_text())
    if trace["checkpoint_match"] is not True:
        raise ValueError("Rust prover and verifier transcript checkpoints differ")
    groups = {depth: [] for depth, _ in QUERY_SHAPES}
    for event in trace["prover_events"]:
        if event["op"] == "sample_bits" and event["arg0"] in groups:
            groups[event["arg0"]].append(event["arg1"])
    for depth, count in QUERY_SHAPES:
        if len(groups[depth]) != count:
            raise ValueError(f"Expected {count} query samples at depth {depth}")
    return [(depth, groups[depth]) for depth, _ in QUERY_SHAPES]


def fixture_queries(directory):
    return queries_from_trace(Path(directory) / TRACE_NAME)


def transform(blob, queries, inverse=False):
    expected_prefix = codec.DFS_PREFIX if inverse else codec.OLD_PREFIX
    if blob[:10] != expected_prefix:
        raise ValueError("WHRB version does not match the requested conversion")
    sections = codec.parse_blob(blob)
    if len(queries) != len(QUERY_SHAPES):
        raise ValueError("The fixed schedule requires four query batches")
    out = bytearray(blob)
    out[:10] = codec.OLD_PREFIX if inverse else codec.DFS_PREFIX
    decommitments = [section for section in sections
                     if section.name.endswith("decommitments")]
    for section, (depth, indices), (expected_depth, count) in zip(
            decommitments, queries, QUERY_SHAPES):
        if depth != expected_depth or len(indices) != count:
            raise ValueError("Merkle query shape differs from the fixed schedule")
        permutation = order(indices, depth)
        if len(permutation) * 20 != section.length:
            raise ValueError(f"Sibling count differs from {section.name}")
        for target, source in enumerate(permutation):
            if inverse:
                target, source = source, target
            start = section.offset
            out[start + 20 * target:start + 20 * (target + 1)] = \
                blob[start + 20 * source:start + 20 * (source + 1)]
    return bytes(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("transcript", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--inverse", action="store_true", help="Convert DFS to breadth-first order")
    args = parser.parse_args()
    queries = queries_from_trace(args.transcript)
    args.output.write_bytes(transform(args.input.read_bytes(), queries, args.inverse))


if __name__ == "__main__":
    main()
