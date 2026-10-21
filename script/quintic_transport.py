#!/usr/bin/env python3
"""Lossless proof compression for the fixed KoalaBear quintic schedule.

The proof starts with "WHRB" followed by the two-byte header field 0x0101
for depth-first Merkle sibling order or 0x0001 for breadth-first order.

WHRC envelope (14-byte header): magic[4], version:u8=1, mode:u8, decoded_len:u32be,
payload_len:u32be, payload. Mode 0 is raw. Mode 1 retains the original
WHRB header and compresses 65 rows: 31 round-1 rows, 19 round-2 rows,
the final polynomial and 14 final opening rows. Opening rows contain 16
extension elements; the final polynomial contains 64. Other sections
retain their exported encodings.

Rows: mask:u8. Zero means original row-major bytes. Otherwise bits 0..4
mark constant coefficient columns. Coefficients are emitted in order 0..4:
one big-endian u32 for a marked column, n big-endian u32s for an unmarked column. A compressed
row emitted by the encoder contains only canonical field words; invalid rows
use raw fallback. The decoder preserves arbitrary 32-bit words and leaves
field canonicality to the proof verifier.
By default the encoder uses only all-constant or exactly-one-variable masks,
which have fast EVM decoder paths; other rows are raw. The explicit
allow_generic_masks option emits all eligible constant columns for codec
conformance testing. The decoder accepts any nonempty subset of constant
columns; this is unambiguous but intentionally permits
equivalent encodings, including explicit raw rows and a raw whole blob.
The encoder chooses mode 0 when the encoded payload would be at least as
large as the proof. The decoder checks reserved mask bits, section bounds,
declared lengths and exact consumption; decoded size is at most 5,268,590
bytes.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import struct
from pathlib import Path

MODULUS = 0x7F000001
MAGIC = b"WHRC"
VERSION = 1
ENVELOPE_BYTES = 14
OLD_PREFIX = bytes.fromhex("57485242000114050303")
DFS_PREFIX = bytes.fromhex("57485242010114050303")
# Largest WHRB blob described by four uint16 decommitment counts.
MAX_DECODED_BYTES = 25_790 + 4 * 65_535 * 20


class CodecError(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class Section:
    name: str
    offset: int
    length: int
    kind: str
    rows: int = 0
    row_elements: int = 0


def sections_from_header(header: bytes) -> list[Section]:
    if len(header) < 18:
        raise CodecError("WHRB header is truncated")
    if header[:10] not in (OLD_PREFIX, DFS_PREFIX):
        raise CodecError("Unsupported WHRB magic, version, or fixed configuration")
    decomm = struct.unpack(">4H", header[10:18])
    out: list[Section] = []
    cursor = 0

    def add(name: str, length: int, kind: str, rows: int = 0, n: int = 0) -> None:
        nonlocal cursor
        out.append(Section(name, cursor, length, kind, rows, n))
        cursor += length

    add("header", 18, "header")
    add("statement_point", 440, "field_be")
    add("statement_evaluation", 20, "field_be")
    add("initial_commitment", 20, "digest")
    add("initial_ood", 20, "field_le")
    add("initial_sumcheck", 160, "field_le")
    add("initial_sumcheck_pow", 16, "pow_le")
    for r, q in enumerate((38, 31, 19)):
        add(f"round{r}_commitment", 20, "digest")
        add(f"round{r}_ood", 20, "field_le")
        add(f"round{r}_pow", 4, "pow_le")
        if r == 0:
            add("round0_rows", q * 16 * 4, "field_be")
        else:
            add(f"round{r}_rows", q * 16 * 20, "rows", q, 16)
        add(f"round{r}_decommitments", decomm[r] * 20, "digest")
        add(f"round{r}_sumcheck", 160, "field_le")
        add(f"round{r}_sumcheck_pow", 16, "pow_le")
    add("final_polynomial", 1280, "rows", 1, 64)
    add("final_pow", 4, "pow_le")
    add("final_rows", 4480, "rows", 14, 16)
    add("final_decommitments", decomm[3] * 20, "digest")
    add("final_sumcheck", 240, "field_le")
    return out


def parse_blob(blob: bytes) -> list[Section]:
    sections = sections_from_header(blob[:18])
    expected = sections[-1].offset + sections[-1].length
    if len(blob) != expected:
        raise CodecError(f"WHRB length {len(blob)} does not match {expected}")
    return sections


def _canonical_words(data: bytes) -> bool:
    return all(v[0] < MODULUS for v in struct.iter_unpack(">I", data))


def encode_row(row: bytes, elements: int, *, allow_generic_masks: bool = False) -> bytes:
    if elements not in (16, 64) or len(row) != elements * 20:
        raise CodecError("Unsupported row shape")
    if not _canonical_words(row):
        return b"\x00" + row
    columns = [[row[20*r + 4*c:20*r + 4*c + 4] for r in range(elements)]
               for c in range(5)]
    mask = sum(1 << c for c, col in enumerate(columns) if all(v == col[0] for v in col))
    if mask == 0 or (not allow_generic_masks and mask.bit_count() < 4):
        return b"\x00" + row
    return bytes([mask]) + b"".join(col[0] if mask & (1 << c) else b"".join(col)
                                   for c, col in enumerate(columns))


def decode_row(data: bytes, position: int, elements: int) -> tuple[bytes, int]:
    if elements not in (16, 64) or not (0 <= position < len(data)):
        raise CodecError("Missing row mask or unsupported shape")
    mask = data[position]
    position += 1
    if mask & 0xE0:
        raise CodecError("Reserved row mask bits are nonzero")
    if mask == 0:
        end = position + elements * 20
        if end > len(data):
            raise CodecError("Truncated raw row")
        return data[position:end], end
    column_bytes = 4 * mask.bit_count() + 4 * elements * (5 - mask.bit_count())
    if position + column_bytes > len(data):
        raise CodecError("Truncated column row")
    columns = []
    for c in range(5):
        size = 4 if mask & (1 << c) else 4 * elements
        col = data[position:position + size]
        position += size
        columns.append([col] * elements if size == 4 else
                       [col[i:i + 4] for i in range(0, size, 4)])
    return b"".join(columns[c][r] for r in range(elements) for c in range(5)), position


def _envelope(mode: int, decoded_length: int, payload: bytes) -> bytes:
    if decoded_length > MAX_DECODED_BYTES or len(payload) > MAX_DECODED_BYTES + 65:
        raise CodecError("Codec size limit exceeded")
    return MAGIC + bytes([VERSION, mode]) + struct.pack(">II", decoded_length, len(payload)) + payload


def wrap_raw(blob: bytes) -> bytes:
    """Wrap exact bytes without row compression."""
    return _envelope(0, len(blob), blob)


def compress(blob: bytes, *, force_structured: bool = False, allow_generic_masks: bool = False) -> bytes:
    if len(blob) > MAX_DECODED_BYTES:
        raise CodecError("Decoded size limit exceeded")
    try:
        sections = parse_blob(blob)
    except CodecError:
        if force_structured:
            raise
        return _envelope(0, len(blob), blob)
    chunks = []
    for section in sections:
        raw = blob[section.offset:section.offset + section.length]
        if section.kind == "rows":
            width = 20 * section.row_elements
            chunks.extend(encode_row(raw[i:i + width], section.row_elements, allow_generic_masks=allow_generic_masks)
                          for i in range(0, len(raw), width))
        else:
            chunks.append(raw)
    payload = b"".join(chunks)
    if not force_structured and len(payload) >= len(blob):
        return _envelope(0, len(blob), blob)
    return _envelope(1, len(blob), payload)


def decompress(encoded: bytes, *, max_decoded_bytes: int = MAX_DECODED_BYTES) -> bytes:
    if len(encoded) < ENVELOPE_BYTES:
        raise CodecError("Envelope is truncated")
    if encoded[:4] != MAGIC or encoded[4] != VERSION:
        raise CodecError("Unsupported codec magic or version")
    mode = encoded[5]
    decoded_length, payload_length = struct.unpack(">II", encoded[6:14])
    if decoded_length > max_decoded_bytes or decoded_length > MAX_DECODED_BYTES:
        raise CodecError("Decoded size limit exceeded")
    if payload_length != len(encoded) - ENVELOPE_BYTES:
        raise CodecError("Envelope payload length mismatch")
    payload = encoded[ENVELOPE_BYTES:]
    if mode == 0:
        if decoded_length != payload_length:
            raise CodecError("Raw length mismatch")
        return payload
    if mode != 1:
        raise CodecError("Unknown codec mode")
    sections = sections_from_header(payload[:18])
    expected = sections[-1].offset + sections[-1].length
    if decoded_length != expected:
        raise CodecError("Declared decoded length does not match WHRB header")
    # Structural bounds checked before decoded allocation: 65 targeted rows,
    # each >=21 bytes; raw rows add one byte to their original row length.
    untouched = sum(s.length for s in sections if s.kind != "rows")
    minimum = untouched + sum(s.rows * 21 for s in sections if s.kind == "rows")
    maximum = decoded_length + sum(s.rows for s in sections if s.kind == "rows")
    if not minimum <= len(payload) <= maximum:
        raise CodecError("Structured payload is outside exact structural size bounds")
    chunks = []
    cursor = 0
    for section in sections:
        if section.kind == "rows":
            for _ in range(section.rows):
                row, cursor = decode_row(payload, cursor, section.row_elements)
                chunks.append(row)
        else:
            end = cursor + section.length
            if end > len(payload):
                raise CodecError(f"Truncated section: {section.name}")
            chunks.append(payload[cursor:end])
            cursor = end
    if cursor != len(payload):
        raise CodecError("Trailing encoded bytes")
    out = b"".join(chunks)
    if len(out) != decoded_length:
        raise CodecError("Internal decoded size mismatch")
    return out


def section_table(blob: bytes, encoded: bytes) -> list[dict]:
    if encoded[5] != 1 or decompress(encoded) != blob:
        raise CodecError("A matching structured encoding is required")
    payload = encoded[14:]
    cursor = 0
    table = []
    for section in parse_blob(blob):
        start = cursor
        masks = []
        if section.kind == "rows":
            for _ in range(section.rows):
                masks.append(payload[cursor])
                _, cursor = decode_row(payload, cursor, section.row_elements)
        else:
            cursor += section.length
        raw = blob[section.offset:section.offset + section.length]
        data = payload[start:cursor]
        row = dataclasses.asdict(section)
        row.update(encoded_payload_offset=start, encoded_envelope_offset=start + 14,
                   encoded_length=len(data), zero_bytes=raw.count(0),
                   encoded_zero_bytes=data.count(0), masks=masks,
                   encoded_min_bytes=section.rows * 21 if section.kind == "rows" else section.length,
                   encoded_max_bytes=section.length + section.rows if section.kind == "rows" else section.length)
        table.append(row)
    return table


def gas_counts(data: bytes) -> dict:
    zero = data.count(0)
    tokens = zero + 4 * (len(data) - zero)
    return dict(bytes=len(data), zero=zero, nonzero=len(data) - zero, tokens=tokens,
                eip7623_floor=21000 + 10 * tokens, intrinsic=21000 + 4 * tokens)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("compress", "decompress", "inspect"))
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path, nargs="?")
    parser.add_argument("--force-structured", action="store_true",
                        help="Use mode 1 even when raw rows make it larger than mode 0")
    parser.add_argument("--allow-generic-masks", action="store_true",
                        help="Opt into slower generic decoder masks for conformance testing")
    args = parser.parse_args()
    if args.allow_generic_masks and args.action != "compress":
        parser.error("--allow-generic-masks applies only to compression")
    if args.force_structured and args.action != "compress":
        parser.error("--force-structured applies only to compression")
    data = args.input.read_bytes()
    if args.action == "inspect":
        blob = decompress(data)
        print(json.dumps(dict(encoded=gas_counts(data), decoded=gas_counts(blob),
                              sha256=hashlib.sha256(blob).hexdigest(),
                              sections=section_table(blob, data) if data[5] == 1 else []), indent=2))
        return
    if args.output is None:
        parser.error("output path is required")
    args.output.write_bytes(compress(data, force_structured=args.force_structured,
                                     allow_generic_masks=args.allow_generic_masks)
                           if args.action == "compress" else decompress(data))


if __name__ == "__main__":
    main()
