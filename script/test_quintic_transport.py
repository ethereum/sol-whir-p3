import random
import unittest
import hashlib
from pathlib import Path

import quintic_transport as q
from generate_quintic_transport_vectors import conformance_vectors, proof_transports
from merkle_dfs_transport import fixture_queries, order, transform

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / 'testdata'
PREFIX = 'quintic_whir_k22_jb100_ext5_lir4_ff4_rsv3_pow28_'


def word(n):
    return n.to_bytes(4, 'big')


class TransportTests(unittest.TestCase):
    def test_independent_literal_vectors(self):
        self.assertEqual(q.compress(b'abc').hex(), '5748524301000000000300000003616263')
        constant = b''.join(word(c + 1) for c in range(5)) * 16
        encoded = bytes.fromhex('1f0000000100000002000000030000000400000005')
        self.assertEqual(q.encode_row(constant, 16), encoded)
        self.assertEqual(q.decode_row(encoded, 0, 16), (constant, 21))
        varying = b''.join(word(r) + word(11) + word(12) + word(13) + word(14) for r in range(16))
        encoded = b'\x1e' + b''.join(word(r) for r in range(16)) + b''.join(word(c) for c in (11,12,13,14))
        self.assertEqual(q.encode_row(varying, 16), encoded)
        self.assertEqual(q.decode_row(encoded, 0, 16), (varying, 81))
        raw = b''.join(word(100*r + c) for r in range(16) for c in range(5))
        self.assertEqual(q.encode_row(raw, 16), b'\0' + raw)
        self.assertEqual(q.decode_row(b'\0' + raw, 0, 16), (raw, 321))

    def test_all_four_fixture_roundtrips(self):
        files = sorted(FIXTURES.glob(PREFIX + '*.blob'))
        self.assertEqual(len(files), 4)
        for file in files:
            with self.subTest(file=file.name):
                blob = file.read_bytes()
                self.assertEqual(q.decompress(q.compress(blob)), blob)

    def test_invalid_field_is_preserved_raw(self):
        row = word(q.MODULUS) + bytes(316)
        self.assertEqual(q.encode_row(row, 16), b'\0' + row)
        self.assertEqual(q.decode_row(b'\0' + row, 0, 16)[0], row)
        encoded = b'\x1f' + word(q.MODULUS) + bytes(16)
        self.assertEqual(q.decode_row(encoded, 0, 16)[0], (word(q.MODULUS)+bytes(16))*16)

    def test_random_rows_and_raw_bytes(self):
        rng = random.Random(153172)
        for n in (16,64):
            for mask in range(32):
                constants = [rng.randrange(q.MODULUS) for _ in range(5)]
                row = b''.join(word(constants[c] if mask >> c & 1 else rng.randrange(q.MODULUS))
                               for _ in range(n) for c in range(5))
                encoded = q.encode_row(row, n, allow_generic_masks=True)
                self.assertEqual(q.decode_row(encoded,0,n), (row,len(encoded)))
        for length in (0,1,17,18,320,54330,65536):
            data = rng.randbytes(length)
            self.assertEqual(q.decompress(q.compress(data)),data)

    def test_incompressible_structured_and_global_fallback(self):
        original = (FIXTURES/(PREFIX+'success.blob')).read_bytes()
        blob = bytearray(original)
        rng = random.Random(72131)
        for s in q.parse_blob(original):
            if s.kind == 'rows':
                blob[s.offset:s.offset+s.length] = b''.join(word(rng.randrange(q.MODULUS)) for _ in range(s.length//4))
        raw = q.compress(bytes(blob))
        structured = q.compress(bytes(blob),force_structured=True)
        self.assertEqual(raw[5],0)
        self.assertEqual(len(structured),len(blob)+14+65)
        self.assertEqual(q.decompress(raw),bytes(blob))
        self.assertEqual(q.decompress(structured),bytes(blob))

    def test_proof_mutations_preserved(self):
        blob = (FIXTURES/(PREFIX+'success.blob')).read_bytes()
        rng = random.Random(10493)
        for _ in range(100):
            changed = bytearray(blob)
            pos = rng.randrange(len(blob))
            changed[pos] ^= 1 << rng.randrange(8)
            self.assertEqual(q.decompress(q.compress(bytes(changed))),bytes(changed))
        for s in q.parse_blob(blob):
            if s.kind == 'rows':
                changed = bytearray(blob)
                changed[s.offset:s.offset+4] = word(0xffffffff)
                self.assertEqual(q.decompress(q.compress(bytes(changed))),bytes(changed))

    def test_envelope_malformed(self):
        blob = (FIXTURES/(PREFIX+'success.blob')).read_bytes()
        good = q.compress(blob)
        bad = [good[:i] for i in (0,4,13,14,31,len(good)-1)]
        bad += [good+b'x']
        for offset,value in ((0,0),(4,2),(5,2),(6,255),(10,255),(14,0),(18,2)):
            changed=bytearray(good);changed[offset]=value;bad.append(bytes(changed))
        # Keep outer length correct while adding trailing inner bytes.
        changed=bytearray(good+b'X');changed[10:14]=word(len(changed)-14);bad.append(bytes(changed))
        first = next(s for s in q.section_table(blob,good) if s['kind']=='rows')['encoded_envelope_offset']
        changed=bytearray(good);changed[first]=32;bad.append(bytes(changed))
        for data in bad:
            with self.assertRaises(q.CodecError): q.decompress(data)
        with self.assertRaises(q.CodecError):q.decompress(good,max_decoded_bytes=len(blob)-1)

    def test_declared_decoded_length_matches_header_for_each_mode(self):
        for name in ('success.whrc', 'success.dfs.whrc', 'success.raw.whrc'):
            encoded = (FIXTURES / 'transport' / name).read_bytes()
            decoded_length = int.from_bytes(encoded[6:10], 'big')
            for changed_length in (decoded_length - 1, decoded_length + 1):
                with self.subTest(transport=name, decoded_length=changed_length):
                    changed = bytearray(encoded)
                    changed[6:10] = word(changed_length)
                    with self.assertRaises(q.CodecError):
                        q.decompress(bytes(changed))

    def test_dfs_header_preserved(self):
        blob = bytearray((FIXTURES/(PREFIX+'success.blob')).read_bytes())
        blob[4:6] = bytes.fromhex('0101')
        self.assertEqual(q.decompress(q.compress(bytes(blob))), bytes(blob))

    def test_default_fast_mask_policy(self):
        for n in (16,64):
            for mask in range(32):
                row=b''.join(word(100+c if mask>>c&1 else 1000+10*r+c)
                             for r in range(n) for c in range(5))
                generic=q.encode_row(row,n,allow_generic_masks=True)
                default=q.encode_row(row,n)
                self.assertEqual(generic[0],mask)
                self.assertEqual(default[0],mask if mask.bit_count()>=4 else 0)
                self.assertEqual(q.decode_row(default,0,n)[0],row)
                self.assertEqual(q.decode_row(generic,0,n)[0],row)
        blob=(FIXTURES/(PREFIX+'success.blob')).read_bytes()
        self.assertEqual(hashlib.sha256(q.compress(blob)).hexdigest(),
                         '4bb9c881fbe5a5755bff072d8f336b6ebae10731679f47f71d8271edbe29ece3')

    def test_row_malformed(self):
        for data in (b'',b'\x20',b'\xff',b'\0'+bytes(319),b'\x1f'+bytes(19),b'\x01'+bytes(259)):
            with self.assertRaises(q.CodecError):q.decode_row(data,0,16)

    def test_conformance_vectors_are_current(self):
        generated = conformance_vectors(FIXTURES)
        directory = FIXTURES / 'transport'
        self.assertEqual(set(generated), {path.name for path in directory.iterdir()
                                         if path.name != 'manifest.json'})
        for name, data in generated.items():
            with self.subTest(vector=name):
                self.assertEqual((directory / name).read_bytes(), data)

    def test_valid_proof_corpus_transports_are_current(self):
        corpus = FIXTURES / 'quintic_valid_proofs'
        for seed in ('seed-1', 'seed-2'):
            directory = corpus / seed
            blob = (directory / (PREFIX + 'success.blob')).read_bytes()
            for name, data in proof_transports(directory, force_structured=True).items():
                with self.subTest(seed=seed, transport=name):
                    self.assertEqual((directory / name).read_bytes(), data)
                    if name.endswith('.whrc'):
                        decoded = q.decompress(data)
                        expected = ((directory / 'success.dfs.blob').read_bytes()
                                    if name == 'success.dfs.whrc' else blob)
                        self.assertEqual(decoded, expected)
                        self.assertEqual(data[5], 0 if name == 'success.raw.whrc' else 1)

    def test_dfs_reorders_only_siblings(self):
        for directory in (FIXTURES, FIXTURES / 'quintic_valid_proofs/seed-1',
                          FIXTURES / 'quintic_valid_proofs/seed-2'):
            blob = (directory / (PREFIX + 'success.blob')).read_bytes()
            queries = fixture_queries(directory)
            dfs = transform(blob, queries)
            self.assertEqual(dfs[:10], q.DFS_PREFIX)
            self.assertEqual(transform(dfs, queries, inverse=True), blob)
            for section in q.parse_blob(blob)[1:]:
                original = blob[section.offset:section.offset + section.length]
                converted = dfs[section.offset:section.offset + section.length]
                if section.name.endswith('decommitments'):
                    self.assertEqual(sorted(original[i:i+20] for i in range(0, len(original), 20)),
                                     sorted(converted[i:i+20] for i in range(0, len(converted), 20)))
                else:
                    self.assertEqual(converted, original)
            with self.assertRaises(ValueError):
                transform(dfs, queries)
            with self.assertRaises(ValueError):
                transform(blob[:-1], queries)

    def test_dfs_index_bounds_and_duplicates(self):
        self.assertEqual(order([0], 0), [])
        self.assertEqual(order([1, 1, 2, 2], 3), order([1, 2], 3))
        for indices, depth in (([], 1), ([-1], 1), ([2], 1), ([0], -1), ([0], 97)):
            with self.assertRaises(ValueError):
                order(indices, depth)


if __name__ == '__main__': unittest.main(verbosity=2)
