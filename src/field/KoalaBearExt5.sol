// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { KoalaBear } from "./KoalaBear.sol";

library KoalaBearExt5 {
    uint256 internal constant DEGREE = 5;
    uint256 internal constant COEFF_MASK = 0xffffffff;
    uint256 internal constant ONE = uint256(1) << 224;
    uint256 internal constant TWO = uint256(2) << 224;
    uint256 internal constant INV_TWO = 1_065_353_217;
    uint256 internal constant LOW_96_MASK = (uint256(1) << 96) - 1;
    uint256 internal constant PACKED_HIGH_BIT = uint256(0x80000000) << 224
        | (uint256(0x80000000) << 192) | (uint256(0x80000000) << 160) | (uint256(0x80000000) << 128)
        | (uint256(0x80000000) << 96);
    uint256 internal constant PACKED_LOW_31 = uint256(0x7fffffff) << 224
        | (uint256(0x7fffffff) << 192) | (uint256(0x7fffffff) << 160) | (uint256(0x7fffffff) << 128)
        | (uint256(0x7fffffff) << 96);
    uint256 internal constant PACKED_CANONICAL_BIAS = uint256(0x00ffffff) << 224
        | (uint256(0x00ffffff) << 192) | (uint256(0x00ffffff) << 160) | (uint256(0x00ffffff) << 128)
        | (uint256(0x00ffffff) << 96);

    error BaseScalarOutOfRange(uint256 value);
    error PackedExtensionElementOutOfRange(uint256 value);

    function pack(uint256[5] memory coeffs) internal pure returns (uint256 packed) {
        unchecked {
            packed = (coeffs[0] << 224) | (coeffs[1] << 192) | (coeffs[2] << 160)
                | (coeffs[3] << 128) | (coeffs[4] << 96);
        }
    }

    function unpack(uint256 packed) internal pure returns (uint256[5] memory coeffs) {
        coeffs[0] = packed >> 224;
        coeffs[1] = (packed >> 192) & COEFF_MASK;
        coeffs[2] = (packed >> 160) & COEFF_MASK;
        coeffs[3] = (packed >> 128) & COEFF_MASK;
        coeffs[4] = (packed >> 96) & COEFF_MASK;
    }

    function validatePacked(uint256 packed) internal pure {
        unchecked {
            uint256 invalidHighBits = packed & PACKED_HIGH_BIT;
            uint256 invalidLow31 =
                ((packed & PACKED_LOW_31) + PACKED_CANONICAL_BIAS) & PACKED_HIGH_BIT;
            if (((packed & LOW_96_MASK) | invalidHighBits | invalidLow31) == 0) {
                return;
            }
            revert PackedExtensionElementOutOfRange(packed);
        }
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256 out) {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let sum := add(a, b)
            let highBits :=
                and(
                    add(sum, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000),
                    0x8000000080000000800000008000000080000000000000000000000000000000
                )
            out := and(
                sub(sum, mul(shr(31, highBits), modulus)),
                0xffffffffffffffffffffffffffffffffffffffff000000000000000000000000
            )
        }
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256 out) {
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let tmp :=
                sub(add(a, 0x7f0000017f0000017f0000017f0000017f000001000000000000000000000000), b)
            let highBits :=
                and(
                    add(tmp, 0x00ffffff00ffffff00ffffff00ffffff00ffffff000000000000000000000000),
                    0x8000000080000000800000008000000080000000000000000000000000000000
                )
            out := and(
                sub(tmp, mul(shr(31, highBits), modulus)),
                0xffffffffffffffffffffffffffffffffffffffff000000000000000000000000
            )
        }
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return _mulPacked(a, b);
    }

    function mulReference(uint256 a, uint256 b) internal pure returns (uint256) {
        return pack(_mulCoeffs(unpack(a), unpack(b)));
    }

    function square(uint256 a) internal pure returns (uint256) {
        return _squarePacked(a);
    }

    function fromBase(uint256 value) internal pure returns (uint256) {
        if (value >= KoalaBear.MODULUS) {
            revert BaseScalarOutOfRange(value);
        }
        return value << 224;
    }

    function mulBase(uint256 a, uint256 scalar) internal pure returns (uint256) {
        if (scalar >= KoalaBear.MODULUS) {
            revert BaseScalarOutOfRange(scalar);
        }
        return _scalarMul(a, scalar);
    }

    /// @dev Gaussian-elimination fallback. Keep this out of verifier hot paths unless re-profiled.
    function inv(uint256 a) internal pure returns (uint256) {
        require(a != 0, "ZERO_INV");
        uint256[5] memory coeffs = unpack(a);
        uint256[5][5] memory mat;
        uint256[5] memory rhs;
        rhs[0] = 1;

        unchecked {
            for (uint256 col = 0; col < DEGREE; ++col) {
                uint256[5] memory basis;
                basis[col] = 1;
                uint256[5] memory product = _mulCoeffs(coeffs, basis);
                for (uint256 row = 0; row < DEGREE; ++row) {
                    mat[row][col] = product[row];
                }
            }

            for (uint256 pivot = 0; pivot < DEGREE; ++pivot) {
                uint256 pivotRow = pivot;
                while (pivotRow < DEGREE && mat[pivotRow][pivot] == 0) {
                    ++pivotRow;
                }
                require(pivotRow < DEGREE, "SINGULAR");

                if (pivotRow != pivot) {
                    for (uint256 col = pivot; col < DEGREE; ++col) {
                        (mat[pivot][col], mat[pivotRow][col]) =
                        (mat[pivotRow][col], mat[pivot][col]);
                    }
                    (rhs[pivot], rhs[pivotRow]) = (rhs[pivotRow], rhs[pivot]);
                }

                uint256 invPivot = KoalaBear.inv(mat[pivot][pivot]);
                for (uint256 col = pivot; col < DEGREE; ++col) {
                    mat[pivot][col] = KoalaBear.mul(mat[pivot][col], invPivot);
                }
                rhs[pivot] = KoalaBear.mul(rhs[pivot], invPivot);

                for (uint256 row = 0; row < DEGREE; ++row) {
                    if (row == pivot) {
                        continue;
                    }
                    uint256 factor = mat[row][pivot];
                    if (factor == 0) {
                        continue;
                    }
                    for (uint256 col = pivot; col < DEGREE; ++col) {
                        mat[row][col] =
                            KoalaBear.sub(mat[row][col], KoalaBear.mul(factor, mat[pivot][col]));
                    }
                    rhs[row] = KoalaBear.sub(rhs[row], KoalaBear.mul(factor, rhs[pivot]));
                }
            }
        }

        return pack(rhs);
    }

    function extrapolate_012(uint256 e0, uint256 e1, uint256 e2, uint256 r)
        internal
        pure
        returns (uint256)
    {
        return _extrapolate012Fast(e0, e1, e2, r);
    }

    function extrapolate_012_reference(uint256 e0, uint256 e1, uint256 e2, uint256 r)
        internal
        pure
        returns (uint256)
    {
        uint256 l0 = _scalarMul(mul(sub(r, ONE), sub(r, TWO)), INV_TWO);
        uint256 l1 = mul(r, sub(TWO, r));
        uint256 l2 = _scalarMul(mul(r, sub(r, ONE)), INV_TWO);
        return add(add(mul(e0, l0), mul(e1, l1)), mul(e2, l2));
    }

    function extrapolate_012_from_sumcheck(uint256 c0, uint256 claimedEval, uint256 c2, uint256 r)
        internal
        pure
        returns (uint256)
    {
        return extrapolate_012(c0, sub(claimedEval, c0), c2, r);
    }

    function eq_poly_eval(uint256[] memory p, uint256[] memory q)
        internal
        pure
        returns (uint256 acc)
    {
        require(p.length == q.length, "LEN");
        acc = ONE;
        unchecked {
            for (uint256 i = 0; i < p.length; ++i) {
                uint256 term = add(ONE, sub(sub(_scalarMul(mul(p[i], q[i]), 2), p[i]), q[i]));
                acc = mul(acc, term);
            }
        }
    }

    function evaluate_hypercube(uint256[] memory evals, uint256[] memory point)
        internal
        pure
        returns (uint256)
    {
        uint256 size = evals.length;
        require(size != 0 && (size & (size - 1)) == 0, "BAD_EVALS");
        require(size == (uint256(1) << point.length), "DIM");

        unchecked {
            for (uint256 i = 0; i < point.length; ++i) {
                size >>= 1;
                for (uint256 j = 0; j < size; ++j) {
                    evals[j] = _foldOnce(evals[j], evals[j + size], point[i]);
                }
            }
        }

        return evals[0];
    }

    function _foldOnce(uint256 a0, uint256 a1, uint256 r) internal pure returns (uint256) {
        return add(a0, mul(r, sub(a1, a0)));
    }

    function _scalarMul(uint256 a, uint256 scalar) private pure returns (uint256) {
        uint256 out;
        assembly ("memory-safe") {
            let modulus := 0x7f000001
            let mask := 0xffffffff
            out := or(
                or(
                    or(
                        shl(224, mulmod(shr(224, a), scalar, modulus)),
                        shl(192, mulmod(and(shr(192, a), mask), scalar, modulus))
                    ),
                    or(
                        shl(160, mulmod(and(shr(160, a), mask), scalar, modulus)),
                        shl(128, mulmod(and(shr(128, a), mask), scalar, modulus))
                    )
                ),
                shl(96, mulmod(and(shr(96, a), mask), scalar, modulus))
            )
        }
        return out;
    }

    /// @dev Split the reversed transport polynomial into even/odd radix-2^64 lanes.
    /// If r = p-1, even/odd convolution lanes are <= 3*r^2 < 2^64.
    /// Direct mixed products have lanes <= 2*r^2; their sum has lanes
    /// <= 4*r^2 < 2^64, with no carries. Both have degree at most three
    /// in radix 2^64, so the cross result is also < 2^256.
    /// The omitted degree-four even product is a0*b0, computed separately.
    /// All reduced numerators are nonnegative and < 2^68 after the p*2^35 bias.
    function _mulPacked(uint256 a, uint256 b) private pure returns (uint256 out) {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let mask := 0xffffffff00000000ffffffff00000000ffffffff
            let ae := and(shr(96, a), mask)
            let ao := and(shr(128, a), mask)
            let be := and(shr(96, b), mask)
            let bo := and(shr(128, b), mask)
            let even := mul(ae, be)
            let odd := mul(ao, bo)
            let cross := add(mul(ae, bo), mul(ao, be))
            let c0 := mul(shr(224, a), shr(224, b))
            let laneMask := 0xffffffffffffffff
            let c1 := shr(192, cross)
            let c2 := add(shr(192, even), shr(128, odd))
            let c3 := and(shr(128, cross), laneMask)
            let c4 := add(and(shr(128, even), laneMask), and(shr(64, odd), laneMask))
            let c5 := and(shr(64, cross), laneMask)
            let c6 := add(and(shr(64, even), laneMask), and(odd, laneMask))
            let c7 := and(cross, laneMask)
            let c8 := and(even, laneMask)
            let bias := shl(35, M)
            out := or(
                or(
                    or(
                        shl(224, mod(add(add(c0, c5), sub(bias, c8)), M)),
                        shl(192, mod(add(c1, c6), M))
                    ),
                    or(
                        shl(160, mod(add(add(add(c2, sub(bias, c5)), c7), c8), M)),
                        shl(128, mod(add(add(c3, sub(bias, c6)), c8), M))
                    )
                ),
                shl(96, mod(add(c4, sub(bias, c7)), M))
            )
        }
    }

    /// @dev The same even/odd split, with cross = 2*even*odd by symmetry.
    /// Each lane before doubling is <= 2*(p-1)^2 < 2^63, so doubling cannot
    /// carry between lanes or overflow the retained 256-bit cross polynomial.
    function _squarePacked(uint256 a) private pure returns (uint256 out) {
        assembly ("memory-safe") {
            let M := 0x7f000001
            let mask := 0xffffffff00000000ffffffff00000000ffffffff
            let ae := and(shr(96, a), mask)
            let ao := and(shr(128, a), mask)
            let even := mul(ae, ae)
            let odd := mul(ao, ao)
            let cross := shl(1, mul(ae, ao))
            let c0 := mul(shr(224, a), shr(224, a))
            let laneMask := 0xffffffffffffffff
            let c1 := shr(192, cross)
            let c2 := add(shr(192, even), shr(128, odd))
            let c3 := and(shr(128, cross), laneMask)
            let c4 := add(and(shr(128, even), laneMask), and(shr(64, odd), laneMask))
            let c5 := and(shr(64, cross), laneMask)
            let c6 := add(and(shr(64, even), laneMask), and(odd, laneMask))
            let c7 := and(cross, laneMask)
            let c8 := and(even, laneMask)
            let bias := shl(35, M)
            out := or(
                or(
                    or(
                        shl(224, mod(add(add(c0, c5), sub(bias, c8)), M)),
                        shl(192, mod(add(c1, c6), M))
                    ),
                    or(
                        shl(160, mod(add(add(add(c2, sub(bias, c5)), c7), c8), M)),
                        shl(128, mod(add(add(c3, sub(bias, c6)), c8), M))
                    )
                ),
                shl(96, mod(add(c4, sub(bias, c7)), M))
            )
        }
    }

    function _extrapolate012Fast(uint256 e0, uint256 e1, uint256 e2, uint256 r)
        private
        pure
        returns (uint256)
    {
        uint256 delta = sub(e1, e0);
        uint256 q2Packed = sub(sub(e2, e1), delta);
        assembly ("memory-safe") {
            // Canonical x is halved by (x + (x & 1) * p) / 2.
            // Each even numerator is below 2p < 2^32, so lanes do not carry.
            let odd :=
                and(q2Packed, 0x0000000100000001000000010000000100000001000000000000000000000000)
            q2Packed := shr(1, add(q2Packed, mul(odd, 0x7f000001)))
        }
        return add(e0, mul(r, add(sub(delta, q2Packed), mul(r, q2Packed))));
    }

    function _mulCoeffs(uint256[5] memory a, uint256[5] memory b)
        private
        pure
        returns (uint256[5] memory out)
    {
        uint256 c0 = KoalaBear.mul(a[0], b[0]);
        uint256 c1 = _sum2(a[0], b[1], a[1], b[0]);
        uint256 c2 = _sum3(a[0], b[2], a[1], b[1], a[2], b[0]);
        uint256 c3 = _sum4(a[0], b[3], a[1], b[2], a[2], b[1], a[3], b[0]);
        uint256 c4 = _sum5(a[0], b[4], a[1], b[3], a[2], b[2], a[3], b[1], a[4], b[0]);
        uint256 c5 = _sum4(a[1], b[4], a[2], b[3], a[3], b[2], a[4], b[1]);
        uint256 c6 = _sum3(a[2], b[4], a[3], b[3], a[4], b[2]);
        uint256 c7 = _sum2(a[3], b[4], a[4], b[3]);
        uint256 c8 = KoalaBear.mul(a[4], b[4]);
        uint256 c5MinusC8 = KoalaBear.sub(c5, c8);

        out[0] = KoalaBear.add(c0, c5MinusC8);
        out[1] = KoalaBear.add(c1, c6);
        out[2] = KoalaBear.add(KoalaBear.sub(c2, c5MinusC8), c7);
        out[3] = KoalaBear.add(KoalaBear.sub(c3, c6), c8);
        out[4] = KoalaBear.sub(c4, c7);
    }

    function _sum2(uint256 a0, uint256 b0, uint256 a1, uint256 b1) private pure returns (uint256) {
        return KoalaBear.add(KoalaBear.mul(a0, b0), KoalaBear.mul(a1, b1));
    }

    function _sum3(uint256 a0, uint256 b0, uint256 a1, uint256 b1, uint256 a2, uint256 b2)
        private
        pure
        returns (uint256)
    {
        return KoalaBear.add(_sum2(a0, b0, a1, b1), KoalaBear.mul(a2, b2));
    }

    function _sum4(
        uint256 a0,
        uint256 b0,
        uint256 a1,
        uint256 b1,
        uint256 a2,
        uint256 b2,
        uint256 a3,
        uint256 b3
    ) private pure returns (uint256) {
        return KoalaBear.add(_sum2(a0, b0, a1, b1), _sum2(a2, b2, a3, b3));
    }

    function _sum5(
        uint256 a0,
        uint256 b0,
        uint256 a1,
        uint256 b1,
        uint256 a2,
        uint256 b2,
        uint256 a3,
        uint256 b3,
        uint256 a4,
        uint256 b4
    ) private pure returns (uint256) {
        return KoalaBear.add(_sum4(a0, b0, a1, b1, a2, b2, a3, b3), KoalaBear.mul(a4, b4));
    }
}
