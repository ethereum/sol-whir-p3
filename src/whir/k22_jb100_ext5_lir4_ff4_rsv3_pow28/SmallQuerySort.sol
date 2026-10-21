// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { LibSort } from "solady/utils/LibSort.sol";

/// @notice Full-width sorted-unique output for short query arrays.
/// @dev Adapted from Solady LibSort (MIT, Vectorized). The bounded fast path
/// removes sorted/reverse prescans and uses smaller insertion-sort leaves.
/// It accepts arbitrary uint256 values and duplicates, uses no scratch memory,
/// and delegates arrays longer than 64 elements to LibSort.
/// Prescan removal can cost more on already sorted or reverse-sorted inputs;
/// the bound caps that tradeoff. Query sampling itself is unchanged.
library SmallQuerySort {
    function sortUnique(uint256[] memory a) internal pure {
        uint256 length = a.length;
        if (length > 64) {
            LibSort.sort(a);
            LibSort.uniquifySorted(a);
            return;
        }
        if (length < 2) return;
        assembly ("memory-safe") {
            function swap(a_, b_) -> _a, _b {
                _b := a_
                _a := b_
            }
            function mswap(i_, j_) {
                let t_ := mload(i_)
                mstore(i_, mload(j_))
                mstore(j_, t_)
            }
            function sortInner(w_, l_, h_) {
                // A distance of at most 10 words means at most 11 elements.
                // Preserve LibSort's insertion sentinel and partition ordering.
                if iszero(gt(sub(h_, l_), 0x140)) {
                    // Hardcode sort the first 2 elements.
                    let i_ := add(l_, 0x20)
                    if iszero(lt(mload(l_), mload(i_))) { mswap(i_, l_) }
                    for { } 1 { } {
                        i_ := add(i_, 0x20)
                        if gt(i_, h_) { break }
                        let k_ := mload(i_) // Key.
                        let j_ := add(i_, w_) // The slot before the current slot.
                        let v_ := mload(j_) // The value of `j_`.
                        if iszero(gt(v_, k_)) { continue }
                        for { } 1 { } {
                            mstore(add(j_, 0x20), v_)
                            j_ := add(j_, w_)
                            v_ := mload(j_)
                            if iszero(gt(v_, k_)) { break }
                        }
                        mstore(add(j_, 0x20), k_)
                    }
                    leave
                }
                // Pivot slot is the average of `l_` and `h_`.
                let p_ := add(shl(5, shr(6, add(l_, h_))), and(31, l_))
                // Median of 3 with sorting.
                {
                    let e0_ := mload(l_)
                    let e1_ := mload(p_)
                    if iszero(lt(e0_, e1_)) { e0_, e1_ := swap(e0_, e1_) }
                    let e2_ := mload(h_)
                    if iszero(lt(e1_, e2_)) {
                        e1_, e2_ := swap(e1_, e2_)
                        if iszero(lt(e0_, e1_)) { e0_, e1_ := swap(e0_, e1_) }
                    }
                    mstore(h_, e2_)
                    mstore(p_, e1_)
                    mstore(l_, e0_)
                }
                // Hoare's partition.
                {
                    // The value of the pivot slot.
                    let x_ := mload(p_)
                    p_ := h_
                    for { let i_ := l_ } 1 { } {
                        for { } 1 { } {
                            i_ := add(0x20, i_)
                            if iszero(gt(x_, mload(i_))) { break }
                        }
                        let j_ := p_
                        for { } 1 { } {
                            j_ := add(w_, j_)
                            if iszero(lt(x_, mload(j_))) { break }
                        }
                        p_ := j_
                        if iszero(lt(i_, p_)) { break }
                        mswap(i_, p_)
                    }
                }
                if iszero(eq(add(p_, 0x20), h_)) { sortInner(w_, add(p_, 0x20), h_) }
                if iszero(eq(p_, l_)) { sortInner(w_, l_, p_) }
            }

            let w := not(0x1f) // `-0x20`.
            let l := add(a, 0x20) // Low slot.
            let h := add(a, shl(5, length)) // High slot.
            mstore(a, 0) // For insertion sort's inner loop to terminate.
            sortInner(w, l, h)
        }
        // Compaction restores the array header to the unique length.
        _compactSorted(a, length);
    }

    /// @dev The caller establishes length > 1. Sorting temporarily zeroes the
    /// array header; data bounds use the original supplied length.
    function _compactSorted(uint256[] memory a, uint256 length) private pure {
        assembly ("memory-safe") {
            let writePtr := add(a, 32)
            let previous := mload(writePtr)
            let end := add(writePtr, shl(5, length))
            for { let readPtr := add(writePtr, 32) } lt(readPtr, end) {
                readPtr := add(readPtr, 32)
            } {
                let value := mload(readPtr)
                writePtr := add(writePtr, shl(5, iszero(eq(value, previous))))
                mstore(writePtr, value)
                previous := value
            }
            mstore(a, shr(5, sub(writePtr, a)))
        }
    }
}
