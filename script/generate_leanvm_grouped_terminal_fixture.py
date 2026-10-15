#!/usr/bin/env python3
"""Generate the Solidity fixture for a freshly verified grouped terminal proof."""

from generate_leanvm_two_commitment_terminal_fixture import main


if __name__ == "__main__":
    main(grouped=True)
