#!/usr/bin/env python3
"""
libc_identify.py
-----------------
A small pwntools-native helper for identifying and downloading the exact
remote libc build used by a CTF target, given a single leaked symbol address.

This is a lightweight wrapper around the public libc.rip API
(https://libc.rip) — it is not a novel technique. Similar/more mature prior
art: LibcSearcher (https://github.com/lieanu/LibcSearcher, offline dataset),
libc-database (https://github.com/niklasb/libc-database, which libc.rip is
itself built on), and pwninit (https://github.com/io12/pwninit, broader
challenge-setup automation). The value here is purely ergonomic: a short,
reusable, pwntools-friendly call instead of re-writing the same
query/filter/download boilerplate for every ret2libc challenge.

How it works:
    ASLR only randomizes a libc mapping's *base* address, which is always
    page-aligned (a multiple of 0x1000). The *offset* of any given symbol
    within a specific libc build is fixed. So the low bits of a leaked
    address act as a build fingerprint, independent of ASLR. This script
    sends those low bits to libc.rip, which returns every known libc build
    matching that fingerprint for the given symbol.

CLI usage:
    python3 libc_identify.py puts 0x7f90e2062970

Usage as a module:
    from libc_identify import find_and_download_libc
    libc = find_and_download_libc('puts', leaked_puts_addr)
    libc.address = leaked_puts_addr - libc.symbols['puts']
"""

import sys
import requests
from pwn import ELF, log


def find_candidates(symbol_name: str, leaked_addr: int, tail_len: int = 3) -> list:
    """
    Query the libc.rip API for every known libc build whose `symbol_name`
    offset ends with the last `tail_len` hex digits of `leaked_addr`.

    tail_len=3 (12 bits) is usually enough since it's bounded by page size;
    increase it if the query returns too many or zero candidates.
    """
    tail = hex(leaked_addr)[-tail_len:]
    log.info(f'Querying libc.rip: symbol={symbol_name}, tail={tail}')

    resp = requests.post(
        'https://libc.rip/api/find',
        json={'symbols': {symbol_name: tail}}
    )
    resp.raise_for_status()
    return resp.json()


def filter_arch(candidates: list, arch: str = 'amd64') -> list:
    """Keep only candidates matching the given architecture (amd64/x86_64 vs i386/i686)."""
    keys = ['amd64', 'x86_64'] if arch in ('amd64', 'x86_64') else ['i386', 'i686']
    return [c for c in candidates if any(k in c['id'] for k in keys)]


def download_libc(candidate: dict, save_path: str = './libc_remote.so.6') -> ELF:
    """Download the chosen libc build and return it as a pwntools ELF object."""
    log.info(f"Downloading: {candidate['id']}")
    data = requests.get(candidate['download_url']).content
    with open(save_path, 'wb') as f:
        f.write(data)
    return ELF(save_path, checksec=False)


def find_and_download_libc(symbol_name: str, leaked_addr: int,
                            arch: str = 'amd64', tail_len: int = 3,
                            pick_index: int = 0) -> ELF:
    """
    End-to-end helper: query, filter by architecture, pick a candidate, and
    download it as a ready-to-use ELF object.

    If pick_index=0 turns out to be the wrong point-release (exploit crashes
    after this), re-run with pick_index=1, 2, ... to try the next candidate
    without re-querying manually.
    """
    candidates = find_candidates(symbol_name, leaked_addr, tail_len)
    if not candidates:
        log.error('No candidates found. Try increasing tail_len (e.g. 4 or 5).')
        sys.exit(1)

    filtered = filter_arch(candidates, arch)
    if not filtered:
        log.warning(f'No {arch} candidates found; falling back to the full candidate list.')
        filtered = candidates

    log.info(f'{len(filtered)} candidate(s) found:')
    for c in filtered:
        log.info(f"  - {c['id']}")

    chosen = filtered[pick_index]
    log.success(f"Chosen: {chosen['id']}")
    return download_libc(chosen)


if __name__ == '__main__':
    # Quick standalone check, without needing a full exploit script:
    #   python3 libc_identify.py puts 0x7f90e2062970
    if len(sys.argv) != 3:
        print('Usage: python3 libc_identify.py <symbol_name> <leaked_address_hex>')
        sys.exit(1)

    symbol = sys.argv[1]
    addr = int(sys.argv[2], 16)

    libc = find_and_download_libc(symbol, addr)
    libc.address = addr - libc.symbols[symbol]

    log.success(f'libc base    : {hex(libc.address)}')
    log.success(f"system addr  : {hex(libc.symbols['system'])}")
    log.success(f'/bin/sh addr : {hex(next(libc.search(b"/bin/sh\\x00")))}')
