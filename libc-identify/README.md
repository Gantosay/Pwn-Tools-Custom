# libc-identify

A small [pwntools](https://github.com/Gallopsled/pwntools)-native helper that identifies and downloads the exact remote libc build used by a CTF target, given a single leaked symbol address — useful whenever a challenge gives you the binary but **no accompanying `libc.so.6`**.

## Why

In `ret2libc` exploitation, once you leak a libc symbol's runtime address, you still need to know *which specific libc build* the remote server is running in order to compute offsets to `system`, `/bin/sh`, etc. Doing this manually (searching `libc.rip` in a browser, downloading, loading it by hand) is slow and gets repeated for every challenge. This script automates that lookup end to end.

## How it works

ASLR only randomizes a libc mapping's *base* address, which is always page-aligned (a multiple of `0x1000`). The *offset* of any given symbol inside a specific libc build is fixed. So the low bits of a leaked address act as a build fingerprint, independent of ASLR. This tool sends those bits to the public [libc.rip](https://libc.rip) API, which returns every known libc build matching that fingerprint, and downloads the chosen one.

## Install

```bash
pip install pwntools requests
```

## Usage

### As a standalone check
```bash
python3 libc_identify.py puts 0x7f90e2062970
```

### As a module in an exploit script
```python
from libc_identify import find_and_download_libc

leaked_puts = 0x7f90e2062970  # from your GOT-leak exploit

libc = find_and_download_libc('puts', leaked_puts, arch='amd64')
libc.address = leaked_puts - libc.symbols['puts']

system_addr = libc.symbols['system']
binsh_addr  = next(libc.search(b'/bin/sh\x00'))
```

If the top API match turns out to be the wrong point-release (exploit crashes after this step), re-run with `pick_index=1`, `2`, ... to try the next candidate.

## Prior art

This is a lightweight personal-workflow wrapper around the `libc.rip` API, not a novel technique. More mature/complete tooling already exists:
- [LibcSearcher](https://github.com/lieanu/LibcSearcher) — offline dataset
- [libc-database](https://github.com/niklasb/libc-database) — the project `libc.rip` is itself built on
- [pwninit](https://github.com/io12/pwninit) — broader CTF challenge setup automation

## License

MIT
