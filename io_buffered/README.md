# io_buffered.py

A tiny, dependency-free, pwntools-style I/O layer for talking to a local
process or a remote TCP/TLS service — written for the one day `pip install
pwntools` isn't an option.

## Why this exists

`pwntools` is the right tool for CTF/exploit-dev I/O almost all the time.
But every once in a while you're somewhere with no outbound internet — an
isolated lab, a pivoted-into network, a locked-down sandbox, a box you're
not supposed to install random packages on — and you still need to script
interaction with a `nc`-style service: send a command, wait for a prompt,
send a payload, read back an exact number of bytes.

`io_buffered.py` is ~150 lines of plain Python (stdlib only — `socket`,
`ssl`, `subprocess`) that reimplements the handful of pwntools primitives
that cover 90% of real exploit scripts:

| pwntools | io_buffered.py |
|---|---|
| `p = process('./binary')` | `ProcIO('./binary')` |
| `p = remote(host, port)` | `RemoteIO(host, port)` |
| `p = remote(host, port, ssl=True, sni=host)` | `RemoteIO(host, port, use_ssl=True)` |
| `p.sendline(data)` | `io.sendline(data)` |
| `p.send(data)` | `io.send(data)` |
| `p.recvuntil(marker)` | `io.recv_until(marker)` |
| `p.sendlineafter(marker, data)` | `io.recv_until(marker); io.sendline(data)` |
| `p.recv(n)` | `io.recv(n)` |
| `p.recvline()` | `io.recv_line()` |
| `p.interactive()` | `io.interactive()` |

## The one bug that matters (read this before you write your own)

If you ever write a "quick and dirty" `recv_until` yourself, you will
probably write something like:

```python
# DON'T DO THIS
def recv_until(sock, marker):
    buf = b""
    while marker not in buf:
        buf += sock.recv(4096)
    return buf
```

This silently **drops data**. A real server very often writes a prompt and
the bytes that follow it in the same flush, and TCP (even more so TLS,
which buffers in whole records) will frequently hand you both in a single
`recv()` call. The snippet above finds the marker, returns, and throws away
everything in `buf` *after* the marker — including real data you needed for
the next read.

This bites you in exactly the way you'd expect: it works fine against a
local process (where timing often happens to line up) and then silently
returns empty/garbage against a real remote target, which is the most
confusing possible failure mode because the exploit *logic* is correct and
the bug is purely in the transport layer.

`io_buffered.py` fixes this with one internal buffer (`self._buf`) that
every method reads from first before touching the socket/pipe, and that
keeps whatever comes in past the marker for the next call — the same
approach pwntools' `tube` class uses internally.

## API

```python
from io_buffered import ProcIO, RemoteIO

io = ProcIO("./chall")                              # local subprocess
io = RemoteIO("1.2.3.4", 1337)                        # plain TCP
io = RemoteIO("chal.example.com", 9999, use_ssl=True)  # TLS (e.g. ncat --ssl)

io.send(b"raw bytes")
io.sendline("text or bytes, newline added")

io.recv(n)                      # up to n bytes (buffered, non-blocking-ish)
io.recv_exact(n)                # blocks until exactly n bytes or timeout
io.recv_until(b"Content: \n")   # reads (and consumes) up to & including marker
io.recv_line()                  # one line, newline stripped

io.alive()                      # still connected / process still running
io.close()
io.interactive()                # drop into a live two-way terminal <-> io proxy
```

Every `recv_*` call takes an optional `timeout=` (seconds).

## Example

```python
from io_buffered import RemoteIO

io = RemoteIO("chal.example.com", 9999, use_ssl=True)

io.recv_until(b"Command: ")
io.sendline("1")
io.recv_until(b"Size: ")
io.sendline("24")

io.recv_until(b"Command: ")
io.sendline("5")   # exit / trigger / whatever

io.interactive()
```

## OPSEC note: this also avoids an install footprint

A side benefit worth calling out explicitly, beyond "no internet available":
in environments where a SOC/EDR is watching, `pip install pwntools` (and
its dependencies — `capstone`, `unicorn`, `ropgadget`, etc.) is itself a
signal. A Python process suddenly reaching out to PyPI and a handful of
mirror/CDN domains to pull down packages is exactly the kind of egress
pattern that gets flagged.

`io_buffered.py` only uses stdlib (`socket`, `ssl`, `subprocess`) — nothing
to install, so nothing to fetch, so no package-manager egress traffic at
all. A couple of things worth being precise about, though:

- **It doesn't hide the connection to the target.** The actual `nc`/TLS
  session to whatever you're exploiting is still a network connection and
  still visible to anyone watching that traffic, exactly as it would be
  with pwntools. What disappears is specifically the *install step*, not
  the exploit traffic itself.
- **It doesn't hide the fact that you're running a socket-opening Python
  script.** If the environment has EDR watching process behavior (not just
  network egress), `python3` opening a raw socket from an odd directory can
  itself be a signal — that's about operational tradecraft in general, not
  something this tool changes.
- **Side benefit: no leftover install artifacts.** Because nothing gets
  pip-installed, there's no `site-packages` footprint, no `.egg-info`, no
  pip cache entries left behind on the box you ran this from. For an
  authorized engagement where minimizing on-disk footprint matters (things
  a blue team or forensic review might later find), that's a genuine
  operational plus — one script file, stdlib only, nothing installed.

So the accurate way to put it: this removes the **install surface**, not
network visibility in general.

## Limitations (on purpose — this is meant to be small)

- No `ELF()`-style automatic symbol/offset resolution — grab offsets with
  `nm -D ./libc.so.6 | grep symbol_name` (watch for the `@@GLIBC_x.y.z`
  version suffix in the output if you parse it yourself) or `readelf`.
- No `one_gadget` integration — run `one_gadget ./libc.so.6` separately.
- No pipe/process PTY allocation — if a target binary behaves differently
  under a real TTY (buffering, etc.) this won't replicate that; pwntools'
  `process(..., raw=False)` / `pty` handling covers more edge cases.
- `interactive()` uses `select()` and a 0.2s poll loop — fine for an
  interactive shell, not built for high-throughput binary transfer (use
  `recv_exact(n)` in a script for that instead).

If you need more than this, you need pwntools. This is specifically the
"I have 10 minutes, no internet, and stdlib Python" tool.
