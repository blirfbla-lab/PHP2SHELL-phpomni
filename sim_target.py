#!/usr/bin/env python3
"""sim_target.py — pure-Python stand-in for a php2shell-vulnerable target.

No PHP, no Docker: this speaks just enough HTTP to exercise phpomni's CVE
engine end to end — fingerprint -> leak -> forge -> trigger — for both the
mod_php (109618) and FPM (109619) chains. The heap mechanics are faked
deterministically, so a pass here proves the client protocol logic, not the
memory corruption itself. Use it as a regression harness before touching a
real lab.

The fake build mirrors php:8.4.26-apache (bookworm): zif_system and
zval_ptr_dtor live at libphp+0x465370 / libphp+0x65EB60, and the fake-object
geometry matches BUILTIN_PROFILES["8.4.26/amd64"].

Usage:
    python sim_target.py                     # mod_php chain on 127.0.0.1:8099
    python sim_target.py --sapi fpm --port 8098   # 109619 chain behind nginx
    python sim_target.py --memory-limit 128  # phpomni must climb its ladder
    python sim_target.py --post-max 6        # phpomni must report CONFIG BLOCKED

Then, from the repo root:
    python phpomniv13.py http://127.0.0.1:8099/ --cve-only --cmd id
    python phpomniv13.py http://127.0.0.1:8099/ --cve-only --stage --lhost 127.0.0.1
    python phpomniv13.py --calibrate http://127.0.0.1:8099/ --profiles-out p.json
"""
from __future__ import annotations

import argparse
import re
import socket
import threading
import urllib.parse

# --- fake build constants (bookworm, amd64) ---------------------------------
# LIBPHP/CHUNK deliberately carry a 0x20 byte: php_url_encode emits it as
# '+', so the end-to-end runs prove the client folds '+' back to 0x20.
LIBPHP = 0x7F1220340000        # fake libphp base, page aligned, 0x20 at byte 3
DTOR = 0x65EB60                # zval_ptr_dtor offset inside libphp
ZIF = 0x465370                # zif_system offset inside libphp
CHUNK = 0x7F5520400000         # fake Zend MM chunk base, 2MB aligned, 0x20 at byte 3
# fake-object geometry inside the reclaim chunk (must mirror BUILTIN_PROFILES)
PDESTRUCTOR, ARDATA, NUMUSED = 0x38, 0x18, 0x20
ZSTRING, STRLEN, STRVAL = 0x5A8, 0x5B8, 0x5C0

PHPINFO_PATHS = ("/phpinfo.php", "/info.php", "/test.php", "/server-status")


def _p64(v: int) -> bytes:
    return v.to_bytes(8, "little")


def _php_url_encode(data: bytes) -> str:
    """php_url_encode(): 0x20 -> '+', everything else non-alphanumeric -> %XX."""
    return urllib.parse.quote_from_bytes(data, safe="").replace("%20", "+")


class Sim:
    """Deterministic fake of the vulnerable request cycle."""

    def __init__(self, sapi: str = "apache", memory_limit: int = 8, post_max: int = 0):
        self.sapi = sapi
        self.mem = memory_limit << 20          # memory_limit, bytes
        self.post_max = (post_max << 20) if post_max else 0   # 0 = unlimited
        self.lock = threading.Lock()
        self.armed = False
        self.events: list[str] = []

    # ---- identity ----------------------------------------------------------

    def server_headers(self) -> dict[str, str]:
        if self.sapi == "apache":
            return {"Server": "Apache/2.4.69 (Debian)", "X-Powered-By": "PHP/8.4.26"}
        return {"Server": "nginx/1.25.3", "X-Powered-By": "PHP/8.4.26"}

    def note(self, msg: str) -> None:
        self.events.append(msg)
        print(f"[sim] {msg}", flush=True)

    def fatal(self) -> bytes:
        """The OOM reply: names memory_limit, exactly like the real one."""
        return (f"PHP Fatal error:  Allowed memory size of {self.mem} bytes"
                f" exhausted (tried to allocate {self.mem + 16} bytes)"
                f" in Unknown on line 0\n").encode()

    def post_max_warn(self, body_len: int) -> bytes:
        """PHP rejects an oversized body before parsing it; the warning
        names post_max_size (rendered because display_errors is on)."""
        return (f"PHP Warning:  POST Content-Length of {body_len} bytes"
                f" exceeds the limit of {self.post_max} bytes"
                f" in Unknown on line 0\n").encode()

    # ---- leaks ------------------------------------------------------------

    def heap_cookie(self) -> str:
        """Stage-1 style: the reclaimed chunk full of heap pointers."""
        raw = bytearray(4096)
        for i in range(0, 4096 - 8, 16):
            raw[i:i + 8] = _p64(CHUNK)
        return "PHPSESSID=" + _php_url_encode(bytes(raw)) + "; path=/"

    def lib_cookie(self) -> str:
        """Stage-2 style: cookie starts at PS(id)+0x18, pDestructor at [8:16]."""
        raw = bytearray(4096)
        raw[8:16] = _p64(LIBPHP + DTOR)
        for i in range(64, 4096 - 8, 64):
            raw[i:i + 8] = _p64(CHUNK)
        return "PHPSESSID=" + _php_url_encode(bytes(raw)) + "; path=/"

    # ---- forge execution ----------------------------------------------------

    def fire(self, forge: bytes) -> tuple[bool, bytes]:
        """Validate the forged fake object; on a hit, 'run' the command."""
        if len(forge) < STRVAL + 1:
            return False, b""
        pdestr = int.from_bytes(forge[PDESTRUCTOR:PDESTRUCTOR + 8], "little")
        arr = int.from_bytes(forge[ARDATA:ARDATA + 8], "little")
        nused = int.from_bytes(forge[NUMUSED:NUMUSED + 4], "little")
        zrc = int.from_bytes(forge[ZSTRING:ZSTRING + 4], "little")
        ztype = int.from_bytes(forge[ZSTRING + 4:ZSTRING + 8], "little")
        slen = int.from_bytes(forge[STRLEN:STRLEN + 8], "little")
        want_pdestr = LIBPHP + ZIF
        want_arr = (CHUNK & ~0xF) + ZSTRING
        if (pdestr != want_pdestr or arr != want_arr or nused != 1
                or zrc != 1 or ztype != 6 or not 0 < slen <= len(forge) - STRVAL):
            self.note(f"forge rejected: pdestr={pdestr:#x} (want {want_pdestr:#x}) "
                      f"arr={arr:#x} (want {want_arr:#x}) nused={nused} "
                      f"z=({zrc},{ztype}) slen={slen}")
            return False, b""
        cmd = forge[STRVAL:STRVAL + slen - 1].decode("latin1")
        self.note(f"RCE via forged zif_system: {cmd!r}")
        return True, b"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"

    # ---- request dispatch ----------------------------------------------------

    def handle(self, method: str, path: str, headers: dict, body: bytes):
        """Return (status, body, extra_header_or_None)."""
        if method == "GET":
            if any(path.startswith(p) for p in PHPINFO_PATHS):
                return 404, b"not found\n", None
            return 200, b"SIM OK\n", None
        m = re.search(r"boundary=([^;\s]+)", headers.get("content-type", ""))
        if not m:
            return 200, b"ok\n", None
        if self.post_max and len(body) >= self.post_max:
            self.note("post_max: body rejected before parse")
            return 200, self.post_max_warn(len(body)), None
        boundary = m.group(1).encode()
        parts = _parse_parts(body, boundary)
        names = [p["name"] for p in parts]
        has_prog = "PHP_SESSION_UPLOAD_PROGRESS" in names
        fat = max((len(p["data"]) for p in parts), default=0)
        with self.lock:
            # 1. OOM producer: upload progress + a part past memory_limit.
            #    A part below the limit must NOT arm (phpomni's config ladder
            #    relies on the missing fatal to climb).
            if has_prog and fat >= self.mem:
                self.armed = True
                self.note("producer: OOM, session state left stale")
                return 200, self.fatal(), None
            # 2. FPM trigger: field "r" carrying the forged object
            rp = next((p for p in parts if p["name"] == "r"
                       and len(p["data"]) >= 0xA7), None)
            if rp is not None:
                hit, out = self.fire(rp["data"])
                return 200, out, None
            # 3. mod_php trigger: file part = 0x100 pad + forged object
            fp = next((p for p in parts if p.get("filename")
                       and len(p["data"]) > 0x200), None)
            if fp is not None and has_prog:
                hit, out = self.fire(fp["data"][0x100:])
                return 200, out, None
            # 4. leak consumer: PHPSESSID + progress, no oversized part
            if has_prog and "PHPSESSID" in names and fat < self.mem:
                if not self.armed:
                    return 200, b"sim: not armed\n", None
                self.armed = False
                if any(p["name"] == "1999" for p in parts):
                    self.note("consumer: heap leak handed back in Set-Cookie")
                    return 200, b"sim: leak\n", ("Set-Cookie", self.heap_cookie())
                self.note("consumer: libphp leak handed back in Set-Cookie")
                return 200, b"sim: leak\n", ("Set-Cookie", self.lib_cookie())
        return 200, b"sim: post\n", None


def _parse_parts(body: bytes, boundary: bytes) -> list[dict]:
    """Split a multipart body into {name, filename?, data} parts."""
    parts: list[dict] = []
    delim = b"--" + boundary
    for seg in body.split(delim):
        if not seg or seg.startswith(b"--"):
            continue
        seg = seg.strip(b"\r\n")
        if b"\r\n\r\n" not in seg:
            continue
        head, _, data = seg.partition(b"\r\n\r\n")
        nm = re.search(rb'name="([^"]*)"', head)
        fn = re.search(rb'filename="([^"]*)"', head)
        if not nm:
            continue
        parts.append({"name": nm.group(1).decode("latin1"),
                      "filename": fn.group(1).decode("latin1") if fn else None,
                      "data": data})
    return parts


def _read_request(sock: socket.socket):
    """Read one HTTP request. Returns (method, path, headers, body) or None.

    phpomni's chunked exploit bodies never carry the terminating 0-chunk
    (the interesting part happens mid-upload), so chunked reading stops at
    the closing multipart boundary instead.
    """
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            d = sock.recv(65536)
            if not d:
                return None
            buf += d
    except socket.timeout:
        return None
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    try:
        method, path = lines[0].split()[0:2]
    except (IndexError, ValueError):
        return None
    headers: dict[str, str] = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, _, v = ln.partition(":")
            headers[k.strip().lower()] = v.strip()
    body = rest
    if "chunked" in headers.get("transfer-encoding", "").lower():
        closing = None
        m = re.search(r"boundary=([^;\s]+)", headers.get("content-type", ""))
        if m:
            closing = b"--" + m.group(1).encode() + b"--"
        # The mod_php trigger deliberately stalls mid-body (past min_freq)
        # before sending the forge, so the read timeout must outlast the
        # stall (~2s). Complete bodies exit on the closing boundary anyway.
        sock.settimeout(5.0)
        while True:
            if closing and closing in body:
                break
            if body.endswith(b"0\r\n\r\n"):
                break
            try:
                d = sock.recv(1 << 20)
            except socket.timeout:
                break
            if not d:
                break
            body += d
        raw, pos = bytearray(), 0
        while True:
            nl = body.find(b"\r\n", pos)
            if nl < 0:
                break
            try:
                size = int(body[pos:nl].split(b";")[0], 16)
            except ValueError:
                break
            if size == 0:
                break
            raw += body[nl + 2:nl + 2 + size]
            pos = nl + 2 + size + 2
        sock.settimeout(10)
        return method, path, headers, bytes(raw)
    n = int(headers.get("content-length", "0") or 0)
    while len(body) < n:
        d = sock.recv(65536)
        if not d:
            break
        body += d
    return method, path, headers, body


def _reply(sock: socket.socket, status: int, body: bytes, extra, sim: Sim,
           keep: bool) -> None:
    reason = "OK" if status == 200 else "Not Found"
    sh = sim.server_headers()
    hdr = [f"HTTP/1.1 {status} {reason}", f"Server: {sh['Server']}",
           f"X-Powered-By: {sh['X-Powered-By']}"]
    if extra:
        hdr.append(f"{extra[0]}: {extra[1]}")
    hdr += ["Content-Type: text/html; charset=UTF-8",
            f"Content-Length: {len(body)}",
            "Connection: keep-alive" if keep else "Connection: close"]
    sock.sendall(("\r\n".join(hdr) + "\r\n\r\n").encode() + body)


def _serve(sock: socket.socket, sim: Sim) -> None:
    sock.settimeout(60)
    try:
        while True:
            req = _read_request(sock)
            if req is None:
                return
            method, path, headers, body = req
            status, out, extra = sim.handle(method, path, headers, body)
            keep = "close" not in headers.get("connection", "").lower()
            _reply(sock, status, out, extra, sim, keep)
            if not keep:
                return
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


def main() -> int:
    ap = argparse.ArgumentParser(description="phpomni lab simulator (pure Python)")
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--sapi", choices=["apache", "fpm"], default="apache",
                    help="apache = mod_php 109618 chain, fpm = nginx-fronted 109619 chain")
    ap.add_argument("--memory-limit", type=int, default=8, metavar="MB",
                    help="fake memory_limit (default 8); phpomni's ladder must climb it")
    ap.add_argument("--post-max", type=int, default=0, metavar="MB",
                    help="fake post_max_size (0 = unlimited); below the OOM body"
                         " size phpomni must report CONFIG BLOCKED")
    args = ap.parse_args()
    sim = Sim(args.sapi, args.memory_limit, args.post_max)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(16)
    print(f"sim_target: {args.sapi} chain on http://127.0.0.1:{args.port}/", flush=True)
    print(f"sim_target: libphp={LIBPHP:#x} zif=+{ZIF:#x} dtor=+{DTOR:#x} chunk={CHUNK:#x}",
          flush=True)
    print(f"sim_target: memory_limit={args.memory_limit}M"
          f" post_max={args.post_max or 'off'}", flush=True)
    try:
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=_serve, args=(conn, sim), daemon=True).start()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
