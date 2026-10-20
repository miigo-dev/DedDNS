#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import html
import ipaddress
import json
import os
import random
import re
import shutil
import socket
import ssl
import string
import struct
import sys
import time
import zlib
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Optional
from urllib.parse import urljoin, urlparse

CONNECT_TIMEOUT = 4
READ_TIMEOUT = 6
TOTAL_TIMEOUT = 10
DNS_TIMEOUT = 4
CONCURRENCY = 50
RETRIES = 1
MAX_BODY_READ = 16_384
WILDCARD_PROBES = 2
MAX_REDIRECTS = 5
REDIRECT_CODES = {301, 302, 303, 307, 308}

ACCEPT_ENCODING = "gzip, deflate"


@dataclass(frozen=True)
class LabelInfo:
    mark: str
    tag: str      
    title: str    
    desc: str     
    note: str     
    suffix: str   


LABELS = {
    "LIVE": LabelInfo("[+]", "LIVE", "Live", "answers 2xx/3xx, no WAF in front",
                      "", "live"),
    "LIVE_CF": LabelInfo("[c]", "CF", "Live behind Cloudflare", "answers 2xx/3xx via Cloudflare",
                         " (Cloudflare)", "cloudflare"),
    "PROTECTED": LabelInfo("[!]", "WAF", "Protected", "401/403/429 or a WAF/bot challenge page",
                           " (Protected)", "protected"),
    "TLS_ISSUE": LabelInfo("[x]", "TLS", "TLS issues", "only reachable with certificate checks off",
                           " (TLS issue)", "tls_issues"),
    "WILDCARD": LabelInfo("[?]", "WILD", "Possible wildcard", "same response as a random subdomain",
                          " (possible wildcard)", "possible_wildcard"),
    "HTTP_ERROR": LabelInfo("[e]", "ERR", "HTTP errors", "server is up but returns 4xx/5xx",
                            " (HTTP error)", "http_errors"),
    "DEAD": LabelInfo("[-]", "DEAD", "Dead", "no DNS or no HTTP(S) answer",
                      "", "dead"),
}

DEAD_REASONS = {
    "dns_resolution_failed": "No DNS record",
    "dns_timeout": "DNS timeout",
    "no_response": "Resolves, but no HTTP(S) answer",
}
LABEL_RANK = {label: i for i, label in enumerate(LABELS)}

PROTECTED_STATUSES = {401, 403, 407, 429}

CHALLENGE_HEADERS = ("cf-mitigated", "x-sucuri-block")
CHALLENGE_TITLE_PHRASES = (
    "just a moment",
    "attention required",
    "access denied",
    "request blocked",
    "request rejected",
    "you have been blocked",
    "security check",
    "verify you are human",
    "captcha",
    "ddos-guard",
    "incapsula incident",
    "web application firewall",
)
CHALLENGE_BODY_MARKERS = (
    "/cdn-cgi/challenge-platform/",
    "cf-chl-",
    "_incapsula_resource",
    "sucuri website firewall",
)

_BANNER_UNICODE = """\
▓█████▄ ▓█████ ▓█████▄ ▓█████▄  ███▄    █   ██████
▒██▀ ██▌▓█   ▀ ▒██▀ ██▌▒██▀ ██▌ ██ ▀█   █ ▒██    ▒
░██   █▌▒███   ░██   █▌░██   █▌▓██  ▀█ ██▒░ ▓██▄
░▓█▄   ▌▒▓█  ▄ ░▓█▄   ▌░▓█▄   ▌▓██▒  ▐▌██▒  ▒   ██▒
░▒████▓ ░▒████▒░▒████▓ ░▒████▓ ▒██░   ▓██░▒██████▒▒
 ▒▒▓  ▒ ░░ ▒░ ░ ▒▒▓  ▒  ▒▒▓  ▒ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░
 ░ ▒  ▒  ░ ░  ░ ░ ▒  ▒  ░ ▒  ▒ ░ ░░   ░ ▒░░ ░▒  ░ ░
 ░ ░  ░    ░    ░ ░  ░  ░ ░  ░    ░   ░ ░ ░  ░  ░
   ░       ░  ░   ░       ░             ░       ░
 ░              ░       ░                          """

_BANNER_ASCII = r"""
 ____           _ ____  _   _ ____
|  _ \  ___  __| |  _ \| \ | / ___|
| | | |/ _ \/ _` | | | |  \| \___ \
| |_| |  __/ (_| | |_| | |\  |___) |
|____/ \___|\__,_|____/|_| \_|____/"""


def render_banner() -> str:
    """Pick the richest banner the current stdout can encode; always ASCII-safe."""
    enc = getattr(sys.stdout, "encoding", None) or "ascii"
    art = _BANNER_UNICODE
    try:
        art.encode(enc)
    except (UnicodeEncodeError, LookupError):
        art = _BANNER_ASCII
    return "\n".join(["", art, ""])


DEDDNS_BANNER = render_banner()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.40 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/123.0.6312.52 Mobile/15E148 Safari/604.1",
]


def random_headers() -> dict:
    """Build a realistic request header set with a random user agent."""
    ua = random.choice(USER_AGENTS)
    is_mobile = any(m in ua for m in ("Mobile", "Android", "iPhone", "iPad"))
    is_firefox = "Firefox" in ua
    is_safari = "Safari" in ua and "Chrome" not in ua

    if is_firefox:
        accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        accept_language = random.choice(["en-US,en;q=0.5", "en-GB,en;q=0.5", "en-US,en;q=0.9,fr;q=0.5"])
    elif is_safari and not is_mobile:
        accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        accept_language = random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.9"])
    else:
        accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
        accept_language = random.choice([
            "en-US,en;q=0.9",
            "en-US,en;q=0.9,es;q=0.8",
            "en-GB,en;q=0.9",
            "en-US,en;q=0.9,fr;q=0.8",
        ])

    headers = {
        "User-Agent": ua,
        "Accept": accept,
        "Accept-Encoding": ACCEPT_ENCODING,
        "Accept-Language": accept_language,
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    }

    if random.random() < 0.4:
        headers["DNT"] = "1"

    return headers


@dataclass
class Response:
    url: str
    final_url: str
    status: int
    headers: dict
    text: str
    tls_issue: bool = False


@dataclass
class Fingerprint:
    """Response summary with the probed hostname masked out, so a wildcard
    page that echoes its own hostname still compares equal across hosts."""
    status: int
    final_url: str
    title: str
    content_length: int
    body_hash: str


@dataclass
class Baseline:
    ips: frozenset
    fp: Fingerprint


@dataclass
class Result:
    host: str
    label: str
    ips: list = field(default_factory=list)
    reason: str = ""
    status: int = 0
    url: str = ""
    final_url: str = ""
    title: str = ""
    server: str = ""

    def __post_init__(self):
        if not self.url:
            self.url = host_url("https", self.host)


def _help_epilog() -> str:
    categories = "\n".join(
        f"  {info.tag:<5} {info.desc}" for info in LABELS.values()
    )
    return f"""\
input format:
  One host or URL per line (hosts, URLs, host:port, IPs, *.example.com).
  Blank lines and # comments are skipped; duplicates removed. Use '-' for stdin.

categories (best response per host wins):
{categories}

results:
  Dashboard while scanning, then a table per category (--plain for one line
  per host, automatic when piped). --save (default) appends URLs to
  <output-dir>/<base>_<category>.txt. --json PATH writes a full report
  ('-' for stdout). Ctrl-C still saves what finished.

examples:
  %(prog)s subs.txt                       # scan, dashboard, save lists
  %(prog)s subs.txt -c 100 -t 6 --no-save # faster, nothing to disk
  subfinder -d example.com -silent | %(prog)s -
  %(prog)s subs.txt --json - 2>/dev/null | jq -r '.results[]|select(.label=="LIVE").url'

exit status: 0 done  1 bad/empty input  2 bad args  130 interrupted (partial saved)
"""


def _int_at_least(minimum: int):
    def parse(value: str) -> int:
        try:
            n = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"expected an integer, got {value!r}")
        if n < minimum:
            raise argparse.ArgumentTypeError(f"must be >= {minimum}, got {n}")
        return n
    return parse


def _positive_float(value: str) -> float:
    try:
        n = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a number, got {value!r}")
    if n <= 0:
        raise argparse.ArgumentTypeError(f"must be > 0, got {value}")
    return n


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        usage="%(prog)s [options] INPUT",
        epilog=_help_epilog(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    g = p.add_argument_group("input")
    g.add_argument("input", metavar="INPUT",
                   help="file with one host or URL per line, or '-' to read from stdin")

    g = p.add_argument_group("output")
    save = g.add_mutually_exclusive_group()
    save.add_argument("--save", dest="save", action="store_true", default=True,
                      help="append URLs to <base>_<category>.txt files (default)")
    save.add_argument("--no-save", dest="save", action="store_false",
                      help="don't write the per-category text files")
    g.add_argument("-o", "--output-dir", metavar="DIR", default=".",
                   help="where the text files go; created if missing (default: current dir)")
    g.add_argument("-j", "--json", metavar="PATH",
                   help="write a JSON report to PATH; '-' prints it to stdout and sends "
                        "everything else to stderr")

    g = p.add_argument_group("scanning")
    g.add_argument("-c", "--concurrency", metavar="N", type=_int_at_least(1), default=CONCURRENCY,
                   help=f"hosts scanned at once (default: {CONCURRENCY})")
    g.add_argument("-t", "--timeout", metavar="SEC", type=_positive_float, default=TOTAL_TIMEOUT,
                   help=f"max seconds per HTTP request, redirects included (default: {TOTAL_TIMEOUT})")
    g.add_argument("-r", "--retries", metavar="N", type=_int_at_least(0), default=RETRIES,
                   help="extra attempts after a dropped or reset connection; timeouts and "
                        f"refused connections are not retried (default: {RETRIES})")
    g.add_argument("--resolver", metavar="IP",
                   help="DNS server to query (default: system resolver; falls back to OS lookup)")
    g.add_argument("--no-wildcard", action="store_true",
                   help="skip wildcard detection (fewer requests; wildcard hosts then show as live)")

    g = p.add_argument_group("display")
    g.add_argument("-v", "--verbose", action="store_true",
                   help="list dead hosts by name instead of only counting them")
    g.add_argument("--plain", action="store_true",
                   help="one line per host instead of the dashboard (automatic when piped)")

    if argv is None and len(sys.argv) == 1:
        p.print_help()
        sys.exit(2)
    return p.parse_args(argv)


HOST_LABEL_RE = re.compile(r"(?!-)[a-z0-9_-]{1,63}(?<!-)")


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def normalize_host(line: str) -> Optional[str]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    if "://" in line:
        try:
            host = urlparse(line).hostname
        except ValueError:
            return None
    else:
        host = line.split("/")[0].split(":")[0]

    if not host:
        return None

    host = host.lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]

    if is_ip(host):
        return host
    if len(host) > 253 or not all(HOST_LABEL_RE.fullmatch(lbl) for lbl in host.split(".")):
        return None
    return host


def read_hosts(lines: Iterable[str]) -> list:
    return list(dict.fromkeys(h for h in map(normalize_host, lines) if h))


def host_url(scheme: str, host: str) -> str:
    return f"{scheme}://[{host}]" if ":" in host else f"{scheme}://{host}"


def random_label(n: int = 12) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))


def wildcard_parent(host: str) -> Optional[str]:
    """Zone a DNS wildcard would have to live in to cover `host`.

    Using the immediate parent (not a naive last-two-labels "apex") handles
    deep names like a.b.example.com and avoids probing *.co.uk.
    """
    if is_ip(host):
        return None
    labels = host.split(".")
    return ".".join(labels[1:]) if len(labels) >= 3 else None


def extract_title(text: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", html.unescape(m.group(1))).strip()[:120]


def fingerprint(resp: Response, host: str) -> Fingerprint:
    mask = re.compile(re.escape(host), re.I)
    text = mask.sub("{HOST}", resp.text)
    body = text.encode("utf-8")
    return Fingerprint(
        status=resp.status,
        final_url=mask.sub("{HOST}", resp.final_url),
        title=extract_title(text),
        content_length=len(body),
        body_hash=hashlib.sha256(body).hexdigest()[:16] if body else "",
    )


def same_fingerprint(a: Fingerprint, b: Fingerprint) -> bool:
    if a.status != b.status:
        return False
    if a.body_hash and a.body_hash == b.body_hash:
        return True
    if a.title != b.title or a.final_url != b.final_url:
        return False
    if a.title:
        return True
    longest = max(a.content_length, b.content_length)
    return longest == 0 or abs(a.content_length - b.content_length) / longest < 0.05


def matches_wildcard(fp: Fingerprint, ips: list, baselines: list) -> bool:
    return any(
        same_fingerprint(fp, b.fp)
        or (frozenset(ips) == b.ips and fp.status == b.fp.status and fp.title == b.fp.title)
        for b in baselines
    )


def is_cloudflare(headers: dict) -> bool:
    return headers.get("server", "").lower() == "cloudflare" or "cf-ray" in headers


def is_challenge(headers: dict, title: str, text: str) -> bool:
    if any(h in headers for h in CHALLENGE_HEADERS):
        return True
    title = title.lower()
    if any(p in title for p in CHALLENGE_TITLE_PHRASES):
        return True
    lower_text = text.lower()
    return any(m in lower_text for m in CHALLENGE_BODY_MARKERS)


def classify(resp: Response) -> str:
    if resp.tls_issue:
        return "TLS_ISSUE"
    if resp.status in PROTECTED_STATUSES or is_challenge(resp.headers, extract_title(resp.text), resp.text):
        return "PROTECTED"
    if 200 <= resp.status < 400:
        return "LIVE_CF" if is_cloudflare(resp.headers) else "LIVE"
    return "HTTP_ERROR"


def choose_best(responses: list) -> tuple:
    """Pick the most useful response: best label, then https, then lowest status."""
    return min(
        ((classify(r), r) for r in responses),
        key=lambda lr: (LABEL_RANK[lr[0]], not lr[1].url.startswith("https://"), lr[1].status),
    )


def decode_body(body: bytes, charset: Optional[str]) -> str:
    try:
        return body.decode(charset or "utf-8", errors="ignore")
    except LookupError:
        return body.decode("utf-8", errors="ignore")


def redirect_target(r: Result) -> str:
    """Final URL if the probe was redirected somewhere meaningful, else ''."""
    if r.final_url and r.final_url.rstrip("/") != r.url.rstrip("/"):
        return r.final_url
    return ""


def dead_reason(reason: str) -> str:
    if reason.startswith("error:"):
        return f"Scanner error ({reason[6:]})"
    return DEAD_REASONS.get(reason, reason or "unknown")


def domain_sort_key(host: str) -> tuple:
    return (1, host) if is_ip(host) else (0, tuple(reversed(host.split("."))))


def zone_of(host: str) -> str:
    """Rough registrable zone, only used to visually separate groups."""
    return host if is_ip(host) else ".".join(host.split(".")[-2:])


def format_result(r: Result) -> str:
    info = LABELS[r.label]
    note = f" (Dead: {dead_reason(r.reason)})" if r.label == "DEAD" else info.note
    ips = ",".join(r.ips[:3]) if r.ips else "N/A"
    status = f"[{r.status}]" if r.status else "[---]"
    redirect = f" -> {redirect_target(r)}" if redirect_target(r) else ""
    title = f' "{r.title}"' if r.title else ""
    return f"{info.mark} {status} {r.url}{redirect} [{ips}]{note}{title}"


def clip(text: str, width: int) -> str:
    return text if len(text) <= width else text[: max(0, width - 1)] + "~"


def safe_print(msg: str, err: bool = False):
    stream = sys.stderr if err else sys.stdout
    try:
        print(msg, file=stream, flush=True)
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), stream.fileno())


class DNSTimeout(Exception):
    pass


class DNSFailure(Exception):
    pass


def _encode_qname(host: str) -> bytes:
    out = bytearray()
    for label in host.split("."):
        lb = label.encode("ascii")
        if not lb or len(lb) > 63:
            raise DNSFailure("bad label")
        out.append(len(lb))
        out += lb
    out.append(0)
    return bytes(out)


def _build_query(qid: int, host: str, qtype: int) -> bytes:
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = _encode_qname(host) + struct.pack(">HH", qtype, 1)
    return header + question


def _skip_name(data: bytes, off: int) -> int:
    while True:
        if off >= len(data):
            raise DNSFailure("truncated name")
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            return off + 2
        off += 1 + length


def _parse_response(data: bytes, want_type: int) -> tuple:
    """Return (list of ip strings, rcode)."""
    if len(data) < 12:
        raise DNSFailure("short header")
    _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    rcode = flags & 0x0F
    off = 12
    for _ in range(qd):
        off = _skip_name(data, off)
        off += 4
    ips = []
    for _ in range(an):
        off = _skip_name(data, off)
        if off + 10 > len(data):
            break
        rtype, rclass, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        off += rdlen
        if rclass != 1 or rtype != want_type:
            continue
        if want_type == 1 and rdlen == 4:
            ips.append(socket.inet_ntop(socket.AF_INET, rdata))
        elif want_type == 28 and rdlen == 16:
            ips.append(socket.inet_ntop(socket.AF_INET6, rdata))
    return ips, rcode


class _DNSProto(asyncio.DatagramProtocol):
    def __init__(self, fut: asyncio.Future):
        self.fut = fut

    def datagram_received(self, data, addr):
        if not self.fut.done():
            self.fut.set_result(data)

    def error_received(self, exc):
        if not self.fut.done():
            self.fut.set_exception(exc)

    def connection_lost(self, exc):
        if exc and not self.fut.done():
            self.fut.set_exception(exc)


class UDPResolver:
    """Minimal async DNS client over UDP against one or more servers."""

    def __init__(self, servers: list, timeout: float, retries: int = 1):
        self.servers = servers
        self.timeout = timeout
        self.retries = retries

    async def _exchange(self, server: str, packet: bytes) -> bytes:
        loop = asyncio.get_event_loop()
        fut = loop.create_future()
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _DNSProto(fut), remote_addr=(server, 53), family=family
        )
        try:
            transport.sendto(packet)
            return await asyncio.wait_for(fut, self.timeout)
        finally:
            transport.close()

    async def query(self, host: str, qtype: str) -> list:
        want = 1 if qtype == "A" else 28
        qid = random.randint(0, 0xFFFF)
        packet = _build_query(qid, host, want)
        timed_out = False
        for server in self.servers:
            for _ in range(self.retries + 1):
                try:
                    data = await self._exchange(server, packet)
                except asyncio.TimeoutError:
                    timed_out = True
                    continue
                except OSError:
                    break
                if len(data) < 2 or struct.unpack(">H", data[:2])[0] != qid:
                    continue
                try:
                    ips, rcode = _parse_response(data, want)
                except Exception:
                    break
                if ips:
                    return ips
                if rcode in (0, 3):
                    return []
                break
        if timed_out:
            raise DNSTimeout()
        raise DNSFailure()


class SystemResolver:
    """Fallback resolver using the OS getaddrinfo (thread pool)."""

    def __init__(self, timeout: float):
        self.timeout = timeout

    async def query(self, host: str, qtype: str) -> list:
        loop = asyncio.get_event_loop()
        family = socket.AF_INET if qtype == "A" else socket.AF_INET6
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, None, family=family, type=socket.SOCK_STREAM),
                self.timeout,
            )
        except asyncio.TimeoutError:
            raise DNSTimeout()
        except OSError:
            raise DNSFailure()
        return sorted({info[4][0] for info in infos})


def detect_system_dns() -> list:
    """Find the OS DNS servers (resolv.conf on unix, registry on Windows)."""
    servers: list = []
    if os.name == "nt":
        try:
            import winreg
            base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as key:
                for name in ("NameServer", "DhcpNameServer"):
                    try:
                        val, _ = winreg.QueryValueEx(key, name)
                    except FileNotFoundError:
                        continue
                    servers += re.split(r"[ ,]+", str(val).strip())
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base + r"\Interfaces") as ifaces:
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(ifaces, i)
                    except OSError:
                        break
                    i += 1
                    with winreg.OpenKey(ifaces, sub) as k2:
                        for name in ("NameServer", "DhcpNameServer"):
                            try:
                                val, _ = winreg.QueryValueEx(k2, name)
                            except FileNotFoundError:
                                continue
                            servers += re.split(r"[ ,]+", str(val).strip())
        except Exception:
            pass
    else:
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            servers.append(parts[1])
        except Exception:
            pass

    out = []
    for s in servers:
        s = s.split("%")[0].strip()
        if s and is_ip(s) and s not in out:
            out.append(s)
    return out


def build_resolver(args):
    servers = [args.resolver] if args.resolver else detect_system_dns()
    if servers:
        return UDPResolver(servers, DNS_TIMEOUT, retries=1)
    return SystemResolver(DNS_TIMEOUT)


def _charset(headers: dict) -> Optional[str]:
    m = re.search(r"charset=([\w\-]+)", headers.get("content-type", ""), re.I)
    return m.group(1) if m else None


def _host_header(host: str, port: int, scheme: str) -> str:
    default = 443 if scheme == "https" else 80
    hostpart = f"[{host}]" if ":" in host else host
    return hostpart if port == default else f"{hostpart}:{port}"


class HTTPClient:
    """Async HTTP/1.1 GET with redirects, built on asyncio.open_connection."""

    def __init__(self, connect_timeout: float, read_timeout: float, total_timeout: float):
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.total_timeout = total_timeout
        self._secure_ctx = ssl.create_default_context()
        insecure = ssl.create_default_context()
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE
        self._insecure_ctx = insecure
        with contextlib.suppress(Exception):
            insecure.set_ciphers("DEFAULT@SECLEVEL=1")

    async def fetch_once(self, url: str, verify: bool) -> tuple:
        """Return (Response | None, error kind)."""
        try:
            resp = await asyncio.wait_for(self._chain(url, verify), self.total_timeout)
            return resp, ""
        except asyncio.TimeoutError:
            return None, "timeout"
        except ssl.SSLError:
            return None, "tls"
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            return None, "transient"
        except ConnectionRefusedError:
            return None, "connect"
        except OSError:
            return None, "connect"
        except Exception:
            return None, "other"

    async def _chain(self, start_url: str, verify: bool) -> Response:
        url = start_url
        for hop in range(MAX_REDIRECTS + 1):
            status, headers, reader, writer = await self._request(url, verify)
            try:
                loc = headers.get("location")
                if status in REDIRECT_CODES and loc and hop < MAX_REDIRECTS:
                    nxt = urljoin(url, loc)
                    p = urlparse(nxt)
                    if p.scheme in ("http", "https") and p.hostname:
                        url = nxt
                        continue
                body = await self._read_body(reader, headers)
                return Response(
                    url=start_url,
                    final_url=url,
                    status=status,
                    headers=headers,
                    text=decode_body(body, _charset(headers)),
                )
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
        raise ConnectionError("too many redirects")

    async def _request(self, url: str, verify: bool) -> tuple:
        p = urlparse(url)
        scheme = p.scheme
        host = p.hostname
        port = p.port or (443 if scheme == "https" else 80)
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        ctx = None
        if scheme == "https":
            ctx = self._secure_ctx if verify else self._insecure_ctx
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx,
                                    server_hostname=host if ctx else None),
            self.connect_timeout,
        )
        try:
            req = [f"GET {path} HTTP/1.1", f"Host: {_host_header(host, port, scheme)}"]
            for k, v in random_headers().items():
                req.append(f"{k}: {v}")
            req.append("Connection: close")
            writer.write(("\r\n".join(req) + "\r\n\r\n").encode("latin-1", "ignore"))
            await asyncio.wait_for(writer.drain(), self.read_timeout)
            status, headers = await self._read_head(reader)
            return status, headers, reader, writer
        except BaseException:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            raise

    async def _read_head(self, reader: asyncio.StreamReader) -> tuple:
        line = await asyncio.wait_for(reader.readline(), self.read_timeout)
        if not line:
            raise ConnectionError("empty response")
        parts = line.decode("latin-1").split(" ", 2)
        if len(parts) < 2 or not parts[0].startswith("HTTP/"):
            raise ValueError("malformed status line")
        status = int(parts[1])
        headers: dict = {}
        for _ in range(100):
            hl = await asyncio.wait_for(reader.readline(), self.read_timeout)
            if hl in (b"\r\n", b"\n", b""):
                break
            k, sep, v = hl.decode("latin-1").partition(":")
            if sep:
                headers[k.strip().lower()] = v.strip()
        if 100 <= status < 200:
            return await self._read_head(reader)
        return status, headers

    async def _read_capped(self, reader: asyncio.StreamReader, limit: int) -> bytes:
        chunks, size = [], 0
        while size < limit:
            chunk = await asyncio.wait_for(reader.read(limit - size), self.read_timeout)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        return b"".join(chunks)

    async def _read_chunked(self, reader: asyncio.StreamReader, limit: int = MAX_BODY_READ) -> bytes:
        body = bytearray()
        while len(body) < limit:
            size_line = await asyncio.wait_for(reader.readline(), self.read_timeout)
            if not size_line:
                break
            token = size_line.split(b";", 1)[0].strip()
            try:
                csize = int(token, 16)
            except ValueError:
                break
            if csize == 0:
                break
            want = min(csize, limit - len(body))
            data = await self._read_capped(reader, want)
            body += data
            if len(data) < csize:
                break
            await asyncio.wait_for(reader.readline(), self.read_timeout)
        return bytes(body)

    async def _read_body(self, reader: asyncio.StreamReader, headers: dict) -> bytes:
        if "chunked" in headers.get("transfer-encoding", "").lower():
            raw = await self._read_chunked(reader)
        else:
            cl = headers.get("content-length", "")
            limit = min(int(cl), MAX_BODY_READ) if cl.isdigit() else MAX_BODY_READ
            raw = await self._read_capped(reader, limit)
        return self._decompress(raw, headers.get("content-encoding", ""))

    @staticmethod
    def _decompress(raw: bytes, encoding: str) -> bytes:
        enc = encoding.lower()
        try:
            if "gzip" in enc:
                return zlib.decompressobj(zlib.MAX_WBITS | 16).decompress(raw)
            if "deflate" in enc:
                try:
                    return zlib.decompressobj().decompress(raw)
                except zlib.error:
                    return zlib.decompressobj(-zlib.MAX_WBITS).decompress(raw)
        except Exception:
            return raw
        return raw


class Scanner:
    def __init__(self, http: HTTPClient, resolver, retries: int, wildcard: bool):
        self.http = http
        self.resolver = resolver
        self.retries = retries
        self.wildcard = wildcard
        self._wildcards: dict = {}

    async def resolve(self, host: str) -> tuple:
        """Return (sorted ips, failure reason)."""
        if is_ip(host):
            return [host], ""
        answers = await asyncio.gather(
            self.resolver.query(host, "A"), self.resolver.query(host, "AAAA"),
            return_exceptions=True,
        )
        ips = set()
        timed_out = False
        for a in answers:
            if isinstance(a, DNSTimeout):
                timed_out = True
            elif isinstance(a, BaseException):
                continue
            else:
                ips.update(a)
        if ips:
            return sorted(ips), ""
        return [], "dns_timeout" if timed_out else "dns_resolution_failed"

    async def fetch(self, url: str, verify: bool) -> tuple:
        for attempt in range(self.retries + 1):
            resp, err = await self.http.fetch_once(url, verify)
            if resp or err != "transient" or attempt == self.retries:
                return resp, err
            await asyncio.sleep(0.5 * (attempt + 1))
        return None, "other"

    async def probe(self, host: str, scheme: str) -> Optional[Response]:
        url = host_url(scheme, host)
        resp, err = await self.fetch(url, True)
        if resp is None and err == "tls":
            resp, _ = await self.fetch(url, False)
            if resp:
                resp.tls_issue = True
        return resp

    async def probe_all(self, host: str) -> list:
        results = await asyncio.gather(self.probe(host, "https"), self.probe(host, "http"))
        return [r for r in results if r]

    async def _probe_wildcard(self, parent: str) -> list:
        hosts = [f"{random_label()}.{parent}" for _ in range(WILDCARD_PROBES)]
        resolved = await asyncio.gather(*(self.resolve(h) for h in hosts))
        targets = [(h, ips) for h, (ips, _) in zip(hosts, resolved) if ips]
        if not targets:
            return []

        responses = await asyncio.gather(*(self.probe_all(h) for h, _ in targets))
        return [
            Baseline(ips=frozenset(ips), fp=fingerprint(r, h))
            for (h, ips), rs in zip(targets, responses)
            for r in rs
        ]

    async def wildcard_baselines(self, parent: str) -> list:
        if parent not in self._wildcards:
            self._wildcards[parent] = asyncio.ensure_future(self._probe_wildcard(parent))
        try:
            return await asyncio.shield(self._wildcards[parent])
        except Exception:
            return []

    async def scan(self, host: str) -> Result:
        ips, dns_err = await self.resolve(host)
        if not ips:
            return Result(host, "DEAD", reason=dns_err)

        responses = await self.probe_all(host)
        if not responses:
            return Result(host, "DEAD", ips=ips, reason="no_response")

        label, best = choose_best(responses)

        parent = wildcard_parent(host) if self.wildcard else None
        if parent and matches_wildcard(fingerprint(best, host), ips, await self.wildcard_baselines(parent)):
            label = "WILDCARD"

        return Result(
            host=host,
            label=label,
            ips=ips,
            status=best.status,
            url=best.url,
            final_url=best.final_url,
            title=extract_title(best.text),
            server=best.headers.get("server", "")[:80],
        )

    async def close(self):
        for fut in self._wildcards.values():
            fut.cancel()


@contextlib.contextmanager
def file_lock(path: str, timeout: float = 10):
    """Cross-platform advisory lock via an O_EXCL sidecar file."""
    lockpath = f"{path}.lock"
    start = time.monotonic()
    fd = None
    while True:
        try:
            fd = os.open(lockpath, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError:
            with contextlib.suppress(OSError):
                if time.monotonic() - os.path.getmtime(lockpath) > 60:
                    os.unlink(lockpath)
                    continue
            if time.monotonic() - start > timeout:
                raise TimeoutError(f"could not lock {path}")
            time.sleep(0.1)
    try:
        yield
    finally:
        if fd is not None:
            os.close(fd)
            with contextlib.suppress(OSError):
                os.unlink(lockpath)


def load_existing_lines(file_path: str) -> set:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return {line.strip() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


def save_outputs(results: list, base: str, out_dir: str) -> list:
    """Append new URLs to <base>_<suffix>.txt. Returns [(path, n_new)]."""
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for label, info in LABELS.items():
        urls = sorted({r.url for r in results if r.label == label})
        if not urls:
            continue
        path = os.path.join(out_dir, f"{base}_{info.suffix}.txt")
        try:
            with file_lock(path):
                existing = load_existing_lines(path)
                new_urls = [u for u in urls if u not in existing]
                if new_urls:
                    with open(path, "a", encoding="utf-8") as f:
                        f.writelines(u + "\n" for u in new_urls)
                written.append((path, len(new_urls)))
        except OSError as e:
            safe_print(f"[!] Could not write {path}: {e}", err=True)
        except TimeoutError as e:
            safe_print(f"[!] {e}, skipping", err=True)
    return written


def result_to_dict(r: Result) -> dict:
    d = {
        "host": r.host,
        "label": r.label,
        "category": LABELS[r.label].title,
        "status": r.status or None,
        "url": r.url,
        "final_url": r.final_url or None,
        "redirected": bool(redirect_target(r)),
        "title": r.title or None,
        "server": r.server or None,
        "ips": r.ips,
    }
    if r.label == "DEAD":
        d["reason"] = r.reason
        d["reason_text"] = dead_reason(r.reason)
    return d


def build_json_report(results: list, total: int, source: str, started_at: str,
                      elapsed: float, interrupted: bool, args) -> dict:
    counts = Counter(r.label for r in results)
    ordered = sorted(results, key=lambda r: (LABEL_RANK[r.label], domain_sort_key(r.host)))
    return {
        "meta": {
            "source": source,
            "started_at": started_at,
            "elapsed_seconds": round(elapsed, 2),
            "hosts_total": total,
            "hosts_scanned": len(results),
            "interrupted": interrupted,
            "options": {
                "concurrency": args.concurrency,
                "timeout": args.timeout,
                "retries": args.retries,
                "wildcard_detection": not args.no_wildcard,
            },
        },
        "summary": {label: counts[label] for label in LABELS},
        "results": [result_to_dict(r) for r in ordered],
    }


def write_json(report: dict, path: str):
    data = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if path == "-":
        sys.stdout.write(data)
        sys.stdout.flush()
        return
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
    os.replace(tmp, path)


def enable_ansi() -> bool:
    """Turn on ANSI escape handling; needed on older Windows consoles."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


class PlainUI:
    """Line-per-result output; used for pipes, --plain, or JSON on stdout.
    Results go to stdout (unless stdout carries JSON), everything else to stderr."""

    def __init__(self, args):
        self.verbose = args.verbose
        self.results_to_stdout = args.json != "-"

    def warn(self, msg: str):
        safe_print(f"[!] {msg}", err=True)

    def start(self, total: int, source: str, args):
        safe_print(f"[*] Scanning {total} host(s) from {source} with concurrency={args.concurrency}...", err=True)

    def on_result(self, r: Result):
        if r.label != "DEAD" or self.verbose:
            safe_print(format_result(r), err=not self.results_to_stdout)

    def stop(self):
        pass

    def report(self, results: list, total: int, saved: list, elapsed: float, interrupted: bool):
        counts = Counter(r.label for r in results)
        parts = [f"{counts[l]} {l.lower()}" for l, info in LABELS.items() if counts[l]]
        stopped = " (interrupted)" if interrupted else ""
        safe_print(f"\n[=] {len(results)}/{total} scanned in {elapsed:.1f}s{stopped}: "
                   + (" | ".join(parts) or "nothing"), err=True)

        dead = Counter(r.reason for r in results if r.label == "DEAD")
        if dead:
            safe_print("[-] dead: " + ", ".join(f"{n}x {dead_reason(k)}" for k, n in sorted(dead.items())), err=True)
        for path, n in saved:
            safe_print(f"[*] {path}: JSON report" if n is None else f"[+] {path}: +{n} new", err=True)


class LiveUI:
    """Live ASCII dashboard while scanning, then results grouped by category."""

    RECENT = 8

    def __init__(self, args):
        self.verbose = args.verbose
        self.counts: Counter = Counter()
        self.recent: deque = deque(maxlen=self.RECENT)
        self.total = 0
        self.done = 0
        self.started = time.monotonic()
        self.ansi = enable_ansi()
        self._last_lines = 0
        self._last_render = 0.0

    def warn(self, msg: str):
        safe_print(f"[!] {msg}", err=True)

    def start(self, total: int, source: str, args):
        self.total = total
        self.started = time.monotonic()
        opts = (f"target: {source}   hosts: {total}   conc: {args.concurrency}   "
                f"timeout: {args.timeout:g}s   wildcard: {'off' if args.no_wildcard else 'on'}   "
                f"save: {'off' if not args.save else args.output_dir}")
        print(DEDDNS_BANNER)
        print(clip(opts, _term_width()))
        print()
        self._render(force=True)

    def on_result(self, r: Result):
        self.counts[r.label] += 1
        self.done += 1
        if r.label != "DEAD" or self.verbose:
            self.recent.append(r)
        now = time.monotonic()
        if self.done < self.total and now - self._last_render < 0.1:
            return
        self._last_render = now
        self._render()

    def stop(self):
        if self.ansi and self._last_lines:
            sys.stdout.write(f"\x1b[{self._last_lines}A\x1b[J")
            sys.stdout.flush()
            self._last_lines = 0
        elif not self.ansi:
            sys.stdout.write("\r" + " " * 120 + "\r")
            sys.stdout.flush()

    def _frame(self, width: int) -> list:
        pct = self.done / self.total if self.total else 1.0
        bar_w = max(10, min(40, width - 34))
        filled = int(bar_w * pct)
        bar = "#" * filled + "-" * (bar_w - filled)
        elapsed = time.monotonic() - self.started
        lines = [f"[{bar}] {self.done}/{self.total} {pct * 100:5.1f}% {elapsed:6.1f}s"]
        lines.append("  ".join(f"{info.tag}:{self.counts[l]}" for l, info in LABELS.items()))
        lines.append("-" * min(width, 72))
        if self.recent:
            for r in self.recent:
                status = str(r.status) if r.status else "---"
                title = f'  "{r.title}"' if r.title else ""
                lines.append(f" {LABELS[r.label].mark} {status:>3} {r.url}{title}")
        else:
            lines.append(" waiting for first responses...")
        return [clip(ln, width) for ln in lines]

    def _render(self, force: bool = False):
        width = _term_width()
        if not self.ansi:
            tags = " ".join(f"{info.tag}:{self.counts[l]}" for l, info in LABELS.items() if self.counts[l])
            msg = f"[{self.done}/{self.total}] {tags}"
            sys.stdout.write("\r" + clip(msg, 118).ljust(118))
            sys.stdout.flush()
            return
        lines = self._frame(width)
        out = []
        if self._last_lines:
            out.append(f"\x1b[{self._last_lines}A")
        for ln in lines:
            out.append("\x1b[2K" + ln + "\n")
        sys.stdout.write("".join(out))
        sys.stdout.flush()
        self._last_lines = len(lines)

    def _group_block(self, label: str, items: list, width: int):
        info = LABELS[label]
        print(f"=== {info.title} ({len(items)}) === {info.desc}")
        prev_zone = None
        for r in sorted(items, key=lambda r: domain_sort_key(r.host)):
            zone = zone_of(r.host)
            if prev_zone is not None and zone != prev_zone:
                print()
            prev_zone = zone
            status = str(r.status) if r.status else "---"
            extra = []
            target = redirect_target(r)
            if target:
                extra.append(f"-> {target}")
            if r.title:
                extra.append(f'"{r.title}"')
            if r.server:
                extra.append(f"({r.server})")
            line = f"  {info.mark} [{status:>3}] {r.url}"
            if extra:
                line += "  " + "  ".join(extra)
            print(clip(line, width))
        print()

    def _dead_block(self, items: list, width: int):
        info = LABELS["DEAD"]
        print(f"=== {info.title} ({len(items)}) === {info.desc}")
        by_reason: dict = {}
        for r in items:
            by_reason.setdefault(r.reason, []).append(r.host)
        for reason, hosts in sorted(by_reason.items(), key=lambda kv: -len(kv[1])):
            hosts.sort(key=domain_sort_key)
            print(f"  {dead_reason(reason)}: {len(hosts)}")
            if self.verbose:
                for h in hosts:
                    print(clip(f"    {info.mark} {h}", width))
        if not self.verbose:
            print("  (use -v to list dead hosts by name)")
        print()

    def _summary(self, results: list, total: int, saved: list, elapsed: float, interrupted: bool):
        counts = Counter(r.label for r in results)
        print("=" * 48)
        print("SUMMARY" + ("  (interrupted)" if interrupted else ""))
        for label, info in LABELS.items():
            n = counts[label]
            if not n:
                continue
            share = n / len(results)
            bar = "#" * max(1, round(share * 24))
            print(f"  {info.tag:<5} {n:>5}  {bar} {share * 100:4.0f}%")
        print(f"  {len(results)}/{total} hosts scanned in {elapsed:.1f}s")
        lists = [(p, n) for p, n in saved if n is not None]
        if lists:
            out_dir = os.path.dirname(lists[0][0]) or "."
            print(f"  saved to {out_dir}{os.sep}")
            for path, n in lists:
                print(f"    {os.path.basename(path)}  +{n} new")
        for path, n in saved:
            if n is None:
                print(f"  JSON report -> {path}")

    def report(self, results: list, total: int, saved: list, elapsed: float, interrupted: bool):
        width = _term_width()
        groups: dict = {label: [] for label in LABELS}
        for r in results:
            groups[r.label].append(r)

        print()
        if not any(groups[l] for l in LABELS if l != "DEAD"):
            print("  No responding hosts found.\n")
        for label, items in groups.items():
            if not items:
                continue
            if label == "DEAD":
                self._dead_block(items, width)
            else:
                self._group_block(label, items, width)
        if results:
            self._summary(results, total, saved, elapsed, interrupted)


def _term_width() -> int:
    return shutil.get_terminal_size((80, 24)).columns


def make_ui(args):
    if args.plain or args.json == "-" or not sys.stdout.isatty():
        return PlainUI(args)
    return LiveUI(args)


def _quiet_loop_noise(loop, context):
    """Swallow the harmless socket-teardown errors the Windows Proactor loop
    logs when a peer drops an SSL connection; pass everything else through."""
    exc = context.get("exception")
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return
    if isinstance(exc, OSError) and "connection_lost" in context.get("message", ""):
        return
    loop.default_exception_handler(context)


async def run(args: argparse.Namespace) -> None:
    asyncio.get_running_loop().set_exception_handler(_quiet_loop_noise)
    if args.input == "-":
        hosts, base, source = read_hosts(sys.stdin), "stdin", "stdin"
    else:
        if not os.path.isfile(args.input):
            safe_print(f"[x] File not found: {args.input}", err=True)
            sys.exit(1)
        with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
            hosts = read_hosts(f)
        base = os.path.splitext(os.path.basename(args.input))[0]
        source = args.input

    if not hosts:
        safe_print("[x] No valid subdomains found", err=True)
        sys.exit(1)

    ui = make_ui(args)
    resolver = build_resolver(args)
    if isinstance(resolver, SystemResolver):
        ui.warn("no system DNS servers found; using the OS resolver (getaddrinfo)")
    http = HTTPClient(CONNECT_TIMEOUT, READ_TIMEOUT, args.timeout)

    ui.start(len(hosts), source, args)
    started = time.monotonic()
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    interrupted = False
    results: list = []

    scanner = Scanner(http, resolver, args.retries, not args.no_wildcard)
    sem = asyncio.Semaphore(args.concurrency)

    async def worker(h: str) -> Result:
        async with sem:
            try:
                return await scanner.scan(h)
            except Exception as e:
                return Result(h, "DEAD", reason=f"error:{type(e).__name__}")

    try:
        try:
            for fut in asyncio.as_completed([worker(h) for h in hosts]):
                r = await fut
                results.append(r)
                ui.on_result(r)
        finally:
            await scanner.close()
    except asyncio.CancelledError:
        interrupted = True
        raise
    finally:
        ui.stop()
        elapsed = time.monotonic() - started
        saved = save_outputs(results, base, args.output_dir) if args.save and results else []
        if args.json:
            report = build_json_report(results, len(hosts), source, started_at, elapsed, interrupted, args)
            try:
                write_json(report, args.json)
                if args.json != "-":
                    saved.append((args.json, None))
            except OSError as e:
                ui.warn(f"Could not write JSON report {args.json}: {e}")
        ui.report(results, len(hosts), saved, elapsed, interrupted)


def main():
    args = parse_args()
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
