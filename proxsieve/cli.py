import argparse
import csv
import io
import json
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import requests

SCHEMES = ("http", "https", "socks4", "socks5")
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
]
PROXY_HEADERS = ("via", "x-forwarded-for", "forwarded", "x-real-ip", "x-proxy-id", "proxy-connection", "client-ip")
FIELDS = ("proxy", "live", "status", "latency_ms", "anonymity", "error")


def parse_proxy(line, default_scheme="http"):
    """Return a normalized proxy URL, or None for blank/comment lines."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if "://" not in line:
        line = f"{default_scheme}://{line}"
    scheme, rest = line.split("://", 1)
    scheme = scheme.lower()
    hostport = rest.rsplit("@", 1)[-1]
    if scheme not in SCHEMES or ":" not in hostport or not hostport.rsplit(":", 1)[1].isdigit():
        raise ValueError(f"invalid proxy: {line!r}")
    return f"{scheme}://{rest}"


def anonymity(data, real_ip):
    """Classify from the target's echo (httpbin-style: origin + headers)."""
    headers = {k.lower(): str(v) for k, v in (data.get("headers") or {}).items()}
    seen = " ".join([str(data.get("origin", ""))] + list(headers.values()))
    if real_ip and real_ip in seen:
        return "transparent"
    if any(h in headers for h in PROXY_HEADERS):
        return "anonymous"
    return "elite"


def check(proxy, url, timeout, retries, real_ip):
    # socks5h so DNS resolves through the proxy, not locally
    purl = proxy.replace("socks5://", "socks5h://", 1)
    result = {"proxy": proxy, "live": False, "status": None, "latency_ms": None, "anonymity": None, "error": None}
    for attempt in range(retries + 1):
        if attempt:
            time.sleep(0.5 * 2 ** (attempt - 1))
        start = time.monotonic()
        try:
            r = requests.get(url, proxies={"http": purl, "https": purl}, timeout=timeout,
                             headers={"User-Agent": random.choice(USER_AGENTS)})
        except requests.RequestException as e:
            result["error"] = type(e).__name__
            continue
        result.update(status=r.status_code, latency_ms=round((time.monotonic() - start) * 1000), error=None)
        if r.ok:
            result["live"] = True
            try:
                result["anonymity"] = anonymity(r.json(), real_ip)
            except ValueError:
                pass  # target isn't a JSON echo service; anonymity unknown
            return result
        result["error"] = f"HTTP {r.status_code}"
    return result


def real_ip(url, timeout):
    try:
        return requests.get(url, timeout=timeout).json().get("origin", "").split(",")[0].strip() or None
    except (requests.RequestException, ValueError):
        return None


def render(results, fmt):
    if fmt == "json":
        return json.dumps(results, indent=2)
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.DictWriter(buf, FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(results)
        return buf.getvalue().rstrip("\n")
    rows = [FIELDS] + [tuple("" if r[f] is None else str(r[f]) for f in FIELDS) for r in results]
    widths = [max(len(row[i]) for row in rows) for i in range(len(FIELDS))]
    return "\n".join("  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip() for row in rows)


def main(argv=None):
    p = argparse.ArgumentParser(prog="proxsieve", description="Check http/https/socks4/socks5 proxies concurrently.")
    p.add_argument("file", nargs="?", default="-", help="proxy list file, one per line ('-' or omitted = stdin)")
    p.add_argument("--url", default="https://httpbin.org/get", help="URL to probe (default: %(default)s)")
    p.add_argument("--scheme", choices=SCHEMES, default="http", help="scheme for bare host:port lines")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--retries", type=int, default=1)
    p.add_argument("--workers", type=int, default=50)
    p.add_argument("--max-latency", type=int, metavar="MS", help="treat slower proxies as dead")
    p.add_argument("--format", choices=("table", "json", "csv"), default="table")
    p.add_argument("--live-out", metavar="FILE", help="write live proxies to FILE")
    a = p.parse_args(argv)
    if a.timeout <= 0 or a.retries < 0 or a.workers < 1:
        p.error("--timeout and --workers must be positive, --retries non-negative")

    try:
        src = sys.stdin if a.file == "-" else open(a.file, encoding="utf-8")
        with src:
            proxies = list(dict.fromkeys(filter(None, (parse_proxy(l, a.scheme) for l in src))))
    except (OSError, ValueError) as e:
        p.error(str(e))
    if not proxies:
        p.error("no proxies given")

    me = real_ip(a.url, a.timeout)
    with ThreadPoolExecutor(a.workers) as pool:
        results = list(pool.map(lambda x: check(x, a.url, a.timeout, a.retries, me), proxies))
    if a.max_latency is not None:
        for r in results:
            if r["live"] and r["latency_ms"] > a.max_latency:
                r.update(live=False, error=f"latency > {a.max_latency}ms")

    print(render(results, a.format))
    live = [r["proxy"] for r in results if r["live"]]
    if a.live_out:
        with open(a.live_out, "w", encoding="utf-8") as f:
            f.write("".join(x + "\n" for x in live))
    return 0 if live else 1
