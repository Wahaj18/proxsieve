# proxsieve

proxsieve checks lists of HTTP, HTTPS, SOCKS4 and SOCKS5 proxies in parallel. For each proxy it records whether a request through it succeeds, the round-trip time of that request, the HTTP status or failure class, and how much of the client's identity the proxy exposes to the destination server.

Public proxy lists are noisy. A large share of entries are dead, slow, or forward the client's address to the destination. proxsieve answers three questions about each entry using one request to an endpoint you choose:

1. Does the proxy forward a request and return a successful response within a time limit?
2. How long does that request take, end to end?
3. Can the destination see the client's address, or see that a proxy was used?

## Method

### Baseline probe

Before testing any proxy, proxsieve sends one direct request, without a proxy, to the probe URL (`--url`, default `https://httpbin.org/get`). The endpoint must return JSON with an `origin` field that holds the address it observed. proxsieve takes the first comma-separated value of `origin` as the client's public address. If this request fails or the response is not JSON, the baseline is empty and proxsieve cannot detect transparent proxies in that run.

### Anonymity classification

For every proxy that returns a successful response, proxsieve parses the JSON body. It expects the `origin` field and a `headers` object holding the request headers the endpoint received. It then assigns one of three classes, checked in this order:

| Class | Condition |
|---|---|
| `transparent` | The baseline address appears in `origin` or in any received header value. |
| `anonymous` | The baseline address is absent, but at least one header that proxies commonly add is present: `Via`, `X-Forwarded-For`, `Forwarded` (RFC 7239), `X-Real-IP`, `X-Proxy-ID`, `Proxy-Connection`, `Client-IP`. |
| `elite` | Neither the baseline address nor any of those headers is present. |

The address check is a substring match over `origin` and all header values, so it also catches proxies that put the client address in a non-standard header. If the response body is not JSON, the anonymity field is left empty and the proxy is still reported as live.

### Latency

proxsieve reads a monotonic clock immediately before the request and again when the response headers and body have arrived. The difference, in milliseconds, is reported as `latency_ms`. It covers connection setup to the proxy, the proxy's connection to the endpoint (including TLS for an `https` probe URL), and the endpoint's processing time. Only the successful attempt is timed. With `--max-latency MS`, any live proxy slower than `MS` is reclassified as dead, with the reason `latency > MSms`.

### Retries

A request that raises a connection, timeout or protocol error, or returns an HTTP status of 400 or higher, counts as a failed attempt. proxsieve makes up to `--retries` additional attempts per proxy. Before attempt *n* (counting from 1 for the first retry) it waits 0.5 x 2^(n-1) seconds: 0.5 s, 1 s, 2 s, and so on. The result records the last error, which is the exception class name or `HTTP <status>`.

### Concurrency

Checks run in a thread pool of `--workers` threads (default 50). Each thread performs one blocking request at a time, so at most `--workers` proxy connections are open at once. Input lines are normalized and deduplicated before scheduling, and results are printed in input order.

### SOCKS5 DNS

`socks5://` entries are rewritten to `socks5h://`, so the proxy resolves the probe hostname instead of the local machine. This prevents a DNS lookup for the probe host from leaving the client's own network. SOCKS4 has no remote name resolution in this mode, so a `socks4://` check resolves the hostname locally.

### Request headers

Each request carries a User-Agent string chosen at random from a short list of current desktop browsers. Some proxies reject requests with library default User-Agents. No other identifying headers are added.

## Limitations and threat model

- Classification depends on the probe endpoint. It must echo the observed source address and the received headers as JSON, in the format httpbin's `/get` uses. With any other URL, proxsieve still measures liveness and latency, but the anonymity field stays empty.
- The result holds for one endpoint, one path and one moment. A proxy can treat other hosts differently, add headers only to plain HTTP requests, or change behavior over time. An `https` probe URL hides request headers from HTTP proxies that tunnel with CONNECT, so `elite` against an HTTPS endpoint does not mean the same proxy adds no headers to plain HTTP traffic.
- proxsieve trusts the endpoint. A malicious or misconfigured endpoint can return any `origin` and `headers` it likes. Run your own echo service if the results matter.
- The baseline assumes one stable public address. Behind NAT pools, multiple uplinks or a VPN that changes routes during the run, the baseline may not match the address the proxy receives traffic from, and transparent proxies can be misclassified as `anonymous` or `elite`.
- The header list is fixed. A proxy that reveals itself through a header not on the list, or through TLS or TCP fingerprints, is classified as `elite`.
- Latency includes the endpoint and the path from proxy to endpoint, not only the proxy. Compare numbers only within the same run and the same probe URL.
- proxsieve does not inspect or verify TLS through the proxy beyond what `requests` does by default, and it does not test for content injection.
- Every check sends traffic to third-party proxies. Test only proxies you are allowed to use.

## Install

Python 3.9 or newer is required.

```sh
git clone https://github.com/Wahaj18/proxsieve
cd proxsieve
pip install .
```

The only runtime dependency is `requests[socks]`, which pulls in PySocks.

## Usage

The input file holds one proxy per line, either `host:port` or `scheme://[user:pass@]host:port`, where the scheme is `http`, `https`, `socks4` or `socks5`. Blank lines and lines starting with `#` are skipped. Bare `host:port` lines use the scheme given by `--scheme` (default `http`). Pass `-` or omit the file to read from standard input.

```sh
proxsieve proxies.txt
cat proxies.txt | proxsieve --format json
proxsieve proxies.txt --scheme socks5 --timeout 5 --retries 2 --workers 200
proxsieve proxies.txt --max-latency 1500 --live-out live.txt --format csv
proxsieve proxies.txt --url http://127.0.0.1:8080/get
```

| Option | Default | Meaning |
|---|---|---|
| `--url URL` | `https://httpbin.org/get` | Probe endpoint, also used for the baseline request |
| `--scheme` | `http` | Scheme for bare `host:port` lines |
| `--timeout SEC` | `10` | Per-request timeout in seconds |
| `--retries N` | `1` | Additional attempts after a failure |
| `--workers N` | `50` | Size of the thread pool |
| `--max-latency MS` | none | Mark live proxies slower than `MS` as dead |
| `--format` | `table` | `table`, `json` or `csv` |
| `--live-out FILE` | none | Write live proxies to `FILE`, one per line |

Example output. The addresses below come from the documentation ranges in RFC 5737.

```text
$ proxsieve proxies.txt
proxy                        live   status  latency_ms  anonymity    error
http://198.51.100.7:8080     True   200     412         elite
http://198.51.100.23:3128    True   200     287         anonymous
http://203.0.113.40:80       True   200     951         transparent
socks5://203.0.113.91:1080   True   200     633         elite
socks4://192.0.2.15:4145     False                                   ConnectTimeout
http://192.0.2.200:8000      False  403                              HTTP 403
```

## Output formats

All three formats contain the same fields for each proxy:

| Field | Type | Meaning |
|---|---|---|
| `proxy` | string | Normalized proxy URL |
| `live` | boolean | A successful response arrived within the timeout and latency limit |
| `status` | integer or null | HTTP status of the last response |
| `latency_ms` | integer or null | Duration of the last request that returned a response |
| `anonymity` | string or null | `transparent`, `anonymous`, `elite`, or empty if unknown |
| `error` | string or null | Exception class name, `HTTP <status>`, or `latency > <MS>ms` |

`table` is an aligned text table for reading in a terminal. `json` is an array of objects. `csv` has a header row followed by one row per proxy, with empty cells for null values.

```json
[
  {
    "proxy": "http://198.51.100.23:3128",
    "live": true,
    "status": 200,
    "latency_ms": 287,
    "anonymity": "anonymous",
    "error": null
  }
]
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | At least one proxy is live |
| 1 | No proxy is live |
| 2 | Usage error, an unreadable input file, an invalid proxy line, or an empty list |

## Development

```sh
pip install -e '.[test]'
pytest
```

The tests replace `requests.get` with a stub, so they make no network requests.

## License

MIT. See [LICENSE](LICENSE).

## Citation

```bibtex
@software{proxsieve,
  author = {Wahaj18},
  title  = {proxsieve: concurrent proxy reachability, latency and anonymity measurement},
  year   = {2026},
  version = {0.1.0},
  url    = {https://github.com/Wahaj18/proxsieve},
  license = {MIT}
}
```
