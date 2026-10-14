import json
from unittest import mock

import pytest
import requests

from proxsieve import cli

REAL = "1.2.3.4"


def resp(status=200, data=None):
    r = mock.Mock(status_code=status, ok=status < 400)
    r.json.return_value = data or {}
    return r


def fake_get(url, proxies=None, **kw):
    if proxies is None:
        return resp(data={"origin": REAL})
    p = proxies["https"]
    if "dead" in p:
        raise requests.ConnectTimeout()
    if "trans" in p:
        return resp(data={"origin": f"{REAL}, 9.9.9.9", "headers": {"X-Forwarded-For": REAL}})
    if "anon" in p:
        return resp(data={"origin": "9.9.9.9", "headers": {"Via": "1.1 squid"}})
    return resp(data={"origin": "9.9.9.9", "headers": {"User-Agent": kw["headers"]["User-Agent"]}})


@pytest.mark.parametrize("line,want", [
    ("1.1.1.1:80", "http://1.1.1.1:80"),
    ("SOCKS5://u:p@h:1080", "socks5://u:p@h:1080"),
    ("  # comment", None),
    ("", None),
])
def test_parse(line, want):
    assert cli.parse_proxy(line) == want


@pytest.mark.parametrize("bad", ["ftp://h:1", "nohost", "h:port"])
def test_parse_invalid(bad):
    with pytest.raises(ValueError):
        cli.parse_proxy(bad)


def test_anonymity_levels():
    assert cli.anonymity({"origin": REAL}, REAL) == "transparent"
    assert cli.anonymity({"origin": "9.9.9.9", "headers": {"Forwarded": "x"}}, REAL) == "anonymous"
    assert cli.anonymity({"origin": "9.9.9.9", "headers": {}}, REAL) == "elite"


@pytest.fixture
def net():
    with mock.patch.object(cli.requests, "get", side_effect=fake_get) as g, mock.patch.object(cli.time, "sleep"):
        yield g


def test_end_to_end_json(tmp_path, net, capsys):
    f = tmp_path / "p.txt"
    f.write_text("trans:1\nanon:2\nelite:3\nsocks5://dead:4\n")
    out = tmp_path / "live.txt"
    assert cli.main([str(f), "--format", "json", "--live-out", str(out), "--retries", "2"]) == 0
    res = {r["proxy"]: r for r in json.loads(capsys.readouterr().out)}
    assert res["http://trans:1"]["anonymity"] == "transparent"
    assert res["http://anon:2"]["anonymity"] == "anonymous"
    assert res["http://elite:3"]["anonymity"] == "elite"
    dead = res["socks5://dead:4"]
    assert not dead["live"] and dead["error"] == "ConnectTimeout"
    assert out.read_text().splitlines() == ["http://trans:1", "http://anon:2", "http://elite:3"]
    # socks5 upgraded to socks5h; 3 attempts for the dead proxy
    dead_calls = [c for c in net.call_args_list if c.kwargs.get("proxies") and "dead" in c.kwargs["proxies"]["https"]]
    assert len(dead_calls) == 3 and dead_calls[0].kwargs["proxies"]["https"].startswith("socks5h://")


def test_none_live_and_max_latency(tmp_path, net, capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO("dead:1\n"))
    assert cli.main(["--format", "csv", "--retries", "0"]) == 1
    assert capsys.readouterr().out.startswith("proxy,live,status")
    f = tmp_path / "p.txt"
    f.write_text("elite:3\n")
    assert cli.main([str(f), "--max-latency", "-1"]) == 1
    assert "latency >" in capsys.readouterr().out


def test_http_error_status(tmp_path, capsys):
    f = tmp_path / "p.txt"
    f.write_text("h:1\n")
    with mock.patch.object(cli.requests, "get", return_value=resp(403)):
        assert cli.main([str(f), "--retries", "0"]) == 1
    assert "HTTP 403" in capsys.readouterr().out


@pytest.mark.parametrize("args", [["/nonexistent"], ["--timeout", "0"], ["--format", "xml"]])
def test_usage_errors(args):
    with pytest.raises(SystemExit) as e:
        cli.main(args)
    assert e.value.code == 2


def test_bad_line_is_usage_error(tmp_path):
    f = tmp_path / "p.txt"
    f.write_text("ftp://h:1\n")
    with pytest.raises(SystemExit) as e:
        cli.main([str(f)])
    assert e.value.code == 2
