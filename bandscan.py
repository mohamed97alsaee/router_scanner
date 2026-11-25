#!/usr/bin/env python3
"""
bandscan — find the best LTE band combination for a Huawei HiLink router
(built for the B715s-23c on Al Madar, works on most HiLink 4G routers).

It tries each candidate band lock, waits for the router to re-attach,
samples signal quality (RSRP / RSRQ / SINR / cell / 4G+), optionally runs a
real speed test, ranks the results and applies the winner.

Pure Python 3 standard library — no pip install needed.

Commands
  status                 show current mode, bands, antenna, cell and signal
  watch                  live signal meter (use while aiming the antenna)
  scan                   test band combinations and pick the best
  apply  --bands 1+3     lock to bands (e.g. 1, 3, 1+3)
  reset                  unlock all supported bands
  antenna {auto,external,internal,mix}

The password is never stored: pass it via the ROUTER_PASSWORD env var or
type it at the prompt. Run `python3 bandscan.py -h` for all options.
"""
from __future__ import annotations

import argparse
import base64
import csv
import getpass
import hashlib
import itertools
import json
import os
import re
import signal as _signal
import socket
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------- constants

# LTE band -> bit in the LTEBand hex mask (band N = bit N-1)
SUPPORTED_BANDS = [1, 3, 7, 8, 20, 28, 32, 38]  # B715s-23c
ALL_BANDS_MASK = "20880800C5"                   # all of the above

# Bands that must never be locked on their own at this site (see notes):
# B7 has no service, B8/B20 are weak. They may still appear inside combos.
NEVER_ALONE = {7, 8, 20}

DEFAULT_CANDIDATES = ["1", "3", "1+3", "1+3+20", "1+3+8", "3+20", "all"]
EXPLORE_CANDIDATES = ["28", "38", "1+3+28", "1+3+38"]

ANTENNA = {"auto": "0", "external": "1", "internal": "2", "mix": "3"}
ANTENNA_NAME = {v: k for k, v in ANTENNA.items()}

NET_TYPE_EX = {"1011": "4G+ (CA)", "101": "4G", "1021": "4G+", "111": "5G NSA",
               "41": "3G", "46": "3G DC-HSPA+", "45": "HSPA+", "0": "no service"}
CONN_STATUS = {"901": "connected", "902": "disconnected", "900": "connecting",
               "903": "disconnecting"}

ERRORS = {
    "100002": "not supported by this firmware",
    "100003": "session expired / not logged in",
    "108001": "wrong username",
    "108002": "wrong password",
    "108003": "user already logged in",
    "108006": "wrong username or password",
    "108007": "too many login attempts, wait a few minutes",
    "125002": "CSRF token invalid",
    "125003": "CSRF token expired",
}


def bands_to_mask(bands: list[int]) -> str:
    m = 0
    for b in bands:
        m |= 1 << (b - 1)
    return format(m, "X")


def mask_to_bands(mask: str) -> list[int]:
    try:
        m = int(mask, 16)
    except (TypeError, ValueError):
        return []
    return [i + 1 for i in range(64) if m >> i & 1]


def parse_bands(spec: str) -> tuple[str, str]:
    """'1+3' -> ('B1+B3', '5'); 'all' -> ('all', ALL_BANDS_MASK)."""
    spec = spec.strip().lower()
    if spec == "all":
        return "all", ALL_BANDS_MASK
    bands = sorted({int(x) for x in spec.replace(",", "+").split("+") if x})
    bad = [b for b in bands if b not in SUPPORTED_BANDS]
    if bad:
        raise ValueError(f"band(s) {bad} not supported (supported: {SUPPORTED_BANDS})")
    return "+".join(f"B{b}" for b in bands), bands_to_mask(bands)


def num(v, default=None):
    """'-95dBm' -> -95.0, '>=-44dBm' -> -44.0, '' -> default."""
    if v is None:
        return default
    s = "".join(ch for ch in str(v) if ch in "-.0123456789")
    try:
        return float(s)
    except ValueError:
        return default


# ------------------------------------------------------------------ client

class RouterError(Exception):
    def __init__(self, code: str, path: str):
        self.code = code
        super().__init__(f"{path}: error {code} ({ERRORS.get(code, 'unknown')})")


class HiLink:
    # how to obtain a CSRF token for writes, tried in this order (first that works is remembered)
    STRATEGIES = ["header", "page", "page2", "sestok", "sestok_cookie"]  # sestok_cookie may drop the login: last

    def __init__(self, host: str, username: str = "admin", password: str | None = None,
                 timeout: float = 8):
        self.base = host if host.startswith("http") else f"http://{host}"
        self.base = self.base.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self.session_id: str | None = None   # SessionID cookie, managed by hand
        self.tokens: list[str] = []          # tokens the router handed out in headers
        self.logged_in = False
        self.strategy: str | None = None     # token strategy that last worked
        self.trace: list[str] | None = None  # set to a list to record a debug log
        self.lock = threading.RLock()        # one request/token exchange at a time

    # -- debug log (tokens shortened, password never logged)
    @staticmethod
    def _short(v):
        return f"{v[:6]}…({len(v)})" if v and len(v) > 10 else v

    def _redact(self, text):
        t = re.sub(r"<(TokInfo|SesInfo)>([^<]*)", lambda m: f"<{m.group(1)}>{self._short(m.group(2))}", text.strip())
        return t.replace("<?xml version='1.0' encoding='UTF-8'?>", "").replace('<?xml version="1.0" encoding="UTF-8"?>', "")[-160:]

    def _log(self, msg):
        if self.trace is not None:
            self.trace.append(msg)

    # -- raw http
    def _req(self, path: str, data: str | None = None, token: str | None = None):
        headers = {"X-Requested-With": "XMLHttpRequest",
                   "Referer": self.base + "/html/home.html"}
        body = None
        if data is not None:
            body = data.encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
        if token:
            headers["__RequestVerificationToken"] = token
        if self.session_id:
            headers["Cookie"] = f"SessionID={self.session_id}"
        req = urllib.request.Request(self.base + path, data=body, headers=headers)
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            text = r.read().decode("utf-8", "replace")
            h = r.headers
        for c in h.get_all("Set-Cookie") or []:
            m = re.search(r"SessionID=([^;,\s]+)", c)
            if m:
                self.session_id = m.group(1)
        self._collect_tokens(h)
        if self.trace is not None and (data is not None or path.endswith("SesTokInfo")):
            tok_hdrs = {k: self._short(v) for k, v in h.items() if "token" in k.lower()}
            self._log(f"{'POST' if data is not None else 'GET '} {path}  sent_token={self._short(token)} "
                      f"cookie={self._short(self.session_id)}  set-cookie={bool(h.get_all('Set-Cookie'))} "
                      f"token_headers={tok_hdrs}  -> {self._redact(text)}")
        return text, h

    def _collect_tokens(self, h):
        """The router hands out the next valid CSRF token(s) in response headers."""
        one, two = h.get("__RequestVerificationTokenone"), h.get("__RequestVerificationTokentwo")
        if one:
            self.tokens = [t for t in (one, two) if t]
        elif h.get("__RequestVerificationToken"):
            self.tokens = ([t for t in h["__RequestVerificationToken"].split("#") if t] + self.tokens)[:4]

    @staticmethod
    def _parse(text: str, path: str) -> dict | str:
        root = ET.fromstring(text.strip())
        if root.tag == "error":
            raise RouterError(root.findtext("code", "?"), path)
        if len(root) == 0:
            return (root.text or "").strip()  # e.g. <response>OK</response>
        return {c.tag: (c.text or "").strip() for c in root}

    def _sestok(self, adopt_cookie: bool | None = None) -> str | None:
        text, _ = self._req("/api/webserver/SesTokInfo")
        root = ET.fromstring(text)
        ses = root.findtext("SesInfo") or ""
        if adopt_cookie is None:
            adopt_cookie = not self.logged_in
        if adopt_cookie and ses:
            self.session_id = ses[len("SessionID="):] if ses.startswith("SessionID=") else ses
        return root.findtext("TokInfo")

    def _page_tokens(self) -> list[str]:
        """Tokens embedded in the web UI as <meta name="csrf_token" content="…">."""
        try:
            text, _ = self._req("/html/home.html")
        except OSError:
            return []
        return (re.findall(r'name="csrf_token"\s+content="([^"]+)"', text)
                or re.findall(r'content="([^"]+)"\s+name="csrf_token"', text))

    def _token_for(self, strategy: str) -> str | None:
        try:
            if strategy == "header":
                return self.tokens.pop(0) if self.tokens else None
            if strategy == "sestok":
                return self._sestok(adopt_cookie=False)
            if strategy == "sestok_cookie":
                return self._sestok(adopt_cookie=True)
            if strategy in ("page", "page2"):
                p = self._page_tokens()
                return (p[0] if strategy == "page" else p[-1]) if p else None
        except (RouterError, ET.ParseError, OSError):
            return None
        return None

    # -- api helpers with auto re-login on 100003
    def _ensure_session(self):
        """The router answers 125002 to any request without a session cookie."""
        if not self.session_id:
            self._sestok(adopt_cookie=True)

    def _get_unlocked(self, path: str):
        self._ensure_session()
        try:
            return self._parse(self._req(path)[0], path)
        except RouterError as e:
            if e.code in ("125002", "125003") and not self.logged_in:
                self.session_id = None          # stale anonymous session: get a new one
                self._ensure_session()
                return self._parse(self._req(path)[0], path)
            if e.code == "100003" and self.password:
                self.login()
                return self._parse(self._req(path)[0], path)
            raise

    def _post_unlocked(self, path: str, inner_xml: str):
        self._ensure_session()
        body = f'<?xml version="1.0" encoding="UTF-8"?><request>{inner_xml}</request>'
        order = ([self.strategy] if self.strategy else []) + \
                [s for s in self.STRATEGIES if s != self.strategy]
        relogged = False
        last: RouterError | None = None
        while True:
            for strat in order:
                tok = self._token_for(strat)
                if tok is None:
                    continue
                try:
                    res = self._parse(self._req(path, body, tok)[0], path)
                except RouterError as e:
                    self._log(f"  strategy {strat}: {e}")
                    last = e
                    if e.code in ("125002", "125003"):
                        continue
                    if e.code == "100003":
                        break
                    raise
                if res != "OK":
                    raise RouterError(f"unexpected:{res}", path)
                self.strategy = strat
                self._log(f"  strategy {strat}: OK")
                return res
            needs_login = last is not None and (
                last.code == "100003" or (last.code in ("125002", "125003") and not self.logged_in))
            if needs_login and not relogged:
                if not self.password:
                    raise RouterError("100003", path) from last
                self.login()
                relogged = True
                continue
            if needs_login is False and not relogged and self.password:
                # logged in but every token was refused: the session may be stale
                self.login()
                relogged = True
                continue
            raise last or RouterError("125002", path)

    def get(self, path: str):
        with self.lock:
            return self._get_unlocked(path)

    def post(self, path: str, inner_xml: str):
        with self.lock:
            return self._post_unlocked(path, inner_xml)

    def login(self):
        with self.lock:
            return self._login_unlocked()

    # -- login
    def _login_unlocked(self):
        if not self.password:
            raise RouterError("100003", "/api/user/login")
        self.session_id = None
        self.tokens = []
        self.logged_in = False
        state = self._parse(self._req("/api/user/state-login")[0], "state-login")
        ptype = state.get("password_type", "4") if isinstance(state, dict) else "4"
        sources = [("sestok", lambda: self._sestok(adopt_cookie=True)),
                   ("page", lambda: (self._page_tokens() or [None])[0]),
                   ("page2", lambda: (self._page_tokens() or [None])[-1])]
        last = None
        for name, get_tok in sources:
            try:
                token = get_tok()
            except (RouterError, ET.ParseError, OSError):
                token = None
            if not token:
                continue
            if ptype == "4":
                h = base64.b64encode(hashlib.sha256(self.password.encode()).hexdigest().encode()).decode()
                pw = base64.b64encode(hashlib.sha256(
                    (self.username + h + token).encode()).hexdigest().encode()).decode()
            else:
                pw = base64.b64encode(self.password.encode()).decode()
            body = ('<?xml version="1.0" encoding="UTF-8"?><request>'
                    f"<Username>{self.username}</Username><Password>{pw}</Password>"
                    f"<password_type>{ptype}</password_type></request>")
            self._log(f"login: password_type={ptype} token_from={name}")
            try:
                text, _ = self._req("/api/user/login", body, token)
                self._parse(text, "/api/user/login")
                break
            except RouterError as e:
                last = e
                if e.code not in ("125002", "125003"):
                    raise
        else:
            raise last or RouterError("125002", "/api/user/login")
        self.logged_in = True
        try:  # confirm the router agrees we are logged in (State 0 = logged in)
            st = self.get("/api/user/state-login")
            self._log(f"after login: state-login State={st.get('State') if isinstance(st, dict) else st}")
        except RouterError:
            pass

    def ensure_login(self):
        """Log in if a password is available or the router demands it."""
        if self.password:
            self.login()
            return
        try:
            self._sestok()
            self._parse(self._req("/api/device/signal")[0], "/api/device/signal")
        except RouterError as e:
            if e.code != "100003":
                raise
            self.password = os.environ.get("ROUTER_PASSWORD") or getpass.getpass(
                f"Router password for {self.username}@{self.base}: ")
            self.login()

    # -- high level
    def net_mode(self) -> dict:
        return self.get("/api/net/net-mode")

    def set_bands(self, lte_mask: str, network_mode: str = "03", network_band: str | None = None):
        if network_band is None:
            network_band = self.net_mode().get("NetworkBand", "3FFFFFFF")
        self.post("/api/net/net-mode",
                  f"<NetworkMode>{network_mode}</NetworkMode>"
                  f"<NetworkBand>{network_band}</NetworkBand>"
                  f"<LTEBand>{lte_mask}</LTEBand>")

    def antenna(self) -> str | None:
        try:
            r = self.get("/api/device/antenna_set_type")
            return r.get("antennasettype") if isinstance(r, dict) else None
        except RouterError:
            return None

    def set_antenna(self, value: str):
        self.post("/api/device/antenna_set_type", f"<antennasettype>{value}</antennasettype>")

    def signal(self) -> dict:
        return self.get("/api/device/signal")

    def status(self) -> dict:
        return self.get("/api/monitoring/status")


# ------------------------------------------------------------ measurements

def snapshot(r: HiLink) -> dict:
    s, st = r.signal(), r.status()
    return {
        "rsrp": num(s.get("rsrp")), "rsrq": num(s.get("rsrq")),
        "sinr": num(s.get("sinr")), "rssi": num(s.get("rssi")),
        "rscp": num(s.get("rscp")), "ecio": num(s.get("ecio")),  # 3G
        "band": s.get("band"), "cell_id": s.get("cell_id"), "pci": s.get("pci") or s.get("sc"),
        "earfcn": s.get("earfcn"), "dlbandwidth": s.get("dlbandwidth"),
        "conn": st.get("ConnectionStatus"), "net": st.get("CurrentNetworkTypeEx")
                or st.get("CurrentNetworkType"),
        "bars": st.get("SignalIcon"),
    }


def has_signal(s: dict) -> bool:
    return s.get("rsrp") is not None or s.get("rscp") is not None


def is_3g(res: dict) -> bool:
    return res.get("rsrp") is None and res.get("rscp") is not None


def wait_connected(r: HiLink, timeout: float, min_wait: float, stop=lambda: False) -> bool:
    end = time.time() + min_wait
    while time.time() < end:
        if stop():
            return False
        time.sleep(0.5)
    end = time.time() + max(0, timeout - min_wait)
    while not stop():
        try:
            if r.status().get("ConnectionStatus") == "901" and has_signal(snapshot(r)):
                return True
        except (RouterError, OSError):
            pass
        if time.time() > end:
            return False
        time.sleep(2)
    return False


def speed_test(url: str, max_bytes: int, max_secs: float) -> float | None:
    """Download throughput in Mbit/s (None on failure)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "bandscan/2.0"})
        t0 = time.time()
        got = 0
        with urllib.request.urlopen(req, timeout=15) as resp:
            while got < max_bytes and time.time() - t0 < max_secs:
                chunk = resp.read(65536)
                if not chunk:
                    break
                got += len(chunk)
        dt = time.time() - t0
        return round(got * 8 / dt / 1e6, 2) if dt > 0 and got > 0 else None
    except (OSError, urllib.error.URLError):
        return None


def latency_stats(host="1.1.1.1", port=443, n=10) -> dict:
    """TCP-connect latency: median, jitter (mean change between tries) and loss %."""
    times = []
    for _ in range(n):
        try:
            t0 = time.time()
            with socket.create_connection((host, port), timeout=2):
                times.append((time.time() - t0) * 1000)
        except OSError:
            pass
        time.sleep(0.1)
    if not times:
        return {"latency_ms": None, "jitter_ms": None, "loss_pct": 100.0}
    jit = statistics.mean(abs(a - b) for a, b in zip(times, times[1:])) if len(times) > 1 else 0.0
    return {"latency_ms": round(statistics.median(times), 1), "jitter_ms": round(jit, 1),
            "loss_pct": round(100 * (n - len(times)) / n, 1)}


def latency_ms(host="1.1.1.1", port=443, n=5) -> float | None:  # kept for compatibility
    return latency_stats(host, port, n)["latency_ms"]


def radio_score(res: dict) -> float:
    if is_3g(res):
        ecio = res.get("ecio") if res.get("ecio") is not None else -20
        rscp = res.get("rscp") if res.get("rscp") is not None else -115
        return (ecio + 20) * 2 + (rscp + 115) * 0.4 - 10   # 3G is capped well below LTE
    sinr = res.get("sinr") if res.get("sinr") is not None else -5
    rsrq = res.get("rsrq") if res.get("rsrq") is not None else -20
    rsrp = res.get("rsrp") if res.get("rsrp") is not None else -125
    radio = sinr * 2 + (rsrq + 20) * 1.5 + (rsrp + 125) * 0.4
    if res.get("net") in ("1011", "1021"):
        radio += 8  # carrier aggregation bonus
    return radio


def score(res: dict) -> float:
    """Higher is better: speed first (when measured), then signal quality, then stability."""
    if not res.get("connected"):
        return -1e9
    s = radio_score(res)
    s -= 2 * (res.get("sinr_sd") or 0)                # SINR jumping around = unstable
    if res.get("loss_pct") is not None:
        s -= res["loss_pct"] * 1.5 + min(res.get("jitter_ms") or 0, 100) * 0.1
        s -= (res.get("latency_ms") or 150) / 25
    if res.get("down_mbps") is not None:
        s += res["down_mbps"] * 8
    return s


def measure(r: HiLink, samples: int, interval: float, stop=lambda: False) -> dict:
    snaps = []
    for _ in range(samples):
        if stop():
            break
        try:
            snaps.append(snapshot(r))
        except (RouterError, OSError):
            pass
        time.sleep(interval)
    if not snaps:
        return {}
    out = dict(snaps[-1])
    for k in ("rsrp", "rsrq", "sinr", "rssi", "rscp", "ecio"):
        vals = [s[k] for s in snaps if s[k] is not None]
        out[k] = round(statistics.median(vals), 1) if vals else None
    sinrs = [s["sinr"] for s in snaps if s["sinr"] is not None]
    out["sinr_min"] = min(sinrs, default=None)
    out["sinr_sd"] = round(statistics.pstdev(sinrs), 2) if len(sinrs) > 1 else 0.0
    out["cells_seen"] = sorted({s["cell_id"] for s in snaps if s["cell_id"]})
    out["samples"] = len(snaps)
    return out


# ------------------------------------------------------------- scan engine

def parse_spec(spec: str) -> dict:
    """A test configuration: LTE band lock, '3G' (WCDMA / H+ only) or 'auto' (4G/3G auto)."""
    s = str(spec).strip().lower()
    if s in ("3g", "h+", "wcdma", "umts"):
        return {"spec": "3g", "label": "3G / H+", "mode": "02", "mask": None}
    if s == "auto":
        return {"spec": "auto", "label": "Auto 4G/3G", "mode": "00", "mask": ALL_BANDS_MASK}
    label, mask = parse_bands(s)
    return {"spec": s, "label": label, "mode": "03", "mask": mask}


def config_key(mode, mask, antenna) -> str:
    return f"{mode or '03'}|{(mask or '-').upper()}|{antenna or '-'}"


def is_bad_alone(mask: str | None, mode: str) -> bool:
    b = mask_to_bands(mask or "")
    return mode == "03" and len(b) == 1 and b[0] in NEVER_ALONE


def rank(results: list[dict]) -> list[dict]:
    ok = [x for x in results if x.get("connected")]
    return sorted(ok, key=lambda x: (-x["score"], len(mask_to_bands(x.get("mask") or ""))))


TIE_MARGIN = 3.0  # scores closer than this are measurement noise, not a real difference


def pick_best(ranked: list[dict], track: dict[str, float] | None = None) -> dict | None:
    """Best result that may stay applied (never a weak band alone). Results within
    TIE_MARGIN of the top are treated as a tie: prefer the better track record
    from earlier scans, then the simpler band set — so the setting doesn't flip on noise."""
    allowed = [x for x in ranked if not is_bad_alone(x.get("mask"), x.get("mode", "03"))]
    if not allowed:
        return ranked[0] if ranked else None
    top = allowed[0]["score"]
    tied = [x for x in allowed if x["score"] >= top - TIE_MARGIN]
    track = track or {}
    return max(tied, key=lambda x: (track.get(x["key"], -1e9), -len(mask_to_bands(x.get("mask") or "")),
                                    x["score"]))


def load_history(out_dir="results") -> list[dict]:
    """All saved scans, oldest first (also reads the older scan file format)."""
    scans = []
    for f in sorted(Path(out_dir).glob("scan-*.json")):
        try:
            d = json.loads(f.read_text())
        except (OSError, ValueError):
            continue
        for x in d.get("results", []):
            x.setdefault("mode", "03")
            x.setdefault("label", x.get("combo"))
            x["key"] = config_key(x["mode"], x.get("mask"), x.get("antenna"))
        d["file"] = f.name
        scans.append(d)
    return scans


def history_summary(out_dir="results") -> list[dict]:
    """Per-configuration track record across all scans, best first."""
    agg: dict[str, dict] = {}
    for d in load_history(out_dir):
        for x in d.get("results", []):
            a = agg.setdefault(x["key"], {"key": x["key"], "label": x.get("label"), "mode": x["mode"],
                                          "mask": x.get("mask"), "antenna": x.get("antenna"),
                                          "tests": 0, "fails": 0, "scores": [], "mbps": [], "last": None})
            a["tests"] += 1
            a["last"] = d.get("time")
            if x.get("connected"):
                a["scores"].append(round(score(x), 1))  # same formula for old and new scans
                if x.get("down_mbps") is not None:
                    a["mbps"].append(x["down_mbps"])
            else:
                a["fails"] += 1
    out = []
    for a in agg.values():
        recent = a["scores"][-3:]
        a["avg_score"] = round(statistics.mean(recent), 1) if recent else None
        a["best_score"] = max(a["scores"]) if a["scores"] else None
        a["avg_mbps"] = round(statistics.mean(a["mbps"][-3:]), 1) if a["mbps"] else None
        # reliability: a config that sometimes fails to connect is penalised
        a["rating"] = None if a["avg_score"] is None else round(
            a["avg_score"] - 15 * a["fails"] / a["tests"], 1)
        del a["scores"], a["mbps"]
        out.append(a)
    return sorted(out, key=lambda a: -(a["rating"] if a["rating"] is not None else -1e9))


@dataclass
class ScanOptions:
    candidates: list = field(default_factory=lambda: list(DEFAULT_CANDIDATES))
    antennas: list = field(default_factory=list)  # [] = keep the current antenna
    full: bool = False          # find bands with service, then test every combination of them
    include_3g: bool = False    # also test 3G / H+ only and Auto 4G/3G
    recheck_top: int = 3        # re-test the best N configs from earlier scans
    only_recheck: bool = False  # quick mode: only re-test earlier winners
    speedtest: bool = False
    settle: float = 20
    attach_timeout: float = 45  # extra seconds to wait for a connection before "no service"
    samples: int = 6
    interval: float = 2
    apply_best: bool = True
    out_dir: str = "results"
    speed_url: str = "https://speed.cloudflare.com/__down?bytes=50000000"
    speed_bytes: int = 20_000_000
    speed_secs: float = 10


def run_scan(r: HiLink, opt: ScanOptions, log=print, stop=lambda: False, on_result=None) -> dict:
    """Test configurations, rank them, compare with history, apply the best, save everything."""
    lines: list[str] = []

    def say(msg):
        line = f"{datetime.now():%H:%M:%S}  {msg}"
        lines.append(line)
        log(line)

    started = datetime.now()
    orig = r.net_mode()
    orig_ant = r.antenna()
    antennas = [None] if orig_ant is None else (opt.antennas or [ANTENNA_NAME.get(orig_ant)])
    say(f"original: mode={orig.get('NetworkMode')} LTEBand={orig.get('LTEBand')} "
        f"antenna={ANTENNA_NAME.get(orig_ant, orig_ant)}")

    history = history_summary(opt.out_dir)
    prev_best = next((h for h in history if h["rating"] is not None), None)
    if prev_best:
        say(f"previous best on record: {prev_best['label']} [{prev_best['antenna']}] "
            f"rating {prev_best['rating']} over {prev_best['tests']} test(s)")

    results: list[dict] = []
    cur_ant = [orig_ant]
    done_keys: set[str] = set()

    def run_one(cfg: dict, ant, tag=""):
        key = config_key(cfg["mode"], cfg["mask"], ant)
        if key in done_keys or stop():
            return None
        done_keys.add(key)
        if ant and orig_ant is not None and ANTENNA[ant] != cur_ant[0]:
            r.set_antenna(ANTENNA[ant])
            cur_ant[0] = ANTENNA[ant]
            say(f"--- antenna -> {ant} (router reports {ANTENNA_NAME.get(r.antenna(), '?')})")
        name = f"{cfg['label']}" + (f" [{ant}]" if ant else "")
        say(f"[{len(done_keys)}] {tag}{name}")
        res = {"combo": cfg["label"], "label": cfg["label"], "spec": cfg["spec"], "mode": cfg["mode"],
               "mask": cfg["mask"], "antenna": ant, "key": key}
        try:
            r.set_bands(cfg["mask"] or orig.get("LTEBand", ALL_BANDS_MASK), cfg["mode"], orig.get("NetworkBand"))
        except RouterError as e:
            say(f"    set failed: {e}")
            res["error"] = str(e)
            results.append(res)
            if e.code == "100003":
                raise
            return res
        res["connected"] = wait_connected(r, opt.settle + opt.attach_timeout, opt.settle, stop)
        if not res["connected"]:
            say("    no service" if not stop() else "    stopped")
            res["score"] = None
            results.append(res)
            if on_result:
                on_result(res)
            return res
        res.update(measure(r, opt.samples, opt.interval, stop))
        res["antenna_read"] = ANTENNA_NAME.get(r.antenna()) if orig_ant is not None else None
        res.update(latency_stats())
        if opt.speedtest:
            res["down_mbps"] = speed_test(opt.speed_url, opt.speed_bytes, opt.speed_secs)
        res["score"] = round(score(res), 1)
        res["net_name"] = NET_TYPE_EX.get(res.get("net"), res.get("net"))
        sig = (f"RSCP {res.get('rscp')} EcIo {res.get('ecio')}" if is_3g(res) else
               f"B{res.get('band')} cell {res.get('cell_id')} SINR {res.get('sinr')}±{res.get('sinr_sd')} "
               f"RSRP {res.get('rsrp')} RSRQ {res.get('rsrq')}")
        say(f"    {sig} {res['net_name']}  ping {res.get('latency_ms')}ms jitter {res.get('jitter_ms')} "
            f"loss {res.get('loss_pct')}%" + (f"  {res.get('down_mbps')} Mbit/s" if opt.speedtest else "")
            + f"  score {res['score']}")
        results.append(res)
        if on_result:
            on_result(res)
        return res

    interrupted = False
    try:
        # 1. re-test earlier winners first, so today's numbers are comparable
        if opt.recheck_top or opt.only_recheck:
            top = [h for h in history if h["rating"] is not None][:max(opt.recheck_top, 3 if opt.only_recheck else 0)]
            for h in top:
                ant = h["antenna"] if (h["antenna"] in ANTENNA and orig_ant is not None) else None
                cfg = {"spec": h["label"], "label": h["label"], "mode": h["mode"], "mask": h["mask"]}
                run_one(cfg, ant, tag="re-check ")

        if not opt.only_recheck:
            for ant in antennas:
                if stop():
                    break
                plan: list[dict] = []
                if opt.full:
                    # probe each band alone to learn which have service here
                    serving = []
                    for b in SUPPORTED_BANDS:
                        if b == 32:   # B32 is downlink-only, it cannot carry a connection alone
                            continue
                        res = run_one(parse_spec(str(b)), ant, tag="probe ")
                        key = config_key("03", bands_to_mask([b]), ant)
                        got = res or next((x for x in results if x.get("key") == key), None)
                        if got and got.get("connected") and str(got.get("band")) == str(b):
                            serving.append(b)
                    say(f"bands with service [{ant or 'current'}]: {', '.join(f'B{b}' for b in serving) or 'none'}")
                    extra = [b for b in (32,) if serving]
                    pool = serving[:6]
                    for n in range(2, len(pool) + 1):
                        for combo in itertools.combinations(pool, n):
                            plan.append(parse_spec("+".join(map(str, combo))))
                    for combo in ([*pool, *extra],) if extra else ():
                        plan.append(parse_spec("+".join(map(str, combo))))
                    plan.append(parse_spec("all"))
                else:
                    plan = [parse_spec(c) for c in opt.candidates]
                if opt.include_3g:
                    plan += [parse_spec("3g"), parse_spec("auto")]
                for cfg in plan:
                    if stop():
                        break
                    run_one(cfg, ant)
    except KeyboardInterrupt:
        interrupted = True
        say("interrupted")

    stopped = interrupted or stop()
    ranked = rank(results)
    track = {h["key"]: h["rating"] for h in history if h["rating"] is not None}
    best = pick_best(ranked, track)
    if best and ranked and best["key"] != ranked[0]["key"]:
        say(f"top scores within {TIE_MARGIN:g} points are a tie — chose {best['label']} [{best.get('antenna')}] "
            f"({best['score']}) over {ranked[0]['label']} ({ranked[0]['score']}) for its track record / fewer bands")

    say("RANKING (best first):")
    for i, x in enumerate(ranked, 1):
        say(f"  {i:>2}. {x['label']:<16} {x.get('antenna') or '':<9} score {x['score']:>6}  "
            + (f"RSCP {x.get('rscp')}" if is_3g(x) else f"SINR {x.get('sinr')} RSRP {x.get('rsrp')}")
            + (f"  {x.get('down_mbps')} Mbit/s" if x.get("down_mbps") is not None else ""))
    dead = [x["label"] + (f" [{x['antenna']}]" if x.get("antenna") else "") for x in results if not x.get("connected")]
    if dead:
        say("no service: " + ", ".join(dead))

    if prev_best and best:
        today_prev = next((x for x in ranked if x["key"] == prev_best["key"]), None)
        if best["key"] == prev_best["key"]:
            say(f"previous best {prev_best['label']} [{prev_best['antenna']}] is still the best today")
        elif today_prev:
            say(f"new best {best['label']} [{best.get('antenna')}] score {best['score']} beats previous best "
                f"{prev_best['label']} [{prev_best['antenna']}] which scored {today_prev['score']} today")

    applied = None
    if stopped or not best or not opt.apply_best:
        r.set_bands(orig.get("LTEBand", ALL_BANDS_MASK), orig.get("NetworkMode", "03"), orig.get("NetworkBand"))
        if orig_ant is not None and cur_ant[0] != orig_ant:
            r.set_antenna(orig_ant)
        say(f"restored original settings (LTEBand={orig.get('LTEBand')}, antenna={ANTENNA_NAME.get(orig_ant, orig_ant)})")
    else:
        if best.get("antenna") and orig_ant is not None and ANTENNA[best["antenna"]] != cur_ant[0]:
            r.set_antenna(ANTENNA[best["antenna"]])
        r.set_bands(best["mask"] or orig.get("LTEBand", ALL_BANDS_MASK), best["mode"], orig.get("NetworkBand"))
        applied = best["key"]
        say(f"BEST applied: {best['label']} [{best.get('antenna')}] mode={best['mode']} "
            f"LTEBand={best['mask']} score {best['score']}")

    out = Path(opt.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = started.strftime("%Y%m%d-%H%M%S")
    record = {"time": stamp, "router": r.base, "original": orig, "original_antenna": orig_ant,
              "options": asdict(opt), "stopped": stopped, "best": best["key"] if best else None,
              "applied": applied, "ranking": [x["key"] for x in ranked], "results": results, "log": lines}
    path = out / f"scan-{stamp}.json"
    path.write_text(json.dumps(record, indent=2))
    with open(out / f"scan-{stamp}.csv", "w", newline="") as f:
        keys = ["label", "antenna", "mode", "mask", "connected", "score", "down_mbps", "latency_ms",
                "jitter_ms", "loss_pct", "sinr", "sinr_sd", "sinr_min", "rsrp", "rsrq", "rscp", "ecio",
                "band", "cell_id", "pci", "earfcn", "net", "antenna_read"]
        w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        w.writerows(ranked + [x for x in results if not x.get("connected")])
    say(f"saved {path} and .csv")
    record["file"] = path.name
    return record


# ------------------------------------------------------------- formatting

def table(rows: list[dict], cols: list[tuple[str, str]]) -> str:
    def fmt(v):
        if v is None or v == "":
            return "-"
        if isinstance(v, float):
            return f"{v:g}"
        return str(v)
    data = [[fmt(r.get(k)) for k, _ in cols] for r in rows]
    widths = [max(len(h), *(len(d[i]) for d in data)) if data else len(h)
              for i, (_, h) in enumerate(cols)]
    line = "  ".join(h.ljust(w) for (_, h), w in zip(cols, widths))
    sep = "  ".join("-" * w for w in widths)
    body = ["  ".join(c.ljust(w) for c, w in zip(d, widths)) for d in data]
    return "\n".join([line, sep, *body])


def quality(sinr, rsrp):
    if sinr is None or rsrp is None:
        return "?"
    if sinr >= 13 and rsrp >= -90:
        return "excellent"
    if sinr >= 5 and rsrp >= -100:
        return "good"
    if sinr >= 0 and rsrp >= -110:
        return "fair"
    return "poor"


# ---------------------------------------------------------------- commands

def cmd_status(r: HiLink, args):
    nm = r.net_mode()
    ant = r.antenna()
    s = snapshot(r)
    rows = [
        ("Network mode", nm.get("NetworkMode")),
        ("LTE bands", f"{nm.get('LTEBand')}  ({'+'.join(f'B{b}' for b in mask_to_bands(nm.get('LTEBand', '')))})"),
        ("Antenna", f"{ant} ({ANTENNA_NAME.get(ant, '?')})" if ant else "n/a"),
        ("Connection", f"{s['conn']} ({CONN_STATUS.get(s['conn'], '?')})"),
        ("Network type", f"{s['net']} ({NET_TYPE_EX.get(s['net'], '?')})"),
        ("Band / EARFCN", f"B{s['band']} / {s['earfcn']}  {s['dlbandwidth'] or ''}"),
        ("Cell ID / PCI", f"{s['cell_id']} / {s['pci']}"),
        ("RSRP / RSRQ / SINR", f"{s['rsrp']} dBm / {s['rsrq']} dB / {s['sinr']} dB"
                               f"  -> {quality(s['sinr'], s['rsrp'])}"),
    ]
    if args.json:
        print(json.dumps({"net_mode": nm, "antenna": ant, **s}, indent=2))
        return
    w = max(len(k) for k, _ in rows)
    for k, v in rows:
        print(f"{k.ljust(w)}  {v}")


def cmd_watch(r: HiLink, args):
    print("Live signal — move/rotate the antenna slowly. Ctrl-C to stop.\n")
    best = None
    try:
        while True:
            s = snapshot(r)
            sinr = s["sinr"] if s["sinr"] is not None else -10
            bar = "#" * max(0, min(40, int((sinr + 10) * 40 / 40)))
            if best is None or sinr > best:
                best = sinr
            print(f"{datetime.now():%H:%M:%S}  B{s['band']:<3} cell {s['cell_id'] or '-':<9} "
                  f"RSRP {s['rsrp']!s:>6}  RSRQ {s['rsrq']!s:>5}  SINR {s['sinr']!s:>5}  "
                  f"{NET_TYPE_EX.get(s['net'], s['net']):<9} |{bar:<40}| best {best}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print()


def cmd_apply(r: HiLink, args):
    if args.mask:
        mask = args.mask.upper().removeprefix("0X")
        label = "+".join(f"B{b}" for b in mask_to_bands(mask)) or "?"
    else:
        label, mask = parse_bands(args.bands)
    r.set_bands(mask, args.mode)
    print(f"Locked to {label} (LTEBand={mask}). Waiting for reconnect…")
    ok = wait_connected(r, 60, args.settle)
    print("connected" if ok else "WARNING: not connected after 60 s")
    cmd_status(r, args)


def cmd_reset(r: HiLink, args):
    r.set_bands(ALL_BANDS_MASK, args.mode)
    print(f"All bands unlocked (LTEBand={ALL_BANDS_MASK}). Waiting for reconnect…")
    wait_connected(r, 60, args.settle)
    cmd_status(r, args)


def cmd_antenna(r: HiLink, args):
    r.set_antenna(ANTENNA[args.type])
    print(f"Antenna set to {args.type} -> now {ANTENNA_NAME.get(r.antenna(), '?')}")


def cmd_scan(r: HiLink, args):
    candidates = args.candidates or DEFAULT_CANDIDATES + (EXPLORE_CANDIDATES if args.explore else [])
    if not args.force:
        keep = []
        for c in candidates:
            cfg = parse_spec(c)
            if is_bad_alone(cfg["mask"], cfg["mode"]):
                print(f"skip {cfg['label']}: on the never-lock-alone list (use --force to test anyway)")
            else:
                keep.append(c)
        candidates = keep
    opt = ScanOptions(candidates=candidates, antennas=args.antennas or ([args.antenna] if args.antenna else []),
                      full=args.full, include_3g=args.include_3g, recheck_top=args.recheck,
                      only_recheck=args.recheck_only, speedtest=args.speedtest, settle=args.settle,
                      samples=args.samples, interval=args.interval, attach_timeout=args.attach_timeout, apply_best=not args.no_apply,
                      out_dir=args.out, speed_url=args.speed_url, speed_bytes=args.speed_bytes,
                      speed_secs=args.speed_secs)
    print("Internet drops for a few seconds on each switch. Ctrl-C stops and restores the original settings.\n")
    run_scan(r, opt)


def cmd_history(r: HiLink | None, args):
    h = history_summary(args.out)
    if not h:
        print("no saved scans yet")
        return
    print(f"Track record from {len(load_history(args.out))} saved scan(s), best first:\n")
    print(table(h[:args.top], [("label", "Config"), ("antenna", "Antenna"), ("mode", "Mode"), ("mask", "LTEBand"),
                               ("tests", "Tests"), ("fails", "Fails"), ("avg_score", "AvgScore"),
                               ("avg_mbps", "Mbit/s"), ("rating", "Rating"), ("last", "Last")]))


def token_debug(r: HiLink) -> dict:
    """Find which CSRF-token method this router accepts. Writes back the CURRENT
    settings unchanged, so nothing on the router actually changes."""
    r.trace = []
    out = {"router": r.base, "results": {}, "works": [], "login": None}
    try:
        info = r.get("/api/device/basic_information")
        out["device"] = {k: info.get(k) for k in ("devicename", "SoftwareVersion", "WebUIVersion")}
        st = r.get("/api/user/state-login")
        out["state_before"] = {k: st.get(k) for k in ("State", "password_type", "extern_password_type", "firstlogin")}
    except (RouterError, OSError) as e:
        r._log(f"info read failed: {e}")
    try:
        r.login()
        out["login"] = "OK"
    except RouterError as e:
        out["login"] = f"FAILED: {e}"
    try:
        st = r.get("/api/user/state-login")
        out["state_after"] = {k: st.get(k) for k in ("State", "username", "userlevel")}
    except (RouterError, OSError):
        pass
    nm = r.get("/api/net/net-mode")
    same = (f"<NetworkMode>{nm.get('NetworkMode')}</NetworkMode><NetworkBand>{nm.get('NetworkBand')}"
            f"</NetworkBand><LTEBand>{nm.get('LTEBand')}</LTEBand>")
    body = f'<?xml version="1.0" encoding="UTF-8"?><request>{same}</request>'
    for strat in HiLink.STRATEGIES:
        r._log(f"--- strategy {strat}")
        tok = r._token_for(strat)
        if not tok:
            out["results"][strat] = "no token available"
            continue
        try:
            res = r._parse(r._req("/api/net/net-mode", body, tok)[0], "/api/net/net-mode")
            out["results"][strat] = "OK" if res == "OK" else f"unexpected {res}"
        except RouterError as e:
            out["results"][strat] = f"error {e.code} ({ERRORS.get(e.code, '?')})"
    out["works"] = [k for k, v in out["results"].items() if v == "OK"]
    if out["works"]:
        r.strategy = out["works"][0]
    out["trace"] = r.trace
    r.trace = None
    return out


def cmd_debug(r: HiLink, args):
    print(f"Router {r.base} — logging in and testing token methods (settings are written back unchanged)…")
    d = token_debug(r)
    print(f"device: {d.get('device')}\nstate before: {d.get('state_before')}\nlogin: {d['login']}"
          f"\nstate after: {d.get('state_after')}\n\nToken method results:")
    for k, v in d["results"].items():
        print(f"  {k:<14} {v}")
    print("\n" + (f"WORKS: {', '.join(d['works'])} — the scanner will use it automatically."
                  if d["works"] else "No method worked — please send the debug log below."))
    outdir = Path(args.out); outdir.mkdir(parents=True, exist_ok=True)
    f = outdir / f"debug-{datetime.now():%Y%m%d-%H%M%S}.txt"
    f.write_text(json.dumps({k: v for k, v in d.items() if k != "trace"}, indent=2) + "\n\n" + "\n".join(d["trace"]))
    print(f"debug log: {f}  (tokens shortened, password not included)\n")
    print("\n".join(d["trace"]))


# -------------------------------------------------------------------- main

def main(argv=None):
    p = argparse.ArgumentParser(description="Huawei HiLink LTE band scanner")
    p.add_argument("--host", default=os.environ.get("ROUTER_HOST", "192.168.8.1"))
    p.add_argument("--user", default=os.environ.get("ROUTER_USER", "admin"))
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("status");  s.add_argument("--json", action="store_true")
    w = sub.add_parser("watch");   w.add_argument("--interval", type=float, default=1.5)

    a = sub.add_parser("apply")
    g = a.add_mutually_exclusive_group(required=True)
    g.add_argument("--bands", help="e.g. 1, 3, 1+3, all")
    g.add_argument("--mask", help="raw LTEBand hex mask, e.g. 5 or 20880800C5")
    a.add_argument("--mode", default="03", help="NetworkMode (03 = LTE only, 00 = auto)")
    a.add_argument("--settle", type=float, default=20)
    a.add_argument("--json", action="store_true")

    rs = sub.add_parser("reset")
    rs.add_argument("--mode", default="03"); rs.add_argument("--settle", type=float, default=20)
    rs.add_argument("--json", action="store_true")

    an = sub.add_parser("antenna"); an.add_argument("type", choices=list(ANTENNA))

    hi = sub.add_parser("history", help="track record of every saved scan")
    hi.add_argument("--out", default="results"); hi.add_argument("--top", type=int, default=20)

    dbg = sub.add_parser("debug", help="find which CSRF token method the router accepts")
    dbg.add_argument("--out", default="results")

    sc = sub.add_parser("scan")
    sc.add_argument("--candidates", nargs="+", help=f"combos to test (default {DEFAULT_CANDIDATES})")
    sc.add_argument("--explore", action="store_true", help=f"also try {EXPLORE_CANDIDATES}")
    sc.add_argument("--force", action="store_true", help="allow locking B7/B8/B20 alone")
    sc.add_argument("--settle", type=float, default=20, help="seconds to wait after each switch")
    sc.add_argument("--samples", type=int, default=6)
    sc.add_argument("--attach-timeout", type=float, default=45,
                    help="extra seconds to wait for a connection before calling it no service")
    sc.add_argument("--interval", type=float, default=2)
    sc.add_argument("--speedtest", action="store_true", help="also measure real download speed")
    sc.add_argument("--speed-url", default="https://speed.cloudflare.com/__down?bytes=50000000")
    sc.add_argument("--speed-bytes", type=int, default=20_000_000)
    sc.add_argument("--speed-secs", type=float, default=10)
    sc.add_argument("--full", action="store_true",
                    help="find bands with service, then test every combination of them")
    sc.add_argument("--include-3g", action="store_true", help="also test 3G/H+ only and Auto 4G/3G")
    sc.add_argument("--recheck", type=int, default=3, help="re-test the best N configs from earlier scans (0=off)")
    sc.add_argument("--recheck-only", action="store_true", help="quick: only re-test earlier winners")
    sc.add_argument("--antenna", choices=list(ANTENNA), help="use one antenna mode for the whole scan")
    sc.add_argument("--antennas", nargs="+", choices=list(ANTENNA),
                    help="compare antenna modes, e.g. --antennas external internal")
    sc.add_argument("--no-apply", action="store_true", help="restore original instead of applying best")
    sc.add_argument("--out", default="results")

    args = p.parse_args(argv)
    if args.cmd == "history":
        return cmd_history(None, args)
    r = HiLink(args.host, args.user, os.environ.get("ROUTER_PASSWORD"))
    if args.cmd in ("scan", "apply", "reset", "antenna", "debug") and not r.password:
        # changing settings always needs a login, even when reading doesn't
        r.password = getpass.getpass(f"Router password for {r.username}@{r.base}: ")
    try:
        if args.cmd != "debug":
            r.ensure_login()
        {"status": cmd_status, "watch": cmd_watch, "apply": cmd_apply, "reset": cmd_reset,
         "antenna": cmd_antenna, "scan": cmd_scan, "debug": cmd_debug}[args.cmd](r, args)
    except RouterError as e:
        if e.code == "100003":
            sys.exit("Session expired / not logged in — run again and enter the router password.")
        sys.exit(f"Router error: {e}")
    except (urllib.error.URLError, OSError) as e:
        sys.exit(f"Cannot reach router at {r.base}: {e}\n"
                 "Is this computer connected to the router's Wi-Fi/LAN?")


if __name__ == "__main__":
    _signal.signal(_signal.SIGPIPE, _signal.SIG_DFL) if hasattr(_signal, "SIGPIPE") else None

    def _term(*_):  # treat "kill" like Ctrl-C so a scan restores the original settings
        raise KeyboardInterrupt
    _signal.signal(_signal.SIGTERM, _term)
    main()
