#!/usr/bin/env python3
"""
Simple web UI for bandscan.  Run:  python3 ui.py   then open http://127.0.0.1:8088

Listens on localhost only. The router password you type is kept in memory
for this run and never written to disk.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import threading
import urllib.error
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import bandscan as bs

ROUTER: bs.HiLink | None = None
HOST = os.environ.get("ROUTER_HOST", "192.168.8.1")
OUT_DIR = "results"
SCAN = {"running": False, "stop": False, "current": None, "done": 0, "log": [], "results": [],
        "best": None, "applied": None, "error": None, "file": None}
DEBUG = {"running": False, "result": None}


def router() -> bs.HiLink:
    global ROUTER
    if ROUTER is None:
        ROUTER = bs.HiLink(HOST, "admin", os.environ.get("ROUTER_PASSWORD"))
    return ROUTER


# ------------------------------------------------------------------ actions

def api_status():
    r = router()
    nm = r.net_mode()
    ant = r.antenna()
    s = bs.snapshot(r)
    s.update({
        "lte_mask": nm.get("LTEBand"), "network_mode": nm.get("NetworkMode"),
        "bands_locked": bs.mask_to_bands(nm.get("LTEBand", "")),
        "antenna": bs.ANTENNA_NAME.get(ant) if ant else None,
        "net_name": bs.NET_TYPE_EX.get(s["net"], s["net"]),
        "conn_name": bs.CONN_STATUS.get(s["conn"], s["conn"]),
        "quality": bs.quality(s["sinr"], s["rsrp"]) if s["rsrp"] is not None else "3G",
        "host": r.base, "logged_in": r.logged_in, "is_3g": bs.is_3g(s),
    })
    return s


def scan_worker(opt: bs.ScanOptions):
    def log(line):
        SCAN["log"].append(line)
        SCAN["log"] = SCAN["log"][-400:]
        m = re.match(r"\S+\s+\[(\d+)\]\s+(.*)", line)
        if m:
            SCAN["done"], SCAN["current"] = int(m.group(1)), m.group(2)

    def on_result(res):
        SCAN["results"].append(res)

    try:
        rec = bs.run_scan(router(), opt, log=log, stop=lambda: SCAN["stop"], on_result=on_result)
        SCAN.update(best=rec["best"], applied=rec["applied"], file=rec["file"])
    except bs.RouterError as e:
        SCAN["error"] = ("Router login needed (100003) — log in and start again" if e.code == "100003" else str(e))
        log(f"ERROR: {SCAN['error']}")
    except Exception as e:  # noqa: BLE001
        SCAN["error"] = str(e)
        log(f"ERROR: {e}")
    finally:
        SCAN.update(running=False, current=None)


def debug_worker():
    try:
        DEBUG["result"] = bs.token_debug(router())
    except Exception as e:  # noqa: BLE001
        DEBUG["result"] = {"error": str(e)}
    finally:
        DEBUG["running"] = False


def history_payload():
    scans = []
    for d in reversed(bs.load_history(OUT_DIR)):
        ranked = bs.rank(d.get("results", []))
        best = next((x for x in ranked if x["key"] == d.get("best")), ranked[0] if ranked else None)
        scans.append({"file": d["file"], "time": d.get("time"), "tests": len(d.get("results", [])),
                      "best": best and f"{best['label']} [{best.get('antenna') or '-'}]",
                      "best_score": best and best.get("score"),
                      "kind": "full" if (d.get("options") or {}).get("full") else
                              "re-check" if (d.get("options") or {}).get("only_recheck") else "quick",
                      "stopped": d.get("stopped")})
    return {"scans": scans, "configs": bs.history_summary(OUT_DIR)}


def scan_file(name):
    if not re.fullmatch(r"scan-[\d-]+\.json", name):
        raise ValueError("bad file name")
    d = json.loads((Path(OUT_DIR) / name).read_text())
    for x in d.get("results", []):
        x.setdefault("mode", "03")
        x.setdefault("label", x.get("combo"))
        x["key"] = bs.config_key(x["mode"], x.get("mask"), x.get("antenna"))
        x.setdefault("net_name", bs.NET_TYPE_EX.get(x.get("net"), x.get("net")))
    d["ranked"] = bs.rank(d.get("results", []))
    d["failed"] = [x for x in d.get("results", []) if not x.get("connected")]
    return d


# ------------------------------------------------------------------- server

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, obj, ctype="application/json"):
        body = obj.encode() if isinstance(obj, str) else json.dumps(obj, default=str).encode()
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # browser went away

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def guard(self, fn):
        try:
            self.reply(200, fn())
        except bs.RouterError as e:
            self.reply(401 if e.code == "100003" else 500,
                       {"error": str(e), "need_login": e.code == "100003"})
        except (urllib.error.URLError, OSError) as e:
            self.reply(502, {"error": f"Cannot reach router at {router().base} ({e}). "
                                      "Is this computer on the router's Wi-Fi?", "unreachable": True})
        except ValueError as e:
            self.reply(400, {"error": str(e)})

    def do_GET(self):
        p = self.path.split("?")[0]
        if p in ("/", "/index.html"):
            return self.reply(200, PAGE, "text/html; charset=utf-8")
        if p == "/api/status":
            return self.guard(api_status)
        if p == "/api/scan":
            return self.reply(200, {k: v for k, v in SCAN.items() if k != "stop"})
        if p == "/api/history":
            return self.guard(history_payload)
        if p.startswith("/api/history/"):
            return self.guard(lambda: scan_file(p.rsplit("/", 1)[1]))
        if p == "/api/debug":
            return self.reply(200, DEBUG)
        if p == "/api/config":
            return self.reply(200, {"host": router().base, "supported": bs.SUPPORTED_BANDS,
                                    "never_alone": sorted(bs.NEVER_ALONE),
                                    "defaults": bs.DEFAULT_CANDIDATES, "explore": bs.EXPLORE_CANDIDATES})
        self.reply(404, {"error": "not found"})

    def do_POST(self):
        global ROUTER
        data = self.body()
        p = self.path
        if p == "/api/login":
            def go():
                global ROUTER
                ROUTER = bs.HiLink(data.get("host") or HOST, data.get("user") or "admin",
                                   data.get("password") or None)
                try:
                    ROUTER.ensure_login() if ROUTER.password else ROUTER.signal()
                except Exception:
                    ROUTER.password = None  # don't keep a password that didn't work
                    raise
                return {"ok": True, "host": ROUTER.base}
            return self.guard(go)
        if p == "/api/apply":
            def go():
                r = router()
                if data.get("antenna") in bs.ANTENNA:
                    r.set_antenna(bs.ANTENNA[data["antenna"]])
                mode = data.get("mode") or "03"
                if data.get("mask") and data["mask"] != "-":
                    mask = data["mask"].upper()
                elif data.get("bands"):
                    _, mask = bs.parse_bands("+".join(str(b) for b in data["bands"]))
                else:
                    mask = r.net_mode().get("LTEBand", bs.ALL_BANDS_MASK)  # e.g. 3G: keep LTE mask
                r.set_bands(mask, mode)
                return {"ok": True, "mask": mask, "mode": mode}
            return self.guard(go)
        if p == "/api/antenna":
            return self.guard(lambda: (router().set_antenna(bs.ANTENNA[data["type"]]), {"ok": True})[1])
        if p == "/api/scan/start":
            if SCAN["running"]:
                return self.reply(409, {"error": "scan already running"})
            if not router().password:
                return self.reply(401, {"error": "log in first", "need_login": True})
            try:
                cands = data.get("candidates") or bs.DEFAULT_CANDIDATES
                [bs.parse_spec(c) for c in cands]
                mode = data.get("mode", "quick")
                opt = bs.ScanOptions(
                    candidates=cands,
                    antennas=[a for a in (data.get("antennas") or []) if a in bs.ANTENNA],
                    full=mode == "full", only_recheck=mode == "recheck",
                    include_3g=bool(data.get("include_3g")),
                    recheck_top=3 if data.get("recheck", True) else 0,
                    speedtest=bool(data.get("speedtest")),
                    settle=float(data.get("settle", 20)), samples=int(data.get("samples", 6)),
                    out_dir=OUT_DIR)
            except (ValueError, TypeError) as e:
                return self.reply(400, {"error": str(e)})
            SCAN.update(running=True, stop=False, results=[], log=[], best=None, applied=None,
                        error=None, done=0, current=None, file=None)
            threading.Thread(target=scan_worker, args=(opt,), daemon=True).start()
            return self.reply(200, {"ok": True})
        if p == "/api/scan/stop":
            SCAN["stop"] = True
            return self.reply(200, {"ok": True})
        if p == "/api/debug":
            if DEBUG["running"] or SCAN["running"]:
                return self.reply(409, {"error": "busy — wait for the scan/test to finish"})
            if not router().password:
                return self.reply(401, {"error": "log in first", "need_login": True})
            DEBUG.update(running=True, result=None)
            threading.Thread(target=debug_worker, daemon=True).start()
            return self.reply(200, {"ok": True})
        self.reply(404, {"error": "not found"})


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Band Scanner</title>
<style>
:root{--bg:#f5f6f8;--card:#fff;--ink:#14161a;--mute:#6b7280;--line:#e5e7eb;--acc:#2563eb;
--ok:#16a34a;--good:#65a30d;--fair:#d97706;--poor:#dc2626}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--ink:#e8eaed;--mute:#9aa0a6;
--line:#2a2f3a;--acc:#60a5fa}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:20px 16px 60px}
header{display:flex;align-items:center;gap:12px;margin-bottom:16px}
h1{font-size:20px;margin:0}h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;
color:var(--mute);margin:0 0 12px}
.dot{width:10px;height:10px;border-radius:50%;background:var(--mute);flex:none}
.dot.on{background:var(--ok);box-shadow:0 0 0 4px color-mix(in srgb,var(--ok) 25%,transparent)}
.dot.off{background:var(--poor)}
.sub{color:var(--mute);font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px;min-width:0}
.big{display:flex;gap:10px;flex-wrap:wrap}
.metric{flex:1;min-width:88px;border:1px solid var(--line);border-radius:10px;padding:10px}
.metric b{display:block;font-size:24px;font-variant-numeric:tabular-nums}
.metric span{font-size:12px;color:var(--mute)}
.bar{height:6px;border-radius:3px;background:var(--line);margin-top:6px;overflow:hidden}
.bar i{display:block;height:100%;border-radius:3px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:4px 14px;margin-top:12px;font-size:14px}
.kv dt{color:var(--mute)}.kv dd{margin:0;font-variant-numeric:tabular-nums}
.pill{display:inline-block;padding:2px 10px;border-radius:99px;font-size:12px;font-weight:600;color:#fff}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:4px 0 12px}
.chip{border:1px solid var(--line);background:transparent;color:var(--ink);border-radius:99px;
padding:6px 12px;cursor:pointer;font:inherit;font-size:14px}
.chip.on{background:var(--acc);border-color:var(--acc);color:#fff}
.chip.warn{border-style:dashed}
.chip.sm{padding:3px 10px;font-size:13px}
button.btn{border:0;border-radius:9px;padding:9px 14px;font:inherit;font-weight:600;cursor:pointer;
background:var(--acc);color:#fff}
button.ghost{background:transparent;color:var(--ink);border:1px solid var(--line)}
button.danger{background:var(--poor)}
button:disabled{opacity:.5;cursor:default}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
select,input{font:inherit;padding:8px 10px;border-radius:9px;border:1px solid var(--line);
background:var(--card);color:var(--ink);max-width:100%}
canvas{width:100%;height:90px;display:block;margin-top:12px}
table{width:100%;border-collapse:collapse;font-size:13.5px;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:7px 6px;border-bottom:1px solid var(--line);white-space:nowrap}
th{color:var(--mute);font-weight:500;font-size:12px}
tr.best td{background:color-mix(in srgb,var(--ok) 13%,transparent)}
tr.dim td{color:var(--mute)}
tr.click{cursor:pointer}tr.click:hover td{background:color-mix(in srgb,var(--acc) 8%,transparent)}
.tablewrap{overflow-x:auto}
.log{font:12px/1.5 ui-monospace,Menlo,monospace;background:var(--bg);border-radius:9px;padding:10px;
max-height:220px;overflow:auto;white-space:pre-wrap;margin-top:12px}
.prog{height:8px;background:var(--line);border-radius:4px;overflow:hidden;margin:10px 0}
.prog i{display:block;height:100%;background:var(--acc);transition:width .4s}
.prog.busy i{width:30%!important;animation:slide 1.4s infinite ease-in-out}
@keyframes slide{0%{margin-left:-30%}100%{margin-left:100%}}
.msg{padding:10px 12px;border-radius:9px;margin-bottom:14px;display:none;font-size:14px}
.msg.err{display:block;background:color-mix(in srgb,var(--poor) 14%,transparent);color:var(--poor)}
.msg.ok{display:block;background:color-mix(in srgb,var(--ok) 14%,transparent);color:var(--ok)}
.full{grid-column:1/-1}
#login{display:none}
.hero{background:#0b0f14;color:#e8eaed;border-radius:18px;padding:22px 16px 18px;margin-bottom:14px;
display:flex;flex-direction:column;align-items:center;gap:14px;text-align:center}
.hero-modes{display:inline-flex;background:#151b23;border-radius:99px;padding:4px;gap:2px}
.hero-modes button{border:0;background:transparent;color:#9aa0a6;padding:7px 16px;border-radius:99px;
font:inherit;font-size:14px;cursor:pointer}
.hero-modes button.on{background:#22c55e;color:#04130a;font-weight:600}
.hero-stage{position:relative;width:200px;height:200px;display:grid;place-items:center}
.go{position:relative;width:168px;height:168px;border-radius:50%;border:0;cursor:pointer;
background:#22c55e;color:#04130a;font:700 28px/1 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
letter-spacing:.08em;box-shadow:0 10px 40px rgba(34,197,94,.35)}
.go:active{transform:scale(.97)}
.go .ring{position:absolute;inset:0;border-radius:50%;border:2px solid #22c55e;pointer-events:none;
animation:pulse 3.2s ease-out infinite}
.go .r2{animation-delay:1.6s}
@keyframes pulse{0%{transform:scale(1);opacity:.6}100%{transform:scale(1.45);opacity:0}}
.spin{position:absolute;inset:0}
.spin svg{width:100%;height:100%;animation:rot 1.6s linear infinite}
.spin .trk{fill:none;stroke:#1e2733;stroke-width:8}
.spin .arc{fill:none;stroke:#22c55e;stroke-width:8;stroke-linecap:round;stroke-dasharray:120 400}
@keyframes rot{to{transform:rotate(360deg)}}
.spin-n{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.spin-n b{font-size:52px;line-height:1;font-variant-numeric:tabular-nums}
.spin-n span{font-size:13px;color:#9aa0a6;margin-top:4px}
.hero-cur{min-height:20px;font-size:14px;color:#c9cdd2;max-width:100%;overflow-wrap:anywhere}
.hero .chk{color:#c9cdd2}
.hero-more{color:#60a5fa;font-size:14px;text-decoration:none}
[hidden]{display:none!important}
@media (prefers-reduced-motion:reduce){.go .ring,.spin svg{animation:none}}
label.chk{display:flex;align-items:center;gap:6px;font-size:14px}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:10px;overflow:hidden}
.seg button{border:0;background:transparent;color:var(--ink);padding:8px 12px;font:inherit;font-size:14px;cursor:pointer}
.seg button.on{background:var(--acc);color:#fff}
.hint{font-size:13px;color:var(--mute);margin:8px 0 12px}
.tag{font-size:11px;padding:1px 7px;border-radius:99px;border:1px solid var(--line);color:var(--mute)}
.banner{border-left:4px solid var(--ok);padding:8px 12px;background:color-mix(in srgb,var(--ok) 8%,transparent);
border-radius:6px;margin:10px 0;font-size:14px;display:none}
</style></head><body><div class="wrap">
<header><div class="dot" id="dot"></div><div><h1>LTE Band Scanner</h1>
<div class="sub" id="hostline">connecting…</div></div></header>
<div class="msg" id="msg"></div>

<div class="hero" id="hero">
<div class="hero-modes" id="heromodes"><button data-m="quick">Quick</button><button data-m="full">Full</button><button data-m="recheck">Re-check</button></div>
<div class="hero-stage">
<button class="go" id="gobtn" onclick="startScan()" aria-label="Start scan"><span class="ring"></span><span class="ring r2"></span>START</button>
<div class="spin" id="herospin" hidden><svg viewBox="0 0 120 120"><circle class="trk" cx="60" cy="60" r="52"/><circle class="arc" cx="60" cy="60" r="52"/></svg>
<div class="spin-n"><b id="heron">0</b><span>tests done</span></div></div>
</div>
<div class="hero-cur" id="herocur"></div>
<button class="btn danger" id="herostop" onclick="stopScan()" hidden>Stop &amp; restore</button>
<label class="chk"><input type="checkbox" id="herospeed" checked autocomplete="off"> Speed test (slower, most accurate)</label>
<a href="#details" class="hero-more" onclick="$('details').scrollIntoView({behavior:'smooth'});return false">More options ↓</a>
</div>

<div class="card" id="login" style="margin-bottom:14px">
<h2>Router login</h2>
<div class="sub" style="margin-bottom:8px">Reading the signal works without it, but scanning or changing bands needs a login.</div>
<div class="row"><input id="host" placeholder="192.168.8.1" size="14">
<input id="user" value="admin" size="8">
<input id="pass" type="password" placeholder="router password" autocomplete="current-password">
<button class="btn" onclick="login()">Connect</button></div>
<div class="sub" style="margin-top:8px">Kept in memory for this run only, never saved.</div>
</div>

<div class="grid" id="details">
<div class="card"><h2>Signal</h2>
<div class="big">
<div class="metric"><span id="l1">SINR</span><b id="sinr">–</b><div class="bar"><i id="sinrb"></i></div></div>
<div class="metric"><span id="l2">RSRP</span><b id="rsrp">–</b><div class="bar"><i id="rsrpb"></i></div></div>
<div class="metric"><span id="l3">RSRQ</span><b id="rsrq">–</b><div class="bar"><i id="rsrqb"></i></div></div>
</div>
<canvas id="chart" width="600" height="180"></canvas>
<div class="sub">SINR history · aim the antenna for the highest line</div>
</div>

<div class="card"><h2>Connection</h2>
<span class="pill" id="qual">–</span>
<dl class="kv">
<dt>Status</dt><dd id="conn">–</dd><dt>Type</dt><dd id="net">–</dd>
<dt>Band</dt><dd id="band">–</dd><dt>Cell / PCI</dt><dd id="cell">–</dd>
<dt>EARFCN</dt><dd id="earfcn">–</dd><dt>Locked</dt><dd id="locked">–</dd>
<dt>Antenna</dt><dd id="ant">–</dd></dl>
</div>

<div class="card"><h2>Manual control</h2>
<div class="chips" id="bandchips"></div>
<div class="row">
<button class="btn" onclick="applyBands()">Apply bands</button>
<button class="btn ghost" onclick="preset([1,3])">B1+B3</button>
<button class="btn ghost" onclick="preset([1])">Pin B1</button>
<button class="btn ghost" onclick="resetBands()">All bands</button></div>
<div class="row" style="margin-top:10px">
<button class="btn ghost" onclick="applyCfg({mode:'02'})">3G / H+ only</button>
<button class="btn ghost" onclick="applyCfg({mode:'00',mask:'20880800C5'})">Auto 4G/3G</button></div>
<h2 style="margin-top:18px">Antenna</h2>
<div class="row"><select id="antsel"><option value="auto">Auto</option><option value="external">External</option>
<option value="internal">Internal</option><option value="mix">Mix</option></select>
<button class="btn ghost" onclick="setAnt()">Set</button></div>
</div>

<div class="card full"><h2>Auto scan</h2>
<div class="seg" id="modeseg">
<button data-m="quick" class="on">Quick</button><button data-m="full">Full (every combo)</button>
<button data-m="recheck">Re-check best</button></div>
<div class="hint" id="modehint"></div>
<div class="chips" id="candchips"></div>
<div class="row" style="margin-bottom:8px"><span class="sub">Antennas:</span>
<label class="chk"><input type="checkbox" class="antc" value="external" checked> External</label>
<label class="chk"><input type="checkbox" class="antc" value="internal"> Internal</label>
<label class="chk"><input type="checkbox" class="antc" value="mix"> Mix</label>
<label class="chk"><input type="checkbox" class="antc" value="auto"> Auto</label></div>
<div class="row">
<label class="chk"><input type="checkbox" id="g3"> Include 3G / H+ and Auto</label>
<label class="chk"><input type="checkbox" id="recheck" checked> Re-test previous best 3</label>
<label class="chk"><input type="checkbox" id="speed" checked autocomplete="off"> Speed test (slower, most accurate)</label>
<label class="chk">Settle <input id="settle" type="number" value="20" min="5" max="90" style="width:70px"> s</label>
</div>
<div class="row" style="margin-top:12px">
<button class="btn" id="startbtn" onclick="startScan()">Start scan</button>
<button class="btn danger" id="stopbtn" onclick="stopScan()" disabled>Stop &amp; restore</button>
<span class="sub" id="scanstate"></span></div>
<div class="prog" id="prog"><i id="progbar" style="width:0"></i></div>
<div class="banner" id="banner"></div>
<div class="tablewrap"><table><thead><tr><th>#</th><th>Config</th><th>Antenna</th><th>Cell</th>
<th>SINR</th><th>±</th><th>RSRP</th><th>RSRQ</th><th>Type</th><th>Ping</th><th>Loss</th><th>Mbit/s</th><th>Score</th><th></th></tr></thead>
<tbody id="res"><tr><td colspan="14" class="sub">No scan yet. Internet drops for a few seconds on each switch. Results are ranked best first.</td></tr></tbody></table></div>
<div class="log" id="log"></div>
</div>

<div class="card full"><h2>History</h2>
<div class="hint">Every scan is saved. The track record below combines all of them: each scan re-tests the top 3, so the winners keep being re-checked.</div>
<div class="tablewrap"><table><thead><tr><th>#</th><th>Config</th><th>Antenna</th><th>Tests</th><th>Fails</th>
<th>Avg score</th><th>Mbit/s</th><th>Rating</th><th>Last</th><th></th></tr></thead><tbody id="hcfg"></tbody></table></div>
<h2 style="margin-top:18px">Saved scans</h2>
<div class="tablewrap"><table><thead><tr><th>Time</th><th>Type</th><th>Tests</th><th>Best</th><th>Score</th></tr></thead>
<tbody id="hscans"></tbody></table></div>
</div>

<div class="card full"><h2>Diagnostics</h2>
<div class="hint">Checks the login and which security-token method your router accepts. It writes your current settings back unchanged, so nothing on the router changes.</div>
<div class="row"><button class="btn ghost" id="dbgbtn" onclick="runDebug()">Run connection test</button>
<button class="btn ghost" onclick="copyDebug()">Copy log</button><span class="sub" id="dbgstate"></span></div>
<div class="tablewrap" style="margin-top:12px"><table><tbody id="dbgres"></tbody></table></div>
<div class="log" id="dbglog" style="display:none"></div>
</div>
</div></div>
<script>
const $=id=>document.getElementById(id);
let cfg, sel=new Set(), cands=new Set(), hist=[], mode='quick', viewing=null;
const col={excellent:'var(--ok)',good:'var(--good)',fair:'var(--fair)',poor:'var(--poor)','3G':'var(--fair)','?':'var(--mute)'};
const HINT={quick:'Tests the combos you pick below with each selected antenna.',
 full:'Finds which bands have service, then tests every combination of them (can take 20–40 min per antenna).',
 recheck:'Fast: only re-tests the best 3 configs from earlier scans and applies today\'s winner (~3 min).'};
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function msg(t,kind='err'){const m=$('msg');m.className='msg '+(t?kind:'');m.textContent=t||''}
function needLogin(e){if(e&&(e.need_login||String(e.message||e).includes('100003'))){$('login').style.display='block';
 msg('Log in to the router first (password box above), then try again.');$('pass').focus();return true}return false}
async function api(p,body){const r=await fetch(p,body?{method:'POST',headers:{'Content-Type':'application/json'},
 body:JSON.stringify(body)}:{});const j=await r.json();if(!r.ok){const e=new Error(j.error||r.status);Object.assign(e,j);throw e}return j}
function pct(v,lo,hi){return Math.max(0,Math.min(100,(v-lo)/(hi-lo)*100))}
function level(v,a,b,c){return v>=a?'var(--ok)':v>=b?'var(--good)':v>=c?'var(--fair)':'var(--poor)'}
function setBar(id,v,lo,hi,a,b,c){const i=$(id);if(v==null){i.style.width=0;return}
 i.style.width=pct(v,lo,hi)+'%';i.style.background=level(v,a,b,c)}
function fmtTime(t){return t?t.replace(/^(\d{4})(\d\d)(\d\d)-(\d\d)(\d\d)(\d\d)$/,'$3/$2 $4:$5'):'–'}
function bandLabel(c){return c==='all'?'All':c.split('+').map(x=>'B'+x).join('+')}
function chips(){
 $('bandchips').innerHTML=cfg.supported.map(b=>`<button class="chip ${sel.has(b)?'on':''} ${cfg.never_alone.includes(b)?'warn':''}"
  onclick="tog(${b})" title="${cfg.never_alone.includes(b)?'weak / no service here alone':''}">B${b}</button>`).join('');
 const all=[...cfg.defaults,...cfg.explore];
 $('candchips').style.display=mode==='quick'?'flex':'none';
 $('candchips').innerHTML=all.map(c=>`<button class="chip ${cands.has(c)?'on':''}" onclick="togc('${c}')">${bandLabel(c)}</button>`).join('');
 $('modehint').textContent=HINT[mode];
 document.querySelectorAll('#modeseg button,#heromodes button').forEach(b=>b.classList.toggle('on',b.dataset.m===mode));
}
document.querySelectorAll('#modeseg button,#heromodes button').forEach(b=>b.onclick=()=>{mode=b.dataset.m;chips()});
$('herospeed').onchange=()=>{$('speed').checked=$('herospeed').checked};
$('speed').onchange=()=>{$('herospeed').checked=$('speed').checked};
function heroUpdate(s){$('gobtn').hidden=s.running;$('herospin').hidden=!s.running;$('herostop').hidden=!s.running;
 $('heron').textContent=s.done||0;const best=s.results.find(r=>r.key===s.best);
 $('herocur').textContent=s.running?(s.current?'Testing: '+s.current:'Starting…'):s.error?'Error: '+s.error:
  best?(s.applied?`Best: ${best.label} [${best.antenna||'-'}] · score ${best.score} · applied`:
   `Stopped — original settings restored · best so far: ${best.label} [${best.antenna||'-'}]`):
  s.file&&!s.results.length?(mode==='recheck'?'Nothing to re-check yet — run Quick or Full first':'Nothing was tested'):''}
function tog(b){sel.has(b)?sel.delete(b):sel.add(b);chips()}
function togc(c){cands.has(c)?cands.delete(c):cands.add(c);chips()}
function preset(a){sel=new Set(a);chips();applyBands()}
function draw(){const c=$('chart'),x=c.getContext('2d'),w=c.width,h=c.height;x.clearRect(0,0,w,h);
 const css=getComputedStyle(document.documentElement);x.strokeStyle=css.getPropertyValue('--line');x.lineWidth=1;
 [0,13].forEach(v=>{const y=h-pct(v,-10,30)/100*h;x.beginPath();x.moveTo(0,y);x.lineTo(w,y);x.stroke()});
 if(hist.length<2)return;x.strokeStyle=css.getPropertyValue('--acc');x.lineWidth=3;x.beginPath();
 hist.forEach((v,i)=>{const px=i/(120-1)*w,py=h-pct(v,-10,30)/100*h;i?x.lineTo(px,py):x.moveTo(px,py)});x.stroke()}
async function poll(){
 try{const s=await api('/api/status');$('dot').className='dot on';$('login').style.display=s.logged_in?'none':'block';
  $('hostline').textContent=s.host+(s.logged_in?' · logged in':'');
  if($('msg').textContent.startsWith('Cannot reach'))msg('');
  if(s.is_3g){$('l1').textContent='Ec/Io';$('l2').textContent='RSCP';$('l3').textContent='RSSI';
   $('sinr').textContent=s.ecio??'–';$('rsrp').textContent=s.rscp??'–';$('rsrq').textContent=s.rssi??'–';
   setBar('sinrb',s.ecio,-20,0,-6,-10,-14);setBar('rsrpb',s.rscp,-115,-60,-75,-85,-100);setBar('rsrqb',null)}
  else{$('l1').textContent='SINR';$('l2').textContent='RSRP';$('l3').textContent='RSRQ';
   $('sinr').textContent=s.sinr??'–';$('rsrp').textContent=s.rsrp??'–';$('rsrq').textContent=s.rsrq??'–';
   setBar('sinrb',s.sinr,-10,30,13,5,0);setBar('rsrpb',s.rsrp,-125,-70,-90,-100,-110);setBar('rsrqb',s.rsrq,-20,-3,-10,-15,-20)}
  const q=$('qual');q.textContent=s.quality;q.style.background=col[s.quality]||'var(--mute)';
  $('conn').textContent=s.conn_name;$('net').textContent=s.net_name;$('band').textContent=s.band?'B'+s.band+' · '+(s.dlbandwidth||''):'–';
  $('cell').textContent=(s.cell_id||'–')+' / '+(s.pci||'–');$('earfcn').textContent=s.earfcn||'–';
  $('locked').textContent=(s.network_mode==='02'?'3G only':s.network_mode==='00'?'Auto · ':'')+(s.network_mode==='02'?'':s.bands_locked.map(b=>'B'+b).join('+')+'  ('+s.lte_mask+')');
  $('ant').textContent=s.antenna||'n/a';
  if(s.sinr!=null){hist.push(s.sinr);if(hist.length>120)hist.shift();draw()}
  if(!sel.size){sel=new Set(s.bands_locked.filter(b=>cfg.supported.includes(b)));chips()}
  if(s.antenna&&document.activeElement!==$('antsel'))$('antsel').value=s.antenna;
 }catch(e){$('dot').className='dot off';if(!needLogin(e))msg(e.message)}
}
async function login(){try{await api('/api/login',{host:$('host').value,user:$('user').value,password:$('pass').value});
 $('pass').value='';msg('Logged in','ok');setTimeout(()=>msg(''),1500);poll()}catch(e){msg(e.message)}}
async function applyCfg(c){try{const r=await api('/api/apply',c);msg('Applied '+(c.label||(r.mode==='02'?'3G / H+ only':r.mode==='00'?'Auto 4G/3G':'LTEBand '+r.mask))+(c.antenna?' + '+c.antenna+' antenna':'')+' — reconnecting (~20 s)…','ok');hist=[]}catch(e){if(!needLogin(e))msg(e.message)}}
async function applyBands(){if(!sel.size)return msg('Pick at least one band');
 const b=[...sel].sort((a,c)=>a-c);if(b.length===1&&cfg.never_alone.includes(b[0])&&!confirm('B'+b[0]+' is weak or has no service here. Lock anyway?'))return;
 applyCfg({bands:b,mode:'03',label:b.map(x=>'B'+x).join('+')})}
function resetBands(){sel=new Set();applyCfg({mask:'20880800C5',mode:'03',label:'all bands'})}
async function setAnt(){try{await api('/api/antenna',{type:$('antsel').value});msg('Antenna set to '+$('antsel').value,'ok')}catch(e){if(!needLogin(e))msg(e.message)}}
async function startScan(){if(mode==='quick'&&!cands.size)return msg('Pick combos to test');
 const ants=[...document.querySelectorAll('.antc:checked')].map(x=>x.value);
 try{await api('/api/scan/start',{mode,candidates:[...cands],antennas:ants,include_3g:$('g3').checked,
  recheck:$('recheck').checked,speedtest:$('speed').checked,settle:+$('settle').value});msg('');viewing=null;scanPoll()}
 catch(e){if(!needLogin(e))msg(e.message)}}
async function stopScan(){await api('/api/scan/stop',{});$('scanstate').textContent='stopping and restoring…'}
function applyRow(i){const r=window._rows[i];applyCfg({mask:r.mask||'-',mode:r.mode,antenna:r.antenna||'',label:r.label})}
function renderResults(results,bestKey,banner){
 const ok=results.filter(r=>r.connected).sort((a,b)=>b.score-a.score);const bad=results.filter(r=>!r.connected);
 window._rows=ok;
 $('res').innerHTML=ok.length||bad.length?ok.map((r,i)=>{const g3=r.rsrp==null&&r.rscp!=null;return `<tr class="${r.key===bestKey?'best':''}">
  <td>${i+1}</td><td><b>${esc(r.label)}</b>${r.key===bestKey?' <span class="tag">best</span>':''}</td><td>${esc(r.antenna||'–')}</td>
  <td>${g3?'3G':esc((r.band?'B'+r.band+' ':'')+(r.cell_id||''))}</td>
  <td>${g3?'Ec/Io '+r.ecio:(r.sinr??'–')}</td><td>${r.sinr_sd??'–'}</td><td>${g3?r.rscp:(r.rsrp??'–')}</td><td>${r.rsrq??'–'}</td>
  <td>${esc(r.net_name||'')}</td><td>${r.latency_ms??'–'}</td><td>${r.loss_pct!=null?r.loss_pct+'%':'–'}</td><td>${r.down_mbps??'–'}</td>
  <td><b>${r.score}</b></td><td><button class="chip sm" onclick="applyRow(${i})">Apply</button></td></tr>`}).join('')
  +bad.map(r=>`<tr class="dim"><td>–</td><td>${esc(r.label)}</td><td>${esc(r.antenna||'–')}</td><td colspan="11">${r.error?'error':'no service'}</td></tr>`).join('')
  :'<tr><td colspan="14" class="sub">No results yet…</td></tr>';
 const b=$('banner');b.style.display=banner?'block':'none';b.innerHTML=banner||'';
}
async function scanPoll(){const s=await api('/api/scan');
 $('startbtn').disabled=s.running;$('stopbtn').disabled=!s.running;heroUpdate(s);
 $('scanstate').textContent=s.running?`Testing #${s.done}: ${s.current||'…'}`:(s.error?'Error: '+s.error:s.applied?'Done — best config applied':s.file?'Done — original settings restored':'');
 $('prog').classList.toggle('busy',s.running);$('progbar').style.width=s.running?'30%':(s.file?'100%':'0');
 if(!viewing){const best=s.results.find(r=>r.key===s.best);
  renderResults(s.results,s.best,!s.running&&best?`Best: <b>${esc(best.label)}</b> [${esc(best.antenna||'-')}] · score ${best.score}${s.applied?' · applied to the router':''}`:'');
  $('log').textContent=s.log.join('\n');$('log').scrollTop=1e9}
 if(s.error)needLogin(s.error);
 if(s.running)setTimeout(scanPoll,1500);else if(s.file)loadHistory();
}
async function loadHistory(){try{const h=await api('/api/history');window._cfgs=h.configs;
 $('hcfg').innerHTML=h.configs.length?h.configs.slice(0,15).map((c,i)=>`<tr class="${i===0&&c.rating!=null?'best':''}"><td>${i+1}</td>
  <td><b>${esc(c.label)}</b></td><td>${esc(c.antenna||'–')}</td><td>${c.tests}</td><td>${c.fails}</td><td>${c.avg_score??'–'}</td>
  <td>${c.avg_mbps??'–'}</td><td><b>${c.rating??'–'}</b></td><td>${fmtTime(c.last)}</td>
  <td>${c.rating!=null?`<button class="chip sm" onclick="applyHist(${i})">Apply</button>`:''}</td></tr>`).join('')
  :'<tr><td colspan="10" class="sub">No saved scans yet.</td></tr>';
 $('hscans').innerHTML=h.scans.map(s=>`<tr class="click" onclick="viewScan('${s.file}')"><td>${fmtTime(s.time)}</td>
  <td>${s.kind}${s.stopped?' · stopped':''}</td><td>${s.tests}</td><td>${esc(s.best||'–')}</td><td>${s.best_score??'–'}</td></tr>`).join('')
}catch(e){}}
function applyHist(i){const c=window._cfgs[i];applyCfg({mask:c.mask||'-',mode:c.mode,antenna:c.antenna||'',label:c.label})}
async function viewScan(f){try{const d=await api('/api/history/'+f);viewing=f;
 renderResults(d.results,d.best||(d.ranked[0]&&d.ranked[0].key),`Viewing saved scan from <b>${fmtTime(d.time)}</b> · <a href="#" onclick="viewing=null;scanPoll();return false">back to current scan</a>`);
 $('log').textContent=(d.log||['(no log saved for this older scan)']).join('\n');
 $('res').scrollIntoView({behavior:'smooth',block:'center'})}catch(e){msg(e.message)}}
async function runDebug(){try{await api('/api/debug',{});$('dbgbtn').disabled=true;debugPoll()}catch(e){if(!needLogin(e))msg(e.message)}}
async function debugPoll(){const d=await api('/api/debug');$('dbgbtn').disabled=d.running;
 $('dbgstate').textContent=d.running?'testing… (~15 s)':'';
 if(d.running)return setTimeout(debugPoll,1000);
 const r=d.result;if(!r)return;if(r.error){$('dbgres').innerHTML=`<tr><td>Error</td><td>${esc(r.error)}</td></tr>`;return}
 const rows=[['Device',r.device?`${r.device.devicename} · fw ${r.device.SoftwareVersion} · web ${r.device.WebUIVersion}`:'–'],
  ['Login',r.login],['Login state before → after',(r.state_before?r.state_before.State:'?')+' → '+(r.state_after?r.state_after.State:'?')+'  (0 = logged in, -1 = logged out)'],
  ...Object.entries(r.results).map(([k,v])=>['Token: '+k,v]),
  ['Result',r.works.length?'✅ Works with: '+r.works.join(', ')+' (now used automatically)':'❌ No method worked — copy the log and send it']];
 $('dbgres').innerHTML=rows.map(([k,v])=>`<tr><td class="sub">${esc(k)}</td><td>${esc(v)}</td></tr>`).join('');
 const l=$('dbglog');l.style.display='block';l.textContent=(r.trace||[]).join('\n');window._dbg=r}
function copyDebug(){if(!window._dbg)return msg('Run the test first');
 navigator.clipboard.writeText(JSON.stringify(window._dbg,null,2)).then(()=>msg('Debug log copied','ok'),()=>msg('Copy failed — select the log text instead'))}
(async()=>{cfg=await api('/api/config');$('host').value=cfg.host.replace('http://','');
 $('speed').checked=$('herospeed').checked=true;
 cands=new Set(cfg.defaults);chips();poll();setInterval(poll,2000);scanPoll();loadHistory();debugPoll()})();
</script></body></html>"""


def main():
    global HOST, OUT_DIR
    p = argparse.ArgumentParser(description="Band scanner web UI")
    p.add_argument("--host", default=HOST, help="router address (default 192.168.8.1)")
    p.add_argument("--port", type=int, default=8088)
    p.add_argument("--out", default=OUT_DIR, help="folder for saved scans")
    p.add_argument("--no-browser", action="store_true")
    a = p.parse_args()
    HOST, OUT_DIR = a.host, a.out
    url = f"http://127.0.0.1:{a.port}"
    try:
        srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    except OSError as e:
        if e.errno not in (48, 98):  # address already in use (macOS / Linux)
            raise
        print(f"The UI is already running on {url} — opening it.\n"
              f"(To run another copy use a different port: python3 ui.py --port 8090)")
        if not a.no_browser:
            webbrowser.open(url)
        return
    print(f"Band scanner UI on {url}  (router {HOST}) — Ctrl-C to quit")
    if not a.no_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
