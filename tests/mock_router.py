#!/usr/bin/env python3
"""Fake Huawei HiLink router for testing bandscan.py offline.

  python3 tests/mock_router.py 8765      (password: test)
"""
import base64
import hashlib
import secrets
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import xml.etree.ElementTree as ET

PASSWORD = "test"
STATE = {"LTEBand": "20880800C5", "NetworkMode": "00", "NetworkBand": "3FFFFFFF",
         "antenna": "0", "switched_at": 0.0, "sessions": set(), "tokens": set(),
         "session_tokens": set()}  # tokens valid for logged-in writes (handed out in headers)

# what the "site" offers per band: (cell, pci, earfcn, rsrp, rsrq, sinr, CA-capable)
CELLS = {1: ("28057964", "306", "400", -97, -10, 9, True),
         3: ("28057921", "121", "1650", -92, -13, 3, True),
         8: ("28057990", "77", "3740", -104, -14, 1, False),
         20: ("28057911", "45", "6300", -101, -12, 2, False)}


def bands(mask):
    m = int(mask, 16)
    return [i + 1 for i in range(64) if m >> i & 1]


def xml(d):
    return "<?xml version='1.0' encoding='UTF-8'?><response>" + "".join(
        f"<{k}>{v}</{k}>" for k, v in d.items()) + "</response>"


def err(code):
    return f"<?xml version='1.0' encoding='UTF-8'?><error><code>{code}</code><message></message></error>"


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def sid(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "SessionID":
                return v
        return None

    def send(self, body, cookie=None, hdrs=None):
        b = body.encode()
        self.send_response(200)
        for k, v in (hdrs or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "text/xml")
        if cookie:
            self.send_header("Set-Cookie", f"SessionID={cookie}; path=/; HttpOnly")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def authed(self):
        return self.sid() in STATE["sessions"]

    def current(self):
        if time.time() - STATE["switched_at"] < 3:
            return None
        if STATE["NetworkMode"] == "02":  # 3G only (WCDMA / H+)
            return dict(rscp="-88dBm", ecio="-9dB", rssi="-70dBm", sc="211", cell_id="1234567",
                        rsrp="", rsrq="", sinr="", band=""), "3g"
        active = [b for b in bands(STATE["LTEBand"]) if b in CELLS]
        if not active or time.time() - STATE["switched_at"] < 3:
            return None
        bonus = 4 if STATE["antenna"] == "1" else 0
        best = max(active, key=lambda b: CELLS[b][5])
        cell, pci, earfcn, rsrp, rsrq, sinr, ca = CELLS[best]
        ca_on = ca and sum(1 for b in active if CELLS[b][6]) >= 2
        return dict(band=best, cell_id=cell, pci=pci, earfcn=earfcn, rsrp=f"{rsrp + bonus}dBm",
                    rsrq=f"{rsrq}dB", sinr=f"{sinr + bonus}dB", rssi="-70dBm",
                    dlbandwidth="20MHz"), ca_on

    def do_GET(self):
        p = self.path
        if p == "/api/webserver/SesTokInfo":
            tok = secrets.token_hex(16)
            STATE["tokens"].add(tok)
            return self.send(xml({"SesInfo": f"SessionID=anon{secrets.token_hex(4)}", "TokInfo": tok}))
        if p == "/api/user/state-login":
            return self.send(xml({"State": "-1", "password_type": "4"}))
        if p == "/html/home.html":
            t = secrets.token_hex(16); STATE["session_tokens"].add(t)
            return self.send(f'<html><head><meta name="csrf_token" content="{t}"/></head></html>')
        # like the real B715: status reads work without login
        if p == "/api/net/net-mode":
            return self.send(xml({k: STATE[k] for k in ("NetworkMode", "NetworkBand", "LTEBand")}))
        if p == "/api/device/antenna_set_type":
            return self.send(xml({"antennasettype": STATE["antenna"]}))
        if p == "/api/device/signal":
            cur = self.current()
            return self.send(xml(cur[0] if cur else {"rsrp": "", "sinr": "", "band": ""}))
        if p == "/api/monitoring/status":
            cur = self.current()
            if not cur:
                return self.send(xml({"ConnectionStatus": "902", "CurrentNetworkTypeEx": "0"}))
            return self.send(xml({"ConnectionStatus": "901", "SignalIcon": "4",
                                  "CurrentNetworkTypeEx": "45" if cur[1] == "3g" else "1011" if cur[1] else "101"}))
        self.send(err("100002"))

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        tok = self.headers.get("__RequestVerificationToken")
        req = ET.fromstring(body)
        if self.path == "/api/user/login":
            if tok not in STATE["tokens"]:
                return self.send(err("125002"))
            STATE["tokens"].discard(tok)
            h = base64.b64encode(hashlib.sha256(PASSWORD.encode()).hexdigest().encode()).decode()
            exp = base64.b64encode(hashlib.sha256(
                (req.findtext("Username") + h + tok).encode()).hexdigest().encode()).decode()
            if req.findtext("Password") != exp:
                return self.send(err("108006"))
            sid = secrets.token_hex(16)
            STATE["sessions"].add(sid)
            one, two = secrets.token_hex(16), secrets.token_hex(16)
            STATE["session_tokens"] |= {one, two}
            return self.send("<?xml version='1.0' encoding='UTF-8'?><response>OK</response>", cookie=sid,
                             hdrs={"__RequestVerificationTokenone": one, "__RequestVerificationTokentwo": two})
        # writes: real firmware answers 125002 when not logged in or token not from a header
        if not self.authed() or tok not in STATE["session_tokens"]:
            return self.send(err("125002"))
        STATE["session_tokens"].discard(tok)
        nxt = secrets.token_hex(16); STATE["session_tokens"].add(nxt)
        ok = "<?xml version='1.0' encoding='UTF-8'?><response>OK</response>"
        self._next = {"__RequestVerificationToken": nxt}
        if self.path == "/api/net/net-mode":
            for k in ("NetworkMode", "NetworkBand", "LTEBand"):
                STATE[k] = req.findtext(k)
            STATE["switched_at"] = time.time()
            return self.send(ok, hdrs=self._next)
        if self.path == "/api/device/antenna_set_type":
            STATE["antenna"] = req.findtext("antennasettype")
            return self.send(ok, hdrs=self._next)
        self.send(err("100002"))


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
