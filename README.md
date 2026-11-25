# bandscan — LTE band scanner for Huawei HiLink routers

Built for a **Huawei B715s-23c on Al Madar (Libya)**. It works on most HiLink 4G routers.
It tries LTE band locks one at a time. For each one it measures the signal and, if you want, real download speed, then applies the best.
It uses only the Python 3 standard library, so there's nothing to install.

## Before you start
- Connect this computer to the **router's Wi-Fi or LAN**, so that http://192.168.8.1 opens.
- The password is never saved. Either type it when prompted or set it for the current shell only:
  `export ROUTER_PASSWORD=...`

## Simple UI (recommended)
```bash
python3 ui.py
```
This opens http://127.0.0.1:8088. Log in with your router password: it's kept in memory only, and a password that fails is forgotten.

- **Signal / Connection:** live SINR, RSRP and RSRQ (Ec/Io and RSCP on 3G) with a SINR history line, plus band, cell, 4G+, the locked bands and the antenna.
- **Manual control:** band chips, B1+B3, Pin B1, All bands, 3G / H+ only, Auto 4G/3G, and the antenna selector.
- **Auto scan:**
  - *Quick* tests the combos you pick.
  - *Full* finds which bands have service, then tests **every combination** of them.
  - *Re-check best* re-tests the top 3 from history in about 3 minutes.
  - Options: the antennas to compare, *Include 3G / H+ and Auto*, *Re-test previous best 3*, and *Speed test*.
  - Results are ranked best first. The winner is applied; *Stop* restores your original settings.
- **History:** every scan is saved with its full log. The track record ranks each setting across all scans, and you can click a saved scan to see its results.
- **Diagnostics:** checks the login and which security-token method the router accepts. It writes your current settings back unchanged, so nothing on the router changes.

## How the best setting is chosen
- **Score:** speed counts most when you run the speed test. Otherwise it's signal (SINR, then RSRQ, then RSRP, with a bonus for 4G+), minus stability penalties: SINR swinging between samples, ping, jitter and packet loss.
- **Ties:** results within 3 points are measurement noise. A tie goes to the setting with the better track record, then to the one with fewer bands, so the router doesn't jump between settings from one scan to the next.
- **History:** every scan first re-tests the 3 best settings from history, so today's winner is compared against earlier winners under today's conditions. History scores are recalculated with the current formula, so old and new scans compare fairly.
- **3G / H+:** scored on RSCP and Ec/Io, and it's capped below LTE. In practice it only wins if you run the speed test and it really is faster.
- **Safe to stop:** B7, B8 and B20 are never left locked alone. Ctrl-C, Stop or killing the scan restores your original bands and antenna.

## Commands
```bash
python3 bandscan.py status                 # mode, bands, antenna, cell, RSRP/RSRQ/SINR
python3 bandscan.py watch                  # live meter for aiming the antenna
python3 bandscan.py scan                   # test default combos, apply the best
python3 bandscan.py scan --speedtest       # rank by real download speed (recommended)
python3 bandscan.py scan --explore         # also try B28 / B38
python3 bandscan.py scan --antennas external internal   # compare antennas too
python3 bandscan.py scan --full --include-3g --speedtest  # every combo + 3G/H+, ranked by real speed
python3 bandscan.py scan --recheck-only                   # quick: re-test the best 3 from history
python3 bandscan.py history                               # track record of all saved scans
python3 bandscan.py debug                                 # which login/token method the router accepts
python3 bandscan.py scan --candidates 1 3 1+3 --no-apply
python3 bandscan.py apply --bands 1+3      # your known-good setting (LTEBand=5)
python3 bandscan.py apply --bands 1        # "pin the cell" 28057964 (no 4G+)
python3 bandscan.py reset                  # all bands (LTEBand=20880800C5)
python3 bandscan.py antenna external
```

## How a scan works
1. Saves the current `LTEBand` and `NetworkMode`.
2. For each combo it sets LTE-only and the band mask, waits for `ConnectionStatus=901`, then takes 6 signal samples and records the median.
3. Optional: measures latency and runs a Cloudflare download test.
4. Ranks the combos. Real Mbit/s counts most when measured; otherwise the score uses SINR, then RSRQ, then RSRP, with a bonus for 4G+ (CA).
   With `--antennas`, every combo is tested once per antenna mode, and you also get the best result for each antenna.
5. Applies the winner (bands + antenna), or restores the original with `--no-apply` or Ctrl-C.
   Results are saved to `results/scan-*.json` and `.csv`.

Site rules from your notes: B7 has no service, and B8 and B20 are weak, so none of them is ever locked alone (`--force` overrides this). They can still appear inside combos.

## Signal guide
| Metric | Excellent | Good | Fair | Poor |
|---|---|---|---|---|
| SINR (dB) | ≥ 13 | 5–13 | 0–5 | < 0 |
| RSRP (dBm) | ≥ -90 | -90 to -100 | -100 to -110 | < -110 |
| RSRQ (dB) | ≥ -10 | -10 to -15 | -15 to -20 | < -20 |

In a weak spot, SINR matters most. Aim the antenna with `watch` before running a scan.

## Testing without the router
```bash
python3 tests/mock_router.py 8765 &
ROUTER_HOST=127.0.0.1:8765 ROUTER_PASSWORD=test python3 bandscan.py scan --settle 4 --samples 2
```
