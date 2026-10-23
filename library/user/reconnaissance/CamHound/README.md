# CamHound

Wi-Fi camera census and response for the WiFi Pineapple Pager — the recon+response successor to
CamScout, which it replaces. Detection is unchanged and still passive; what is new is that a
detection can now be acted on from the same screen that found it.

CamHound reads the PineAP Recon lists
every 20 s, lists every camera-vendor and camera-capable 802.11 device it can hear, categorises it,
grades it on a 0-100 confidence scale with reason tags, and, on request, locks the radio on one
suspect to test whether it is streaming (**Watch**), whether it reacts to movement (**Stimulus
test**) or where it is (**Locate**). Identity scanning is passive and free. Watch and Locate pause
Recon channel hopping for the length of the lock (30-120 s). CamHound never joins a network.

With `RESPONSE=1` a fourth rung appears on the device card — **Disrupt** — which reads the target's
protection posture from its own beacon and then disconnects it with deauthentication and
disassociation, channel-switch announcements, or all three. See [Response](#response).
**`RESPONSE` defaults to 0**, and with it off CamHound transmits nothing and behaves exactly as
CamScout did. `AUTO_RESPOND=1` additionally lets the funnel raise Disrupt by itself once a Watch
confirms a device is streaming; it is a second key precisely because that rung transmits.

## What it cannot see

- A camera that is powered off, or one that only records to a card and never talks to Wi-Fi.
- Wired (PoE) cameras. Only the NVR/base station may show up, as an AP or a client.
- 6 GHz devices unless 6 GHz is enabled in the Recon settings (status line says `6 GHz not scanned`).
- 5 GHz 40/80 MHz streams may be invisible to Watch if the lock parks the radio at 20 MHz (Phase 0 item 28).
- Sub-300 kbps streams and Wi-Fi 6 UL-OFDMA uplinks under-count in Watch (frames under 1000 bytes
  are not "big"); Watch reports them as IDLE or NONE.
- Brand from a module OUI: Ring Doorbell Pro, eufy and most white-label cameras sit on Liteon, USI,
  AzureWave, Sercomm or Espressif blocks and surface only in the **Unidentified modules** list until Watched.
- A battery/event camera that is asleep looks idle in Watch. Use the Stimulus test.
- INCONCLUSIVE is about the measurement (lock, band, distance), not about the device.

## How it works: four tiers

1. **Identity** (free, every device, every cycle): OUI/vendor rows, setup-mode SSIDs, hidden-SSID
   plus camera vendor, a kit signal (AP and all clients share one camera brand), probed camera SSIDs,
   a packet-rate BUSY hint. Negative rows: randomised client MAC (-40), endpoint maker such as Intel
   or Apple (-25).
2. **Behaviour** (30-120 s channel lock, one suspect at a time): header-only tcpdump captures split
   by direction in the kernel (`wlan addr2` = uplink, `wlan addr1` = downlink), parsed with
   hexdump+awk. Live view grades STREAM / DOWN / IDLE / NONE / INCONCLUSIVE; the Stimulus test
   grades EVENT / EVENT? by comparing a 30 s still baseline with 20 s of you moving in front of it
   plus a 20 s settle window.
3. **Response** (opt-in, off by default): reads the target's PMF and beacon-protection posture from
   its own beacon, then disconnects it with deauth+disassoc, channel-switch announcements, or all
   three, and judges from Recon whether it actually went quiet. This is the only tier that
   transmits, and it does nothing unless `RESPONSE=1`. See [Response](#response).
4. **Active LAN** (opt-in, not in this version): joining the network to confirm an RTSP/ONVIF feed
   is planned as `LAN_CONFIRM=1` in v1.1b and is off by default.

## Install

1. Copy the `CamHound` folder to `/root/payloads/user/reconnaissance/CamHound/` (or the same path on
   `/sd` or `/mmc/root`). Keep `cam_signatures.txt` next to `payload.sh`; without it a built-in copy
   of the rows is used and the status line says `(built-in)`.
2. If the files came through Windows: `sed -i 's/\r$//' payload.sh cam_signatures.txt; chmod +x payload.sh`.
3. Start **Recon in continuous mode** in the Pager GUI. CamHound only reads what Recon hears.
4. Launch CamHound from the payload menu. Needs `_pineap`, `jq` (falls back to a built-in parser),
   `tcpdump` + `hexdump` for Watch (without them Watch is greyed), `/lib/hak5/oui.txt`.

## Quick start, the two-button flow

- **Scan**: the status line updates every cycle: `HH:MM 123+4 T85 U12 B3 [ROOM]` = devices, new scored
  this cycle, top new score, module-OUI clients, busy clients, mode. The first cycle is a silent
  baseline. New LIKELY rows come as a yellow block with one short vibe; new CONFIRMED rows as a red
  block with a triple vibe.
- When something scores CONFIRMED or LIKELY you get one dialog: **Watch now?** (A = yes, B = no). A
  STREAM or EVENT verdict is followed by **Locate?**. That is the whole flow: two presses.
- **B** during a scan opens **Review hits** (hold it up to one cycle). Rows read
  `conf tags prox role rssi`, e.g. `90 HIK-OUI NA-58` = confidence 90, Hikvision OUI, NEAR, AP, -58 dBm.
  Pick a row for the detail card: `Watch`, `Locate`, `Ignore for session`, `Back`.
- **Unidentified modules: check these** lists Espressif/Realtek/Liteon-class clients sorted busy-first.
  They are not cameras until Watched.
- **Mode**: `ROOM` (default: vibrate on everything LIKELY, proximity -60/-75 dBm) or `SITE` (floor
  walk: FAR rows do not vibrate, -70/-85 dBm). Mode never changes what is listed.
- **Write report** renders `/root/loot/CamHound/report_<run>.txt` now; it is also written every 15
  cycles and at exit.

Buttons: A = select / stop (Watch, Locate), B = back / pause, UP and DOWN scroll lists only.

## Confidence model

Two axes, one number. Identity `I` is the sum of identity rows; behaviour `Bh` the sum of Watch,
stimulus and BUSY rows. `conf = I_eff + Bh_eff`, where a single identity class caps `I_eff` at 69,
behaviour without identity caps `Bh_eff` at 69 (the yellow **STREAM lane**), and a negative
behaviour row never lowers a grade that identity alone earns.

| Band | conf | Colour | Reachable by |
|---|---|---|---|
| CONFIRMED | 80-100 | red | two independent identity classes summing 80+, or one class of 45+ plus STREAM/EVENT behaviour |
| LIKELY | 45-79 | amber | camera-brand hardware, or a mixed vendor that streams, or any device that passed the stimulus test |
| POSSIBLE | 20-44 | white | one weak signal (mixed vendor, camera word in the SSID); list only, no vibe |
| STREAM lane | 20-69 | yellow | streaming-like behaviour with no identity (webinar laptop or a module camera); never vibrates |
| MODULE | 0 | white, own list | IoT radio module, brand unknown |

Identity classes: OUI (OUI/VENDOR/VENDOR_WEAK rows), SSID (SSID/SSID_WEAK rows), KIT. Fixed tags
(HIDDEN +10, RAND -40, PROBE +5, KIT? +10, MODULE 0, BUSY +10) never count as a class. A randomised
MAC caps at 69, an endpoint vendor at 79 unless it passes the stimulus test.

Worked examples (all in `payload.sh --selftest`): Hikvision OUI AP beaconing `EZVIZ_xxxxxxxxx` = 90
CONFIRMED. Wyze client alone = 45 LIKELY; + Watch STREAM = 100 CONFIRMED; + Watch DOWN = 45 LIKELY
with verdict DOWN. TP-Link client on a `Tapo_Cam_` AP = 65 LIKELY. Idle Blink on an Amazon OUI = 20
POSSIBLE. Espressif client alone = modules list; + STREAM = 55 yellow lane; + EVENT = 75 LIKELY.
Intel laptop on a video call = 30 yellow lane, never red. Reolink AP with two Reolink clients = 80
CONFIRMED kit, one alert on the AP. TP-Link AP "Camden Hotel" = 20 POSSIBLE (`cam` must be a word).

Behaviour rows: STREAM +55 (rate 30, or 35 at 25+ big fr/s; sustained 20 s +10; up-heavy +15),
EVENT +60, EVENT? +40, up-heavy only +15, BUSY +10, down-heavy -20. All weights and thresholds are
lab starting points; the test matrix below carries the measured values.

Categories (from the highest identity row): SECURITY, DOORBELL, BABY, ACTION, DASH, DRONE,
BODYCAM, ALPR (reserved: no Wi-Fi signature is verified; use Flock_Detect over BLE), NVR/KIT,
MIXED, IOT-MODULE, ENDPOINT, UNKNOWN.

## Watch

- **Live view**: six 10 s windows, double-buffered captures, A stops after the current window.
  STREAM needs four windows at streaming rate, so stopping before 40 s can give NONE at best.
  Each window prints `w3 10.0s U 196k D 4k as 48.9` and `big 14.2/s oth 3`. Verdict words:
  `STREAM` steady big uplink; `DOWN` download-heavy (call, update, phone); `IDLE`/`QUIET` small
  frames only; `NONE` traffic without a camera pattern; `INCONCLUSIVE` nothing from the target in
  the first two windows (the screen shows the lock read-back, Recon's last RSSI and age).
- **Stimulus test (~90 s)**: waits for the uplink to settle, `Baseline 30s. Keep still.`, then
  `Now move 20s: walk, wave, lights`, then 20 s settle. EVENT when the uplink jumps 2x (and reaches
  8 big fr/s, up-heavy); EVENT? at 1.5x. `Repeat (n/3)` keeps the best run. A no-change result
  means asleep, disarmed, in cooldown, local-record, or not a camera (Blink 30-60 s cooldown, Wyze
  free tier 5 min).
- Rates are shown as a band (`<0.5 / 0.5-2 / 2-8 / >8 Mbps`); the same camera's band can differ 2x
  at night (IR). Compare badges, not Mbps. `(weak)` marks a non-STREAM verdict taken below -72 dBm.
- Setup-mode APs (EZVIZ_, Tapo_Cam_, BLINK-, Ring-) are never auto-offered Watch: they are not
  streaming. You can still Watch them from the card.

## Locate

`_pineap MONITOR <mac> any` RSSI with a 5-sample median, four LED tiers (blue, cyan, yellow, red),
a click per sample and a vibe at the hot tier, 3 dB hysteresis, `stale Ns` when no new reading
arrives. A stops. AP targets refresh fast; a client refreshes only when it transmits (an idle
camera may show `quiet 45s (idle cam?)`). Randomised probe-only MACs get no Locate offer.

## How to sweep a room

Start Recon in continuous mode. Stand at the doorway for two cycles (40 s) for the baseline. Walk
the perimeter and pause one full cycle per wall and corner: RSSI is last-seen per cycle, so
position beats dwell. A drywall partition costs 1-3 dB, 100 mm brick 4-8 dB, 100 mm concrete
6-15 dB; only a structural wall or floor costs 15-30 dB, so absolute RSSI is never a room-boundary
test. Hold the Pager away from the body in the same orientation and move in steps of 0.5 m or more.
Watch works from the same room or within ~10 m. Idle cameras refresh slowly: use Locate. For a
street survey keep a steady pace and set `GPS=1`; `inventory.tsv` keeps the strongest reading's fix.

## Configuration

Edit the config block at the top of `payload.sh`. Starred keys can also be set without editing and
survive updates: `PAYLOAD_SET_CONFIG camhound CYCLE_SECS 10` (`PAYLOAD_DEL_CONFIG camhound CYCLE_SECS`
removes it). Overrides are counted on the start screen and listed in `events.log`.

| Key | Default | Persist | Meaning |
|---|---|---|---|
| MODE | ROOM | menu | ROOM or SITE |
| CYCLE_SECS | 20 | * | scan period (floor 5) |
| COOLDOWN_SECS | 600 | * | re-alert suppression per MAC; re-alert only after it moves into MID or better |
| ALERT_DIALOG | 1 | * | blocking ALERT on NEW CONFIRMED when AUTO_WATCH=0 |
| AUTO_WATCH / AUTO_LOCATE | 1 / 1 | * | the two-press funnel; set 0 for walk surveys |
| AUTO_WATCH_RSSI | -72 | | minimum last RSSI to auto-offer Watch |
| RSSI_MIN | 0 | * | optional list gate on the session's best RSSI (0 = widest net) |
| SOUND | 0 | * | ringtone on CONFIRMED |
| SHOW_MODULES | 1 | | modules list in the menu |
| MODULE_HINT_RSSI | -55 | | one-time "module strong+busy: Watch?" hint |
| BUSY_PPS / BUSY_CYCLES | 10 / 2 | | BUSY = rate floor for N cycles and top-3 on the band |
| WIN_SECS / LIVE_WINDOWS | 10 / 6 | | Watch window and count |
| WIN_BASE_S / WIN_STIM_S / WIN_POST_S / QUIET_SECS | 30 / 20 / 20 / 15 | | stimulus windows |
| THR_STREAM_UP | 10 | * | big uplink frames/s for STREAM |
| THR_ASYM10 / THR_CV10 / THR_DOWN10 | 30 / 6 / 25 | | x10: up-heavy 3.0, steady 0.6, down-heavy 2.5 |
| THR_DELTA10 / THR_DELTA_WEAK10 / THR_STIM_UP | 20 / 15 / 8 | | stimulus 2.0x, 1.5x, 8 big fr/s floor |
| BIG_BYTES | 1000 | | "big frame" threshold |
| WATCH_MIN_RSSI | -72 | | weak-signal warning on the Watch header |
| WATCH_OTHERS | 1 | | third capture "others on this BSS" (Phase 0 item 13c decides CPU) |
| RELOCK_PER_WINDOW | 0 | | re-issue the lock before every window (Phase 0 item 8) |
| MAX_RUNS | 3 | | stimulus repeats per target |
| REPORT_EVERY | 15 | | cycles between report rewrites |
| GPS | 0 | | closest-approach GPS stamping |
| KEEP_PCAP / KEEP_RAW | 0 / 0 | | keep Watch pcaps / per-second bucket lines in loot |
| DEDUPE_H | 0 | * | hours: a device stored in inventory.tsv within this horizon is not alerted again unless its band rose or it is 10 dB closer; `Scan (fresh)` ignores it for one run |
| INVENTORY_KEEP_DAYS | 30 | | inventory.tsv rows older than this are pruned at start (0 = never) |
| ROW_W | 22 | | list row budget (36-40 expected after Phase 0 item 19) |
| RESPONSE | 0 | * | master switch for the Disrupt rung; 0 = recon only, nothing transmits |
| RESPONSE_CONFIRM | 1 | * | blocking confirmation before any transmit |
| POSTURE_TTL | 300 | * | seconds a posture badge stays cached per BSSID |
| RESP_SETTLE_SECS | 6 | * | wait after transmitting before re-reading the target to judge the effect |
| BCN_CAP_SECS / BCN_CAP_COUNT | 4 / 5 | | beacon capture window and frame count for a posture read |
| RESP_LOCK_SECS | 20 | | EXAMINE lock duration held across a response |

## Response

Off by default. `PAYLOAD_SET_CONFIG camhound RESPONSE 1` adds **Disrupt** to the device card.

**1 · Posture.** The badge comes from the target's own beacon, captured on `RECON_IF` — the only
source that covers every band, since `radio0` is 2.4 GHz-only and `radio1` carries no managed
interface, so no `iw scan` on this device can read 5/6 GHz RSN. CamHound reads MFPC (bit 7) and
MFPR (bit 6) from the RSN Capabilities field of element 48, and Beacon Protection from bit 84 of
the Extended Capabilities element (127). Badges cache per BSSID for `POSTURE_TTL`; a failed read (`?`) is not cached, and the beacon is
captured under a short channel lock when no Watch lock is held, since Recon hops while unlocked.

| Badge | Meaning | deauth+disassoc | CSA |
|---|---|---|---|
| `D+C` | no PMF | works | works |
| `D?+C` | PMF optional (transition mode) | per-client | works |
| `C` | PMF required (WPA3) | ignored | works |
| `NONE` | PMF + beacon protection | blocked | blocked |
| `NOINJ` | DFS 5 GHz or 6 GHz channel | cannot transmit | cannot transmit |
| `?` | no beacon captured | unknown | unknown |

`D?+C` cannot be resolved from a beacon alone, because PMF is negotiated per client — a transition
-mode BSS can hold both protected and unprotected clients at once. `NOINJ` is a regulatory wall,
not a property of the target: cfg80211 marks DFS and 6 GHz channels no-initiate-radiation for a
monitor interface, so frames are dropped before they reach the air whatever the target's posture.

**2 · Attack.** All three are always offered, ordered by what the beacon says will work and
labelled `works` / `partial` / `blocked` / `unknown`. The badge advises; you decide. If nothing is
expected to work you are asked once, then may proceed anyway.

| Option | Command | Frames |
|---|---|---|
| `DEAUTH` | `PINEAPPLE_DEAUTH_CLIENT [bssid] [target] [channel]` | deauth + disassociation |
| `CSA` | `PINEAPPLE_DEAUTH_CLIENT_CSA [bssid] [channel]` | channel-switch announcements |
| `BOTH` | `PINEAPPLE_DEAUTH_CLIENT_ALL [bssid] [target] [channel]` | all three |

An AP target is attacked broadcast (`ff:ff:ff:ff:ff:ff`); a client target is attacked through its
own AP's BSSID on that AP's channel. An unassociated client has no BSS to announce from and is
refused. CSA takes no target because it rides in a beacon.

**3 · Verdict.** Every kernel-side drop path reports success, so "we sent it" proves nothing. The
channel is locked with the same `lock_target` Watch uses (verified read-back, falling back to a
channel lock, aborting if the radio is still hopping), and after `RESP_SETTLE_SECS` the target is
re-read from Recon:

| Verdict | Means |
|---|---|
| `MOVED` | gone from Recon, or its packet counter stalled with nothing newer seen |
| `NO_EFFECT` | packet counter still advancing — it never left |
| `INCONCLUSIVE` | no baseline, no follow-up reading, or the counter stalled but it was seen again |
| `LOCK_FAILED` | the radio would not hold the target channel; nothing was transmitted |
| `NO_CLIENTS` | AP target with no visible clients; refused before anything was transmitted |

A broadcast attempt (AP target) is measured on the AP's visible, non-randomised clients, since the AP
itself keeps beaconing whatever happens: `responses.tsv` gets one row per client with that client as
`target`, and the verdict shown is the aggregate (`MOVED` only when every client went quiet,
`NO_EFFECT` when any kept transmitting, `INCONCLUSIVE` otherwise). An AP with no visible clients is
refused. Recon's packet counter is direction-blind, so a disconnected client that keeps probing still
reads as transmitting.

Beacon protection (WPA3, Dec-2020 onward, mandatory for AP support in Wi-Fi 7) defeats the CSA
path outright, and CSA bursts are detectable — Kismet alerts on CSA floods and on announcements
that reuse a captured beacon's timestamp.

## Loot (`/root/loot/CamHound/`, flat)

- `inventory.tsv`: one `|`-separated row per MAC, rewritten atomically each cycle and kept across runs:
  `first_seen`, `n_seen`, the strongest RSSI with its time and GPS fix, and Watch evidence (`beh_score`,
  `beh_verdict`) carry over, rows older than `INVENTORY_KEEP_DAYS` are pruned at start, randomised
  client MACs are never stored, devices known from an earlier run carry the `SEEN` tag, and the report
  counts them as `returning`. Header:
  `#first_seen|last_seen|run_id|mac|role|cat|vendor|label|conf|id_score|beh_score|beh_verdict|band|ssid|ap_bssid|ch|freq|rssi_best|rssi_best_ts|rssi_last|prox|n_seen|pkt_rate|signals|lan_tag|lat|lon`
  (`band` = 2/5/6 GHz, `signals` = tags, epoch seconds, `-` for empty). ~160 B per MAC.
- `events.log`: `epoch level msg` (cycle, alert, mode, watch, locate, cfg, warn, run, resp).
- `responses.tsv` (only once a response is fired): one `|`-separated row per attempt. Header:
  `#epoch|mac|role|bssid|target|ch|band|badge|rsn_caps|beacon_prot|attack|cmd|lock|pk_before|pk_after|verdict`
  (`rsn_caps` is the raw 2-octet RSN Capabilities field, low octet first; `beacon_prot` is octet 10
  of the Extended Capabilities element, or `-` when absent).
- `watch_<run>_<mac>.tsv`: one row per Watch episode:
  `#epoch|mac|role|bssid|ch|freq|mode|run|secs|up|down|asym|cv|delta|rec|drops|verdict|batt_start|batt_end|charging`.
- `report_<run>.txt`: headline counts, suspects by confidence, vendor census, AP-to-client tree
  (`BASE?` marks a hidden AP with 1-4 clients on a module/mixed OUI), modules, GPS, footer.
- `raw_<run>.txt` (KEEP_RAW=1) replays on a laptop: `bash payload.sh --replay <file>`.

## Laptop checks

`bash payload.sh --selftest` runs 39 checks (signature lint, both oui.txt layouts, every worked
example above, proximity, row width, pcap parser) with `LOG`/`LED` stubbed; `--replay <pcap or
bucket file>` runs the Watch parser on a saved window. BusyBox `hexdump` and `awk` are enough.

## Test matrix (fill the Measured column on your unit)

| Check | Target | Measured |
|---|---|---|
| T1 STREAM recall, HD live view, same room | >= 0.95 of windows | |
| T2 STREAM on controls (browsing, download, idle) | <= 0.05 | |
| T3 INCONCLUSIVE on an associated live-view camera within 10 m | <= 0.10 of attempts | |
| T4 identity precision, 20-minute scan, hand-verified | CONFIRMED 1.0, LIKELY >= 0.8 at -60 dBm | |
| CPU idle scan (300+ devices) | <= 25 % of the core | |
| CPU Watch, busiest channel / 20 Mbps upload on channel | <= 25 % / <= 60 %, 0 kernel drops | |
| Blind room test, 5 rooms | LIKELY within 2 cycles, zero CONFIRMED in empty rooms | |
| Battery: 30 min scan / 10 min Watch / 5 min Locate | report range, charging=no | |

Phase 0 items referenced above are the on-device spikes in the project plan (lock read-back,
client JSON fields, capture primitive, dialog delivery, row width). Until they are run, the status
line says `prox: uncal` and proximity thresholds are the defaults.

## Background

Informed by DeWiCam (Cheng, Ji, Lu, Xu, ASIACCS 2018) for the uplink-rate test, Lumos (Sharma,
Soltanaghaei, Rowe, Sekar, USENIX Security 2022) for the RSSI walk, and SnoopDog (Singh, Garcia,
Noor, Srivastava, USENIX Security 2021) and Liu et al. (MobiSys 2018) for stimulus-response. Those
papers evaluated continuously streaming devices; Watch inherits their blind spot for event cameras,
which is why the Stimulus test exists. Credits: device_hunter (MONITOR loop), SkimmerScanner
(signature file, install-dir probe), SignalFence and live_probe (wlan1mon capture), find_hackers
(RECON JSON shape), Tunnel_Rat (EXAMINE lock from a user payload).

## Contributing a signature

Add one `TYPE|CAT|LABEL|PATTERN  # note` line to `cam_signatures.txt` (format in the file header),
run `bash payload.sh --selftest`, and state in the note how the row was verified. Do not add
weights: they are fixed per TYPE. Ship unverified rows commented out.

## Roadmap

v1.1: Recon-menu hooks (`library/recon/client|access_point/CamHound`), inventory persistence across
runs, settings menu, band write (`PINEAPPLE_SET_BANDS`), WPS/IE peek, LAN confirm (opt-in RTSP
DESCRIBE). v2: multi-channel passive behaviour sweep, BLE co-hit, pocket mode, external capture radio.
