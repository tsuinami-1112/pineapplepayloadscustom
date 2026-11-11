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

A fourth rung sits on the device card — **Disrupt** — which reads the target's protection posture
from its own beacon and then disconnects it with deauthentication and disassociation, channel-switch
announcements, or all three. See [Response](#response).
**`RESPONSE` defaults to 1**, so recon and response are both live out of the box. Set it to 0 —
Settings → Response settings, or `PAYLOAD_SET_CONFIG camhound RESPONSE 0` — for a recon-only run
that transmits nothing and behaves exactly as CamScout did. Only **DEAUTH on a client row** is
aimed at one device: `CSA` has no target argument at all and `BOTH`'s is discarded, so both hit
every client on the BSS, and an AP row resolves the target to broadcast so *everything* is BSS-wide
there. The picker marks the broad options ` bss` and the confirm names the real blast radius.
`AUTO_RESPOND=1` additionally lets the funnel *offer* Disrupt by itself: after a Watch
confirms a device is streaming, or for a newly CONFIRMED device the Watch and Locate offers did not
take (with `AUTO_WATCH=0` that is every new CONFIRMED device). The offer is a dialog, and
`RESPONSE_CONFIRM` still gates the transmit; it is a second key precisely because that rung transmits.

## What it cannot see

- A camera that is powered off, or one that only records to a card and never talks to Wi-Fi.
- Wired (PoE) cameras. Only the NVR/base station may show up, as an AP or a client.
- 6 GHz devices unless 6 GHz is enabled in the Recon settings or `BAND6=1` (Settings → Recon settings)
  writes it for the run; the status line says `6 GHz not scanned` otherwise.
- 5 GHz 40/80 MHz streams may be invisible to Watch if the lock parks the radio at 20 MHz (Phase 0 item 28).
- Sub-300 kbps streams and Wi-Fi 6 UL-OFDMA uplinks under-count in Watch (frames under 1000 bytes
  are not "big"); Watch reports them as IDLE or NONE.
- Brand from a module OUI: Ring Doorbell Pro, eufy and most white-label cameras sit on Liteon, USI,
  AzureWave, Sercomm or Espressif blocks and surface only in the **Unidentified modules** list until Watched.
- A battery/event camera that is asleep looks idle in Watch. Use the Stimulus test.
- INCONCLUSIVE is about the measurement (lock, band, distance), not about the device.

**Which AP a client is associated to — until you ask.** `_pineap RECON CLIENTS` is new in 2.0.0; on
1.1.3 it is `Unknown recon command` (measured 2026-11-03), so CamHound reads clients from
`RECON DEVICES` there (a device that neither beacons nor answers probes). Both verbs return the same
object, which carries probed SSIDs but **no association field** (CLAUDE.md §"2.0.0-stable,
analysed"). So every client starts out unassociated: its `ap_bssid` column reads `-`, and kit
detection, client Watch and Stimulus, and per-client Disrupt are dormant for it.

CamHound can read the AP off the air instead, one client at a time, when you ask for it. A client
card with no AP offers **`Watch (find AP first)`** and **`Disrupt (find AP first)`**: picking either
pauses Recon for about nine seconds, parks the radio on the channel the client was last heard on,
listens for the client's own data frames, and reads the BSSID from them. Then it carries on into the
menu you picked. The answer is kept for the run — the inventory, the kit tags and the report's
AP→client tree pick it up at the next cycle — and once it is older than `ASSOC_TTL` it is looked at
again whenever Watch or Disrupt opens on that client, from the card or from one of the automatic
offers. A look that does **not** re-confirm the AP keeps the old answer and is not repeated for
another `ASSOC_TTL`, so the picks in between open the menu straight away with nothing said; with
`ASSOC_TTL=0` every pick looks again. An AP-row Disrupt does the same for every client it hears transmitting to that AP. Only the
client's own frames count as evidence of where it is: an AP keeps sending to a client for a while
after the client has gone, which is exactly what is on the air after a Disrupt that worked. When the
lookup finds nothing it says why and the card is unchanged:

| It says | It means |
|---|---|
| `not heard on ch N in 6s` | no data frame from the client on that channel in the window. An idle or sleeping camera, or a client last heard off its AP's channel. **Not** "unassociated". Try again while it is busy |
| `heard on ch N (k of its own frames) but no AP twice` | the client was heard, but too little to name an AP from. Try again |
| `itself not heard on ch N (k records, none of its own)` | frames addressed to the client were captured and none it sent: it has left, moved channel, or is out of earshot. Nothing is recorded |
| `itself not heard on ch N: only X sending to it (k frames)` | AP X is transmitting to the client and the client is not answering: it has left X, moved channel, or is out of earshot. Nothing is recorded. If you have just disconnected it, rescan and look again |
| `talks to X (n) and Y (m): not deciding` | the client sent n frames to X and m to Y, neither clearly ahead (a roam, or a mesh). Nothing is recorded |
| `not parked on ch N` then `listening across the hop instead` | the radio would not hold the channel, so it listens while hopping for three times as long. Slower and less likely to hear a quiet client, not broken |
| `snap … too small for radiotap …` | raise `CLI_CAP_SNAP` |

One more state follows a lookup that had to listen across the hop: the AP was heard, but Recon has
not listed it yet, so its channel is not known. The card then reads `Watch n/a (no channel)` and
`Disrupt n/a (no channel)` rather than acting on a guess. Resume the scan; the row gets its
channel as soon as Recon lists that AP.

*Laptop-verified only: none of this has run on a Pager yet. There is no background pass — the
lookup parks the radio, so it happens only on a row you pick.*

## How it works: four tiers

1. **Identity** (free, every device, every cycle): OUI/vendor rows, setup-mode SSIDs, hidden-SSID
   plus camera vendor, a kit signal (AP and all clients share one camera brand), probed camera SSIDs,
   a packet-rate BUSY hint. Negative rows: randomised client MAC (-40), endpoint maker such as Intel
   or Apple (-25).
2. **Behaviour** (30-120 s channel lock, one suspect at a time): header-only tcpdump captures split
   by direction in the kernel (`wlan addr2` = uplink, `wlan addr1` = downlink), parsed with
   hexdump (or od) + awk. Live view grades STREAM / DOWN / IDLE / NONE / INCONCLUSIVE; the Stimulus test
   grades EVENT / EVENT? by comparing a 30 s still baseline with 20 s of you moving in front of it
   plus a 20 s settle window.
3. **Response** (on by default): reads the target's PMF and beacon-protection posture from
   its own beacon, then disconnects it with deauth+disassoc, channel-switch announcements, or all
   three, and judges from Recon whether it actually went quiet. This is the only tier that
   transmits; `RESPONSE=0` removes it and with it every transmit. See [Response](#response).
4. **Active LAN** (opt-in, not in this version): joining the network to confirm an RTSP/ONVIF feed
   is planned as `LAN_CONFIRM=1` in v1.1b and is off by default.

## Install

1. Copy the `CamHound` folder to `/root/payloads/user/reconnaissance/CamHound/` (or the same path on
   `/sd` or `/mmc/root`). Keep `cam_signatures.txt` next to `payload.sh`; without it a built-in copy
   of the rows is used and the status line says `(built-in)`.
2. **Copy the two Recon hooks as well** — `library/recon/client/CamHound/` to
   `/root/payloads/recon/client/CamHound/` and `library/recon/access_point/CamHound/` to
   `/root/payloads/recon/access_point/CamHound/`, each with its own `cam_signatures.txt`. They are
   byte-identical to each other and are what adds CamHound to the Pager's **Recon** menu, so you can
   act on a device you selected there. The Recon UI tells the hook which AP a client belongs to, and
   nothing in `_pineap`'s output does, so this is the route that has been measured on a device.
   *Amended 2026-11-11:* it is no longer the only one — a client row in CamHound's own Review list
   now reaches the same targeted frame through `Disrupt (find AP first)`, which reads the BSSID off
   the air first (see "Which AP a client is associated to"); that path is laptop-verified only, and
   a client is refused only when no lookup has named an AP for it. Skipping this step still costs
   you the Recon menu entry.
3. **If you cloned on Windows, fix the line endings — this one bites.** Git for Windows defaults
   `core.autocrlf=true`, so your working tree gets CRLF even though the repo stores LF, and the
   device then fails with `$'\r': command not found` and `not a valid identifier`. The repo carries
   a `.gitattributes` pinning `*.sh`/`*.txt` to LF, so the durable fix is
   `git config core.autocrlf false`, then re-checkout (`git rm -r --cached . && git reset --hard`).
   To repair a device that already has CRLF copies, on the Pager — using `tr` with an octal escape,
   because this BusyBox build's `sed` does not reliably read `\r` in a pattern:
   ```sh
   for f in /root/payloads/user/reconnaissance/CamHound/payload.sh \
            /root/payloads/recon/client/CamHound/payload.sh \
            /root/payloads/recon/access_point/CamHound/payload.sh; do
     tr -d '\015' < "$f" > "$f.lf" && mv "$f.lf" "$f" && chmod +x "$f"
   done
   ```
   Note that **no gate in this repo can catch this**: `check_sync.sh`, the selftest and the harness
   all run against the checkout that was committed from, never against the copy on the device.
4. **Decide whether you want the Disrupt rung armed.** `RESPONSE` ships at `1`, so a fresh install
   can transmit — behind the attack picker and a confirm, but present. For a recon-only run:
   `PAYLOAD_SET_CONFIG camhound RESPONSE 0`, or Settings → Response settings on the device.
5. Start **Recon in continuous mode** in the Pager GUI. CamHound only reads what Recon hears.
6. Launch CamHound from the payload menu. Needs `_pineap`, `jq` (falls back to a built-in parser),
   `tcpdump` plus `hexdump` or `od` for Watch and for the Disrupt rung's client capture (without them
   Watch is greyed, and a BSS-wide Disrupt from an AP row cannot list the clients it hits — it still
   fires its broadcast frame and records `INCONCLUSIVE`), `/lib/hak5/oui.txt`.
7. Worth doing once, before anything else: `bash payload.sh --selftest` **on the Pager**. It
   transmits nothing and changes nothing — every device command is stubbed, and its loot and its
   child list live in a temp directory of its own — and it is the one run that puts the parsers
   through the device's own BusyBox `awk`, `hexdump` and `jq`, which a laptop only imitates. (An
   earlier version of this step said it exercised an `od` path: there is no `od` on a Pager, and
   that fallback exists for laptops without `hexdump`.)
8. With `RECON_FRESH` at its default, launching asks Recon for a **fresh session**, so the lists
   show what is transmitting now rather than everything heard since boot. The start screen says
   `fresh Recon session requested`; if the firmware refuses it says `not confirmed` with the
   firmware's reason, and the run may list what Recon already held. This wipes the Recon session
   for anything else using it; `RECON_FRESH 0` leaves it alone.

## Quick start, the two-button flow

- **Scan**: the status line updates every cycle: `HH:MM 123+4 T85 U12 B3 [ROOM]` = devices, new scored
  this cycle, top new score, module-OUI clients, busy clients, mode. The first cycle is a silent
  baseline. New LIKELY rows come as a yellow block with one short vibe; new CONFIRMED rows as a red
  block with a triple vibe.
- When something scores CONFIRMED or LIKELY you get one dialog: **Watch now?** (A = yes, B = no). A
  STREAM or EVENT verdict is followed by **Locate?**. That is the whole flow: two presses.
- **B** during a scan opens **Review hits**, in the window the screen announces: after every cycle
  it prints `press B now to review (20s)` and waits that long (`CYCLE_SECS`) for the press. That
  wait is the only time the payload is given the button — while a cycle is being worked through the
  firmware keeps it, so press when the line appears, not before. Rows read
  `role conf tags prox rssi`, e.g. `A 90 HIK-OUI N-58` = an AP (`c` is a client), confidence 90,
  Hikvision OUI, NEAR, -58 dBm. *(Until 2026-11-11 this said "hold it up to one cycle" and gave
  the row as `90 HIK-OUI NA-58`; the role letter leads the row now.)*
  Pick a row for the detail card: `Watch`, `Disrupt`, `Locate`, `Ignore for session`, `Back`. On a
  client whose AP is not known the first two read `Watch (find AP first)` and
  `Disrupt (find AP first)` — see "What it cannot see".
- **Unidentified modules: check these** lists Espressif/Realtek/Liteon-class clients sorted busy-first.
  They are not cameras until Watched. Rows read `mac vendor proximity`, with ` busy` and ` KIT?`
  when they apply: `c0ffee000003 Espress N`. The MAC is whole because it is what the row is picked
  by; the vendor name is what gives way, so the proximity and the two markers always fit.
- **Other devices** lists what was heard in the room and is in neither list above: an AP no
  signature names, a module AP, an unscored client. Rows read `A|c label proximity rssi`, e.g.
  `A bebird-R1-0386 N-26` = an AP, fourteen characters of its SSID (else its vendor, else its MAC), NEAR, -26 dBm. FAR and
  unheard devices are left out, so it is the room and not the building, and two devices that
  would draw the same row get the tail of their MAC appended. Picking a row opens the same card
  with the cursor on Watch; a device Watched into a STREAM verdict scores its way into Review hits
  and leaves this list, so it drains as you work through it.
- **Proximity in all three lists is as of the last scan cycle.** A device reads `?` once it has
  gone 90 s without being heard, counted up to that cycle and not while you are reading a list —
  the lists are only ever drawn with the scan paused. The card's `Ns ago` is the wall-clock age.
- **Mode**: `ROOM` (default: vibrate on everything LIKELY, proximity -60/-75 dBm) or `SITE` (floor
  walk: FAR rows do not vibrate, -70/-85 dBm). Mode never changes what is listed.
- **Write report** renders `/root/loot/CamHound/report_<run>.txt` now; it is also written every 15
  cycles and at exit.

Buttons: A = select / stop (Watch, Locate), B = back / pause, UP and DOWN scroll lists only.

## Confidence model

Two axes, one number. Identity `I` is the sum of identity rows; behaviour `Bh` the sum of Watch,
stimulus and BUSY rows. `conf = I_eff + Bh_eff`, where a single identity class caps `I_eff` at 69,
behaviour without identity caps `Bh_eff` at 69 (the yellow **STREAM lane**), and a negative
behaviour row (DOWN, -20) never lowers a grade that identity of 45+ earns; below that it does lower
`conf`, so a POSSIBLE row can drop out of Review hits after a DOWN Watch.

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
removes it). Overrides are counted on the start screen and listed in `events.log`. The **Settings**
menu item does the same from the device, on two pages. **Recon settings** holds CYCLE_SECS,
THR_STREAM_UP, COOLDOWN_SECS, DEDUPE_H, RECON_FRESH, RSSI_MIN, ALERT_DIALOG, SOUND, AUTO_WATCH,
AUTO_LOCATE, BAND6, ASSOC_CAP_SECS and ASSOC_TTL (everything past the first eight sits behind
`More...`, because `Back` takes the first slot of a nine-row page);
**Response settings** holds RESPONSE, RESPONSE_CONFIRM, AUTO_RESPOND, SWEEP_TARGETED, RESP_LOCK_SECS,
RESP_SETTLE_SECS and POSTURE_TTL. Numbers go through NUMBER_PICKER, switches are On/Off. Switching RESPONSE_CONFIRM off
asks a second time, because it is the key that keeps every transmit behind a dialog; a lock shorter
than RESP_SETTLE_SECS + 5 is raised to it and saved as raised, so the menu shows what is in force.
`Reset defaults` deletes the saved overrides of all twenty keys. Changes apply at once and persist.

| Key | Default | Persist | Meaning |
|---|---|---|---|
| MODE | ROOM | menu | ROOM or SITE |
| CYCLE_SECS | 20 | * | scan period (floor 5) |
| COOLDOWN_SECS | 600 | * | re-alert suppression per MAC; re-alert only after it moves into MID or better |
| ALERT_DIALOG | 1 | * | blocking ALERT on NEW CONFIRMED when AUTO_WATCH=0 |
| AUTO_WATCH / AUTO_LOCATE | 1 / 1 | * | the two-press funnel; set 0 for walk surveys |
| AUTO_WATCH_RSSI | -72 | | minimum last RSSI to auto-offer Watch |
| RSSI_MIN | 0 | * | optional list gate, dBm, on the best RSSI known for the MAC, carried-over best included (0 = widest net; a kit AP passes when a kit client does) |
| BAND6 | 0 | * | also scan 6 GHz: writes the device's bands plus 6 for this run, trusted only when the radio is then seen on a 6 GHz channel (or uci reads it back); every issued write is put back at exit, by the watchdog if the run is killed, or at the next start; 2.4 GHz dwell drops to about a third. On bare 1.1.3 the write was a no-op with pineapd running (day-one 8c), and the status line says so |
| ASSOC_CAP_SECS | 6 | * | how long the find-AP lookup listens for one client's own frames (2 to 30; a larger value is capped); three times this when the radio will not park |
| ASSOC_TTL | 300 | * | seconds an AP learned off the air is trusted before Watch or Disrupt looks again (0 = look every time) |
| SOUND | 0 | * | ringtone on CONFIRMED |
| SHOW_MODULES | 1 | | modules list in the menu |
| SHOW_OTHER | 1 | | "Other devices" list in the menu |
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
| RECON_FRESH | 1 | * | ask Recon for a fresh session at launch, so a run shows what is transmitting now (a new session replaces the Recon list for anything else using it too; the start screen says whether the request was refused) |
| DEDUPE_H | 0 | * | hours: a device stored in inventory.tsv within this horizon is not alerted again unless its band rose or it is 10 dB closer; `Scan (fresh)` ignores it for one run |
| INVENTORY_KEEP_DAYS | 30 | | inventory.tsv rows older than this are pruned at start (0 = never) |
| ROW_W | 22 | | list row budget (36-40 expected after Phase 0 item 19) |
| RESPONSE | 1 | * | master switch for the Disrupt rung; 0 = recon only, nothing transmits |
| RESPONSE_CONFIRM | 1 | * | blocking confirmation before any transmit (Settings asks twice before switching it off) |
| AUTO_RESPOND | 0 | * | let the funnel raise Disrupt by itself (needs RESPONSE=1) |
| SWEEP_TARGETED | 1 | * | after a BSS-wide deauth, also send one targeted deauth per recovered member |
| POSTURE_TTL | 300 | * | seconds a posture badge stays cached per BSSID |
| RESP_SETTLE_SECS | 6 | * | wait after transmitting before re-reading the target to judge the effect |
| BCN_CAP_SECS / BCN_CAP_COUNT | 4 / 5 | | beacon capture window and frame count for a posture read |
| RESP_LOCK_SECS | 20 | * | EXAMINE lock held across a response; raised to RESP_SETTLE_SECS + 5 when set lower, and re-armed after the client capture |
| CLI_CAP_SECS | 4 | | seconds spent listening for who is on the target BSS (`bss` scope only) |
| CLI_CAP_COUNT | 800 | | frame cap for that capture |
| CLI_CAP_SNAP | 128 | | capture snap; must clear the radiotap header + 16 to reach the client address |

## Response

On by default. `PAYLOAD_SET_CONFIG camhound RESPONSE 0`, or Settings → Response settings, removes
**Disrupt** from the device card and with it everything that transmits.

**Scope: only `DEAUTH` on a client row hits one device.** `PINEAPPLE_DEAUTH_CLIENT_CSA` takes
`[bssid] [channel]` and has no target argument, so `CSA` is BSS-wide by its own signature;
`PINEAPPLE_DEAUTH_CLIENT_ALL` advertises a `[target]` that its handler parses and discards, so
`BOTH` is BSS-wide too. An AP row resolves the target to broadcast, so on one of those all three
options are BSS-wide. `attack_scope()` is the single place that decides; the picker appends ` bss`
to a broad option and the pre-transmit confirm reads *"on EVERY client of <bssid>"* rather than
naming one device. `posture_opts` still orders by expected efficacy, so a BSS-wide attack is
preselected on the common badges — deliberately, since demoting the attack most likely to work
would make the advice worse; the marker and the confirm carry the breadth instead.

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
| `NOINJ` | channel we cannot transmit on: DFS 5 GHz, 6 GHz, or disabled/no-IR under the live domain | cannot transmit | cannot transmit |
| `?` | no beacon captured | unknown | unknown |

`D?+C` cannot be resolved from a beacon alone, because PMF is negotiated per client — a transition
-mode BSS can hold both protected and unprotected clients at once. `NOINJ` is a gate verdict,
not a property of the target: pineapd refuses the 16 DFS channels and 6 GHz outright, and cfg80211
drops frames on channels the live regulatory domain marks disabled or no-IR. pineapd logs its refusal
and returns an error; cfg80211's drop is silent (the frame is freed and `sendto` reports success), so
CamHound refuses rather than guesses (`csa_injectable`, two gates; see `dev/pager-csa-primitives.md`).

**2 · Attack.** All three are always offered, ordered by what the beacon says will work and
labelled `works` / `partial` / `blocked` / `unknown`. The first in the list is preselected, so the
ordering is the recommendation. The badge advises; you decide — there are two gates, and both can be
overridden:

- **`NONE` or `NOINJ`** — nothing is offered. You are asked once ("Nothing is expected to work"),
  and may proceed anyway.
- **`?`** — the beacon could not be read, so none of the labels mean anything. CSA leads, because it
  works on every badge but `NONE`, and you are asked once ("Fire blind?") before the picker.

| Option | Command | Frames | Scope |
|---|---|---|---|
| `DEAUTH` | `PINEAPPLE_DEAUTH_CLIENT [bssid] [target] [channel]` | deauth + disassociation | one client (from a client row); whole BSS from an AP row |
| `CSA` | `PINEAPPLE_DEAUTH_CLIENT_CSA [bssid] [channel]` | channel-switch announcements | whole BSS |
| `BOTH` | `PINEAPPLE_DEAUTH_CLIENT_ALL [bssid] [target] [channel]` | all three | whole BSS |

An AP target is attacked broadcast (`ff:ff:ff:ff:ff:ff`); a client target is attacked through its
own AP's BSSID on that AP's channel. A client with no AP known has no BSS to announce from and is
refused — but *amended 2026-11-11*: its card offers `Disrupt (find AP first)` instead of a dead end,
and one lookup that hears the client is enough to make the row attackable. CSA takes no target
because it rides in a beacon.

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

An AP-row Disrupt whose client capture recovered **nobody** — no station heard twice, a capture cut
before the client address (raise `CLI_CAP_SNAP`), or no usable `tcpdump` — **still fires its
broadcast frame** (operator-decided 2026-11-10: *"I'll accept nuclear blast. Let the AP row fire broadcast frames."*). It
writes one `INCONCLUSIVE` row for `ff:ff:ff:ff:ff:ff` with `pk_before`/`pk_after` `-`, because there
is nothing to measure, and `events.log` names the reason: `no-members <bssid> why=NO_CLIENTS`,
`SNAP_SHORT` or `NO_CAPTURE`, then `fired … with no members recovered`. Loot written before 2026-11-10
may still carry `NO_CLIENTS`, `NO_MATCH`, `SNAP_SHORT` or `NO_CAPTURE` in the verdict column: those
rows recorded a refusal, and nothing was transmitted for them.

What is measured follows the attack's **scope**, not the row you picked. A `cli`-scope attempt
(`DEAUTH` from a client row) measures that one device. A `bss`-scope attempt (`CSA` or `BOTH` from any
row, or anything from an AP row) is measured on the BSSID's visible, non-randomised clients, since the
AP itself keeps beaconing whatever happens; the device you picked is always among them, even behind a
randomised MAC. `responses.tsv` gets one row per subject (each measured client, or the broadcast
placeholder when nobody was heard), and the verdict shown is the
aggregate (`MOVED` only when every subject went quiet, `NO_EFFECT` when any kept transmitting,
`INCONCLUSIVE` otherwise). When you picked one device and more than one was measured, a second line
`picked <mac>: <verdict>` names that device's own result, so a collateral `NO_EFFECT` cannot read as
"my camera stayed up". A subject Recon never listed before the burst is `INCONCLUSIVE`, never `MOVED`.
**Where the client list comes from.** No Pager firmware tells a payload which AP a client belongs
to, so for a `bss`-scope attempt CamHound listens for a few seconds on the target's channel and takes
the stations it hears talking to that BSSID. A station has to be heard at least twice to count, so a
camera that sends nothing in the window is missed — and an AP whose clients are all silent is
**still attacked**, blind, with the broadcast frame (operator-decided 2026-11-10; the confirm says
"on EVERY client of <bssid>"), and recorded `INCONCLUSIVE`. That listening happens under the channel lock, which is
therefore held for `RESP_LOCK_SECS + CLI_CAP_SECS + 2` and then **re-armed** for the measurement
itself, so a slow parse cannot eat the window the verdict depends on.

Recon's packet counter is direction-blind, so a disconnected client that keeps probing still reads
as transmitting.

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
- `responses.tsv` (only once a response is fired): one `|`-separated row per subject — each measured
  client, or `ff:ff:ff:ff:ff:ff` itself when an AP row fired with nobody heard — so a
  `bss`-scope attempt against a BSSID with four visible clients writes four rows for one attempt. Header:
  `#epoch|mac|role|bssid|target|ch|band|badge|rsn_caps|beacon_prot|attack|cmd|lock|pk_before|pk_after|verdict`
  (`rsn_caps` is the raw 2-octet RSN Capabilities field, low octet first; `beacon_prot` is octet 10
  of the Extended Capabilities element, or `-` when absent).
- `watch_<run>_<mac>.tsv`: one row per Watch episode:
  `#epoch|mac|role|bssid|ch|freq|mode|run|secs|up|down|asym|cv|delta|rec|drops|verdict|batt_start|batt_end|charging`.
- `report_<run>.txt`: headline counts, suspects by confidence, vendor census, AP-to-client tree
  (`BASE?` marks a hidden AP with 1-4 clients on a module/mixed OUI), modules, GPS, footer.
- `raw_<run>.txt` (KEEP_RAW=1) replays on a laptop: `bash payload.sh --replay <file>` (it keeps the
  up-direction rows of every window and reports them as one).

## Laptop checks

`bash payload.sh --selftest` runs the self-checks (signature lint, both oui.txt layouts, every worked
example above, proximity, row width, pcap parser, posture, response and settings vectors; it prints its
own count, which grows with every addition) with `LOG`/`LED` stubbed; `--replay <pcap, bucket or
raw file>` runs the Watch parser on a saved window (a raw file's up-direction rows, every window). BusyBox `hexdump` and `awk` are enough.

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

Shipped since v1: Recon-menu hooks (`library/recon/client|access_point/CamHound`), inventory
persistence across runs, the Settings menu, the response rung, the band write (`BAND6`). v1.1
remaining: WPS/IE peek, LAN confirm (opt-in RTSP DESCRIBE). v2: multi-channel passive
behaviour sweep, BLE co-hit, pocket mode, external capture radio.
