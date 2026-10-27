# CamHound development notes

Developer material for `library/user/reconnaissance/CamHound` and its Recon-menu hooks. Nothing in
this folder runs on the Pager; it is for whoever builds the next phases.

**Start at `/CLAUDE.md`** for repo-wide orientation: the three-copy edit contract and its validation
commands, a code map of the payload by rung, which document answers which question, and the firmware
facts that are settled so they do not get re-derived.

## Files

| File | Purpose |
|---|---|
| `PLAN_v2.md` | the full recon design: user answers, adopted ideas, confidence model, feature list, phases, the Phase 0 spike table (section 7.1) |
| `RESPONSE.md` | the response side (the Disrupt rung): why CSA works where deauth cannot, the undocumented firmware primitives, the posture model and its element/bit references, target resolution, the channel lock, the verdict model, block placement, and what is still unverified |
| `gen_hooks.sh` | regenerates `library/recon/{client,access_point}/CamHound/` from the user payload (header + config + lib block + watch-core block + `hook_main.sh`) |
| `check_sync.sh` | fails when the shared blocks differ between the user payload and the hooks |
| `hook_header.sh`, `hook_main.sh` | the hook-only parts |
| `harness/run_harness.sh` | laptop harness: stub DuckyScript commands, fake `_pineap`/`tcpdump`/`iwinfo`, RECON fixtures; scenarios live, stimulus, lock, nojq, locate, disrupt, persist, settings |

Rule: edit the user payload, then `gen_hooks.sh`, then `check_sync.sh`, then `payload.sh --selftest`
and `harness/run_harness.sh`. The lib block (`# --- camhound lib begin/end ---`) and the watch-core
block (`# --- watch core begin/end ---`) must stay self-contained: everything Watch and Locate need
lives inside them.

## Status

Coded and verified on a laptop only (selftest **112/112**, harness scenarios green, shellcheck
clean). The v1.1 Recon hooks are generated and checked the same way. **No Pager has run any of it.**

The payload is recon **and response**: it was renamed from CamScout when the Disrupt rung landed.
The recon tiers are unchanged and still passive; the response tier is the only part that transmits
and is off by default (`RESPONSE=0`). Its design, the firmware primitives it calls and the list of
what remains unverified are in `RESPONSE.md`.

## Roadmap

1. **Phase 0, on-device spikes** (SSH, about an hour, Pager plus the lab camera). Section 7.1 of
   the plan lists each command, the code path it decides and the coded fallback. Gating rows:
   tool presence and `hexdump -e`; `oui.txt` layout; RECON CLIENTS JSON fields (`signal`,
   `packets`, `probes`, `ap_mac`); per-cycle cost; `_PAYLOAD_HOME` and own MACs; `iw phy` bands;
   EXAMINE lock read-back, channel width and 10x re-lock; MONITOR line rate; the `-s 32 -w`
   capture primitive, direction filters, three concurrent captures, parse time; CPU budgets
   (25 % scan, 25/60 % Watch); `timeout N WAIT_FOR_BUTTON_PRESS A B` and dialogs outside the wait
   loop; LIST_PICKER capacity and row width; whether UI Cancel runs the trap; `LED AMBER`,
   multi-argument `VIBRATE`, `RINGTONE alert`; `PAYLOAD_*_CONFIG` semantics; data frames under the
   lock per band; hop period. Outcome: a spike log and changed config values, no redesign.
2. **Phase 0b, calibration** (`KEEP_RAW=1`, nine 3-minute Watch runs at two positions): freezes
   `BUSY_PPS`, the NEAR/FAR offsets per band and `THR_STREAM_UP`; fills T1-T3 in the README test matrix.
3. **Phase 3 device exit**: STREAM on live view, IDLE when stopped, EVENT on a wave; INCONCLUSIVE
   shows the lock read-back; Cancel mid-Watch leaves no tcpdump; a second instance refuses; T4
   identity precision; battery figures.
4. **Phase 3b, blind room test**: one camera, five rooms, LIKELY within two cycles in the same room,
   zero CONFIRMED in empty rooms.
5. **Phase 4 remainder**: clean install from a Windows zip, `PAYLOAD_DEL_CONFIG` of every
   calibration override, Measured column filled.
6. **v1.1, one PR each, with on-device evidence**: Recon hooks (generated here; hook spike:
   Recon keeps growing while the hook runs, Cancel runs the trap); inventory persistence across
   runs (`DEDUPE_H`, clock guard, 30-day prune); settings menu (NUMBER_PICKER for five keys, Reset
   via `PAYLOAD_DEL_CONFIG`); band write (`PINEAPPLE_SET_BANDS wlan1mon 2 5 [6]`, restored at exit,
   gate: no pineapd restart); WPS/IE peek (`tcpdump -xx -s 1024 -c 12` on beacons and probe
   responses, WPSMODEL +45/+40 as a new identity class, `ie_sig` column); retry percentage via
   BPF `wlan[1] & 0x08`; LAN confirm v1.1b (`LAN_CONFIRM=1`, 2.4 GHz join on wlan0cli, ARP
   candidates that are scored rows, port precheck, RTSP OPTIONS/DESCRIBE over `/dev/tcp`, ONVIF
   probe; FEED +45 identity class, AUTH/RTSP/ONVIF +30, vendor port +15); in-lock wide-channel
   Watch (`iw dev wlan1mon set freq <f> 80 <centre>` only after the lock stopped hopping).
7. **v2 and later**: multi-channel passive behaviour sweep riding PineAP's hop; byte-exact rates
   and keepalive period as a class label; retry/sequence dedupe at `-s 128`; sqlite fallback if a
   RECON row cap is proven; BLE co-hit; real pocket mode (DISABLE_DISPLAY); external capture radio;
   MODE persistence.

Out of CamHound's scope by design: DEVICE_FILTER response hooks, WiGLE upload, generated OUI
tables, per-row weights, BLE-only lists, `iw set channel` while PineAP hops, recon.db reads per
cycle, SSDP/active mDNS/nmap auto-install, `exec "$0"`.

Disconnection is now **in** scope: the payload was renamed from CamScout to CamHound when the
response side landed, and `RESPONSE=1` adds a Disrupt rung offering deauth+disassoc, channel-switch
announcements, or all three. It is off by default, so with `RESPONSE=0` the payload transmits
nothing and behaves exactly as the recon-only build did. See `RESPONSE.md`.
