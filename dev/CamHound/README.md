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
| `harness/run_harness.sh` | laptop harness: stub DuckyScript commands, fake `_pineap`/`tcpdump`/`iwinfo`/`iw` (US-like channel table for a fixture phy dir), stub `NUMBER_PICKER`/`PAYLOAD_SET_CONFIG`/`PAYLOAD_DEL_CONFIG`, RECON fixtures (the client fixture is in the 2.0.0 `probe`-object shape, with `ap_mac` kept as a stand-in for the association the firmware does not expose; a net tree under `NET_SYSFS` names phy0 as wlan1mon's phy; `HARNESS_NO_BEACON=1` makes the fake tcpdump capture nothing, `HARNESS_NO_CLIENTS=1` refuses `RECON CLIENTS` as 1.1.3 does and serves `fix/devices.json`, the measured `RECON DEVICES` shape with sorted keys, and `HARNESS_BANDS_NOOP=1` makes the band write change nothing, as measured); scenarios live, stimulus, lock, nojq (both parsers, over CLIENTS and over DEVICES), locate, disrupt, members (the real-firmware shape -- no association at all, membership read off the air; `HARNESS_NO_MEMBERS` / `HARNESS_NO_ARM` / `HARNESS_NO_OR` / `HARNESS_SHORT_SNAP` / `HARNESS_BAD_PCAP` / `HARNESS_ALIEN_MEMBERS` drive the four refusal tokens and the uplink-only fallback filter), cliscope (the client-row Disrupt: both scopes in one menu), blind, noinj, persist, settings, bands (the write, the measured no-op, the Settings toggle, a record left by a killed run, the killed run's own watchdog), devices |

Rule: edit the user payload, then `gen_hooks.sh`, then `check_sync.sh`, then `payload.sh --selftest`
and `harness/run_harness.sh`. The lib block (`# --- camhound lib begin/end ---`) and the watch-core
block (`# --- watch core begin/end ---`) must stay self-contained: everything Watch and Locate need
lives inside them.

## Status

Coded and verified on a laptop only (selftest ends `0 failed` and prints its own count, harness scenarios green, shellcheck
clean). The v1.1 Recon hooks are generated and checked the same way. **No Pager has run any of it.**

**Status of the response rung, 2026-11-04:** it fires from a user-payload **AP** row and from both
Recon hooks, with the subject set recovered from a BSSID-filtered capture, because no shipped
firmware supplies a client→AP association (`RESPONSE.md` §13a-i). A user-payload **client** row
still aborts in `resp_target`, and client Watch, Stimulus, kit detection and the AP→client tree are
still inert, all for the same missing `AP_OF` — one fix did not buy five.

The payload is recon **and response**: it was renamed from CamScout when the Disrupt rung landed.
The recon tiers are unchanged and still passive; the response tier is the only part that transmits
and is **on by default** (`RESPONSE=1`), with `RESPONSE=0` restoring a recon-only run. Its design,
the firmware primitives it calls and the list of what remains unverified are in `RESPONSE.md`.

## Loading it onto a Pager, and what to watch on the first run

**Everything described here is on `master`** as of PR #21 (2026-11-04); take it from there rather
than from a feature branch, and check `git log --oneline -1` against the tip before copying, because
a half-updated device is the one failure mode none of the gates can see. Nothing in CamHound has
run on a device yet; everything is laptop-verified.

**Three directories, nine files.** Each needs `payload.sh` and `cam_signatures.txt` beside it; the
signature file is byte-identical in all three, and so are the two hooks (`cmp` them — that is the
edit contract, not a mistake).

```sh
ssh root@172.16.52.1 'mkdir -p /root/payloads/user/reconnaissance/CamHound \
  /root/payloads/recon/client/CamHound /root/payloads/recon/access_point/CamHound'
for d in user/reconnaissance recon/client recon/access_point; do
  scp library/$d/CamHound/payload.sh library/$d/CamHound/cam_signatures.txt \
      root@172.16.52.1:/root/payloads/$d/CamHound/
done
ssh root@172.16.52.1 'chmod +x /root/payloads/*/*/CamHound/payload.sh'
```

`/sd/payloads/...` and `/mmc/root/payloads/...` work equally — `find_install_dir` probes
`_PAYLOAD_HOME`, then the script's own directory, then all three roots, which is why each hook finds
its own signature file despite all three copies carrying the same `PAYLOAD_REL`. From a Windows
checkout: `sed -i 's/\r$//' payload.sh cam_signatures.txt` (the repo copies are LF; `file` will tell
you).

**Re-uploading after either session lands more work: copy all three again.** `check_sync.sh` compares
the three copies *in the repo*, so a stale hook left on the device is invisible to every gate we
have. The hooks change whenever the lib or watch-core block does — which is most response-rung and
most parser work — so "I only edited the user payload" is not a reason to skip them.

**`RESPONSE` ships at 1**, so a fresh install arms the Disrupt rung (still behind the attack picker
and `RESPONSE_CONFIRM`). For a recon-only first run:
`PAYLOAD_SET_CONFIG camhound RESPONSE 0`.

`--selftest` is safe to run on the device — every device-changing command is stubbed — so the
cheapest first step is `bash payload.sh --selftest` on the Pager itself. It is also the only way to
exercise the `od` fallback in `pcap_stream`/`pcap_words`, since a laptop with `hexdump` never takes
that branch and `od` is what the Pager actually has.

Then start **Recon in continuous mode** in the GUI, run CamHound, and watch
`/root/loot/CamHound/events.log` for these, in order:

| marker | means |
|---|---|
| `client verb: DEVICES` | the `RECON CLIENTS` probe got rc 255 and fell back, as 1.1.3 requires |
| `inj probe: tx phy phy1` | the injection gate read the transmitting phy, not a merge of all of them |
| `members <bssid> n=N ... dwell=Ns lock=Ns` | a `bss`-scope Disrupt recovered N stations off the air; **this is the dwell figure `resp_clamp_lock`'s floor needs** |
| `re-armed <bssid> Ns for the measurement` | the lock was re-armed after the capture, so the parse cannot eat the verdict window |
| `NO_CAPTURE` / `SNAP_SHORT` / `NO_MATCH` / `NO_CLIENTS` in `responses.tsv` | a refusal, and which of the four reasons — `SNAP_SHORT` names `CLI_CAP_SNAP` as the knob |

Known-inert on 1.1.3, so do not read these as faults: client association (kit detection, client
Watch and Stimulus, the AP→client tree, and per-client Disrupt from the user payload), and `BAND6`
(the band write is a measured no-op as issued — `dev/pager-day-one.md` 8c). Two measurements worth
taking before trusting any response-rung result: the radiotap `it_len` on `phy1` (if it exceeds 112,
`CLI_CAP_SNAP` is too small and every capture reads as `SNAP_SHORT`), and Phase 0 13a — whether data
frames appear on `wlan1mon` at all under a held EXAMINE lock, since if they do not the membership
capture returns an empty set for a reason that has nothing to do with the BSS.

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
6. **v1.1, one PR each, with on-device evidence**. Shipped, laptop-verified, on-device evidence
   still owed: Recon hooks (generated here; the hook spike -- Recon keeps growing while the hook
   runs, Cancel runs the trap -- is the device check); inventory persistence across runs
   (`DEDUPE_H`, clock guard, 30-day prune); settings menu (Recon and Response pages over all
   sixteen starred keys; RESPONSE_CONFIRM-off asks twice; the lock clamp re-runs on apply; Reset via
   `PAYLOAD_DEL_CONFIG`); band write (`BAND6`: `PINEAPPLE_SET_BANDS wlan1mon <bands> 6` once after the
   overrides, trusted only when the radio is then seen on a 6 GHz channel or uci reads the 6 back, every
   issued write restored in cleanup and, via a state file, by the watchdog or the next start; on bare 1.1.3
   the call changed nothing with pineapd running — no restart, no uci change, no 6 GHz hop, day-one 8c —
   and the payload says so); clients from
   `RECON DEVICES` where `CLIENTS` is refused (1.1.3, measured). Remaining: WPS/IE peek (`tcpdump -xx -s 1024 -c 12` on beacons and probe
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
response side landed, and the Disrupt rung offers deauth+disassoc, channel-switch announcements, or
all three. It is **on by default** (`RESPONSE=1`); `RESPONSE=0` makes the payload transmit nothing
and behave exactly as the recon-only build did. Only `DEAUTH` on a client row is targeted — see
`RESPONSE.md` §2 for why, and `attack_scope()` for the one place that decides.
