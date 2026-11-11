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
| `harness/run_harness.sh` | laptop harness: stub DuckyScript commands, fake `_pineap`/`tcpdump`/`iwinfo`/`iw` (US-like channel table for a fixture phy dir), stub `NUMBER_PICKER`/`PAYLOAD_SET_CONFIG`/`PAYLOAD_DEL_CONFIG`, RECON fixtures (the client fixture is in the 2.0.0 `probe`-object shape, with `ap_mac` kept as a stand-in for the association the firmware does not expose; a net tree under `NET_SYSFS` names phy0 as wlan1mon's phy; `HARNESS_NO_BEACON=1` makes the fake tcpdump capture nothing, `HARNESS_NO_CLIENTS=1` refuses `RECON CLIENTS` as 1.1.3 does and serves `fix/devices.json`, the measured `RECON DEVICES` shape with sorted keys, and `HARNESS_BANDS_NOOP=1` makes the band write change nothing, as measured); scenarios live, stimulus, lock (a second instance refused; a SIGKILLed run cleaned up by its watchdog; a SIGTERMed run ending instead of carrying on), nojq (both parsers, over CLIENTS and over DEVICES), locate, disrupt, members (the real-firmware shape -- no association at all, membership read off the air; `HARNESS_NO_MEMBERS` / `HARNESS_NO_ARM` / `HARNESS_NO_OR` / `HARNESS_SHORT_SNAP` / `HARNESS_BAD_PCAP` / `HARNESS_ALIEN_MEMBERS` drive the capture reasons, and `HARNESS_FIRE_REFUSE` makes the fake deauth commands refuse the way `hak5cmd` does (rc 0, the error on stderr), which must loot `CMD_REFUSED` and never a verdict (`NO_CAPTURE`, `SNAP_SHORT`, `NO_CLIENTS` — since 2026-11-10 reasons that fire the broadcast and loot `INCONCLUSIVE`, not refusals) and the uplink-only fallback filter), cliscope (the client-row Disrupt: both scopes in one menu), csainj (the optional CSA injector, on a second copy of the payload with `CSA_INJECTOR` set in its config block; `HARNESS_INJ_FAIL` makes the fake `pagerinj` fail to clone a beacon), blind, noinj, persist, settings, bands (the write, the measured no-op, the Settings toggle, a record left by a killed run, the killed run's own watchdog), devices, assoc (the inverse lookup on the real-firmware shape, ten arms: a client's AP found from its card's Watch row, then Watch and a targeted Disrupt on it; the same lookup entered from the Disrupt row; that entry again with `ASSOC_TTL=0`, where the one pick must listen once and the next pick is the one that re-checks; `HARNESS_ASSOC_DOWN` (the AP is heard sending to a client that is itself silent: `NO_UPLINK`, nothing named); a tcpdump that will not arm (`HARNESS_NO_ARM`, which the fake honours for this capture as it does for the membership one); the miss already in the fixtures, a camera last heard on 2437 MHz whose AP is on channel 36; a membership capture teaching both cameras their NVR, which wakes kit detection; `HARNESS_NO_PARK` (EXAMINE_CHANNEL does not park: the hop is listened across), `HARNESS_ASSOC_TWO` (two BSSIDs alike: no decision) and `HARNESS_NO_OR` (uplink-only retry). The fake tcpdump answers the lookup only when the radio could have heard the client: hopping, or parked on its AP's channel, which the EXAMINE stubs track in `/tmp/cs_harness_hop` and `/tmp/cs_harness_chan`) |

Rule: edit the user payload, then `gen_hooks.sh`, then `check_sync.sh`, then `payload.sh --selftest`
and `harness/run_harness.sh`. The lib block (`# --- camhound lib begin/end ---`) and the watch-core
block (`# --- watch core begin/end ---`) must stay self-contained: everything Watch and Locate need
lives inside them.

## Status

Coded and gated on a laptop (selftest ends `0 failed` and prints its own count, harness scenarios green, shellcheck
clean), with the v1.1 Recon hooks generated and checked the same way — and, since 2026-11-05, **partly
run on the device**. What has and has not run there, with the citation for each:

| what | on the device? | record |
|---|---|---|
| `--selftest` | yes, 259/0 on 2026-11-04 | below |
| a live scan from the user payload | yes, 2026-11-05 | CLAUDE.md "Second contact": `inventory.tsv` rows, the OUI-table hang it found |
| a Disrupt from the user payload (AP row), with the membership capture | yes, 2026-11-05 | CLAUDE.md "Second contact": the `responses.tsv` row and `resp members … n=1 why=ok itmax=56` |
| seven Disrupt attempts that refused with `NO_MATCH` | yes, 2026-11-09 | CLAUDE.md "Third contact"; the transmit-set fix came from them |
| Watch (Live view, Stimulus) and Locate | no record in this repo | none of CLAUDE.md's eight "contact" sections reports a CamHound Watch or Locate run; what they do record is the precondition, that data frames appear on `wlan1mon` under a held EXAMINE lock ("Second contact") |
| the inverse association lookup, and so client-row Watch and Disrupt | no | landed 2026-11-10; `dev/pager-day-one.md` 8d is its first run |

*This table replaces a paragraph that still said nothing but `--selftest` had run on a device; a
review on 2026-11-10 caught it disagreeing with `RESPONSE.md`'s header.*

**First device run, 2026-11-04: `--selftest` passes on the operator's 1.1.3 Pager — 259 checks, 0
failed.** That is the first CamHound code to execute on hardware, and it is a narrow slice: the
selftest stubs every device-changing command, so it exercises the parsers, the pcap walkers and the
scoring against the device's real `jq`, `hexdump`, `awk`, `bash` and busybox, and **nothing about the
radio**. It earned its keep immediately: the first attempt was 255 checks / **4 failed**, which is
how the `gsub` defect below was found. ~~No live scan, Watch, Locate or Disrupt has run yet.~~
*(True on 2026-11-04; a scan and a Disrupt ran the next day — see the table above.)*

**Status of the response rung, 2026-11-04:** it fires from a user-payload **AP** row and from both
Recon hooks, with the subject set recovered from a BSSID-filtered capture, because no shipped
firmware supplies a client→AP association (`RESPONSE.md` §13a-i). ~~A user-payload **client** row
still aborts in `resp_target`, and client Watch, Stimulus, kit detection and the AP→client tree are
still inert, all for the same missing `AP_OF` — one fix did not buy five.~~

**Status of the association, 2026-11-10 — coded, laptop-verified, never run on a device.** The user
payload now reads a client's AP off the air when the operator picks `Watch (find AP first)` or
`Disrupt (find AP first)` on its card (`assoc_lookup`: park on the client's channel, capture its own
data frames, read the BSSID from them), and every membership capture teaches the stations it heard
transmitting their AP. A resolved client is watchable, attackable by the one targeted frame the firmware can
send, counted by kit detection and listed under its AP in the report. **Not bought:** there is no
background pass, so an unresolved client still reads `-`; and the lookup's park is
`PINEAPPLE_EXAMINE_CHANNEL` on its own, which no bench session has issued — if it does not park,
the lookup says so and listens across the hop for three windows instead (`dev/pager-day-one.md` 8d
is the check). The hooks are unaffected in behaviour: they get their association from the Recon UI.

The payload is recon **and response**: it was renamed from CamScout when the Disrupt rung landed.
The recon tiers are unchanged and still passive; the response tier is the only part that transmits
and is **on by default** (`RESPONSE=1`), with `RESPONSE=0` restoring a recon-only run. Its design,
the firmware primitives it calls and the list of what remains unverified are in `RESPONSE.md`.

## Loading it onto a Pager, and what to watch on the first run

**Everything described here is on `master`** as of PR #21 (2026-11-04); take it from there rather
than from a feature branch, and check `git log --oneline -1` against the tip before copying, because
a half-updated device is the one failure mode none of the gates can see. ~~Nothing in CamHound has
run on a device beyond `--selftest`, which passed on 2026-11-04 (259/0, after it caught the `gsub`
defect at 255/4); everything else is laptop-verified.~~ *Superseded: the Status table above lists
what has run on the device since. The inverse lookup is on `claude/clever-wozniak-hn3xyn` until it
is merged, so until then take the three `payload.sh` copies from that branch, not from `master`.*

**Three directories, six files.** Each needs `payload.sh` and `cam_signatures.txt` beside it; the
signature file is byte-identical in all three, and so are the two hooks (`cmp` them — that is the
edit contract, not a mistake). *(This line said "nine files" until 2026-11-11; three directories of
two files each is six.)* The loop below is POSIX shell. From PowerShell, where `for … do` does not
exist, the same copy is six plain lines that need no quoting — run them from the repo root:

```
scp library/user/reconnaissance/CamHound/payload.sh root@172.16.52.1:/root/payloads/user/reconnaissance/CamHound/
scp library/user/reconnaissance/CamHound/cam_signatures.txt root@172.16.52.1:/root/payloads/user/reconnaissance/CamHound/
scp library/recon/client/CamHound/payload.sh root@172.16.52.1:/root/payloads/recon/client/CamHound/
scp library/recon/client/CamHound/cam_signatures.txt root@172.16.52.1:/root/payloads/recon/client/CamHound/
scp library/recon/access_point/CamHound/payload.sh root@172.16.52.1:/root/payloads/recon/access_point/CamHound/
scp library/recon/access_point/CamHound/cam_signatures.txt root@172.16.52.1:/root/payloads/recon/access_point/CamHound/
```

```sh
ssh root@172.16.52.1 'mkdir -p /root/payloads/user/reconnaissance/CamHound \
  /root/payloads/recon/client/CamHound /root/payloads/recon/access_point/CamHound'
for d in user/reconnaissance recon/client recon/access_point; do
  scp library/$d/CamHound/payload.sh library/$d/CamHound/cam_signatures.txt \
      root@172.16.52.1:/root/payloads/$d/CamHound/
done
ssh root@172.16.52.1 'chmod +x /root/payloads/*/*/CamHound/payload.sh'
```

### Optional: the CSA injector

CamHound's CSA leg can be routed to `dev/injector/pagerinj` instead of the firmware command, which
is the only way to get a CSA that could work: pineapd hardcodes Channel Switch Count 0 *and* a New
Channel Number of 14 (Japan-only), both literals with one call site, so no setting reaches either.

```sh
scp dev/injector/pagerinj root@172.16.52.1:/root/pagerinj
ssh root@172.16.52.1 'chmod +x /root/pagerinj; /root/pagerinj --selftest | tail -2'
```

**Leave `CSA_INJECTOR` empty until the bench says otherwise.** `dev/injector/README.md` requires
pineapd STOPPED — it hops the interface and its own CSA flood is a clone source `pagerinj` skips —
and CamHound cannot stop pineapd, because Recon, the EXAMINE lock and every deauth command *are*
pineapd. Turning the hook on bets that CamHound's EXAMINE lock holds the channel well enough, and
nothing has measured that. Measure it standalone first with `dev/injector/run_17a.sh`. That script
parks the radio with EXAMINE by default and leaves pineapd running; pass `--stop-pineapd` only if
you want it stopped, because stopping it takes the monitor interfaces down with it (measured on the
bench) and the script has to bring them back up. It restores whatever it changed on `EXIT`, `INT`,
`TERM`, `HUP` and `QUIT` — true since 2026-11-10. Two audits went into that sentence: the first
found the signal handler restoring and then carrying on to transmit anyway, and the second found
that `HUP` and `QUIT` had no trap at all, so closing the ssh session the bench workflow runs over
killed the shell without firing the `EXIT` trap and left pineapd stopped. There is still no trap
for `KILL`, and there cannot be. Once it is proven, set `CSA_INJECTOR` (and
optionally `CSA_COUNT`, `CSA_CHAN`) in the config block of the user payload and regenerate the
hooks; they are not starred because `cfg()` takes integers only, so a path cannot come through
`PAYLOAD_SET_CONFIG`.

`/sd/payloads/...` and `/mmc/root/payloads/...` work equally — `find_install_dir` probes
`_PAYLOAD_HOME`, then the script's own directory, then all three roots, which is why each hook finds
its own signature file despite all three copies carrying the same `PAYLOAD_REL`. From a Windows
checkout: `sed -i 's/\r$//' payload.sh cam_signatures.txt` (the repo copies are LF; `file` will tell
you).

**Driving the device from PowerShell: single quotes outside, and no `"` character anywhere inside.**
PowerShell's escape character is a backtick, not a backslash, so `\$x` and `\"` do not mean what a
POSIX habit expects. Worse, a `"` inside a single-quoted string is stripped when PowerShell builds
the command line for a native program such as `ssh.exe`, and the remote shell then receives the
command unquoted: `ssh host 'sed -n "s/.*(\([0-9]*\) MHz).*/\1/p"'` arrives at the Pager with the
quotes gone and dies with `ash: syntax error: unexpected "("`. **Four commands across two sessions
now, three of them after the rule had already been stated** — the fourth on 2026-11-10, composing a
`tcpdump -e "type mgt and (subtype auth or ...)"` read of the 17a captures. Note what makes it
sticky: the error names the `(`, so it reads as a filter-syntax problem, and the author goes looking
at pcap-filter grammar instead of at their own quoting. It also bites when you are *writing commands
for the operator to paste* rather than driving the device yourself, which feels different and is not.

Prefer a form that needs no quotes:
- `grep MHz` over a quoted regex; `cut -d\| -f17` over `awk -F"[|]"`; `cut -c1-8` over `awk '{print $1}'`.
- **Repeat `-e` instead of using alternation**: `grep -i -e assoc -e authentication -e deauth`
  needs no quotes at all, where `grep -iE 'assoc|auth'` needs them twice over — once for PowerShell
  and once to keep `ash` from reading the `|` as a pipe.
- tcpdump joins its trailing arguments into the filter, so `tcpdump -r f -nn -e type mgt` and
  `tcpdump -r f -nn wlan addr1 AA:BB:...` need no quoting either. It is only the operators that
  take parentheses or `or` chains that do — and those are the ones to push into `grep`.

Where a quote is genuinely needed, send the script on **stdin**, where it never touches a command
line at all:
`'awk -F"[|]" "\$17>5925" file' | ssh root@172.16.52.1 sh` — ssh still prompts for the password,
which it reads from `/dev/tty` rather than stdin.

**Re-uploading after either session lands more work: copy all three again.** `check_sync.sh` compares
the three copies *in the repo*, so a stale hook left on the device is invisible to every gate we
have. The hooks change whenever the lib or watch-core block does — which is most response-rung and
most parser work — so "I only edited the user payload" is not a reason to skip them.

**`RESPONSE` ships at 1**, so a fresh install arms the Disrupt rung (still behind the attack picker
and `RESPONSE_CONFIRM`). For a recon-only first run:
`PAYLOAD_SET_CONFIG camhound RESPONSE 0`.

`--selftest` is safe to run on the device — every device-changing command is stubbed, and since
2026-11-04 so is every display and dialog command, so it no longer paints the Pager's screen nor can
it block on a button press. The cheapest first step is `bash payload.sh --selftest` on the Pager
itself. Expect `== 454 checks, 0 failed ==` (the count as of 2026-11-11; it grows with every case added) and
the two block hashes; a lower count means the copy
on the device is older than the repo's.

*Corrected 2026-11-04. An earlier version of this paragraph called the device run "the only way to
exercise the `od` fallback in `pcap_stream`/`pcap_words`, since a laptop with `hexdump` never takes
that branch and `od` is what the Pager actually has". **Both halves are backwards.** All three
dumpers are `if hexdump; then hexdump; else od; fi` (`payload.sh:636`, `:694`, `:1894`); `hexdump`
is in the measured device inventory and `od` ships in neither firmware image, so a Pager always
takes the **hexdump** branch and a device run exercises the fallback less, not more. The `od` branch
is for a host that lacks hexdump — which is what the cloud container running the gates is, so the
two machines take opposite branches and neither alone covers both.*

Then start **Recon in continuous mode** in the GUI, run CamHound, and watch
`/root/loot/CamHound/events.log` for these, in order:

**Confirmed on the device, 2026-11-04:** the `gsub` row below is why `jq_works()` exists — jq is
present on a Pager but has no Oniguruma, so the parsers compiled to nothing and `HAVE_JQ` lied.
`--selftest` now reports 259/0 there.

| marker | means |
|---|---|
| `start v… jq=1 tcpdump=1` | the run-start line. **`jq=1` is worth one look after the 2026-11-10 upload:** `jq_works` now also runs the AP program (`JQ_APS`) on a fixture and wants the exact row, pinned from this repo's jq 1.7. Any jq ≥ 1.5 should print the same row; if the device's does not, this reads `jq=0`, the start screen says `no-jq` and the regex fallback parsers are in use. The device `--selftest` says so first — its `aps jq:` and `jq probe: a working jq is accepted` cases fail and print what the device's jq produced |
| `client verb: DEVICES` | the `RECON CLIENTS` probe got rc 255 and fell back, as 1.1.3 requires |
| `inj probe: tx phy phy1` | the injection gate read the transmitting phy, not a merge of all of them |
| `members <bssid> n=N ... dwell=Ns lock=Ns` | a `bss`-scope Disrupt recovered N stations off the air; **this is the dwell figure `resp_clamp_lock`'s floor needs** |
| `re-armed <bssid> Ns for the measurement` | the lock was re-armed after the capture, so the parse cannot eat the verdict window |
| `assoc <mac> -> <bssid> n=N up=U recs=R itmax=I ch=C lock=ok dwell=Ns` | a client's AP was read off the air: N frames between the two out of R records, U of them the client's own (at least one is required), radiotap I bytes, parked on channel C. **`lock=` is the first-run answer to whether `EXAMINE_CHANNEL` alone parks:** `ok` it did, `unverified` the channel could not be read back, `hop` it did not and the capture ran across the hop |
| `assoc <mac> none why=NO_FRAMES\|NO_PAIR\|NO_UPLINK\|AMBIGUOUS\|SNAP_SHORT\|NO_CAPTURE … ch=C lock=…` | the lookup found no AP and the card is unchanged. `NO_FRAMES` means not heard on channel C in the window — the client may be idle, or its AP may be on another channel than the one it was last heard on; it is not evidence that the client is unassociated. `NO_UPLINK … down=<bssid>/K` means that AP was heard sending K frames to the client and the client itself was not heard: nothing is named, because an AP goes on sending to a client that has left it |
| `assoc members of <bssid>: N heard, M client row(s) now carry this AP[, K more only sent to (not taught)]` | an AP-row Disrupt's membership capture heard N stations transmitting to that AP; M of them have a client row that now carries it, and those cards offer Watch and Disrupt outright. The other N − M have no Recon row yet (remembered, applied when one appears) or an AP the firmware supplied. K further members were heard only as the destination of the AP's frames: they are in the attack and its measurement, and are not taught this AP |
| `no-members <bssid> why=NO_CAPTURE\|SNAP_SHORT\|NO_CLIENTS` then `fired … broadcast with no members recovered` | an AP-row Disrupt recovered nobody and **fired the broadcast anyway** (operator-decided 2026-11-10, "nuclear blast"); `responses.tsv` has one `INCONCLUSIVE` row for `ff:ff:ff:ff:ff:ff`. These tokens are no longer loot verdicts — `SNAP_SHORT` still names `CLI_CAP_SNAP` as the knob |

Known-inert on 1.1.3, so do not read these as faults: client association **until a client is
resolved** — the firmware supplies none, so kit detection, client Watch and Stimulus, the AP→client
tree and per-client Disrupt are dormant for any client that has not been looked up from its card or
heard in a membership capture — and `BAND6`
(the band write is a measured no-op as issued — `dev/pager-day-one.md` 8c). ~~Two measurements worth
taking before trusting any response-rung result: the radiotap `it_len` on `phy1`, and Phase 0 13a.~~
**Both were taken on 2026-11-05** (CLAUDE.md "Second contact"): the radiotap header on `phy1` is
56 bytes, so `CLI_CAP_SNAP=128` clears the 72 a record needs with room to spare (the limit is an
`it_len` above 112), and data frames do appear on `wlan1mon` under a held EXAMINE lock. The one that
is still owed is the lookup's own: whether `PINEAPPLE_EXAMINE_CHANNEL` parks without
`EXAMINE_BSSID` (`dev/pager-day-one.md` 8d).

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
