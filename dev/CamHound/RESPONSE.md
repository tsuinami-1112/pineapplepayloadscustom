# CamHound response side — how it works

Developer reference for the **Disrupt** rung: the part of CamHound that turns a detection into a
disconnection. `PLAN_v2.md` covers the recon side; this covers everything downstream of it.

Status: coded and laptop-verified; `--selftest` passes on a real 1.1.3 Pager as of 2026-11-04
(259/0), but **no part of this rung has transmitted, or even been reached, on hardware** — the
selftest stubs every device-changing command. Section
[What is unverified](#what-is-unverified) is the honest list.

---

## 1. Why this exists, and why it is not just a deauth

A classic deauthentication attack forges a management frame telling a client it has been
disconnected. 802.11w (PMF) makes deauth and disassoc *robust management frames*: unicast ones are
CCMP-protected under the PTK, group ones carry an MMIE keyed by the IGTK. WPA3-Personal mandates
PMF, so a forged deauth has no valid MIC and is dropped. Hak5's own `DEAUTH_CLIENT` documentation
says as much: networks using PMF "will not be susceptible", and 6 GHz is excluded because every
6 GHz network mandates WPA3.

Cameras are increasingly WPA3. So the interesting primitive is the one that works anyway:

**Beacons are not robust management frames.** 802.11w does not protect them. A Channel Switch
Announcement element carried in a beacon is therefore unauthenticated even on a PMF-required
network. Spoof the AP's BSSID, inject a beacon carrying a CSA pointing at another channel, and a
compliant client follows the switch. The real AP never moved, so the client lands on a dead channel
and has to rescan. Same observable outcome as a deauth, achieved entirely outside the frames PMF
covers.

This is not a deauth and calling it one invites the wrong mental model. It is a channel-switch
spoof, it has a different detection signature, and it works where deauth cannot.

## 2. The firmware already does it

The Pager's shipping firmware implements this natively and **does not document it.** Found by
reading `usr/sbin/pineapd` and `usr/bin/_pineap` out of the 1.1.3 image:

```
recon_engine::inject_csa(char const*, pineap_wifi_channel const&, unsigned char)
csa_beacon_record        (per-BSSID cache, std::unordered_map)
"Caught beacon for CSA on {}" -> "Queuing CSA for {}" -> "Queued packets for CSA on {}"
"Request to inject CSA expired for {}: {}ms"
```

Built on `libwifi.so.0.0.10` (`libwifi_create_beacon`, `libwifi_add_tag`,
`libwifi_create_radiotap`). The "queued … expired" strings matter: pineapd *queues* the injection
and times it out, meaning it waits for its own hopper to reach the target channel. The channel
contention problem solves itself inside the daemon, because the same process owns both the hopping
and the injection.

Three DuckyScript commands expose it. Signatures confirmed from `hak5cmd`'s own help text, not
inferred:

| Key | Command | Frames | Scope |
|---|---|---|---|
| `DEAUTH` | `PINEAPPLE_DEAUTH_CLIENT [bssid] [target] [channel]` | deauth + disassociation | one client |
| `CSA` | `PINEAPPLE_DEAUTH_CLIENT_CSA [bssid] [channel]` | channel-switch announcements | whole BSS |
| `BOTH` | `PINEAPPLE_DEAUTH_CLIENT_ALL [bssid] [target] [channel]` | all three | whole BSS |

**Scope is not what the signatures suggest, and `attack_scope()` is the one place that decides.**
`CSA` takes no target: the **[V]** reading is the Go handler, `StartDeauthCsa` parses one MAC with a
28-byte frame against `StartDeauth`'s two and 32 (CLAUDE.md §"2.0.0-stable, analysed"), and hak5cmd's
help lists `[bssid] [channel]` — the help alone would not settle it, since this repo has caught it
wrong three times. "Because it rides in a beacon" is the carrier question §13 still lists as not
proven, so that explanation is **[A]**; the breadth does not depend on it. `BOTH` advertises a `[target]` that its handler parses and
discards, so it is BSS-wide too; the readings behind that are **[V]** and the "discards it"
conclusion is **[A]**, falsifiable by firing `BOTH` at one client among several and seeing whether
the others stay associated (evidence in `CLAUDE.md` §"2.0.0-stable, analysed"). And because
`resp_target` resolves an **AP row** to a broadcast target, every attack on one is BSS-wide
regardless of the key. The picker appends ` bss` to a broad option and the pre-transmit confirm
reads "on EVERY client of <bssid>", because "`CSA` on <one client>" would be a lie. `posture_opts`
is unchanged and still orders by efficacy, so a BSS-wide attack is preselected on the common
badges — the marker and the confirm carry that, not a reordering that would demote the attack most
likely to work.

There is also a
`_pineap` layer (`DEAUTH`, `DEAUTHCSA`, `DEAUTHALL`) and an HTTP layer (`/api/pineap/deauth`,
`/deauth_csa`, `/deauth_all`); the DuckyScript wrappers are what payloads should use.

Consequence for this design: **no injector binary, no cross-compile, no OpenWrt SDK, no release
artefact.** The response side is shell calling vendor primitives, exactly like the rest of the
payload. That is why it is a few hundred lines of shell between the `response posture` and `response rung`
markers in payload.sh (§8) and not a C project.

## 3. Posture: deciding what can work

Three attacks, and two of them silently do nothing against the wrong target. The badge is read from
the target's own beacon.

**The two bits that matter.**

| Property | Element | Location |
|---|---|---|
| MFPC — PMF capable | RSN, ID 48 | RSN Capabilities, bit 7 → `0x80` of the low octet |
| MFPR — PMF required | RSN, ID 48 | RSN Capabilities, bit 6 → `0x40` of the low octet |
| Beacon Protection | **Extended Capabilities, ID 127** | **bit 84** → octet 10 (0-based), mask `0x10` |

Beacon protection is **not** in the RSNXE (ID 244). That element has no such bit; the thing that
looks like it is RSNXE bit 11, "Protected Announce Support", which is something else. Confirmed
against hostap (`WLAN_EXT_CAPAB_BEACON_PROTECTION 84`) and Wireshark (`wlan.extcap.b84`, mask
`0x10`). An earlier draft of this code asserted RSNXE from memory and was wrong.

RSN Capabilities sits after two variable-length suite lists, so `rsn_caps()` walks them rather than
assuming an offset: version (2) + group cipher (4) + pairwise count (2) + 4×N + AKM count (2) +
4×M, then the 2-octet capabilities field.

**The badge table.**

| Badge | Meaning | `DEAUTH` | `CSA` |
|---|---|---|---|
| `D+C` | no PMF | works | works |
| `D?+C` | PMF optional (WPA3 transition) | partial | works |
| `C` | PMF required (WPA3) | blocked | works |
| `NONE` | PMF + beacon protection | blocked | blocked |
| `NOINJ` | channel we cannot transmit on | cannot transmit | cannot transmit |
| `?` | no beacon captured | unknown | unknown |

Two honest limits baked into the model. `D?+C` **cannot be resolved from a beacon at all**, because
PMF is negotiated per client — a transition-mode BSS can hold protected and unprotected clients
simultaneously, so the badge says `partial` and means it. And `NOINJ` is a property of the
*channel*, not the target, so `csa_injectable()` short-circuits the whole read: a channel we cannot
transmit on needs no capture.

`NOINJ` is decided by **two independent gates in series**, which are easy to conflate:

- **Gate 1 — pineapd, in userspace.** A compiled-in channel switch (`pineap_wifi_interface::inject`
  at `0x46e800`–`0x46e826`, duplicated in `interface_tracker::inject_deauth` at
  `0x472c66`–`0x472c8a`) refusing exactly the 16 FCC DFS channels
  `52 56 60 64 100 104 108 112 116 120 124 128 132 136 140 144`, plus 6 GHz when the channel's band
  field says 6 GHz. It never consults the kernel's regulatory state — no `NL80211_CMD_GET_REG`
  anywhere in the binary — so **no regdb edit or `iw reg set` can lift it**. `pcap_inject` has one
  call site, inside the gated function, so every frame passes it. Encoded as the constant
  `PINEAPD_DFS_BLOCKED`, because mirroring a compiled-in firmware policy is exactly what a constant
  is for.
- **Gate 2 — cfg80211, in the kernel.** `cfg80211_reg_check_beaconing()` (this kernel's rename of
  `cfg80211_reg_can_beacon()`) prohibits `IEEE80211_CHAN_DISABLED | IEEE80211_CHAN_NO_IR` for a
  monitor vif. **`IEEE80211_CHAN_RADAR` is not prohibited** — so under `country 'US'`, where no
  5 GHz rule below 5850 MHz carries `NO-IR` (169/173/177 do, via `5850–5895 … PASSIVE-SCAN`,
  measured 2026-11-02 — CLAUDE.md §First contact), gate 2 permits all of 36–165 and the DFS block
  is entirely gate 1's.
  This gate *does* follow the regulatory domain, so it is read live by `inj_probe()` from
  `iw phy <phy> channels` on the transmitting phy and cached in `INJ_OK` keyed `band/channel`.

Why reading gate 2 live rather than hardcoding it: a frame gate 2 rejects is freed with
`NETDEV_TX_OK`, so nothing reports an error and an over-permissive verdict **reads back as the
target having resisted**. That is strictly worse than refusing a channel that would have worked,
which is why the fallback when the probe fails is only what is injectable under *both* the US and
world domains — 2.4 GHz 1–11 and 5 GHz 36–48. Under the world domain even 149–165 is `NO-IR`, and
2.4 GHz 12–14 are blocked under both (`DISABLED` under US, `NO-IR` under `00`). **36–48 is in that
set only because of the shipped `regulatory.db`**, which is upstream wireless-regdb 2025.02.20 with
exactly one edit — `NO-IR` dropped from the world domain's 5170–5250 rule
(`dev/pager-6ghz-determination-plan.md` §C2, a reading of the shipped db). Upstream `00` marks 36–48
`NO-IR`, so a db rebuilt from upstream makes the fallback over-permissive on 36–48 and it must then
shrink to 2.4 GHz 1–11. Falsifier: `iw phy <txphy> channels` printing `No IR` on 5180 MHz while
`iw reg get` says `00`.

`inj_probe()` must run in the **parent shell** — `preflight()` and on entry to `disrupt_menu()`.
`csa_injectable()` is reached from `posture_from_caps()` inside `$( )`, where writes to globals are
discarded, so it is strictly read-only. It reads the table of the **transmitting phy only** — the
one behind `RECON_IF`, named by `<NET_SYSFS>/<RECON_IF>/phy80211/name` — because gate 2 is applied
by the phy the frame leaves from, and pineapd injects on that interface: its live cmdline carries
`--inject wlan1mon` (CLAUDE.md §First contact). Falsified by
`cat /proc/$(pgrep -n pineapd)/cmdline | tr "\0" " "` showing `--inject` on another interface, in
which case `RECON_IF` is the wrong phy to read. Only when that file cannot be read does it fall
back to merging every phy under `INJ_SYSFS` (last row per `band/channel` key wins, in glob order),
and then it logs,
to `events.log` and as a yellow `LOG`, that the tx phy was unresolved and how many phys were merged:
the merge is over-permissive wherever two phys share a band and disagree, and `radio0` registers
2.4 GHz as the transmitter does, so every 2.4 GHz key is written twice. The selftest pins both modes
on a two-phy fixture that disagrees on channel 6; the harness fixture names `phy0` as `wlan1mon`'s
phy and the `disrupt` scenario asserts the resolved path was taken.

**Where the posture comes from, and why.** From a beacon captured on `RECON_IF` (`wlan1mon`), not
from `iw scan`. This is forced by the hardware: `radio0` is `band '2g'` and `radio1` carries **only**
a monitor interface, so **no `iw scan` on this device can read 5/6 GHz RSN at all.** `wlan0` is the
enabled dummy station used for scanning but it is on `radio0`, hence 2.4 GHz only. `SCAN_IF` is
retained as a reserved key for a future 2.4 GHz cross-check and is currently unused.

The capture runs under a short EXAMINE lock. Recon hops `wlan1mon` across two bands while unlocked,
so a 4-second window aimed at one BSSID mostly missed; without the lock the posture read usually
returned `?`.

`posture_of()` must be called **directly, not inside `$(...)`**. It returns the badge on stdout *and*
in `POSTURE_LAST`, and sets `POSTURE_RSN` / `POSTURE_EXT` in the caller's shell. A command
substitution runs it in a subshell, loses all of that, and leaves `responses.tsv` with `-` in
`rsn_caps` and `beacon_prot`. Badges cache per BSSID for `POSTURE_TTL`; a failed read is
deliberately **not** cached, so a transient miss does not stick for five minutes.

## 4. The attack contract

The badge **advises; it never decides.** All three attacks are offered, ordered by what the beacon
predicts and labelled honestly, so a deliberate no-hope attempt stays the operator's call. Where
nothing is expected to work the operator is asked once and may still proceed.

- `response_cmd <key>` → the DuckyScript command name
- `posture_opts <badge>` → viable keys, best first; empty for `NONE` and `NOINJ`
- `posture_expect <badge> <key>` → `works` | `partial` | `blocked` | `unknown`
- `posture_why <badge>` → one line of plain English for the screen

## 5. Target resolution

`resp_target <mac>` sets `R_BSSID`, `R_TARGET`, `R_CH`, `R_BAND`:

- **AP target** → attacked broadcast: `R_BSSID` is the AP, `R_TARGET` is `ff:ff:ff:ff:ff:ff`.
- **Client target** → attacked through its own AP: `R_BSSID` is `AP_OF[mac]`, `R_TARGET` is the
  client, and the channel is the *AP's*, because a client rides its AP's channel.
- **Unassociated client** → refused. There is no BSS to announce from.
- **No known channel** → refused.
- **Unknown band** → derived from the channel number (≤14 → 2, 36–177 → 5), so a target whose
  frequency was never seen does not read as a regulatory block.

## 6. Channel lock

Reuses Watch's `lock_target` / `unlock_target` rather than a second implementation: it issues
`PINEAPPLE_EXAMINE_BSSID`, reads the channel back three times via `iwinfo`, falls back to
`PINEAPPLE_EXAMINE_CHANNEL`, and reports failure if the radio is still hopping. Returns 0 locked,
1 locked-by-channel, 2 failed. On failure the response **does not transmit** and the attempt is
logged as `LOCK_FAILED`.

`lock_target` takes the channel to verify as an optional third argument. It previously verified
against `WATCH_CH`, which only `watch_prepare` sets — so a response lock was checked against the
*previous Watch target's* channel, or against nothing in a fresh session. The response rung passes
`R_CH` explicitly; the Watch callers are unchanged and still default to `WATCH_CH`. Firmware 1.1.3's
changelog also records a fix for "a channel-locked interface could resume channel hopping under
certain circumstances", which is why the lock is verified rather than assumed.

## 7. Verdict: why "we sent it" proves nothing

Every kernel-side drop path on an injected frame returns `NETDEV_TX_OK` — no counter, no log, and
`sendto()` reports the full byte count. Bad radiotap, a NULL channel context, a `NO_IR` channel, an
interface that is not running: all of them reach userspace as success. So the send call is not
evidence. Only the target's subsequent behaviour is.

**What gets measured: subjects, not the target.** `resp_snapshot <scope>` collects a packet counter
and last-seen time per *subject* from one Recon read. The scope comes from `attack_scope` — what the
chosen command can actually reach — **not** from which row the operator picked:

- **`cli` scope** (only `DEAUTH` on a client row) → the client itself.
- **`bss` scope** (everything else, including `CSA`/`BOTH` picked from a *client* row) → the BSSID's
  **visible, non-randomised clients**. The AP's own counter is deliberately never used: it keeps
  beaconing whatever happens to its clients, so it carries no signal. Randomised MACs are excluded
  via `is_rand` because they rotate and would read as `MOVED` for free — except the picked target
  itself, which is always a subject even behind a randomised MAC, so an explicit pick is never
  dropped from its own loot.
- A client row that Recon happens to list as an AP falls back to `recon_stat`.

**Why scope and not row type.** `CSA` takes no target argument at all and `_ALL`'s is parsed and
discarded, so both transmit BSS-wide even when the operator picked one client. Selecting subjects by
row type therefore measured a single camera and wrote a single loot row for a transmit that hit the
whole BSS: `MOVED: 1/1 quiet` was a claim about one device presented as the outcome of a BSS-wide
action, and the other devices knocked off left no record. Fixed 2026-11-03; the harness `cliscope`
scenario drives both arms from the same menu (`scope=cli subjects=1` for `DEAUTH`, `scope=bss
subjects=4` for `BOTH`).

Because the aggregate now covers the whole blast radius, a collateral `NO_EFFECT` would otherwise
read as "the camera I aimed at stayed up". So when the pick is a client row and there is more than
one subject, `resp_fire` also names that device's own verdict (`picked <mac>: <verdict>`, on screen
and in `events.log`).

**This widening depends on the association column, which no shipped firmware supplies.** The `bss`
sweep matches a client's `ap_mac` against `R_BSSID`; `JQ_CLI` reads that as `(.ap_mac // .bssid //
"-")` and the 2.0.0 device object has **neither** key, so every client row carries `-`. The sweep
then matches nothing. *Corrected 2026-11-03 — an earlier revision of this paragraph said the
measurement "falls back to the picked target alone, one subject, as before". That is wrong on both
row types and the error mattered, because it made the rung look merely degraded when it is in fact
unable to fire:*

- on an **AP row** the picked target is `ff:ff:ff:ff:ff:ff`, so there is no target to fall back to:
  subjects are **0** and `resp_fire` refuses with `NO_CLIENTS` before transmitting *(the state of
  2026-11-03; since 2026-11-10 an AP row with zero subjects fires anyway — see below)*;
- on a **client row** it never reaches the sweep at all — `AP_OF` is `-`, so `resp_target` returns 1
  and `disrupt_menu` aborts with "nothing to attack: no associated BSS".

So the *selection rule* is correct and the *data to feed it* does not exist on either firmware. The
honest state as of 2026-11-03 was that **the response rung could not transmit on 1.1.3 or on
2.0.0**, and the blocker was the association column rather than the firmware version. **§13a-i
closed that for AP rows on 2026-11-04** by reading the association off the air; a user-payload
client row still aborts in `resp_target`. See §13 and §13a-i. **[A]** *Falsified by:* `_pineap RECON
CLIENTS format=json | jq '.[0]|keys'` on a 2.0.0 Pager with an associated client returning any key
that carries the BSSID.

This distinction was a real defect, not a refinement. The first version asked Recon about
`R_TARGET` directly, and for a broadcast attempt that is `ff:ff:ff:ff:ff:ff`, which never appears in
Recon. `recon_stat` therefore failed, `present` was 0, and **every broadcast attempt was judged
`MOVED` regardless of effect**, with no counters in its loot row. The unit tests covered
`resp_verdict`'s branches in isolation and never the composition that fed it, so they passed while
the result was wrong.

**A broadcast target with no subjects FIRES — operator-decided 2026-11-10: *"I'll accept nuclear blast. Let the AP row fire broadcast frames."***
Until that day it was refused before anything was transmitted, with a loot row whose verdict column
named the capture's reason, on the argument that "sending would be unverifiable noise". That
argument was the 2026-11-09 defect one layer up: the frame is addressed to `ff:ff:ff:ff:ff:ff` and
needs no member list, and `CLI_AWK`'s `seen[c] >= 2` filter (kept, unchanged — it guards the
*measurement* set against FCS-corrupt addresses) can legitimately admit zero members from a BSS
proven occupied by hundreds of records (`AUDIT-2026-11-10.md`, "Open question"). So the measurement
gate was again gating the transmit. Now `resp_fire` makes the broadcast target itself the one
subject with `p0 '-'`, so `resp_verdict` scores it `INCONCLUSIVE` and the loot has exactly one row,
for `ff:ff:ff:ff:ff:ff`, `pk_before`/`pk_after` `-`; the targeted sweep is skipped (there is no
station to aim at); and `events.log` carries `no-members <bssid> why=<reason> …` before the fire and
`fired <key> <bssid> broadcast with no members recovered why=<reason>` after it. The blast radius is
the confirm's ("on EVERY client of <bssid>"), unchanged. Refusals that are not about membership —
`LOCK_FAILED`, `CMD_REFUSED`, a missing command — still refuse.

*Corrected 2026-11-04: this used to read "refused **before the lock is taken**", which is now the
opposite of the code.* The lock is taken first, because the membership capture has to run on the
target's channel and the pre-read has to see what it found. Every refusal path past the lock
therefore calls `unlock_target` and logs `unlocked after refusal` — a leaked EXAMINE would pin the
radio off its hop cycle for the rest of the run.

The reasons below are **`events.log` reasons, no longer loot verdicts** (since 2026-11-10):

| reason | meaning | the knob |
|---|---|---|
| `NO_CAPTURE` | no `tcpdump`, the filter would not arm, or what came back is not a readable pcap | fix the tool or the filter |
| `SNAP_SHORT` | records arrived but a record **at the snaplen** was cut before `addr2` | raise `CLI_CAP_SNAP` |
| ~~`NO_MATCH`~~ | *retired 2026-11-09: heard members are transmit targets now, so it has no producer* | — |
| `NO_CLIENTS` | armed, listened, nobody there | the BSS really is empty |

Before this split they were one silence, and "we could not look" was indistinguishable from "the BSS
is empty". `NO_MATCH` mattered most of the four while it existed: reporting it as `NO_CLIENTS` would
describe a BSS we demonstrably heard traffic on as dead, and send the operator to look for a dead AP
instead of at the gate that dropped the stations.

`resp_fire` then snapshots, transmits, waits `RESP_SETTLE_SECS`, re-snapshots, and judges **each
subject** with `resp_verdict`:

| Per-subject verdict | Means |
|---|---|
| `MOVED` | gone from Recon, or its packet counter stalled with nothing newer seen |
| `NO_EFFECT` | counter still advancing — it never left |
| `INCONCLUSIVE` | no baseline, no follow-up reading, or the counter stalled but it was seen again |
| `LOCK_FAILED` | the radio would not hold the channel; nothing was transmitted |
| ~~`NO_CLIENTS`~~ | *no longer written (2026-11-10): a broadcast target with no clients fires, and is the one `INCONCLUSIVE` subject* |

`resp_aggregate` reduces those to the one verdict shown on screen and written to `events.log`:
**`MOVED` only when every subject went quiet**, `NO_EFFECT` when any kept transmitting,
`INCONCLUSIVE` otherwise. The screen also shows the ratio (`3/4 quiet`), because "two of five
cameras dropped" is a materially different outcome from "all five dropped" and collapsing them
would hide it.

Worth stating plainly: **nobody has publicly demonstrated the CSA attack moving a real client.** The
aircrack-ng PR that popularised it (#2724, still unmerged) ships a regression test whose hostapd
config has no `wpa=`, no `ieee80211w` and no station — it counts bytes leaving an interface and
skips in CI. This verdict model is what turns an unverifiable attack into a measurable one, and it
is the most valuable part of the response side.

## 8. Where the code lives, and why

CamHound ships as **three payloads** generated from one source. `dev/CamHound/gen_hooks.sh` builds
`library/recon/{client,access_point}/CamHound/payload.sh` from the user payload's config block +
lib block + watch-core block + `hook_main.sh`, and `check_sync.sh` enforces byte-identity of those
blocks across all three. That constrains placement absolutely:

| Code | Block | Shared with hooks? |
|---|---|---|
| config keys | config block | yes |
| posture read (`# --- response posture ---`) | **lib block** | yes |
| response rung (`# --- response rung ---`) | **watch-core block** | yes |
| `set_state` response states | lib block | yes |
| `detail_card` Disrupt row, `offer_dialogs` rung | user payload only | no |
| selftest | user payload only | no |

The rung sits in the watch-core block because it depends on `lock_target`/`unlock_target`, which
live there — and because putting it there means `gen_hooks.sh` carries it into both Recon hooks with
**no change to `gen_hooks.sh` or `check_sync.sh`.** Anything added to the response side must respect
this: edit the user payload, run `gen_hooks.sh`, then `check_sync.sh`, then `--selftest`, then the
harness.

## 9. Entry points

Five ways to reach Disrupt, all gated on `RESPONSE`, which defaults to 1:

1. **Device card** (`detail_card`) — the manual path, beside Watch and Locate. Shows a cached badge
   in the row when one is fresh; an uncached badge is not worth a capture just to render a menu.
2. **Post-Watch picker** (`summary_card`) — after any Watch that reaches a verdict (an INCONCLUSIVE
   Watch logs and returns with no picker: `live_view` and `stimulus_test` call `summary_card` only on
   the other branch).
3. **Post-Watch auto-offer** — on a `STREAM` or `EVENT` verdict, the strongest evidence CamHound can
   produce that a device is a live camera. This is where the funnel closes: detect → Watch →
   confirmed → respond.
4. **Recon hooks** (`hook_main.sh`) — a target selected from the Recon AP or client menu.
5. **`offer_dialogs`** — the third branch of its `if`/`elif` chain, reached by a CONFIRMED device
   that the Watch and Locate branches above it did not take and that `auto_respond_ok` accepts
   (`RESPONSE=1`, `AUTO_RESPOND=1`, not ignored, `resp_target` succeeds). With `AUTO_WATCH=1` that
   is a device that cannot be Watched — no tcpdump; an unassociated client fails `resp_target` and
   never gets here. With `AUTO_WATCH=0` (the README's walk-survey setting) it is **every newly
   CONFIRMED device**, on identity evidence alone and with no Watch; with `AUTO_LOCATE=0` a
   CONFIRMED setup AP too. The confirm dialog, the picker and `RESPONSE_CONFIRM` still gate the
   transmit.

## 10. Config

| Key | Default | Persist | Meaning |
|---|---|---|---|
| `RESPONSE` | 1 | `*` | master switch; 0 = recon only, nothing transmits |
| `RESPONSE_CONFIRM` | 1 | `*` | blocking confirmation before any transmit |
| `AUTO_RESPOND` | 0 | `*` | let the funnel raise Disrupt by itself (needs `RESPONSE=1`) |
| `POSTURE_TTL` | 300 | `*` | seconds a badge stays cached per BSSID |
| `RESP_SETTLE_SECS` | 6 | `*` | wait after transmitting before judging the effect |
| `BCN_CAP_SECS` / `BCN_CAP_COUNT` | 4 / 5 | | beacon capture window and frame count |
| `RESP_LOCK_SECS` | 20 | `*` | EXAMINE lock duration held across a response; raised to `RESP_SETTLE_SECS + 5` when set lower |
| `SCAN_IF` | `wlan0` | | reserved, currently unused |

The six starred keys are also on the device's **Settings → Response settings** page. Switching
`RESPONSE_CONFIRM` off asks a second time, and a lock shorter than `RESP_SETTLE_SECS + 5` is raised
on apply and saved as raised (`settings_apply` re-runs `resp_clamp_lock`), so the menu shows the value
in force. `Reset defaults` clears these overrides along with the recon ones.

**Two keys, not one.** `RESPONSE` opens the manual rung; `AUTO_RESPOND` additionally lets CamHound
raise the *offer* by itself. Since 2026-11-03 `RESPONSE` ships at **1**, so the rung is present out of
the box, and `RESPONSE_CONFIRM` (also 1, and now failing closed on any non-zero value) gates every
individual transmit. The separation is what makes "the rung exists" and "CamHound may raise it by
itself" independent choices.

*Corrected: an earlier revision said `AUTO_RESPOND=0` was "the only thing keeping the shipped default
free of an unprompted transmit path", which undersells the design — **there is no unprompted transmit
path at any setting.** `AUTO_RESPOND` only raises a dialog; the picker still has to be answered and
the confirm cleared, and with `RESPONSE_CONFIRM=0` the picker's accept is itself an operator action.
No combination of the three keys reaches the air without a dialog.*

## 11. Loot

`responses.tsv`, `|`-separated with a `#` header, **one row per measured subject** (so an attempt
whose scope is `bss` against a BSSID with four clients writes four rows, one attempt — including when
the operator picked a single client row and chose `CSA` or `BOTH`):

```
#epoch|mac|role|bssid|target|ch|band|badge|rsn_caps|beacon_prot|attack|cmd|lock|pk_before|pk_after|verdict
```

`mac` is the enumerated target the operator acted on; **`target` is the subject actually measured**
— the individual client for a broadcast attempt, not `ff:ff:ff:ff:ff:ff`. `resp_write` takes that as
an optional 9th argument and defaults to `R_TARGET`. `rsn_caps` is the raw 2-octet RSN Capabilities
field, low octet first; `beacon_prot` is octet 10 of the Extended Capabilities element, or `-` when
absent. Keeping the raw bytes means a disputed badge can be re-derived from the loot rather than
re-argued.

The aggregate verdict is **not** in this file; it is on screen and in `events.log`. The per-subject
rows are the evidence, the aggregate is the summary.

## 12. What is verified

Laptop only, no radio. The selftest ends **0 failed** (it prints its own count, which grows with every
addition, so it is not restated here), and
the harness has a `disrupt` scenario that exercises the whole chain end to end — log-only stubs for
the three `PINEAPPLE_DEAUTH_CLIENT*` commands that record their arguments and transmit nothing, plus
a synthetic-beacon branch in the fake `tcpdump`. That scenario checks the posture read happening
under a lock on the target channel, the badge derived from the beacon, the correct command invoked
with the right BSSID/target/channel, the lock verified as `ok` rather than by-channel, the
per-subject loot rows with badge and raw caps, the aggregate verdict, the no-clients guard, the
cached badge appearing on the card afterwards, and EXAMINE being released. Two further scenarios
reach the confirms the badge logic adds: `blind` (the fake `tcpdump` captures no beacon, so the badge
is `?`) checks that the "Fire blind?" dialog appears, that accepting it offers CSA first with every
option labelled `unknown`, fires `PINEAPPLE_DEAUTH_CLIENT_CSA` with bssid and channel only, and
writes loot rows with badge `?` and caps `-`, and that declining it sends nothing and writes no row;
`noinj` (the Reolink AP moved to DFS channel 52) checks that gate 1 answers `NOINJ` with no capture
and no lock, and that declining "Try anyway?" sends nothing. An accepted "Try anyway?" is still
unreached by any test. `cliscope` (2026-11-03) drives both scopes from one client-row menu: `DEAUTH`
confirms one device and measures one subject; `BOTH` confirms "EVERY client", measures the four
visible clients, loots all four and names the picked device's own verdict. `disrupt` now runs at the
shipped default with no `RESPONSE` override in the saved config, and asserts the transmit. The selftest
pins `attack_scope` on four cases, `resp_snapshot` on seven (own-BSS sweep, cli scope, bss from a client
row, a target whose row is foreign to the BSSID in both scopes, a randomised pick kept, one Recon read
for the sweep, and the `recon_stat` fallback adding an out-of-sweep pick for one more read), and
`resp_verdict - - - - 0` as `INCONCLUSIVE`.

Unit coverage:

- every badge from hand-built RSN and Extended-Capabilities byte vectors, both beacon-protection
  states, absent/short/truncated/garbage elements, each regulatory class
- beacon element parsing against synthetic frames built by `st_beacon_pcap()` — open network,
  WPA2 without PMF, PMF required, PMF + beacon protection, DFS override, bad pcap magic, a capture
  containing no beacon
- `ie_find` on absent and truncated element chains; `rsn_caps` walking the suite lists
- target resolution for AP / client / unassociated / channel-less
- every verdict branch
- the two-key auto-respond gate, ignored targets, unattackable targets
- the loot row's field count against its header

`check_sync.sh` clean, all three payloads parse, `shellcheck` clean.

## 13. What is unverified

*Superseded three times, so read this floor as history: 2026-11-04 (membership read off the air,
§13a-i), 2026-11-05 (a Disrupt transmitted from the user payload, CLAUDE.md "Second contact"), and
2026-11-10 (an AP row fires even when the capture recovers nobody — operator-decided,
*"I'll accept nuclear blast. Let the AP row fire broadcast frames."*). The `NO_CLIENTS` outcomes in the table below no longer happen on an AP row.
What still holds is the user-payload **client** row aborting in `resp_target`.*

**⚠ First, the floor — and it applies to the USER PAYLOAD only.** From the user payload this rung
cannot transmit on any shipped firmware, and flashing does not fix that. The Recon hooks reach the
air by another route entirely; the exception at the end of this section is the important part.
Two different mechanisms, same outcome, and the blocker is the **association column** rather than the
firmware version:

| firmware | what happens | where |
|---|---|---|
| **1.1.3** | `_pineap RECON CLIENTS` does not exist (measured 2026-11-03: `Unknown recon command`, rc 255); since that day `recon_lines CLIENTS` reads `RECON DEVICES` instead, whose object carries no association, so a client row has `AP_OF` `-` and `resp_target` refuses it like 2.0.0's. Every AP row has `R_TARGET` broadcast, subjects are 0 → `NO_CLIENTS`. | `resp_snapshot`'s `[ "$a" = "$R_BSSID" ]` sweep iterates the `RECON DEVICES` client rows and matches none, every `AP_OF` being `-` → `resp_fire` refusal; a client row is refused earlier, by `resp_target` |
| **2.0.0** | client rows arrive, but the device object has no association field, so `JQ_CLI`'s `(.ap_mac // .bssid // "-")` yields `-` for all of them. An **AP row** finds 0 matching clients → `NO_CLIENTS`. A **client row** never reaches the sweep: `AP_OF` is `-`, so `resp_target` returns 1 and `disrupt_menu` aborts with "nothing to attack: no associated BSS". | `payload.sh:2122-2123`; `resp_snapshot`'s `[ "$a" = "$R_BSSID" ]` |

*Corrected 2026-11-03. An earlier revision of this section said the rung was "inert until the device
is flashed to 2.0.0", which is wrong and was the more consequential half of the claim — it implied a
flash would buy a working response rung, and it would not. The 1.1.3 half stands.* From the user
payload, nothing is transmitted on either firmware and the refusal is logged.

**⚠ The Recon client hook is the exception, and it transmits on 1.1.3 today.** Everything above is
about the **user payload**, whose association comes from `recon_lines CLIENTS`. The two Recon hooks do
not use it: `hook_target` (`dev/CamHound/hook_main.sh:20-37`) builds its one row from the
`_RECON_SELECTED_*` variables the Recon UI exports, setting `AP_OF[$HOOK_MAC]` from
`_RECON_SELECTED_AP_BSSID` and the channel from `_RECON_SELECTED_{CLIENT,AP}_CHANNEL`, with **no
`_pineap RECON` call at all**. So a hook client row has a real association and a real channel,
`resp_target`'s client branch passes, and `resp_fire` transmits behind the usual picker and confirm —
on 1.1.3, on 2.0.0, regardless of what `RECON CLIENTS` returns. *Found by the recon-side session's
review; verified at `hook_main.sh`'s `hook_target` and `resp_target`.* So "the rung cannot
transmit" was true of the user payload only, and §13a-i has since made it untrue of its AP rows too.

**[A]** — the `CLIENTS` byte count and the 2.0.0 device-object shape are `[V]` from the binaries (see
`/CLAUDE.md`); the code paths were read in the payload; composing them is the inference. *Falsified
by:* a Disrupt transmitting **from the user payload** on either firmware, or `_pineap RECON CLIENTS
format=json | jq '.[0]|keys'` on a 2.0.0 Pager returning any key that carries the BSSID. (An earlier
form of this falsifier named AP rows only, which could not have caught the hook path — the lesson
being that a falsifier naming one entry point does not test a claim made about the payload.)

**The lead that was worth trying, followed 2026-11-03.** 1.1.3 *does* have `RECON DEVICES` and
`COUNT DEVICES` (only `CLIENTS` is new), and CamHound now reads `RECON DEVICES` where `CLIENTS` is
refused (`recon_verb_probe` at start, `JQ_DEVCLI` for the rows): probe-only clients are listed on
1.1.3 with their probed SSIDs. What the on-device command showed is that the object carries **no
association** — the device's own keys are `freq`, `mac`, `packets`, `signal`, `time` beside the
hash-keyed `beacon`/`response`/`probe` objects — so that half of the lead is spent, and the rung is
no nearer firing from the user payload. The other half is untested: the `probe`/`beacon` objects are
keyed by an opaque internal **SSID hash**, so a client's probe-key set and an AP's beacon-key set
could in principle be intersected to recover an association the JSON does not state outright.
**[A]**, offered as a direction, not a finding — a client probing for an SSID is not necessarily
associated to it, and §13a's capture route is the better evidence.

### 13a. The association column is a chokepoint, and the rung is fixable without it

**Five separate features, one missing field.** Verified in code 2026-11-03, so this is worth more
than any one of them: `AP_OF[mac] == "-"` disables **Watch on a client** and **Stimulus**
(`watchable()`, and `watch_prepare`'s "no BSSID: cannot lock"), **kit detection** — CamHound's
largest single identity signal — (`kit_eval`), the **AP→client tree** in the report
(`write_report`), and the **response rung** for client rows (`resp_target`). Cited by name: every
one of those four line numbers went stale within a commit. Fixing the association is therefore the
highest-value change available to this payload, and worth more than a firmware flash.

**But the response rung does not actually need it, and this reframes the whole problem.** Read what
goes on the air (`resp_fire`'s transmit): `CSA` is `<bssid> <ch>` and `BOTH` is `<bssid> <target>
<ch>` with the target discarded. **Both need only a BSSID and a channel, and `RECON APS` supplies
both on 1.1.3.** The firmware can transmit these today. What refuses is CamHound's own verification
guard (`resp_fire`, the `NO_CLIENTS` branch — *removed for AP rows 2026-11-10, operator-decided,
"nuclear blast"*): `resp_snapshot` found nobody to *measure*. So the
blocker is the oracle, not the capability — the rung is asking the firmware a question the firmware
cannot answer, when the answer is on the air.

**The fix: derive subjects and verdict from a capture.** Every primitive already ships —

| need | already in the payload |
|---|---|
| BSSID-filtered data capture | `start_caps`, `"type data and wlan addr1 $WATCH_BSSID and not wlan addr2 $WATCH_MAC"` — shape only: its `-s 32` is **too short to reach `addr2`**, see §13a-i |
| pcap + radiotap + 802.11 walking | `beacon_find` — reads radiotap `it_len` at `p+2`, frame at `p+rt`, knows the 24+12 offsets |
| octet / u16 readers | `hex_octet`, `hex_u16le` |
| channel lock across a response | `lock_target` / `RESP_LOCK_SECS`, already held |

A client's MAC is `addr2`, six octets at `p + rt + 10`. Walking the records for frames addressed to
the BSSID yields that AP's active clients off the air — **firmware-independent, works on 1.1.3 and
2.0.0 alike**. It is also better evidence than it replaces: Recon's `packets` is session-cumulative
and dwell-biased (`PLAN_v2.md:206` says so), while a before/after capture counts frames in a window
we control.

Ranked options: **(1)** capture-based subjects and verdict, ~30-40 lines reusing the above plus
`resp_snapshot`/`resp_fire` wiring, selftest cases (`st_pcap` already builds synthetic pcaps) and a
harness scenario; **(2)** the §13 lead, half followed 2026-11-03: the one-command probe is spent
(`RECON DEVICES` carries no association), and what remains is intersecting a client's probe-hash keys
with an AP's beacon-hash keys, **[A]** and weaker than (1) because probing for an SSID is not
association; **(3)** let a BSS-wide attack fire with an explicit `INCONCLUSIVE` when nothing is
measurable — nearly free, but it discards the discipline that makes the verdict worth having, so it
belongs *underneath* (1) as the heard-nothing fallback, not instead of it.

Two unverified mechanics, both parameters rather than obstacles: whether `-s 32` clears radiotap far
enough to reach `addr2` (`capture_beacon` uses `-s 0`, so the snap may need raising), and whether a
second concurrent capture is safe during a response — already an open Phase 0 question in
`PLAN_v2.md`. One real limitation: a capture sees only **active** clients, so an associated-but-idle
camera stays invisible and a silent BSS still has nothing to measure. For a camera hunter that bias
is mostly benign, since a streaming camera is busy by definition.

### 13a-i. The build decision of record (2026-11-04): membership from the air, counters from Recon

**§13a above is the problem statement and stays; its option (1) — "capture-based subjects *and*
verdict" — is NOT what was decided.** What was adopted is the narrower split: **the capture supplies
MEMBERSHIP; Recon still supplies the COUNTERS.** `resp_verdict`, `resp_aggregate` and `resp_write`
are untouched, so their selftest and harness coverage keeps its meaning, and `resp_snapshot` keeps
its documented one-Recon-read property. Recorded here so the next session does not re-derive the
counts-from-capture version, and does not read §13a's option (1) as the plan.

**⚠ Three mechanics asserted in §13a's draft are wrong.** Each was checked against the file, not
recalled; a reader who implements §13a as written will hit all three.

| §13a says | What the artifact says | Consequence |
|---|---|---|
| "A client's MAC is `addr2`, six octets at `p + rt + 10`" | True **only for a ToDS frame**. On a FromDS frame `addr2` **is the BSSID** and `addr1` is the client. `addr2` is always the *transmitter* (`PLAN_v2.md:55`, IDEA_27 at `:164`) — and on a downlink frame the transmitter is the AP. | Harvesting `addr2` unconditionally records the AP as its own client. `resp_snapshot`'s stated invariant — "The AP's own counter is never the subject: it keeps beaconing whatever happens to its clients" (`payload.sh:2184`) — breaks, and one AP subject scoring `NO_EFFECT` makes `resp_aggregate` return `NO_EFFECT` for the whole attempt (`:2203`), so successes systematically read as failures. |
| "whether `-s 32` clears radiotap far enough to reach `addr2`" — framed as a parameter | **Arithmetic settles it: it cannot.** `addr2` occupies frame octets 10-15, so a record must hold `rt + 16` bytes. mac80211's RX radiotap is at minimum FLAGS+CHANNEL+DBM_ANTSIGNAL and normally TSFT, with an MCS/HE block on an ax radio (`phy1`, backports 6.12.61): 18 at the optimistic floor, and `18 + 16 = 34 > 32`. The Watch rung's `-s 32` is **deliberately header-only** — `PCAP_AWK` reads only `hdr[1]`, `hdr[3]`, `hdr[4]` (`payload.sh:1756-1759`) and never touches frame content — so its existence is evidence of nothing about address reachability. | At `-s 32` every record fails the `rt + 16` guard and the walker returns **zero** clients, which is indistinguishable from the `NO_CLIENTS` bug being fixed. |
| the primitives table: `beacon_find` + `hex_octet` / `hex_u16le` are "already in the payload" | The **algorithm** transfers; the **mechanism** does not. Bash `${var:off:len}` costs O(length of the *whole* string), so a `pcap_bytes` + substring walk is O(records x filesize). Measured twice, independently, with a **fixed read count of 2000** against a growing string — that fixed count is the whole proof, since a constant number of reads taking longer on a bigger string means each read is O(length). First run 32 KB 156 ms, 128 KB 969 ms, 512 KB 3331 ms, 2048 KB 13634 ms; re-run 146 / 751 / 3665 / 15938 ms. *Corrected on the re-run:* an earlier revision of this row also claimed head-offset and tail-offset timings were **identical**, offered as ruling out "it is just the offset". They are not — at 2048 KB the tail offset came back at 9539 ms against 15938 ms at the head, about 40% faster. That sub-claim is withdrawn; it was never load-bearing, and the fixed-count scaling above settles the question without it. The Pager is a 580 MHz MIPS 24KEc, 15-40x slower. `beacon_find` escapes this only because `capture_beacon` bounds it with `-c 5` of ~350 B. | A parse that overruns the EXAMINE lock produces the **false `MOVED`** that `resp_clamp_lock` exists to prevent: the post-fire Recon read lands after hopping resumed, the counter looks stalled, and `resp_verdict` scores `MOVED` with a green `RESPOND_HIT`. Reproduce in one line (a session scratchpad will not exist for you): `h=$(head -c 2097152 /dev/zero \| tr '\0' a); time for ((i=0;i<2000;i++)); do b="${h:$((i*2)):2}"; done`. |

**Resolved mechanics, as decisions.** Filter `type data and (wlan addr1 <bssid> or wlan addr2
<bssid>)`, falling back once to `type data and wlan addr1 <bssid>` if tcpdump fails to arm —
`PLAN_v2.md:599` (Phase 0 item 13b) records "OR filter fails -> two instances" as an open risk on
this libpcap, and the fallback discharges it on the first device run instead of scheduling a bench
step. Snap **128**, not 96: `PLAN_v2.md:53`'s `-s 96` is a *conditional* upgrade for the Watch
"others" capture gated on parse time, not a validated minimum for addressing, and `PLAN_v2.md:236`
still lists both "minimum accepted snaplen" and "radiotap length on this driver" as hardware-only
unknowns. `PLAN_v2.md:71` (item 10) is the better precedent: `-s 128`, "it_len read per record".
Parse with a **byte-oriented awk state machine**, never `pcap_bytes`. The walker reads the DS bits
and matches the BSSID **in frame** rather than trusting the BPF filter, so it is correct under a
widened, mistaken or stubbed filter — which matters here because the harness tcpdump stub
**implements no filtering at all**.

**Two things §13a listed as unverified are now closed on paper, no Pager needed.**

1. *"whether `-s 32` clears radiotap"* — answered above: no, by arithmetic. Not a parameter.
2. *"whether a second concurrent capture is safe during a response"* — **it does not arise.** Every
   path into `disrupt_menu` is reached after `stop_caps` and `unlock_target` have already run:
   `live_view` unlocks before `summary_card`, as does `stimulus_test`, and
   `review_list` / `detail_card` / `hook_menu` are outside Watch entirely. `CAP_PIDS` is empty at
   `resp_fire` time. Phase 0 item 13c (CPU under concurrent captures) is therefore **not** a
   precondition for this work. *Falsified by:* a `disrupt_menu` call site reachable with
   `WATCH_LOCKED=1` and `CAP_PIDS` non-empty.

**🆕 What a device run buys for free.** Logging the largest radiotap `it_len` the walker saw, on
every run, **discharges `PLAN_v2.md:236`'s "radiotap length on this driver"** — an item currently
parked as hardware-only — without a bench step, and makes the snap length self-reporting: `it_len
max + 16 > snap` says "measured wrong", where silence would say "nobody there". Take that reading
**before** trusting any other result from the rung; if it comes back above 112 the snap needs raising
and every other result is confounded by an empty subject set.

**Union, never replacement.** The test **as shipped** is

```sh
[ "$a" = "$R_BSSID" ] || { [ "$RESP_MEMBERS_BSS" = "$R_BSSID" ] && [ -n "${RESP_MEMBERS[$m]+x}" ]; } || continue
```

*An earlier revision of this section quoted it without the `RESP_MEMBERS_BSS` guard. That guard is
not decoration: without it a set gathered for one BSSID is applied to the next target, which is the
staleness bug `posture_of` documents for its caps globals, and the selftest case "a set gathered for
another BSSID is ignored" fails when it is removed.* Measured on this host at the time of the
decision: replacing the `ap_mac` test breaks **5 of the 9** `snapshot` selftest cases (236 checks /
5 failed), unioning breaks **none** (236 / 0). Those counts are pre-implementation; the suite is
larger now.
The decisive failure is *"snapshot bss stays at one read: got [2] want [1]"* — under replacement the
picked target falls out of the sweep and fires the `recon_stat` fallback, destroying the
single-Recon-read property. Note **why** the five fail, because it is not what it looks like: the
selftest's own `recon_lines` stub supplies real `ap_mac` values, as does
`dev/CamHound/harness/fix/cli.json`, so the existing cases test a column **no shipped firmware
emits**. Union is still the right answer, for a reason independent of the fixtures — on real
firmware `$a` is always `-`, so the union *is* the membership test there, and it is the identity
transform until a capture runs.

**⚠ No harness scenario drives Disrupt on the real-firmware shape.** `cli.json` carries 10 `ap_mac`
values; `devices.json`, the fixture built from the measured 1.1.3 output, carries none. Only
`HARNESS_NO_CLIENTS=1` reaches `devices.json` (`harness/stubs/_pineap`), and the three scenarios
that set it — `nojq`, `devices` — never open Disrupt. So the `NO_CLIENTS` refusal that is the entire
bug **has no coverage today** *(history: `s_members` covered it from 2026-11-04, and since 2026-11-10
that arm asserts the zero-member AP row FIRES, via `nomem_fired`)*, and `s_disrupt`'s `moved=2 ... of 2` is produced by association data
the device never supplies. Any fix here must add a Disrupt-under-`HARNESS_NO_CLIENTS` arm or it is
testing fiction.

**Honest bound.** This unblocks **AP-row** Disrupt in the user payload and the **Recon
access_point hook**, which is refused 100% of the time today on both firmwares. It does **not**
populate `AP_OF`, so the other four chokepoint features stay inert, and a user-payload **client**
row still aborts in `resp_target`'s client branch — on real firmware such a row is not even
`watchable` (`:1018`), so the detect→Watch→confirmed→Disrupt funnel reaches `summary_card` only for
AP rows anyway. The inverse lookup that would fix the client row — `type data and wlan addr2 <mac>`,
BSSID from `addr1` on a ToDS frame, the same walker with the two addresses swapped — is worth more
than this change, because `AP_OF` gates five features. It is **recon-side** (`AP_OF` is filled by
`record_seen`/`JQ_DEVCLI` at `:1226` and surfaces in `inventory.tsv`'s `ap_bssid` column and the
report tree), so it is handed over with the parser proven rather than written here.

Needs a Pager:

- whether `tcpdump` beacon capture on `wlan1mon` works while pineapd owns and hops it
- whether the three `PINEAPPLE_DEAUTH_CLIENT*` commands behave as `hak5cmd`'s help text claims
- `PINEAPPLE_DEAUTH_CLIENT_ALL`'s target argument — its help says "all clients on an AP" yet it
  takes a target, which is passed through but whose semantics are unconfirmed
- whether `DEAUTHCSA` emits a CSA-bearing beacon or a spectrum-management action frame — **beacon,
  strongly indicated but not proven.** The evidence is `csa_beacon_record`,
  `recon_engine::inject_csa` and the string `"Caught beacon for CSA on {}"`. It is **not** the
  import list: pineapd imports 21 `libwifi_*` symbols of which four are builders
  (`libwifi_create_beacon`, `_deauth`, `_disassoc`, `_radiotap`), but it also imports `pcap_inject`
  and injects arbitrary caller-supplied buffers, and it already hand-composes a CSA element without
  importing any `libwifi_*_tag` function — so "no action builder, therefore no action frame" does
  not follow. (The shipped `.so` exports 113 functions including `libwifi_create_action` and
  `libwifi_create_probe_resp`, all unreferenced. See `dev/pager-csa-primitives.md`.) An earlier
  revision of this file recorded this as settled on the invalid argument; the conclusion survives,
  the reasoning did not.
- whether Recon's packet counters move the way `resp_verdict` assumes
- whether the CSA attack moves a real client **at all** — see §7

**A note on running the harness where no hex dumper is present.** `preflight()` sets `HAVE_TCPDUMP`
when `tcpdump` and either `hexdump` or `od` are present (`capture_ready`). On a machine with neither
dumper, `HAVE_TCPDUMP` stays 0, `capture_beacon` returns immediately, and every assertion that depends
on a capture fails — the Watch scenarios and the posture half of `disrupt`. This is environmental and
not a code defect; installing either dumper clears all of them. Worth knowing
because the failures look alarming and are not.

History: an earlier gate required `hexdump` alone although **both** pcap readers (`pcap_words`,
`pcap_bytes`) already had `od` fallbacks; `capture_ready` now accepts either dumper. On a Pager
`hexdump` is always present via busybox, so this only ever mattered on a laptop.

## 14. Known limits

- **Beacon protection defeats the CSA *channel move*** (WPA3, December 2020 update onward; AP
  support is mandatory in Wi-Fi 7, and hostapd enables it by itself once 11be is on with PMF), so
  that decays over time. Verified in mac80211's receive path: where the client holds a BIGTK and MFP
  is in use, an MME-less beacon is dropped before the CSA element is parsed.
- **`NONE` meaning "nothing this firmware sends works" is correct, and here is the proof.** There
  *is* a path by which a forged CSA beacon denies auth/assoc even on a beacon-protected AP —
  `ieee80211_scan_rx()` updates the BSS cache before the protection check, and
  `ieee80211_mgd_csa_in_process()` then makes `ieee80211_mgd_auth()` and `ieee80211_mgd_assoc()`
  bail. But **pineapd cannot reach it.** Its CSA element is built at `0x4bee8a` as
  `{37, len 3, mode 1, new_ch=<runtime>, count 0}`, and `ieee80211_mgd_csa_present()`
  (`mac80211_mlme.c:8349`) discards any CSA with `count == 0` before that check runs. So the refusal
  never fires. Count 0 is simultaneously what makes the *channel move* immediate
  (`max_t(int, count, 1) - 1` clamps it to zero delay), which is why CSA works on the other badges.
  **[V]** both sides — the emitted bytes and the kernel check. Full working in
  `dev/pager-csa-primitives.md`, section "THE ONE BYTE".
  *The experiment this implies:* any non-zero count survives `csa_present()`, so the same frame with
  `count = 3` would get the move **and** the refusal. That needs a non-pineapd injector (Stage B of
  `dev/pager-6ghz-determination-plan.md`); there is no setting for it. Until that is measured,
  `posture_opts` offering nothing at `NONE` is right, not conservative.
- **DFS and 6 GHz are refused** by pineapd's compiled-in switch (gate 1) whatever the regulatory
  domain, and cfg80211 (gate 2) silently drops frames on channels the live domain marks disabled or
  no-IR; `csa_injectable` models both. From the stock commands: 2.4 GHz and non-DFS 5 GHz only.
- **Detection is improving fast.** Kismet merged a CSA-flood alert (>20 CSA beacons from one BSSID
  in 2 s) and has an open signature targeting tools that copy a captured beacon and change only the
  sequence number — which is what `DEAUTHCSA` does. Expect this to be visible to a competent WIDS.
- An SSID containing an escaped quote truncates in a display label. Targeting is unaffected.

## 15. References

- aircrack-ng PR #2724, "Added new CSA-based deauth" — the reference implementation and its
  limitations: https://github.com/aircrack-ng/aircrack-ng/pull/2724
- Kismet CSA detection: issue #666 (merged), #668 and #669 (spoofed-CSA signatures)
- Beacon protection: Wi-Fi Alliance WPA3 December 2020 update; Vanhoef, *Protecting Wi-Fi Beacons
  from Outsider Forgeries*, WiSec 2020
- MFPC/MFPR bits: hostap `src/common/wpa_common.h`; `iw` `scan.c`; Wireshark
  `packet-ieee80211.c`
- Beacon Protection bit 84: hostap `src/ap/ieee802_11_shared.c`,
  `WLAN_EXT_CAPAB_BEACON_PROTECTION`
- Hak5 `DEAUTH_CLIENT` documentation, for the vendor's own statement that PMF blocks it
