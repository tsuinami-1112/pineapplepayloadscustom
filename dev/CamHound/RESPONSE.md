# CamHound response side — how it works

Developer reference for the **Disrupt** rung: the part of CamHound that turns a detection into a
disconnection. `PLAN_v2.md` covers the recon side; this covers everything downstream of it.

Status: coded and verified on a laptop only. **No Pager has run any of it.** Section
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

| Key | Command | Frames |
|---|---|---|
| `DEAUTH` | `PINEAPPLE_DEAUTH_CLIENT [bssid] [target] [channel]` | deauth + disassociation |
| `CSA` | `PINEAPPLE_DEAUTH_CLIENT_CSA [bssid] [channel]` | channel-switch announcements |
| `BOTH` | `PINEAPPLE_DEAUTH_CLIENT_ALL [bssid] [target] [channel]` | all three |

`CSA` takes no target because it rides in a beacon and has no unicast recipient. There is also a
`_pineap` layer (`DEAUTH`, `DEAUTHCSA`, `DEAUTHALL`) and an HTTP layer (`/api/pineap/deauth`,
`/deauth_csa`, `/deauth_all`); the DuckyScript wrappers are what payloads should use.

Consequence for this design: **no injector binary, no cross-compile, no OpenWrt SDK, no release
artefact.** The response side is shell calling vendor primitives, exactly like the rest of the
payload. That is why it is ~370 lines and not a C project.

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
  5 GHz rule carries `NO-IR`, gate 2 permits all of 36–165 and the DFS block is entirely gate 1's.
  This gate *does* follow the regulatory domain, so it is read live by `inj_probe()` from
  `iw phy <phy> channels` and cached in `INJ_OK` keyed `band/channel`.

Why reading gate 2 live rather than hardcoding it: a frame gate 2 rejects is freed with
`NETDEV_TX_OK`, so nothing reports an error and an over-permissive verdict **reads back as the
target having resisted**. That is strictly worse than refusing a channel that would have worked,
which is why the fallback when the probe fails is only what is injectable under *both* the US and
world domains — 2.4 GHz 1–11 and 5 GHz 36–48. Under the world domain even 149–165 is `NO-IR`, and
2.4 GHz 12–14 are blocked under both (`DISABLED` under US, `NO-IR` under `00`).

`inj_probe()` must run in the **parent shell** — `preflight()` and on entry to `disrupt_menu()`.
`csa_injectable()` is reached from `posture_from_caps()` inside `$( )`, where writes to globals are
discarded, so it is strictly read-only. Every phy is probed and merged; each registers only its own
bands, so `band/channel` keys do not collide, and this avoids having to guess which interface
pineapd will pick as its injector.

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

**What gets measured: subjects, not the target.** `resp_snapshot()` collects a packet counter and
last-seen time per *subject* from one Recon read:

- **client target** → the client itself.
- **broadcast target** (an AP) → the AP's **visible, non-randomised clients**. The AP's own counter
  is deliberately never used: it keeps beaconing whatever happens to its clients, so it carries no
  signal. Randomised MACs are excluded via `is_rand` because they rotate and would read as `MOVED`
  for free.
- A client row that Recon happens to list as an AP falls back to `recon_stat`.

This distinction was a real defect, not a refinement. The first version asked Recon about
`R_TARGET` directly, and for a broadcast attempt that is `ff:ff:ff:ff:ff:ff`, which never appears in
Recon. `recon_stat` therefore failed, `present` was 0, and **every broadcast attempt was judged
`MOVED` regardless of effect**, with no counters in its loot row. The unit tests covered
`resp_verdict`'s branches in isolation and never the composition that fed it, so they passed while
the result was wrong.

**A broadcast target with no visible clients is refused** before the lock is taken and before
anything is transmitted, and records a `NO_CLIENTS` row. There is nothing to disconnect and nothing
to measure, so sending would be unverifiable noise.

`resp_fire` then snapshots, transmits, waits `RESP_SETTLE_SECS`, re-snapshots, and judges **each
subject** with `resp_verdict`:

| Per-subject verdict | Means |
|---|---|
| `MOVED` | gone from Recon, or its packet counter stalled with nothing newer seen |
| `NO_EFFECT` | counter still advancing — it never left |
| `INCONCLUSIVE` | no baseline, no follow-up reading, or the counter stalled but it was seen again |
| `LOCK_FAILED` | the radio would not hold the channel; nothing was transmitted |
| `NO_CLIENTS` | broadcast target with no measurable clients; nothing was transmitted |

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

Four ways to reach Disrupt, all gated on `RESPONSE=1`:

1. **Device card** (`detail_card`) — the manual path, beside Watch and Locate. Shows a cached badge
   in the row when one is fresh; an uncached badge is not worth a capture just to render a menu.
2. **Post-Watch picker** (`summary_card`) — after any Watch.
3. **Post-Watch auto-offer** — on a `STREAM` or `EVENT` verdict, the strongest evidence CamHound can
   produce that a device is a live camera. This is where the funnel closes: detect → Watch →
   confirmed → respond.
4. **Recon hooks** (`hook_main.sh`) — a target selected from the Recon AP or client menu.
5. **`offer_dialogs`** — a secondary rung for a CONFIRMED device that cannot be Watched at all (no
   tcpdump, or not associated), placed below the existing Watch and Locate rungs so identification
   still comes first.

## 10. Config

| Key | Default | Persist | Meaning |
|---|---|---|---|
| `RESPONSE` | 0 | `*` | master switch; 0 = recon only, nothing transmits |
| `RESPONSE_CONFIRM` | 1 | `*` | blocking confirmation before any transmit |
| `AUTO_RESPOND` | 0 | `*` | let the funnel raise Disrupt by itself (needs `RESPONSE=1`) |
| `POSTURE_TTL` | 300 | `*` | seconds a badge stays cached per BSSID |
| `RESP_SETTLE_SECS` | 6 | `*` | wait after transmitting before judging the effect |
| `BCN_CAP_SECS` / `BCN_CAP_COUNT` | 4 / 5 | | beacon capture window and frame count |
| `RESP_LOCK_SECS` | 20 | | EXAMINE lock duration held across a response |
| `SCAN_IF` | `wlan0` | | reserved, currently unused |

**Two keys, not one.** `RESPONSE` opens the manual rung; `AUTO_RESPOND` additionally lets CamHound
raise it unprompted. Both default off, so enabling response capability does not by itself create an
unprompted transmit path.

## 11. Loot

`responses.tsv`, `|`-separated with a `#` header, **one row per measured subject** (so a broadcast
attempt against an AP with four clients writes four rows, one attempt):

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

Laptop only, no radio. Selftest is **127 checks, 0 failures** (was 39 before the response side; the
most recent additions are recon-side, for inventory persistence), and
the harness has a `disrupt` scenario that exercises the whole chain end to end — log-only stubs for
the three `PINEAPPLE_DEAUTH_CLIENT*` commands that record their arguments and transmit nothing, plus
a synthetic-beacon branch in the fake `tcpdump`. That scenario checks the posture read happening
under a lock on the target channel, the badge derived from the beacon, the correct command invoked
with the right BSSID/target/channel, the lock verified as `ok` rather than by-channel, the
per-subject loot rows with badge and raw caps, the aggregate verdict, the no-clients guard, the
cached badge appearing on the card afterwards, and EXAMINE being released.

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

**A note on running the harness where `hexdump` is absent.** `preflight()` sets `HAVE_TCPDUMP` only
when **both** `tcpdump` and `hexdump` are present. On a machine without `hexdump`, `HAVE_TCPDUMP`
stays 0, `capture_beacon` returns immediately, and every assertion that depends on a capture fails —
the Watch scenarios and the posture half of `disrupt`. This is environmental and not a code defect:
re-running with a small `od`-backed `hexdump` shim on `PATH` clears all of them. Worth knowing
because the failures look alarming and are not.

Mildly interesting: the gate requires `hexdump` even though **both** pcap readers have `od`
fallbacks (`pcap_words` and `pcap_bytes`). On a Pager `hexdump` is always present via busybox, so
this never matters in production — it only affects laptop runs. Gating on `hexdump || od` would fix
it.

## 14. Known limits

- **Beacon protection defeats the CSA *channel move*** (WPA3, December 2020 update onward; AP
  support is mandatory in Wi-Fi 7, and hostapd enables it by itself once 11be is on with PMF), so
  that decays over time. Verified in mac80211's receive path: where the client holds a BIGTK and MFP
  is in use, an MME-less beacon is dropped before the CSA element is parsed.
- **But the `NONE` badge overstates the defence, and this is a known inaccuracy.** `NONE` currently
  means "nothing here works" and `posture_opts` offers no attack. In fact a sustained forged-CSA
  beacon flood — exactly what `DEAUTHCSA` emits — still **denies auth and association** on a
  beacon-protected AP: `ieee80211_scan_rx()` updates the cfg80211 BSS cache *before* the
  protection check, and `ieee80211_mgd_csa_in_process()` then makes both
  `ieee80211_mgd_auth()` and `ieee80211_mgd_assoc()` bail ("AP is in CSA process, reject
  auth"/"reject assoc"). A camera that cannot re-associate is off the air. **[V]** by source
  reading, **not bench-tested** — which is why the badge has not been changed. Changing it means
  changing what the payload offers an operator, and that wants a real client behind it first.
  Caveats to test: it needs a flood (real beacons overwrite the cache), it bites at connect/roam
  time rather than on an already-associated client, and only `posture_expect` would still be
  honest in calling the channel-move outcome `blocked`.
- **DFS and 6 GHz cannot be attacked from a monitor interface**, so the 6 GHz radio is recon-only
  surface. 2.4 GHz and non-DFS 5 GHz only.
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
