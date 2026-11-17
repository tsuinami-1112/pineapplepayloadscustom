# CamHound response side — how it works

Developer reference for the **Disrupt** rung: the part of CamHound that turns a detection into a
disconnection. `PLAN_v2.md` covers the recon side; this covers everything downstream of it.

Status: coded, laptop-verified, and **transmitting on hardware since 2026-11-05** — a Disrupt ran the
whole chain from the user payload on the 1.1.3 unit (CLAUDE.md "Second contact"), and since
2026-11-10 an AP row fires even when the capture recovers nobody (below). `--selftest` last passed on
the Pager at 259/0 (2026-11-04); on the laptop it is the count printed at the end, which grows with
every case added. The selftest
still stubs every device-changing command, so section [What is unverified](#what-is-unverified)
remains the honest list of what the bench has not measured.

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

**Two** DuckyScript commands reach it, and CamHound's three menu keys are built from those two.
`PINEAPPLE_DEAUTH_CLIENT_ALL` is not one of them — read the correction under the table before
trusting any older statement in this file about it:

| Key | Command | Frames | Scope |
|---|---|---|---|
| `DEAUTH` | `PINEAPPLE_DEAUTH_CLIENT [bssid] [target] [channel]` | deauth + disassociation | one client |
| `CSA` | `PINEAPPLE_DEAUTH_CLIENT_CSA [bssid] [channel]` | channel-switch announcements | whole BSS |
| `BOTH` | `PINEAPPLE_DEAUTH_CLIENT [bssid] [target] [channel]`, **then a CSA as a second command** (`csa_issue`) | deauth + disassociation, then a channel-switch announcement | whole BSS |

**⚠ Corrected 2026-11-09: `BOTH` is NOT `PINEAPPLE_DEAUTH_CLIENT_ALL`, and that command builds no
deauth frame at all.** `[V]` from pineapd and the Go daemon, re-derived in CLAUDE.md "Third
contact"; the addresses are there and are not repeated here. All three
`PINEAPPLE_DEAUTH_CLIENT*` commands reach **one** pineapd function,
`interface_tracker::command_send_deauth` @ `0x4733d8`, which dispatches on a numeric opcode and not
on the payload: **400 = deauth only, 401 = deauth + CSA, 402 = CSA only.** The Go daemon emits
`li a0,400` in `StartDeauth`, `li a0,402` in `StartDeauthCsa` and `li a0,402` in **`StartDeauthAll`**
— `li`/`ori a0,401` occur **zero** times anywhere in the binary, so pineapd's deauth+CSA opcode is
dead code that has never run. `_ALL` and `_CSA` are therefore **the same command on the wire**, and
`_ALL` queues a CSA while building no deauth frame; the `ff:ff:ff:ff:ff:ff` it writes into `sta` is
dead data the 402 path never reads. Measured beside it on one address, one channel, one BSSID,
minutes apart: `PINEAPPLE_DEAUTH_CLIENT <bssid> ff:ff:ff:ff:ff:ff 8` **dropped** the client while
`PINEAPPLE_DEAUTH_CLIENT_ALL <bssid> ff:ff:ff:ff:ff:ff 8` did nothing.

So `response_cmd BOTH` returns **`PINEAPPLE_DEAUTH_CLIENT`** — the opcode-400 deauth, the one frame
this firmware actually builds — and `resp_fire` issues the CSA itself as a **second** command
through `csa_issue` (§7a). That is the only way to get what opcode 401 would have done. *Every
claim in this file that rests on `_ALL` "parsing and discarding a target" is withdrawn with it: the
402 path never reads `sta`, so there is no discarded target to reason from.*

**Scope is not what the signatures suggest, and `attack_scope()` is the one place that decides.**
`CSA` takes no target: the **[V]** reading is the Go handler, `StartDeauthCsa` parses one MAC with a
28-byte frame against `StartDeauth`'s two and 32 (CLAUDE.md §"2.0.0-stable, analysed"), and hak5cmd's
help lists `[bssid] [channel]` — the help alone would not settle it, since this repo has caught it
wrong three times. "Because it rides in a beacon" is the carrier question §13 still lists as not
proven, so that explanation is **[A]**; the breadth does not depend on it. ~~`BOTH` advertises a `[target]` that its handler parses and
discards, so it is BSS-wide too~~ — **withdrawn 2026-11-09, see the correction above:** `_ALL` is
not on `BOTH`'s path at all.

**`BOTH` is still `bss`, and this is the reason of record.** Its CSA leg is BSS-wide *by
construction* — `csa_issue` sends `<bssid> <ch>`, a command with no target argument — and at the
shipped `SWEEP_TARGETED=1` the targeted sweep follows the deauth to every **subject** of the
attempt, which on an AP row is every heard member (§7). The honest corner, stated rather than
smoothed over: with `SWEEP_TARGETED=0` a client-row `BOTH` is one targeted deauth plus a BSS-wide
CSA leg, so the confirm's "on EVERY client of <bssid>" **over-warns** about the deauth half while
staying true of the CSA half. Over-warning in one non-default corner is the direction to err in.
*Falsified by:* a client-row `BOTH` at `SWEEP_TARGETED=0` disconnecting a client other than the
picked one, which would make the confirm literally true of the deauth half too.

And because
`resp_target` resolves an **AP row** to a broadcast target, every attack on one is BSS-wide
regardless of the key. The picker appends ` bss` to a broad option and the pre-transmit confirm
reads "on EVERY client of <bssid>", because "`CSA` on <one client>" would be a lie. **`posture_opts`
no longer orders by efficacy.** It returns `DEAUTH BOTH CSA` on every badge where anything is
offered at all (empty for `NOINJ` and `NONE`), and `pick_list` preselects element 0, so `DEAUTH` is
the default everywhere. That is exactly the reordering an earlier revision of this paragraph said
would "demote the attack most likely to work", and the measurement is why it is now right: `DEAUTH`
is the only key whose frame this firmware builds, so leading `CSA` under PMF preselected an attack
that provably transmits nothing.

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
| `D+C` | no PMF | works | lands **only with an injector**; `fw-broken` without one |
| `D?+C` | PMF optional (WPA3 transition) | partial | lands **only with an injector**; `fw-broken` without one |
| `C` | PMF required (WPA3) | blocked | lands **only with an injector**; `fw-broken` without one |
| `NONE` | PMF + beacon protection | blocked | blocked |
| `NOINJ` | channel we will not transmit on (or, with no live table read, one outside the always-safe set) | cannot transmit | cannot transmit |
| `?` | no beacon captured | unknown | unknown |

*The `CSA` column changed on 2026-11-15 and used to read `works` on the first three rows.* It is
the badge's verdict on the **channel-switch mechanism**, which is not the same question as whether
this firmware can send one: pineapd's CSA announces **channel 14 with Channel Switch Count 0** (both
literals with one call site, no setting reaches either) and `_ALL` builds no deauth frame, so with
no `CSA_INJECTOR` configured and executable the label is `fw-broken` on every badge the picker
still speaks for. *Qualified 2026-11-17: this read "whatever the beacon says", which the table's own
`NONE` and `NOINJ` rows contradict. `posture_expect` returns `blocked` for both **before**
the `fw-broken` short-circuit is reached, and those two badges are reachable in the picker — the
"Nothing is expected to work — try anyway?" fallback offers all three keys there. Read in
`posture_expect`: the `NOINJ` and `NONE` returns precede the `[ "$inj" = 0 ]` CSA case, while the
`?` test FOLLOWS it — so badge `?` does label CSA `fw-broken` with no injector, and only these two
badges are exceptions. Falsified by: `posture_expect NOINJ CSA` or `posture_expect NONE CSA`
printing `fw-broken` with `CSA_INJECTOR` empty.* `posture_why` carries the same sentence onto the screen in one line, and on
those two badges says instead what an injector does and does not buy: `NONE` → "PMF + beacon
protection: no forged frame is expected to work, injector or not", `NOINJ` → "will not inject here:
pineapd refuses DFS and 6 GHz, the channel table the rest (or none was read); an injector is unproven
on DFS, dropped on 6 GHz" (the gate asymmetry below).

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

The badge **advises; it never decides.** All three attacks are offered with **`DEAUTH` first** — the
order no longer tracks the badge — and labelled honestly, so a deliberate no-hope attempt stays the
operator's call. Where nothing is expected to work the operator is asked once and may still proceed;
that fallback offers `DEAUTH BOTH CSA`, in that order, for the same reason the picker does.

- `response_cmd <key>` → the DuckyScript command name. **`DEAUTH` and `BOTH` both resolve to
  `PINEAPPLE_DEAUTH_CLIENT`** (opcode 400); `BOTH`'s second leg is `csa_issue`, not a command name.
- `posture_opts <badge>` → the offered keys: `DEAUTH BOTH CSA` wherever anything is offered at all,
  empty for `NONE` and `NOINJ`. `pick_list` preselects element 0, so the string order *is* the
  default.
- `posture_expect <badge> <key>` → the picker's label, which follows the **sender** and not the
  badge alone. The labels of record for the CSA-bearing keys are **`fw-broken`** (the firmware CSA),
  **`injector`** (a CSA routed to `CSA_INJECTOR`, **and `BOTH` on badge `C` with one configured** —
  under PMF-required the deauth half cannot land, so the label names the leg that does send),
  **`deauth+csa`** (`BOTH` with an injector on `D+C`) and **`deauth only`** (`BOTH` without one).
  *The `injector`-on-`BOTH` arm was added to this bullet 2026-11-17; `posture_expect`'s `BOTH)`
  branch under an injector reads `deauth+csa` on `D+C`, `partial` on `D?+C` and `injector`
  otherwise, and `C` is the badge that reaches "otherwise" on shipped firmware — `NONE`/`NOINJ`
  return `blocked` and `?` returns `unknown` earlier. Falsified by: `posture_expect C BOTH` with an
  executable `CSA_INJECTOR` printing anything else.* Beside them the deauth half still carries
  the badge's own word — `works` with no PMF, `partial` under PMF-optional, `blocked` under
  PMF-required and at `NONE`/`NOINJ` — and everything at badge `?` is `unknown`, except `CSA` with
  no injector, which the `fw-broken` short-circuit answers first (§3 above has the branch order).
  *The flat `works | partial | blocked | unknown` list this line carried until 2026-11-15 is
  withdrawn as a specification of the set.* It was written when the label depended on the badge
  alone, and it hid the case that mattered most: with an injector configured — the one configuration
  the whole CSA hook exists to enable — an injector-blind label told the operator CSA was
  `fw-broken` while `csa_issue` was routing it to `pagerinj` and the loot row recorded two legs
  landing. The picker lied in exactly the case it was there for.
- `posture_why <badge>` → one line of plain English for the screen. Its CSA half says that CSA lands
  **only with an injector configured**, and is `fw-broken` without one. On the two badges that offer
  nothing it names what an injector changes there, because `posture_expect` says only `blocked`:
  `NONE` → "PMF + beacon protection: no forged frame is expected to work, injector or not" (the
  forgery is what beacon protection defeats, so the sender is beside the point; "expected" because
  the client must have installed a BIGTK for that, which a beacon cannot show), `NOINJ` → "will not
  inject here: pineapd refuses DFS and 6 GHz, the channel table the rest (or none was read); an
  injector is unproven on DFS, dropped on 6 GHz" (the two gates below: on 5 GHz DFS only gate 1
  fires, which `pagerinj` bypasses, and no frame has yet been shown to reach the air there; on
  6 GHz gate 2 fires too and cfg80211 drops it silently; "the channel table the rest" is
  `csa_injectable`'s third producer, a channel the live table marks disabled or No IR or never
  lists at all — 5 GHz 169/173/177 carry No IR under US, and 2.4 GHz 12-14 are simply absent from
  the eleven-line 2.4 GHz table measured there — gate 2 for the channels it flags, and for one it
  never lists the radio does not offer it at all, neither being something a sender gets past; and "(or
  none was read)" is that producer's other half, CamHound's own conservatism when no table could be
  read and no gate verdict at all, since the fallback passes only 2.4 GHz 1-11 and 5 GHz 36-48 and
  so refuses 5 GHz 149-165, which gate 2 permits under US — §3 above, and CLAUDE.md "First
  contact": "Channel 149 is clear of both"). *Both lines reworded 2026-11-17; they read "no frame
  this firmware sends works" and "the radio may not transmit on this channel", neither of which
  distinguishes the two gates or mentions an injector. The `NOINJ` line's first rewording, "DFS or
  6 GHz: pineapd refuses here; …", blamed pineapd for the third producer and was caught by the fix
  round's intent lens; its second, "the reg table the rest" for both halves, blamed cfg80211 for the
  no-table fallback and was caught by the round's code and docs sceptics, all the same day.*

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
`PINEAPPLE_EXAMINE_BSSID`, reads the channel back three times via `cur_channel` (`iwinfo` first,
then `iw dev info`), falls back to `PINEAPPLE_EXAMINE_CHANNEL`, and reports failure if the radio is
still hopping. **It has FOUR return codes and only ONE of them is a refusal** — this line said
"0 locked, 1 locked-by-channel, 2 failed" until 2026-11-15, which left the one an incautious reader
is most likely to normalise away undocumented:

| rc | `lock` in the loot | what it means | the response |
|---|---|---|---|
| 0 | `ok` | two or more readable samples agree with each other **and** with the target channel — or no target channel was supplied at all (`want 0`), there being nothing to disagree with | transmits |
| 1 | `by-channel` | the samples agreed but on the wrong channel, and the read after `PINEAPPLE_EXAMINE_CHANNEL` came back equal to the target | transmits |
| **3** | **`unverified`** | the channel could not be established: no readable sample, exactly **one** readable sample, or an empty read after `EXAMINE_CHANNEL` | **transmits**, and the loot says `unverified` instead of claiming a verification that did not happen |
| 2 | `failed` | **either** readable samples that **disagree with each other** — the radio is still hopping — **or** samples that agree on the **wrong** channel where the read after `EXAMINE_CHANNEL` also lands elsewhere (`ch 7 != 8, lock failed`) | refuses: nothing is transmitted and the attempt is looted `LOCK_FAILED` |

**⚠ rc 3 is "unverified, PROCEED". Do not normalise it to 0, and do not fold it into 2.** Refusing
every response on a device whose channel will not read back is worse than labelling it; and
reporting `ok` from a single sample would be *more* confidence from *less* evidence than the
two-sample case beside it, since one reading cannot establish that a radio is parked. `resp_fire`
maps rc 3 to `lock=unverified`, shows `LOCK_TEXT` to the operator in yellow, and carries on. Four
separate fixes converged on this shape over two days; CLAUDE.md "Third contact"'s last bullet has
the sequence.

**rc 2 has two producers and the round-2 review found all three docs describing one.** The row
above now carries both. They are told apart by the line in `events.log`: the hopping branch prints
`<if> still hopping (samples _/6/11): lock failed` — the **raw, pre-backfill** triple — while the
other prints `ch <c4> != <want>, lock failed` and names no samples at all, because by then the
three samples agreed and the disagreement is between the read-back and the target. Note that
samples agreeing on a channel that is not `want` do **not** give rc 2 by themselves: they are the
entry to the fourth read, which returns 1 when it lands on target, 3 when it comes back empty and
2 only when it lands somewhere else. Read in `lock_target`, at both of its `return 2` sites.
*Falsified by:* that `c4` branch being unreachable — e.g. an earlier guard making `c4` equal to
`want` whenever it is readable.

**On rc 0 `LOCK_TEXT` names the channel it agreed on and the raw triple together**, in the form
`<if> ch N, target ch M (samples a/b/c)`. It is set before the backfill as well as after, and until
2026-11-17 only the pre-backfill assignment survived on the rc-0 path — so the `8/8/_` pattern,
which has returned rc 0 since 2026-11-15, told the operator `ch ?` beside `lock=ok` — and `ch ?`
is not a cosmetic slip there, because Watch's INCONCLUSIVE card and Stimulus's both print
`LOCK_TEXT` whatever rc the lock returned (rc 2 aborts before the card), so the one screen where
the operator asks whether the radio was parked pointed at the lock as the cause of the missing
frames. *Falsified by:* an `8/8/_` lock at `want 1` whose text contains `ch ?`.

**Two readable samples are two readable samples, whichever one was missing.** An unreadable sample
is a *missing reading*, not a different channel — `cur_channel` prints nothing when it cannot parse
one — so the comparison is backfilled from the last sample outward, and `8/8/_` now reaches the same
rc 0 as `_/8/8`. Until 2026-11-15 an empty **third** sample short-circuited to rc 3 before the
backfill ran, so two agreeing reads scored `ok` or `unverified` depending on nothing but which slot
was blank. The hopping line logs the **raw, pre-backfill** triple (`samples _/6/11`): the 2026-11-09
bench defect was diagnosable only because the empty slot was visible, and printing the repaired
values made its own signature unreachable by construction. *Falsified by:* a `lock_target` rc
changing for any of those sample patterns without `cur_channel` changing.

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
- **On an AP row the subject set is widened again — in `resp_fire`, not in `resp_snapshot`.** Every
  station the membership capture **heard** is appended as a subject with `p0 '-'`, including the
  randomised MACs and the stations Recon has no row for that the sweep above drops, and each one
  gets its own `responses.tsv` row. `resp_verdict` scores a subject with no baseline `INCONCLUSIVE`,
  never `MOVED` — the honest answer for a device we transmitted at and cannot measure.

**The aggregate pays for that honesty, and it is worth knowing before reading a loot file.**
`resp_aggregate` returns `MOVED` only when some subject moved **and none was inconclusive**, so a
single heard-but-unmeasurable station **caps the attempt at `INCONCLUSIVE`** however many measured
subjects fell silent. It can still read `NO_EFFECT`: any subject whose counter kept advancing
outranks the inconclusive ones, because that is positive evidence the attack missed. The transmit
set and the measurement set were the same array until 2026-11-09, which is what silenced the rung
entirely on an AP whose only client carried a randomised MAC — seven consecutive refusals, CLAUDE.md
"Third contact".

**Why scope and not row type.** `CSA` takes no target argument at all, and `BOTH`'s CSA leg is that
same `<bssid> <ch>` command, so both put a BSS-wide frame on the air even when the operator picked
one client. (~~`_ALL`'s target is parsed and discarded~~ — withdrawn 2026-11-09: `_ALL` is not on
either path, §2.) Selecting subjects by
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
closed that for AP rows on 2026-11-04** by reading the association off the air; ~~a user-payload
client row still aborts in `resp_target`~~ *(amended 2026-11-10: the recon side's inverse lookup
landed — a client row's card now offers `Disrupt (find AP first)`, which reads the client's AP off
the air and then opens this menu; laptop-verified only, see §13a-i's bound)*. See §13 and §13a-i. **[A]** *Falsified by:* `_pineap RECON
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
| `LOCK_FAILED` | the radio would not hold the channel (`lock_target` rc **2** only); nothing was transmitted |
| `CMD_REFUSED` | the command refused — a non-zero rc, or **anything on stderr**, which is the only signal `hak5cmd` gives since it exits 0 on every path including its errors. Nothing was transmitted. Written for **every** subject of the attempt, and deliberately outside the `MOVED`/`NO_EFFECT`/`INCONCLUSIVE` vocabulary so that a refusal can never be mistaken for a measurement by a reader of `responses.tsv` |
| ~~`NO_CLIENTS`~~ | *no longer written (2026-11-10): a broadcast target with no clients fires, and is the one `INCONCLUSIVE` subject* |

**`CMD_REFUSED` and `LOCK_FAILED` are the only two refusal verdicts this rung writes.** The capture
reasons are not among them — since 2026-11-10 `NO_CAPTURE`, `SNAP_SHORT` and `NO_CLIENTS` are
`events.log` reasons that accompany a broadcast that **did** fire (table above). And `unverified` is
a value of the loot's **`lock` column**, not a verdict: a row can read `lock=unverified` beside any
of `MOVED`, `NO_EFFECT` or `INCONCLUSIVE`.

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

### 7a. `csa_issue`: what each return code asserts

The CSA leg has two possible senders and they answer "did it work?" **oppositely**, so `csa_issue`
owns the question instead of leaving it to its callers:

- **`hak5cmd`** (the firmware command `PINEAPPLE_DEAUTH_CLIENT_CSA`) exits **0 on every path,
  including its error paths**, and writes the error to **stderr** (measured 2026-11-05). Stderr is
  the only signal; the rc is worthless.
- **`pagerinj`** (`CSA_INJECTOR`) returns `failed && !sent ? 1 : 0` and prints its `sent=`/`failed=`
  summary to **stderr even on success**, so the **rc** is the signal and testing stderr would report
  failure every single time.

One rule for both would file a fabricated result, which is the whole thing this rung exists to
prevent. There is a third complication on the injector path: `csa_issue` runs it under `timeout`, and `wait`
returns **`timeout`'s** status rather than the child's — 124 on expiry whatever the injector itself
exited with — so the wrapper's status is not the injector's verdict either.

| rc | the assertion | the evidence it rests on |
|---|---|---|
| 0 | the sender ran clean | injector rc 0; or the firmware command rc 0 **with empty stderr** |
| **2** | **frames DID leave the radio, and the run was then capped by its own timeout** | `sent=N` with N > 0 on the injector's own stderr. Nothing else is accepted as proof of a send |
| **3** | **capped with no send evidence** — the wrapper expired (status 124, or ≥ 128 for a signal) and there is no `sent=N` line with N > 0 | the *absence* of a `sent=N`, N > 0. The test is `sent=[1-9]`, so a `sent=0` is a `sent=` line and is still **not** evidence. So rc 3 means "we do not know", never "nothing was sent" |
| 1 | refusal: nothing was sent | injector rc 1; a missing command; or the firmware command's stderr |

**The no-band case is a fall-through, not a return code.** When `csa_newchan` can offer no honest
new channel — `CSA_CHAN` 0 and `R_BAND` outside 2/5/6 — `csa_issue` logs
`csa injector skipped: no band for <bssid>, cannot pick a new channel` and drops out of the
injector block into the **firmware** sender, which is then classified by the firmware rule, 0 or 1.
The row above listed it as an rc-1 producer until 2026-11-17; there is no `return` on that arm (read
in `csa_issue`, the `[ -z "$nc" ]` branch, and `csa_newchan`'s own comment: "band unknown: refuse to
guess, the caller falls back to the firmware"). The only thing it guarantees is that the loot's
`cmd` column will name `PINEAPPLE_DEAUTH_CLIENT_CSA` rather than the injector. *Falsified by:* a
`csa_issue` returning 1 with `R_BAND` unset while `PINEAPPLE_DEAUTH_CLIENT_CSA` exists and exits 0
with empty stderr.

**rc 2 must never collapse to 1.** The refusal path writes `CMD_REFUSED`, which asserts that no
frame left the radio — writing it for frames whose own stderr says `sent=90` is a false statement in
the loot, in the one direction this rung is built to avoid. **And rc 3 must never collapse to 2**,
which is what it did until 2026-11-15: a bare 124 was scored as a send on the strength of the
wrapper's status alone, so an injector that expired having transmitted *nothing* was recorded as
having transmitted. The two failures are mirror images and both put a claim in the loot that the
evidence does not carry.

**How `resp_fire` handles each, at both of its call sites.**

*The `CSA` arm*, where the CSA is the whole attack:

- **rc 0 and rc 2 proceed to the measurement.** rc 2 warns on screen and logs that it was capped
  after sending: a capped run is a reason to distrust the **dwell**, not a reason to claim nothing
  went out.
- **rc 3 also proceeds to the measurement, but EVERY verdict behind it is read down.** Each
  subject that would have scored `NO_EFFECT`, `MOVED` or anything else becomes `INCONCLUSIVE`,
  because "nothing was transmitted" explains all of them equally well — and `NO_EFFECT` on a CSA is
  one of the open firmware questions this rung exists to *answer*, so filing any of them from an
  unproven send would file a fabricated answer. The word that was scored is **kept, not lost**: the
  `subject` line in `events.log` carries it as `raw=MOVED`, and the aggregate screen line gains
  `; CSA send unproven`. The loot records the CSA leg as **unknown** rather than naming a sender
  that may not have sent — the sender's name with a trailing `?` in the `cmd` column, at both arms.
  *Corrected 2026-11-17. This read "A **`MOVED` stands**: the device went quiet, and reading that
  down would throw away a positive result", and the reason — an absent frame cannot explain a quiet
  subject — is false. `resp_verdict` produces `MOVED` from two states and both are what an idle or
  wandering device does unprovoked: the subject dropped out of the Recon list (`present=0`), or its
  cumulative packet counter did not advance (`t1 = t0`). The payload says so itself in
  `attack_scope`'s comment — "an idle camera reads MOVED whether or not anything was transmitted
  ... MOVED on a quiet device is weak" — and the harness has been driving exactly that producer on
  every run, its counters being frozen by default. Measured by the round-2 review: with the
  selftest stub's post-read made equal to its pre-read, the rc-3 case looted
  `pagerinj:ch1:n3? MOVED 0`, which `resp_aggregate` turned into `RESPOND_HIT` — green LED, 300 ms
  vibrate — one screen after this arm had printed "nothing is claimed". Keeping `MOVED` was a
  defensible policy; the reason given for it was not, and the doubt reached no column but `cmd`.
  Falsified by: `resp_verdict` returning `INCONCLUSIVE` for `p0=10 t0=100 p1=10 t1=100 present=1`,
  which would make `MOVED` require positive evidence of a change.*
- The `csa inject` log line carries **two** numbers and they are not the same thing: `rc=` is the
  `timeout` wrapper's status and `issue=` is the classification above, so `rc=124 issue=3` is the
  capped-with-no-evidence case and **`issue=`** is what to grep for.
- **rc 1 is the refusal**: `CMD_REFUSED` for every subject, and nothing is measured.

*The `BOTH` arm*, where the deauth has **already** left the radio by the time the CSA leg is issued,
so no CSA result may fail the attempt:

- rc 0 and rc 2 both count as sent and name the sender in the loot's `cmd` column.
- rc 3 is recorded **unknown** — the leg is neither claimed nor denied — and **no verdict is read
  down here**, unlike the `CSA` arm: the deauth has already left the radio, so a `NO_EFFECT` still
  has a transmission behind it and remains a reading. `csa_unknown` is set only inside the `CSA`
  branch (read in `resp_fire`).
- rc 1 warns ("the CSA leg did not send; the deauth was still transmitted") and logs the failure.
- **None of the four aborts the attempt or changes the deauth's verdict.**

`csa_clamp` bounds `CSA_INJ_SECS` and `CSA_INJ_WAIT` to 1–60 before both the invocation and
`resp_fire`'s lock budget, because `pagerinj` reads `--secs 0` as "transmit until signalled" and
`csa_issue` runs it in the **foreground**: a hand-edited 0 would park `resp_fire` forever behind a
transmitter no teardown could reach. The injector is `child_add`ed as well, so the watchdog and
`kill_children` can both find it. The three CSA keys (`CSA_INJECTOR`, `CSA_COUNT`, `CSA_CHAN`) are
deliberately **unstarred**: `cfg()` accepts integers only, so a path cannot arrive through
`PAYLOAD_SET_CONFIG`, and a star without a `SETTINGS_TABLE` row would be a lie.

**`CSA_INJECTOR` defaults to empty and should stay that way until the bench says otherwise.**
`dev/injector/README.md` requires pineapd **stopped**, and CamHound cannot stop pineapd — Recon, the
EXAMINE lock and every deauth command *are* pineapd — so the in-payload path bets that the EXAMINE
lock holds the channel well enough, and that bet is **unmeasured**. The validated way to run
`pagerinj` is standalone, `dev/injector/run_17a.sh`.

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
| `SWEEP_TARGETED` | 1 | `*` | after a BSS-wide deauth, also send one targeted `PINEAPPLE_DEAUTH_CLIENT` per subject of the attempt |
| `SCAN_IF` | `wlan0` | | reserved, currently unused |

The **seven** starred keys are also on the device's **Settings → Response settings** page — count
them in `SETTINGS_TABLE`, whose `response` group holds `RESPONSE`, `RESPONSE_CONFIRM`,
`AUTO_RESPOND`, `SWEEP_TARGETED`, `RESP_LOCK_SECS`, `RESP_SETTLE_SECS` and `POSTURE_TTL`.
*This said "six" until 2026-11-15 and the table above was missing its `SWEEP_TARGETED` row, so the
count and the table were wrong together — and a starred key with no row here is the same lie a
starred key with no `SETTINGS_TABLE` row would be.* Switching
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

`responses.tsv`, `|`-separated with a `#` header, **one row per subject** — each measured client, or,
since 2026-11-10, the broadcast placeholder `ff:ff:ff:ff:ff:ff` when a zero-member AP row fires — (so an attempt
whose scope is `bss` against a BSSID with four clients writes four rows, one attempt — including when
the operator picked a single client row and chose `CSA` or `BOTH`):

```
#epoch|mac|role|bssid|target|ch|band|badge|rsn_caps|beacon_prot|attack|cmd|lock|pk_before|pk_after|verdict
```

`mac` is the enumerated target the operator acted on; **`target` is the subject actually measured**
— the individual client for a broadcast attempt, not `ff:ff:ff:ff:ff:ff` — **with one exception since
2026-11-10: a zero-member AP row writes exactly one row whose `target` IS `ff:ff:ff:ff:ff:ff`, with
`pk_before`/`pk_after` `-` and verdict `INCONCLUSIVE`, because nothing could be measured** (the
2026-11-10 paragraph above). `resp_write` takes that as
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
per-subject loot rows with badge and raw caps, the aggregate verdict, the zero-member AP row firing
anyway and looting `INCONCLUSIVE` (`nomem_fired`, since 2026-11-10; before that, the no-clients guard), the
cached badge appearing on the card afterwards, and EXAMINE being released. Two further scenarios
reach the confirms the badge logic adds: `blind` (the fake `tcpdump` captures no beacon, so the badge
is `?`) checks that the "Fire blind?" dialog appears, that accepting it offers
`DEAUTH bss (unknown)`, `BOTH bss (unknown)` and `CSA bss (fw-broken)` **in that order** — at badge
`?` the deauth half is genuinely unread, while the firmware CSA is known broken whatever the beacon
would have said, which is why the third label is not `unknown` too — that a `CSA` picked there fires
`PINEAPPLE_DEAUTH_CLIENT_CSA` with bssid and channel only and writes loot rows with badge `?` and
caps `-`, and that declining it sends nothing and writes no row. *This paragraph said "offers CSA
first with every option labelled `unknown`" until 2026-11-15, which was the pre-reordering picker
and a label set that predated `posture_expect` following the sender;*
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

The CSA leg and the lock are pinned at the level the mistakes were actually made at — a return code
meaning one thing in `csa_issue` and another at the call site, which no end-to-end scenario catches:
`csa_issue`'s **rc 2** *and* `resp_fire`'s acceptance of rc 2 at **both** arms, the same pair for
**rc 3**, `csa_clamp`'s bounds, the targeted sweep's **stderr**-refusal detection (an rc of 0 with a
message on stderr, which is the only shape `hak5cmd` produces), a check that no `-k` reaches the
injector's argv unless `timeout` was probed to accept it, and `lock_target`'s symmetry cases —
one-empty, middle-empty, last-empty, one readable sample, an empty fourth read and a genuinely
hopping radio, each confirmed by a mutation that fails only its own case.

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
~~What still holds is the user-payload **client** row aborting in `resp_target`.~~ *Amended
2026-11-11:* `resp_target` does still return 1 for a row whose AP is `-`, but the card no longer
reaches it that way — it offers `Disrupt (find AP first)`, which runs `assoc_lookup` and opens
`disrupt_menu` on the answer (2026-11-10, laptop-verified only; see the bound table at §13a-i).*

**⚠ First, the floor — and it applies to the USER PAYLOAD only.** From the user payload this rung
cannot transmit on any shipped firmware, and flashing does not fix that. The Recon hooks reach the
air by another route entirely; the exception at the end of this section is the important part.
Two different mechanisms, same outcome, and the blocker is the **association column** rather than the
firmware version:

| firmware | what happens | where |
|---|---|---|
| **1.1.3** | `_pineap RECON CLIENTS` does not exist (measured 2026-11-03: `Unknown recon command`, rc 255); since that day `recon_lines CLIENTS` reads `RECON DEVICES` instead, whose object carries no association, so a client row has `AP_OF` `-` and `resp_target` refuses it like 2.0.0's. Every AP row has `R_TARGET` broadcast, subjects are 0 → `NO_CLIENTS`. | `resp_snapshot`'s `[ "$a" = "$R_BSSID" ]` sweep iterates the `RECON DEVICES` client rows and matches none, every `AP_OF` being `-` → `resp_fire` refusal; a client row is refused earlier, by `resp_target` |
| **2.0.0** | client rows arrive, but the device object has no association field, so `JQ_CLI`'s `(.ap_mac // .bssid // "-")` yields `-` for all of them. An **AP row** finds 0 matching clients → `NO_CLIENTS`. A **client row** never reaches the sweep: `AP_OF` is `-`, so `resp_target` returns 1 and `disrupt_menu` aborts with "nothing to attack: no associated BSS". | `resp_target`'s client branch, and `disrupt_menu`'s abort beside it; `resp_snapshot`'s `[ "$a" = "$R_BSSID" ]` |

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
one of those four line numbers went stale within a commit. *(2026-11-15: this file's own five
`payload.sh:NNNN` citations had gone the same way — they landed in `assoc_learn_members`,
`assoc_lookup`, `battery_tick`, `kill_children` and `score_device`, not one of them the function
meant — and are now function names. Grep this file for `payload.sh:` and it should find nothing.)* Fixing the association is therefore the
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
| "A client's MAC is `addr2`, six octets at `p + rt + 10`" | True **only for a ToDS frame**. On a FromDS frame `addr2` **is the BSSID** and `addr1` is the client. `addr2` is always the *transmitter* (`PLAN_v2.md:55`, IDEA_27 at `:164`) — and on a downlink frame the transmitter is the AP. | Harvesting `addr2` unconditionally records the AP as its own client. `resp_snapshot`'s stated invariant — "The AP's own counter is never the subject: it keeps beaconing whatever happens to its clients" (`resp_snapshot`'s header comment) — breaks, and one AP subject scoring `NO_EFFECT` makes `resp_aggregate` return `NO_EFFECT` for the whole attempt, so successes systematically read as failures. |
| "whether `-s 32` clears radiotap far enough to reach `addr2`" — framed as a parameter | **Arithmetic settles it: it cannot.** `addr2` occupies frame octets 10-15, so a record must hold `rt + 16` bytes. mac80211's RX radiotap is at minimum FLAGS+CHANNEL+DBM_ANTSIGNAL and normally TSFT, with an MCS/HE block on an ax radio (`phy1`, backports 6.12.61): 18 at the optimistic floor, and `18 + 16 = 34 > 32`. The Watch rung's `-s 32` is **deliberately header-only** — `PCAP_AWK` reads only `hdr[1]`, `hdr[3]`, `hdr[4]` (in its own program text) and never touches frame content — so its existence is evidence of nothing about address reachability. | At `-s 32` every record fails the `rt + 16` guard and the walker returns **zero** clients, which is indistinguishable from the `NO_CLIENTS` bug being fixed. |
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
`watchable`, so the detect→Watch→confirmed→Disrupt funnel reaches `summary_card` only for
AP rows anyway. The inverse lookup that would fix the client row — `type data and wlan addr2 <mac>`,
BSSID from `addr1` on a ToDS frame, the same walker with the two addresses swapped — is worth more
than this change, because `AP_OF` gates five features. It is **recon-side** (`AP_OF` is filled by
`record_seen`/`JQ_DEVCLI` and surfaces in `inventory.tsv`'s `ap_bssid` column and the
report tree), so it is handed over with the parser proven rather than written here.

**Bound amended 2026-11-10 — the inverse lookup landed, from the recon side, laptop-verified only.**
What changed for this rung, and what did not:

| row | before | since 2026-11-10 |
|---|---|---|
| user-payload **client** row, AP unknown | `Disrupt n/a (not associated)`; `resp_target` returns 1 | `Disrupt (find AP first)`: `assoc_lookup` parks on the client's channel, reads its BSSID from its own data frames, then `disrupt_menu` opens on it. `attack_scope` is `cli` for `DEAUTH`, so this is the one targeted frame the firmware sends |
| user-payload client row, lookup hears nothing | — | the card is unchanged and the reason is logged (`assoc <mac> none why=…`); nothing transmits |
| user-payload client row, AP heard but its channel not known | — | `Disrupt n/a (no channel)`: across the hop, or behind a park that could not be read back, the channel listened on is not recorded, and an AP Recon has not listed has none of its own. `resp_target` returns 1 as it always did for a row with no channel; the row gets one when Recon lists the AP |
| a learned AP older than `ASSOC_TTL`, any path into this menu | — | `disrupt_menu` calls `assoc_refresh` first (behind `command -v`), so the card, the post-Watch funnel and `AUTO_RESPOND` all look again before anything is aimed at it. A look that does **not** re-confirm the AP keeps it and counts as the look: `assoc_stale` takes the later of the learn time and the last attempt, so the next look is another `ASSOC_TTL` away and the picks in between open the menu with no listen and nothing said. `ASSOC_TTL=0` looks on every pick |
| user-payload **AP** row | fires, membership from the air | unchanged — and `resp_members`' success path now hands the stations it heard to `assoc_learn_members` (behind `command -v`: the function is not in the hooks), so the client rows of those it heard **transmitting** carry this AP afterwards; a member the AP was only sending to stays a member for the attack and is not taught (2026-11-11: it may have left, and after a Disrupt that worked it has) |
| both Recon **hooks** | association from `_RECON_SELECTED_*` | unchanged in behaviour. `CLI_AWK` gained a `mode=pairs` branch in the lib block, so the hooks' lib hash moved. *Amended 2026-11-11:* the membership walk beside it is no longer byte-for-byte what it was — since 2026-11-11 (`9fd8b6c`) it counts each member's own transmissions and prints one `UP <sta> <n>` line per member heard transmitting, in the hooks' copy too. The **admitted set** is unchanged, which is what matters here, and is pinned by the selftest's `pairs: the membership walk beside it admits the same three stations as before` with `pairs: and says which of them were heard transmitting, which is not all of them` beside it. The hooks' `resp_members` reads only the `CLI` lines, so the extra output changes nothing there |

Four things in this rung are touched. Three were agreed with this file's owner beforehand: the
guarded line in `resp_members`, `disrupt_row`'s `Disrupt (find AP first)` label (guarded on
`command -v assoc_can`, so a hook still prints `n/a`), and the `mode=pairs` branch in `CLI_AWK`
together with the `UP` lines the membership walk beside it now prints.
The fourth came out of the review of the lookup and is reported to the owner rather than agreed in
advance: one guarded line at the top of `disrupt_menu` (and its twin in `watch_menu`) that
re-checks a stale learned AP. All four are no-ops in the hooks. Nothing in `resp_fire`,
`resp_snapshot`, `resp_verdict` or the lock changed.

**What is NOT established, because nothing here has run on a device:** that
`PINEAPPLE_EXAMINE_CHANNEL` parks the radio without a preceding `EXAMINE_BSSID` (every measured
park began with `EXAMINE_BSSID`, and `lock_target` adds the channel command only when the BSSID step
did not already land on the channel; the lookup reads the park back and falls back to listening across the hop), and
that a camera's uplink is heard within the 6 s window. `dev/pager-day-one.md` 8d is the bench
check. *Falsified by:* a client-row Disrupt whose loot row names a BSSID the client is not
associated to.

Needs a Pager — **four of the six below have since been answered; they are struck in place, with the
pointer, rather than deleted, because what closed them is where the next session should look:**

- ~~whether `tcpdump` beacon capture on `wlan1mon` works while pineapd owns and hops it~~
  **Answered 2026-11-05 for the locked case, which is the only case this rung uses.** The Disrupt
  that ran on the 1.1.3 unit looted `…|ch 9|D+C|0c00|…` — a badge and a raw RSN Capabilities field,
  neither of which can exist without a beacon having been captured and parsed (CLAUDE.md "Second
  contact"). The capture runs under a short EXAMINE lock, so the *hopping* half of the question is
  the reason the lock is there and remains unmeasured. **[A]** on the step from "a badge was looted"
  to "the capture worked". *Falsified by:* a loot row with a real badge produced without a beacon
  capture.
- ~~whether the three `PINEAPPLE_DEAUTH_CLIENT*` commands behave as `hak5cmd`'s help text claims~~
  **Answered 2026-11-09, and they do not** — read from pineapd's own handler rather than from the
  help, which this binary has now had wrong four times: one function, one numeric opcode, 400/401/402
  (CLAUDE.md "Third contact", §2 above). Measured alongside it: `_CSA` takes **two** arguments and
  not three (2026-11-05).
- ~~`PINEAPPLE_DEAUTH_CLIENT_ALL`'s target argument — its help says "all clients on an AP" yet it
  takes a target, which is passed through but whose semantics are unconfirmed~~ **Answered
  2026-11-09: the semantics are that there are none.** `_ALL` sends opcode **402**, and the 402 path
  never reads `sta`, so the `ff:ff:ff:ff:ff:ff` the Go daemon writes by immediate is dead data and
  `_ALL` builds no deauth frame at all (§2). The question was well posed and its answer makes the
  command unusable rather than untargeted.
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
  the reasoning did not. *Strengthened 2026-11-09, still not closed:* `inject_csa` @ `0x4a125c` only
  **queues** a record, and the CSA element is constructed inside `index_beacon_ns` (at `+0xc0a`) —
  i.e. the frame is built when a beacon from that BSSID is indexed, which is what a beacon-carried
  CSA looks like from the inside and is hard to explain for an action frame. A capture is still what
  would close it (CLAUDE.md "Third contact").
- whether Recon's packet counters move the way `resp_verdict` assumes — **still open, and it is now
  the oldest unanswered item in this section**
- ~~whether the CSA attack moves a real client **at all** — see §7~~ **Answered 2026-11-10, and not
  through these commands — the question has moved to `pagerinj` for good.** A CSA-bearing cloned
  beacon from `pagerinj` does reach a live client, and it does two **separable** things: Channel
  Switch **Mode 1** quiesces the client in place (six arms, zero auth and zero assoc frames in any
  of their captures), while **mode 0** makes it re-associate (a complete Authentication / ReAssoc
  Request / ReAssoc Response cycle, twice in one run). CLAUDE.md "Seventh contact" for the
  separation and "Eighth contact" for the frame-by-frame read. Two cautions carry back here:
  "mode 0 **moves** it" is **[A]** and was *withdrawn* as a reading — no frame in that capture shows
  the station change channel or says where it went — and the **count ≥ 1 denial** prediction was
  tested and **failed**, the client re-associating successfully while count-3 CSAs were in the air,
  for a reason that is structural: the target AP's own beacons keep refreshing the cached IEs, so
  17a cannot test the denial path against an AP that is still on the air. None of this is reachable
  from the firmware commands, whose CSA announces **channel 14 with count 0**.

**🆕 Open, from the recon side (2026-11-15): a member heard only as a DESTINATION may be a member
that already left.** After a deauth that worked, the AP goes on retrying to the departed station for
a while — so a station the next capture hears only as `addr1` can still be admitted as a member, and
a *successful* attack is exactly the condition that produces them. `CLI_AWK` already distinguishes
the two directions and prints `UP <sta> <n>` for a station heard **transmitting** (and `OWN <sta>
<n>` for every frame it sent), which `resp_members` could use to tell "present" from "was present";
it currently reads only the `CLI` lines, which admit either direction. **Recorded as an observation,
not a change:** `resp_members`' success path belongs to the recon-side session, and nothing about it
is touched here. Note the trade-off is real in both directions — dropping destination-only stations
from the *transmit* set would re-introduce the 2026-11-09 defect, where the measurement gate gated
the frame — so if this is acted on, the place to act is the **measurement** set. *Falsified by:* a
station that a post-deauth capture hears **only** as the AP's destination turning out to be still
associated — which would make destination-only no evidence of departure, and the distinction not
worth drawing.

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
