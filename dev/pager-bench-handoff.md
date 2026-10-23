# Handoff — operating the Pager at the bench

**For the session that will walk the operator through first contact with the hardware.** Written by
the development session that did the firmware analysis. Everything here is on disk; nothing depends
on that session still existing.

Read this first, then `dev/pager-day-one.md` for the running order. The reasoning behind every step
is in `dev/pager-6ghz-determination-plan.md`; the gate and primitive facts are in
`dev/pager-csa-primitives.md`; CamHound's response side is in `dev/CamHound/RESPONSE.md`.

---

## 1. What the operator is doing

They own a Hak5 WiFi Pineapple Pager (model Mk1), working inside a **shielded RF chamber rated well
above anything the device can transmit**, licensed and authorised. The RF-containment question is
settled — do not re-litigate it, and do not pad answers with legal caveats; they have asked for
that explicitly.

The goal is a **determination**: can 6 GHz injection be unlocked on this device, and separately,
can 5 GHz DFS injection be. The second is the bigger practical win. Both are gated by software, not
by hardware.

The operator is competent and moves fast. They want verified answers, not hedged ones, and they
have twice caught this project's own sessions asserting things from memory that turned out wrong.
**If you are not sure, say so and check.** Marking a claim verified when it is inferred is the
failure mode that costs them bench time.

---

## 2. The single most important concept: two gates in series

A frame needs to clear **both**. They block different channels for unrelated reasons, and only one
of them responds to the regulatory domain. Nearly every confusing result traces back to conflating
them.

### Gate 1 — pineapd, in userspace. Hardcoded. Regulatory domain is irrelevant to it.

A compiled-in channel switch, duplicated in `pineap_wifi_interface::inject` (`0x46e800`–`0x46e826`)
and `interface_tracker::inject_deauth` (`0x472c66`–`0x472c8a`). Blocked set is **exactly** the 16
FCC DFS channels:

```
52 56 60 64  100 104 108 112  116 120 124 128 132 136 140 144
```

Everything else passes: `ch < 52`, `ch 65–99`, `ch 113–115`, `ch >= 145`. **ETSI DFS channels 68–96
are not blocked** — useful as a gate-1-free DFS control if the chamber AP can sit on ch 96.

Plus a separate 6 GHz refusal: `chan->+0x1c == 8`, wholesale, no subset.

`pcap_inject` has **exactly one call site**, inside the gated function, so every injected frame
passes gate 1 — and a non-pineapd injector bypasses it completely. The binary contains no
`NL80211_CMD_GET_REG` and no regulatory strings at all; channel enumeration reads only
`FREQUENCY_ATTR_FREQ` and `FREQUENCY_ATTR_DISABLED`. **No regdb edit or `iw reg set` can lift
gate 1.** There is no environment variable (`getenv` is never called), no UCI option, no debug flag.

### Gate 2 — cfg80211, in the kernel. This one follows the regulatory domain.

`ieee80211_monitor_start_xmit()` calls `cfg80211_reg_check_beaconing()` — this kernel's rename of
`cfg80211_reg_can_beacon()`, which survives only as a static inline wrapper hardcoding
`relax = false`. For a monitor vif the prohibited flags are:

```
IEEE80211_CHAN_DISABLED | IEEE80211_CHAN_NO_IR
```

**`IEEE80211_CHAN_RADAR` is not prohibited.** This matters enormously: under `country 'US'` **no
5 GHz channel carries `NO_IR` at all**, so gate 2 permits all of 36–165 and the DFS block is
entirely gate 1's.

**The refusal is silent.** A blocked frame is freed and the path returns `NETDEV_TX_OK` — no errno,
no counter, `sendto()` reports the full byte count. Nothing on the Pager can distinguish
"transmitted" from "silently dropped". This is why an independent receiver is mandatory for any
claim that a frame went out.

---

## 3. Hardware facts, settled

From FCC ID **2A52Y-MK1** (grantee Hak5 LLC), radio report `TZ0278250701FRF08` and internal photos
`TZ0278250701PH03`:

- **Certified to transmit on all four 6 GHz sub-bands** — U-NII 5 (5945–6425), 6 (6425–6525),
  7 (6525–6875), 8 (6875–7125 MHz), 802.11ax. The 6 GHz PHY exists and the antennas are tuned for
  it (measured 4.43 dBi and 2.93 dBi, 2T2R).
- **The Pager is a one-transmitter, two-receiver device.** Antennas `WIFI-1` / `WIFI-2` are
  annotated "Wifi 2.4G/5G/6G Antenna 1/2" and do all transmitting, on every band. `2.4G-1` /
  `2.4G-2` are annotated **"Not used for transmitting"** — `radio0` is receive-only. Corroborated
  by its config: `band '2g'` on `platform/10300000.wmac`, with every AP-mode interface shipping
  `disabled '1'`.
- Board revision `Pager V2.2.0`, dated 2025/06/03. If the unit differs, re-check assumptions.
- The module part number is under an intact shield can; BOM and schematics are withheld. The exact
  MT7921 variant is unknown and no longer matters.

**Consequence for the bench: `wlan0mon` cannot receive 5 GHz.** It is a fine independent receiver
for a 2.4 GHz control — and being a physically different chip is exactly why it is useful there —
but it cannot hear ch 52, and its silence would be silence either way.

**A refuted hypothesis, recorded so nobody re-derives it:** that the device was 6 GHz
receive-capable but never certified to transmit. It *was* certified. The gate is not a
certification gap.

---

## 4. What the operator needs, and why

| Item | Why it is not optional |
|---|---|
| **6E-capable monitor receiver** — they ordered an EDUP AX1672 (MT7921AU, USB 3.0, tri-band) | The only way to distinguish "transmitted" from "silently dropped". Load-bearing for **both** branches: it is also the 5 GHz receiver for the DFS tests, since `wlan0mon` cannot hear 5 GHz. |
| **6 GHz AP** in the chamber | Beacon source for receiver proof, and the CSA target. |
| **Real 6 GHz client** | **Required, not optional.** A beacon capture tells you the AP's beacon-protection *policy*; only a real client tells you whether a forged beacon is actually dropped, because enforcement depends on the client's own driver (§5). |
| **5 GHz AP on a DFS channel** | The DFS branch's target. |

**Validate the receiver against a source that is not the Pager, before the Pager is powered on.**
If that is skipped, no later result can be interpreted.

Do **not** suggest an Intel AX210/AX211 as the receiver: iwlwifi learns its country from received
beacons in client mode, so in monitor mode the regdom stays `00` and 6 GHz channels come back
`disabled`. Same class of trap as the device under test.

---

## 5. The value gate — raise this early

It may end the 6 GHz branch before any effort is spent, and the operator should decide with it in
hand rather than discover it at step 15.

`pineapd` imports 21 `libwifi_*` symbols, of which four are builders (`libwifi_create_beacon`,
`_deauth`, `_disassoc`, `_radiotap`). Its CSA almost certainly rides a spoofed beacon — that rests
on `csa_beacon_record`, `recon_engine::inject_csa` and the string `"Caught beacon for CSA on {}"`,
**not** on the import list, because pineapd also imports `pcap_inject` and can transmit any byte
buffer it composes itself (it already hand-builds a CSA element without importing any
`libwifi_*_tag` function). Treat the carrier as strongly indicated, not proven.

The device's `/usr/lib/libwifi.so.0.0.10` exports **113** functions — 92 of them unreferenced by
pineapd — including `libwifi_create_action`, `_action_no_ack`, `_add_action_detail`,
`_create_probe_resp` and `libwifi_set_probe_resp_channel`. A non-pineapd injector can `dlopen` the
shipped library and get action frames and probe responses without vendoring anything. **Linking
`-lwifi` against the shipped file does not work** (it has no section headers; `ld` refuses it) —
use `dlopen`/`dlsym`, no headers ship so write prototypes and struct layouts by hand against
upstream `0.0.10`, and because it is MIPS16 never mask bit 0 of a `dlsym` result.

**Separate the two effects before judging any of this.** *Moving* a client to another channel and
*stopping it connecting at all* are reached through different code and have different defences. An
earlier revision of these notes collapsed them and got the conclusion wrong twice.

| Attack on 6 GHz | Viability |
|---|---|
| Deauth / disassoc | **Dead by standard.** 6 GHz mandates WPA3 (OWE even for open), so PMF is mandatory. Hak5's own docs say this. |
| Beacon CSA, as a **channel move** | **Works unless the AP *and* the client both enforce beacon protection.** mac80211 drops MME-less beacons once the client holds a BIGTK, before the CSA element is read — but the client's driver has to be able to install one. |
| Beacon CSA, as **connection denial** | The path is real — the forged beacon reaches the cfg80211 BSS cache *before* the protection check, and mac80211 refuses auth and assoc while a cached CSA is present — but **pineapd cannot reach it.** Its CSA carries Channel Switch Count = 0, and the kernel discards a count-0 CSA before that check. Needs an injector of our own with `count != 0`. See §5a. |
| Probe-response CSA | **Moves nothing** in station mode, and the same count-0 problem blocks the denial path. |
| Public-Action eCSA (cat 4, action 4) | Outside PMF's robust set, so it reaches a protected client — but it does not switch anything. With the CSA mode byte set it blocks the client's TX queues, and **the stall persists** (the unblock sits behind a beacon-CRC short-circuit that a stable AP never trips). On a driver advertising `HANDLES_QUIET_CSA`, it does nothing at all. |

> If the deliverable is "the client changes channel", beacon protection may well end it. If the
> deliverable is "the camera stops working", it does not — the denial path survives. Ask the
> operator which one they need before declaring the branch dead, and say which effect you measured.

### §5a The one byte that settles it: pineapd's CSA carries Count = 0

Before planning anything around CSA, know this. pineapd builds every CSA element as
`{37, len 3, mode 1, new_ch = runtime, count 0}` — construction at `0x4bee8a`, inside
`recon_engine::index_beacon_ns`, which catches a real beacon and clones it. And
`ieee80211_mgd_csa_present()` (`mac80211_mlme.c:8349`) throws away any CSA whose count is 0 *before*
the auth/assoc refusal check:

```c
	if (csa && csa->count == 0)
		csa = NULL;
```

So **the connection-denial effect cannot be triggered by anything pineapd sends.** It is not a
flood-rate problem; the frames are disqualified by their own contents. Count 0 is simultaneously
what makes the *channel move* immediate, which is why CSA works on every other badge. **[V]** on
both sides.

Any non-zero count survives that check, so the same frame with `count = 3` would get the move **and**
the refusal. There is no setting for it — this needs the Stage-B injector, which is wanted for the
DFS work anyway. That is **day-one step 17a**, and it is the highest-value cheap experiment in the
runbook. Do not go hunting for a config option, and do not patch pineapd's instruction without
reading the warning in `dev/pager-csa-primitives.md` §"THE ONE BYTE".

### The beacon capture answers half the gate — take it, but do not stop there

Capture one beacon from the chamber AP and read two fields. This is cheap and worth doing first:

| What | Where | tshark |
|---|---|---|
| MMIE present in the beacon | element ID **76** | `wlan.tag.number == 76` |
| Beacon Protection Enabled | Extended Capabilities (ID 127) **bit 84** — octet 10 zero-based, mask `0x10` | `wlan.extcap.b84 == 1` |

Both present → that AP enables beacon protection. Neither → it does not, and beacon CSA moves
clients. Expect the former more often than you would think: hostapd switches `beacon_prot` on by
itself whenever 11be is enabled with PMF, so a modern 6 GHz AP tends to have it without anyone
asking.

**What the capture cannot tell you:** whether a client will actually drop the forged beacon.
Enforcement needs the client to hold a BIGTK, and `nl80211` refuses key indices 6–7 outright unless
the client's wiphy advertises `NL80211_EXT_FEATURE_BEACON_PROTECTION` (or `..._CLIENT` for a
station). hostapd hands out the BIGTK without checking the client can use it, so a bit-84 AP will
happily associate a client that enforces nothing. That is why the real client is on the equipment
list.

**Report which AP and which client.** "Beacon CSA worked" on its own is uninterpretable — it may
mean only "my AP does not enable beacon protection", or "this client cannot enforce it".

A client that does enforce reports MME-less beacons back to its AP in a WNM Notification frame
(`WNM_NOTIF_TYPE_BEACON_PROTECTION_FAILURE`), and mac80211 surfaces the same failure to userspace
via `cfg80211_rx_unprot_mlme_mgmt()`, so the attack is self-announcing on a protected network. The
mechanism is **[V]**; whether a given client actually sends it is **[A]**.

---

## 6. Traps that will mislead you

1. **The log wording lies.** `pineap_wifi_interface::inject`'s DFS branch loads the **6 GHz** format
   string. A line reading `"{} can not inject on 6GHz restricted channel X/Y"` *with* an
   interface-name prefix is a **5 GHz DFS** refusal. Only `"can not inject on DFS restricted
   channel"` (no prefix) comes from `inject_deauth`. **Attribute by prefix, never by the words.**
2. **`inject_csa` freezes the channel before the refusal.** It injects nothing itself — it records a
   `csa_beacon_record` and calls `set_and_freeze_primary_channel_hop_s`. Firing CSA at a blocked
   channel parks the radio there and transmits nothing. If recon goes quiet after a failed attempt,
   that is why; unfreeze before continuing.
3. **Silent drops look like a resisting target.** See gate 2 above.
4. **Band-4 presence is a hardware read, not a regulatory one.** `mt76_check_sband()` runs before
   `ieee80211_register_hw()`, so the regdomain cannot cull the band. Do not re-run the Band-4 test
   under different countries hoping it appears.
5. **Do not let the device update its firmware** before the version is recorded. Every address and
   offset above is pinned to **1.1.3-stable**.

---

## 7. The cheap test that could skip an entire invasive stage

Before anyone reaches for a hex editor, at step 15 of the day-one order:

The band field that triggers gate 1's 6 GHz refusal is written at **exactly one instruction in the
whole binary** — inside `pineap_wifi_channel::from_string`'s `"%uW6e"` branch. Every other producer
writes a different encoding (`mac80211::get_channel` hardcodes `0`;
`find_primary_widest_channel` writes the raw `nl80211_band` index). And the DFS switch cannot catch
a 6 GHz channel either, since valid 6 GHz 20 MHz channel numbers are ≡1 mod 4 while the blocked set
is ≡0 mod 4.

`interface_tracker::command_send_deauth` builds its channel via `from_string` on the command's
string field. **So how the channel is spelled may decide whether gate 1 fires at all.** Issue the
same 6 GHz target twice — once as `"37W6e"`, once as a plain frequency — and compare the log. If
only the first is refused, Stage C is unnecessary.

This is **[A]**, inferred from the writers rather than traced at runtime. It is cheap to test and
would be expensive to assume.

---

## 8. Code this project ships that needs on-device validation

`csa_injectable()` in `library/user/reconnaissance/CamHound/payload.sh` decides whether CamHound
will fire at a target. It models both gates:

- Gate 1 as the constant `PINEAPD_DFS_BLOCKED` (mirroring the compiled-in firmware policy) plus a
  blanket 6 GHz refusal pending this determination.
- Gate 2 live, via `inj_probe()` parsing `iw phy <phy> channels` into `INJ_OK` keyed `band/channel`.

Two things to check on-device, both free:

1. **`inj_probe()`'s parser has never seen live `iw` output.** It was written against the format
   strings inside the shipped `iw` binary, not against a real run. Capture
   `iw phy <phy> channels` verbatim and diff it against what `inj_probe` produced, once, by hand.
2. **Which regulatory domain is actually live** (`iw reg get`). The fallback set when the probe
   fails is deliberately conservative — 2.4 GHz 1–11 and 5 GHz 36–48 only, the set injectable under
   *both* US and world domains. If the device runs US, 149–165 should also come back injectable
   once the probe works.

`inj_probe()` must run in the **parent shell** (`preflight()` and `disrupt_menu()`), because
`csa_injectable()` is reached from `posture_from_caps()` inside `$( )` where writes to globals are
discarded. If you touch this code, preserve that.

---

## 9. What is verified, and what is not

**Verified** by direct inspection of the shipped binaries, the kernel/driver source for this exact
build, or the FCC filing: the gate-1 channel set and its two addresses; gate 2's prohibited flags;
that `pcap_inject` has one call site; the shipped regdb's contents for US / world / GB; that
`CONFIG_CFG80211_REQUIRE_SIGNED_REGDB=n` (no `.p7s` literal, no PKCS#7 imports, no signature file);
`disable_clc` as a module parameter; 6 GHz certification and antenna gains; the antenna map; the
log-string mix-up; that `inject_csa` injects nothing itself.

Also verified by reading the mac80211 receive path this build backports (station mode): that a
client holding a BIGTK drops MME-less beacons before the CSA element is parsed, provided MFP is in
use and the frame is not flagged `RX_FLAG_DECRYPTED`; that a probe-response CSA never reaches the
chanswitch path; that a forged CSA beacon still poisons the cfg80211 BSS cache and makes auth and
assoc bail; that an unprotected Public-Action eCSA blocks TX queues rather than switching, and that
the unblock sits behind a beacon-CRC short-circuit so the stall persists; that a Spectrum-Management
CSA action frame is trusted from its category alone and so is **not** insider-only without PMF; and,
with `nm -D` / `objdump -T` / `readelf --use-dynamic`, that the shipped `libwifi.so.0.0.10` exports
113 functions including action-frame and probe-response builders pineapd does not use.

**Assumed / inferred, stated as such:** that gate 1's 6 GHz check is unreachable for
hardware-derived channels (§7); that `inject_csa` emits via the beacon path specifically — the
import list does *not* prove this, since pineapd can inject arbitrary bytes via `pcap_inject` and
already hand-composes elements; the motive behind the gate; that no undisclosed hardware enforcement
exists — the FCC filing that would describe it is withheld, so this is absence of public evidence,
not evidence of absence; that a pre-2024 or non-Linux client might honour an unprotected eCSA by
actually switching.

**Not determined:** whether the MT7961's closed firmware independently gates 6 GHz TX; whether
beacon protection is *required* on 6 GHz (WPA3 and PMF are; the Wi-Fi Alliance specification itself
could not be retrieved, so that leg is unverified rather than refuted, and the requirement that does
exist was drafted for Wi-Fi 7, not for the band); whether a given client driver supports BIGTK
installation at all; which drivers set `HANDLES_QUIET_CSA`; client behaviour on stacks other than
mac80211; free flash space; the module part number.
