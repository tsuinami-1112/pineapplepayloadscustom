# WiFi Pineapple Pager: the CSA disconnect primitives

**Purpose of this file.** Hand it to any session that needs the Pager's channel-switch-announcement
(CSA) attack. It exists so nobody has to re-derive this by grepping the firmware image again —
that takes an hour and several sessions have now done it independently.

Verified against firmware **1.1.3-stable** (`OPENWRT_RELEASE="Pineapple Pager 24.10.1
r28597-0425664679"`, `DISTRIB_REVISION='20260302-1457-g16e57f5-dirty'`, `OPENWRT_ARCH="mipsel_24kc"`).

---

## Read this first — three facts, and they are easy to confuse

1. **The CSA attack IS in the shipping firmware.** It is implemented in `pineapd` and exposed by
   two CLIs. It is not something you need to build, port or cross-compile.
2. **It is NOT documented anywhere.** Not in Hak5's published DuckyScript reference, not on
   documentation.hak5.org, and not in any file on the device itself. Worse than absent: the
   published `DEAUTH_CLIENT` page states that PMF/802.11w networks "will not be susceptible" and
   that 6 GHz is excluded because WPA3 blocks injected deauth — which is true of *deauth* and
   actively misleading about what the device can actually do. **A docs search will tell you this
   feature does not exist. It does.**
3. **It is NOT the aircrack-ng implementation.** [aircrack-ng PR #2724](https://github.com/aircrack-ng/aircrack-ng/pull/2724)
   adds `aireplay-ng --csa`; that PR is **still open and unmerged**, `src/aireplay-ng/csa.h` on
   master is a 404, and the Pager ships **no aircrack-ng, no mdk4, no hcxdumptool and no python3**.
   Do not go looking for `aireplay-ng` on the device. The vendor primitive is unrelated to it.

If you only remember one line: **`_pineap DEAUTHCSA <bssid> <channel>` already exists and works
against WPA3, and nothing in the documentation will tell you so.**

## The commands

Three DuckyScript commands, usable directly from a payload. Signatures below are taken verbatim
from `hak5cmd`'s own help text, not inferred:

| Key | Command | Frames |
|---|---|---|
| deauth | `PINEAPPLE_DEAUTH_CLIENT [bssid] [target] [channel]` | deauthentication + disassociation |
| CSA | `PINEAPPLE_DEAUTH_CLIENT_CSA [bssid] [channel]` | channel-switch announcements |
| both | `PINEAPPLE_DEAUTH_CLIENT_ALL [bssid] [target] [channel]` | all three frame types |

Verbatim help text:

```
PINEAPPLE_DEAUTH_CLIENT_CSA - Use PineAP to attempt to disconnect
all Wi-Fi clients on an AP using channel-switch announcements
PINEAPPLE_DEAUTH_CLIENT_CSA [bssid] [channel]

PINEAPPLE_DEAUTH_CLIENT_ALL - Use PineAP to attempt to disconnect
all Wi-Fi clients on an AP using deauthentication,
disassociation, and channel-switch announcements
PINEAPPLE_DEAUTH_CLIENT_ALL [bssid] [target] [channel]
```

The CSA form takes **no target** because the announcement rides in a beacon and has no unicast
recipient. That asymmetry is confirmed by two distinct arity-check error strings in `_pineap`:
`Expected [bssid] [target] [channel]` and `Expected [bssid] [channel]`.

There are two lower layers if you need them. The `_pineap` socket client:

```
DEAUTH       Inject deauthentication and disassociation packets
DEAUTHALL    Inject deauthentication, disassociation, and CSA packets
DEAUTHCSA    Inject CSA packets
```

and an HTTP API: `/api/pineap/deauth`, `/api/pineap/deauth_all`, `/api/pineap/deauth_csa`.

**Prefer the `PINEAPPLE_DEAUTH_CLIENT*` DuckyScript wrappers** in payloads — they are the same
surface the rest of the library uses (e.g. `library/user/interception/fenris` calls
`PINEAPPLE_DEAUTH_CLIENT`).

## Where it lives, and how to re-verify in 30 seconds

`DEAUTHCSA` / `DEAUTH_CLIENT_CSA` appears in **exactly two files on the entire device**, both
binaries, and **zero documentation files**:

```
/usr/bin/_pineap
/usr/bin/hak5cmd
```

The implementation is in `/usr/sbin/pineapd`. Re-verify with `strings`:

```sh
strings /usr/sbin/pineapd | grep -E 'inject_csa|csa_beacon_record|CSA'
strings /usr/bin/_pineap  | grep -E '^DEAUTH(ALL|CSA)?$|^Inject '
strings /usr/bin/hak5cmd  | grep -A3 'PINEAPPLE_DEAUTH_CLIENT_CSA -'
```

What you will find in `pineapd`:

| Evidence | Meaning |
|---|---|
| `_ZN12recon_engine10inject_csaEPKcRK19pineap_wifi_channelh` | `recon_engine::inject_csa(char const*, pineap_wifi_channel const&, unsigned char)` — it lives in the **recon engine**, which is why it is reachable from the Recon UI |
| `csa_beacon_record` in a `std::unordered_map` | a per-BSSID cache of captured beacons |
| `"Caught beacon for CSA on {}"` | it **captures a real beacon** from the target first |
| `"Queuing CSA for {}"` → `"Queued packets for CSA on {}"` | the injection is queued, not immediate |
| `"Request to inject CSA expired for {}: {}ms"` | the queue **times out** — it is waiting for its own channel hopper to reach the target channel |

Those last three matter practically: **pineapd solves the channel-contention problem internally**,
because the same process owns both the channel hopping and the injection. You do not need to fight
it for the radio the way a userspace injector would.

Frame construction is `/usr/lib/libwifi.so.0.0.10` — Hak5's own Apache-2.0 802.11 library. It
exports `libwifi_create_beacon`, `libwifi_add_tag`, `libwifi_create_radiotap` and
`libwifi_create_auth`. `pineapd` imports only the beacon/deauth/disassoc subset; the auth builder
is shipped but unreferenced by anything on the device.

### Disassembling pineapd: it is MIPS16e, and the usual tools silently fail

Budget an hour if you skip this. `pineapd`'s C++ is **MIPS16e, not MIPS32**: `readelf -h` shows
`Flags: 0x74001005 … mips16`, the ABIFLAGS segment has `ases = 0x400` (`AFL_ASE_MIPS16`), and every
function symbol value is **odd** (the ISA bit) — e.g. `pineap_wifi_interface::inject` =
`0x0046e7d1`. Only crt/INIT/PLT-adjacent code is MIPS32. The binary also has **no section headers**,
so you must work from program headers and the dynamic symbol table.

Neither a stock `objdump` (usually x86-only) nor `llvm-objdump` can disassemble MIPS16 — LLVM has no
MIPS16 disassembler, and both will produce confident garbage rather than an error. What works:

```sh
apt-get install -y binutils-mipsel-linux-gnu
# vma = 0x400000 + file offset, for the single executable PT_LOAD (offset 0, size 0x1380e0)
mipsel-linux-gnu-objdump -D -b binary -m mips:16 -EL --adjust-vma=0x400000 \
    --start-address=0x46e7d0 --stop-address=0x46ea40 usr/sbin/pineapd
```

`-m mips:16` (`bfd_mach_mips16`) is the load-bearing flag. Dynamic symbols: SYMTAB `0x404f0c`,
STRTAB `0x40fc6c`, SYMENT 16, `MIPS_SYMTABNO` 2774. PLT: JMPREL `0x44488c`, 414 entries, MIPS16 PLT
stubs are 16 bytes from `0x5367d0` with each stub's `.got.plt` slot address at stub+12.

MIPS16 condition semantics, which are easy to misread backwards:

| Instruction | Effect |
|---|---|
| `CMPI rx,imm` | `T = rx ^ imm` (so `T == 0` means **equal**) |
| `SLTIU rx,imm` | `T = (rx <u imm)` |
| `BTEQZ` / `BTNEZ` | branch if `T == 0` / `T != 0` |

So `sltiu v0,145 ; bteqz L` reads **"if v0 >= 145 goto L"**, not the reverse.

**Two things that are inferred, not confirmed** — do not state them as fact:

- Whether `DEAUTHCSA` emits a CSA-bearing **beacon** or a spectrum-management **action frame**. The
  `inject_csa` signature plus `"Caught beacon for CSA"` and `libwifi_create_beacon` strongly imply
  beacon, but nobody has captured it. What *is* verified: `recon_engine::inject_csa` (`0x4a125c`)
  injects nothing itself — it holds no `libwifi_create_*`, no queue `emplace` and no `pcap_inject`.
  It records a `csa_beacon_record` in an `unordered_map` and calls
  `set_and_freeze_primary_channel_hop_s`, so the CSA leaves via the ordinary beacon path.
  **Operational consequence:** firing CSA at a gate-1-blocked channel will still *set and freeze the
  radio's primary channel* there, and only the subsequent beacon is refused — so it disrupts channel
  hopping while transmitting nothing. `csa_injectable()` refusing those channels prevents that, which
  is a second, independent reason the refusal is correct.
- `PINEAPPLE_DEAUTH_CLIENT_ALL`'s `[target]` argument. Its help says "all Wi-Fi clients on an AP"
  yet it takes a target; pass `ff:ff:ff:ff:ff:ff` for broadcast, but the exact semantics are
  unverified.

## Why CSA works where deauth does not

802.11w (PMF) makes deauthentication and disassociation **robust management frames**: unicast ones
are CCMP-protected under the PTK, group-addressed ones carry an MMIE keyed by the IGTK. WPA3-Personal
mandates PMF, so a forged deauth has no valid MIC and is dropped. This is why Hak5's own docs say
WPA3 is immune — for deauth, they are right.

**Beacons are not robust management frames.** 802.11w does not protect them, so a Channel Switch
Announcement element carried in a beacon is unauthenticated even on a PMF-required network. Spoof
the AP's BSSID, inject a beacon carrying a CSA pointing at another channel, and a compliant client
follows the switch. The real AP never moved, so the client lands on a dead channel and must rescan.
Same observable outcome as a deauth, achieved entirely outside the frames PMF covers.

Confirmable in the kernel: `_ieee80211_is_robust_mgmt_frame()` returns true only for deauth,
disassoc and non-excluded action frames. A beacon is not in that set.

**It is not a deauth, and calling it one causes mistakes.** It is a channel-switch spoof. Different
frame, different reason it works, different detection signature.

## What defeats it

**Beacon protection.** Added in the Wi-Fi Alliance's WPA3 December-2020 update: a BIGTK plus a
Management MIC element in the beacon. Where both AP and client enforce it, forged CSA beacons are
dropped. Client support is still patchy, which is why the attack works today — but AP support is
**mandatory in Wi-Fi 7**, so this decays.

Reading it from a beacon, for target triage:

| Property | Element | Location |
|---|---|---|
| MFPC — PMF capable | RSN, ID 48 | RSN Capabilities, bit 7 → `0x80` of the low octet |
| MFPR — PMF required | RSN, ID 48 | RSN Capabilities, bit 6 → `0x40` of the low octet |
| **Beacon Protection** | **Extended Capabilities, ID 127** | **bit 84** → octet 10 (0-based), mask `0x10` |

**Beacon protection is NOT in the RSNXE (ID 244).** That element has no such bit; the one that
looks like it is RSNXE bit 11, "Protected Announce Support", which is a different thing. This has
already been got wrong once in this repo. Sources: hostap `src/ap/ieee802_11_shared.c`
(`WLAN_EXT_CAPAB_BEACON_PROTECTION 84`) and Wireshark `wlan.extcap.b84`, mask `0x10`.

Note RSN Capabilities sits after two variable-length suite lists — version (2) + group cipher (4) +
pairwise count (2) + 4×N + AKM count (2) + 4×M — so walk them rather than assuming an offset.

A working implementation of all of this already exists in this repo:
`library/user/reconnaissance/CamHound/payload.sh`, in the block marked
`# --- response posture begin ---`, with its design written up in `dev/CamHound/RESPONSE.md`.

## Hard constraints

### Bands: two independent gates, and the obvious explanation is the wrong one

A frame needs to clear **two gates in series**. Confusing them wastes a lot of time, because they
block different channel sets for unrelated reasons and only one of them responds to the regulatory
domain.

#### Gate 1 — pineapd, in userspace. Hardcoded. The regulatory domain is irrelevant to it.

`pineapd` refuses before the kernel is ever involved. The policy is a compiled-in channel-number
switch (GCC-lowered to range tests plus `0x1111` / `0x11111111` bitmask shifts), duplicated at:

| Function | Address range | File offset |
|---|---|---|
| `pineap_wifi_interface::inject` | `0x46e800`–`0x46e826` | `0x6e800`–`0x6e826` |
| `interface_tracker::inject_deauth` | `0x472c66`–`0x472c8a` | `0x72c66`–`0x72c8a` |

The blocked set is **exactly** the 16 standard 20 MHz FCC DFS channels:

```
52 56 60 64  100 104 108 112  116 120 124 128 132 136 140 144
```

Everything else is allowed: `ch < 52`, `ch 65–99`, `ch 113–115`, `ch >= 145`. Note that **ETSI's
DFS channels 68–96 are NOT blocked** — `68` takes the `65..115` branch, `68-100` underflows, fails
the `sltiu 13` bound, and the inject proceeds.

`pcap_inject` has **exactly one call site**, inside `pineap_wifi_interface::inject`, so every
injected frame passes gate 1. `inject_deauth` checks the same predicate redundantly, so a deauth is
tested twice.

This gate **never asks the kernel about regulatory state**: there is no `NL80211_CMD_GET_REG`
anywhere in the binary, no `alpha2`/`country`/`regdom`/`regulatory`/`radar`/`NO_IR` strings, and no
regdb file access. Channel enumeration (`mac80211::nl80211_get_freqlist_cb`) reads only
`NL80211_FREQUENCY_ATTR_FREQ` and `NL80211_FREQUENCY_ATTR_DISABLED` — never `RADAR`, `NO_IR`,
`DFS_STATE` or `INDOOR_ONLY`. **So `iw reg set`, a custom `regulatory.db`, or
`cfg80211.ieee80211_regdom=` cannot lift gate 1.** There is no environment variable (`getenv` is
never called), no UCI option, and no debug flag that skips it.

On refusal it logs and returns `-1` without reaching `set_channel` or `pcap_inject`.

> **Debugging trap.** The DFS branch in `pineap_wifi_interface::inject` loads the **6 GHz** format
> string, not the DFS one. So `"{} can not inject on 6GHz restricted channel X/Y"` (with an
> interface-name prefix) is actually a **5 GHz DFS** refusal from the common path, while
> `"can not inject on DFS restricted channel X/Y"` can only come from `inject_deauth`. Do not
> diagnose by log wording.

#### Gate 2 — cfg80211, in the kernel. This one does follow the regulatory domain.

`ieee80211_monitor_start_xmit()` calls **`cfg80211_reg_check_beaconing()`** — the modern rename of
`cfg80211_reg_can_beacon()`; on this build (kernel 6.6.86 + backports 6.12.61) `mac80211.ko`
imports `cfg80211_reg_check_beaconing` and the old name is absent from both modules. For
`NL80211_IFTYPE_MONITOR` the prohibited flags are:

```
IEEE80211_CHAN_DISABLED | IEEE80211_CHAN_NO_IR
```

**`IEEE80211_CHAN_RADAR` is not prohibited there.** The DFS relaxation branch is also never taken,
because `cfg80211_chandef_dfs_required()` returns 0 for `MONITOR` — but that branch could only ever
*grant* permission, so it is not what blocks DFS.

**The refusal is silent.** The frame is freed and the function returns `NETDEV_TX_OK` — no errno, no
dropped-frame counter, and `sendto()` reports the full byte count. If you are debugging "the command
ran and nothing happened on the air", suspect this first.

#### What the shipped regdb actually says

Decoded from `/lib/firmware/regulatory.db` (RGDB v20, 6176 bytes, 175 countries):

```
US (dfs_region=FCC)
  2400.0 - 2472.0 MHz  30.0 dBm  [-]
  5150.0 - 5250.0 MHz  23.0 dBm  [AUTO-BW]
  5250.0 - 5350.0 MHz  24.0 dBm  [DFS, AUTO-BW]        <- DFS, and NO-IR is NOT set
  5470.0 - 5730.0 MHz  24.0 dBm  [DFS]                 <- DFS, and NO-IR is NOT set
  5730.0 - 5850.0 MHz  30.0 dBm  [AUTO-BW]
  5925.0 - 7125.0 MHz  12.0 dBm  [NO-OUTDOOR, NO-IR]
00 (world)
  5250.0 - 5330.0 MHz  [DFS, NO-IR, AUTO-BW]
  5490.0 - 5730.0 MHz  [DFS, NO-IR]
  5735.0 - 5835.0 MHz  [NO-IR]                         <- even 149-165 is NO-IR here
GB (ETSI)
  5925.0 - 6425.0 MHz  24.0 dBm  [NO-OUTDOOR]          <- 6 GHz with NO-IR NOT set
```

**So under `country 'US'` no 5 GHz channel carries `NO_IR` at all** — gate 2 permits all of 36–165,
and the effective block on 52–144 is **entirely gate 1's**. An earlier version of this document
blamed `NO_IR` for the DFS block; that was wrong. Under the world domain `00`, by contrast, gate 2
*does* block 52–144 and 149–165, so which domain is live changes the answer for 149–165.

Consequences worth internalising:

- **Changing the regulatory domain will not open DFS.** Gate 1 is compiled in.
- **2.4 GHz is not uniformly open.** Channels 12–14 are `DISABLED` under US (a 20 MHz channel 12
  spans 2457–2477, past the 2472 rule edge) and `NO_IR` under `00`. Gate 1 allows them, so gate 2
  silently eats them.
- Only **2.4 GHz 1–11 and 5 GHz 36–48** are injectable under *both* domains. That is the only safe
  assumption when the live domain is unknown, and it is what `csa_injectable()` falls back to.

### 6 GHz: do not conflate the two barriers

6 GHz networks also all mandate WPA3/PMF, but that is a **separate** fact and it is *not* what
stops CSA:

| Barrier | Blocks deauth? | Blocks CSA? |
|---|---|---|
| Gate 1: pineapd band-field check | yes | yes — but see below, it may be reachable-around |
| Gate 2: regulatory `NO_IR` | yes | **yes under US — the real regulatory wall** |
| WPA3/PMF mandate | yes | **no** — beacons are not PMF-protected |

So 6 GHz CSA is blocked by *mechanism*, not by WPA3. Do not write it off as doubly-blocked by
crypto; PMF kills deauth there but leaves CSA untouched.

**The hardware does 6 GHz.** Established, correcting an earlier assumption in this file: the only
Wi-Fi blob shipped is `WIFI_RAM_CODE_MT7961_1.bin`, but MT7921AU (USB Filogic 330) loads that same
blob and is a 6E part, and mt76 decides band 4 from a runtime NIC capability query, so the filename
proves nothing either way. Decisively, Hak5 ship a 6 GHz toggle in the Pager's own recon UI —
`lib/pager/themes/wargames/components/recon/recon_band_settings.json` defines menu item `id: "6ghz"`
bound to `$_6Ghz_ENABLED` — and `preflight()` reads `uci get pineapd.wlan1mon.bands`, which is what
that toggle drives. Confirm on hardware with `iw phy1 info | grep -A3 'Band 4'`.

**Settled by the FCC filing.** FCC ID `2A52Y-MK1` (grantee Hak5 LLC), test report
`TZ0278250701FRF08`, certifies the Pager to **transmit** on all four 6 GHz sub-bands — U-NII 5
(5945–6425), 6 (6425–6525), 7 (6525–6875) and 8 (6875–7125 MHz) — 802.11ax, with measured internal
antenna gains of 4.43 dBi and 2.93 dBi, 2T2R. So the PHY exists and the antennas are tuned for
6 GHz; neither is an open question any more. A hypothesis that the device was receive-capable but
never certified to transmit on 6 GHz is **refuted** — recorded here so it is not re-derived.

The gate is therefore not a certification gap. A certified 6 GHz device may transmit as a compliant
AP or client, and an FCC client may transmit only after an enabling signal from an AP it is
associated with; monitor-mode injection is unsolicited transmission with no association. That is
what `NO_IR` encodes, so pineapd's hardcoded refusal and the regdb flag are two independent
encodings of one rule — **the device may talk on 6 GHz, but never first.** **[A]** on the motive,
**[V]** on the certification. Details: `dev/pager-6ghz-determination-plan.md`, Addendum 2.

Both gates are worth probing separately, because neither is as solid as it looks:

- **Gate 1 is a single equality on a struct field**, not a frequency bound:
  `lw v0,28(chan); cmpi v0,8; bteqz <refuse>` — i.e. `chan->+0x1c == 8`, refusing 6 GHz wholesale
  (the "restricted channel" wording is just the log format; there is no subset). That field is
  written to `8` at **exactly one instruction in the whole binary**, inside
  `pineap_wifi_channel::from_string` on the branch taken when the channel string matches `"%uW6e"`.
  The other producers write different encodings: `mac80211::get_channel` hardcodes `0`, and
  `mac80211::find_primary_widest_channel` writes the raw `nl80211_band` index (3 for 6 GHz).
  **INFERRED, not verified on hardware:** a channel not parsed from `"<n>W6e"` text therefore never
  carries `8`, so gate 1's 6 GHz check cannot fire for it — and the DFS switch does not catch it
  either, since every valid 6 GHz 20 MHz channel number is ≡1 mod 4 while the blocked set is
  ≡0 mod 4. `interface_tracker::command_send_deauth` builds its channel via `from_string` on the
  command's string field, so **how CamHound spells the channel may decide whether gate 1 fires.**
  Two incompatible encodings for one field looks like a firmware bug rather than a designed escape.
- **Gate 2 is regdomain-dependent and the regdb is unsigned.** US sets `[NO-OUTDOOR, NO-IR]` on
  5925–7125, but **GB sets only `[NO-OUTDOOR]` on 5925–6425** — no `NO-IR`, which maps to
  `IEEE80211_CHAN_INDOOR_ONLY` and is *not* in the prohibited set. And
  `CONFIG_CFG80211_REQUIRE_SIGNED_REGDB=n` on this build: the `.p7s` filename literal is absent from
  `cfg80211.ko`, there are no PKCS#7/keyring imports, and no `regulatory.db.p7s` exists in the
  rootfs — so a replacement regdb should load unsigned. `mt7921-common.ko` also exposes
  `disable_clc` for MediaTek's firmware-side country clamp.

So the honest reading is: **6 GHz CSA is singly-blocked by regulation in the kernel, and possibly
not blocked at all by pineapd depending on channel encoding.** That makes it worth testing rather
than assuming. It is also where CSA is *least* likely to pay off, since 6 GHz clients are the newest
silicon and therefore the most likely to implement beacon protection (Ext Cap bit 84), which defeats
CSA outright and yields a `NONE` badge.

`csa_injectable()` refuses all 6 GHz until this is settled on hardware — refusing a channel that
would have worked is recoverable, whereas an over-permissive verdict is silently misread as the
target resisting.

### No handshake behind it

WPA3-SAE has no offline-crackable 4-way exchange and no PMKID, so CSA buys nothing for handshake
capture. Its value is disconnect and forced roam, not cracking.

## Detection — assume you are visible

Kismet gained CSA detection in October 2026:

- **issue/PR #666 (merged)** — a CSA-flood alert that fires when one BSSID sends **more than 20
  CSA-bearing beacons within 2 seconds**.
- **#668 / #669 (open)** — signatures specifically targeting tools that copy a captured beacon and
  change only the sequence number, detected by a **reused TSF with a changed sequence number**.

That second signature describes `DEAUTHCSA`'s mechanism (`"Caught beacon for CSA"` = copy a real
beacon). Assume a competent WIDS sees this.

## Re-deriving from scratch, if you do not trust this file

```sh
# 1. current firmware metadata (version, release date, sha256)
curl -s https://downloads.hak5.org/api/devices/wifipineapplepager
# 2. fetch the image
curl -s -L -o pager.bin https://downloads.hak5.org/api/devices/wifipineapplepager/firmwares/latest
# 3. verify sha256 against the API value, then extract
binwalk -e pager.bin      # uImage (LZMA kernel) + squashfs rootfs
# 4. grep the rootfs as shown above
```

1.1.3-stable published SHA-256:
`3073d6b8f91b46eddda20450f9b93f4e3e018e65f5943f4b0941a1fff7f8cd33` (released 2026-10-03). Always
re-check the API rather than trusting that hash — the point of this file is to save the grep, not
to replace verification.

## Sources

- aircrack-ng PR #2724, "Added new CSA-based deauth" — the upstream implementation, **unmerged**,
  and the clearest write-up of the technique: https://github.com/aircrack-ng/aircrack-ng/pull/2724
- Hak5 `DEAUTH_CLIENT` documentation, for the vendor's own (deauth-only) PMF statement:
  https://documentation.hak5.org/wifi-pineapple-pager/wifi-pineapple-commands/deauth_client.md
- Hak5 Pager DuckyScript command reference — note the absence of any CSA command:
  https://documentation.hak5.org/wifi-pineapple-pager/payloads-1/duckyscript-for-the-wifi-pineapple-pager
- Hak5 firmware API: https://downloads.hak5.org/api/devices/wifipineapplepager
- Kismet CSA detection: https://github.com/kismetwireless/kismet/issues/666 ·
  https://github.com/kismetwireless/kismet/issues/668 ·
  https://github.com/kismetwireless/kismet/pull/669
- Beacon protection: Wi-Fi Alliance WPA3 December-2020 update; Vanhoef, *Protecting Wi-Fi Beacons
  from Outsider Forgeries*, WiSec 2020 — https://papers.mathyvanhoef.com/wisec2020.pdf
- MFPC/MFPR and Beacon-Protection bit positions: hostap `src/common/wpa_common.h` and
  `src/ap/ieee802_11_shared.c`; Wireshark `epan/dissectors/packet-ieee80211.c`
- libwifi (the Apache-2.0 library `pineapd` builds frames with):
  https://github.com/libwifi/libwifi
- In-repo working implementation and design notes:
  `library/user/reconnaissance/CamHound/payload.sh` and `dev/CamHound/RESPONSE.md`

## The 6 GHz / DFS determination plan

The operator runbook for settling whether 6 GHz and 5 GHz DFS injection can be unlocked on real
hardware — decision tree, exact commands, rollbacks and early exits — is
`dev/pager-6ghz-determination-plan.md`. Its addendum carries the disassembled pineapd gate.
