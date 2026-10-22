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

**Two things that are inferred, not confirmed** — do not state them as fact:

- Whether `DEAUTHCSA` emits a CSA-bearing **beacon** or a spectrum-management **action frame**. The
  `inject_csa` signature plus `"Caught beacon for CSA"` and `libwifi_create_beacon` strongly imply
  beacon, but nobody has captured it.
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

### Bands: 2.4 GHz and non-DFS 5 GHz only

`ieee80211_monitor_start_xmit()` calls `cfg80211_reg_can_beacon(wiphy, chandef, iftype)`, which
fails on any channel flagged `IEEE80211_CHAN_NO_IR` — "no initiating radiation", meaning you may
not *start* transmitting there on your own initiative, only respond to a legitimate master you have
heard. Injecting on a monitor interface is unsolicited initiation by definition, so it is refused.

**The refusal is silent.** The frame is freed and the function returns `NETDEV_TX_OK` — no errno,
no dropped-frame counter, and `sendto()` reports the full byte count. If you are debugging "the
command ran and nothing happened on the air", this is the first thing to suspect.

The DFS escape hatch does not help: there is a relaxation permitting `NO_IR` channels once a DFS
channel has completed its Channel Availability Check and a legitimate AP is operating, but
`cfg80211_chandef_dfs_required()` returns 0 for `NL80211_IFTYPE_MONITOR` (grouped with
STATION/AP_VLAN/NAN), so a monitor vif can never qualify.

Both excluded ranges use that same mechanism for different reasons:

- **DFS 5 GHz (52–144)** — shared with weather and military radar, so the rule is "listen for radar
  first".
- **All 6 GHz** — 6 GHz has no unconditional transmit mode at all. Every device must fall under
  LPI (low-power indoor, power-capped), SP (standard power, which requires **AFC** — reporting
  geolocation to a coordination service and receiving an authorised channel and power list before
  radiating, because the band is shared with incumbent licensed fixed microwave links), or VLP
  (very low power, portable). A transmitter must be authorised *before* it radiates, which is
  exactly what `NO_IR` encodes.

### 6 GHz: do not conflate the two barriers

6 GHz networks also all mandate WPA3/PMF, but that is a **separate** fact and it is *not* what
stops CSA:

| Barrier | Blocks deauth? | Blocks CSA? |
|---|---|---|
| Regulatory `NO_IR` | yes | **yes — this is the real wall** |
| WPA3/PMF mandate | yes | **no** — beacons are not PMF-protected |

So the Pager's 6 GHz radio is **reconnaissance surface only** because of regulation, not because of
WPA3. If the regulatory block were ever absent — a VLP-authorised path, or a permissive regdomain —
**CSA on 6 GHz would become viable while deauth stayed dead.** Do not write off 6 GHz CSA as
doubly-blocked; it is singly-blocked, by regulation.

Caveat on verification: the per-channel flags live in a binary regdb
(`/lib/firmware/regulatory.db`, `wireless-regdb 2025.02.20` on 1.1.3) and reading them needs
`regdbdump`, which is not on the device. The mechanism above is kernel behaviour and is solid; the
exact flag set depends on regdb version and country code. `radio1` ships `country 'US'` and
`band '5g'`, so 6 GHz operation depends on PineAP's runtime band selection anyway. Hak5's own
`DEAUTH_CLIENT` docs state the 6 GHz injection limit independently, which corroborates this as a
regulatory wall rather than a device limitation.

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
