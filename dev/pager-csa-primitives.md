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

Frame construction is `/usr/lib/libwifi.so.0.0.10` — upstream `github.com/libwifi/libwifi`,
Apache-2.0, whose AUTHORS names Hak5 LLC among others. opkg records it as package `libwifi`
version `main-r1`, source `extra_feeds/hak5/libs/libwifi`; internal version string `0.0.10`.

`pineapd` imports **21** `libwifi_*` symbols, of which exactly **four are builders**
(`libwifi_create_beacon`, `_deauth`, `_disassoc`, `_radiotap`); the rest are parse/free/get/check/
dump. **The library exports 113 `libwifi_*` functions, so 92 ship unreferenced.** **[V]** — three
independent readers (`nm -D`, `objdump -T`, `readelf --use-dynamic -sW`) agree exactly on both
counts.

```sh
# what the library exports / what pineapd imports -- anchor to ^libwifi_ and check the UND column
readelf --use-dynamic -sW usr/lib/libwifi.so.0.0.10 | awk 'NR>3 && $8 ~ /^libwifi_/ && $7!="UND"'
readelf --use-dynamic -sW usr/sbin/pineapd         | awk 'NR>3 && $8 ~ /^libwifi_/ && $7=="UND"'
```

**Anchor the match, or you get 29 instead of 21.** A bare `grep libwifi` on pineapd's dynsym also
catches eight of pineapd's *own* defined C++ methods whose mangled names embed libwifi **struct**
types (`...R11libwifi_bss...`, `libwifi_frame`, `libwifi_sta`, `libwifi_parsed_deauth`). Those are
not libwifi functions.

Among the 92 unused, the ones that matter here:

| Family | Shipped, never called by pineapd |
|---|---|
| Action frames | `libwifi_create_action`, `libwifi_create_action_no_ack`, `libwifi_add_action_detail`, plus free/dump/length |
| Probe responses | `libwifi_create_probe_resp`, **`libwifi_set_probe_resp_channel`**, **`libwifi_set_probe_resp_ssid`**, plus free/dump/length |
| Element editing | `libwifi_add_tag`, `libwifi_create_tag`, `libwifi_remove_tag`, `libwifi_quick_add_tag`, `libwifi_tag_iterator_*` |
| Other | full assoc/reassoc/auth/ATIM/RTS/CTS/timing-advert builders, RSN/WPA cipher enumeration, `libwifi_random_mac` |

The asymmetry is the point: pineapd **parses** probe responses (`libwifi_parse_probe_resp` is
imported) and never builds one, and touches no Action symbol in either direction.

### The tooling here lies, and it lies with exit status 0

`e_shnum = 0` — the file has **no section headers** — so anything that walks the section table finds
nothing. Measured, binutils 2.42, on this exact file. **Every one of these exits 0:**

| Command | Result |
|---|---|
| `nm -D` | **works** — 138 symbols |
| `objdump -T` | **works** |
| `readelf --use-dynamic -sW` (`-DsW`) | **works** |
| `readelf --dyn-syms` | prints **nothing at all**, zero bytes, empty stderr |
| `readelf -s` | prints *"Dynamic symbol information is not available for displaying symbols."* |

Counter-intuitively the BFD tools succeed and readelf fails: BFD reconstructs the table from
`PT_DYNAMIC` automatically, while readelf needs `--use-dynamic` to be told to. Note `-D` pairs with
`-s`, not with `--dyn-syms`. By ablating one dynamic tag at a time, `DT_HASH` is what all three
working readers depend on — remove it and all three report zero; `DT_MIPS_SYMTABNO` is irrelevant.

**An empty symbol list here is a tool artefact, not an absence** — and since the failures are silent
and exit 0, this is exactly how the earlier "there is no action-frame builder" conclusion was
reached. An earlier revision of this document also claimed `nm -D` fails. It does not.

### Reaching the unused builders from a helper

`dlopen("libwifi.so.0", RTLD_NOW)` + `dlsym` **works**: the runtime loader reads only `PT_DYNAMIC`,
section headers are never mapped, `DT_HASH`/`DT_SYMTAB`/`DT_STRTAB` all sit inside the first
`PT_LOAD`, exports are `GLOBAL`/`DEFAULT`/`FUNC` with no `VERDEF` so plain `dlsym` suffices, and the
full symlink chain (`libwifi.so` → `.so.0` → `.so.0.0.10`) ships in `/usr/lib`, which is musl's
default search path. pineapd itself is section-header-less and already binds these 21 symbols from
this file through the same hash machinery.

Three traps:

1. **Linking `-lwifi` against this file fails.** Not "needs section headers" — it is refused:
   `ld` says `file in wrong format`, gold says `may be corrupt`, both exit 1. Isolated by
   experiment: an equivalent MIPS `.so` links fine, and `objcopy --strip-section-headers` on that
   same file reproduces the failure verbatim. BFD's linker path for a shared-object *input* needs a
   real `SHT_DYNSYM`; the `PT_DYNAMIC` synthesis that `nm`/`objdump` use is not wired into it.
   Workarounds, tested: `dlopen`/`dlsym`, or generate a stub `.so` from the export list with
   `-soname libwifi.so.0` and link against that — the binary then records `NEEDED: libwifi.so.0`
   and binds the real library at runtime.
2. **No headers and no static library ship** (`libwifi.list` holds only the three files), so a
   helper must declare its own prototypes **and struct layouts**. Struct/ABI mismatch is the real
   risk here, not symbol visibility. Match upstream libwifi `0.0.10`.
3. **MIPS16: do not mask bit 0 of the address.** `st_value` carries the ISA bit —
   `libwifi_create_action` is `0x3429`. `dlsym` returns the ISA-bit-set address and calling it
   through a function pointer is correct; clearing bit 0 jumps into MIPS32 mode and crashes.

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

## Which CSA carrier actually does what

Five frame types can carry a channel switch, and they are **not** interchangeable. The important
structural point, which earlier revisions of this document got wrong twice: *moving* a client and
*denying it a connection* are two different effects reached through two different code paths, and a
carrier that is useless for one can be the best tool for the other.

Read from the mac80211 this build backports (backports-6.12) —
`ieee80211_sta_process_chanswitch()`, `ieee80211_rx_mgmt_probe_resp()`, `ieee80211_rx_get_bigtk()`,
`ieee80211_scan_rx()`, `ieee80211_mgd_csa_in_process()`. Station mode throughout; mesh differs (see
below). Categories from hostap `ieee802_11_defs.h`: Spectrum Mgmt `0`, Public `4`, Protected Dual
`9`; `WLAN_PA_EXT_CHANNEL_SWITCH_ANNOUNCE` is Public Action value `4`.

| Carrier | PMF covers it? | Against an **associated** client | Against a client **connecting** |
|---|---|---|---|
| **Beacon** + CSA element | No — a beacon is not a robust frame | **Switches channel** (`IEEE80211_CSA_SOURCE_BEACON`) — unless the client holds a BIGTK, which drops the beacon in rx before the element is parsed. | **Denies auth and assoc, beacon protection or not.** See below. |
| **Spectrum Management action** (cat 0) | **Only when PMF is in use** | **Switches channel.** `:7506` assigns `PROT_ACTION` from the *category*, with no check that the frame arrived protected, and the protection filter in `ieee80211_drop_unencrypted_mgmt()` sits inside `if (rx->sta && test_sta_flag(rx->sta, WLAN_STA_MFP))`. So on a **non-PMF** BSS an unprotected, unicast cat-0 CSA moves the client with no MIC and no insider access. With PMF: dropped without keys → insider only. | n/a — needs association |
| **Protected Dual of Public Action** (cat 9) | **Yes**, unconditionally | Insider only — an unprotected cat-9 frame is dropped outright (`RX_DROP_U_UNPROT_DUAL`), no MFP test required. | n/a |
| **Public Action / Extended CSA** (cat 4, action 4) | **No** — Public Action is outside the robust set | **No switch.** Tagged `UNPROT_ACTION`; with the CSA mode byte set it blocks the vif's TX queues, with mode 0 it does nothing at all. **The stall is not self-healing** — see below. | n/a |
| **Probe response** + CSA element | No | **Ignored** — `ieee80211_rx_mgmt_probe_resp()` never reaches the chanswitch path. | **Denies assoc while the client is scanning.** See below. |

The kernel says why eCSA is handled that way, in its own comment:

> *"We don't really trust public action frames, but block queues (go to quiet mode) for them
> anyway, we should get a beacon soon to either know what the CSA really is, or figure out the
> public action frame was actually an attack."*

### The connection-denial path, which beacon protection does not close

A CSA element in a forged beacon reaches the cfg80211 BSS cache **before** any beacon-protection
check, because `__ieee80211_rx_handle_packet()` hands every beacon to `ieee80211_scan_rx()` up front
while `ieee80211_drop_unencrypted_mgmt()` sits at the tail of the per-sdata handler chain,
downstream. For a beacon `ieee80211_scan_rx()` has **no "is a scan running" gate** — it needs only a
broadcast DA, a non-disabled channel, and at least one non-monitor interface up — and it then
replaces `bss->beacon_ies`. `ieee80211_mgd_csa_in_process()` reads those cached IEs and both
`ieee80211_mgd_auth()` and `ieee80211_mgd_assoc()` bail on it: *"AP is in CSA process, reject
auth"* / *"reject assoc"*. **[V]**

So in principle a sustained forged-CSA beacon flood stops a client (re)connecting to a
beacon-protected AP — not a channel move, but a camera that cannot re-associate is off the air just
the same. The real AP's beacons overwrite `beacon_ies` again, so it needs a flood rather than a
single frame, and it bites at connect/roam time, not on an already-associated client.

**pineapd cannot do it, for a reason that has nothing to do with flood rate.** See the next section;
this matters more than anything else on this page if you are planning a CSA attack.

### THE ONE BYTE: pineapd writes Channel Switch Count = 0, which disqualifies the denial path

`recon_engine::index_beacon_ns` catches a genuine beacon for the target BSSID and clones it with a
CSA element appended. The construction is at **`0x4bee8a`** (MIPS16e; `-m mips:16`, first `PT_LOAD`
maps vaddr `0x400000` to file offset `0`):

```
4bee8a:  li   v1,37      ; sb v1,0(v0)    element ID 37 = Channel Switch Announcement
4bee8e:  li   v1,3       ; sb v1,1(v0)    length 3
4bee92:  li   v1,1       ; sb v1,2(v0)    Channel Switch Mode   = 1   (hardcoded)
4bee96:  lbu  v1,52(a0)  ; sb v1,3(v0)    New Channel Number    = runtime field, a0+52
4bee9e:                    sb s1,4(v0)    Channel Switch Count  = 0   (s1 zeroed at 0x4bee6c)
```

So every CSA pineapd emits is `{37, 3, mode=1, new_ch=<runtime>, count=0}`. Only element 37 — no
Extended CSA (60), no Operating Class. **[V]**

Now the receiving side, `ieee80211_mgd_csa_present()` (`mac80211_mlme.c:8349`):

```c
	if (csa && csa->count == 0)
		csa = NULL;
```

A count-0 CSA is thrown away *before* the auth/assoc refusal check, so
`ieee80211_mgd_csa_in_process()` returns false and nothing is refused. **The connection-denial path
cannot be triggered by pineapd's CSA at all.** Not too few frames, not too slow — the frames are
disqualified by their own contents. **[V]** on both sides: the emitted bytes and the kernel check.

Meanwhile count 0 is exactly right for the *channel move*: `process_chanswitch` computes the delay
as `(max_t(int, csa_ie.count, 1) - 1) * beacon_int`, which clamps 0 to a zero delay — switch
immediately. And `mode = 1` sets `blocked_tx`, so an accepting client also stops transmitting, and
on the `drop_connection` path deliberately does not send a deauth. pineapd's CSA is tuned for the
instant kick and is, by construction, invisible to the refusal logic. That is consistent with Hak5
shipping it as "CSA Deauthentication".

**The experiment this implies.** Any non-zero count (1–255) survives `csa_present()`, so a frame
identical but for that byte would get the move *and* the refusal. pineapd hardcodes 0 and there is
no setting for it, so this needs a non-pineapd injector — which is Stage B of
`dev/pager-6ghz-determination-plan.md` anyway, and which also chooses its own send rate (needed to
win the ~100 ms cache race against the real AP) and bypasses gate 1. One tool, three jobs. Patching
pineapd's instruction instead would be global, would slow the working attack by ~200 ms, and is not
a clean one-byte edit: the register holding the zero is reused two instructions earlier to write a
string terminator. Prefer the injector. **[A]** that count≠0 produces the refusal in practice —
derived from the kernel check, not measured.

The probe-response row reaches the same check through `bss->proberesp_ies`, with two differences:
the probe-response branch of `ieee80211_scan_rx()` **does** require an active scan, and the
`proberesp_ecsa_stuck` heuristic (added for CVE-2024-26682, "ECSA elements stuck in probe
responses") can suppress it. That heuristic is narrow: keyed on `WLAN_EID_EXT_CHANSWITCH_ANN` (60)
only, needs two identical copies at least a second apart, needs `mode != 0`, and needs the
announced channel to equal the current one. A plain **CSA element (37)** in a probe response is
never suppressed, nor is an eCSA pointing somewhere else. **[V]**

### The eCSA stall persists; it does not heal

The unblock is inside `ieee80211_sta_process_chanswitch()`, but the beacon handler short-circuits
before reaching it:

```c
	if ((ncrc == link->u.mgd.beacon_crc && link->u.mgd.beacon_crc_valid) || ...)
		goto free;                          /* <-- before process_chanswitch() */
```

and `ncrc` covers the beacon interval/capability plus **only** the elements in `care_about_ies`
(COUNTRY, ERP_INFO, CHANNEL_SWITCH, PWR_CONSTRAINT, HT_CAPABILITY, HT_OPERATION,
EXT_CHANSWITCH_ANN) — TIM, DTIM count and timestamp are excluded. A stable AP's beacon CRC is
therefore constant, so every beacon after the first hits `goto free` and the unblock is never
reached. An unprotected eCSA never sets `csa_active`, so the other two unblock sites
(`chswitch_post_beacon`, `abort_chanswitch`) cannot fire either. The stall holds until the AP's
CRC-relevant elements change or the client disconnects — and the client will not even transmit its
own deauth on teardown while `blocked_tx` is set. **[V]**

The opposite failure mode also exists: `ieee80211_vif_block_queues_csa()` returns immediately if the
driver advertises `IEEE80211_HW_HANDLES_QUIET_CSA`, in which case the unprotected eCSA produces no
observable effect at all. Which drivers set it is **[A]** — not determinable from the local sources.

So "the ceiling is a self-healing TX stall", as an earlier revision put it, was wrong in both
directions: against most drivers it is a *persistent* uplink stall, and against some it is nothing.

### Scoping

The action-frame rows require association and a spoofed BSSID matching the AP: `:7487` takes a
`break` out of the CSA switch unless `u.mgd.associated` and `mgmt->bssid == vif.cfg.ap_addr` (the
frame still reaches userspace; it is not dropped). That gate does **not** apply to the beacon and
probe-response rows, which run through entirely different code — and the probe-response row's real
effect happens precisely when the client is *not* associated.

"A CSA element in a probe response is never acted on" is a **station-mode** statement. In mesh mode
on the same tree it is false: `ieee80211_mesh_rx_bcn_presp()` handles beacons and probe responses
alike and calls `ieee80211_mesh_process_chnswitch()`, which performs a real switch. Gated by
`mesh_matches_local()`, so it is an unsecured-mesh vector. **[V]**

A beacon CSA does not always switch, either. It disconnects instead on a cross-band announcement or
an unusable chandef, is ignored on a same-channel announcement with `mode == 0`, and disconnects on
a parse failure. "Switches channel" is one of several outcomes.

## What defeats it

**Beacon protection.** Added in the Wi-Fi Alliance's WPA3 December-2020 update: a BIGTK plus a
Management MIC element (MMIE, element ID 76) in the beacon. It defeats the beacon **channel-move**
only. It does **not** close the connection-denial path above, because the BSS cache is updated
ahead of the drop.

**Where both AP and client enforce it, forged CSA beacons are dropped** — and both halves are
required, which an earlier revision of this document lost by calling it an "AP-side switch":

- **AP side.** hostapd advertises Ext Cap bit 84 only when `beacon_prot=1` **and** the driver sets
  `WPA_DRIVER_FLAGS_BEACON_PROTECTION`, and it distributes the BIGTK whenever `beacon_prot=1` and
  MFP is negotiated — it does **not** condition that on the client's bit 84. An AP whose driver
  lacks support cannot turn it on at all.
- **Client side.** Enforcement needs the client to actually hold a BIGTK, and that is a driver
  capability: `nl80211` rejects key indices 6–7 with *"BIGTK not supported"* unless the wiphy sets
  `NL80211_EXT_FEATURE_BEACON_PROTECTION`, or `..._BEACON_PROTECTION_CLIENT` for a station. A
  client that cannot install one associates happily and enforces nothing. **[V]**

So **the AP's bit 84 tells you the AP's policy, not whether a given client will drop a forged
beacon.** It is a cheap and worthwhile free read, but it answers half the question; the other half
needs the client.

When the client does enforce, the mechanism is `ieee80211_rx_get_bigtk()` deliberately selecting a
key whenever *either* BIGTK index is installed "so that `ieee80211_drop_unencrypted_mgmt()` can
properly drop both unprotected Beacon frames and Beacon frames that claim to use another BIGTK key
index", and the drop (`RX_DROP_U_UNPROT_BEACON`) precedes CSA parsing. Two conditions on it, both
load-bearing: it sits inside `if (rx->sta && test_sta_flag(rx->sta, WLAN_STA_MFP))`, so **no MFP
means no enforcement**; and the whole function returns early when `RX_FLAG_DECRYPTED` is set, so the
check is skipped for frames the hardware claims to have handled. **[V]**

AP support is **mandatory in Wi-Fi 7**, so the attack decays — and faster than "mandatory" suggests,
because hostapd turns `beacon_prot` on *by itself* when 11be is enabled with PMF ("Enabling beacon
protection as IEEE 802.11be is enabled for this BSS"). A current 6 GHz or Wi-Fi 7 AP will often have
it on with nobody having configured it, so treat it as the default case rather than the exception.

Whether beacon protection is *required* for 6 GHz specifically is **not established** — WPA3 and
PMF are (hostapd's own `hostapd_config_check_bss_6g()` enforces RSN, `ieee80211w` required, no
PSK/FT-PSK, no WEP/TKIP, SAE H2E, and says nothing about `beacon_prot`). The requirement that does
exist was drafted by TGbe for EHT, not for the band. The Wi-Fi Alliance WPA3 specification itself
could not be read — the download redirects into an SSO endpoint — so that leg is unverified rather
than refuted; nothing found points the other way.

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
