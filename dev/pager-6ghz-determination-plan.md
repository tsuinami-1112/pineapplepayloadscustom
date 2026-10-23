# WiFi Pineapple Pager — 6 GHz / DFS Injection Determination Plan

**Operator runbook. Execute top to bottom. Stop at the first early-exit that fires.**

> For the condensed bench ordering — what to do first, and why each step sits where it
> does — see **`dev/pager-day-one.md`**. This document holds the reasoning, exact commands,
> rollbacks and early exits behind it.

Target question: *can 6 GHz injection be unlocked on this device, yes or no, and if yes how?*

Firmware under analysis: **1.1.3-stable**, `pineapd` sha256 `adc9d36d…8493`, `regulatory.db` sha256 `30954f89…4b44`, `_pineap` sha256 `e1739d97…7d69`.

---

## Reading this document

| Tag | Meaning |
|---|---|
| **[V]** | Verified by direct inspection of the shipped binaries / the exact kernel + driver source the device was built from |
| **[A]** | Assumed or inferred — stated with its basis, not proven |
| **[RO]** | Read-only step, no device state changed |
| **[INV]** | Invasive, with risk level and tested rollback |

**Two global rules.**

1. **Restore a shipped file with `cp /rom/<path> <path>`, never `rm`.** The rootfs is squashfs + overlayfs; `rm` through the merged mount writes a whiteout that *hides* the original instead of revealing it, and leaves you with no file at all. **[V]** Never touch `/overlay/upper` on a mounted overlay.
2. **Never write the `all` mtd partition.** It is offset 0, size 0 (whole chip), and is *not* marked read-only — writing it destroys u-boot and the per-unit `factory` calibration/MAC partition. Recovery would need an external SPI programmer and case disassembly. **[V]** There is exactly one device and no spare.

---

# Step 0 — Prerequisites (before the device arrives)

## 0.1 Acquire hardware — THIS HAS LEAD TIME, ORDER NOW

| Item | Why | Constraint |
|---|---|---|
| **6E-capable monitor receiver** — mt7921au based: ALFA AWUS036AXML, Netgear A8000 (`0846:9060`), or TP-Link TXE50UH (`35bc:0107`) | No on-device signal can distinguish "firmware dropped it" from "it left the antenna". Without an independent receiver, every result on a band is uninterpretable. **[V]** | **Do NOT use Intel AX210/AX211.** iwlwifi is self-managed regulatory and partly learns its country from received beacons; a shielded chamber has none, so it may never expose 6 GHz. **[A]** — vendor/community reports, not tested. Avoid Netgear A7500 (`0846:9065`), which is the dual-band AX1800 part. |
| **6 GHz-capable AP** for inside the chamber | Needed as a beacon source for RX proof, and **mandatory** as a CSA target (see 0.3). | Must be able to beacon on 6 GHz on a channel you choose. |
| **5 GHz AP that can sit on a DFS channel** (ch 52 or 100) | The DFS branch is the real deliverable (§5). | — |
| USB-C data cable (not charge-only) | Sole control channel. | — |
| Attenuators or fixed ≥1 m geometry in the chamber | At centimetre range "nothing captured" can be receiver front-end overload, not a gate. | — |

**Plan B if the 6E parts do not arrive:** run the **5 GHz DFS branch (§5) to completion** — it needs no 6E hardware at all — and defer 6 GHz. Do not run the 6 GHz branch blind.

## 0.2 Desk work — resolves part of D1 before the box is opened

The six research lenses all declared "does the MT7961 have a 6 GHz PHY" unresolvable offline. That is true of the *driver* path, but not of the *regulatory filing*.

- Look up the Pager's **FCC ID** (on the device label / in the FCC OET database). The **grant** lists the exact frequency bands the product was certified to transmit on. No UNII-5/6/7/8 (5925–7125 MHz) entry ⇒ the product was never certified for 6 GHz TX, which strongly predicts the cheaper dual-band module SKU *and* that the antennas and front-end filters were never tuned for 6 GHz.
- The **internal photos** (also public) show the module part number and antenna count.
- Status: **not done — the Pager's FCC ID does not appear in Hak5's published documentation, so it must be read off the device label or found by brand search.** **[V]** (grepped `hak5/llms-full.txt`: the string "FCC" appears but no ID).

This is free, available before arrival, and is the only pre-arrival evidence about the **antenna path** — which no amount of software inspection can reach.

## 0.3 THE VALUE GATE — read this before spending any effort on 6 GHz

**Run this now, on the extracted rootfs. It costs one command and it may end the project.**

```sh
strings -a fw/rootfs/usr/sbin/pineapd | grep -o 'libwifi_create[a-z_0-9]*' | sort -u
```

Result **[V]**:

```
libwifi_create_beacon
libwifi_create_deauth
libwifi_create_disassoc
libwifi_create_radiotap
```

That is pineapd's entire frame-construction repertoire. Combined with the symbol `csa_beacon_record` and the strings `beacon-csa` / `probe-csa`, pineapd's CSA is delivered in a **spoofed beacon or probe response**, not an action frame. **[V]**

**Correction (2026-10-23).** This said "there is no action-frame builder", which is true of *pineapd* and false of *the device*. pineapd imports 21 `libwifi_*` symbols of which four are builders; `/usr/lib/libwifi.so.0.0.10` exports **113**, including `libwifi_create_action`, `_action_no_ack`, `_add_action_detail`, `_create_probe_resp` and the `libwifi_*_tag` element API — 92 ship unreferenced. Read them with `nm -D`, `objdump -T` or `readelf --use-dynamic -sW`; the `.so` has no section headers, so `readelf -s` says "Dynamic symbol information is not available" and `readelf --dyn-syms` prints nothing, both exiting 0. **[V]** (An earlier version of this note also claimed `nm -D` fails. It does not — see `dev/pager-csa-primitives.md`.)

**Second correction.** "pineapd cannot emit an action frame because it imports no action builder" does **not** follow, and should not be relied on: pineapd imports `pcap_inject` and its own `inject`/`inject_queue` methods take an arbitrary caller-supplied byte buffer, and it demonstrably composes 802.11 element bytes by hand already — it emits a CSA element while importing neither `libwifi_add_tag` nor `libwifi_create_tag`. The beacon conclusion still stands on `csa_beacon_record`, `recon_engine::inject_csa` and the string `"Caught beacon for CSA on {}"`; the import list is not what establishes it. **[A]** on the carrier, not **[V]**.

### What this means for 6 GHz

| Attack | Viability on 6 GHz | Basis |
|---|---|---|
| **Deauth / disassoc** | **Dead by standard.** All 6 GHz BSSs must use WPA3 (OWE even for "open"), so PMF is mandatory and these frames are rejected by any compliant client. | **[V]** — Hak5's *own* documentation states this: *"all networks on 6GHz require WPA3 protections (even 'open' networks on 6GHz require WPA3-OWE); WPA3 includes Protected Management Frames or PMF, which prevents injected disconnection packets."* |
| **Beacon-borne CSA — moving an associated client** | **Works unless both the AP *and* the client enforce beacon protection.** mac80211 drops MME-less beacons once the client holds a BIGTK, before the CSA element is parsed. Both halves are needed: the AP must set `beacon_prot` (and its driver must support it), and the client's driver must be able to install a BIGTK at all (`nl80211` refuses key idx 6–7 without `NL80211_EXT_FEATURE_BEACON_PROTECTION[_CLIENT]`). The AP's Ext Cap bit 84 is its *policy*, not the client's behaviour. | **[V]** for mac80211 (`ieee80211_rx_get_bigtk`, `ieee80211_drop_unencrypted_mgmt`, `nl80211.c` key-idx gate). Note enforcement also requires MFP and is skipped when `RX_FLAG_DECRYPTED` is set. |
| **Beacon-borne CSA — denying a connection** | **The path exists and pineapd cannot reach it.** `ieee80211_scan_rx()` updates `bss->beacon_ies` before the handler chain's drop, and `ieee80211_mgd_csa_in_process()` then makes auth and assoc bail — but `ieee80211_mgd_csa_present()` discards any CSA whose Channel Switch Count is 0, and pineapd hardcodes 0 (`0x4bee8a`). With an injector of our own at `count != 0` this becomes the one effect that survives beacon protection. | **[V]** both sides (emitted bytes + `mac80211_mlme.c:8349`). Needs a flood and bites at connect/roam time. See `pager-csa-primitives.md` §"THE ONE BYTE" and day-one step 17a. |
| **Probe-response CSA** (`probe-csa`) | **Moves nothing** — `ieee80211_rx_mgmt_probe_resp()` never reaches `ieee80211_sta_process_chanswitch()`. But it **denies association while the client is scanning**, through `bss->proberesp_ies` and the same `csa_in_process` check. The `proberesp_ecsa_stuck` heuristic (CVE-2024-26682) suppresses only eCSA (60), two identical copies ≥1 s apart, `mode != 0`, announcing the *current* channel — a plain CSA element (37) is never suppressed. | **[V]** for mac80211 **station mode** — in mesh mode a probe-response CSA does switch. This row previously read "the one plausible survivor", then "it does nothing"; both were wrong. |
| **Public Action / Extended CSA** (cat 4, action 4) | **The only CSA-family frame that gets past PMF *and* beacon protection from outside** — Public Action is outside the robust set. It does not switch the client: with the CSA mode byte set it blocks the vif's TX queues (mode 0 does nothing). **The stall persists** — the unblock lives inside `process_chanswitch`, which the beacon handler's CRC short-circuit normally prevents reaching, so it holds until the AP's CRC-relevant IEs change or the client disconnects, and the client will not even send its own deauth meanwhile. Needs a non-pineapd injector; the on-device `libwifi` exports the builder. | **[V]** for current mac80211 (`IEEE80211_CSA_SOURCE_UNPROT_ACTION`, `care_about_ies`, `goto free` at the CRC check). **[A]** that an older or non-Linux client may switch instead — the `CSA_SOURCE` split arrived with the 2024 MLO rework. Also a no-op entirely on a driver advertising `IEEE80211_HW_HANDLES_QUIET_CSA`. An earlier version of this row called it "self-healing"; that was wrong in both directions. |
| **Spectrum Management CSA action** (cat 0) | Irrelevant *on 6 GHz* — PMF is mandatory there, so it needs keys. Recorded because it is **not** insider-only off 6 GHz: `:7506` tags it `PROT_ACTION` from the category with no check that the frame arrived protected, and the protection filter only runs under MFP. On a non-PMF 2.4/5 GHz BSS an unprotected unicast cat-0 CSA moves the client, no MIC needed — better targeting than a beacon. | **[V]** for mac80211 (`mac80211_mlme.c:7487-7516`, `rx612.c:2454-2510`). |

### Early exit E0

> **If the required deliverable is client disconnection (deauth/disassoc), the answer to the operator's question is: "yes, the gates can be lifted, and it will not work." Stop the 6 GHz branch here and go to §5 (5 GHz DFS).**
>
> Proceed into 6 GHz only if the deliverable is **CSA**. The ceiling depends on which effect you need, and it is better than an earlier revision of this plan claimed: a *channel move* needs an AP (or client) without beacon protection, but **connection denial survives beacon protection** via the BSS-cache path, using the beacon pineapd already builds. If the goal is "the camera stops working" rather than "the camera changes channel", the gate is much weaker than it looks.
>
> **Half the gate is answerable from one beacon capture.** Capture a beacon from the target AP and read two things: an MMIE (element 76) present in the beacon, and Extended Capabilities bit 84 (`wlan.extcap.b84`, octet 10 zero-based, mask `0x10`). Both set → that AP enables beacon protection. Neither → it does not, and beacon-CSA moves clients.
>
> **It does not answer the other half.** Enforcement needs the *client* to hold a BIGTK, which its driver must support, so a bit-84 AP can still be associated by clients that enforce nothing. The real 6 GHz client is required, not optional — it is the only way to learn whether a forged beacon is actually dropped. Expect bit 84 to be set more often than not: hostapd enables `beacon_prot` by itself whenever 11be is on with PMF.

This is why Hak5 shipped "CSA Deauthentication" in 1.1.1 *while leaving the 6 GHz injection gate in place*. **[V]** — the gate strings are byte-identical in 1.1.3, the newest firmware.

## 0.4 Recovery image + printed procedures

```sh
mkdir -p ~/pager-baseline && cd ~/pager-baseline
curl -L -o pineapplepager-firmware-1.1.3-signed.bin \
  https://downloads.hak5.org/api/devices/wifipineapplepager/firmwares/latest
sha256sum pineapplepager-firmware-1.1.3-signed.bin
curl -s https://downloads.hak5.org/api/devices/wifipineapplepager/firmwares | head -c 400
curl -sL https://documentation.hak5.org/wifi-pineapple-pager/firmware-recovery.md -o firmware-recovery.md
curl -sL https://documentation.hak5.org/wifi-pineapple-pager/factory-reset.md  -o factory-reset.md
```

**PASS:** sha256 = `3073d6b8f91b46eddda20450f9b93f4e3e018e65f5943f4b0941a1fff7f8cd33`, size `33884001`. **[V]**

**Do not proceed to any invasive step without a verified recovery image.** Without it, every later worst case escalates from "15-minute reflash" to "RMA".

Recovery ladder, lowest tier last:

| Tier | Action | Scope |
|---|---|---|
| 1 | `cp /rom/<path> <path>` | one file |
| 2 | `/etc/init.d/pineapplepager stop` (also deletes the procd service so it cannot respawn) | service |
| 3 | GPIO radio power cycle (§A1 note) | radio1 only |
| 4 | `jffs2reset -y && reboot` | whole overlay; **keeps** eMMC loot/payloads |
| 5 | `prepare-upgrade <signed.bin> && sysupgrade /tmp/firmware.bin` | boot flash, over SSH |
| 6 | USB web recovery at `http://172.16.52.1` (hold **A**/green, power 3 s, release, connect USB-C) — plain HTTP, ~15 min, **boot flash only, eMMC intact** | boot flash |
| 7 | Factory reset (hold **B**/left-red through power-on ~30 s, **A** commits) — `jffs2reset` **plus a full zero-fill of the eMMC** | everything |

**[V]** on all tiers from the init scripts and vendor docs. **[A]** on the A/B physical mapping: the DTS node names are the inverse of the case silkscreen, so **read the on-screen prompt; do not trust a remembered combination.** The factory-reset screen is reached by one button press and cancelled by one button press — there is no second confirmation and no timeout, so be certain which button cancels *before* entering it.

**Charge first.** Vendor instruction: do not flash until the battery shows solid red (charging) or solid green (charged). Make this a hard precondition on every reboot-bearing and flash-class step. **[V]**

---

# Phase 0 — Mandatory backup gate

**No step tagged [INV] anywhere in this document may run until P0.1–P0.4 have passed.**

### P0.1 [RO] First boot and SSH

Complete the on-screen wizard (PIN, root password, timezone). First boot takes 3–4 min, or 10–15 min if freshly flashed — **do not interrupt it**; it partitions the eMMC and generates SSH keys. **[V]**

```sh
ip -brief addr | grep -i 172.16.52
ping -c3 172.16.52.1
ssh root@172.16.52.1 'echo ok; uname -a; cat /etc/openwrt_release'
```

**PASS:** laptop gets a `172.16.52.x` address, ssh prints `ok` and `6.6.86`.
**FAIL:** `169.254.x.x` → refresh the interface. No RTL8153 NIC → charge-only cable. Password refused → wizard not finished.
If `172.16.52.0/24` collides with a local Docker/VPN subnet, fix it on the laptop **now**, not mid-recovery.

### P0.2 [RO] Firmware identity gate

```sh
ssh root@172.16.52.1 'sha256sum /usr/sbin/pineapd /usr/bin/_pineap /lib/firmware/regulatory.db /pineapple/pineapple'
```

**PASS:** `pineapd` = `adc9d36d…8493`, `_pineap` = `e1739d97…7d69`, `regulatory.db` = `30954f89…4b44`.

**FAIL — any mismatch ⇒ STOP.** Every byte offset in this plan and every prebuilt artifact (patched binary, regdb variants) was computed against those exact files. Re-derive before using any of them: `pineapd_gate.py check` prints per-site bytes and will refuse a file it does not recognise. **[V]**

### P0.3 [RO] Baseline state, off-device

```sh
cd ~/pager-baseline
ssh root@172.16.52.1 'cat /proc/mtd; echo ---; cat /proc/mounts; echo ---; cat /proc/cmdline;
  echo ---; lsmod; echo ---; iw reg get; echo ---; iw dev; echo ---; uci export;
  echo ---; ubus call system board; echo ---; opkg list-installed; echo ---; df -h;
  echo ---; ls -la /sys/class/gpio/; echo ---; dmesg' > baseline-state.txt 2>&1
ssh root@172.16.52.1 'for p in /sys/class/ieee80211/*; do n=$(basename $p); echo "== $n";
  iw phy $n info; iw phy $n channels; done' > baseline-phy.txt 2>&1
ssh root@172.16.52.1 'sha256sum /lib/firmware/regulatory.db /usr/sbin/pineapd /usr/sbin/iw \
  /usr/bin/hak5cmd /lib/modules/6.6.86/*.ko' > baseline-hashes.txt
ssh root@172.16.52.1 'cp /etc/config/pineapd /etc/config/pineapd.stock; cp /etc/config/wireless /etc/config/wireless.stock'
```

**PASS:** `/proc/mtd` lists labels `u-boot`, `u-boot-env`, `factory`, `firmware`, `all` plus split `kernel`/`rootfs`/`rootfs_data`; `/proc/mounts` shows squashfs on `/rom` and jffs2/overlay on `/overlay`.

**Record the label→mtdN mapping and use it verbatim later. Never guess an index** — the DTS order suggests `u-boot`=mtd0 … `all`=mtd4, but mtdsplit appends dynamic partitions and shifts the tail. **[V]**

### P0.4 [RO] Irreplaceable flash dumps — streamed off-device

```sh
cd ~/pager-baseline
# substitute the REAL indices from P0.3
ssh root@172.16.52.1 'dd if=/dev/mtd2 bs=65536' > pager-factory.bin     # label "factory"
ssh root@172.16.52.1 'dd if=/dev/mtd1 bs=65536' > pager-uboot-env.bin
ssh root@172.16.52.1 'dd if=/dev/mtd0 bs=65536' > pager-uboot.bin
ssh root@172.16.52.1 'dd if=/dev/mtd4 bs=65536' > pager-flash-all.bin    # read-only use ONLY
sha256sum pager-*.bin | tee pager-backup.sha256
```

**PASS:** `pager-factory.bin` exactly 65536 bytes, `pager-uboot.bin` 196608 bytes, and the first 1024 bytes of `pager-factory.bin` are **not** uniform 0xFF/0x00 (that is real per-unit calibration data).

**Why this is the gate:** the `factory` partition holds the radio0 calibration EEPROM and the device MAC. **It cannot be reconstructed from the Hak5 download — it is per-unit.** **[V]**

> **Honesty note:** for `u-boot` and `factory`, "backed up" means **archived, not recoverable**. Restoring them needs an external SPI programmer and case disassembly (which voids warranty). Having the dump does **not** make an `all`-partition write survivable.

### P0.5 [RO] Prove the restore path, and build the one-shot restore script

```sh
ssh root@172.16.52.1 'mount | grep -E " / | /rom | /overlay "
  ls -la /rom/lib/firmware/regulatory.db /rom/usr/sbin/pineapd
  sha256sum /rom/lib/firmware/regulatory.db /lib/firmware/regulatory.db \
            /rom/usr/sbin/pineapd /usr/sbin/pineapd
  df -h /overlay'
```

**PASS:** `/rom` is squashfs ro; `/rom` and live hashes match each other (nothing modified yet); `/overlay` has ample free space.

Write `~/pager-baseline/restore-stock.sh` and **run it once now, while the device is unmodified, to prove it is a no-op**:

```sh
#!/bin/sh
# restore-stock.sh — run against a Pager at 172.16.52.1
ssh root@172.16.52.1 '
  /etc/init.d/pineapplepager stop
  ubus call service delete "{\"name\":\"pineapd\"}" 2>/dev/null
  cp /rom/usr/sbin/pineapd /usr/sbin/pineapd; chmod 755 /usr/sbin/pineapd
  cp /rom/lib/firmware/regulatory.db /lib/firmware/regulatory.db
  cp /etc/config/pineapd.stock  /etc/config/pineapd
  cp /etc/config/wireless.stock /etc/config/wireless
  sed -i "/disable_clc/d" /etc/modules.conf
  uci commit
  iw reg set US
  sync
  sha256sum /usr/sbin/pineapd /lib/firmware/regulatory.db
'
```

Expected hashes afterwards: `adc9d36d…8493` and `30954f89…4b44`.

**Also keep an append-only mutation ledger** (`~/pager-baseline/ledger.txt`): one line per change, with its rollback command, written *as you make it*. Without it a mid-session anomaly cannot be attributed.

---

# Stage A — Zero-risk determination

Everything learnable without modifying the device, most decisive first.

## A0 [RO] Use the vendor's own 6 GHz toggle and just look

Before touching `uci`, `opkg`, or any binary. The vendor ships a 6 GHz toggle in **Recon settings** and in **Settings → Network → 6GHz**, and the docs say 6 GHz is merely "off by default". **[V]**

**Action:** turn it on in the UI. Then observe:

```sh
ssh root@172.16.52.1 'uci get pineapd.wlan1mon.bands; cat /proc/$(pgrep -n pineapd)/cmdline | tr "\0" " "; echo'
```

| Outcome | Interpretation | Branch |
|---|---|---|
| `bands` becomes `2,5,6` and argv carries `--band wlan1mon:2,5,6` | The vendor UI already performs the only configuration change this plan needs. Skip B1 entirely. | → A1 |
| Nothing changes | The toggle drives a different path (display/scan only). | → A1, and B1 becomes necessary |

Zero risk, zero cost, on a device straight out of the box. Shipped default is `bands '2,5'` while the init script's own default is `'2,5,6'`. **[V]**

## A1 [RO] Inventory, and map wlan1mon to its phy

```sh
ssh root@172.16.52.1 '
uname -a; lsusb
lsmod | grep -E "mt79|mt76"
iw dev
for n in /sys/class/net/wlan*; do i=$(basename $n);
  p=$(basename $(readlink -f $n/phy80211) 2>/dev/null); echo "$i -> $p"; done
basename $(readlink -f /sys/class/net/wlan1mon/phy80211) > /tmp/phy1name; cat /tmp/phy1name
readlink -f /sys/class/ieee80211/*/device
cat /sys/module/mt7921_common/parameters/disable_clc
ls -ld /sys/class/ieee80211/$(cat /tmp/phy1name)/device/of_node 2>&1
mount | grep -w debugfs
ls /sys/kernel/debug/ieee80211/$(cat /tmp/phy1name)/mt76/ 2>/dev/null
'
```

**PASS:** two phys; `wlan1mon` maps to one (expected `phy1`); `lsusb` shows a MediaTek device; device path ends `1-1.2:1.3`; `of_node` reports **No such file** (confirms the device-tree `power-limits` gate is inert — USB devices have no of_node) **[V]**; `xmit-queues` exists under `.../mt76/`.

**FAIL:** `wlan1mon` absent or no `phy80211` symlink → the radio did not probe; go to `dmesg` before anything else. `of_node` **exists** → a second hard clamp is live and must be investigated before any transmit result is trusted (clearing it means a DTB edit, which is a flash write and the only genuinely brick-capable operation in this problem space — it is deliberately **not** in this plan).

**VID:PID note:** `0e8d:7961` is the generic MediaTek ID used by **both** 6E and dual-band-only mt7921au modules, so it decides nothing. `0846:9060`/`35bc:0107` are *Netgear/TP-Link retail* IDs — an embedded Hak5 module presenting one would be surprising. **A USB ID is a product identity, not an RF capability. Do not branch on it; fall through to A2.** **[V]**

**CLC is dead here — do not test it.** `mt7921_load_clc()` returns before parsing anything on *any* USB device, and in the shipped `mt7921-common.ko` the `disable_clc` test (0x2f50) and the `MT76_BUS_USB` test (0x2f64) **branch to the same address, 0x3034**. `disable_clc=1` is provably a no-op on radio1. The single `cat` above is for the record only. **[V]**

## A2 [RO] ★ THE DECISIVE D1 TEST — one command

```sh
ssh root@172.16.52.1 'PHY=$(cat /tmp/phy1name); echo "phy=$PHY"
  iw phy "$PHY" info | grep -E "^[[:space:]]+Band [0-9]+:"'
```

**PASS:** three lines — `Band 1:` (2.4), `Band 2:` (5), **`Band 4:` (6 GHz)**. `iw` prints `nla_type + 1` and `NL80211_BAND_6GHZ == 3`. ⇒ `phy->cap.has_6ghz == 1`.

**FAIL:** only `Band 1:` and `Band 2:`. ⇒ the MT7961 firmware's `MT_NIC_CAP_6G` TLV reported 0.

**Why this is regdomain-independent — and why the obvious test is a trap.** `mt76_check_sband()` (the only thing that can NULL out `wiphy->bands[]`) runs at `mac80211.c:767-769`, and `ieee80211_register_hw()` — inside which cfg80211 applies the regulatory domain — runs at `:777`, strictly afterwards. The `CHAN6G` macro sets no default flags, so at check time every channel has `flags == 0` and the band can never be culled. **Band-4 presence is the hardware read; per-channel flags are the regdomain read. Never confuse them.** **[V]**

> This corrects a contradiction in the research: one lens claimed "country choice matters for whether Band 4 even appears." **That is wrong**, by the ordering above. Do not re-run A2 under different countries hoping Band 4 appears.

### Early exit E1

> **No `Band 4` ⇒ the answer is NO, hard stop for 6 GHz.** `mt76_init_sband_6g()` is the *only* code path that can assign `wiphy->bands[NL80211_BAND_6GHZ]`, and it is gated solely on `phy->cap.has_6ghz`. **No regulatory.db edit, module parameter, UCI setting, or pineapd patch can synthesise a 6 GHz band on a radio whose firmware reports 0.** **[V]**
>
> Record it, treat the vendor's "tri-band" wording as covering the product rather than this radio, and **go to §5 (5 GHz DFS)**, which is unaffected.

## A3 [RO] Separate the regulatory answer from the hardware answer

```sh
ssh root@172.16.52.1 'PHY=$(cat /tmp/phy1name)
iw reg get
iw phy "$PHY" channels > /tmp/chan.US.before
awk "/^Band 4:/{f=1} f&&/^Band [0-9]+:/&&!/Band 4:/{f=0} f" /tmp/chan.US.before > /tmp/b4.US
echo "6GHz total: $(grep -c "MHz \[" /tmp/b4.US)"
echo "6GHz disabled: $(grep -c "(disabled)" /tmp/b4.US)"
echo "6GHz No IR: $(grep -c "No IR" /tmp/b4.US)"
cat /tmp/b4.US | head -20'
```

**PASS (expected under US):** `total=59`, `disabled=0`, `No IR=59`. `iw reg get` shows `country US: DFS-FCC` and **no** `phy#N (self-managed)` block.

**FAIL:** all 59 print `(disabled)` and No-IR is 0 → the active domain has no 6 GHz rule at all, almost certainly world domain `00`, whose shipped rules jump from 5735–5835 MHz straight to 57240 MHz. Fix the domain first (B2) before concluding anything.

Absence of a `(self-managed)` block empirically confirms regdb edits govern this radio: `REGULATORY_WIPHY_SELF_MANAGED` appears nowhere in mt76; mt7921 installs only `hw->wiphy->reg_notifier` (`mt7921_init.c:325`). **[V]**

Also record the **5 GHz** block now — you need it for §5 and for the A4 oracle:

```sh
ssh root@172.16.52.1 'awk "/^Band 2:/{f=1} f&&/^Band [0-9]+:/&&!/Band 2:/{f=0} f" /tmp/chan.US.before' > chan5g.US
```

**Expected [V]:** `5180`/`5745` have neither `No IR` nor `(disabled)`; `5260`/`5500`/`5660` show `Radar detection` and a DFS state but **NOT** `No IR`. **28** 5 GHz channels total (mt76 registers 28, not 25 — the research oracle's denominator was wrong; its 6 GHz denominator of 59 is correct). **[V]**

## A4 [RO] The monitor-TX predicate, and the country oracle

**This is now verified against the exact device vintage (v6.12.61), correcting a research error.**

The research derived the predicate from a `tx.c` that calls `cfg80211_reg_can_beacon` — a symbol that appears **zero** times in the shipped `cfg80211.ko`, which exports only `cfg80211_reg_check_beaconing`. That looked like it invalidated the predicate. It does not. The chain resolves cleanly:

1. v6.12.61 `ieee80211_monitor_start_xmit` calls `cfg80211_reg_can_beacon(wiphy, chandef, sdata->vif.type)`.
2. That is a **static inline wrapper** in `include/net/cfg80211.h:9028` which builds `struct cfg80211_beaconing_check_config config = { .iftype = iftype };` — so **`.relax = false` and `.reg_power = 0`**, hardcoded — and calls `cfg80211_reg_check_beaconing()`. Hence the real export, and hence no `cfg80211_reg_can_beacon` symbol.
3. In `cfg80211_reg_check_beaconing`, `cfg->relax` is false ⇒ `check_no_ir` stays true; `cfg->reg_power != IEEE80211_REG_VLP_AP` ⇒ `permitting_flags` stays 0. So neither the IR-relaxation path nor the 6 GHz VLP-AP override can fire.
4. `_cfg80211_reg_can_beacon(..., IEEE80211_CHAN_NO_IR, 0)`: for `NL80211_IFTYPE_MONITOR`, `cfg80211_chandef_dfs_required()` returns **0** ⇒ `check_radar = false` ⇒ `IEEE80211_CHAN_RADAR` is **never tested**; and because `dfs_required > 0` is false, the NO_IR relaxation does not apply either.

**Verified predicate for monitor injection: `!IEEE80211_CHAN_DISABLED && !IEEE80211_CHAN_NO_IR`.** **[V]**

Two consequences, both load-bearing:

- **cfg80211 does NOT block 5 GHz DFS monitor injection on this device.** US regdb sets `DFS` but not `NO-IR` on 5250–5350 and 5470–5730, and RADAR is not tested for MONITOR. **The only thing blocking DFS injection is pineapd's own hardcoded bitmask.** → §5
- **cfg80211 DOES block 6 GHz**, because US sets `NO-IR` on 5925–7125.

### Country oracle — from the shipped database

Verified directly out of the shipped `regulatory.db` **[V]**:

| CC | dfs_region | 6 GHz rule | 6 GHz injectable |
|---|---|---|---|
| **US** | FCC | 5925–7125 @ 12 dBm **[NO-OUTDOOR, NO-IR]** | **0 / 59** |
| **AR** | **FCC** | 5925–7125 @ 12 dBm [NO-OUTDOOR] | **59 / 59** |
| **CO** | FCC | 5925–7125 @ 12 dBm [NO-OUTDOOR] | 59 / 59 |
| **PE** | FCC | 5925–7125 @ 12 dBm [NO-OUTDOOR] | 59 / 59 |
| **CR** | FCC | 5925–7125 @ **30 dBm** [NO-OUTDOOR] | 59 / 59 |
| **CA** | FCC | 5925–7125 @ 12 dBm [NO-OUTDOOR] | 59 / 59 (loses 3 × 5 GHz) |
| **GB** | ETSI | 5925–**6425** @ 24 dBm [NO-OUTDOOR] | **24 / 59 — DO NOT USE** |

> **Use AR (or CR for 30 dBm). Do NOT use GB.** GB's single rule stops at 6425 MHz, so UNII-6/7/8 become `IEEE80211_CHAN_DISABLED` — and DISABLED is prohibited on the monitor TX path unconditionally, in every kernel version. Three of the six research lenses recommended GB; they were wrong, and the GB pass criterion ("5955 no longer shows No IR") is satisfied even while two thirds of the band is hard-disabled. **[V]**
>
> **AR's dfs_region is FCC, not ETSI.** A research lens stated `country AR: DFS-ETSI` as the pass criterion; scoring that literally would record FAIL on a successful test and escalate to an unnecessary invasive step. **Score on the no-IR and disabled counts, never on the dfs_region string.** **[V]**

**Oracle caveat [A]:** the per-country counts above come from an offline reimplementation of `handle_channel`/`map_regdom_flags`. It is a *model of the kernel, not the kernel*, and its 5 GHz channel set (25) does not match the device's (28). The 6 GHz column is what matters here and its denominator is right, but treat it as **prediction** — B2 checks it against the real device before anything is built or written.

**AR 5 GHz deltas vs US, so the B2 diff is not read as an anomaly [V]:** AR is 5170–5250 @ 17 dBm (US: 5150–5250 @ 23), 5250–5330 (US: –5350), 5490–5730 (US: 5470–), 5735–5835 (US: 5730–5850). **All DFS channels 52–64 and 100–144 survive under AR.** Lost: ch 32 (5160) and the 5845+ edge. Expect many 5 GHz `Maximum TX power` lines in the diff — score 5 GHz separately.

## A5 [RO] Confirm the gate ladder and the log channel, against the stock binary

There are **three** userspace gates in series plus the kernel, not two. **[V]**

| # | Gate | Where | Observable | Bypass |
|---|---|---|---|---|
| a0 | **Band mask** | `uci pineapd.wlan1mon.bands='2,5'` | **silence** — 6 GHz never enters the hop list, no refusal logged | `uci` (B1), or the vendor UI (A0) |
| a1 | **Go UI refusal** | `/pineapple/pineapple`: *"Cannot deauth clients on DFS or 6GHz channels"* | UI error | **free** — drive pineapd's socket with `/usr/bin/_pineap` |
| a2 | **pineapd hardcoded** | `chan_type==8` (6 GHz) **and** a separate DFS channel-number bitmask, each at **two** sites | `[!] … can not inject on {6GHz,DFS} restricted channel` | 16-byte patch (C1) or avoid pineapd (B3) |
| b | **cfg80211 NO_IR** | `ieee80211_monitor_start_xmit` | **silent** — frame freed, `NETDEV_TX_OK` returned | regdomain (B2) |
| c | **firmware / MCU** | `SET_CHAN_DOMAIN` | silent | unknown — not resolvable offline |

> **F6 in the brief described one gate; there are two *conditions* inside pineapd, each at two sites.** The `"6GHz restricted"` string in `pineap_wifi_interface::inject` is printed by **both**, which is what made it look like a single 6 GHz gate. The DFS test there is mislabelled. **[V]**
>
> **The 6 GHz and DFS conditions are independent.** `frequency_to_channel` maps 6 GHz as `(freq-5950)/5`, so 6 GHz channel numbers are all ≡1 mod 4, while the DFS bitmask covers only numbers ≡0 mod 4. The DFS mask can never block a 6 GHz channel. They can be lifted separately. **[V]**

Confirm the log channel and capture the stock refusal text:

```sh
# terminal 1
ssh root@172.16.52.1 'logread -f | grep -iE "inject|deauth|restricted|pineapd"'
# terminal 2 — use a REAL AP you control in the chamber
ssh root@172.16.52.1 '
/usr/bin/_pineap INTERFACE LIST
/usr/bin/_pineap DEAUTH <real-bssid> 36      # non-DFS 5 GHz control
/usr/bin/_pineap DEAUTH <real-bssid> 100     # DFS: expect refusal
'
```

**PASS:** ch36 logs an injection line; ch100 logs `[!] [<ts>] can not inject on DFS restricted channel 100/…`; `_pineap` never prints the Go UI's string (that belongs to the UI only).

**FAIL:** ch36 also refuses → the blocker is upstream of the gate (no inject interface bound, pcap not initialised); fix that first, no patch can help. `_pineap` cannot reach `/tmp/pineap_sock` → pineapd is not running; `/etc/init.d/pineapd start`.

> **Scoring warning.** pineapd emits its "injecting…" line regardless of what the kernel then does. **Run the external receiver during the ch36 control too** — otherwise this step reads PASS even in the scenario where the kernel is dropping everything, and the later ch100 result gets misattributed. **[V]**

## A6 [RO] Instrument inventory — and the bad news

```sh
ssh root@172.16.52.1 'for t in hcxdumptool aireplay-ng mdk4 python3 scapy horst tc tcpdump; do
  printf "%-14s " $t; command -v $t || echo ABSENT; done; df -h /overlay /tmp /mmc'
```

**Verified from the rootfs [V]:** `tcpdump` present (**capture only**), `libpcap.so.1.10.5` present. **ABSENT:** `hcxdumptool`, `aireplay-ng`, `mdk4`, `python3`, `scapy`, `horst`, **`tc`**. `ucode` is present but its module set is fs/nl80211/rtnl/ubus/uci/uloop — no socket module, so no AF_PACKET from ucode. The hcx* binaries present are offline converters.

**Nothing on the stock image can transmit a frame except pineapd**, which is the only caller of `pcap_inject`. And `tc` is absent, so the qdisc-counter fallback does not exist either. An injector must be staged (B3).

---

# Stage B — Reversible modification

Ordered least to most invasive. Every step has a one-command rollback.

## B0 [INV, risk: none] Build the measurement rig — this licenses everything after it

**The counter question in the brief has no "before or after" answer: `ieee80211_monitor_start_xmit` never writes `dev->stats` or `dev->tstats` on *any* path, and `ieee80211_monitorif_ops` declares no `.ndo_get_stats64`. `wlan1mon`'s `tx_packets`/`tx_dropped` read 0 forever regardless of outcome. [V]**

The five usable observables:

| ID | Observable | Separates |
|---|---|---|
| **O1** | `logread` refusal line | gate a2 fired |
| **O2** | argv / `uci` band mask | gate a0 |
| **O3** | `/sys/kernel/debug/ieee80211/$PHY/mt76/xmit-queues` **`head` column** advances by 1 per frame handed to the driver | **gate b vs gates c/d** — a frame killed at cfg80211 never reaches `tx_queue_skb`, so `head` does not move |
| **O4** | TX-status **echo** captured on `wlan1mon` itself, with radiotap `TX_FLAGS` | reached the driver and a completion came back |
| **O5** | **external receiver** | **the only thing that separates "firmware dropped it" from "it left the antenna"** |

**O4 nuance [V]:** a **broadcast** frame gets `IEEE80211_TX_CTL_NO_ACK`, so its status fires at USB bulk-out completion and proves only "the driver accepted it". A **unicast** frame has its pktid tracked and the status comes from a real firmware TXS report (mt76 advertises `REPORTS_TX_ACK_STATUS`), so its `TX_FAIL` bit is a genuine hardware verdict. Use unicast when you want hardware-sourced truth. **A capture on `wlan1mon` is the echo (O4) and is never evidence of over-the-air transmission.**

### Mandatory rig controls

1. **Stop channel hopping.** Shipped config is `hop '1'`, `hopspeed 'fast'`, and injection is **asynchronous** (`inject_queue` + a `ping_injection_handler` thread + a `ping_channel_hopper` thread). If the hopper moves `wlan1mon` before dequeue, the frame goes out on another channel and the parked receiver sees nothing — which would be scored as a kernel gate. **[V]**
   ```sh
   ssh root@172.16.52.1 'uci set pineapd.wlan1mon.hop=0; uci commit pineapd; /etc/init.d/pineapd restart
     sleep 5; iw dev wlan1mon info | grep -E "channel|txpower"'
   ```
   Poll `xmit-queues` **continuously**, not as two snapshots 3 s apart.

2. **`addr2` must not match any local vif MAC.** `monitor_start_xmit` re-homes the frame to any local interface whose MAC equals `addr2`, and *that* interface's iftype is what reaches the predicate. For AP/ADHOC/MESH, `dfs_required > 0`, `check_radar` engages, and DFS channels **are** blocked. **[V]**
   ```sh
   ssh root@172.16.52.1 'ip -o link | grep -o "ether [0-9a-f:]*" | cut -d" " -f2 | tr A-F a-f'
   ```
   Confirm `02:00:5e:11:22:33` is absent from that list.

3. **Paired same-run control.** `monitor_start_xmit` has **three silent drops before the regulatory check**, each producing an observable *identical* to the NO_IR drop (frame freed, `NETDEV_TX_OK`, no counter, no `head` movement, no echo, nothing on air) **[V]**:
   - `!ieee80211_sdata_running(sdata)` → `fail`
   - **`chanctx_conf == NULL`** after the `local->monitor_sdata` fallback → `fail_rcu`  ← *the one nobody modelled*
   - `cfg80211_chandef_usable(…, IEEE80211_CHAN_DISABLED)` fails → `fail_rcu`
   - and `ieee80211_parse_tx_radiotap()` failure → `fail_rcu`

   **`iw dev … set freq` returning 0 does not guarantee a channel context was assigned.** So: **every TX test injects the identical frame on 5180 MHz first and then on the channel under test, in one rig invocation with no interface state changes in between, and is scored only on the delta.** A failed 5180 control means *"rig broken, re-establish"* — not data. Re-run the control after **every** interface or module state change.

4. **Negative control + fresh nonce.** Before each positive test, run the receiver for the same duration with the Pager **idle** and require **zero** matches. Put a **unique per-run nonce** in the test SSID (not a constant). Delete pcaps between runs rather than overwriting.

5. **Explicit radiotap rate on 6 GHz frames.** An 8-byte radiotap with `present==0` specifies no rate, so rate control picks `sband->bitrates[0]` — and mt76 registers only the **OFDM subset** for 6 GHz (`mt76_init_sband_6g(phy, rates + 4, n_rates - 4)`), while 6 GHz is **HE-only by specification**. A null result would then be confounded between "a gate blocked it" and "the firmware will not transmit a legacy-OFDM preamble on band 4". Add an `IEEE80211_RADIOTAP_RATE` field, record the rate used, run the same frame on 5180 as a rate control, and capture **with radiotap** on the receiver so you report the observed PHY type. **Note: injecting a true HE frame is not possible through this stack's radiotap TX parser** — it parses only LEGACY RATE, MCS (HT) and VHT. **[V]**

**Rollback:** `uci set pineapd.wlan1mon.hop=1; uci commit pineapd; /etc/init.d/pineapd restart`

## B1 [INV, risk: none] Let pineapd consider band 6

Skip if A0 already did this. Necessary but **not sufficient** — it touches no gate.

```sh
ssh root@172.16.52.1 'uci show pineapd | grep -n bands
  uci set pineapd.wlan1mon.bands="2,5,6"; uci commit pineapd
  /etc/init.d/pineapd restart; sleep 8
  cat /proc/$(pgrep -n pineapd)/cmdline | tr "\0" " "; echo
  /usr/bin/_pineap INTERFACE LIST'
```

**PASS:** argv carries `--band wlan1mon:2,5,6` and `INTERFACE LIST` shows 6 GHz frequencies in wlan1mon's channel list.

**FAIL:** argv still `2,5` → the uci change did not take (wrong section name; check `uci show pineapd`). argv correct but **no** 6 GHz channels listed → check, in order: (1) `iw reg get` is not country `00`, (2) `iw phy $PHY channels` shows 6 GHz not `DISABLED`.

> pineapd builds its list from `nl80211_get_freqlist_cb`, which parses `NL80211_FREQUENCY_ATTR` up to maxtype 17 but **only ever reads `tb[1]` (FREQ) and `tb[2]` (DISABLED)** — `tb[3]` (NO_IR) and `tb[5]` (RADAR) are never loaded. So under US, 6 GHz channels are NO-IR but *not* DISABLED and **will** be included. A research lens claimed an empty list would mean pineapd filters on advertised bands; that cannot produce the symptom under US. **[V]**

**Rollback:** `uci set pineapd.wlan1mon.bands='2,5'; uci commit pineapd; /etc/init.d/pineapd restart`

## B2 [INV, risk: low] ★ THE CHEAP ROUTE — clear NO_IR with no file change at all

```sh
ssh root@172.16.52.1 'PHY=$(cat /tmp/phy1name)
iw reg get | head -3
iw reg set AR && sleep 2
iw reg get | head -3
iw phy "$PHY" channels > /tmp/chan.AR.after
awk "/^Band 4:/{f=1} f&&/^Band [0-9]+:/&&!/Band 4:/{f=0} f" /tmp/chan.AR.after > /tmp/b4.AR
echo "6GHz total=$(grep -c "MHz \[" /tmp/b4.AR) disabled=$(grep -c "(disabled)" /tmp/b4.AR) noIR=$(grep -c "No IR" /tmp/b4.AR)"
diff /tmp/b4.US /tmp/b4.AR | head -40'
```

**PASS:** `total=59 disabled=0 noIR=0`, and the band-4 diff shows 59 removed `No IR` lines.
**Assert both:** `noIR=0` **and** `disabled=0`. Clearing NO-IR on one sampled channel is not enough — that is exactly how GB passes while UNII-6/7/8 are hard-disabled.

**FAIL:** `noIR` stays 59 → the domain did not take; suspect **netifd racing you** (see below) or a cached prior USER hint, and re-read `iw reg get` immediately and again after 10 s. `disabled` becomes non-zero on 6 GHz → a live clamp, which the source analysis rules out; re-check `of_node` from A1.

> A research lens attributed a stuck domain to "CLC, or a driver-set regdomain". **Neither can produce it:** CLC sets per-channel flags and cannot pin `alpha2`, and it is inert on USB; mt7921 is not self-managed. The two real candidates are netifd and a cached hint. **[V]**

**OPERATIONAL TRAP [V]:** netifd re-asserts the UCI country on **every** radio bring-up (`mac80211.sh:1163`), so any `wifi reload` / `wifi up` silently reverts a manual `iw reg set`. To make it stick:

```sh
ssh root@172.16.52.1 'uci set wireless.radio1.country=AR; uci commit wireless; wifi reload; sleep 5
  iw reg get | head -3'
```

**Rollback:** `iw reg set US` (runtime-only; also restored by reboot) and `uci set wireless.radio1.country=US; uci commit wireless; wifi reload`. **No file was modified.**

> **If B2 reaches `noIR=0 disabled=0`, the entire custom-regulatory.db branch (C2) is unnecessary. Skip it.**

## B3 [INV, risk: low] Get an injector that does not involve pineapd

The cleanest isolation of gate a2 from gate b — and the device's `opkg` already points at the **stock OpenWrt 24.10.1 `mipsel_24kc` feeds with the official 24.10 usign key installed**. **[V]**

```sh
ssh root@172.16.52.1 'df -h /overlay /tmp
  opkg update
  opkg -d ram install hcxdumptool      # /etc/opkg.conf already defines: dest ram /tmp
  /tmp/usr/bin/hcxdumptool --version 2>/dev/null || hcxdumptool --version'
```

`hcxdumptool` is 40 KB download / 143 KB installed; its three dependencies (`libc`, `libpcap1`, `libopenssl3`) are already on the box. **[V]**

**Use `-d ram` (tmpfs), not `-d root`** — flash is small, and a reboot then becomes the rollback.

**FAIL:** `Signature check failed` → confirm date/time; usign is not time-based, so this more likely means a transparent proxy. Out of space → `-d mmc` if a card is fitted. Note `opkg update` **will report one failure** for the vendor `hak5` feed line, which returns 404 — not operator error. **[V]**

**Limitation [V]:** `hcxdumptool`, `aireplay-ng` and `mdk4` do **not** generate CSA frames, and `mdk4` is not in the 24.10.1 feeds at all. For CSA without pineapd, note first that **the frame builders are already on the device**: `/usr/lib/libwifi.so.0.0.10` exports `libwifi_create_beacon`, `libwifi_create_probe_resp`, `libwifi_create_action`, `libwifi_add_action_detail`, `libwifi_set_probe_resp_channel` and `libwifi_create_tag` among 113 exports, so a helper can `dlopen("libwifi.so.0")` + `dlsym` instead of carrying its own 802.11 builder. **[V]** **Three jobs, one tool:** it bypasses gate 1 (DFS/6 GHz), it chooses its own send rate (needed to win the ~100 ms BSS-cache race against the real AP), and it can set a **non-zero Channel Switch Count**, which pineapd hardcodes to 0 and which is what blocks the connection-denial effect entirely — see day-one step 17a. That makes the helper smaller than estimated below and removes the libwifi vendoring step; it still has to be cross-compiled. **Do not plan on linking `-lwifi` against the shipped file — it is refused** (`file in wrong format`; no section headers). Use `dlopen`/`dlsym`, or generate a stub `.so` from the export list with `-soname libwifi.so.0` and link against that. No headers or static library ship, so prototypes **and struct layouts** must be written by hand against upstream libwifi `0.0.10`; and because the library is MIPS16, never mask bit 0 of a `dlsym` result. **[V]** Otherwise you need either `scapy` (~28 MB with python3 — almost certainly will not fit the overlay; use `-d mmc`) or a ~20 KB cross-compiled AF_PACKET helper built with `openwrt-sdk-24.10.1-ramips-mt76x8_gcc-13.3.0_musl.Linux-x86_64.tar.zst` (correct target: `mipsel_24kc`, musl, **soft-float** — the loader name `/lib/ld-musl-mipsel-sf.so.1` must match). New code needs only plain MIPS32; the vendor binaries' MIPS16e encoding is irrelevant. **[V]**

**Do NOT use `aireplay-ng` as the primary instrument** — its osdep layer has its own channel handling and would add a gate to an experiment whose whole purpose is isolating gates. Keep it as a cross-check only.

**Rollback:** `opkg -d ram remove hcxdumptool` (or reboot — tmpfs).

## B4 [INV, risk: low] ★ Prove transmission on 5 GHz DFS — the real deliverable

**Do this before any 6 GHz work.** See §5 for why.

```sh
# receiver (separate adapter, parked, radiotap on):
#   ip link set wlanX down; iw dev wlanX set type monitor; ip link set wlanX up
#   iw dev wlanX set channel 52
#   tcpdump -i wlanX -e -s0 -w /tmp/rx_neg.pcap &   # NEGATIVE control, Pager idle
#   ... wait, kill, require ZERO matches ...
#   tcpdump -i wlanX -e -s0 -w /tmp/rx_ch52.pcap &
# Pager, raw path (no pineapd), with the 5180 control in the SAME invocation:
ssh root@172.16.52.1 '/etc/init.d/pineapd stop; sleep 2; ip link set wlan1mon up
  for F in 5180 5260; do
    iw dev wlan1mon set freq $F 20; echo "freq $F rc=$?"
    iw dev wlan1mon info | grep -E "channel|txpower"
    cat /sys/kernel/debug/ieee80211/$(cat /tmp/phy1name)/mt76/xmit-queues
    # ... transmit the nonce-bearing frame here via hcxdumptool / the helper ...
    cat /sys/kernel/debug/ieee80211/$(cat /tmp/phy1name)/mt76/xmit-queues
  done'
```

**PASS (predicted [V]):** `rc=0` on both; `head` advances on **both** 5180 and 5260; the receiver captures the nonce on **both**. ⇒ **cfg80211 does not gate DFS monitor injection**, exactly as the predicate says.

**FAIL:** `head` does not move on **5180** → rig broken (most likely no chanctx); do not score 5260. `head` moves on 5180 but not 5260 → cfg80211 *is* blocking DFS, contradicting both the source and A3's channel dump; re-read the 5260 flags and treat regulatory.db as the target. `head` +1 on 5260 but receiver silent → **gate c, the firmware**, or RF geometry; check attenuation and the negative control first.

**Rollback:** `iw dev wlan1mon set freq 2437 20; /etc/init.d/pineapd start` (pineapd re-applies its own channel list on start). Nothing persistent changed.

## B5 [INV, risk: low] Attribute gate a2 — side by side on the same channel

```sh
ssh root@172.16.52.1 '/etc/init.d/pineapd start; sleep 5
  logread -f > /tmp/log_pd.txt 2>&1 & LP=$!
  # poll xmit-queues continuously in a loop while issuing:
  /usr/bin/_pineap DEAUTH <real-bssid> 100
  sleep 3; kill $LP; grep -F "can not inject on" /tmp/log_pd.txt'
```

**PASS:** `logread` shows `can not inject on DFS restricted channel 100/…` **and** `head` does **not** move — while B4 proved the raw socket *does* transmit on that same channel. That is direct, side-by-side proof that **pineapd's userspace gate, not the kernel, blocks DFS injection**.

**FAIL:** no refusal and `head` +1 → pineapd injected fine and gate a2 did not fire for that code path. Refusal **and** `head` +1 → two frames in flight; re-run in quieter airspace.

**Rollback:** none needed (transmits only).

## B6 [INV, risk: low] 6 GHz test — only if A2 found Band 4 AND E0 cleared CSA

```sh
# Tune the receiver FIRST — a NO-IR 6 GHz channel is passive-only, so scanning will never find it.
ssh root@172.16.52.1 'PHY=$(cat /tmp/phy1name); /etc/init.d/pineapd stop; sleep 2
  iw dev wlan1mon set freq 5180 20   # paired control, same invocation
  # ... transmit nonce frame, check head + receiver ...
  iw dev wlan1mon set freq 5955 20; echo "6g rc=$?"
  # ... transmit identical nonce frame, check head + receiver ...'
```

**Predicted under US [V]:** `rc=0` (NO-IR is **not** checked at set-channel time), but `head` does **not** move, no echo, receiver silent ⇒ **gate b, cfg80211's NO_IR test, is the 6 GHz blocker**. This is the silent-success trap reproduced on purpose and caught by two independent observables.

**Two-tier set-channel observable [V]:** nl80211 rejects a **DISABLED** channel *loudly* with extack `"(extension) channel is disabled"` (`-EINVAL`), whereas a **NO-IR-only** channel passes set-channel *silently* and then has its frames dropped at TX. That distinguishes the two causes for free, with no guessing.

**Then re-run under AR (B2 applied)** and expect `head` to move and the receiver to capture — proving the 6 GHz block is **regulatory.db policy, reversible from userspace, with no hardware or firmware change**.

**Note [V]:** `cfg80211_set_monitor_channel` returns `-EBUSY` unless the phy has monitors only. That bites on **phy0**, where the `wlan0` dummy STA is up — `ip link set wlan0 down` first if you tune `wlan0mon`.

**Rollback:** `iw dev wlan1mon set freq 5180 20; /etc/init.d/pineapd start`

## B7 [INV, risk: low] ★ Separate "the PHY works" from "the antenna passes 6 GHz"

**No step in the research does this, and it is the distinction the question actually turns on.** `has_6ghz` is a chip-level MCU capability byte; an mt7921au module with no 6 GHz filter, PA or antenna path can report it and still pass every other test in this plan.

At **fixed distance and fixed TX rate**, record mean RSSI on the external receiver for an identical frame on **5180, 5745, and 5955 / 6115 / 6915 MHz**. Also run the **reciprocal direction** (external AP transmits, Pager receives) on every band tested.

**PASS:** 6 GHz mean RSSI within **6–10 dB** of 5 GHz.
**FAIL:** 6 GHz 20+ dB down ⇒ the die is 6E-capable but the **RF front end / antenna is not**. The radio will pass every software test and fail every real engagement.

Report the numbers in the verdict. Pair with the §0.2 FCC internal photos, which show antenna count and routing.

---

# Stage C — Invasive (only if Stage B is exhausted)

**Recovery plan, stated up front:** Phase 0 gave you (1) `cp /rom/X X` per file, (2) `restore-stock.sh`, (3) `jffs2reset -y && reboot`, (4) SSH reflash, (5) USB web recovery. Nothing in Stage C writes a bootloader, partition table, eFuse, or DTB. **Check `df -h /overlay` before each write** — a jffs2 that fills mid-copy-up leaves the target truncated *while the squashfs original is already shadowed*, which is the exact state where "restore from /rom" is most needed and "the file looks present" is most misleading.

**Before Stage C: disable vendor autoupdate / the Go UI update path.** Any firmware update replaces the squashfs and silently reverts the patch — and 1.1.3 ships the *identical* gated binary, so updating never helps. A patched device that quietly reverts mid-engagement invalidates every result taken after that point. **[V]**

## C1 [INV, risk: medium] Patch pineapd's gate

Needed only if you want pineapd's integrated CSA/recon workflow rather than a bolt-on tool. **Six same-length edits, 16 bytes, no control-flow or size change**, round-trip tested byte-exact to the stock sha256. **[V]**

| Group | file off | vaddr | stock → patched | Effect |
|---|---|---|---|---|
| 6ghz | 0x06e802 | 0x46e802 | `0872` → `ff72` | `cmpi v0,8` → `cmpi v0,255` in `pineap_wifi_interface::inject` |
| 6ghz | 0x072c68 | 0x472c68 | `0872` → `ff72` | same in `interface_tracker::inject_deauth` |
| dfs | 0x06e964 | 0x46e964 | `02f1116b` → `00f0006b` | `li v1,4369` → 0 (mask ch52–64/100–112) |
| dfs | 0x06ebd0 | 0x46ebd0 | `11111111` → `00000000` | pool word (mask ch116–144) |
| dfs | 0x072d66 | 0x472d66 | `02f1116b` → `00f0006b` | same, deauth path |
| dfs | 0x0733c0 | 0x4733c0 | `11111111` → `00000000` | same, deauth path |

**Patch the groups separately.** The **dfs** group rests on a fully disassembled bitmask — solid. The **6ghz** group rests on the inference that `chan_type == 8` denotes the 6 GHz type, which is **[A] probable, not verified**: the literal store of 8 into offset 28 was never traced. If that inference is wrong the two edits are simply **inert, not harmful** — but they must not be credited as "gate lifted" on that basis.

```sh
# off-box, with the tested tool
cp ~/pager-baseline/pineapd.stock ./pineapd.patched
python3 -I tools/pineapd_gate.py check ./pineapd.patched
python3 -I tools/pineapd_gate.py patch dfs ./pineapd.patched     # or: 6ghz / all
sha256sum ./pineapd.patched
# on the Pager — stop the UI FIRST so procd cannot respawn a broken binary every second
ssh root@172.16.52.1 '/etc/init.d/pineapplepager stop; sleep 3
  ubus call service delete "{\"name\":\"pineapd\"}" 2>/dev/null
  pgrep pineapd || echo PINEAPD-STOPPED; df -h /overlay'
scp ./pineapd.patched root@172.16.52.1:/tmp/
ssh root@172.16.52.1 'cp /tmp/pineapd.patched /usr/sbin/pineapd; chmod 755 /usr/sbin/pineapd
  sha256sum /usr/sbin/pineapd
  /usr/sbin/pineapd --help >/tmp/o 2>&1; echo "exit=$?"; head -5 /tmp/o'
ssh root@172.16.52.1 '/etc/init.d/pineapplepager start; sleep 8; pgrep pineapd; logread | tail -20'
```

> **C1 has no valid pass criterion of its own. A live process proves only that six byte edits did not crash pineapd — it is zero evidence about the gate.**
>
> **The pass criterion is: the specific refusal line captured in A5 is gone, for the identical command on the identical channel, AND the frame is captured at the external receiver (B4/B5 rig).** Anything less is the silent-success trap.

**Cannot brick the device [V]:** nothing in the rootfs integrity-checks `pineapd`; it is **not started at boot** (`# don't autostart, let go bring us up`); the UI is the separate `/pineapple/pineapple` process; and sshd is independent. A broken pineapd degrades recon/injection only. It **is** `procd respawn 0 1 0` (unlimited), so a crashing binary loops every second — noisy and battery-hungry, not fatal. Risk is "medium" because it writes a vendor binary, not because the failure mode is severe.

**Rollback:** `/etc/init.d/pineapplepager stop; ubus call service delete '{"name":"pineapd"}'; cp /rom/usr/sbin/pineapd /usr/sbin/pineapd; chmod 755 /usr/sbin/pineapd; sync; sha256sum /usr/sbin/pineapd` → must print `adc9d36d…8493`; then `/etc/init.d/pineapplepager start`.

**Rejected: LD_PRELOAD.** It cannot intercept this gate. pineapd is non-PIE `EXEC` and calls `frequency_to_channel` via a **direct absolute `jal`**, not a PLT call, so the dynamic linker never gets a chance to rebind it; and the gate returns before `pcap_inject`, so interposing that is useless. The only working variant mprotects `.text` and applies the same bytes in memory — which needs an init-script edit anyway and so is strictly worse than C1. **[V]**

## C2 [INV, risk: medium] Custom regulatory.db — **only if B2 failed**

Needed only if the engagement requires a US-labelled regdomain, or >30 dBm, or 6 GHz plus all 25 US DFS channels in one domain. **If B2 reached `noIR=0 disabled=0`, skip this entirely.**

The shipped `regulatory.db` is itself a **hand-modified, unsigned** database: byte-for-byte upstream wireless-regdb **2025.02.20** `db.txt` compiled with `db2fw.py` after exactly one edit (NO-IR dropped from the world domain's 5170–5250 rule). **The vendor has already done precisely what this step proposes**, which is direct evidence an unsigned replacement loads. **[V]**

Corrections to the brief: the build script is **`db2fw.py`** (VERSION 20 → `regulatory.db`), **not** `db2bin.py` (VERSION 19 → the legacy `regulatory.bin`, the only one importing M2Crypto). `db2fw.py` takes **no key argument** and imports only stdlib. **Signing is never part of the build** — it is a separate openssl step producing `regulatory.db.p7s`, and no `.p7s` exists in the rootfs. With `CONFIG_CFG80211_REQUIRE_SIGNED_REGDB=n`, `regdb_has_valid_signature()` is a stub returning true. **[V]**

**Only five flags are expressible in v20** (`db2fw.py` asserts `flags & ~0x899 == 0`): NO-OFDM, NO-OUTDOOR, DFS, NO-IR, AUTO-BW. Using NO-INDOOR/NO-CCK/PTP-ONLY aborts the build. **This also means the 6 GHz VLP permitting flags cannot be expressed in this database format at all**, which closes the one theoretical override the predicate analysis left open. **[V]**

Build **on the build host** (the Pager has no Python and no toolchain), and prefer **variant B** — append a bespoke `country XX` — because it is purely **additive** and touches nothing existing:

```sh
sh tools/regdb_build/REPRO.sh /tmp/regdb-work
# regulatory.db.vendor must equal 30954f89…4b44  (proves the db.txt baseline is the vendor's)
# regulatory.db.B      = 8eb6e4dfe54c73a8a80bdb3472721797ac25b85f975195e7378f0d7bd1ad041e
```

**A vendor-hash mismatch ⇒ STOP.** Shipping a db built from the wrong baseline would silently re-add NO-IR to the world domain's 5170–5250 rule.

```sh
scp /tmp/regdb-work/regulatory.db.B root@172.16.52.1:/root/regulatory.db.new
ssh root@172.16.52.1 'df -h /overlay; sha256sum /root/regulatory.db.new
  cp /root/regulatory.db.new /lib/firmware/regulatory.db
  iw reg reload
  iw reg set XX && sleep 2          # REQUIRED — see trap below
  iw reg get | head -3'
```

**RELOAD TRAP [V]:** `reg_reload_regdb()` synthesises a hint with `initiator = NL80211_REGDOM_SET_BY_CORE`; `set_regdom()` dispatches that to `reg_set_rd_core()`, which **returns `-EINVAL` for any non-world alpha2**, and the error path then calls `restore_regulatory_settings()`. So **`iw reg reload` alone can never apply a non-world country** — it bounces through world domain `00`. **Always follow it with an explicit `iw reg set <CC>`** (or reboot).

**FAIL:** `country 00` **with** a `malformed or signature is missing/invalid` message → `valid_regdb()` rejected it on magic/version/bounds; restore immediately. `country 00` with **no** message → the reload trap above; re-run `iw reg set XX`. Either way, world `00` sets NO-IR across nearly all of 5 GHz and so **silently degrades the 5 GHz capability the device shipped with** — detect it with `iw reg get`, never assume success.

**Rollback (tested in P0.5):** `cp /rom/lib/firmware/regulatory.db /lib/firmware/regulatory.db; sync; iw reg set US` → hash must return to `30954f89…4b44`. **Never `rm`.** Blanket fallback: `jffs2reset -y && reboot`.

**Persistence [V]:** the write copies up into jffs2 and **survives reboot**, but **not sysupgrade** — `/lib/firmware` appears in no `/lib/upgrade/keep.d/*` list and `/etc/sysupgrade.conf` is comments only. To keep it: `echo /lib/firmware/regulatory.db >> /etc/sysupgrade.conf`.

## C3 — Explicitly NOT in this plan

| Action | Why excluded |
|---|---|
| **Writing the `all` mtd partition** | Destroys u-boot + per-unit `factory` calibration. External SPI programmer + case disassembly to recover. **Hard stop.** |
| **DTB edit** | Flash write; the only genuinely brick-capable operation here. Reachable only if A1's `of_node` check surprises. |
| **MT7961 eFuse/EEPROM write** | **Irreversible; can permanently brick the radio.** Also unnecessary — and the efuse is not even host-readable: mt7921 never calls `mt76_eeprom_init`, so the mt76 debugfs `eeprom` node is **0 bytes**. **[V]** |
| **Raw u-boot-env write** | No `fw_printenv`/`fw_setenv`/`fw_env.config` ships (platform.sh's references are vestigial), so there is no tooling to validate it. No TFTP or U-Boot recovery is documented — USB web recovery is the vendor's lowest tier. **[V]** |
| `mt76` debugfs `regval` / `regidx` | Arbitrary register read/**write**. Treat as write-never; a bad MCU-mediated write can wedge the firmware. |
| `mt76` debugfs `chip_reset` | Forces a full firmware reload and drops `wlan1mon`. |
| **`disable_clc` anything** | Provably inert on USB (A1). Persisting it to `/etc/modules.conf` writes a dead parameter to flash as a permanent red herring. |
| **Replacing `/lib/firmware/mediatek/WIFI_RAM_CODE_MT7961_1.bin`** | Risks NIC-side state; recoverable from `/rom` only if the NIC survives. |
| **Patching out the `mt76_is_usb()` check to force CLC on** | `mt7921_load_clc` indexes `phy->clc[clc->idx]` with `idx` read straight from the firmware file, **unbounded**, against a 3-element array. And it would buy nothing: CLC cannot touch DFS channels. **[V]** |
| **Dropping in stock OpenWrt `kmod-mt7925u`** | Real ABI break: vermagic matches, but stock `mt7925-common.ko` needs `mt76_wcid_alloc` while this `mt76.ko` exports only `__mt76_wcid_alloc` → `Unknown symbol`. Stock kmods are also built against a different kernel hash. **[V]** |

---

# §5 — The 5 GHz DFS side-benefit: THIS IS THE REAL WIN

**Promote this to a first-class deliverable and run it before any 6 GHz work.** The research buried it as a control experiment for the 6 GHz effort; the priority is backwards.

| | 6 GHz | **5 GHz DFS (ch 52–144)** |
|---|---|---|
| cfg80211 blocks monitor TX? | **Yes** (NO-IR) | **No** — US regdb sets DFS without NO-IR, and RADAR is not tested for MONITOR **[V]** |
| Regdomain change needed? | Yes (B2) | **None** |
| Custom regulatory.db needed? | No (B2 suffices) | **None** |
| Kernel change needed? | No | **None** |
| New hardware needed? | 6E receiver **and** 6E AP | **A 5 GHz receiver** — see the correction in Addendum 2c. An earlier draft claimed `wlan0mon` was a free in-enclosure receiver; it is `band '2g'` and cannot hear ch 52. |
| Only obstacle | NO-IR + pineapd + PMF | **pineapd's hardcoded channel bitmask alone** |
| Fix cost | B2 + 4-byte patch group | **12-byte `dfs` patch group, or `opkg install hcxdumptool`** |
| **Does deauth actually work?** | **No** — PMF mandatory | **Yes** — ordinary WPA2 networks, PMF optional |
| Coverage won | 59 channels nobody is on yet | **~16 widely-deployed channels** |

**Sequence:** A3 (confirm no NO-IR on 5260/5500) → B0 (rig) → B3 (`hcxdumptool`) → B4 (inject ch 52, confirm on the **external 5 GHz receiver**, not `wlan0mon`) → B5 (attribute) → C1 `dfs` group only, if the integrated pineapd workflow is wanted.

This needs **no kernel change and no regdb change**. It does need a 5 GHz-capable receiver (Addendum 2c), which the 6E adapter from §0.1 already satisfies — so it adds no purchase beyond what the 6 GHz branch requires anyway, and it is verifiable on day one.

---

# Decision tree

```
Step 0.3  VALUE GATE — what is the deliverable?
  ├─ deauth/disassoc on 6 GHz ──────────── E0: unlockable but POINTLESS (PMF). → §5. STOP 6 GHz.
  └─ CSA ──────────────────────────────────┐ continue; ceiling = beacon CSA (channel move),
                                            │ or beacon/probe-resp CSA flood (connection denial,
                                            │ survives beacon protection)
                                            │
Phase 0   backup gate (P0.1–P0.5) ─ FAIL → STOP. Do not proceed invasive.
  │
A0        vendor 6 GHz toggle ───────────── sets bands 2,5,6? → skip B1
A1        inventory ───────────────────────  of_node EXISTS → investigate DT clamp first
  │
A2 ★      iw phy $PHY info | grep "Band "
  ├─ NO Band 4 ──────────────────────────── E1: answer is NO. HARD STOP for 6 GHz. → §5
  └─ Band 4 present ───────────────────────┐
                                            │
A3/A4     flags + predicate + oracle ─────── 6 GHz all (disabled)? → fix domain (B2) first
  │
B0        rig + 5180 control + neg control ─ control FAILS → rig broken, fix before any data
  │
§5 ★      5 GHz DFS branch (B3→B4→B5) ────── THE DELIVERABLE. Do this first.
  │
B2 ★      iw reg set AR
  ├─ noIR=0 AND disabled=0 ──────────────── kernel gate OPEN, file-free, reversible. SKIP C2.
  └─ else ───────────────────────────────── C2 (custom regdb, additive variant B)
  │
B6        6 GHz TX test (paired control) ─── head moves + receiver captures?
  ├─ no ──────────────────────────────────── gate b confirmed → ensure B2 applied, retest
  └─ yes ─────────────────────────────────── kernel gate clear → B7
  │
B7 ★      RSSI delta 6 GHz vs 5 GHz
  ├─ >20 dB down ───────────────────────── E2: PHY works, ANTENNA does not. Report and STOP.
  └─ within 6–10 dB ──────────────────────┐
                                           │
B5/C1     pineapd gate ─────────────────── pass ONLY on: refusal gone AND receiver captures
  │
VERDICT   fill the table below
```

---

# Early-exit conditions

| ID | Condition | Verdict | Basis |
|---|---|---|---|
| **E0** | Deliverable is client disconnection | **Unlockable but operationally worthless on 6 GHz.** PMF is mandatory there; pineapd can only build beacon/deauth/disassoc. Redirect to §5. | **[V]** incl. vendor docs |
| **E0b** | Deliverable is a CSA **channel move**, but the target AP enables beacon protection (MMIE + Ext Cap bit 84) **and** the client can enforce it | **Beacon-CSA channel move defeated** — mac80211 drops MME-less beacons once the client holds a BIGTK. `probe-csa` does not move a station-mode client either. The remaining outside paths: an unprotected Public-Action eCSA (no switch, but a persistent uplink stall), and the **connection-denial** path, which beacon protection does not close. Decide which effect the engagement actually needs before stopping. | **[V]** for mac80211 |
| **E1** | A2 shows no `Band 4` | **NO. Hard stop.** No software can create the band. | **[V]** |
| **E2** | B7 shows 6 GHz RSSI ≳20 dB below 5 GHz | **NO in practice.** 6E die behind a 2.4/5 GHz antenna path. Passes every software test, fails every engagement. | measurement |
| **E3** | P0.2 firmware hash ≠ 1.1.3 | **STOP.** Every offset and prebuilt artifact is invalid. Re-derive first. | **[V]** |
| **E4** | B4 passes but B6 fails even under AR with `noIR=0 disabled=0` | **Gate c (firmware/MCU).** Not resolvable offline and not addressable by anything in this plan. Report and stop. | **[V]** that the driver side is exhausted |
| **E5** | P0.4 `factory` partition reads all 0xFF/0x00 | **STOP.** Calibration data already absent; raise with Hak5 before experimenting. | — |

---

# Terminal verdict — fill this in and stop

| # | Question | Result |
|---|---|---|
| a | Does any 6 GHz attack survive PMF? (CSA yes / deauth no) | |
| b | `has_6ghz` — is `Band 4` present? | |
| c | 6 GHz channels injectable under US / under AR | ___ / 59, ___ / 59 |
| d | 6 GHz RSSI delta vs 5 GHz | ___ dB |
| e | pineapd 6ghz gate lifted (refusal gone **and** receiver captured)? | |
| f | **5 GHz DFS** injectable, confirmed at an independent receiver? | |
| g | Mutations left on the device (from the ledger) | |

### The three terminal outcomes

1. **No `Band 4`** ⇒ **NO.** Hard stop; no software can create the band. The 5 GHz DFS win (f) stands on its own.
2. **`Band 4` present, but deliverable is deauth** ⇒ **unlockable and pointless.** Report (f) as the actual deliverable.
3. **`Band 4` + CSA deliverable + acceptable RSSI** ⇒ **YES.** The *how* is: `iw reg set AR` (plus `uci set wireless.radio1.country=AR` so netifd does not revert it) **+** the six-byte `6ghz` pineapd patch group — **no custom regulatory.db, no kernel change, no CLC**.

### Close out

```sh
cd ~/pager-baseline
ssh root@172.16.52.1 'sha256sum /lib/firmware/regulatory.db /usr/sbin/pineapd /usr/sbin/iw \
  /usr/bin/hak5cmd /lib/modules/6.6.86/*.ko' > final-hashes.txt
diff baseline-hashes.txt final-hashes.txt
ssh root@172.16.52.1 'ls -laR /overlay/upper 2>/dev/null | head -60; cat /etc/modules.conf; uci export'
```

`/overlay/upper` is the authoritative list of every deviation from the shipped squashfs. It must contain **exactly** what your ledger says and nothing else. Hash changes to files you never touched (kernel modules especially) invalidate every experimental result until explained. Then run `restore-stock.sh` if the device is to be handed back.

---

# What this plan does NOT resolve

1. **Whether the MT7961's RF front end and antennas actually pass 6 GHz.** B7 measures it comparatively; only the FCC filing (§0.2) or teardown gives a definitive answer. `has_6ghz` is a chip capability byte, not an RF measurement.
2. **Whether the closed MT7961 firmware independently gates 6 GHz TX.** The driver side is fully readable — `mt76_connac_mcu_set_channel_domain()` forwards `alpha2` plus each non-DISABLED channel's cfg80211 flags (including NO_IR and RADAR), so the firmware is a *power-limit* authority, not a NO_IR enforcer — but what `WIFI_RAM_CODE_MT7961_1.bin` does with that is opaque. If B6 fails with `head` +1 and nothing on air, this is the remaining suspect (E4). **[V]** on the driver side only.
3. **Whether `chan_type == 8` really denotes the 6 GHz type.** Strongly supported (the printed message, the `%uW6e` format, `pineap_wifi_channel::string()` branching on 8) but the literal store of 8 into offset 28 was never traced. A wrong inference makes the C1 `6ghz` edits **inert, not harmful**, and A5/B5 would reveal it before any patching. **[A]**
4. **Real client behaviour, on mac80211 and off it.** mac80211 is settled by source for *station mode*: it enforces beacon protection when the client can install a BIGTK, does not move on a probe-response CSA, will not switch on an unprotected eCSA (it stalls TX instead, persistently), and refuses auth/assoc while a cached CSA is present. What that does **not** settle: whether any given client driver supports `NL80211_EXT_FEATURE_BEACON_PROTECTION_CLIENT` at all; which drivers set `IEEE80211_HW_HANDLES_QUIET_CSA` and so ignore the eCSA entirely; what pre-2024 kernels do with an unprotected eCSA; and Windows, Apple and vendor Android stacks, which share none of this code. Needs real clients in the chamber.
5. **The internal module's actual USB VID:PID.** Nothing in the rootfs records a probed device, and the likely answer (`0e8d:7961`) is used by both 6E and dual-band-only modules, so it decides nothing either way.
6. **No MediaTek datasheet distinguishes MT7921AU from MT7921AUN on 6 GHz**; reseller sheets contradict each other. Moot anyway, since mt76 resolves the band complement at runtime.
7. **Any kernel-side change is out of reach.** There is **no GPL source release and no SDK for the Pager** (`hak5.org/gpl` → 404; the 75-page docs sitemap has no licensing page; `github.com/hak5/wifipineapplepager` is a stub of payload/theme submodules; `/api/.../tools` → null; only the Mark 7 is upstream in OpenWrt). You cannot rebuild cfg80211/mac80211/mt76 with different CONFIG options — only binary-patch the shipped `.ko` files, which is high-effort and discards the clean rollback story. **[V]**
8. **No modification can survive a vendor firmware update.** Official images are ed25519-signed against `/etc/firmware-key`, so a self-built image will not install through the supported path; all persistence must live in the jffs2 overlay, which sysupgrade replaces. **[V]**
9. **mt76 USB monitor/injection quality.** Known open problems as of late 2025 / early 2026, including reports of firmware crashes that make the monitor interface disappear until replug. If `wlan1mon` vanishes mid-test, that is the likely cause; recover with the `mt7921-power` GPIO cycle, else reboot. **[A]** — single community source; verify against kernel changelogs before trusting any negative capture result.
10. **The `mt7921-power` GPIO cycle is itself untested.** It is asserted from the `gpio-export` DTS node and `/etc/init.d/mt7921`; nothing demonstrates that dropping the rail forces USB re-enumeration rather than leaving a wedged, still-bound device. Treat it as unverified and keep `reboot` as the stated fallback. **WARNING: `system-power` is exported writable in the same node — writing it cuts system power.** **[A]**
11. **The claimed "milder reset" tier (hold reset ≥10 s → `jffs2reset`) does not exist on this board.** The `/etc/rc.button/reset` handler is real, but **no gpio-key in the DTS carries `KEY_RESTART`** — only `BTN_A`, `BTN_B`, `KEY_POWER` and the four d-pad codes. The handler is unreachable via gpio-keys. The verified equivalent is `jffs2reset -y && reboot` over SSH. **[V]**
12. **A/B physical button mapping.** The DTS node names are the inverse of the case silkscreen. Read the on-screen prompt. **[A]**
13. **Free flash is unmeasurable offline**, so whether `scapy` (~28 MB) fits, and whether an SD card is fitted at all, is unknown until first contact.

---

# Addendum — pineapd's gate, disassembled

Added after this plan was drafted. A full MIPS16e disassembly of `pineapd` resolves several
things the plan could only mark **[A]**, and closes item 3 of "What this plan does NOT resolve".
Method and re-verification recipe: `dev/pager-csa-primitives.md`.

## The DFS predicate is now exact — **[V]**

Not a bitmask to be discovered on the device; it is read out of the binary. The refusal set is
**exactly** the 16 standard 20 MHz FCC DFS channels:

```
52 56 60 64  100 104 108 112  116 120 124 128 132 136 140 144
```

Everything else passes gate 1: `ch < 52`, `ch 65–99`, `ch 113–115`, `ch >= 145`. Implemented as
range tests plus `0x1111` / `0x11111111` shifts, duplicated at:

| Function | Address range | File offset |
|---|---|---|
| `pineap_wifi_interface::inject` | `0x46e800`–`0x46e826` | `0x6e800`–`0x6e826` |
| `interface_tracker::inject_deauth` | `0x472c66`–`0x472c8a` | `0x72c66`–`0x72c8a` |

Three consequences for §5 and C1:

- **ETSI DFS channels 68–96 are not blocked.** `68` takes the `65..115` branch, `68-100`
  underflows, fails the `sltiu 13` bound, and the inject proceeds. If the chamber AP can sit on
  ch 96, that is a gate-1-free DFS channel and a useful control for B5.
- `pcap_inject` has **exactly one call site**, inside `pineap_wifi_interface::inject`, so B3's
  "use a non-pineapd injector" fully bypasses gate 1 — confirmed, not assumed.
- Gate 1 reads no regulatory state at all: no `NL80211_CMD_GET_REG` in the binary, and channel
  enumeration reads only `FREQUENCY_ATTR_FREQ` and `FREQUENCY_ATTR_DISABLED`, never `NO_IR` or
  `RADAR`. **B2 cannot affect gate 1.** The plan's split of B2 (regulatory) from C1 (patch) is
  therefore correct and necessary, not belt-and-braces.

## Item 3 of "does NOT resolve" is now resolved — **[V]**

The plan marks the `chan_type == 8` inference **[A]** because "the literal store of 8 into offset
28 was never traced". It has been. The 6 GHz test is:

```
lw    v0,28(chan)   ; +0x1c, the band field
cmpi  v0,8
bteqz <refuse>
```

`8` is stored into `+0x1c` at **exactly one instruction in the whole binary** — `0x4692b8`
(`sw v0,28(s0)`), inside `pineap_wifi_channel::from_string`'s `strcasestr("W6e")` / `sscanf("%uW6e")`
branch. The other producers write a different encoding entirely: `mac80211::get_channel` hardcodes
`0`, and `mac80211::find_primary_widest_channel` writes the raw `nl80211_band` index (3 for 6 GHz).

So `chan_type == 8` **does** denote 6 GHz, and the C1 `6ghz` patch group is not inert. But the
field carries **two mutually incompatible encodings**, which has a sharper consequence than the
plan assumes:

> **A channel not parsed from `"<n>W6e"` text never carries `8`, so gate 1's 6 GHz check cannot
> fire for it — and the DFS switch does not catch it either, since every valid 6 GHz 20 MHz channel
> number is ≡1 mod 4 while the blocked set is ≡0 mod 4.** **[A]** on "therefore unreachable in
> practice" (it rests on no fourth writer existing; every `sw <reg>,28(<reg>)` in all 1625
> symbol-covered functions was checked). `interface_tracker::command_send_deauth` builds its channel
> via `from_string` on the command's string field, so **how the channel is spelled may decide
> whether gate 1 fires at all.**

**Test this before patching anything.** In A5, issue the same 6 GHz target twice — once with the
channel spelled `"37W6e"`, once as a plain frequency — and compare the log. If only the first is
refused, C1's `6ghz` patch group is unnecessary and the 6 GHz answer is cheaper than Stage C.

## A5's log channel is booby-trapped — **[V]**

A5 reads pineapd's log to confirm which gate fired. The wording lies. `pineap_wifi_interface::inject`'s
DFS branch loads the **6 GHz** format string:

| Log line | Actually means |
|---|---|
| `"{} can not inject on 6GHz restricted channel X/Y"` (interface-name prefix) | a **5 GHz DFS** refusal, from the common inject path |
| `"can not inject on 6GHz restricted channel X/Y"` (no prefix) | a genuine 6 GHz refusal |
| `"can not inject on DFS restricted channel X/Y"` | DFS refusal, and it can **only** come from `inject_deauth` |

Attribute by **which binary logged it and whether the line is name-prefixed**, never by the words
"6GHz" or "DFS". A5 as written would otherwise mis-attribute every DFS refusal as a 6 GHz one.

## A safety note for B4/B5 — **[V]**

`recon_engine::inject_csa` (`0x4a125c`) injects nothing itself: no `libwifi_create_*`, no queue
`emplace`, no `pcap_inject`. It records a `csa_beacon_record` and calls
`set_and_freeze_primary_channel_hop_s`, so the CSA leaves via the ordinary beacon path.

**It sets and freezes the radio's primary channel before the beacon is refused.** Firing CSA at a
gate-1-blocked channel therefore parks the radio there and transmits nothing — it will look like a
silent failure while having actually disrupted channel hopping. If recon goes quiet after a failed
CSA attempt, this is why. Unfreeze before continuing.

---

# Addendum 2 — the FCC filing, read

Resolves §0.2 and item 1 of "What this plan does NOT resolve". Source: FCC ID **2A52Y-MK1**,
grantee **Hak5 LLC**, test report **TZ0278250701FRF08** ("Radio Report_NII_6G"), filed 2025-09-25
by Shenzhen Tongzhou Testing for manufacturer Shenzhen Gainstrong Technology. **[V]**

```
Product Name : Wifi Pineapple Pager        Model Number : Mk1
WLAN         : Supported IEEE 802.11ax
WLAN FCC Operation Frequency:
    U-NII Band 5: 5945~6425 MHz
    U-NII Band 6: 6425~6525 MHz
    U-NII Band 7: 6525~6875 MHz
    U-NII Band 8: 6875~7125 MHz
Antenna Type And Gain : Internal Antenna, Ant. 1: 4.43 dBi, Ant. 2: 2.93 dBi
                        802.11a/n/ac/ax support 2T2R [Antenna 1 and Antenna 2]
```

## What this settles

- **The radio has a 6 GHz PHY.** The product was tested for radiated emissions across all four
  6 GHz sub-bands. Step A2 (`Band 4` present) should now be expected to PASS, and early exit **E1
  should not fire**. Run A2 anyway — it reads `has_6ghz` from this unit's firmware, which is the
  per-unit fact — but treat a FAIL as surprising and re-check the phy mapping before believing it.
- **The antennas pass 6 GHz.** Item 1 of "What this plan does NOT resolve" claimed only the FCC
  filing or a teardown could answer whether the RF front end and antennas work at 6 GHz. They were
  characterised at 6 GHz with measured gains. **Step B7 is demoted from an open question to a
  sanity check**; a large 6 GHz-vs-5 GHz RSSI deficit now indicates a fault, not a design limit.
- **A hypothesis that was wrong, recorded so it is not re-derived.** An earlier reading held that
  the 6 GHz recon toggle plus the pineapd injection gate meant "receive-capable, never certified to
  transmit". **That is refuted.** The product *is* certified to transmit on 6 GHz.

## What it means for the gates

The gate is therefore not a certification gap. The consistent reading is narrower: a certified
6 GHz device may transmit **as a compliant AP or client**, and an FCC client device may transmit
only after an enabling signal from an AP it is associated with. Monitor-mode injection is
unsolicited transmission with no association, which is outside the certified operating mode even on
a certified device. That is exactly what `NO_IR` ("no initiating radiation") encodes — so pineapd's
hardcoded refusal and the regdb's `NO-IR` flag are two independent encodings of one rule: **the
device may talk on 6 GHz, but never first.** **[A]** on the motive; **[V]** on the certification.

Practical consequence: both gates are software, the silicon and antennas beneath them are known
good, and the project's bottleneck is now entirely (a) getting past the two gates and (b) the value
gate at §0.3 — PMF and beacon protection, which this filing does nothing to change.

## Still worth pulling from the filing

| Document | Why |
|---|---|
| `FCC Software Configuration Control Declaration Rev1.0` (Cover Letter, 122 KB) | For U-NII devices the FCC requires a declaration of how software prevents operation outside certified RF parameters. Bears directly on whether anything stronger than a userspace check guards the gate, i.e. on whether Stage C is realistic. |
| `Internal Photos` (3.8 MB) | Module part number and antenna count — pins the exact MT7921 variant. |

`Block Diagram`, `Schematics`, `Operational Description`, `BOM` and
`FCC Software Security Requirements for UNII devices` are listed **Metadata only** under the
filing's confidentiality request and cannot be downloaded.

## Addendum 2b — internal photos and the software-control attestation

Source: FCC ID 2A52Y-MK1, internal photos report **TZ0278250701PH03**, and
`FCC Software Configuration Control Declaration Rev1.0` (signed 2025-09-15). **[V]**

**Hardware, from the photos.** Board silkscreen reads **`Pager V2.2.0`**, dated **`2025/06/03`**.
Antenna labels moulded into the case half: **`WiFi-1`**, **`WiFi-2`**, **`2.4G-2`** — consistent
with the MT7921AU's 2T2R pair (matching the radio report's Ant. 1 = 4.43 dBi, Ant. 2 = 2.93 dBi)
plus a separate 2.4 GHz pair for the SoC's own radio. Two copper RF shield cans; USB-A and USB-C.
If the unit in hand carries a different board revision, re-check the hardware assumptions here.

**Not determined.** The module part number is under an intact shield can, and the BOM, schematics,
block diagram and operational description are all *Metadata only* under the filing's
confidentiality request. The exact MT7921 variant therefore stays unconfirmed — which no longer
blocks anything, since the radio report already establishes 6 GHz TX capability regardless of
variant. One annotation in Fig.10 reads **"Not used for transmitting"**, pointing at connectors
near the one labelled "Bluetooth Antenna"; the published image resolution is too low to tell which
connectors or to read the adjacent silkscreen. Worth a zoom if a receive-only chain would matter.

**What the attestation tells us about Stage C.** The Software Configuration Control Declaration is
the standard KDB 594280 attestation — a signed statement that "no third party will have software,
or configuration control, to program the device out of compliance." It is a legal attestation, not
a technical description: no secure-boot claim, no hardware RF-parameter lock, no signed radio
parameters. The implication is that **pineapd's compiled-in gate and the regdb flag _are_ the
compliance control**, which matches exactly what the binary shows.

> **State this precisely.** The filing that would describe any deeper enforcement —
> `FCC Software Security Requirements for UNII devices Rev1.0` — is withheld as *Metadata only*.
> So this is **absence of public evidence for a hardware lock, not evidence that none exists.**
> It makes Stage C look feasible; it does not prove it. If C1 fails in a way that suggests the
> binary patch took but the radio still refuses, an undisclosed enforcement layer moves from
> "unlikely" to "the leading suspect" — alongside E4 (closed MT7961 firmware), which Addendum 2
> already flags.

## Addendum 2c — the antenna map, and a correction to §5

Source: FCC internal photos **TZ0278250701PH03**, Fig.11 (page 6), read at full resolution. **[V]**

Four antenna positions are labelled in the case, and the annotations are unambiguous:

| Label | Annotation in the filing | Meaning |
|---|---|---|
| `WIFI-1` | **"Wifi 2.4G/5G/6G Antenna 1"** | MT7921AU chain 1 — transmits, all three bands |
| `WIFI-2` | **"Wifi 2.4G/5G/6G Antenna 2"** | MT7921AU chain 2 — transmits, all three bands |
| `2.4G-1` | **"Not used for transmitting"** | radio0 chain 1 — **receive only** |
| `2.4G-2` | **"Not used for transmitting"** | radio0 chain 2 — **receive only** |

So **every transmission on this device — 2.4, 5 and 6 GHz alike — leaves through the MT7921AU's
two antennas.** `radio0` (`platform/10300000.wmac`, the SoC's own mt7603e, UCI `band '2g'`) is a
**receive-only radio**. Corroborated by its own config: every AP-mode interface it defines
(`wlan0mgmt`, `wlan0open`, `wlan0wpa`) ships `disabled '1'`, and only `wlan0mon` plus a dummy sta
are live. The antenna gains in the radio report (Ant. 1 = 4.43 dBi, Ant. 2 = 2.93 dBi) are
therefore `WIFI-1` and `WIFI-2`.

### Correction to §5 — this one would have cost a day on the bench

§5 claimed the DFS branch needed **no new hardware**, because "the Pager's own `wlan0mon` (phy0,
mt7603e, a physically different chip) is a free independent receiver in the same enclosure".

**That is wrong.** `radio0` is `band '2g'`. It is a fine independent receiver for a 2.4 GHz control
— and it genuinely is a different chip, so it remains the right instrument for the B0 rig's 2.4 GHz
sanity check — but **it physically cannot hear 5 GHz channel 52**. The DFS branch needs a 5 GHz-
capable receiver like any other band.

Practical impact is small, because the 6E adapter §0.1 already requires is tri-band and covers
5 GHz. But do not plan the DFS test around `wlan0mon`, and do not read its silence on ch 52 as
"the Pager did not transmit" — it would be silent either way. That is exactly the confounded
pass/fail signal the plan's own validity rules forbid.

### Note for CamHound's injectability probe

`inj_probe()` merges per-channel flags across every phy, chosen so we need not guess which
interface pineapd picks as injector. That stays correct here, but for a reason worth writing down:
**the only transmitting radio (phy1) covers every band the receive-only one does**, so merging
phy0's flags in can never make the merged answer differ from phy1's. If a future revision ships a
transmitting radio0, or a radio0 covering a band phy1 does not, that invariant breaks and the merge
would need to select the transmitting phy instead.
