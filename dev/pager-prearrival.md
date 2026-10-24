# Pager — pre-arrival prep, verified

Everything here was done and checked **before any hardware was in hand**, on 2026-10-23. It covers
steps 1–6 of `dev/pager-day-one.md` that do not need the device, plus two corrections to
`dev/pager-6ghz-determination-plan.md` that came out of doing them.

Read the running order in `dev/pager-day-one.md`. Gate facts: `dev/pager-csa-primitives.md`.
Marker convention is this project's: **[V]** verified against a primary source, **[A]** inferred.

---

## 1. The firmware pin still holds

Every address, offset and hash in the pineapd analysis is pinned to **1.1.3-stable**. That pin is
still the current release:

```
version       1.1.3-stable
release_date  2026-10-03T20:22:50Z
checksum      3073d6b8f91b46eddda20450f9b93f4e3e018e65f5943f4b0941a1fff7f8cd33
```

from `https://downloads.hak5.org/api/devices/wifipineapplepager/firmwares`. **[V]** Nothing has
superseded the analysis.

**This sharpens day-one step 3 rather than cancelling it.** "Do not let it update" is the right
default, but the decision depends on which way the shipped version differs:

| Device ships | Do |
|---|---|
| 1.1.3-stable | Nothing. The analysis applies as written. |
| Older than 1.1.3 | The pinned addresses may not match. Updating **to 1.1.3** is the move that aligns the device with the analysis — a deliberate update, not an accident. |
| Newer than 1.1.3 | Do not update further. Re-check every address before trusting it, and re-verify the pin above. |

Record the version before anything else either way.

## 2. Recovery image — §0.4 PASS

```sh
curl -L -o pineapplepager-firmware-1.1.3-signed.bin \
  https://downloads.hak5.org/api/devices/wifipineapplepager/firmwares/latest
sha256sum pineapplepager-firmware-1.1.3-signed.bin
```

Downloaded and verified: **33884001 bytes**, sha256
`3073d6b8f91b46eddda20450f9b93f4e3e018e65f5943f4b0941a1fff7f8cd33` — exact match to the plan's
pinned PASS. **[V]**

Do this on the bench laptop, not somewhere ephemeral. No invasive step may start without it.

## 3. Injector pre-staged — takes the network off the DFS critical path

B3 installs `hcxdumptool` with `opkg update && opkg -d ram install hcxdumptool`, which needs the
Pager to reach the OpenWrt feeds. **A shielded chamber does not provide that.** It also runs into
the vendor `hak5` feed line returning 404 (noted in B3 — not operator error).

Fetch the package first and install it from a file instead:

```sh
# off-box, before the chamber
curl -L -O https://downloads.openwrt.org/releases/24.10.1/packages/mipsel_24kc/packages/hcxdumptool_6.3.4-r1_mipsel_24kc.ipk
echo '72508f11b957be6071b8a943dc51bb0184cdb75fd3215f5917e1f9470805265e  hcxdumptool_6.3.4-r1_mipsel_24kc.ipk' | sha256sum -c -
scp hcxdumptool_6.3.4-r1_mipsel_24kc.ipk root@172.16.52.1:/tmp/
# on the Pager -- no network, no opkg update
ssh root@172.16.52.1 'opkg -d ram install /tmp/hcxdumptool_6.3.4-r1_mipsel_24kc.ipk'
```

Verified: 40034 bytes, sha256 as above, `ELF32 LSB MIPS32r2` little-endian, interpreter
`/lib/ld-musl-mipsel-sf.so.1` — the soft-float loader B3 requires. **[V]**

### The dependency claim in B3 was wrong

B3 said, marked **[V]**, that "its three dependencies (`libc`, `libpcap1`, `libopenssl3`) are
already on the box". That is the **package metadata**, not the binary. `readelf -d` on the shipped
file:

```
NEEDED  libpcap.so.1
NEEDED  libgcc_s.so.1
NEEDED  libc.so
```

**`libgcc_s.so.1` appears in neither the plan's list nor the package's own `Depends:` field**, so
`opkg` will not pull it and a file-install will not either. It is normally part of OpenWrt base, so
it is very likely present — but that is **[A]**, and the failure mode is a loader error on the DFS
critical path. Ten seconds, on arrival:

```sh
ls -l /lib/libgcc_s.so.1 /usr/lib/libgcc_s.so.1 2>/dev/null
```

Conversely `libopenssl3` is declared but the binary links no libcrypto or libssl — harmless.

Note also that the file has **no section headers** and its ELF header carries the MIPS16 ASE flag
(`Flags: 0x74001005`, and `0x74001005 & EF_MIPS_ARCH_ASE_M16` is set). Both **[V]**.

**An earlier revision of this section said the binary "is itself MIPS16" and tagged that `[V]`.
That was a conclusion drawn from the flag, not a reading, and it does not follow.** The flag says
the ASE is present somewhere in the link; it does not say the main body is MIPS16-encoded. The test
CLAUDE.md names — odd function-symbol values — cannot be applied here: the only addressed symbols
are `_init`, `_fini` and two unnamed entries, all **even**, and those are MIPS32 even inside a
MIPS16 binary (`dev/pager-csa-primitives.md`: "Only crt/INIT/PLT-adjacent code is MIPS32"). The
entry point `0x403590` is even for the same reason. With no section headers there is no `.symtab`
to read, so the body's encoding is **not established** — **[A]**, leaning MIPS16 only because
OpenWrt builds this target with the ASE enabled.

Practical effect: if you ever disassemble it, assume the MIPS16 tooling trap in
`dev/pager-csa-primitives.md` *may* apply and check rather than trust the output. Nothing else here
depends on it.

## 4. `iw` output format — confirmed against the shipped binary

Day-one step 8 and `inj_probe()` both depend on the layout of `iw phy <phy> channels`. OpenWrt
24.10.1 `mipsel_24kc` ships **iw 6.9** in two builds, and the format strings are byte-identical in
both:

| | |
|---|---|
| `iw` (reduced, 137400 B) | sha256 `f9e65314…4b0e89` |
| `iw-full` (205816 B) | sha256 `f7434896…41c5b9` |

```
Band %d:
\t* %d MHz [%d]            <- note the TRAILING SPACE after "] "
(disabled)
\t  No IR
\t  Passive scan
\t  Radar detection
```

**The `channels` subcommand is present in the reduced build too** **[V]** — so `inj_probe()` will
not silently fall back to its conservative set just because the small `iw` package is installed.

From `phy.c:96` in iw 6.9 source, the emitting order per channel is: the `\t* %d MHz [%d] ` line,
then `(disabled)` *and nothing else* if disabled, else `Maximum TX power`, then exactly one of
`No IR` / `Passive scan` / `No IBSS`, then `Radar detection`, then `Channel widths`, then
`DFS state` / `DFS CAC time`. **[V]**

### Why iw spells NO_IR three ways

`nl80211.h` keeps `NL80211_FREQUENCY_ATTR_NO_IR` and `__NL80211_FREQUENCY_ATTR_NO_IBSS` as two
**distinct** enum slots; only the public names `PASSIVE_SCAN` and `NO_IBSS` are `#define`d onto
`NO_IR`. iw prints `No IR` when both slots are present (its comment: "If both flags are set assume
an new kernel"), and falls back to `Passive scan` or `No IBSS` when only one is. A current kernel
sets both, so **this device will print `No IR`** — the others are old-kernel paths. **[V]**

## 5. `inj_probe()` / `inj_parse_channels()` validated — one defect found and fixed

Handoff §8 item 1 said the parser "has never seen live `iw` output". It has now been run against a
fixture built byte-for-byte from the shipped binary's own format strings (trailing space included),
rather than against an invented layout.

**It parses the real format correctly**, and the two-gate separation comes out right:

| Channel | `iw` attributes | gate 2 | `csa_injectable` |
|---|---|---|---|
| 2.4 ch 1 | — | permitted | **injectable** |
| 2.4 ch 12 | `(disabled)` | refused | refused |
| 5 ch 36 | — | permitted | **injectable** |
| 5 ch 52 | `Radar detection` + DFS state | **permitted** | refused — **by gate 1 only** |
| 5 ch 100 | `Radar detection` + DFS state | **permitted** | refused — **by gate 1 only** |
| 5 ch 149 | — | permitted | **injectable** |
| 6 ch 1 / 37 / 233 | `No IR` | refused | refused |

Two things worth keeping:

- **ch 52 and 100 come back gate-2 *permitted*.** The parser correctly ignores `Radar detection`,
  so the entire DFS refusal is attributable to gate 1 — exactly as `dev/pager-csa-primitives.md`
  claims, now demonstrated through the real code path rather than argued.
- **149 is injectable under US**, confirming handoff §8 item 2's prediction.
- The 6 GHz ch 1 / 2.4 GHz ch 1 channel-number collision is handled: `INJ_OK[2/1]=1` and
  `INJ_OK[6/1]=0` coexist, so the `band/channel` keying claim in the code comment holds.

Also verified sound: multi-phy concatenation (the `Band N:` rule flushes across the phy boundary),
`END` flush when the stream has no trailing newline, and no false frequency match on
`Channel widths:` or `DFS state:` lines.

### The defect

`Passive scan` and `No IBSS` were **not** recognised, so a NO_IR channel on an older kernel parsed
as **injectable** — the unsafe direction, and the one that matters, because a cfg80211 silent drop
is indistinguishable from a resisting target. Fixed by widening one regex to
`/^[ \t]+(No IR|Passive scan|No IBSS)[ \t]*$/`, which cannot cause a false refusal on a current
kernel because those lines never print there. ERE alternation confirmed under `mawk` 1.3.4, a
minimal implementation, as evidence for busybox awk on-device. Three selftest cases added
(`157 checks, 0 failed`).

**Still open, and only answerable on hardware:** which regulatory domain is actually live
(`iw reg get`). Under US, 149–165 should come back injectable as above; under world/`00` they
should not. That is day-one step 8.

## 6. On arrival — receiver first, before the Pager is powered

The handoff records an **EDUP AX1672** as ordered. That part is **not** on §0.1's validated list
(ALFA AWUS036AXML, Netgear A8000 `0846:9060`, TP-Link TXE50UH `35bc:0107`), and §0.1 flags a
near-miss trap in exactly this product space: Netgear **A7500** (`0846:9065`) is the wrong
dual-band AX1800 part. Whether the EDUP is the right part is **not determined here** — what matters
is that it binds `mt7921u` and registers band 4.

```sh
lsusb                                   # record VID:PID
lsusb -t                                # which driver claimed it
dmesg | grep -i 'mt7921\|mt76'          # must bind mt7921u
iw reg get                              # must NOT be country 00
iw phy phy0 info | grep -E "^[[:space:]]+Band [0-9]+:"   # Band 4 present?
```

Anything other than `mt7921u`, or a missing band 4, means **stop and swap the part**. Do not power
the Pager first: a receiver you have not validated against a non-Pager source makes every later
result uninterpretable, which is the whole point of day-one step 1.

Do **not** substitute an Intel AX210/AX211. iwlwifi is self-managed regulatory and partly learns
its country from received beacons; a shielded chamber has none, so 6 GHz may never appear. Same
class of trap as the device under test. **[A]** — vendor/community reports, not tested here.

## 7. Restore script, ready to run

From P0.5. Write it before first contact; **run it once while the device is still unmodified** to
prove it is a no-op. A backup you have not restored from is a hypothesis.

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

Keep the append-only mutation ledger (`~/pager-baseline/ledger.txt`) from P0.5 as well: one line per
change with its rollback command, written *as you make it*. Without it a mid-session anomaly cannot
be attributed.

---

## What is still blocked on hardware

| Day-one step | Needs |
|---|---|
| 1 — validate the receiver | the 6E adapter, plus any non-Pager 6E and 5 GHz source |
| 7 — Band 4 present | the Pager |
| 8 — live regulatory state, and `inj_probe` against real `iw` output | the Pager |
| 9 — the value gate beacon capture | the chamber AP (6 GHz branch only) |
| 10–14 — the DFS branch | the receiver **and** a 5 GHz AP that can sit on ch 52 or 100 |

Nothing else in steps 1–6 can be brought forward further than it has been here.
