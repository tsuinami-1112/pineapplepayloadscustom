# pagerinj — the Stage-B injector

An AF_PACKET sender for the Pager bench work. **It never touches the channel**; whatever
`iw dev <if> set freq` left is what it uses. Its capture socket is bound to `-i`, so what it clones
passed through that interface — received there, or injected on it by another process (which is why
CSA-bearing beacons are skipped) — and came from no other interface.

Built and validated with **no hardware**. What it is for, and the reasoning behind every design
choice, is in the header comment of `pagerinj.c` — read that before changing it.

## Why not hcxdumptool or aireplay-ng

**The sufficient reason, which depends on nothing else: neither can build a CSA frame at all**
(§B3's limitation note, **[V]**), and step 17a needs one with a settable count byte. If you read
only one line of this section, that is it.

The channel argument is weaker than an earlier revision of these docs claimed, so here it is
accurately. §B3 rules out aireplay-ng because "its osdep layer has its own channel handling and
would add a gate to an experiment whose whole purpose is isolating gates." For `hcxdumptool`, from
its shipped help text **[V]**:

- It **always sets the frequency itself** — `-c`/`-f`/`-F`, and `failed to set frequency` is an
  error path. There is no option to inherit the interface's current channel.
- But a single `-c`/`-f` **disables its frequency management** (its own words), so `-c 52b` is
  close to what the experiment wants. Saying the aireplay-ng objection "applies to hcxdumptool" was
  an overstatement; one documented channel set is not an osdep layer.
- The risk that actually matters is **regulatory, not channel** — and it is settled, with a **split
  answer**. Against the 6.3.4 tag (`8dad077`), the only `NL80211_FREQUENCY_ATTR_*` references in
  the tree are `FREQ`, `MAX_TX_POWER` and `DISABLED`; **zero for `NO_IR` or `RADAR`** **[V]**. It
  refuses by *not arming* (`usrfrequency_to_scanlist()`, `hcxdumptool.c:3846`), not by declining
  frames.

Composed with `dev/pager-prearrival.md` §5's per-channel table, that splits by band:

| | hcxdumptool | consequence |
|---|---|---|
| **5 GHz DFS** (ch 52 → `Radar detection`) | never reads `RADAR` | arms and transmits — **a good independent cross-check** for `pagerinj` |
| **6 GHz** (ch 37 → `No IR`) | never reads `NO_IR` | arms and transmits, **and gate 2 drops every frame silently** |

**On 6 GHz it is worse than an unknown.** `send_80211_*` only compares `write()`'s return against
the length, `PACKET_IGNORE_OUTGOING` on its RX socket means it never sees its own frames, and its
TX counters count attempted writes — so **it reports success while nothing leaves the antenna**.
A confident false positive, in the one direction this experiment cannot tolerate.

Two more that cost bench time, both **[V]**: a regulatory refusal presents as **`failed to arm
interface` / "driver is broken / driver is busy"** (the `failed to set frequency` string is in the
`-m` path, downstream of the call that already failed — grepping for it will find nothing), and it
randomises the MAC, forces monitor mode and kills powersave while restoring none of it.

`pagerinj` sidesteps all of it by never setting the channel and holding no regulatory opinion. Keep
hcxdumptool as the pinned DFS cross-check and nothing more.

## Jobs

| Job | Mode | Where |
|---|---|---|
| Prove a frame left the antenna on a gate-1 channel | `--nonce` | day-one step 13, plan §B4 |
| Set a non-zero CSA Channel Switch Count | `--csa --count N` | day-one step 17a |
| Keep pineapd's element intact but add a live eCSA count | `--csa --ecsa-count N` | 17a's third arm |
| Unicast Spectrum-Management CSA to one client | `--action --client <mac>` | day-one step 17c |
| Choose the send rate (the ~100 ms BSS-cache race) | `--rate` | all of them |
| Name the legacy PHY rate in the radiotap header | `--phy-rate M` | plan §B0 rig control 5 (6 GHz) |

### `--chan`: the channel the client is told to go to

For `--csa` and `--action`, `--chan` is the CSA **New Channel Number** — where the client is told to
go, not where you are. It must differ from the target's current channel. A same-channel CSA announces
no move, and what the client does with one is not what 17a measures: with mode 0, `csa_present()`
discards it before the count is looked at (`mlme.c:8351-8352` at v6.12, `if (csa && !csa->mode &&
csa->new_ch_num == cur_channel) csa = NULL;` **[V]**), and on the move path
`ieee80211_sta_process_chanswitch()` ignores a switch to the identical chandef when it came in an
action frame (any mode) or in a beacon with mode 0 (`mlme.c:2533-2543`: one `tries to chanswitch to
same channel, ignore` log line, then silence **[V]**). A beacon-borne mode-1 same-channel CSA is not
ignored there, but there is still no channel change to observe. So `--csa` **refuses to transmit**
when the cloned beacon's DS Parameter Set (element 3) equals `--chan`:

```
refusing to transmit: --chan 52 is the channel this beacon's DS Parameter Set says the BSS is
already on.  A same-channel CSA announces no move (and with --mode 0 csa_present() discards it
outright, mlme.c:8351).  Pick a different --chan, or pass --allow-same-chan if that is what you
mean to measure.
```

`--allow-same-chan` overrides it. `--action` reads no beacon, so there `--chan` is taken on trust.
For `--nonce`, `--chan` is only the nonce beacon's own DS Parameter Set (default 1): set it to the
channel you parked the interface on.

### `--phy-rate`, plan §B0 rig control 5

Adds one radiotap RATE field (bit 2; one byte in 500 kbps units — `tx.c:2282` matches `rate * 5`
against bitrates kept in 100 kbps units **[V]** — so whole Mbps 1–127) and nothing else: `it_len` 9,
`it_present` `0x00000004`, the byte at offset 8. Keeping `it_len` and the bitmap consistent is the
whole point: `ieee80211_parse_tx_radiotap()` runs *after* the regulatory gate (`tx.c:2445-2446` at
v6.12), a field that would overrun `it_len` is an iterator `-EINVAL` (`radiotap.c:316-319`), and that
is one more silent drop (`tx.c:2251-2252`) **[V]** — the full reading is in the file header. The
selftest asserts `it_len`, the bitmap and the value, and a second host instance captured and cloned a
`--phy-rate 6` beacon over a real socket. Whether mt76 honours the rate on 6 GHz is for the bench;
run the same frame on 5180 as the rate control, as control 5 says.

### `--clone`: the airtime control, and why it is weaker than it looks

Added 2026-11-10, straight after the first 17a run. That run put a CSA-bearing cloned beacon on the
air and **the camera's video feed froze for the duration, identically for `--count 0` and
`--count 3`, recovering by itself afterwards.** The reading that suggests itself is that the client
honoured the announced switch, went to an empty channel and came back. But the run also put ~95
spoofed beacons carrying the AP's own BSSID on the air, and *that* is an equally good explanation
for a frozen feed. Nothing in the experiment separated the two.

`--clone` separates them: it captures one clean beacon from `--bssid` and floods it **verbatim**,
with no CSA and no eCSA appended. Nothing else changes — same socket, same rate, same `--secs`,
same clone-source discipline (a beacon that already carries element 37 or 60 is still skipped,
because a clone of one of those is not a control).

```sh
./pagerinj -i wlan1mon --clone --bssid FC:58:5A:08:42:15 --secs 10
```

**⚠ IT RAN ON 2026-11-10 AND IT IS A WEAKER CONTROL THAN IT LOOKS.** Two runs, 93 and 90 frames,
did nothing to the feed — and then an adversarial pass found out why that was nearly guaranteed.
mac80211 filters beacons it has already seen: `ncrc = crc32_be(0, &mgmt->u.beacon.beacon_int, 4)`
(`mlme.c:6837` at v6.12.61), `parse_params.filter = care_about_ies` (`:6839`),
`ncrc = elems->crc` (`:6853`), and then

```c
if ((ncrc == link->u.mgd.beacon_crc && link->u.mgd.beacon_crc_valid) || …)
        goto free;                                  /* mlme.c:6929 */
```

which sits **ahead of** `ieee80211_rx_bss_info()` (`:6934`) and
`ieee80211_sta_process_chanswitch()` (`:6936`). `care_about_ies` (`:6050-6057`) covers COUNTRY(7),
ERP_INFO(42), CHANNEL_SWITCH(37), PWR_CONSTRAINT(32), HT_CAPABILITY(45), HT_OPERATION(61),
EXT_CHANSWITCH_ANN(60) — and a **verbatim** clone matches on all of it. So on a mac80211 client every
clone after the first hits `goto free` and reaches neither handler. Element 37 being inside that
filter is precisely why the CSA arm gets through.

So what the pair actually establishes:

| result | what it means |
|---|---|
| the feed freezes here too | the element is irrelevant and the experiment has been measuring airtime |
| the feed does **not** freeze | the **five appended bytes** do the work — but "the channel-switch semantics do" does NOT follow, because any CRC-relevant change would also have got through |

Use `--elem` below to close that gap. `--clone` still earns its place: it eliminates the airtime and
duplicate-BSSID half of the confound, which is real.

### `--elem <eid>:<hex>`: the content control `--clone` cannot be

Appends ONE arbitrary element to the clone instead of a CSA, so the beacon's filtered element set
changes — and its `beacon_crc` with it — **without anything announcing a channel switch**.

```sh
./pagerinj -i wlan1mon --elem 32:00 --bssid FC:58:5A:08:42:15 --secs 10
```

`32:00` is Power Constraint with a 1-byte payload: inside `care_about_ies`, semantically a no-op,
and almost never already present in a 2.4 GHz beacon. A freeze here means the client reacts to its
AP's beacon changing at all, and every count result so far is about beacon churn rather than about
channel switching.

**Pick an id inside the filter or the arm is worthless**, and the tool says so: `--elem 221:…`
(vendor-specific) prints a warning, because the filter additionally tracks only the Microsoft
(00:50:F2) and Cisco DTPC OUIs (`mlme.c:6035-6040`), so an arbitrary vendor OUI changes no CRC and
would be a second guaranteed null. The 2026-11-10 adversarial pass proposed exactly that vendor
element and was wrong about it for this reason. It also refuses an id the cloned beacon already
carries, since the client reads the first instance — the same trap `capture_beacon()` avoids for CSA.

### `--mode`: the half of a CSA nobody had separated

Channel Switch Mode 1 — pineapd's value, and this tool's default — **blocks the client's transmit
queues on the first accepted beacon**, independently of the count:
`ch_switch.block_tx = csa_ie.mode` (`mlme.c:2412`), `blocked_tx = csa_ie.mode` (`:2608`),
`if (csa_ie.mode) ieee80211_vif_block_queues_csa(sdata)` (`:2610`). A stalled uplink alone freezes a
video stream — no ACKs, no keepalives. `dev/pager-csa-primitives.md:408` already said this; three
bench sessions reasoned about the count byte without it.

Two arms separate the quiet from the move, and neither needs new code:

```sh
# quiet, with nothing to move to  (announce the channel it is already on)
./run_17a.sh wlan1mon <bssid> 8 8 3 wlan1mon --mode=1
# move announced, no transmit restriction
./run_17a.sh wlan1mon <bssid> 8 1 3 wlan1mon --mode=0
```

If the quiet arm freezes and the move arm does not, the count byte was never in the causal path.
Note `--mode 0` naming the current channel is discarded outright by `csa_present()` (`mlme.c:8379`),
which is why the quiet arm must be mode 1.

### `--count-dec`: a real AP counts down, and this never did

A conformant AP **decrements** the Channel Switch Count on every beacon — 3, 2, 1 — and switches
when it runs out. `pagerinj` used to transmit a **constant** count, which no AP ever sends, and a
client that tracks the countdown has nothing to track in a constant stream.

**⚠ IT RAN ON 2026-11-10 AND THE ARM WAS CONTAMINATED.** `count_dec_step` wrapped through **0**, so
the bench run's `23 complete countdown(s)` with `sent=92` — and 92 = 4 × 23 exactly — means 23 of
the 92 frames carried count 0, *including the last frame on the air* before the operator watched for
reconnection. An arm built to test count ≥ 1 strictly contained the separate count-0 condition, so
no claim of the form "count N behaves like count 0" could come from it. **Fixed: it floors at 1 and
the log reports frames by count rather than how many times it wrapped** — which is how the
contamination stayed invisible for a whole bench pass. Flooring at 1 is also the faithful model: per
802.11 the count is TBTTs remaining, so a real AP beacons 3, 2, 1 and then switches, and never
announces 0 on the channel it is leaving.

A second correction worth having: decrementing was never the right instrument for the *denial*
question anyway. By this repo's own `[V]` reading (`dev/pager-csa-primitives.md:413`) **any** count
1-255 survives `csa_present()`, so a constant count 3 was already maximally eligible. Decrementing
belongs to the move/tracking path.

```sh
./pagerinj -i wlan1mon --csa --bssid FC:58:5A:08:42:15 --chan 1 --count 3 --count-dec --secs 10
```

It rewrites the count byte **in place** in the already-built frame, so nothing else about the frame
changes between transmissions — the selftest asserts exactly that, one byte differing per step. The
byte is located by *searching* the built frame for element 37 rather than by computing
`RTAP_TX_LEN + clone_len + 4`: that offset depends on the radiotap length, which `--phy-rate`
changes, and a wrong offset would not fail, it would silently rewrite an arbitrary byte of the frame
once per transmission. After reaching 1 the countdown restarts, so a `--secs` window gives the
client several complete countdowns instead of one short burst at the start; the run reports frames
by count. With `--ecsa-count` both counts step together.

The cadence is close to faithful: the 2026-11-10 run put ~109 ms between steps against a real AP's
102.4 ms TBTT, within about 7%. What is still unfaithful is structural — the countdown restarts
instead of switching and going quiet, and the genuine AP keeps beaconing CSA-free alongside, which
on a mac80211 client **aborts the pending switch** (`mlme.c:2452`) roughly every 100 ms. That is why
17a as built cannot produce a completed count ≥ 1 switch against an AP still on the air.

`--count 0 --count-dec` and `--count 1 --count-dec` are both refused: 0 is the "switch immediately"
condition and a separate arm, and 1 would step 1 → 1 forever, a constant stream that the log would
call a countdown.

### 17a's third arm, and why it beats the pair

`ieee80211_mgd_csa_present()` discards **per element** — `if (csa && csa->count == 0) csa = NULL;`
then the same for `ecsa`, then `return csa || ecsa`. So element 37 with count 0 *plus* an eCSA (60)
with a non-zero count returns true while pineapd's own bytes stay byte-identical. The two-arm
version of 17a cannot separate *"the count value is what disqualifies it"* from *"element 37 is the
one that gets looked at"*; this arm can.

`--ecsa-opclass` has **no default on purpose** — though not because a wrong class gets the element
ignored, which was the original reason here and is wrong. The denial arm never reads the class at
all (`csa_present()` reads only datalen, count, mode and new_ch_num), and the move arm *falls back*:
`spectmgmt.c:259` zeroes an unparseable class and `:272` re-reads element 37 **including its count**,
so with `--count 0 --ecsa-count N` a wrong class quietly takes element 37's `0` instead of the
eCSA's `N` and you measure an immediate switch where you meant a delayed one. It changes what the
move arm measures rather than breaking it. Read the value off the target's own Supported Operating
Classes element.

### The action frame (`--action`), step 17c

Category **0**, action **4** — not 17b's category 4. `mac80211_mlme.c:7506` tags it `PROT_ACTION`
from the category alone with no check that it arrived protected, and the protection filter only
runs under MFP, so on a **non-PMF BSS** an unprotected one is acted on. Unicast, so no flood and no
beacon race. Constraints baked into the builder and asserted in the selftest: **A3 must equal the
BSSID** (`rx612.c:3738`; a wrong A3 is dropped with no log), A1 is the client, the client must be
associated, and the frame clears `IEEE80211_MIN_ACTION_SIZE + sizeof(u.action.u.chan_switch)` — 31
bytes against a 26-byte gate.

## Build

Needs the OpenWrt SDK once (192 MB) and the `zstd` binary (`tar --zstd` shells out to it):

```sh
curl -LO https://downloads.openwrt.org/releases/24.10.1/targets/ramips/mt76x8/openwrt-sdk-24.10.1-ramips-mt76x8_gcc-13.3.0_musl.Linux-x86_64.tar.zst
tar --zstd -xf openwrt-sdk-24.10.1-*.tar.zst
make SDK=$PWD/openwrt-sdk-24.10.1-ramips-mt76x8_gcc-13.3.0_musl.Linux-x86_64
make SDK=... verify            # the ABI gate — do not skip it
scp pagerinj root@172.16.52.1:/tmp/
```

Verified output at this change, `gcc 13.3.0 r28597-0425664679` from the SDK the Makefile names
(archive sha256 checked against the release's `sha256sums` before extraction), byte-reproducible
across two rebuilds. These figures move with every edit to `pagerinj.c`; trust your own `stat` and
`sha256sum` over this row:

*(Rebuilt and re-recorded **2026-11-10** twice: for the `--clone`/`--count-dec` commit and again for the `PARTIAL RUN` warning that the first bench pass of those modes showed was needed. The previous
row -- 25468 bytes, `4cf33e5b…b471` -- described the source before those modes existed. Since
`.gitignore` excludes the binaries on purpose, this table is the ONLY record of them in the repo,
which is exactly why it has to move in the same commit as any `pagerinj.c` edit; it has now failed
to do that once, in `df756c3`, so check it rather than trusting it. Verified this time: the SDK
archive's sha256 matched the release's `sha256sums` (`636298c2…5c92`) before extraction, the ABI
gate below passed, two clean rebuilds produced byte-identical output, and
`./pagerinj-host --selftest` gave **126 checks, 0 failed**. Re-recorded a third time the same day, for the `--elem` content control and the `--count-dec` floor fix.)*

| | |
|---|---|
| `pagerinj` | 36476 bytes, sha256 `d44fd10e…8a21` (full: `d44fd10e2fe41d5f58667afe27cfd220e7cfb71312a943152864e5542a668a21`) |
| ABI | `ELF32 LSB MIPS32r2`, little endian, interpreter `/lib/ld-musl-mipsel-sf.so.1` |
| `NEEDED` | `libc.so` only |
| `make static` | 109776 bytes, sha256 `795e07da…f2fa`, no loader, no libc — if the dynamic build ever fails on the device |

*(Update 2026-11-02: `libgcc_s.so.1` **does** ship, byte-identical in 1.1.3 and 2.0.0 —
`8138ad10…9dfcb`, 131359 B. So the flag below is now insurance rather than a fix for a known gap.
Keeping it: a few KB to drop a runtime dependency is still the right trade for a bench tool.)*

`-static-libgcc` is deliberate: the default link wants `libgcc_s.so.1`, which is the one library
`dev/pager-prearrival.md` §3 flags as **unverified** on the Pager. Linking it in costs a few KB and
removes a dependency the device has since been shown to carry.

Binaries are `.gitignore`d — build them, don't commit them.

## Validation done without a radio

```sh
make host && ./pagerinj-host --selftest        # 126 checks, 0 failed
```

The selftest covers the CSA element against the bytes pineapd writes at `0x4bee8a`
(`{37,3,1,ch,0}`), the append path over a captured-beacon fixture, the nonce beacon's layout,
radiotap parsing including the trailing-FCS trap and the extended-bitmap walk (asserted on where
FLAGS is read from, not only on the return code), and the rejection paths the cases name: truncated
header, non-zero version, `it_len` past the buffer or below 8, a radiotap-only capture, a capture too
short for its claimed FCS, a non-beacon, undersized output buffers, an over-long nonce. Not *every*
rejection path: a gcov pass of the selftest at this change shows the `(in[1] & 0x0c)` half of
`csa_frame_build()`'s non-beacon check never taken (the non-beacon case fails on `in[0]`). The
load-bearing case is **"17a control: arms differ in exactly ONE byte"** — if that ever fails, step
17a is not a controlled comparison and its result means nothing.

It also runs the real receive loop: `capture_beacon()` is fed, over a socketpair, a beacon from the
BSSID that already carries pineapd's `{37,3,1,52,0}` and then a clean one, and must return the clean
one with the other counted as skipped; a hard `recv()` error (a closed descriptor) must return at
once with `errno`, not the channel hint.

`strip_capture()` exists as a separate pure function because `csa_frame_build()` appends at
`in_len` with no FCS handling of its own — correct only if the capture was already shortened, and
by then radiotap is gone so there is no flag left to read. A review pointed out the old selftest
*implied* that invariant without asserting it. It is asserted now, and the assertions were
**mutation-tested**: deleting the `flen -= 4` fails four checks, including
"CSA element directly follows the last IE, not the FCS" and "no 0xde FCS byte survives into the
frame". A test that passes but would not catch the bug is worse than no test.

The cases added at this change were mutation-tested the same way, each on a scratchpad copy:
extended-bitmap walk disabled, clone-source skip removed, `--allow-same-chan` ignored, same-channel
check removed, `--phy-rate` `it_len` left at 8, its present bit dropped, the nonce clamp restored,
`recv()` errno swallowed, each of the two rejection arms removed, trailing garbage accepted by the
number parser. Every mutation fails at least one named check.

The transmit path was then exercised end-to-end over a `veth` pair, with one instance beaconing as
the AP and another capturing, cloning and re-transmitting it. On the wire:

```
count=0:  ...63336434 030134 2503013400
count=3:  ...63336434 030134 2503013403
                             ^^^^^^^^^^ element 37, len 3, mode 1, ch 52, count
71 bytes each, differing in exactly 1 byte, at offset 70 — the CSA count.
```

(Recorded before the same-channel refusal existed: both frames announce ch 52 from a ch-52 beacon,
which the tool now refuses without `--allow-same-chan`. The byte-identity argument is unchanged.)

So capture → clone → append → transmit is proven on real sockets with real bytes. Exercised the same
way at this change, on a laptop's `lo` and `eth0`: with the socket **bound to `-i`**, a beacon
transmitted only on `lo` no longer satisfies a capture on `-i eth0` — it did before, which was the
defect — while the same capture on `-i lo` still clones it. A second instance flooding CSA-bearing
clones of a BSSID makes a capture of that BSSID end with `skipped 294 beacon(s) from this BSSID that
already carried a CSA (37) or eCSA (60) element` instead of cloning one of them. Under `--secs 0`,
SIGINT and SIGTERM both end with `interrupted: sent=40 failed=0 …`.

**What is not proven is anything involving a radio**: that a frame reaches the air, that a client
reacts, or that a non-zero count produces the auth/assoc refusal. That last one is `[A]` throughout
the docs — derived from `ieee80211_mgd_csa_present()`, not measured.

## Use

```sh
# FIRST, every time, before any transmit: stop pineapd.  Plan §B0 rig control 1: "If the hopper
# moves wlan1mon before dequeue, the frame goes out on another channel and the parked receiver sees
# nothing — which would be scored as a kernel gate."  §B4 opens with exactly this line.  (Control 1's
# own command, `uci set pineapd.wlan1mon.hop=0; uci commit pineapd; /etc/init.d/pineapd restart`,
# only stops the hopping and leaves pineapd — and its CSA flood, a CSA-bearing clone source the
# 17a capture would have to skip — running; for pagerinj the stop is the right one.)
/etc/init.d/pineapd stop; sleep 2; ip link set wlan1mon up

# B4 / step 13 — prove transmission on a DFS channel.  Set the channel FIRST.  Here --chan is the
# nonce beacon's own DS Parameter Set, so it names the channel you parked on.
iw dev wlan1mon set freq 5260 20
pagerinj -i wlan1mon --nonce PAGERINJ-$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' ') \
         --chan 52 --rate 20 --secs 15
# receiver, separate adapter, already parked on ch 52:
#   tshark -i wlanX -Y 'wlan.ssid contains "PAGERINJ"'

# 17a — the count-byte pair.  Same frame, same flood, one byte different.  The AP is on ch 52, so
# --chan names a DIFFERENT channel: a CSA to the channel the BSS is already on announces no move,
# and pagerinj refuses it unless --allow-same-chan is given.
pagerinj -i wlan1mon --csa --bssid AA:BB:CC:DD:EE:FF --chan 36 --count 0 --rate 20 --secs 30
pagerinj -i wlan1mon --csa --bssid AA:BB:CC:DD:EE:FF --chan 36 --count 3 --rate 20 --secs 30

# when done — §B4's rollback:
iw dev wlan1mon set freq 2437 20; /etc/init.d/pineapd start
```

Run the `count = 0` arm first: it is the negative control, and `"AP is in CSA process, reject
assoc"` **cannot** appear for it. If it does, the count-0 finding is wrong and that is a bigger
result than the experiment.

## Two things it will not tell you

- **`sendto()` succeeding means nothing.** A cfg80211-blocked frame is freed and the path returns
  `NETDEV_TX_OK`, so the `sent=` counter counts calls, not transmissions. Only the external
  receiver can tell you a frame was transmitted. The tool prints this on exit for a reason — when
  `--secs` expires and, under `--secs 0`, on SIGINT/SIGTERM (prefixed `interrupted:`). A hard
  `recv()` error during the beacon wait prints `recv: <strerror>` and exits 1 instead of the
  "is the interface on the target's channel?" hint, which is reserved for a wait that saw nothing.
- **It does not read the regulatory state.** Pair it with day-one step 8 (`iw reg get`,
  `iw phy <phy> channels`); on its own a silence is uninterpretable.
