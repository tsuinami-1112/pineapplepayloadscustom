# pagerinj — the Stage-B injector

An AF_PACKET sender for the Pager bench work. **It never touches the channel**; whatever
`iw dev <if> set freq` left is what it uses. Its capture socket is bound to `-i`, so what it clones
is what that interface heard and nothing else.

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

| | |
|---|---|
| `pagerinj` | 25436 bytes, sha256 `c8526840…7fdf` |
| ABI | `ELF32 LSB MIPS32r2`, little endian, interpreter `/lib/ld-musl-mipsel-sf.so.1` |
| `NEEDED` | `libc.so` only |
| `make static` | 98288 bytes, sha256 `706e138c…7033`, no loader, no libc — if the dynamic build ever fails on the device |

`-static-libgcc` is deliberate: the default link wants `libgcc_s.so.1`, which is the one library
`dev/pager-prearrival.md` §3 flags as **unverified** on the Pager. Linking it in costs a few KB and
removes a dependency nobody can check until the device is in hand.

Binaries are `.gitignore`d — build them, don't commit them.

## Validation done without a radio

```sh
make host && ./pagerinj-host --selftest        # 82 checks, 0 failed
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
