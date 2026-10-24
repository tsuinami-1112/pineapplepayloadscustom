# pagerinj — the Stage-B injector

A ~250-line AF_PACKET sender for the Pager bench work. **It never touches the channel**; whatever
`iw dev <if> set freq` left is what it uses.

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

## The three jobs

| Job | Mode | Where |
|---|---|---|
| Prove a frame left the antenna on a gate-1 channel | `--nonce` | day-one step 13, plan §B4 |
| Set a non-zero CSA Channel Switch Count | `--csa --count N` | day-one step 17a |
| Keep pineapd's element intact but add a live eCSA count | `--csa --ecsa-count N` | 17a's third arm |
| Unicast Spectrum-Management CSA to one client | `--action --client <mac>` | day-one step 17c |
| Choose the send rate (the ~100 ms BSS-cache race) | `--rate` | all of them |

### 17a's third arm, and why it beats the pair

`ieee80211_mgd_csa_present()` discards **per element** — `if (csa && csa->count == 0) csa = NULL;`
then the same for `ecsa`, then `return csa || ecsa`. So element 37 with count 0 *plus* an eCSA (60)
with a non-zero count returns true while pineapd's own bytes stay byte-identical. The two-arm
version of 17a cannot separate *"the count value is what disqualifies it"* from *"element 37 is the
one that gets looked at"*; this arm can.

`--ecsa-opclass` has **no default on purpose**: a wrong operating class gets the element ignored for
a reason that looks exactly like the gate under test. Read it off the target's own Supported
Operating Classes element.

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

Verified output, `gcc 13.3.0 r28597-0425664679`, byte-reproducible across rebuilds:

| | |
|---|---|
| `pagerinj` | 17308 bytes, sha256 `74132ba0…a8f9` |
| ABI | `ELF32 LSB MIPS32r2`, little endian, interpreter `/lib/ld-musl-mipsel-sf.so.1` |
| `NEEDED` | `libc.so` only |
| `make static` | 84096 bytes, no loader, no libc — if the dynamic build ever fails on the device |

`-static-libgcc` is deliberate: the default link wants `libgcc_s.so.1`, which is the one library
`dev/pager-prearrival.md` §3 flags as **unverified** on the Pager. Linking it in costs a few KB and
removes a dependency nobody can check until the device is in hand.

Binaries are `.gitignore`d — build them, don't commit them.

## Validation done without a radio

```sh
make host && ./pagerinj-host --selftest        # 59 checks, 0 failed
```

The selftest covers the CSA element against the bytes pineapd writes at `0x4bee8a`
(`{37,3,1,ch,0}`), the append path over a captured-beacon fixture, the nonce beacon's layout,
radiotap parsing including the trailing-FCS trap, and every rejection path. The load-bearing case
is **"17a control: arms differ in exactly ONE byte"** — if that ever fails, step 17a is not a
controlled comparison and its result means nothing.

`strip_capture()` exists as a separate pure function because `csa_frame_build()` appends at
`in_len` with no FCS handling of its own — correct only if the capture was already shortened, and
by then radiotap is gone so there is no flag left to read. A review pointed out the old selftest
*implied* that invariant without asserting it. It is asserted now, and the assertions were
**mutation-tested**: deleting the `flen -= 4` fails four checks, including
"CSA element directly follows the last IE, not the FCS" and "no 0xde FCS byte survives into the
frame". A test that passes but would not catch the bug is worse than no test.

The transmit path was then exercised end-to-end over a `veth` pair, with one instance beaconing as
the AP and another capturing, cloning and re-transmitting it. On the wire:

```
count=0:  ...63336434 030134 2503013400
count=3:  ...63336434 030134 2503013403
                             ^^^^^^^^^^ element 37, len 3, mode 1, ch 52, count
71 bytes each, differing in exactly 1 byte, at offset 70 — the CSA count.
```

So capture → clone → append → transmit is proven on real sockets with real bytes. **What is not
proven is anything involving a radio**: that a frame reaches the air, that a client reacts, or that
a non-zero count produces the auth/assoc refusal. That last one is `[A]` throughout the docs —
derived from `ieee80211_mgd_csa_present()`, not measured.

## Use

```sh
# B4 / step 13 — prove transmission on a DFS channel. Set the channel FIRST.
iw dev wlan1mon set freq 5260 20
pagerinj -i wlan1mon --nonce PAGERINJ-$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' ') \
         --chan 52 --rate 20 --secs 15
# receiver, separate adapter, already parked on ch 52:
#   tshark -i wlanX -Y 'wlan.ssid contains "PAGERINJ"'

# 17a — the count-byte pair. Same frame, same flood, one byte different.
pagerinj -i wlan1mon --csa --bssid AA:BB:CC:DD:EE:FF --chan 52 --count 0 --rate 20 --secs 30
pagerinj -i wlan1mon --csa --bssid AA:BB:CC:DD:EE:FF --chan 52 --count 3 --rate 20 --secs 30
```

Run the `count = 0` arm first: it is the negative control, and `"AP is in CSA process, reject
assoc"` **cannot** appear for it. If it does, the count-0 finding is wrong and that is a bigger
result than the experiment.

## Two things it will not tell you

- **`sendto()` succeeding means nothing.** A cfg80211-blocked frame is freed and the path returns
  `NETDEV_TX_OK`, so the `sent=` counter counts calls, not transmissions. Only the external
  receiver can tell you a frame was transmitted. The tool prints this on exit for a reason.
- **It does not read the regulatory state.** Pair it with day-one step 8 (`iw reg get`,
  `iw phy <phy> channels`); on its own a silence is uninterpretable.
