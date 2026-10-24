# pagerinj — the Stage-B injector

A ~250-line AF_PACKET sender for the Pager bench work. **It never touches the channel**; whatever
`iw dev <if> set freq` left is what it uses.

Built and validated with **no hardware**. What it is for, and the reasoning behind every design
choice, is in the header comment of `pagerinj.c` — read that before changing it.

## Why not hcxdumptool or aireplay-ng

`dev/pager-6ghz-determination-plan.md` §B3 rules out aireplay-ng because "its osdep layer has its
own channel handling and would add a gate to an experiment whose whole purpose is isolating gates."
**hcxdumptool manages its channel too**, so the same objection applies to it — which is worth
knowing, because §B4's transmit step names it. Treat the pre-staged `hcxdumptool` ipk
(`dev/pager-prearrival.md` §3) as a cross-check, not the primary instrument. **[A]** — from reading
hcxdumptool's interface, not from running it; falsified by a documented mode that transmits on the
interface's existing channel without setting it.

Neither tool can build a CSA frame at all (§B3 limitation note), which is what step 17a needs.

## The three jobs

| Job | Mode | Where |
|---|---|---|
| Prove a frame left the antenna on a gate-1 channel | `--nonce` | day-one step 13, plan §B4 |
| Set a non-zero CSA Channel Switch Count | `--csa --count N` | day-one step 17a |
| Choose the send rate (the ~100 ms BSS-cache race) | `--rate` | both |

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
| `pagerinj` | 11436 bytes, sha256 `00d63e86…a6a2` |
| ABI | `ELF32 LSB MIPS32r2`, little endian, interpreter `/lib/ld-musl-mipsel-sf.so.1` |
| `NEEDED` | `libc.so` only |
| `make static` | 84096 bytes, no loader, no libc — if the dynamic build ever fails on the device |

`-static-libgcc` is deliberate: the default link wants `libgcc_s.so.1`, which is the one library
`dev/pager-prearrival.md` §3 flags as **unverified** on the Pager. Linking it in costs a few KB and
removes a dependency nobody can check until the device is in hand.

Binaries are `.gitignore`d — build them, don't commit them.

## Validation done without a radio

```sh
make host && ./pagerinj-host --selftest        # 29 checks, 0 failed
```

The selftest covers the CSA element against the bytes pineapd writes at `0x4bee8a`
(`{37,3,1,ch,0}`), the append path over a captured-beacon fixture, the nonce beacon's layout,
radiotap parsing including the trailing-FCS trap, and every rejection path. The load-bearing case
is **"17a control: arms differ in exactly ONE byte"** — if that ever fails, step 17a is not a
controlled comparison and its result means nothing.

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
