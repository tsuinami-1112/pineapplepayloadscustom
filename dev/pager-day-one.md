# Pager — order of operations

Bench checklist. The reasoning, exact commands, rollbacks and early exits live in
`dev/pager-6ghz-determination-plan.md`; this is the running order and why each step sits where it
does. Gate facts: `dev/pager-csa-primitives.md`.

**Three rules behind the ordering.** Nothing irreversible before a *tested* restore. Every
decisive-but-free test before any modification. DFS before 6 GHz — it is the bigger win, needs
less, and it proves the measurement rig.

---

## Before the Pager arrives

> Steps 1–6 have already been taken as far as they go without hardware — firmware pin re-checked,
> recovery image verified, injector pre-staged so the chamber needs no network, `iw` output format
> confirmed against the shipped binary, and `inj_probe()`'s parser validated (one defect found and
> fixed). Read `dev/pager-prearrival.md` before re-doing any of it.

**1. Validate the receiver, alone.** Prove the 6E adapter hears both bands against a source that
is not the Pager — a 6E phone hotspot or 6E AP, and any 5 GHz AP parked on ch 52.

```sh
uname -r                       # note it; mt7921u monitor mode is regression-prone by version
iw reg get                     # must NOT be country 00
iw phy phy0 channels | grep -A2 '5260\|6135'
ip link set wlan0 down; iw dev wlan0 set type monitor; ip link set wlan0 up
iw dev wlan0 set channel 52    # then: iw dev wlan0 set freq 6135
tcpdump -i wlan0 -nn type mgt subtype beacon
```

Beacons on both → the rig works, and every later silence is the Pager's fault. **This is the whole
point of an independent receiver; do it first or every later result is uninterpretable.**

**2. Confirm you have a 6 GHz AP and a real 6 GHz client** for the chamber. The value gate (step 9)
cannot run without them.

---

## First contact — before anything is changed

**3. Do NOT let it update firmware.** Every address, offset and sha256 in our analysis is pinned to
**1.1.3-stable**. An update moves them and invalidates the pineapd work. Check the version, record
it, and decide deliberately.

**4. Baseline, off-device.** Hashes of `pineapd`, `regulatory.db`, `iw`, `hak5cmd`, the `.ko` files;
`uci export`; full `iw phy` / `iw reg get` state; the flash dumps. Pull them off the device.

**5. Prove the restore path works** *before* you need it. A backup you have not restored from is a
hypothesis.

**6. Check the board revision** against `Pager V2.2.0` (2025/06/03) from the FCC photos. A different
board means re-checking the hardware assumptions in Addendum 2b/2c.

---

## Free reads that decide everything

**7. The decisive hardware test.**

```sh
iw phy "$PHY" info | grep -E "^[[:space:]]+Band [0-9]+:"
```

`Band 4:` present → the 6 GHz PHY is there. The FCC filing says it should be, so treat a FAIL as
surprising and re-check the phy mapping before believing it. Regdomain-independent — do not re-run
it under different countries.

**8. Capture the real regulatory state.** Two outputs, saved verbatim:

```sh
iw reg get                            # which domain is actually live?
iw phy "$PHY" channels                # per-channel disabled / No IR / Radar detection
uci get pineapd.wlan1mon.bands        # does pineapd even scan band 6?
```

This settles whether the device runs US or world domain — the open question behind CamHound's
fallback — and it is the **first live-device input to `inj_probe()`'s parser**. The parser has
already been validated against a fixture built from the shipped `iw`'s own format strings, which
found and fixed one over-permissive defect (`dev/pager-prearrival.md` §5), so this is a
confirmation rather than first contact. Still diff what `inj_probe` produced against the raw text
by hand, once — a real device can emit attribute lines the fixture did not.

**9. THE VALUE GATE — a beacon capture plus the real client, before spending effort on 6 GHz.**
Beacon protection takes **both** an AP that enables it and a client that can enforce it, so the
capture below settles the AP half cheaply and the client half still needs the client. Capture one
beacon from the 6E AP and read two fields:

**Capture to a file first, then filter.** Do not use `-c` with `-Y` on a live monitor interface:
`-c` is a *capture* autostop count applied before the display filter, so it stops after the first N
frames from anything on the channel and will usually print nothing at all. Capturing nothing is not
a result.

```sh
# capture with a CAPTURE filter and a time bound, not a packet count
tshark -i wlan0 -f 'type mgt subtype beacon' -a duration:15 -w /tmp/bp.pcap

# 1. does the AP advertise beacon protection? (Ext Cap bit 84). Print the tag list too, so an
#    absent Extended Capabilities element is distinguishable from a present-but-zero bit.
tshark -r /tmp/bp.pcap -Y 'wlan.bssid==<AP>' -T fields -e wlan.tag.number -e wlan.extcap.b84

# 2. are its beacons actually carrying an MMIE? (element 76)
tshark -r /tmp/bp.pcap -Y 'wlan.bssid==<AP> && wlan.tag.number==76' | wc -l
```

Confirm you captured the AP at all (`tshark -r /tmp/bp.pcap -Y 'wlan.bssid==<AP>' | wc -l`) before
reading anything into an empty result. Both present → that AP enables beacon protection. Neither →
it does not, and beacon CSA moves clients. Expect "on" to be common: hostapd enables `beacon_prot`
by itself whenever 11be is on with PMF.

**This answers the AP's policy, not the client's behaviour.** Enforcement needs the client to hold
a BIGTK, which `nl80211` refuses unless the client's driver advertises
`NL80211_EXT_FEATURE_BEACON_PROTECTION[_CLIENT]` — and hostapd distributes the BIGTK without
checking. So a bit-84 AP can still have clients that enforce nothing. **The real 6 GHz client is
required to finish this step.**

If protection is being enforced, know what still works before declaring the branch dead:
probe-response CSA moves nothing in station mode, and an unprotected Public-Action eCSA stalls the
client's TX queues rather than switching it (persistently — the unblock sits behind a beacon-CRC
short-circuit) — but **connection denial survives beacon protection as a mechanism**. A forged CSA
beacon reaches the BSS cache ahead of the protection check, and mac80211 then refuses auth and
assoc while a cached CSA is present. Deauth is dead by standard (PMF mandatory).

**You cannot reach that mechanism with stock firmware.** pineapd's CSA carries Channel Switch
Count = 0 and the kernel discards a count-0 CSA before the refusal check — see step 17a. Denial
therefore costs the Stage-B injector, so it is a Stage-B deliverable, not something this step can
hand you.

> **If the deliverable is "the client changes channel", this step may stop the 6 GHz branch. If it
> is "the camera stops working", the branch survives — but only via the Stage-B injector with
> `count != 0`.** Decide which you need, price in the injector if it is the second, and record
> which effect you measured. Either way the DFS branch is unaffected.

---

## DFS branch — the real win

Needs no regdomain change, no custom regdb, no kernel change. pineapd's hardcoded bitmask is the
only obstacle.

**10. Confirm no `NO-IR` on 5260 / 5500** in the step-8 capture. Under US there should be none —
`DFS`/`Radar detection` yes, `No IR` no.

**11. Watch pineapd refuse ch 52**, and attribute it correctly. **The log wording lies**: the DFS
branch loads the 6 GHz format string. A line reading `"{} can not inject on 6GHz restricted
channel"` *with* an interface-name prefix is a **5 GHz DFS** refusal. Attribute by prefix, never by
the words.

**12. Get an injector that is not pineapd.** This is what bypasses gate 1; `pcap_inject` has exactly
one call site, inside the gated function. **Use `pagerinj`** — built, ABI-verified and
frame-validated without hardware, 15.6 KB, `scp` it to `/tmp`: `dev/injector/`. It never sets the
channel and holds no regulatory opinion, which is what makes it a clean probe, and it is the only
one of the three that can build a CSA frame at all — step 17a needs that.

**`hcxdumptool` splits by band, and the 6 GHz half is a trap.** Settled against the 6.3.4 tag: it
reads only `FREQUENCY_ATTR_FREQ`, `MAX_TX_POWER` and `DISABLED` — **no `NO_IR`, no `RADAR`** **[V]**.
So:

- **On 5 GHz DFS it is a good cross-check.** ch 52 reports only `Radar detection`, which it never
  looks at, so it arms and transmits. Run it pinned — `-c 52b` — as an independent second
  instrument alongside `pagerinj`. Pre-staged per `dev/pager-prearrival.md` §3
  (`opkg -d ram install /tmp/hcxdumptool_6.3.4-r1_mipsel_24kc.ipk`, no network needed).
- **On 6 GHz do not use it at all.** It does not read `NO_IR`, so it arms and transmits happily —
  and gate 2 *does* prohibit `NO_IR`, so mac80211 frees every frame and returns `NETDEV_TX_OK`.
  Its `send_80211_*` only compares `write()`'s return against the length, `PACKET_IGNORE_OUTGOING`
  on its RX socket means it never sees its own frames, and its TX counters count attempted writes.
  **It will report success while nothing leaves the antenna.**

Three things about it that cost bench time, all **[V]**:

- **A regulatory refusal looks like a driver fault.** You will never see `failed to set frequency`
  on a capture run — that string is in the `-m` path, downstream of the `set_interface()` call that
  already failed. You get `failed to arm interface` and *"driver is broken / driver is busy"*. Do
  not grep for the string in the binary; it will not appear.
- **It randomises your MAC, forces monitor mode, kills powersave, and restores none of it.**
  `rt_set_interfacemac()` at `:3908`, and a *failure* there only clears a flag rather than aborting.
- **It transmits unasked** — deauth, probe-request, assoc and reassoc flags all default true
  (`:52–55`). Use all five `--disable_*` flags or your gate test has company on the air.

**13. Inject on ch 52 and confirm at the external 5 GHz receiver.** Not `wlan0mon` — `radio0` is
`band '2g'` and cannot hear ch 52; its silence would be silence either way. Run the negative control
(Pager idle, require zero matches) and the positive control (ch 5180, same invocation) or the result
means nothing.

```sh
iw dev wlan1mon set freq 5260 20          # set the channel yourself; pagerinj will not
pagerinj -i wlan1mon --nonce PAGERINJ-$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' ') \
         --chan 52 --rate 20 --secs 15
# receiver, separate adapter, already parked on 52:
#   tshark -i wlanX -Y 'wlan.ssid contains "PAGERINJ"'
```

The nonce is in the SSID **and** in the source MAC, so the frame is identifiable two independent
ways. `pagerinj`'s `sent=` counter is **not** evidence — a gate-2 drop returns `NETDEV_TX_OK`, so it
counts calls, not transmissions. Only the receiver decides.

**14. Attribute the gates** side by side on the same channel: pineapd refusing vs cfg80211 dropping
vs it actually transmitting.

---

## 6 GHz branch — only if step 9 cleared it

**15. The cheap test first, before patching anything.** Issue the same 6 GHz target twice — once
with the channel spelled `"37W6e"`, once as a plain frequency — and compare the log. The band field
that triggers pineapd's 6 GHz refusal is written at exactly one instruction, in `from_string`'s
`"%uW6e"` branch; hardware-derived channels carry a different encoding entirely. **If only the first
is refused, Stage C is unnecessary and 6 GHz is far cheaper than the plan assumes.**

**16. Clear `NO_IR` without touching a file** — `iw reg set` to a domain whose 6 GHz rule lacks
`NO-IR` (GB's 5925–6425 does; US sets it). Re-run step 8 and confirm the per-channel flags actually
changed. Set `uci set wireless.radio1.country=` too so netifd does not revert it.

**17. Inject on 6 GHz, confirm at the receiver.** Tune the receiver *first* — a `NO-IR` channel is
passive-only, so scanning will never find it.

**17a. THE COUNT BYTE — the cheapest high-value experiment on this list.** pineapd builds every CSA
with **Channel Switch Count = 0** (`0x4bee8a`), and `ieee80211_mgd_csa_present()` discards a count-0
CSA before the auth/assoc refusal check. So pineapd's CSA can kick a client but can never deny it a
reconnection. Any non-zero count survives that check.

The Stage-B injector is already built: `dev/injector/` (`pagerinj`). Send the **same frame twice,
differing only in that byte** — `count = 0`, then `count = 3`:

```sh
pagerinj -i wlan1mon --csa --bssid <AP> --chan 52 --count 0 --rate 20 --secs 30   # control
pagerinj -i wlan1mon --csa --bssid <AP> --chan 52 --count 3 --rate 20 --secs 30
```

**Run a third arm — it is better than the pair and costs one more invocation.**
`ieee80211_mgd_csa_present()` discards **per element**:

```c
if (csa  && csa->count  == 0)  csa  = NULL;
if (ecsa && ecsa->count == 0)  ecsa = NULL;
return csa || ecsa;
```

So a frame carrying pineapd's element 37 with count 0 **plus** an eCSA (60) with a non-zero count
returns true — while leaving pineapd's own bytes untouched:

```sh
pagerinj -i wlan1mon --csa --bssid <AP> --chan 52 --count 0 \
         --ecsa-count 3 --ecsa-opclass <N> --rate 20 --secs 30
```

The two-arm version cannot distinguish **"the count value is what disqualifies it"** from
**"element 37 is the one that gets looked at"**. This arm can, because it changes which element
carries the live count without changing the count byte pineapd writes.

Read `--ecsa-opclass` off the target's own Supported Operating Classes element. It is deliberately
not defaulted, but **not** for the reason an earlier revision of this line gave — a wrong class does
*not* get the element ignored. The denial arm never reads the class at all, and on the move path a
bad one zeroes `new_op_class` and **falls back to element 37's count**, which in this arm is 0. So a
wrong class silently turns the move arm's delayed switch into an immediate one while leaving the
denial arm untouched. It changes what you measure rather than breaking it, which is worse.

**Also: leave `--mode` alone.** `csa_present()` discards any element with mode 0 that announces the
channel the target is already on, before the count is even considered — so `--mode 0` plus the
current channel is a silent no-op. pineapd hardcodes mode 1; so does `pagerinj` by default, and it
warns if you override it. Both points: `dev/pager-csa-primitives.md`
§"Four refinements, read at upstream v6.12".

It clones a real beacon from `--bssid` and appends the element, which is what
`recon_engine::index_beacon_ns` does, so the only difference from pineapd's frame is the byte under
test. That one-byte property is asserted in the tool's selftest and was confirmed on the wire
(71-byte frames, differing at offset 70 only) — see `dev/injector/README.md`. Run the `count = 0`
arm **first**: it is the negative control, and `"AP is in CSA process, reject assoc"` cannot appear
for it. If it does, the count-0 finding is wrong, which is a bigger result than the experiment.
Watch whether the client can re-associate while each flood runs. Use the jammer (or a power cycle) to force the disconnect, since
deauth cannot: this is the one target class where PMF makes the usual kick unavailable. Run the
jam-only control first and confirm the client *does* come back without the flood, or the result
means nothing.

There is no setting for the count — do not go looking for one. Patching pineapd's instruction is
possible but global, costs ~200 ms on the working attack, and is not a clean one-byte edit (the zero
register is reused two instructions earlier to NUL-terminate a string). Prefer the injector. Full
working: `dev/pager-csa-primitives.md`, section "THE ONE BYTE".

**17b. If beacon protection is being enforced, test the two remaining outside paths.**

*Connection denial* first, because it is the better outcome — but it is **not** free and it does
**not** use the frame pineapd builds. That frame carries count = 0 and is discarded before the
refusal check (step 17a), so flooding it tests nothing: the null result would read as "denial does
not work" when what you actually sent was disqualified by its own contents. Run it as the
`count = 3` arm of step 17a instead — same injector, same flood, one byte different — then make the
client disconnect and try to reconnect. A client that cannot re-associate while the flood runs is
the result; watch for `"AP is in CSA process, reject assoc"` in its log if it is Linux. That log
line **cannot** appear for the count = 0 arm, which is what makes the pair a clean control.

*Unprotected Public-Action eCSA* second (category 4, action 4, outside PMF's robust set). Expect a
**persistent** uplink stall on a current Linux client rather than a channel move, and nothing
whatsoever if its driver sets `HANDLES_QUIET_CSA`; an older or non-Linux stack may switch properly.
Watch the client's traffic, not just its association state. `pagerinj` does not build this one yet.

**17c. The unicast Spectrum-Management CSA — do this on 2.4 / non-DFS 5 GHz, not 6 GHz.** Category
**0**, action **4**, which is a different frame from 17b's category 4 and reaches a different path.
`mac80211_mlme.c:7506` tags it `PROT_ACTION` from the **category alone**, with no check that it
actually arrived protected, and the protection filter only runs under MFP — so on a **non-PMF BSS**
an unprotected one is acted on, and because it is unicast there is no flood and no race against the
real AP's beacons. Better targeting than a beacon, and it lands on the surface CamHound actually
attacks.

```sh
pagerinj -i wlan1mon --action --bssid <AP> --client <STA> --chan <N> --count 3
```

Three constraints, all from the receive path, each the difference between working and a silent drop:

- **A3 must equal the BSSID** — `rx612.c:3738` compares it against `sdata->deflink.u.mgd.bssid`.
  `pagerinj` sets A3 from `--bssid` for you; a wrong one is dropped with no log at all.
- **A1 is the client**, which is the whole point.
- **The client must be associated.** No keys are needed on a non-PMF BSS, which is why this works.

---

## Only if the above is exhausted

**18. Patch pineapd's gate** (two short instruction ranges) or **replace `regulatory.db`** (unsigned
on this build). Stop the UI first so procd cannot respawn a broken binary, and have the restore
script from step 5 ready.

---

## Two traps worth re-reading before you start

- **`inject_csa` freezes the channel before the refusal.** Firing CSA at a blocked channel parks the
  radio there and transmits nothing. If recon goes quiet after a failed attempt, that is why.
- **A blocked frame is freed with `NETDEV_TX_OK`.** The sender reports success. Nothing on the
  Pager can distinguish "transmitted" from "silently dropped" — which is why every step above that
  claims a transmission requires the independent receiver.
