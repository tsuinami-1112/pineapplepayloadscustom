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
fallback — and it is the **first real-world input to `inj_probe()`'s parser**, which was written
against the shipped `iw`'s format strings but has never seen live output. Diff what `inj_probe`
produced against the raw text by hand, once.

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
short-circuit) — but **connection denial survives beacon protection**. A forged CSA beacon reaches
the BSS cache ahead of the protection check, and mac80211 then refuses auth and assoc while a
cached CSA is present. Deauth is dead by standard (PMF mandatory).

> **If the deliverable is "the client changes channel", this step may stop the 6 GHz branch. If it
> is "the camera stops working", it does not** — the denial path survives. Decide which you need,
> and record which effect you measured. Either way the DFS branch is unaffected.

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

**12. Get an injector that is not pineapd** — `opkg -d ram install hcxdumptool` (tmpfs, so reboot is
the rollback). This is what bypasses gate 1; `pcap_inject` has exactly one call site, inside the
gated function.

**13. Inject on ch 52 and confirm at the external 5 GHz receiver.** Not `wlan0mon` — `radio0` is
`band '2g'` and cannot hear ch 52; its silence would be silence either way. Run the negative control
(Pager idle, require zero matches) and the positive control (ch 5180, same invocation) or the result
means nothing.

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

Build the Stage-B injector (it is needed for the DFS work anyway) and send the **same frame twice,
differing only in that byte** — `count = 0`, then `count = 3`. Watch whether the client can
re-associate while each flood runs. Use the jammer (or a power cycle) to force the disconnect, since
deauth cannot: this is the one target class where PMF makes the usual kick unavailable. Run the
jam-only control first and confirm the client *does* come back without the flood, or the result
means nothing.

There is no setting for the count — do not go looking for one. Patching pineapd's instruction is
possible but global, costs ~200 ms on the working attack, and is not a clean one-byte edit (the zero
register is reused two instructions earlier to NUL-terminate a string). Prefer the injector. Full
working: `dev/pager-csa-primitives.md`, section "THE ONE BYTE".

**17b. If beacon protection is being enforced, test the two remaining outside paths.**

*Connection denial* first, because it is free and uses the frame pineapd already builds: flood the
forged CSA beacon, then make the client disconnect and try to reconnect. A client that cannot
re-associate while the flood runs is the result — watch for `"AP is in CSA process, reject assoc"`
in the client's log if it is Linux.

*Unprotected Public-Action eCSA* second (category 4, action 4, outside PMF's robust set). The
builder is on the device — `dlopen("libwifi.so.0")` gets `libwifi_create_action` and
`libwifi_add_action_detail`; do not try to link against the shipped `.so`. Set the CSA mode byte, or
nothing at all happens. Expect a **persistent** uplink stall on a current Linux client rather than a
channel move, and nothing whatsoever if its driver sets `HANDLES_QUIET_CSA`; an older or non-Linux
stack may switch properly. Watch the client's traffic, not just its association state.

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
