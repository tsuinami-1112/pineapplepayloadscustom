# Pager — order of operations

Bench checklist. The reasoning, exact commands, rollbacks and early exits live in
`dev/pager-6ghz-determination-plan.md`; this is the running order and why each step sits where it
does. Gate facts: `dev/pager-csa-primitives.md`.

**Three rules behind the ordering.** Nothing irreversible before a *tested* restore. Every
decisive-but-free test before any modification. DFS before 6 GHz — it is the bigger win, needs
less, and it proves the measurement rig.

---

## Before the Pager arrives

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

**9. THE VALUE GATE — one beacon capture, before spending any effort on 6 GHz.** Beacon protection
is an **AP-side** switch, so the chamber AP decides it; no client is needed to find out. Capture one
beacon from the 6E AP and read two fields:

```sh
# 1. does the AP advertise beacon protection?  (Ext Cap bit 84)
tshark -i wlan0 -c 5 -T fields -e wlan.extcap.b84 \
       -Y 'wlan.fc.type_subtype==8 && wlan.bssid==<AP>'

# 2. are its beacons actually carrying an MMIE?  (element 76) -- no output = not protected
tshark -i wlan0 -c 5 \
       -Y 'wlan.fc.type_subtype==8 && wlan.bssid==<AP> && wlan.tag.number==76'
```

MMIE (element **76**) present **and** `wlan.extcap.b84 == 1` → beacon protection is on, and
beacon-borne CSA is dead against anything associated to that AP. Neither → beacon-CSA is live.
**Record which**, because "beacon CSA worked" may mean only "my AP does not enable it".

If it is on, the fallbacks are both poor and both verified from mac80211 source: probe-response CSA
is **ignored outright** (the probe-resp path never reaches chanswitch), and an unprotected
Public-Action eCSA only **stalls the client's TX queues** until the next clean beacon. Deauth is
already dead by standard (PMF mandatory). The real client is still worth having — it confirms a
switch actually happens, and non-Linux stacks may differ.

> **If the deliverable is client disconnection, stop the 6 GHz branch here.** The answer is
> "unlockable, and it will not work." Go to the DFS branch, which is unaffected.

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

**17b. If the AP turned out to have beacon protection on, test the one remaining outside path.**
Unprotected Public-Action eCSA (category 4, action 4) is excluded from PMF's robust set, and the
builder is already on the device — `dlopen("libwifi.so.0")` gets you `libwifi_create_action` and
`libwifi_add_action_detail` without vendoring anything. Expect a TX stall on a current Linux client
rather than a channel move; an older or non-Linux stack may switch properly. Watch the client's
traffic, not just its association state.

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
