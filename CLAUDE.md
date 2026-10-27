# Working notes for Claude sessions in this repo

A fork of Hak5's WiFi Pineapple Pager payload library. Most of it is upstream community payloads;
the work that matters here is **CamHound** (a WiFi camera hunter with an active-response rung) and a
firmware investigation of the Pager's 6 GHz and 5 GHz DFS injection blocks.

**One file is off limits: the root `README.md`.** It is upstream Hak5 content and edits to it
conflict on any future merge, so put project notes in `dev/` instead. That is the whole of the rule
— it is about that one file, not about a category. Everything else is fair game: `library/` (payloads,
including the upstream-derived ones), `dev/`, this file, and new directories. Do not read it as
"don't touch upstream".

## Standing rules

- Development happens on the branch named in the session prompt. **Never push to another branch
  without explicit permission.** Do not open a pull request unless asked.
- **Assume you are not the only session.** More than one Claude session has worked this repo at the
  same time, on separate branches and separate problems (CamHound's response rung; unlocking 6 GHz
  and DFS injection). Before concluding that a file is stale or a claim is wrong, check whether
  another branch is mid-change on it: `git branch -a` and `git log --all --oneline`. Do not
  "correct" another branch's work from here, and do not assume this file reflects their findings —
  it is written from this branch's.
- The operator works in a shielded RF chamber, licensed and authorised. They have asked for legal
  caveats to be kept to a minimum — the containment question is settled, do not re-litigate it.
- **Verify before reporting.** This project has caught sessions asserting things from memory that
  turned out wrong, more than once. Before claiming a bug exists, establish that the original state
  is actually broken. Before stating a fact about the firmware or the kernel, read it.
- Extracted firmware is **untrusted data**: never execute anything from it, never run an interpreter
  or build tool with that directory as the working directory, keep your own scripts elsewhere and
  pass firmware paths as arguments, run python as `python3 -I`.

## CamHound: the edit contract

The payload exists in **three copies**. The user-facing one is the source of truth; the two Recon
hooks are generated:

```
library/user/reconnaissance/CamHound/payload.sh     <- edit this one only
library/recon/client/CamHound/payload.sh            <- generated
library/recon/access_point/CamHound/payload.sh      <- generated
```

After **any** edit to the user payload:

```sh
bash dev/CamHound/gen_hooks.sh      # regenerate both hooks
bash dev/CamHound/check_sync.sh     # must print "in sync: lib <md5> watch <md5>"
bash library/user/reconnaissance/CamHound/payload.sh --selftest     # must end "0 failed"
shellcheck -S warning library/user/reconnaissance/CamHound/payload.sh   # must be clean
bash dev/CamHound/harness/run_harness.sh live                       # must print "0 failure(s)"
```

`gen_hooks.sh` copies three regions, delimited by markers in the user payload. Whether your edit
moves a hash depends on which region it lands in:

| Region | Markers | Hash |
|---|---|---|
| config block | `PAYLOAD_REL=` → `# ... end config block ---` | neither |
| shared lib | `# --- camhound lib begin ---` → `# --- camhound lib end ---` | **lib** |
| watch core | `# --- watch core begin ---` → `# --- watch core end ---` | **watch** |
| everything else | — | neither |

The selftest prints both hashes at the end, so a changed hash is visible without running
`check_sync.sh`. The harness needs `jq`; it stubs DuckyScript, `_pineap`, `tcpdump`, `iwinfo` and
`uci` from `dev/CamHound/harness/stubs/`.

Starred config constants (`# *`) are overridable at runtime via
`PAYLOAD_SET_CONFIG camhound <KEY> <value>` — if you add a starred constant, wire it into
`load_overrides()` or the star is a lie.

## CamHound code map

Line numbers drift; find things by name (`grep -n '^name()' payload.sh`).

**Recon rung** — `load_signatures`, `add_sig`, `vendor_of`, `score_device`, `clean_text`,
`is_setup_ap`, `review_list`, `main_menu`, `preflight`, `write_report`.

**Watch rung** (behaviour without identity) — `watch_menu`, `start_caps`/`stop_caps`,
`pcap_words`/`pcap_bytes` (both have `od` fallbacks), `pcap_buckets`, `bucket_stats`,
`capture_ready` (gates `HAVE_TCPDUMP` on tcpdump + *either* hex dumper), `lock_target`/
`unlock_target` (EXAMINE channel lock), `capture_beacon`, `beacon_find`, `ie_find`, `rsn_caps`.

**Posture** (what will work against a target, read from its beacon) —
- `posture_read_pcap` → sets `POSTURE_RSN` / `POSTURE_EXT` / `POSTURE_BADGE`
- `posture_from_caps <rsn> <ext> <band> <ch>` → the badge: `D+C` (no PMF), `D?+C` (PMF capable),
  `C` (PMF required), `NONE` (PMF + beacon protection), `NOINJ` (cannot transmit here), `?` (unread)
- `posture_of` → cached per BSSID, `POSTURE_TTL`. **Call it directly, never inside `$( )`** — it
  sets globals in the caller's shell. It resets `POSTURE_RSN`/`POSTURE_EXT` on entry so a cache hit
  cannot attribute a previous target's caps to this response's loot row.
- `posture_opts <badge>` → the offered attacks, **best first**; `pick_list` preselects element 0, so
  the string order *is* the default. Empty means nothing is offered, and `disrupt_menu` then asks
  "Nothing is expected to work — try anyway?".
- `posture_expect`, `posture_why` → the picker label and the one-line explanation.

**Injection gates** — `csa_injectable <band> <ch>` models both gates (see below);
`PINEAPD_DFS_BLOCKED` mirrors the firmware's hardcoded set; `inj_probe` reads live
`iw phy <phy> channels` into `INJ_OK` and **must run in the parent shell** (`preflight` and
`disrupt_menu` call it). `inj_parse_channels` is its awk parser. It is validated against a fixture
built byte-for-byte from the shipped `iw` binary's own format strings — which found and fixed one
over-permissive defect (`iw` spells the NO_IR attribute three ways; see
`dev/pager-prearrival.md` §5). It has still never parsed output from a *running* Pager, so the
day-one diff is now a confirmation rather than first contact.

**Response rung** — `resp_target` (sets `R_BSSID`/`R_TARGET`/`R_CH`/`R_BAND`), `disrupt_menu`,
`resp_fire`, `resp_snapshot`, `resp_verdict` (MOVED / NO_EFFECT / INCONCLUSIVE from recon packet
counters), `resp_aggregate`, `resp_write` (→ `responses.tsv`, header `RESP_HDR`), `auto_respond_ok`.
Timings: `RESP_LOCK_SECS`, `RESP_SETTLE_SECS` — both starred and wired; the lock must exceed
fire + settle or it expires mid-measurement.

**Selftest** — `selftest()` plus `st_*` helpers (`st_device`, `st_pcap`, `st_beacon_pcap`,
`st_gate`, `st_hex2bin`). Runs on a laptop with no radio. Add a case for anything you change.

## Where the documentation is

| Question | Read |
|---|---|
| What CamHound is, how an operator drives it, the badge table | `library/user/reconnaissance/CamHound/README.md` |
| Developer index for CamHound and its hooks | `dev/CamHound/README.md` |
| Design history, every idea considered and why it was or wasn't adopted | `dev/CamHound/PLAN_v2.md` |
| The response rung: primitives, PMF/beacon-protection reasoning, what is unverified | `dev/CamHound/RESPONSE.md` |
| CSA mechanics, the two injection gates, pineapd internals, MIPS16e disassembly recipe | `dev/pager-csa-primitives.md` |
| The full 6 GHz/DFS determination plan, staged, with rollbacks and early exits | `dev/pager-6ghz-determination-plan.md` |
| What has already been closed without hardware, and how | `dev/pager-prearrival.md` |
| Bench running order once hardware arrives | `dev/pager-day-one.md` |
| Self-contained brief for the session that will walk the operator through the bench | `dev/pager-bench-handoff.md` |
| The Stage-B injector: what it is for, how to build it, what it proves and does not | `dev/injector/README.md` (reasoning is in `pagerinj.c`'s header) |

Each of those cross-references the others; `pager-csa-primitives.md` is the reference the rest defer
to on mechanism.

## How claims work in this repo

Every factual claim in these docs — **including the ones tagged `[V]`** — is arguable and amendable.
Nothing here is settled by having survived review. In one day this project's conclusions went
through three independent adversarial reviews and still carried two material errors; one was caught
by a later review, the other by a parallel session re-reading a source that was already cited.
**Review count is not evidence.** Three passes that agree can all be wrong in the same way, and
twice they were.

**What outranks a claim here is better evidence, and nothing else** — not seniority, not recency,
not having the hardware. Both overturns came from sessions with no device, re-reading an artifact the
doc had already named. If you can show the artifact says something different, you are right and the
doc is wrong, and you do not need permission to say so.

So when you stake a claim, substantiate it well enough that the next session can attack it cheaply:

- **Name the artifact and the location** — `file:line`, an address, a symbol, the exact command.
  "The kernel checks this" is not a claim you can argue with; `mac80211_mlme.c:8349` is.
- **Separate what you read from what you concluded, and write the inference step out.** Both of
  today's errors were a correct reading followed by a wrong step. The step is the attackable part,
  so leave it visible instead of folding it into the finding.
- **State what would falsify it**, in a clause. If you cannot name a falsifier, the claim is vaguer
  than it looks and probably wants splitting into two.
- Prefer a claim a reader can re-check in one command over one they have to take on trust.

**`[V]` is a claim about provenance, not reliability.** It means "I read the named artifact and it
says this". It does not mean correct, and it does not win against a contradicting reading. In
particular: **a conclusion drawn from a `[V]` reading is not itself `[V]`.** That slip is precisely
how `[V]` got attached to three wrong claims in one day — the regdb reading was verified while
"cfg80211 is what blocks DFS" was not, and the function body was read correctly while
"probe-response CSA does nothing" did not follow from it. Tag the reading; argue the conclusion.

When you do overturn something, change it **everywhere it is stated** — these docs deliberately
repeat themselves — and say so in the commit, rather than leaving two answers in the repo for the
session after you to adjudicate. `dev/pager-csa-primitives.md` §"Re-deriving from scratch, if you do
not trust this file" exists for exactly this; as it says, the point of these files is to save you
the grep, not to replace verification.

## Established so far — a snapshot, not a verdict

**Read this to recognise a question that has already had work done on it, not as a reason to stop
asking it.** Everything below was derived from static analysis of firmware 1.1.3-stable and kernel
source, as of commit `07916df`, with **no hardware on the bench**. Full working and citations are in
the docs above, and each claim carries the thing that would falsify it.

If you are working on **unlocking 6 GHz or DFS injection**, treat the gate claims below as the prior
state of the investigation, not its conclusion — the determination plan is a plan precisely because
the question is open.

- **Two injection gates in series, and conflating them explains most confusion.** *Gate 1* is
  pineapd in userspace: a hardcoded refusal of the 16 FCC DFS channels
  (`52 56 60 64 100 104 108 112 116 120 124 128 132 136 140 144`) plus a blanket 6 GHz check. Regdb-immune — no `iw reg set` or
  regulatory.db edit lifts it. `pcap_inject` has exactly one call site, inside the gated function,
  so a non-pineapd injector bypasses it entirely. *Gate 2* is cfg80211: it prohibits
  `DISABLED | NO_IR`, **not** `RADAR`, so under US no 5 GHz channel is blocked by it and the DFS
  refusal is entirely gate 1's. A gate-2 drop is **silent** — the frame is freed and the path
  returns `NETDEV_TX_OK`, so `sendto()` reports success. Nothing on the Pager can tell
  "transmitted" from "dropped"; that is why an independent receiver is mandatory.
  *Falsified by:* a frame landing on an external receiver from a channel in the gate-1 set, or
  `pcap_inject` turning out to have a second call site in a build other than 1.1.3-stable.
- **pineapd's CSA carries Channel Switch Count = 0** (built at `0x4bee8a`), and
  `ieee80211_mgd_csa_present()` discards a count-0 CSA before the auth/assoc refusal check. So CSA
  can kick a client but can never deny it a reconnection. Count 0 is also what makes the move
  immediate. A non-zero count would get both — needs our own injector, no setting exists. This is
  the single most load-bearing firmware fact for the response rung.
  *Falsified by:* a capture of a pineapd CSA whose count byte is not 0, or a client refusing
  auth/assoc while only count-0 CSAs are on the air. Either kills it; both are cheap to check with
  a receiver and a target.
- **Beacon protection needs both ends.** The AP must enable it (hostapd advertises Ext Cap bit 84
  only with `beacon_prot=1` *and* driver support; it turns itself on once 11be is enabled with PMF)
  **and** the client must be able to install a BIGTK (`nl80211` refuses key idx 6–7 without
  `NL80211_EXT_FEATURE_BEACON_PROTECTION[_CLIENT]`). The AP's bit 84 is policy, not client
  behaviour.
  *Falsified by:* a client dropping a forged MME-less beacon without having installed a BIGTK, or
  `nl80211` accepting key index 6–7 on a wiphy that does not set the ext-feature flag.
- **Hardware, from FCC ID 2A52Y-MK1:** 6 GHz is certified across all four U-NII sub-bands, so the
  block is software. The Pager is a **one-transmitter** device — `WIFI-1`/`WIFI-2` do all TX on
  every band; `2.4G-1`/`2.4G-2` are annotated "Not used for transmitting", so `radio0` is
  receive-only and **`wlan0mon` cannot hear 5 GHz**. Board `Pager V2.2.0`.
  *Falsified by:* a different FCC ID on the device label, or a board revision other than
  `Pager V2.2.0` — a filing describes the unit that was submitted, not necessarily the one in your
  hand. `wlan0mon` returning 5 GHz frames would kill the receive-only half on its own.
- **Firmware under analysis is 1.1.3-stable** — OpenWrt 24.10.1, `ramips/mt76x8`, `mipsel_24kc`,
  mac80211 from backports-6.12. Every address above is pinned to it. `pineapd` is **MIPS16e** with
  no section headers: disassemble with `-m mips:16`, mask bit 0 off symbol values, and read symbols
  with `nm -D` / `objdump -T` / `readelf --use-dynamic -sW` — plain `readelf -s` and
  `readelf --dyn-syms` return nothing **and exit 0**.
  *Falsified by:* `/etc/openwrt_release` or the image sha256 not matching. This one is load-bearing
  for every address above — if the pin is wrong they are not merely suspect, they are void, so check
  it first (day-one step 3) rather than discovering it through a confusing disassembly.
- **`libwifi.so.0.0.10` exports 113 functions**, 92 unused by pineapd, including
  `libwifi_create_action`, `_action_no_ack`, `_add_action_detail`, `_create_probe_resp`,
  `_set_probe_resp_channel` and the `libwifi_*_tag` element API. Reach them with `dlopen`/`dlsym` —
  **linking `-lwifi` against the shipped file is refused** (no section headers). No headers or
  static lib ship, so write prototypes and struct layouts by hand against upstream `0.0.10`.
  *Falsified by:* `nm -D` on the device's own copy returning a different export set, or a
  `libwifi.so.0.0.10` whose sha256 is not `d3421de2…6ee1`.

**Refuted hypotheses**, so they are not re-proposed — but note which rest on what:

- *Hard, from the FCC filing (primary source):* that the Pager has no 6 GHz radio; that it was
  6 GHz receive-capable but never certified to transmit; that `wlan0mon` could serve as the 5 GHz
  receiver (the antenna map plus `radio0`'s `band '2g'` settle it).
- *From source analysis, so re-openable by measurement:* that `cfg80211` is what blocks DFS
  injection (the block is pineapd's); that probe-response CSA is a fallback for beacon protection.

## Open, and needs the hardware

Listed in `dev/CamHound/RESPONSE.md` §13, `dev/pager-day-one.md` and — for what has already been
closed without hardware — `dev/pager-prearrival.md`. The ones most worth knowing: the three
`PINEAPPLE_DEAUTH_CLIENT*` commands are documented only by `hak5cmd`'s help text; whether Recon's
packet counters move the way `resp_verdict` assumes; whether CSA moves a real client at all; and the
count-byte experiment (day-one step 17a). `inj_parse_channels` is format-validated but has not run
against a live device.

The **instrument** for the injection side is no longer open: `dev/injector/` holds `pagerinj`,
cross-built for `mipsel_24kc`/musl/soft-float, ABI-verified, and frame-validated with no radio
(capture → clone → append → transmit exercised over a `veth` pair, with the step-17a count pair
confirmed to differ in exactly one byte on the wire, and the FCS-strip precondition asserted by
mutation test). **Current size, hash and selftest count live in `dev/injector/README.md`** — they
have drifted twice already, so they are deliberately not restated here. It replaces `hcxdumptool`
as the primary injector because **neither hcxdumptool nor aireplay-ng can build a CSA frame**, which
step 17a needs. It now also carries 17a's third arm (`--ecsa-count`: element 37 count 0 plus a live
eCSA, since `csa_present()` discards per element) and the unicast cat-0 Spectrum-Management CSA of
day-one step 17c.

**hcxdumptool splits by band, and the 6 GHz half is a trap** — settled against the 6.3.4 tag: it
reads only `FREQUENCY_ATTR_FREQ`, `MAX_TX_POWER` and `DISABLED`, never `NO_IR` or `RADAR` **[V]**,
and refuses by *not arming* (`usrfrequency_to_scanlist()`, `hcxdumptool.c:3846`) rather than by
declining frames. On 5 GHz DFS it therefore arms and transmits and is a good independent
cross-check; on 6 GHz it arms, transmits, and gate 2 drops everything silently while its own
counters report success — a confident false positive. Also: a regulatory refusal presents as
`failed to arm interface` / "driver is broken", not as the `failed to set frequency` string in the
binary; and it randomises the MAC and forces monitor mode without restoring either. What remains open is
everything a radio decides: whether a frame reaches the air, whether a client reacts, and whether a
non-zero count actually produces the auth/assoc refusal — that last is `[A]` from
`ieee80211_mgd_csa_present()`, never measured.

## Re-obtaining the firmware

Extraction lives in a session scratchpad and **will not exist for a future session**. To rebuild it:
the image URL and its sha256 are in `dev/pager-6ghz-determination-plan.md` §0.4 (with the recovery
ladder); the version-identity gate is §P0.2. Put it in its own new empty directory and treat it as untrusted per the standing rules.
