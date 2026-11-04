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
`check_sync.sh`. The harness needs `jq`; it stubs DuckyScript (`NUMBER_PICKER` and `PAYLOAD_SET/DEL_CONFIG` included),
`_pineap`, `tcpdump`, `iwinfo`, `uci` and `iw` (a US-like channel table, answered for the fixture phy
directory the fast copy points `INJ_SYSFS` at, so `inj_probe`'s success path runs) from
`dev/CamHound/harness/stubs/`. Its `LIST_PICKER` answers only with items on the page it was handed: an
answer further down the list makes it press `More...` first, as an operator would, and an answer that is
on no page is refused (logged as `not on this page`).

Starred config constants (`# *`) are overridable at runtime via
`PAYLOAD_SET_CONFIG camhound <KEY> <value>` — if you add a starred constant, wire it into
`load_overrides()` or the star is a lie.

## CamHound code map

Line numbers drift; find things by name (`grep -n '^name()' payload.sh`).

**Recon rung** — `load_signatures`, `add_sig`, `vendor_of`, `score_device`, `clean_text`,
`is_setup_ap`, `review_list`, `main_menu`, `preflight`, `write_report`; `rssi_gate_ok` (the RSSI_MIN
list gate, kit-aware: a kit AP passes when a kit client does) with `rssi_min_clamp`; the Settings menu
(`SETTINGS_TABLE` rows are `KEY|kind|floor|group|label` over all sixteen starred keys; `settings_menu`
is a short top page, `settings_group` one page per group, Recon and Response; `settings_apply` re-runs
`resp_clamp_lock` for the two timing keys and persists a raised lock; RESPONSE_CONFIRM-off asks twice;
`cfg_snapshot_defaults`/`settings_reset`; `cfg_note_set` keeps the override count honest);
`JQ_CLI`/`parse_cli_fallback` read the 2.0.0 client object (`probe` is a hash-keyed object, no
association key), and `recon_verb_probe` picks `RECON DEVICES` (`JQ_DEVCLI`: devices that neither
beacon nor answer probes) where `RECON CLIENTS` is refused, as on 1.1.3; `bands_plan`/`bands_apply`/
`bands_restore` are the opt-in 6 GHz band write (`BAND6`; `bands_live6` samples the live channel and
the write is trusted only when 6 GHz is seen there or in uci — on bare 1.1.3 it was a no-op with
pineapd running, day-one 8c; every issued write is restored in `cleanup`, by the watchdog, or by
`bands_recover` at the next start from `BANDS_STATE`; not copied into the hooks); `raw_up_rows` feeds `--replay` a `raw_<run>.txt`.

**Watch rung** (behaviour without identity) — `watch_menu`, `start_caps`/`stop_caps`,
`pcap_words`/`pcap_bytes` (both have `od` fallbacks), `pcap_buckets`, `bucket_stats`
(**`PCAP_AWK` aborts the whole file on `incl_len % 4 != 0`, so it only parses the `-s 32`
captures it ships with — raising any Watch snap to reach addresses breaks it; verified
2026-11-04, see `dev/CamHound/PLAN_v2.md` item 1**),
`capture_ready` (gates `HAVE_TCPDUMP` on tcpdump + *either* hex dumper), `lock_target`/
`unlock_target` (EXAMINE channel lock), `capture_beacon`, `beacon_find`, `ie_find`, `rsn_caps`.

**Posture** (what will work against a target, read from its beacon) —
- `posture_read_pcap` → sets `POSTURE_RSN` / `POSTURE_EXT` / `POSTURE_BADGE`
- `posture_from_caps <rsn> <ext> <band> <ch>` → the badge: `D+C` (no PMF), `D?+C` (PMF capable),
  `C` (PMF required), `NONE` (PMF + beacon protection), `NOINJ` (cannot transmit here), `?` (unread)
- `posture_of` → cached per BSSID, `POSTURE_TTL`. **Call it directly, never inside `$( )`** — it
  sets globals in the caller's shell. It resets `POSTURE_RSN`/`POSTURE_EXT` on entry and caches the caps
  per BSSID beside the badge, so a cache hit restores this target's caps and never attributes a previous
  target's to this response's loot row.
- `posture_opts <badge>` → the offered attacks, **best first**; `pick_list` preselects element 0, so
  the string order *is* the default. Empty means nothing is offered, and `disrupt_menu` then asks
  "Nothing is expected to work — try anyway?".
- `posture_expect`, `posture_why` → the picker label and the one-line explanation.

**Injection gates** — `csa_injectable <band> <ch>` models both gates (see below);
`PINEAPD_DFS_BLOCKED` mirrors the firmware's hardcoded set; `inj_probe` reads the **transmitting
phy's** live `iw phy <phy> channels` table into `INJ_OK` — the phy behind `RECON_IF`, from
`<NET_SYSFS>/<RECON_IF>/phy80211/name`; only when that file is unreadable does it merge every phy
under `INJ_SYSFS`, and it logs that it did — and **must run in the parent shell** (`preflight` and
`disrupt_menu` call it). `inj_parse_channels` is its awk parser. It is validated against a fixture
built byte-for-byte from the shipped `iw` binary's own format strings — which found and fixed one
over-permissive defect (`iw` spells the NO_IR attribute three ways; see
`dev/pager-prearrival.md` §5). **It has since been run against a live radio (2026-11-02) and was
correct**, including a 5 GHz `No IR` channel (169) that the fixture never contained. No longer a
pending validation.

**Response rung** — `resp_target` (sets `R_BSSID`/`R_TARGET`/`R_CH`/`R_BAND`), `disrupt_menu`,
`resp_fire`, `resp_snapshot`, `resp_verdict` (MOVED / NO_EFFECT / INCONCLUSIVE from recon packet
counters), `resp_aggregate`, `resp_write` (→ `responses.tsv`, header `RESP_HDR`), `auto_respond_ok`.
Timings: `RESP_LOCK_SECS`, `RESP_SETTLE_SECS` — both starred and wired; the lock must exceed
fire + settle or it expires mid-measurement.
`RESPONSE` **defaults to 1** — recon and response are both live out of the box; `RESPONSE=0` is the
recon-only run. `attack_scope <key>` → `cli`|`bss` is the single place that decides blast radius:
only `DEAUTH` on a client row is targeted, because `CSA` has no target argument and `_ALL`'s is
parsed and discarded, and an AP row resolves `R_TARGET` to broadcast so everything is BSS-wide
there. `disrupt_menu` reads it twice — the picker appends ` bss` to a broad option, and the
pre-transmit confirm says "on EVERY client of <bssid>" instead of naming one device. `posture_opts`
still orders by efficacy, so a BSS-wide attack stays preselected on the common badges; the marker
and the confirm carry the breadth rather than the ordering.
**`resp_snapshot <scope>` reads it too, and that was a defect until 2026-11-03**: subjects were
selected by *row type* (`R_TARGET == ff:ff:ff:ff:ff:ff`), so a client-row `CSA`/`BOTH` transmitted
BSS-wide and then measured and looted exactly one device. Subjects now follow the attack's scope,
the picked target is always among them (even behind a randomised MAC the `bss` sweep skips), and
`resp_fire` names that device's own verdict when there is more than one subject so a collateral
`NO_EFFECT` cannot read as "my camera stayed up". Harness scenario `cliscope` drives both arms.
Caveat, and it is bigger than a loot-quality note: the `bss` sweep matches `ap_mac` against
`R_BSSID`, and **no shipped firmware supplies an association**, so the sweep matches nothing. That
does not "degrade measurement to the picked target" — *an earlier revision of this line said so and
it was wrong on both row types.* An AP row has no target to fall back to (broadcast), so subjects
are 0 and `resp_fire` refuses; a client row never reaches the sweep because `AP_OF` is `-` and
`resp_target` returns 1 at `payload.sh:2123`. The selection rule is right and **the rung cannot fire
on either firmware** — see the warning below and `RESPONSE.md` §13.

**Selftest** — `selftest()` plus `st_*` helpers (`st_device`, `st_pcap`, `st_beacon_pcap`,
`st_gate`, `st_hex2bin`, `st_subjects`). Runs on a laptop with no radio. Add a case for anything you change.

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

## Review workflows: the standing rules

Set by the operator on 2026-11-03 for every session that runs an agent review here. The point is
not to ration the heavy shapes — multi-finder reviews, three-lens adversarial verification, judge
panels, critic rounds, fix-then-reverify loops are all welcome, and are the right default for code
the device runs, hardware-facing claims and anything novel. The point is to stop them appearing on
trivial work: a doc edit, a comment's wording, a stale count, a renamed check. Judge the tier by what
a wrong finding would cost if acted on and by how likely the finder is to be wrong, and spend
accordingly.

1. **Tier the verification by consequence and by likelihood of error.** A finding gets the full
   three-lens adversarial pass (trace, intent, impact) when a fix would change code the device runs,
   when it contradicts a fact measured on hardware, or when it is an inference composed from verified
   readings — the error shape this project has been bitten by twice. Freshly written code rates
   higher on likelihood of error than code that has survived a prior pass and a harness run, even at
   equal consequence. Docs, comments, stale counts, wording and test gaps get one sceptical verifier
   whose prompt says: default to refuted unless you can reproduce it from the artifact. When in doubt
   between tiers, take the heavier one and say why.
2. **Cap the finder pool at four dimensions per review.** Batch verification at nine findings per
   agent, grouped by file. Never one agent per finding per lens, unless truly warranted — a claim
   big enough to deserve that attention (one that would redirect the bench, overturn a measured
   fact, or change what the device transmits) can have its own agents, with the reason stated.
3. **Report the refutation count in the first line of every review summary.** A pass that refutes
   nothing is a warning about the verifiers, not a clean bill; say so when it happens.
4. **Name what is already settled before the finders start** — measured on hardware, verified in a
   prior pass, or owned by another session — in the preamble every agent sees. Finders may challenge
   it with a better artifact, but should not re-report it.

## Established so far — a snapshot, not a verdict

**Read this to recognise a question that has already had work done on it, not as a reason to stop
asking it.** Everything below was derived from static analysis of firmware 1.1.3-stable and kernel
source, as of commit `07916df`. Full working and citations are in the docs above, and each claim
carries the thing that would falsify it.

**The device arrived on 2026-11-02, and a first read-only session checked much of it.** What that
confirmed, and the one thing it corrected, is in "First contact" immediately below. Claims not
listed there are still static-analysis only.

### First contact — what a real Pager confirmed, 2026-11-02

Read-only session, no receiver present, firmware deliberately held at 1.1.3-stable.

- **`Band 4:` is present** on `phy1` ⇒ `phy->cap.has_6ghz == 1`. The 6 GHz PHY exists and the
  block is software. Early exit **E1 cleared**. Also corroborates the FCC-derived hardware claims
  for this unit, which mattered because **this unit carries no FCC label at all** — not on the
  case, not under the battery cover. A dual-band variant would not register Band 4.
- **`/sys/class/ieee80211/phy1/device/of_node` does not exist** ⇒ the device-tree `power-limits`
  clamp is inert, as predicted for a USB device. No second hardware gate.
- **P0.2 identity gate passed exactly** — `pineapd` `adc9d36d…8493`, `_pineap` `e1739d97…7d69`,
  `regulatory.db` `30954f89…4b44`. New reference value: **`/pineapple/pineapple` =
  `4493c6c6c8339e1993b5f7642e19fa6ca09241e14361cc1b6eccb0f75090ad3e`** (the Go UI, which carries
  the *"Cannot deauth clients on DFS or 6GHz channels"* refusal string).
- **`iw reg get` shows `country US: DFS-FCC` with no `(self-managed)` block** ⇒ regdb edits do
  govern this radio, as inferred from mt76 having no `REGULATORY_WIPHY_SELF_MANAGED`.
- **The two-gate separation, observed.** The US rules `5250–5350` and `5470–5730` carry `DFS` and
  **no** `NO-IR`; channel 52 reports `Radar detection` with no `No IR`. Gate 2 permits the DFS
  set, so the block on 52–144 is **entirely pineapd's**. Channel 149 is clear of both.
- **Channel counts:** 2.4 GHz 11, 5 GHz 28 / 0 disabled / 16 Radar, 6 GHz 59 / 0 disabled / 59
  `No IR`. 6 GHz `NO_IR` comes from one rule: `(5925 - 7125 @ 320) … PASSIVE-SCAN`.
- **`inj_parse_channels` validated against a live radio** — all 98 channel lines end `] ` with the
  trailing space it keys on, and it correctly handled a **5 GHz `No IR` channel (169)**, a case
  the synthetic fixture never contained. The parser's remaining "never seen a real device" caveat
  is discharged.
- **Corrected:** "under US no 5 GHz channel carries `NO_IR`" was too broad — **169/173/177 do**,
  via `5850–5895 … PASSIVE-SCAN`. The narrow form, "permits all of 36–165", is correct.
- **⭐ The two branches are NOT symmetric targets, and the live data is what shows it.** On
  **5 GHz DFS only gate 1 fires** — those channels are radar-flagged but carry no `NO_IR`, so
  cfg80211 permits them and pineapd alone refuses. On **6 GHz both gates fire** — all 59 channels
  carry `NO_IR`, so even with pineapd bypassed, cfg80211 still drops the frame. Therefore
  **5 GHz DFS needs only a non-pineapd injector** (`pagerinj`, already built), while **6 GHz needs
  that *and* something about gate 2** (step B2's `iw reg set` to a domain whose 6 GHz rule lacks
  `NO-IR`). That asymmetry was implicit in the static reading and is now explicit in measurement;
  it is the clearest single argument for doing the DFS branch first.
- **`pineapd`'s live cmdline**, which settles several things at once and is worth re-reading before
  assuming anything about interface roles:
  `--interface wlan1mon --band wlan1mon:2,5 --primary wlan1mon --inject wlan1mon`,
  `--interface wlan0mon --band wlan0mon:2`,
  `--interface wlan2mon --band wlan2mon:2,5`.
  So **`wlan1mon` is the injection interface** (confirming where gate 1 applies), and pineapd only
  ever asks **radio0 for 2.4 GHz**, independently corroborating the receive-only antenna finding.
  `uci get pineapd.wlan1mon.bands` = `2,5` — band 6 is not scanned, the shipped default as
  predicted. pineapd *is* running despite not autostarting: the Go UI brings it up.
- **🆕 `wlan2mon` — pineapd is configured for a THIRD radio that does not exist on the device.**
  Full interface spec, dual-band `2,5`, while `iw dev` shows only `wlan0`/`wlan0mon` (phy0) and
  `wlan1mon` (phy1). Nothing in these notes anticipated it. The natural reading is a slot for an
  **external USB radio**. **[A]** — that pineapd is *configured* for it does not prove the hardware
  supports one. Worth chasing: if the Pager can host a USB adapter as `wlan2mon`, that is a
  second, separate phy and could serve as the independent 5 GHz receiver the DFS branch needs,
  which is currently the only thing blocking it. *Falsified by:* no spare USB port, or the
  interface failing to appear when one is attached.
- **Instrument inventory confirmed on-device**, matching the rootfs reading item for item:
  `tcpdump`, `iw`, `hak5cmd`, `scp` present; `hcxdumptool`, `aireplay-ng`, `mdk4`, `python3`,
  `horst`, `tc` all **absent**; `libpcap.so.1.10.5` present. No Python means no scapy.
- **`libwifi.so.0.0.10` hash matches** the recorded `d3421de2…6ee1` on the live device, so the
  113-export map holds for this unit.

Operational facts the notes lacked: a box-fresh Pager ships **with no firmware** and boots to a web
installer on **port 1471**, with the wizard only appearing after a flash (§P0.1 is corrected); the
firmware version lives at **`/etc/pineapplepager/version`** (two lines, `1.1.3` / `Stable`), not in
`/etc/openwrt_release`; the clock ships ~18 months stale at the image build date; and this BusyBox
build has **no `cat` options at all and no `sed l`**, so command blocks written for a future bench
session must not use `cat -A` or `sed -n l` to inspect whitespace — use targeted `grep -c` instead.

**`2.0.0-stable` was released 2026-10-29** and is now what `latest` serves. Everything here remains
pinned to 1.1.3; versioned downloads still work
(`…/firmwares/1.1.3-stable`, 303 → signed .bin, sha256 `3073d6b8…cd33`).

### 2.0.0-stable, analysed — what it would and would not cost

Static analysis of the shipped image by the firmware session, whole-rootfs diffed against 1.1.3.
**No hardware**; the live bench readings above are the only measured data.

**Unchanged, byte-identical between 1.1.3 and 2.0.0** — so everything we know about them transfers:
`cfg80211.ko` and `mac80211.ko` (backports **6.12.61**, confirmed from the 2.0.0 binaries —
not a new fact, `pager-csa-primitives.md` already said 6.12.61; the looser "6.12" restatements are
now reconciled),
`regulatory.db`, `iw`, `libwifi.so.0.0.10`, and the `pineapd.wlan1mon.bands '2,5'` uci block.

**The one wireless driver that did change** is `mt76-usb.ko`, 16104 → 19396 bytes, adding three
functions absent from 1.1.3 — `mt76u_rx_desync`, `mt76u_rx_recovery_work`, `mt76u_rx_submit_error`
(0 occurrences each in the 1.1.3 module, 1 each in 2.0.0) — plus a new `usb->rx_lock` and
delayed-work machinery. **[V]** It is a USB **receive**-path recovery patch, which is the path the
"`wlan0mon` is receive-only, so it cannot hear 5 GHz" claim rests on, so it is worth knowing about
before interpreting any 2.0.0 reception result. The mt76 upstream snapshot did **not** move — both
carry the embedded tag `mt76-2025.11.06~eb567bc7` — so this is Hak5's own patch, not a version
bump; every other `mt76*.ko` differs only as a recompile. *Falsified by:* any of those three
symbols appearing in the 1.1.3 module, or the embedded tags differing.

**The gates did not move.** Same 16 FCC DFS channels by byte-identical mask code; the 6 GHz refusal
is still the blanket `chan->+0x1c == 8`; no new refusal string, config option or capability check in
any injection path; and **`pcap_inject` still has exactly one call site inside the gated function**,
so the non-pineapd bypass remains valid.

**What 2.0.0 does break: every `pineapd` address.** `adc9d36d…8493` → `d10ebedb…106f`,
1320040 → 1451176 B. `inject` `0x46e7d0` → **`0x475870`**; `inject_deauth` `0x472c14` →
**`0x4782d0`**. The MIPS16e disassembly recipe survives unchanged (same ELF flags, first PT_LOAD
still maps offset 0 → `0x400000`). Note gate 1 is **four check instances in two functions**, not two.

**So the cost of updating is confined to Stage C** — patching pineapd — which the plan itself labels
"only if the above is exhausted". `pagerinj` bypasses pineapd entirely, so the DFS branch and the
count-byte experiment are unaffected by the address moves.

**And that cost has already been paid.** The 2.0.0 patch sites are mapped, so moving firmware no
longer costs a re-derivation — four check instances in two functions, in both builds:

| site | 1.1.3 | 2.0.0 |
|---|---|---|
| `pineap_wifi_interface::inject` | `0x46e7d0` | `0x475870` |
| `interface_tracker::inject_deauth` | `0x472c14` | `0x4782d0` |
| blanket 6 GHz check (`lw rX,28(rY); cmpi rX,8; bteqz`) | `0x46e800` / `0x472c66` | `0x4758a0` / `0x478322` |
| DFS range-chain entry | `0x46e810` / `0x472c76` | `0x4758b0` / `0x478332` |
| `0x1111` mask immediate | `0x46e964` / `0x472d66` | `0x4759ea` / `0x478422` |
| CSA element construction (`index_beacon_ns+0xc0a` in both) | `0x4bee8a` | `0x4c6aea` |
| `li s1,0` feeding the count byte | `0x4bee6c` | `0x4c6acc` |

Static, from the 2.0.0 image; not yet checked against a running 2.0.0 device. The 1.1.3 column is
the one confirmed on hardware. All four 2.0.0 cells were disassembled rather than inferred: the two
6 GHz checks are the bit-identical `9847 7208 f260 6006` at the **same intra-function offset +0x52**
from each entry point, with only the `bteqz` target relocated, and both range-chain entries show
`5a91 sltiu v0,145`. Reproduce with
`objdump -D -b binary -m mips:16 -EL --adjust-vma=0x400000 --start-address=… usr/sbin/pineapd`.

**New option found on the way:** `CONFIG_MODULE_SIG` is **off in both**, so a hand-built or patched
`.ko` is not blocked by signature checks — a live alternative if the regdb route ever dies.
`CONFIG_CFG80211_REQUIRE_SIGNED_REGDB` is also off in both, and no `regulatory.db.p7s` exists.

**The changelog's "new firmware format"** is squashfs **xz → lz4**, 1 MiB → 256 KiB blocks (hence
"boots twice as fast" and 33.9 → 50.7 MB). The **container and signing envelope are unchanged** —
same `deadc0de` magic, same metadata versions, byte-identical `/etc/firmware-key` — which is mild
evidence a downgrade would still be accepted, though no version check was looked for.

**⚠ `BOTH` is untargeted, and it is the preselected default.** Four readings of the Go daemon,
identical in 1.1.3 and 2.0.0, all **[V]**: **`StartDeauth`**'s argument frame is 32 bytes against 28
for both **`StartDeauthAll`** and **`StartDeauthCsa`** — *corrected 2026-11-03; this line previously
attributed the 32-vs-28 split to `pineAPdDeauth` against `_All`/`_Csa`, which is wrong. All three
`pineAPd*` HTTP handlers have a 16-byte frame, being the same `http.HandlerFunc` shape, so they do
not discriminate; the split is in the `StartDeauth*` trio they call. The conclusion is unaffected —
re-measured against `moduledata.text` on 2026-11-03.* `_Deauth` allocates its request struct at
size class **SC3** while
`_All` and `_Csa` both use **SC2**; `_Deauth` is 924 bytes and parses `net.ParseMAC` **twice**
while `_All` and `_Csa` are **both exactly 668 bytes** and parse it **once**; and only one
`json:"target"` tag string exists in the binary against three each of `bssid` and `channel`.

**The inference, kept separate and tagged [A] because it is one:** three independent size
measurements put `_All` with `_Csa` rather than with `_Deauth`, and `_Csa`'s single MAC is
unambiguously the BSSID — so `_All`'s struct is `{bssid, channel}` and its one `ParseMAC` is the
BSSID. `resp_fire` (`payload.sh:1871`) still passes three positionals and Go's `json.Unmarshal`
drops the unknown field silently.

So **`BOTH` hits every client on the BSSID while `DEAUTH` beside it in the same menu hits one** —
and `posture_opts` lists `BOTH` first on the common badges while `pick_list` preselects element 0,
so **the broad attack is the default**. The payload's own comment documented `_ALL` as taking
`[target]` because hak5cmd's help says so; that comment is now corrected in place. Third instance
of help-not-matching-code in this binary, and the first with an operator-visible consequence.
*Falsified by:* firing `BOTH` at one client among several and seeing whether the others stay
associated; or statically, by a `target` field reachable from `_All`'s type descriptor.
**Whether to relabel or reorder the menu is the CamHound-deauth session's call, not this
branch's** — only the factually wrong comment was fixed here.

**⚠ `_pineap RECON CLIENTS` is new in 2.0.0 — CamHound's client rung has never run on a Pager, and on 1.1.3 it could not have listed a client before the `RECON DEVICES` fallback of 2026-11-03.**
Reading **[V]**: the byte string `CLIENTS` occurs **0 times** in 1.1.3's `/usr/bin/_pineap` and
**12 times** in 2.0.0's; lowercase `clients` 0 vs 4, `client` 0 vs 5. Count them with
`python3 -I -c "import sys;print(open(sys.argv[1],'rb').read().count(b'CLIENTS'))" <_pineap>` —
**not** with `grep -c`, which counts matching *lines* and on a binary with few newlines returns a
smaller, method-dependent number (an earlier revision of this line said "6 times" for exactly that
reason). The `0` is the robust half either way: absent is absent. So on 1.1.3 `recon_lines CLIENTS`
could never have returned a row before 2026-11-03, when `recon_verb_probe` started routing a 1.1.3
unit to `RECON DEVICES` (whose output was measured below, by hand on the bare unit — the first device
run of that path is still owed); on 2.0.0 the verb exists and answers.

Corroborated by the help lines themselves — `strings -a <_pineap> | grep -E '^RECON '`, sorted:

| 1.1.3 | 2.0.0 |
|---|---|
| APS, CHANNELS, COUNT APS, COUNT DEVICES, DEVICES, NEW, WAIT | same, plus **CLIENTS** and **COUNT CLIENTS** |
| IRSEARCH, ISEARCH, RSEARCH, SEARCH *(flat)* | `RECON {APS\|CLIENTS\|DEVICES} SEARCH\|ISEARCH\|RSEARCH\|IRSEARCH` *(now take a subject)* |
| **STOP** | **END** |

`cmd_dispatch_search` is a new symbol in 2.0.0 (`nm -D`, 0 occurrences → 1), which is what the
SEARCH verbs moving under a subject looks like. `_Z18cmd_dispatch_reconR14command_socketiPPc` sits
at `0x453308` in 1.1.3 and `0x4554fc` in 2.0.0 (`nm -D`, verified). Note the `STOP` → `END` row is
**not** a removed verb: `STOP` was never accepted by the recon dispatcher in either build — 1.1.3's
help was simply wrong — so a reviewer diffing only help tables will report a false regression here.

**The 2.0.0 device object, [V] from `_pineap HELP PARSE`** — itself a verb new in 2.0.0 (the byte
string `HELP PARSE` occurs 0 times in 1.1.3 and 3 times in 2.0.0; `keyed by an internal SSID hash`
0 and 1):

```
device: mac, time, signal, freq, packets,
        beacon / response / probe        (objects; absent if none)
beacon|response|probe are objects keyed by an opaque internal SSID hash (decimal string);
  each value: ssid, ssidlen, count, time, signal, freq, channel
  beacon values also: hidden, encryption, encryption_str, mfp_supported, mfp_required
```

Three consequences for CamHound. All are **pre-existing defects that become visible on flash, not
2.0.0 regressions** — they behave identically on both firmwares, and were simply unreachable while
`RECON CLIENTS` returned nothing. Line numbers are master's and will drift:

1. **`JQ_CLI` (`payload.sh:664`) reads probes as `.probes // .probed_ssids // .probed`** — none of
   the three exists. The key is **`probe`, singular**, and it is an **object, not an array**, so
   adding `.probe` to that chain *still* yields nothing: `$p0` becomes the object, the
   `if type == "array"` guard wraps it as `[$p0]`, and `map(.ssid // "")` returns `""` because the
   hash-keyed outer object has no `.ssid` of its own. The correct form reads the object's
   **values** — `[(.probe // {})[].ssid]`. *A relay from the firmware session called this "a
   one-word fix"; that was wrong, and this is the correction.*
2. **`JQ_CLI` reads association as `.ap_mac // .bssid`** — the device object has **no association
   field at all**, so every client row gets `-`. Not a typo to fix but a question of what source
   could fill the column. `dev/CamHound/PLAN_v2.md:256` already carried "no ap_mac" as a *risk*
   with "log one raw object to spike.log" as the mitigation; that Phase 0 spike is now **answered
   from the binary and can be retired**.
3. **`parse_cli_fallback` carries both defects independently of jq**: its `ap_mac` regex can never
   match, and its probes slot is a **hardcoded empty string** in its `printf` — contradicting the
   function's own header comment, which advertises `mac|ap_mac|packets|signal|probes|freq|time|channel`.
   So fixing `JQ_CLI` alone would leave `HAVE_JQ=0` operators broken.

*Falsified by:* `_pineap RECON CLIENTS format=json | jq '.[0]|keys'` on a 2.0.0 Pager with an
associated client returning a key that carries the BSSID — documented or not. That would collapse
(2) to a one-word fix.

**Measured on the 1.1.3 unit, 2026-11-03 (bare firmware, nothing of ours installed):**
`_pineap RECON CLIENTS format=json` prints `Unknown recon command` and exits **255**, so the absence
is now **[V]** by measurement, not only by byte count. `_pineap RECON DEVICES format=json` and
`RECON APS format=json` both return the device object in exactly the shape the 2.0.0 `HELP PARSE`
text describes — `beacon` / `response` / `probe` as hash-keyed objects whose values carry `ssid`,
`ssidlen`, `count`, `time`, `signal`, `freq`, `channel`, beacon values also `hidden` (a JSON
boolean), the device's own keys in alphabetical order (`freq`, `mac`, `packets`, `signal`, `time`)
beside them — and **no association key**. So the 1.1.3 object is the 2.0.0 object; the parsers
written for 2.0.0 read it unchanged (the fallback parser needed one fix: the device's own `signal`
and `time` sit *after* its `probe` object, not before). Consequence: CamHound now takes its client
rows from `RECON DEVICES` where `CLIENTS` is refused (`recon_verb_probe`, one call at start; a
client is a device that neither beacons nor answers probes), so **probe-only clients are listed on
1.1.3 today**, with probed SSIDs — still without association, which is what kit detection, client
Watch and per-client Disrupt wait on. The remaining source to check is the Go UI's recon API
(day-one 8b).

**Also newly available, and relevant to the posture rung:** the `mfp_supported`, `mfp_required`,
`encryption` and `encryption_str` fields on beacon values are **2.0.0-only** — byte-string counts
1.1.3 → 2.0.0 are `mfp_supported` 0 → 2, `mfp_required` 0 → 3, `encryption_str` 0 → 4 (bare
`encryption` is a substring of `encryption_str`, so it is not counted separately).
`posture_*` currently derives PMF from a beacon
capture via `rsn_caps`; on 2.0.0 the recon JSON exposes it per beaconed SSID directly. Whether to
use it is the CamHound sessions' call — recorded here only so it is not re-derived.

**Status, 2026-11-03: `clever-wozniak` has landed (`f012922`, merged at `536de09`), so this is no
longer somebody else's in-flight work.** Verify with `git merge-base --is-ancestor
origin/claude/clever-wozniak-hn3xyn HEAD`. Consequences (1) and (3) above are **fixed in code**:
`JQ_CLI` now reads `(.probe // {})[]?` (the object's values), and `parse_cli_fallback` walks the
probe object's `ssid` values and initialises `ap="-"`. **(2) is not fixed and is not fixable by a
parser change** — the field does not exist in the firmware's output. It is the one defect left, and
it is what makes the response rung unable to fire on either firmware (see the warning in "Open, and
needs the hardware").

**ANSWERED 2026-11-02 — CamHound is clear, and the DuckyScript surface is narrower than feared.**
Enumerated across `usr/bin`, `bin`, `sbin`, `usr/sbin`, `usr/libexec`: **69 commands in each
version, zero added, zero removed, 60 byte-identical, 9 changed — and none of the nine is one
CamHound uses.** All six uppercase commands it calls (`GPS_GET`, `LED`, `PAYLOAD_GET_CONFIG`,
`PAYLOAD_SET_CONFIG`, `RINGTONE`, `VIBRATE`) are byte-identical, as are `tcpdump`, `uci`, `jq`,
`hexdump`, `iw`, `libpcap.so.1.10.5` and `libwifi.so.0.0.10`.

- **The three `PINEAPPLE_DEAUTH_CLIENT*` commands survive with identical arity**, confirmed **from
  the parser** (`cmd_deauth` still does `cmpi a2,3`) rather than from help text. 46 `PINEAPPLE_*`
  commands, zero added, zero removed.
- **`hak5cmd` is a provable pure relink** — identical token and string sets, strings at a uniform
  −4 offset, the only real change being the version literal. **`_pineap` is a genuine recompile**
  (85.69% of bytes differ, 43 verbs retained, 13 added, 0 removed). *Both keep their exact size,
  which means opposite things — equal size proves nothing; byte-diff and look at where the diffs
  fall.* Related trap: `DISTRIB_REVISION` is 28 characters in both, so dozens of files are
  same-size-different-hash from that string alone.
- **Two caveats that bear on the failure mode this file warns about.** *Help text is not a
  specification*, provable in both directions: 1.1.3's `_pineap` help advertised `RECON STOP`,
  which the dispatcher never accepted, and 2.0.0's help says `DEAUTH [bssid] [target]` while the
  parser still demands three. And *`hak5cmd` being unchanged does not establish runtime
  behaviour*: it is only an HTTP client to `/tmp/api.sock`, and the handlers for those routes live
  in **`pineapple/pineapple`**, a Go daemon that grew +1,388,760 bytes (`4493c6c6…ad3e` →
  `b16887ba…`). *An earlier revision of this line called that daemon "outside static reach" and
  said only a capture could settle it. **Both halves were wrong** and are withdrawn:* unlike
  `pineapd` it is **Go 1.27.0, stripped but retaining all 42 section headers**, so `.gopclntab`
  survives and the function table is recoverable (18815 → 19248 functions).

  **Statically confirmed unchanged:** the three HTTP handlers (`pineAPdDeauth`/`All`/`Csa`), the
  three logic functions (`StartDeauth`/`All`/`Csa`) and the forwarder `exchangeCommand` — identical
  in size *and* mnemonic sequence, every differing word a `lui`/`addiu` address pair or a `jal` to
  the same callee. `ValidateDeauthCapable` is inlined into byte-equivalent bodies, so the guard
  cannot have changed either. **The Go daemon is a thin forwarder to pineapd**
  (`StartDeauth*` → `exchangeCommand` → pineapd), corroborated by no `switch_count` / `csa_count` /
  `chanswitch` string existing anywhere in it in either version — so CSA frame construction really
  is pineapd's count-0 code and nothing in the Go layer touches it.

  **What a capture is still for, narrowed:** two shared-infrastructure functions on the deauth path
  did change — `GetStructFromBody` (same size, different mnemonic sequence) and `StartPineap`
  (732 → 252 bytes) — and the PMF UI setters `Get/SetReconMFPAPDeauthOptions` could **not** be
  resolved, because ~4.5% of functab entries come out ≤16 bytes (Go's tiny wrappers and
  mid-function fragments) and those setters land in that band. One capture settles all three. The
  seven functions above are unaffected by that caveat: identical size plus identical mnemonic
  sequence are symbol-table-independent, and their sizes are exact instruction multiples.

**The nine that did change** — none used by CamHound, but three matter to this repo's other
payloads and one matters in a chamber:

| command | change |
|---|---|
| `GPS_CONFIGURE` | **BREAKING.** Gained a mandatory `PINEAP\|GPSD` mode keyword; endpoint moved `gpsd/set_config` → `pineap/gps/set_mode`. Breaks `library/user/general/wardrive_activate/payload.sh:172`. |
| `WIGLE_UPLOAD` | **Data-loss.** See below. |
| `WIGLE_LOGIN` | Adds a **mandatory** reachability probe to `api.wigle.net` with `\|\| exit 1`. **In a shielded chamber it now fails closed where it used to prompt.** |
| `WIFI_WAIT` | Off-by-one fixed, but **`check_count == 0` now waits forever** where it previously returned after one iteration. |
| `WIFI_CONNECT` | Relaxed to 3–5 args; a 1.1.3-era 5-arg call still works. |
| `WIFI_{MGMT,OPEN,WPA}_AP_CLEAR` | Posted the wrong JSON key on 1.1.3 and **silently did nothing**; now actually clear. |
| `GPS_LIST` | Internal only. |

**`WIGLE_UPLOAD` — `[V]`, read from the rootfs trees, not relayed:**

```diff
-  echo rm "$__file"
+  rm -f "$__file"
-  echo mv "$__file" "$__archive_dir/$__file"
+  mv "$__file" "$__archive_dir/$(basename "$__file")"
+__archive_dir=/root/loot/archive/wigle
```

So on 1.1.3 `--archive` was a no-op *and* malformed (`__archive_dir` was unset, plus a double
`shift` that broke the single-file case), and `--remove` echoed. On 2.0.0 both are real.
`library/user/exfiltration/wigle-toolkit/payload.sh:121` therefore **really deletes loot** on the
`LEFT` path, and its "Press A if OK" gate at `:102` was decorative on 1.1.3 because nothing
happened either way. **Identical keystrokes, identical UI, real deletion.**

*(One framing correction: `od` ships in neither image, so CamHound's `od` fallbacks in
`pcap_words`/`pcap_bytes` never execute on a Pager. That is **by design, not dead code** — the
comment at `payload.sh:519` says so, and the branch exists for the laptop `--replay`/`--selftest`
path on hosts that lack `hexdump`. The finding confirms that comment's "a Pager always has busybox
hexdump" assumption.)*

If you are working on **unlocking 6 GHz or DFS injection**, treat the gate claims below as the prior
state of the investigation, not its conclusion — the determination plan is a plan precisely because
the question is open.

- **Two injection gates in series, and conflating them explains most confusion.** *Gate 1* is
  pineapd in userspace: a hardcoded refusal of the 16 FCC DFS channels
  (`52 56 60 64 100 104 108 112 116 120 124 128 132 136 140 144`) plus a blanket 6 GHz check. Regdb-immune — no `iw reg set` or
  regulatory.db edit lifts it. `pcap_inject` has exactly one call site, inside the gated function,
  so a non-pineapd injector bypasses it entirely. *Gate 2* is cfg80211: it prohibits
  `DISABLED | NO_IR`, **not** `RADAR`, so under US **no 5 GHz channel in 36–165** is blocked by it
  and the DFS refusal is entirely gate 1's. (Not "no 5 GHz channel at all", which this line used to
  say: **169/173/177 do carry `NO_IR`**, from the US rule `5850–5895 … PASSIVE-SCAN`, which is the
  `NO_IR` alias. Confirmed on hardware 2026-11-02 — see "First contact" below.)
  A gate-2 drop is **silent** — the frame is freed and the path
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
  mac80211 from **backports-6.12.61** (read from the module binaries; the same in 2.0.0).
  Every address above is pinned to it. `pineapd` is **MIPS16e** with
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
count-byte experiment (day-one step 17a). (`inj_parse_channels` is **no longer** on this list — it
ran against a live radio on 2026-11-02 and was correct; see "First contact".)

**⚠ The response rung cannot transmit from the USER PAYLOAD on any shipped firmware, and flashing
does not fix that. The Recon hooks are a different story — see the exception below.**
The blocker is the **association column**, not the firmware version. On **1.1.3** `_pineap RECON
CLIENTS` does not exist; since 2026-11-03 client rows come from `RECON DEVICES` instead, but that
object carries no association either, so every client row has `AP_OF` `-` and `resp_target` refuses
it exactly as on 2.0.0 (below), while every AP row has `R_TARGET` broadcast, 0 subjects, and
`resp_fire` refuses with `NO_CLIENTS`. On **2.0.0** client
rows arrive but the device object has no association field, so `JQ_CLI`'s `(.ap_mac // .bssid //
"-")` gives `-` for every one; an AP row then finds 0 matching clients and refuses the same way,
while a client row never even reaches the sweep because `AP_OF` is `-` and `resp_target` returns 1
at `payload.sh:2122-2123`. On both, the user payload transmits nothing and logs the refusal.

**⚠ The Recon client hook is the exception, and it transmits on 1.1.3 today.** Everything above is
about the **user payload**, whose association comes from `recon_lines CLIENTS`. The two Recon hooks do
not use it: `hook_target` (`dev/CamHound/hook_main.sh:20-37`) builds its one row from the
`_RECON_SELECTED_*` variables the Recon UI exports, setting `AP_OF[$HOOK_MAC]` from
`_RECON_SELECTED_AP_BSSID` and the channel from `_RECON_SELECTED_{CLIENT,AP}_CHANNEL`, with **no
`_pineap RECON` call at all**. So a hook client row has a real association and a real channel,
`resp_target`'s client branch passes, and `resp_fire` transmits behind the usual picker and confirm —
on 1.1.3, on 2.0.0, regardless of what `RECON CLIENTS` returns. *Found by the recon-side session's
review; verified here at `hook_main.sh:35` and `payload.sh:1982-1988`.* So "the rung cannot
transmit" is true of the user payload only, and the rung is **not** inert on the device as a whole.

*Corrected 2026-11-03: the first version of this warning said `RESPONSE=1` "buys nothing until the
device is flashed", which implied a flash would buy a working rung. It would not, and that was the
load-bearing half. The 1.1.3 half stands.* Note the determination plan's standing instruction —
`dev/pager-6ghz-determination-plan.md:155` "never flash it to this device" — therefore costs nothing
on this axis. **[A]** — the byte counts and object shape are `[V]`; the code paths were read; the
composition is the inference. *Falsified by:* a Disrupt transmitting **from the user payload** on either firmware (the earlier
form of this falsifier said "on an AP row", which could not catch the hook path at all), or
`_pineap RECON CLIENTS format=json | jq '.[0]|keys'` on a 2.0.0 Pager returning a key with the BSSID.

**Lead, half followed 2026-11-03:** 1.1.3 *does* have `RECON DEVICES`/`COUNT DEVICES` (only
`CLIENTS` is new), and CamHound now reads it where `CLIENTS` is refused (`recon_verb_probe`,
`JQ_DEVCLI`), so probe-only clients are listed on 1.1.3 with their probed SSIDs — but the object
carries no association (measured on the bench, bare 1.1.3), so that half is spent. The other half is
untested: the `probe`/`beacon` objects are keyed by an opaque SSID hash, so intersecting a client's
probe keys with an AP's beacon keys might recover an association the JSON never states. **[A]** — a
client probing for an SSID is not necessarily associated to it, and the BSSID-filtered capture in
`dev/CamHound/RESPONSE.md` §13a is the better evidence.

**The association column is a chokepoint gating FIVE features, and the rung is fixable without it.**
Verified in code 2026-11-04: `AP_OF[mac] == "-"` disables Watch-on-a-client and Stimulus
(`watchable()`, `payload.sh:1018`), kit detection (`kit_eval`, `:1237`), the AP→client tree
(`:2374`) and the response rung (`resp_target`, `:2122-2123`).
But the *attack* never needed it — `CSA` is `<bssid> <ch>` and `BOTH`'s target is discarded, and
`RECON APS` supplies both on 1.1.3, so the firmware can transmit today. What refuses is CamHound's
own `NO_CLIENTS` measurement guard. The fix is to read the association off the air with a
BSSID-filtered capture (the filter shape at `:1804`, the radiotap-aware frame walker in
`beacon_find`), which is firmware-independent and better evidence than Recon's cumulative counters.
Full working, ranked options and the resolved mechanics are in `dev/CamHound/RESPONSE.md` §13a
and §13a-i. **Not yet implemented.** ⚠ Three mechanics stated in §13a's first draft are
**wrong** and are corrected in §13a-i, which is the build decision of record: `addr2` is the
client only on a **ToDS** frame, `-s 32` cannot reach `addr2` at all, and the bash
`pcap_bytes`/`hex_octet` walker beacon_find uses is **O(n²)** and cannot be reused at this
file size.

**Two 2.0.0 hazards in this repo's other payloads** — `wigle-toolkit` really deletes loot, and
`wardrive_activate` is broken. Both are `[V]` from the rootfs trees and written up in full in
§"2.0.0-stable, analysed" above; not repeated here, so there is one copy to keep correct.

The **instrument** for the injection side is no longer open: `dev/injector/` holds `pagerinj`,
cross-built for `mipsel_24kc`/musl/soft-float, ABI-verified, and frame-validated with no radio
(capture → clone → append → transmit exercised over a `veth` pair, with the step-17a count pair
confirmed to differ in exactly one byte on the wire, and the FCS-strip precondition asserted by
mutation test). **Current size, hash and selftest count live in `dev/injector/README.md`** — they
have drifted twice already, so they are deliberately not restated here. It replaces `hcxdumptool`
as the primary injector because **neither hcxdumptool nor aireplay-ng can build a CSA frame**, which
step 17a needs. It now also carries 17a's third arm (`--ecsa-count`: element 37 count 0 plus a live
eCSA, since `csa_present()` discards per element) and the unicast cat-0 Spectrum-Management CSA of
day-one step 17c. Since df756c3 it also binds its capture to `-i`, skips a clone source that already
carries a CSA or eCSA element, refuses a `--chan` equal to the cloned beacon's DS channel unless
`--allow-same-chan`, and emits a radiotap RATE field with `--phy-rate <Mbps>`.

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
the image URLs and their sha256s are in `dev/pager-6ghz-determination-plan.md` §0.4 (with the recovery
ladder); the version-identity gate is §P0.2. **Both** 1.1.3-stable (`3073d6b8…cd33`, 33884001 B)
and 2.0.0-stable (`17dab975…7968`, 50726753 B) are recorded there, because every 2.0.0 claim in this
file was derived by diffing the two and is not re-checkable from one alone. Put each in its own new
empty directory and treat it as untrusted per the standing rules.

Note the rootfs is **lz4** squashfs in 2.0.0 and **xz** in 1.1.3, so an `unsquashfs` built without
lz4 support will open 1.1.3 and fail on 2.0.0 — check `unsquashfs -h` for the decompressor list
before concluding the image is bad. In practice the likelier failure is `unsquashfs` not being
installed at all: a reclaimed container loses it, and `apt-get install squashfs-tools` then fails
with "Unable to locate package" until you `apt-get update` first. Also note `-e` takes a *file*
listing paths; to extract a few by name put them after the image
(`unsquashfs -d out rootfs.sqfs pineapple/pineapple`).
