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

  **⚠ That rule was violated three times on 2026-11-10 by a session that had read it, so here is
  the mechanical form: if a claim you are about to write names an artifact — a `file:line`, an
  address, a sysfs path, a kernel function — OPEN THAT ARTIFACT IN THE SAME TURN, before the claim
  goes anywhere.** Knowing the rule is not executing it. All three failures had the citation already
  in hand and none of the three was a hard inference:
  - a bench fix was built on "a mac80211 monitor vif reads `operstate` down while administratively
    up". One `cat /sys/class/net/wlan1mon/flags` on the device refuted it — and the fixture written
    to prove it had been authored *from the hypothesis it was testing*;
  - "the operational prediction fails in both halves" conflated
    `ieee80211_sta_process_chanswitch()` (`mlme.c:2370`, honours count 0) with
    `ieee80211_mgd_csa_present()` (`mlme.c:8356`, discards it) — two different functions, one of
    them cited by name in this file for a week before anyone opened the file;
  - an audit finding's `git ls-files` citation was accepted unrun, and was wrong (the binaries it
    listed are `.gitignore`d).

  **Corollary, and it is the sharper half: a fixture you author from your own hypothesis tests the
  hypothesis against itself.** Build the fixture from a measurement or from the artifact, never from
  the claim — and if you wrote the code, you are the wrong person to confirm an audit finding about
  it. Prefer one primary source you opened over three reviews that agree.
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
bash dev/CamHound/harness/run_harness.sh                            # ALL 16 scenarios; must print "0 failure(s)"
```

**The harness argument is a scenario filter, not a mode.** `run_harness.sh live` runs the `live`
scenario alone - 5 checks of 130 - and still prints `0 failure(s)`, which reads exactly like a full
pass. This gate list said `live` until 2026-11-04 and every session that copied it was running a
fourteenth of the suite (sixteenth now). No argument (or `all`) runs them all; a scenario name runs one,
which is what you want while iterating, never for the gate.

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
`dev/CamHound/harness/stubs/`. The `tcpdump` stub tells the three BSS-shaped captures apart by their
filter (`(wlan addr1 …` membership, `(wlan addr2 …` the inverse lookup, bare `wlan addr2` its
uplink-only retry) and answers the lookup **only when the radio could have heard it**: the EXAMINE
stubs keep a hop marker (`/tmp/cs_harness_hop`) and the parked channel, and a client is heard when
the radio is hopping or parked on its AP's channel — so a lookup parked on the wrong channel misses
in the harness for the reason it would miss on a device. Its `LIST_PICKER` answers only with items on the page it was handed: an
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
(`SETTINGS_TABLE` rows are `KEY|kind|floor|group|label` over all twenty starred keys; `settings_menu`
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

**Association, station → BSSID, read off the air — landed 2026-11-10, LAPTOP-VERIFIED ONLY.** No
firmware names a client's AP, so `AP_OF` was `-` on every client row and five features slept (see
"Open, and needs the hardware"). The user payload now reads it **when the operator picks Watch or
Disrupt on such a row, never in the scan loop** — the lookup parks the radio, and a background pass
would blind Recon for as long as it ran.
- `assoc_lookup <client>` → rc 0 with `AP_OF` set and the row usable at once; rc 1 with `ASSOC_WHY`
  one of `NOT_CLIENT`, `NO_CAPTURE`, `NO_FRAMES`, `NO_PAIR`, `AMBIGUOUS` (runner-up at least half the
  leader), `SNAP_SHORT`. A failed lookup teaches nothing and keeps an earlier answer. `NO_FRAMES` is
  worded "not heard on ch N", never "not associated": a client row's frequency is the device-level
  **last-heard** one, and a scanning client is heard off its AP's channel.
- `lock_channel <ch> <secs>` is the park: `PINEAPPLE_EXAMINE_CHANNEL` **alone**, read back three
  times, with `lock_target`'s rc contract (0 parked, 3 unverified and PROCEED, 2 somewhere else).
  `lock_target` cannot be used because it wants a BSSID and returns 2 without trying the channel
  when the BSSID step does not park. **⚠ `EXAMINE_CHANNEL` without a preceding `EXAMINE_BSSID` has
  never been issued on a Pager** — every measured park issued both — so rc 2 does not fail the
  lookup: it releases the radio and listens across the hop for three windows (`lock=hop`).
- `assoc_capture` is `capture_bss` with the client in the BSSID's place:
  `type data and (wlan addr2 <mac> or wlan addr1 <mac>)`, uplink-only retry when the OR form does
  not arm. `CLI_AWK` (lib block) grew `mode=pairs` for the walk: the same DS-bit decode as the
  membership walk, printing `PAIR <sta> <bssid> <n>` for every pair seen twice, group addresses and
  our own MACs dropped.
- `assoc_learn` is the one place that decides what may be learned: never itself, never an AP row,
  never over an AP the firmware supplied, and no row is invented for a station Recon has not listed.
  The AP row's channel wins over the channel listened on; **the listening channel is recorded only
  behind a verified park** (across the hop it is where the client was last heard and nothing more,
  so such a row says `Disrupt n/a (no channel)` rather than transmitting on a guess); a move to an
  AP with no row drops the old AP's channel and SSID instead of carrying them over.
- `assoc_learn_members` learns the same fact from a membership capture — `resp_members` calls it
  behind `command -v`, because that function is copied into the hooks and this one is not — so one
  AP-row Disrupt teaches every station it heard, and kit detection wakes up for them. Its log line
  gives both numbers, `members of <bssid>: N heard, M client row(s) now carry this AP`: a station
  with no Recon row is only remembered, and one whose AP the firmware supplied keeps it.
- `run_cycle` re-applies `ASSOC_BSS` every cycle (the firmware's `-` would otherwise wipe it, and a
  firmware-supplied AP still wins — and the `ASSOC_CH` fallback applies only to the AP it was
  recorded for, so a firmware-supplied AP never inherits another AP's channel);
  `assoc_stale`/`assoc_refresh` look again before Watch or Disrupt acts on an AP learned more than
  `ASSOC_TTL` ago, listening on the **row's** channel (its AP's), not on the client's last-heard
  frequency. **The call sits at the top of `watch_menu` and `disrupt_menu`** (watch core, behind
  `command -v`), not at the card, so the scan funnel's Watch offers, the post-Watch Disrupt offer
  and `AUTO_RESPOND` get it too — the first version re-checked only from the card, which the
  review of 2026-11-10 caught as a promise the docs made and the code did not keep.
- The card says `Watch (find AP first)` / `Disrupt (find AP first)` (`detail_card`; `disrupt_row`
  in the watch core, guarded on `command -v assoc_can` so the hooks keep `n/a`). **An AP that was
  heard without its channel gives `Watch n/a (no channel)` / `Disrupt n/a (no channel)`**
  (`assoc_nochan`; `watchable` in the lib asks it behind `command -v`): `lock_target` reads a
  channel of 0 as "any channel will do", so a Watch there would park wherever the radio happened
  to be and loot a row for channel 0. The state clears when Recon lists the AP. Two starred keys,
  `ASSOC_CAP_SECS` (clamped to 2–30 by `assoc_clamp`, from `load_overrides` and `settings_apply`:
  the window is slept on, tripled across the hop, with no button check) and `ASSOC_TTL`, wired in
  `load_overrides` and `SETTINGS_TABLE`.
- Selftest block `7m association`; harness scenario `assoc` (six arms on the `HARNESS_NO_CLIENTS=1`
  shape; `HARNESS_NO_PARK`, `HARNESS_ASSOC_TWO` and `HARNESS_NO_OR` drive the refused park, the
  ambiguous pair and the refused OR filter; the miss is the fixtures' own — a camera last heard on
  2437 MHz whose AP is on channel 36).

*Falsified by:* a lookup naming a BSSID the client is not associated to; `NO_FRAMES` on the right
channel for a client that is passing traffic there; or `lock=hop` on every lookup, which would mean
`EXAMINE_CHANNEL` alone does not park (bench check: `dev/pager-day-one.md` 8d). **What it does not
buy:** there is no background pass, so a client nobody picked and no membership capture heard still
reads `-`, and kit detection and the report tree cover only the clients that have been resolved.

**Watch rung** (behaviour without identity) — `watch_menu`, `start_caps`/`stop_caps`,
`pcap_words`/`pcap_bytes` (both have `od` fallbacks), `pcap_buckets`, `bucket_stats`
(**`PCAP_AWK` aborts the whole file on `incl_len % 4 != 0`, so it only parses the `-s 32`
captures it ships with — raising any Watch snap to reach addresses breaks it; verified
2026-11-04, see `dev/CamHound/PLAN_v2.md` item 1**),
`capture_ready` (gates `HAVE_TCPDUMP` on tcpdump + *either* hex dumper), `lock_target`/
`unlock_target` (EXAMINE channel lock), `capture_beacon`, `beacon_find`, `ie_find`, `rsn_caps`.
**⚠ `lock_target` rc 3 is "unverified, PROCEED" and is not a failure — do not normalise it to 0.**
It is returned when the channel cannot be read back at all, when only ONE of the three samples was
readable (one sample cannot establish that the radio is parked), and when the read after
`EXAMINE_CHANNEL` comes back empty. All three write `lock=unverified` to the loot and carry on,
which is the point: refusing every response on a device whose channel will not read back is worse
than labelling it. rc **2** is the refusal. Four separate fixes converged on this shape over two
days; see "Third contact"'s last bullet for the whole sequence.

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
`csa_clamp` (bounds `CSA_INJ_SECS`/`CSA_INJ_WAIT` to 1-60 before both the invocation and the lock
budget, because `pagerinj` reads `--secs 0` as "transmit until signalled" and `csa_issue` runs it in
the foreground — a hand-edited 0 would have parked `resp_fire` forever with a transmitter no
teardown could reach; the injector is now `child_add`ed and `timeout`-capped as well),
`csa_newchan`/`csa_issue` (the CSA leg: routes to `CSA_INJECTOR` when one is configured and
executable, else the firmware command, and owns the rc-vs-stderr question the two senders answer
**oppositely** — `hak5cmd` exits 0 on every error path so stderr is its only signal, while
`pagerinj` prints its `sent=/failed=` summary to stderr even on success so rc is its only signal;
one rule for both would file a fabricated result). **`CSA_INJECTOR` defaults to empty and should
stay that way until the bench says otherwise**: `dev/injector/README.md` requires pineapd STOPPED,
and CamHound cannot stop pineapd — Recon, the EXAMINE lock and every deauth command *are* pineapd —
so the in-payload path bets that the EXAMINE lock holds the channel well enough, and that bet is
unmeasured. The validated way to run `pagerinj` is standalone: `dev/injector/run_17a.sh`. The three
CSA keys (`CSA_INJECTOR`, `CSA_COUNT`, `CSA_CHAN`) are deliberately **unstarred**, because `cfg()`
accepts integers only so a path cannot arrive via `PAYLOAD_SET_CONFIG`, and a star without a
`SETTINGS_TABLE` row is a lie.
`resp_fire`, `resp_snapshot`, `resp_verdict` (MOVED / NO_EFFECT / INCONCLUSIVE from recon packet
counters), `resp_aggregate`, `resp_write` (→ `responses.tsv`, header `RESP_HDR`), `auto_respond_ok`.
**⚠ `csa_issue` rc 2 means "it DID transmit and was then capped by its own timeout" — do not
collapse it to 1.** `wait` returns `timeout`'s status, not the injector's, so a capped run comes
back 124 whatever the injector exited with; scoring that as a refusal writes `CMD_REFUSED`, which
asserts no frame left the radio, for frames whose own stderr says `sent=90`. Both call sites in
`resp_fire` (the `CSA` arm and the `BOTH` arm) handle rc 2 as a send, and the selftest pins it.
Timings: `RESP_LOCK_SECS`, `RESP_SETTLE_SECS` — both starred and wired; the lock must exceed
fire + settle or it expires mid-measurement.
`RESPONSE` **defaults to 1** — recon and response are both live out of the box; `RESPONSE=0` is the
recon-only run. `SWEEP_TARGETED` **defaults to 1**: after a BSS-wide attack, `resp_fire` also sends
one **targeted** `PINEAPPLE_DEAUTH_CLIENT` per recovered member. *Its original rationale — "a
targeted deauth dropped a client that ignored both broadcast forms" — was refuted 2026-11-09: the
broadcast form of the SAME opcode drops that client fine, and the `_ALL`/`_CSA` failures are a
firmware defect, not the station's choice (see "Third contact").* The sweep is kept, for a reason
that survived the refutation: broadcast reaches members the capture never enumerated, targeted
reaches a member whose traffic the BSS-wide frame somehow misses, and the two cost n+1 frames
together. It is guarded on `attack_scope`, not on `R_TARGET`, and never runs for `CSA`. Since
2026-11-09 it sweeps **heard** members, not only measurable ones — the transmit set and the
measurement set are no longer the same array, which is what had silenced the rung entirely on an AP
whose only client carried a randomised MAC. `RECON_FRESH` **defaults to 1** and starts
a fresh Recon session at launch, so a run reports what is transmitting now; it wipes the Recon
session for anything else using it, which is why it is starred. `attack_scope <key>` → `cli`|`bss` is the single place that decides blast radius:
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
**Membership comes off the air (since 2026-11-04), because no shipped firmware supplies an
association.** `bss_clients`/`capture_bss`/`CLI_AWK`/`pcap_stream` (lib block, so the hooks get them)
read a BSSID-filtered data capture and report which stations talked to it; `resp_snapshot` **unions**
that set with the `ap_mac` test rather than replacing it, and ignores a set gathered for a different
BSSID. `resp_members` turns a failed capture into one of three answers — `NO_CAPTURE`, `SNAP_SHORT`,
`NO_CLIENTS` — instead of one silence (a fourth, `NO_MATCH`, has had no producer since the
2026-11-09 transmit-set fix). **Since 2026-11-10 none of them refuses an AP row — operator-decided:
*"I'll accept nuclear blast. Let the AP row fire broadcast frames."*** `CLI_AWK`'s `seen[c] >= 2` filter is unchanged and can
legitimately admit zero members from an occupied BSS; when the subject set is empty after both
sources, `resp_fire` now fires the broadcast anyway, makes the broadcast target itself the one
subject with `p0 '-'` (so `resp_verdict` scores it `INCONCLUSIVE`), skips the targeted sweep, and
logs `no-members <bssid> why=<reason>` before the fire and `fired <key> <bssid> broadcast with no
members recovered why=<reason>` after it. The reason is now an `events.log` line, never a loot
verdict; refusals that are not about membership (`LOCK_FAILED`, `CMD_REFUSED`, a missing command)
are untouched. Selftest `zero members, AP row: …`; harness `nomem_fired`. `resp_fire` takes the lock **first**, captures,
**re-arms** for the measurement, then fires; the re-arm exists because the walker's parse is
2.5-9.1 s on the device and no constant covers it honestly. The `resp` line logs the measured dwell.
Read `RESPONSE.md` §13a-i before changing any of it: three mechanics that look obvious are wrong
there (`addr2` is the client only on a ToDS frame; `-s 32` cannot reach `addr2` at all; the bash
substring walker is O(records x filesize)).
**The honest bound — one fix did not buy five, and the second fix is laptop-verified only.** The
membership capture recovers who is on a BSS *without* naming a client's AP, so on its own it left
client Watch, Stimulus, kit detection, the AP→client tree and a user-payload **client**-row Disrupt
asleep. *Amended 2026-11-10:* the inverse lookup (code map, "Association") now fills `AP_OF` for a
client the operator picks, and `resp_members` hands every station a membership capture heard to
`assoc_learn_members`. So a client row is watchable and attackable **after one lookup that hears
it**, and the other three wake up for the clients that have been resolved — not for the rest, there
being no background pass. None of that has run on a device. What fires with no lookup at all is
unchanged: a user-payload **AP** row, the Recon **access_point** hook, and the Recon **client**
hook's subject set — and since 2026-11-10 (operator-decided, "nuclear blast") an AP row fires its
broadcast frame **even when the capture recovers nobody**, looting one `INCONCLUSIVE` row for
`ff:ff:ff:ff:ff:ff`. See `RESPONSE.md` §13a-i's bound table.

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

Set by the operator on 2026-11-03, rule 2 amended by the operator on 2026-11-04. For every session
that runs an agent review here. The point is not to ration the heavy shapes — multi-finder reviews,
three-lens adversarial verification, judge panels, critic rounds, fix-then-reverify loops are all
welcome, and are the right default for code the device runs, hardware-facing claims and anything
novel. The point is to stop them appearing on trivial work: a doc edit, a comment's wording, a
stale count, a renamed check. Judge the tier by what a wrong finding would cost if acted on and by
how likely the finder is to be wrong, and spend accordingly.

1. **Tier the verification by consequence and by likelihood of error.** A finding gets the full
   three-lens adversarial pass (trace, intent, impact) when a fix would change code the device runs,
   when it contradicts a fact measured on hardware, or when it is an inference composed from verified
   readings — the error shape this project has been bitten by twice. Freshly written code rates
   higher on likelihood of error than code that has survived a prior pass and a harness run, even at
   equal consequence. Docs, comments, stale counts, wording and test gaps get one sceptical verifier
   whose prompt says: default to refuted unless you can reproduce it from the artifact. When in doubt
   between tiers, take the heavier one and say why.
2. **No cap on the finder pool, and no batching ceiling — except for `Fable` and `Mythos`.**
   Scale the review to the question. If it warrants twelve finder dimensions, or one agent per
   finding per lens, run it; rule 1 is what keeps heavy shapes off trivial work, not a fixed
   ceiling. Say in the summary why you went wide, so the next session can judge whether it paid.
   **The exception, matched on the agent's model name: `Fable` and `Mythos` keep the old limits**
   — at most four finder dimensions per review, verification batched at nine findings per agent
   grouped by file, and never one agent per finding per lens unless the claim would redirect the
   bench, overturn a measured fact, or change what the device transmits, with the reason stated.
   *Amended 2026-11-04. The cap previously applied to every model. It was dropped because the
   constraint it encoded — spend proportionate to consequence — is rule 1's job, and a hard
   ceiling was also costing real findings: the review that produced this amendment's sibling
   commit refuted two blockers in a proposal its own author had already gated, and did so by
   fetching a primary source no single-dimension pass would have reached.*
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

**⚠ THE "CONTACT" SECTIONS CONTAIN WITHDRAWN CLAIMS, STRUCK IN PLACE ON PURPOSE — five of the
eight do as of 2026-11-10, and the eighth is itself where part of the seventh is withdrawn.** Text
in `~~strikethrough~~` is wrong and is kept because the *shape* of the error is the useful part —
five of the withdrawals are the same shape, a correct reading composed into a wrong inference, and
four of those were withdrawn by the session that wrote them, three within hours. **That tally is
the file's own, is enumerated nowhere, and so is not a figure you can re-check; two more of the
same shape have been struck since it was written — Fourth contact's "most plausibly the CSA" and
Seventh contact's "the client went to ch 1", the latter in "Eighth contact".** So: read a struck
claim as a warning, never as a fact, and when two sections disagree the **later one supersedes**:

| question | superseded | by |
|---|---|---|
| the three deauth commands | Second contact | **Third** |
| the count byte's effect | Fourth contact | **Fifth** |
| what the control arms established | Fifth contact | **Sixth** |
| why the feed froze | Fourth contact | **Seventh** (the captures) |
| whether a switch ever completed | Seventh contact | **Eighth** (the capture, frame by frame) |

If you find a third answer anywhere, that is a bug in this file and worth a commit on its own.

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

### Second contact — the response rung fires, and five open questions close, 2026-11-05

Live bench session on the 1.1.3 unit with CamHound installed. Everything here is measured, with the
command or the log line that produced it.

- **⭐ A Disrupt transmitted FROM THE USER PAYLOAD.** This is the named falsifier for "the response
  rung cannot transmit", and it is now spent. Loot row: `74:fe:ce:8e:58:1d|ap|…|ch 9|D+C|0c00|BOTH|
  PINEAPPLE_DEAUTH_CLIENT_ALL|ok|3|4|NO_EFFECT`. The whole chain ran: lock, membership capture,
  re-arm, fire, settle, measure, write.
- **Membership really does come off the air.** `resp members 74:fe:ce:8e:58:1d n=1 why=ok itmax=56
  recs=12 short=0 trunc=0 runt=0 dwell=4s lock=26s` — one station recovered from a BSS whose JSON
  carries no association field, with zero short, truncated or runt records. `bss_clients`,
  `capture_bss` and `CLI_AWK` had only ever run against harness fixtures.
- **Phase 0 13a is ANSWERED: data frames do appear on `wlan1mon` under a held EXAMINE lock.** This
  gated Watch entirely and was a shared dependency with the 6 GHz branch. Confirmed twice, the
  second time by hand: `PINEAPPLE_EXAMINE_BSSID …; PINEAPPLE_EXAMINE_CHANNEL 8; tcpdump -i wlan1mon
  -e type data and wlan addr1 …` returns a steady stream of ToDS frames.
- **`itmax=56`** is the radiotap header length this hardware emits. So a record needs `56 + 16 = 72`
  bytes to reach `addr2`, `-s 32` could never have worked (RESPONSE.md §13a-i's arithmetic, now with
  a real number), and `CLI_CAP_SNAP=128` has comfortable margin.
- **`lock=ok` on this unit**, on both the initial lock and the re-arm, so `cur_channel` reads the
  channel back. The `lock=unverified` path added in `32af613` is correct to exist but does not fire
  here. *Falsified by:* a unit with neither `iwinfo` nor a numeric `iw dev info` read-back.
- ~~**⭐ Targeted deauth works; both broadcast forms do not — against ONE client.**~~
  **REFUTED 2026-11-09 — see "Third contact" below, which supersedes this bullet entirely.** The
  readings were right and the inference was wrong, in the shape this file warns about twice. What
  was measured on 2026-11-05: on AP `FC:58:5A:08:42:15` ch 8,
  `PINEAPPLE_DEAUTH_CLIENT <bssid> 4e:42:dc:3b:d1:33 8` dropped the phone immediately, while
  `PINEAPPLE_DEAUTH_CLIENT_ALL <bssid> ff:ff:ff:ff:ff:ff 8` and
  `PINEAPPLE_DEAUTH_CLIENT_CSA <bssid> 8` were accepted (rc 0, empty stderr) and did nothing. The
  step that failed was reading that as *broadcast vs targeted*. It is **opcode vs opcode**:
  `PINEAPPLE_DEAUTH_CLIENT <bssid> ff:ff:ff:ff:ff:ff 8` — broadcast, same BSSID, same channel —
  **drops the client on demand**, so broadcast deauth works here and the `_ALL`/`_CSA` failures are
  a firmware defect in those two commands, not a property of the receiving station. The one thing
  the 2026-11-05 pair does still establish is narrower and was never stated: a recorded randomised
  MAC goes stale. `4e:42:dc:3b:d1:33` no longer drops the phone, because the phone rotated it.
- ~~**The CSA question is NOT answered by that.**~~ **ANSWERED 2026-11-09, and not by a radio
  result** — `_CSA` cannot construct a valid request at all. See "Third contact". The count-0 claim
  is untouched and still `[A]`; it has simply never been reachable through this command.
- **6 GHz is genuinely in the hop set** after the GUI toggle: 22 distinct 6 GHz centres in a
  40-sample window (6015 … 7115 MHz), plus seven 5 GHz DFS channels. **But nothing was heard there**
  — every frequency in `inventory.tsv` is ≤ 5805. Receive is permitted on both (NO-IR and RADAR are
  transmit restrictions), so this corroborates the two-gate model rather than challenging it.
- **The OUI table is why the scan hung.** `/lib/hak5/oui.txt` is 1,258,802 B / 38,959 lines and ONE
  failed `grep -i -m1` over it costs **5.05 s wall, 2.08 s CPU** on the device. At 960 devices in
  recon that is 33–81 minutes for a single cycle, and `events.log` showed `run start` with no
  `emit_cycle` line after ten minutes. Fixed; see the scan-path commit.
- **Scaling factors, because the wrong one was used twice.** Device ÷ same-algorithm BusyBox in the
  container is **~44× wall** (5050 ms ÷ 113 ms) and **~15–18× CPU** (2.08 s ÷ 0.136 s); the gap is
  cold I/O. The ~800× figure is device-BusyBox ÷ container-GNU-grep and is an *implementation*
  comparison — never use it to scale a BusyBox measurement to the device.
- **`WAIT_FOR_BUTTON_PRESS` works and prints the button name**, returning 0 on a press and 124 on a
  timeout — but **0 on its error paths too** (`ERROR: unknown button`, and the usage dump). So
  `rc == 0` alone cannot distinguish a press from a bad argument; check the printed name.
  PLAN_v2 item 16 G's "scan-view button map" is answered. A scan whose cycle overruns `CYCLE_SECS`
  never reaches the wait, so the firmware keeps the button and B appears dead — that was the hang,
  not a button bug.

### Third contact — the deauth commands are not three attacks, they are one with a broken argument, 2026-11-09

Live bench session plus a disassembly of `pineapd`'s single deauth handler. This section **supersedes
the two struck bullets above**. The identity pin was re-verified by sha256 before any address below
was trusted: `pineapd` `adc9d36d065b084856534dee…` / 1320040 B, `pineapple/pineapple`
`4493c6c6c8339e1993b5f764…` / 17685976 B. For both binaries virtual address = file offset + 0x400000.

- **⭐ All three `PINEAPPLE_DEAUTH_CLIENT*` commands reach ONE pineapd function, which dispatches on
  a numeric opcode, not on the payload.** `interface_tracker::command_send_deauth(conn, unsigned,
  string_view)` @ `0x4733d8`. The request is MessagePack with exactly three keys, read by
  `mpack_node_map_cstr_optional` from pointers at `0x4739b0`/`b4`/`b8` → `bssid`, `sta`, `channel`;
  `bssid` and `sta` are 6-byte bin fields (`cmpi v0,6`), `channel` is a string. The dispatch:
  ```
  473528:  lw v0,576(sp); addiu v0,-400; sltiu v0,2; btnez 0x473645   # id in {400,401} -> deauth
  473534:  lw v0,576(sp); addiu v0,-401; sltiu v0,2; btnez 0x473631   # id in {401,402} -> CSA
  ```
  The deauth block ends `b 0x473535`, branching **back into** the CSA test; the CSA block ends
  `b 0x473541`, skipping the deauth test. So **400 = deauth only, 401 = deauth + CSA, 402 = CSA
  only.** Reproduce with the MIPS16e recipe at `--start-address=0x4733d8 --stop-address=0x473b44`.
  **[A] on the name→opcode pairing only:** `register_socket_functions()` registers numeric ids
  (`0x46b73a`/`0x46b762`/`0x46b78a`); the name map lives in the Go daemon and hak5cmd, not here.
- **`sta` is MANDATORY, and pineapd's missing-`sta` throw carries the WRONG MESSAGE — but no
  shipped command reaches it.** `[V]` The `mpack_node_is_missing` test for `sta` is at `0x47347a`;
  `0x473480 bnez v0,0x473825` branches to a throw at `0x473824` (`__cxa_allocate_exception(8)`)
  which is **ahead of the dispatch at `0x473528`**, so a request without `sta` transmits nothing.
  **There is no "missing sta" string because that throw reuses the missing-BSSID message at
  `0x4739dc`** — a genuine copy-paste bug, so the string's absence is not evidence of a missing
  check. The zero-init at `0x473412`-`0x473416` is defensive, not a fall-through.
  **⚠ Read the next bullet before using any of this to explain a failure.** For several hours this
  session the throw WAS the explanation offered for `_ALL` and `_CSA` doing nothing, and it is
  wrong: all three commands supply a `sta`, so the throw is latent, not reached. Recorded because
  it is real and because the wrong message will mislead the next person who does hit it.
- **⭐ The Go layer supplies `sta` for all three, so the throw is unreachable — and `_ALL` has no
  deauth call at all to be identical to.** `[V]`, re-derived from the Go binary. *Heading corrected
  2026-11-10: it previously read "`_ALL`'s deauth call is BYTE-IDENTICAL to the one that works",
  which the table four lines below contradicts — `_ALL` sends opcode 402 and never reaches
  `0x47364e`. That phrasing was a leftover from the withdrawn missing-`sta` explanation, where the
  call was reached and the arguments were the difference. The `[V]` readings in this bullet are
  unaffected; only the conclusion drawn in the heading was stale.*
  `pineap.(*PineAp).StartDeauthAll` @ `0x0086c53c` writes **six `0xff` bytes by immediate** —
  `li v1,-1` at `0x0086c5d8` then `sb v1,46(sp)`…`sb v1,51(sp)` — i.e. `sta = ff:ff:ff:ff:ff:ff`.
  `StartDeauthCsa` @ `0x0086c390` contains **no** `0xff` immediate, and neither does `StartDeauth`
  @ `0x0086c1bc`; all three share one `models.PineapDeauthRequest` whose `Sta [6]byte` always
  encodes, so `_CSA` sends `00:00:00:00:00:00` and `DEAUTH` sends the parsed target.
  | command | opcode | `sta` on the wire | pineapd runs |
  |---|---|---|---|
  | `DEAUTH` | 400 | the parsed target | `inject_deauth(bssid, sta, ch)` |
  | `_ALL` | **402** | `ff:ff:ff:ff:ff:ff` (immediate, and **dead data** — the 402 path never reads `sta`) | `inject_csa(bssid, ch, 14)` **only — no deauth** |
  | `_CSA` | 402 | `00:00:00:00:00:00` (zero value, also unread) | `inject_csa(bssid, ch, 14)` only |
  **⭐ `_ALL` SENDS THE SAME OPCODE AS `_CSA`, so "both" is CSA-only and pineapd's opcode 401 is
  DEAD CODE that has never run.** `[V]`, and it is the whole answer to "why does BOTH do nothing
  when deauth/disassoc works":
  ```
  StartDeauth     0x0086c2b8:  li a0,400     -> deauth only
  StartDeauthCsa  0x0086c464:  li a0,402     -> CSA only
  StartDeauthAll  0x0086c62c:  li a0,402     -> CSA only          <-- not 401
  ```
  `li a0,401` and `ori a0,401` occur **zero** times anywhere in `pineapple/pineapple`; the three
  `StartDeauth*` tails are instruction-for-instruction identical bar that one immediate, and
  `exchangeCommand` passes arg1 through untouched (`0x86e6f4 lw at,64(sp)` / `0x86e6f8 sw at,8(sp)`).
  So `_ALL` and `_CSA` are **the same command on the wire** apart from the unread `sta` bytes, and
  `BOTH` is inert because it puts **no deauth frame on the air at all** — not because the request is
  refused, and not because of anything the receiving station does. 402 fails dispatch test 1
  (402-400 = 2, and `sltiu v0,2` is false for 2) and passes test 2, so it reaches `0x473630` and
  **never `0x47364e`**. *Falsified by:* a 401 immediate anywhere on a deauth path, or `_ALL`
  disconnecting a client.
- ~~**So what is left is the `inject_csa` call that follows.**~~ **WITHDRAWN the same day.** The
  hypothesis was that `inject_csa`'s `set_and_freeze_primary_channel_hop_s` retuned the radio
  between `inject_deauth`'s enqueue and the injection handler's transmit. Its channel half was
  refuted on the bench — firing `_ALL` with the radio already parked on the target channel still did
  nothing — and the opcode finding above makes the whole thing moot: **there was never a deauth to
  lose.** Recorded because the reasoning was published here for a few hours and because the shape of
  the error is worth keeping: a mechanism was invented to explain a difference between two code
  paths that turned out not to be two code paths.
- **⚠ Two methodological traps, both of which cost real time today.** (1) **Go interns field-name
  and tag blobs**, so counting occurrences of a `json:"…"` or `msgpack:"…"` string says how many
  distinct tag *descriptors* exist, NOT which structs use them — proved by three different
  `json:"bssid"` blobs sharing a prefix (`json:"bssid"`, `json:"bssid" uci:"bssid"`,
  `json:"bssid" uci:"macaddr"`). The `json:"target"` count in the section below is therefore weaker
  evidence than it reads; its conclusion survives only because `StartDeauthAll` was measured
  directly. (2) **A `.gopclntab` function table reconstructed by hand can be off by a constant**, and
  this session's was: the three `li a0,40x` sites above were FOUND by a byte scan, then resolved
  against the bad table to `loadProfile`/`playRingtone`/`playVibrate` and **discarded as HTTP status
  codes**. The decisive evidence was in hand and thrown away because a tool known to be suspect was
  trusted to rule it out. Spot-check a reconstructed table against a function whose first
  instruction you can predict before using it to dismiss anything.
- **⭐ The controlled A/B, one address, one channel, one BSSID, two opcodes, minutes apart.** On
  `FC:58:5A:08:42:15` ch 8: `PINEAPPLE_DEAUTH_CLIENT <bssid> ff:ff:ff:ff:ff:ff 8` **dropped the
  client**; `PINEAPPLE_DEAUTH_CLIENT_ALL <bssid> ff:ff:ff:ff:ff:ff 8` did nothing. This is the
  falsifier `attack_scope`'s own comment names, and it is now **spent in the affirmative**:
  broadcast deauth works on this station. It also means the GUI's AP-row deauth button — which the
  operator confirmed is fired with **only the AP row selected** — sends opcode 400 with
  `sta = ff:ff:ff:ff:ff:ff`, i.e. exactly the frame CamHound builds on an AP row.
- **⭐ pineapd TRANSMITS under a held EXAMINE lock.** `PINEAPPLE_EXAMINE_BSSID <bssid> 20;
  PINEAPPLE_EXAMINE_CHANNEL 8 20; PINEAPPLE_DEAUTH_CLIENT <bssid> ff:ff:ff:ff:ff:ff 8` dropped the
  client. This is the transmit-direction counterpart of Phase 0 13a (which answered *receive*), it
  was a live hypothesis for why CamHound's locked fire failed, and it is now closed. The lock is
  innocent. *Falsified by:* the same pair where the unlocked arm works and the locked arm does not.
- **⭐ CamHound refused to transmit, seven times, and the logs name the gate.** Every bebird attempt
  on build `40a0b3a` logged `resp members fc:58:5a:08:42:15 n=1 why=ok itmax=56 recs=286..468
  short=0 trunc=0 runt=0` — the capture *heard* the station cleanly — then `re-armed … lock=ok`,
  then `refused … NO_MATCH members=1`, with `pk_before` and `pk_after` both `-` in every
  `responses.tsv` row. `resp_fire` returned at the subject guard, **before** any command ran. Cause:
  `subjects` was both the transmit set and the measurement set, and `resp_snapshot`'s bss arm drops
  every randomised MAC (`is_rand`, which keys on the second character) and every MAC with no Recon
  row — so the gate that exists to keep the *oracle* honest was suppressing the *frame*. On an AP
  row the "picked target is always a subject" escape hatch cannot help, because `R_TARGET` is
  broadcast and no real MAC equals it. Fixed by admitting heard members as transmit targets with
  `p0 '-'`, which scores them INCONCLUSIVE rather than inventing a verdict.
- **CSA, for whenever a path to it exists, is beacon-triggered, and its total failure is SILENT.**
  `recon_engine::inject_csa(char const*, pineap_wifi_channel const&, unsigned char)` @ `0x4a125c`
  only queues a record; the frame is built when a beacon from that BSSID is indexed, which is why
  the CSA element is constructed at `index_beacon_ns+0xc0a` — a detail this file already recorded
  without drawing the inference. String xrefs place `Queuing CSA for {}` in `inject_csa`'s own pool
  (word @`0x4a14e0`) and `Caught beacon for CSA on {}` / `Queued packets for CSA on {}` /
  `Request to inject CSA expired for {}: {}ms` in `index_beacon_ns`'s (@`0x4bf1f0`/`0x4bf200`/
  `0x4bf1fc`). **`expired` only logs when a beacon DOES arrive, late** — it sits on the age-check
  fail branch at `0x4bef14`, downstream of the map hit. If no beacon ever arrives the record is
  pruned without comment by the loop at `0x4a129c` on the next call, so the common total failure
  leaves **only `Queuing CSA for`** in the log. pineapd does try to win the race:
  `set_and_freeze_primary_channel_hop_s(chan, 5)` sets the channel and freezes the hop for 5 s
  (~50 chances at a 102.4 ms interval), so the on-channel case normally succeeds — but **the freeze
  is 5 s while the record TTL is 10 s**, so 5–10 s is pure luck, and if
  `primary_interface_available()` is false (`0x46e73a`) both the set and the freeze are skipped
  silently with the record still queued. **Keep this distinct from the count-0 claim**: separate
  failure modes, separate falsifiers.
- **⭐ `inject_csa`'s third `unsigned char` is the NEW CHANNEL NUMBER, hardcoded to 14 — a second
  independent reason CSA cannot work, and it does NOT contradict the count-0 fact.** *Resolved
  2026-11-09; this was listed as an open reading for part of the same day.* The sole call site is
  `li a3,14` at `0x473634` (`jal 0x4a125d` at `0x47363a`, the only one in the binary by byte-pattern
  search). The byte lands at record+36 and `index_beacon_ns` writes it into **element 37 byte 3**,
  the New Channel Number; the Count byte is separately `0` from `li s1,0` at `0x4bee6c`. Both are
  true at once, so pineapd's CSA says **"switch to channel 14, immediately"**. Channel 14 is
  2484 MHz — Japan-only, 11b-only, and not in the US table at all — so a client that *did* honour
  the element would be told to move somewhere it may not go. Neither the channel nor the count is
  reachable by any setting or argument: both are literals with one call site.
- ~~**"Both" runs the IDENTICAL `inject_deauth` call as "deauth/disassoc"**~~ **WITHDRAWN
  2026-11-10 — it is the opposite, and the bullet also endorsed the explanation this section
  withdraws.** `inject_deauth` is called from exactly one instruction, `0x47364e`, with four
  arguments from fixed stack slots (`bssid` at `sp+216`, `sta` at `sp+222`, channel at `sp+228`) —
  that reading stands. What does not is "Both runs it": `0x47364e` sits in the block reached only by
  dispatch test 1, i.e. opcode 400 or 401, and `_ALL` sends **402**, which fails that test
  (402-400 = 2, `sltiu v0,2` false) and reaches `0x473630` instead. So BOTH never executes this
  call, and the difference the operator sees IS the code path — not the argument bytes, and not the
  missing-`sta` throw, which no shipped command reaches. Kept rather than deleted because the
  address and argument slots are still the right ones for the DEAUTH path, and because this bullet
  is where the wrong inference was recorded.
- **`inject_deauth` @ `0x472c14` is the gate-1 site, and the recorded addresses check out.** Its
  prologue is `lw v0,28(s0); cmpi v0,8; bteqz` at `0x472c66` (the blanket 6 GHz check) and
  `sltiu v0,145` at `0x472c76` (the DFS range-chain entry) — matching this file's 1.1.3 column
  exactly, which is an independent confirmation that the MIPS16e recipe and the pin are sound. It
  makes no `libwifi_create_deauth` call and has no loop: it queues, and
  `interface_tracker::injection_handler()` builds and sends.
- **A transient channel read-back failure cost a whole response.** `resp lock-failed
  50:92:6a:ae:a8:82 wlan1mon still hopping (/1/1)` — `cur_channel` returned empty, then `1`, then
  `1`, against a target channel of 1. The radio was parked where it was asked to be, but
  `lock_target` required all three samples equal and scored the empty one as a different channel,
  returning 2 and refusing the response with `LOCK_FAILED`. Fixed by comparing only the samples
  that were actually read — **but the first fix only covered ONE empty sample, which is the case
  that was measured.** It backfilled `c1` from `c2` before repairing `c2` from `c3`, so with `c1`
  and `c2` both unreadable `c1` stayed empty and the comparison scored the identical
  `still hopping (/1/1)` refusal. Found by the 2026-11-10 audit (three finder dimensions
  independently), reproduced, and fixed by backfilling from the last sample outward.
  **Then a second 2026-11-10 audit found three more defects in the same function, and the two-empty
  answer above was itself wrong.** It returned 0 and wrote `lock=ok` from a *single* readable
  sample — more confidence than the two-readable-samples case beside it, which returns 3 — because
  the backfill turns the comparison into `c3 = c3 = c3`, a tautology. All three are fixed: one
  readable sample is now `lock=unverified` (rc 3, which still **proceeds**, so the original fix is
  intact and only the label changed); the **fourth** `cur_channel` read, the one after
  `EXAMINE_CHANNEL`, had no empty-sample protection at all and still refused the whole response on
  a transient empty (rc 2 → rc 3); and the hopping log line printed the *backfilled* triple, so the
  `(/1/1)` signature that made this diagnosable in the first place had become unreachable by
  construction — it now prints the raw samples, e.g. `_/6/11`. Selftest coverage is one-empty,
  middle-empty, one-readable-sample, empty-fourth-read and genuinely-hopping, each confirmed by a
  mutation that fails only its own case. *An earlier version of this line also claimed an `st_lock`
  helper; no such function has ever existed, and the cases are inline.* *Falsified by:* a
  `lock_target` rc changing for any of those patterns without `cur_channel` changing.

### Fourth contact — the CSA count byte makes no difference to a real client, 2026-11-10

Live bench on the 1.1.3 unit, `pagerinj` driven by `dev/injector/run_17a.sh`. Target the bebird
camera AP `FC:58:5A:08:42:15` on ch 8, announcing ch 1. **Day-one step 17a has now run.**

- **⭐ Both arms transmitted, and the count byte changed nothing observable.** Transmit is `[V]`;
  the cause of the disruption is `[A]`.
  - count 0: `cloned 108-byte beacon; CSA {37,3,mode=1,ch=1,count=0}; 121 bytes`, `sent=92 failed=0`, rc 0.
  - count 3: `CSA {37,3,mode=1,ch=1,count=3}`, `sent=97 failed=0`, rc 0.
  - Operator observation, **identical for both**: the camera's video feed froze completely for the
    duration of the run and re-associated by itself once the script finished.
- ~~**So the operational prediction fails in both halves.**~~ **WITHDRAWN 2026-11-10, same day —
  both halves conflated two different kernel functions. See "Fifth contact" below, which supersedes
  this bullet.** The short version: the *switch* path honours count 0, so count 0 disrupting was
  never evidence against anything; and "count 3 did not deny reconnection" is not what was observed
  — the client recovered *after* injection stopped, which is precisely what the refusal mechanism
  predicts. The readings were right and the inference was wrong, for the fifth time in three days.
- **Four reasons this does not refute the kernel reading itself.** The reading and the prediction
  are different claims and this project has conflated them before.
  1. `ieee80211_mgd_csa_present()` is **Linux mac80211**. The client here is a consumer handset
     whose chipset most likely handles CSA in WLAN firmware, so the function may not govern it.
  2. **No receiver-side proof.** All three captures recorded **zero packets** — see below — so
     "a frame reached the air" rests on `sendto` success, which this file already says proves nothing.
  3. ~~`pagerinj` sent a **constant** count where a conformant AP decrements.~~ **Instrumented and
     RUN 2026-11-10 (`--count-dec`): no observable difference, but see "Fifth contact" — the
     observable itself cannot see the difference, so this caveat is neither confirmed nor spent.**
     The cadence turned out close to faithful (~109 ms per step against a 102.4 ms TBTT); what is
     still unfaithful is that the countdown wraps to 3 instead of switching and going quiet.
  4. ~~The run also holds an EXAMINE lock for 30 s and brings interfaces up.~~ **Eliminated by an
     accidental negative control in the same session.** The first count-0 attempt issued the
     EXAMINE lock, brought `wlan1mon` and `wlan0mon` up, started the capture, and then transmitted
     **nothing** (`pagerinj rc=1`, `no beacon captured`) — and the feed did **not** freeze. The two
     runs that transmitted froze it. So the freeze tracks the transmitted frames, not the script's
     preamble. What remains confounded is narrower: whether it is the **CSA element** or merely a
     flood of cloned beacons carrying the AP's own BSSID. ~~`pagerinj` has no clone-and-flood mode
     without the element.~~ **BUILT AND RUN 2026-11-10 (`--clone`, twice, no effect) — but the
     adversarial pass then showed that arm is a near-tautological control on a mac80211 client, so
     only the AIRTIME half of this confound is eliminated. See "Fifth contact".**
- **⭐ What is new and positive: a CSA-bearing cloned beacon from `pagerinj` disrupts a live
  client.** "Whether CSA moves a real client at all" was listed as open and unanswerable through
  the firmware commands. Something in that frame reaches this client — ~~most plausibly the CSA,
  since the feed recovered the moment injection stopped, which is what honouring a switch to an
  empty channel then falling back looks like.~~ **REFUTED 2026-11-10 by the captures: this arm and
  every other mode-1 arm contains ZERO auth and assoc frames, so the client never switched and
  never fell back — it was quiesced in place by Channel Switch Mode 1. See "Seventh contact".** ~~*Falsified by:* the same freeze from `pagerinj`
  injecting the cloned beacon with the CSA element omitted.~~ **That falsifier was spent on
  2026-11-10 — two `--clone` runs did nothing to the feed — but it turned out to be a WEAK
  falsifier: a verbatim clone hashes to the same `beacon_crc` as the AP's own beacons and mac80211
  drops it at `mlme.c:6929` before the switch handler, so its null result is close to a tautology.
  What the pair establishes is that the FIVE APPENDED BYTES do the work, not that the channel-switch
  semantics do. The arm that would separate those is `--elem=32:00`, built and unrun.** Also: "most
  plausibly the CSA" is now the weaker reading — Channel Switch Mode 1 blocks the client's TX queues
  count-independently (`mlme.c:2610`), which fits the observable without any switch occurring. See
  "Fifth contact".
- **⚠ The watch interface is blind, and it is pineapd's doing.** Zero packets in all three runs,
  including zero of the AP's own ~10/s beacons, which the `wlan addr2 <bssid>` filter would have
  caught — so the filter is innocent. pineapd's cmdline carries
  `--interface wlan0mon --band wlan0mon:2`, so it **hops** `wlan0mon` and the script's
  `iw dev wlan0mon set freq` is overridden within a hop interval. EXAMINE parks only the
  **primary** (`wlan1mon`). On-device frame-level proof therefore needs the primary — which is also
  the transmitter — or an external receiver. *Falsified by:* a non-empty `wlan0mon` capture on a
  fixed channel while pineapd runs.
- **`wlan1mon` can be administratively DOWN while pineapd is running.** `flags 0x1102`
  (`IFF_BROADCAST|IFF_PROMISC|IFF_MULTICAST`, **no `IFF_UP`**) with `operstate down` and
  `pidof pineapd` = 11482; one run later, `0x1103` / `unknown`, with no intervention but the
  script's own `ip link set up`. So "pineapd is up" does **not** imply "its interfaces are up".
  A run must check, and must try to bring it up rather than refuse.
- **And when `IFF_UP` IS set, this device reports `operstate` `unknown`, never `up`.** Worth
  recording because a fix was built this morning on the assumption that a monitor vif reports
  `down` while up; it does not, and `dev/CamHound/AUDIT-2026-11-10.md`'s last section is the
  retraction.

### Fifth contact — the control arm ran, and an adversarial pass then dismantled what I concluded from it, 2026-11-10

**Read both halves. The second supersedes the first.** Part one is bench data and stands. Part two
is a four-dimension, three-lens adversarial pass — **12 refuted, 11 survived, 0 unverified, every
verifier completed** — which found that the experiment was measuring something other than what it
claimed. Every `[V]` below is `net/mac80211/mlme.c` at v6.12.61, the backports base this firmware
carries, read rather than recalled.

| arm | frame | result | feed |
|---|---|---|---|
| `--clone` control, run 1 | 116 B, verbatim, **no element** | `sent=93 failed=0` | **nothing** |
| `--clone` control, run 2 | 116 B | `sent=90 failed=7` | **nothing** |
| `--csa --count 3 --count-dec` | 121 B, `{37,3,mode=1,ch=1,count=3}` | `sent=92 failed=0` | **froze for the run, recovered unaided** |

Every run printed `park confirmed: wlan1mon reads ch 8 twice`, so the park is not an assumption.

**WHAT SURVIVES.** The **five appended bytes** are what disrupt this client: 3 for 3 with them,
0 for 3 without, plus the accidental null arm. The confound that is eliminated is **airtime and
duplicate-BSSID presence** — not "beacon flood" in general.

**WHAT DOES NOT SURVIVE, and the mechanisms the three-way list missed.**

1. **`--clone` was a near-guaranteed null on a mac80211 client, so it cannot carry "the CSA element
   is what reaches the client".** `[V]` `ncrc = crc32_be(0, &mgmt->u.beacon.beacon_int, 4)`
   (`:6837`), `parse_params.filter = care_about_ies` (`:6839`), `ncrc = elems->crc` (`:6853`), and
   the gate `if ((ncrc == link->u.mgd.beacon_crc && link->u.mgd.beacon_crc_valid) || …) goto free;`
   (`:6929`) sits **ahead of** `ieee80211_rx_bss_info()` (`:6934`) and
   `ieee80211_sta_process_chanswitch()` (`:6936`). `care_about_ies` (`:6050-6057`) is COUNTRY(7),
   ERP_INFO(42), CHANNEL_SWITCH(37), PWR_CONSTRAINT(32), HT_CAPABILITY(45), HT_OPERATION(61),
   EXT_CHANSWITCH_ANN(60). A verbatim clone matches all of it, so after the first one every clone
   hits `goto free` and reaches neither handler. **Element 37 being inside that filter is exactly
   why the CSA arm got through.** So the control separates "extra beacon frames" from "a
   CRC-relevant change", and not "the CSA element" from "any CRC-relevant change to a spoofed
   beacon". The control that does separate them is `--elem=32:00` — **built 2026-11-10, unrun.**
   *A vendor-specific element (221) would be another null: the filter additionally tracks only the
   Microsoft (00:50:F2) and Cisco DTPC OUIs (`:6035-6040`), so an arbitrary OUI changes no CRC. The
   adversarial pass proposed the vendor element and was wrong about it for this reason; pagerinj now
   warns when `--elem` names an id outside the filter.*
2. **Channel Switch Mode = 1 freezes the client count-INDEPENDENTLY, and this repo already said so.**
   `pagerinj` defaults `mode = 1` and every bench line reads `mode=1`. `[V]`
   `ch_switch.block_tx = csa_ie.mode` (`:2412`), `link->u.mgd.csa.blocked_tx = csa_ie.mode`
   (`:2608`), `if (csa_ie.mode) ieee80211_vif_block_queues_csa(sdata)` (`:2610`). And
   **`dev/pager-csa-primitives.md:408` already carried it**: "mode = 1 sets `blocked_tx`, so an
   accepting client also stops transmitting." A stalled uplink alone freezes a video stream — no
   ACKs, no keepalives. **One count-independent mechanism predicts the identical observable for all
   three arms**, which is what was measured. Null if the client's driver advertises
   `IEEE80211_HW_HANDLES_QUIET_CSA`.
3. **The genuine AP's CSA-free beacons ABORT the pending switch, ~10/s.** `[V]`
   `case IEEE80211_CSA_SOURCE_BEACON: … else if (res) { ieee80211_sta_abort_chanswitch(link); return; }`
   (`:2452`). So an accepted CSA is contradicted within about one beacon interval: count 0 switches
   with zero delay and wins that race, count 3's ~205 ms loses it. **17a as built cannot produce a
   completed count ≥ 1 switch against an AP that is still on the air.** And
   `ieee80211_sta_abort_chanswitch()` returns early at `:2244` when the driver exposes no
   `abort_channel_switch` op — the abort becomes a no-op and the quiesce persists instead. Two
   opposite behaviours from the same frames, selected by a driver flag.
4. **The `--count-dec` arm transmitted count 0 on 23 of its 92 frames, and the LAST frame on the air
   carried 0.** `count_dec_step` wrapped through 0, and 92 = 4 × 23 exactly. That arm strictly
   *contained* the separate count-0 condition, so it can support no claim of the form "count N
   behaves like count 0". **Fixed: it floors at 1 (a real AP beacons 3,2,1 and then switches; it
   never announces 0 on the channel it is leaving) and the log now reports frames by count.**
   Separately, by this repo's own `[V]` reading (`dev/pager-csa-primitives.md:413`) **any** count
   1-255 survives `csa_present()`, so a constant count 3 was already a maximally eligible denial
   stimulus — decrementing belongs to the move/tracking path, not the refusal path, and was never
   the right instrument for the denial question.
5. **The auth/assoc refusal cannot freeze an ASSOCIATED client.** `csa_in_process` is reached only
   from `ieee80211_mgd_auth()` (`:8478`) and `ieee80211_mgd_assoc()` (`:8827`) — the paths a station
   takes when it is *not* associated and is trying to join. So it is downstream of whatever
   disconnected the client, not a sibling explanation, and the cached beacon IEs alternate
   CSA-bearing / CSA-free at ~10 Hz, giving a refusal window of ~100 ms at roughly 50% duty.
6. **No capture ran in any of the three arms, and the filter could not have seen the client anyway.**
   No `<watch-if>` was passed, so the `-- capturing on` line appears in none of the logs — the
   zero-packet captures belong to the Fourth-contact runs, and this file briefly said otherwise.
   Worse, the filter was `wlan addr2 <bssid>`: addr2 is the TRANSMITTER, so it could only ever show
   the AP and our clones, never the station that is the whole subject of 17a. **Fixed to
   `wlan addr1 <bssid> or wlan addr2 <bssid>`**, which adds the client's ToDS data and its
   auth/assoc requests, and the script now says plainly when no capture will run.

**So the honest state of 17a: the count byte's effect is UN-MEASURED, not measured-as-null, and the
oracle in use cannot see it.** "Is the feed frozen?" is satisfied by the mode-1 quiesce, by a
completed switch, by an aborted switch thrashing block/unblock at 10 Hz, by a post-disconnect
auth/assoc refusal, and by plain beacon loss. Four sessions went into the transmitter and none into
the measurement.

**⭐ NEXT, in this order, and the first two need no new code.**
1. `--elem=32:00` — a CRC-relevant element that announces nothing. A freeze here means the reaction
   is to the beacon changing at all, and every count result so far is about beacon churn.
2. `--mode=1` with announce-chan **equal** to target-chan (quiet, nothing to move to) against
   `--mode=0` with them different (move announced, no transmit restriction). If the quiet arm
   freezes and the move arm does not, the count byte was never in the causal path.
3. Pass **the inject interface** as `<watch-if>` for both — it is the one EXAMINE parks, and
   "Second contact" measured that client ToDS frames appear on it. Then look for whether the feed's
   return is preceded by an auth/assoc exchange: if it is, the client was disconnected; if not, it
   was quiesced and never left. *This supersedes the earlier "a Linux client and `dmesg -w`"
   recommendation as the FIRST step — that is still the cleanest read of the refusal path, but it is
   no longer needed to separate the two leading mechanisms.*

### Sixth contact — the content control settles C1: the channel-switch element specifically, 2026-11-10

Same session, same target, and **the first 17a arms with a real capture on the parked primary.**
Every arm printed `park confirmed: wlan1mon reads ch 8 twice`.

| arm | frame | frames | feed |
|---|---|---|---|
| `--elem=32:00` — CRC-relevant, **no switch** | 119 B, `+{32,1}` | `sent=93 failed=5` | **nothing** |
| `--mode=1`, announce ch **8** = target (quiet, no move) | 121 B, `{37,3,mode=1,ch=8,count=3}` | `sent=84 failed=7` | **intermittent** — seconds frozen, brief recovery, repeating |
| `--mode=0`, announce ch 1 ≠ target (move, no quiet) | 121 B, `{37,3,mode=0,ch=1,count=3}` | `sent=92 failed=0` | **intermittent**, same pattern |

Compare Fourth contact's `mode=1` + announce ch 1 arm, `sent=97 failed=0`: a **constant** freeze.

- **⭐ C1 NOW HOLDS IN THE STRONG FORM — it is the channel-switch element, not beacon churn.**
  `--elem 32:00` appends PWR_CONSTRAINT, which **is** in `care_about_ies` (`mlme.c:6052`), so the
  frame changes `elems->crc`, clears the gate at `:6929`, and reaches both
  `ieee80211_rx_bss_info()` (`:6934`) and `ieee80211_sta_process_chanswitch()` (`:6936`) — where,
  carrying no CSA, the parse sets `res = 1` and it takes the abort branch. So the frame was
  **parsed, handled, and did nothing visible.** That is the control `--clone` could not be: a
  CRC-relevant, parsed, non-switch change to the AP's own beacon has no effect, while the same
  beacon plus five channel-switch bytes does. The IE-churn confound the adversarial pass raised is
  **spent**. *Falsified by:* any `--elem` arm from `care_about_ies` that freezes the feed.
- **⭐ Both halves of a CSA contribute, and the constant freeze needs BOTH.** Two single-variable
  comparisons against the constant-freeze arm:
  - **drop the quiet** (`--mode=0`, same announce channel): constant → intermittent, at
    `sent=92 failed=0` against `97 failed=0`. This is the clean comparison.
  - **drop the move** (announce the current channel, keep mode 1): constant → intermittent, but at
    `sent=84 failed=7` — 13% fewer frames on the air, so this arm is confounded by its own
    degradation and is the weaker of the two.
  So the mode-1 quiesce is **not** the whole story, which is what the adversarial pass's strongest
  finding proposed, and neither is the move. A both-matter answer, not either/or.
- **The intermittency is new, and it matches the abort race.** Earlier arms were a constant freeze;
  these cycle seconds-frozen / briefly-recovered. The genuine AP's CSA-free beacons abort the
  pending switch at ~10/s (`mlme.c:2452`), so whatever state the client enters is torn down and
  re-established repeatedly. A ~10 Hz trigger against seconds-long freezes says the client's
  recovery costs far more than the cycle — plausibly a stream re-establish per abort. **[A]**: the
  cycle rate was not measured, only described.
- **⭐ AND THERE ARE CAPTURES — 2617, 4224 and 3638 packets on the PARKED primary**, 1.9-4.5 MB,
  with the `addr1 or addr2` filter. The first on-device 17a captures that could see the client at
  all, and they contain the observation that separates "disconnected, then re-associated" from
  "quiesced and never left": whether the feed's return is preceded by an auth/assoc exchange.
  ~~Not yet read.~~ **READ 2026-11-10 — see "Seventh contact". Only the mode-0 arm contains auth/assoc;
  every mode-1 arm contains none, which separates quiesce-in-place from ~~a real switch~~ a
  re-association — that it was a *switch* is `[A]`, withdrawn as a reading 2026-11-10, see
  "Eighth contact" — and refutes Fourth contact's mechanism.**
- **`wlan1mon` flapped in two of the three arms** (`failed=5` of 98, `failed=7` of 91, `failed=0`
  in the third). Third and fourth instances in a day; `!! PARTIAL RUN` now names it, which is how
  the 2a confound above was visible at all.
- *Fixed the same day:* the `> 24`-byte capture branch printed "pineapd HOPS wlan1mon" over 2600
  packets captured on the interface EXAMINE had just parked. The caveat is now scoped to a watch
  interface that is **not** the parked one.

### Seventh contact — the captures separate the two mechanisms, and refute Fourth contact's, 2026-11-10

Not a new transmission: this is the **read** of Sixth contact's captures, which is where the answer
had been sitting. Eight pcaps, one filter:
`tcpdump -r $f -nn -e type mgt | grep -i -e assoc -e authentication -e deauth`.

| arm | mode | announced | auth/assoc in the capture |
|---|---|---|---|
| Fourth contact count 0 (no transmit) | 1 | ch 1 | **none** |
| Fourth contact count 0 | 1 | ch 1 | **none** |
| Fourth contact count 3 | 1 | ch 1 | **none** |
| Fourth contact count-3 `--count-dec` | 1 | ch 1 | **none** |
| two earlier count-3 runs | 1 | ch 1 | **none** |
| Sixth contact `--elem=32:00` | — | nothing | **none** |
| Sixth contact quiet-only | 1 | ch 8 = current | **none** |
| **Sixth contact move-only** | **0** | **ch 1** | **TWO complete cycles** |

The one arm that produced them, twice, ~3 s apart:

```
02:37:23  SA:3a:57:cb:46:8b:77 -> Authentication (Open System)-1: Successful
02:37:23  SA:fc:58:5a:08:42:15 -> Authentication (Open System)-2:
02:37:23  SA:3a:57:cb:46:8b:77 -> ReAssoc Request (bebird-R1-038686) AP : fc:58:5a:08:42:15
02:37:23  SA:fc:58:5a:08:42:15 -> ReAssoc Response AID(1) :: Successful
02:37:26  … the same four again, with a retried Authentication-1
```

- **⭐ THE TWO MECHANISMS ARE SEPARATED, and the oracle that could not see them was the whole
  problem.** `[V]` from the captures:
  - **Channel Switch Mode 1 quiesces the client IN PLACE.** Zero auth, zero assoc, zero deauth
    across *six* mode-1 arms. The client never left the BSS and never had to come back.
  - **Mode 0 produces auth and reassoc frames where mode 1 produces none.** `[V]`: a complete
    Authentication / ReAssoc Request / ReAssoc Response cycle, twice inside one 10-second run.
    ~~**Mode 0 produces a real switch and a real return.** The client went to ch 1, found nothing,
    came back~~ — **[A], and withdrawn as a reading 2026-11-10: no frame in the capture shows the
    station change channel or says where it went.** What it holds is the station ceasing to be
    heard on ch 8 three times (2.947 / 2.482 / 2.450 s) and returning each time, each return
    preceded by a directed Probe Response (155 ms and 144 ms before the two Authentications),
    with zero deauth and zero disassoc anywhere in it. The mode-0-vs-mode-1 DIFFERENCE stands;
    the destination does not. See "Eighth contact".
  Both present to an operator as a frozen video feed, which is exactly why three bench sessions
  could not tell them apart.
- **⭐ So Fourth contact's mechanism is REFUTED, not merely weakened.** It read the freeze as "what
  honouring a switch to an empty channel then falling back looks like". Its arms were all mode 1 and
  **none of them contains a single auth or assoc frame** — the client did not switch and did not
  fall back. It was quiesced. The adversarial pass proposed this and the captures confirm it.
- **⭐ The count ≥ 1 DENIAL prediction is finally tested, and it FAILED.** `ReAssoc Response AID(1)
  :: Successful`, twice, **while count-3 CSAs were still being injected**. `csa_present()` should
  have made `csa_in_process()` true and had `ieee80211_mgd_assoc()` (`mlme.c:8827`) return
  `-EINVAL`. It did not. The mechanism candidate is the one the adversarial pass named: the genuine
  AP's own CSA-free beacons refresh `bss->beacon_ies` between our injected ones, so the refusal
  window is ~100 ms at roughly 50% duty and the client simply lands in a gap. **If that is right,
  17a cannot test the denial path at all against an AP that is still on the air** — and this AP
  cannot be silenced. That is a structural limit on the experiment, not a missing arm. **[A]** on
  the mechanism; `[V]` that the re-association succeeded under injection. **The gaps are now
  measured, and they are small** (`[V]`, "Eighth contact"): our last CSA-bearing beacon preceded
  the two Authentications by **20.64 ms** and **70.66 ms**, and the AP's own last CSA-free beacon
  preceded the first by **51.00 ms** — so at the first re-association our CSAs and the AP's
  refreshing beacons were both on the air inside the 51 ms before the Authentication that should
  have been refused.
- **⚠ An open tension, left open rather than explained away. RESOLVED 2026-11-10 — and it
  DISSOLVED rather than being decided; see "Eighth contact".** The adversarial pass predicted
  (`mlme.c:2452`) that the genuine AP's beacons abort a pending switch ~10/s, so a count-3 switch
  would lose the race and never complete. ~~**It completed twice.**~~ **Nothing in the capture
  shows a completed switch — the premise was an inference, not a reading, so there is no
  composition left to repair.** Both readings are sound and the
  composition does not work, which is precisely the shape this file warns about — so no mechanism is
  invented here. *Resolved by:* a capture read for the ordering of our CSA beacons against the AP's
  own around 02:37:23, which the same pcap already contains. **SPENT 2026-11-10: that read is
  done. The AP's beacons were present and interleaved ~1:1 with ours throughout — 112 beacons,
  9.68/s, zero gaps over 250 ms — including immediately before both re-associations and before
  two of the three departures, so "there was nothing to abort the switch" is ruled out as the
  general explanation. One 204.5 ms unopposed CSA window exists, before the FIRST departure
  only.**
- **The quiet arm's uplink dipped but never stopped.** Client→AP frames per second across the
  mode-1 run: `6, 83, 93, 263, 224, 93, 12, 237, 162, 256, 132, 32`. One deep trough — 12 frames in
  a second against a 100-260 baseline — then full recovery. So mode 1 is a *partial, repeated*
  quiesce, matching the operator's "froze for seconds, briefly unfroze, repeating" and the
  block/unblock thrash the abort race implies, rather than a clean 10-second stop.
- **The client carries a RANDOMISED MAC** — `3a:57:cb:46:8b:77`, second character `a`. That is the
  case `is_rand` keys on, and the case that silenced CamHound's response rung for seven attempts
  (see "Third contact"). Worth knowing that the only station on this AP is one of those.

**What 17a has actually produced, in one line:** the channel-switch element reaches this client and
does two separable things — mode 1 quiesces it in place, ~~mode 0 moves it~~ **mode 0 makes it
re-associate** (`[V]`; that it *moves* is **[A]**, not in the capture — see "Eighth contact") — and
the count byte's denial half cannot be measured here because the target AP keeps beaconing.

### Eighth contact — the mode-0 capture read frame by frame dissolves Seventh contact's tension, 2026-11-10

Not a new transmission: the **record-level** read of the one Sixth-contact arm that produced
auth/assoc — the `--mode=0`, announce-ch-1, count-3 arm on the parked primary, **3638 records**,
filter `wlan addr1 fc:58:5a:08:42:15 or wlan addr2 fc:58:5a:08:42:15`, spanning 11.582 s, first
record at absolute `1793893037.781670`. `dev/injector/run_17a.sh:380` names such a capture
`/root/loot/csa_17a_c3_<epoch>.pcap`, so it is the `…_c3_1793893037.pcap` file provided the capture
was opened in the same second as its first record — **[A]**: the read identified the pcap by its
records alone, and `date +%s` runs before tcpdump's first write. Times below are relative to the
first record, and **every figure here is `[V]`, computed from those 3638 records, unless tagged
`[A]`.**

- **⭐ THE TENSION DISSOLVES, because its premise was never a reading.** The capture holds 204
  beacons, 5 Authentication, 2 Reassociation Request, 2 Reassociation Response, 3 Probe Response —
  and **0 Deauthentication, 0 Disassociation, and no frame showing the station change channel or
  saying where it went**. What it shows is the station ceasing to be heard on ch 8 three times and
  returning each time, so Seventh contact's "it completed twice" was an inference, not a reading.
  **[A]** Going to ch 1 fits it; so does an off-channel scan, a driver reset, a sleep or a range
  change, and nothing here separates them, no receiver being on ch 1. *Falsified by:* a channel-1
  capture holding this station's frames during one of the three absences below.
- **⭐ "There was nothing to abort the switch" is RULED OUT as the general explanation.** The AP
  beaconed continuously: **112 beacons, 9.68/s, zero gaps longer than 250 ms**, and by TBTT
  accounting (each beacon's own TSF divided by the 102400 µs TBTT) exactly **one** of 113 TBTTs
  carries no captured beacon — index 3686, at t ≈ 2.172993. Inside the injection window the two
  streams strictly alternate: of 88 runs of our beacons, **85 are a single beacon of ours between
  two of the AP's**, the longest unopposed run being **3**. *Falsified by:* an AP beacon gap over
  250 ms in this pcap.
- **⭐ The one unopposed window precedes the FIRST departure only.** `2.070865` → `2.275380` is a
  **204.5 ms** span with no AP beacon captured, holding our three beacons at `2.071488`,
  `2.171862`, `2.272598`, with the station's last frame at `2.261299` falling 190.4 ms into it — a
  real coincidence, not waved away. **[A]**, and two reasons it still does not establish that the
  AP was silent when it mattered: at a 102.4 ms TBTT a count of 3 schedules the switch about 307 ms
  after the announcing beacon (count semantics as this file records them, not re-read in that
  pass), so 204.5 ms is about two TBTTs and shorter than the announcement needs; and the capture
  cannot say the AP's beacon was absent from the *air*, only that this receiver recorded none
  there. *Falsified by:* a second unopposed CSA window anywhere in this pcap, or a captured AP
  beacon at TBTT index 3686.
- **⭐ Both returns were preceded by a directed Probe Response, under strict alternation.** One
  addressed to the station precedes each Authentication — `5.252967` (155 ms before), `8.333463`
  (144 ms before), a third at `11.400612` — and the beacon order over the 600 ms before each is
  `AOAOAOAOAOAO` and `OAOAOAOAOAOA` (A = the AP's, O = ours). **[A]** A directed Probe Response
  means the AP received a Probe Request, i.e. each return was an active scan; the station's own
  Probe Requests are outside this filter, carrying the BSSID in neither address. *Falsified by:* a
  station Authentication in this pcap with no directed Probe Response ahead of it.

The three departures, which is where a switch would have begun — 3.531 s and 3.107 s apart, with
presence windows of 2.26, 0.58 and 0.63 s, which **[A]** reads as a station-side scan or roam timer
rather than a reaction clocked by our 9.94/s beacons:

| # | last station frame | next station frame | absent | last AP beacon before it | CSA-only run before it |
|---|---|---|---|---|---|
| 1 | `2.261299` | `5.208104` | 2.947 s | `2.070865`, **190.43 ms** | **n = 2**, span 100.4 ms |
| 2 | `5.791976` | `8.273588` | 2.482 s | `5.756885`, 35.09 ms | n = 1, span 0.0 ms |
| 3 | `8.898842` | `11.348584` | 2.450 s | `8.834094`, 64.75 ms | **n = 0** (the AP's was last) |

- **⚠ Our stimulus is less AP-like than `sent=92` suggests — three instrument facts the next bench
  session should have.** Across all 92 clones: the **sequence number never advanced** (138 on every
  frame), the **beacon TSF field never advanced** (`377241614`, the clone source's value — the AP
  beacon at `t=1.968337`), and the **TIM was frozen** at `01020006` while the genuine AP's
  alternated `00020006`/`01020006` every beacon. Element 37 is `000103` — mode 0, channel 1,
  count 3 — on all 92, while the DS Parameter Set still says channel 8. The clones carry an
  **8-byte radiotap header and no signal field** against the AP's 56 B; **[A]** that this makes
  them locally looped-back transmit records, proving a transmit *attempt* and not reception.
  *Falsified by:* a clone here with a 56-byte radiotap header or a signal field.
- **What this capture cannot decide**, stated plainly because several are load-bearing:
  - whether the station **received** any particular beacon — the ordering measured is this
    receiver's, not the station's;
  - **where** the station went during each ~2.5 s absence, and so whether any switch occurred;
  - **why** it left — no deauth, no disassoc, no AP-originated CSA, no frame stating a reason;
  - whether the kernel **abort path** (`mlme.c:2452`, read in "Fifth contact") governs this
    station's stack — the capture carries no driver or OS identity, and the MAC is randomised
    (`3a:57:cb:46:8b:77`);
  - whether the **count byte** did anything — all 92 clones carried count 3 and mode 0;
  - whether the AP transmitted at TBTT 3686. **Five of the six clones that landed within 3 ms
    before an AP TBTT still produced a captured beacon**, so **[A]** monitor deafening fails as a
    *general* mechanism and that one absent beacon is left unexplained rather than attributed.

**What this read produces, in one line:** the mode-0-vs-mode-1 difference measured in Seventh
contact stands, "there was nothing to abort the switch" is ruled out everywhere but the first
departure, and "the client went to ch 1" is withdrawn as a reading — what this capture shows is a
station leaving and rejoining channel 8, not a channel switch.

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

**⚠ `BOTH` is INERT, not merely untargeted, and it is no longer the preselected default.**
*Heading corrected 2026-11-09.* The analysis below is sound and its conclusion — that `_All`'s
struct carries no caller-supplied target — is now **measured**, not inferred: `StartDeauthAll`
writes `sta = ff:ff:ff:ff:ff:ff` by immediate. What the section under-stated is the consequence:
`_All` puts nothing on the air at all, measured against a client the opcode-400 broadcast drops on
demand. **The mechanism IS settled** — `_All` sends opcode 402, so it queues a CSA and builds no
deauth frame; see "Third contact", which supersedes the "missing `sta`" explanation this file
briefly carried. *Corrected 2026-11-10: this line read "The mechanism for that is not settled"
while pointing at the section that settles it, and described `posture_expect` as labelling
`BOTH`/`CSA` `fw-broken`, which it no longer does.* `posture_opts` now leads with `DEAUTH` on every
badge; `BOTH` is wired to the opcode-400 deauth rather than `_ALL`, and `posture_expect`'s labels
follow the SENDER — `fw-broken` for a firmware CSA, `injector`/`deauth+csa` when `CSA_INJECTOR` is
configured — so the default Disrupt is no longer a guaranteed no-op. Four readings of
the Go daemon,
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

- ~~**The three `PINEAPPLE_DEAUTH_CLIENT*` commands survive with identical arity**, confirmed from
  the parser (`cmd_deauth` still does `cmpi a2,3`).~~ **REFUTED on hardware 2026-11-05.**
  `PINEAPPLE_DEAUTH_CLIENT_CSA` takes **two** arguments, not three: with `<bssid> <channel>` it
  reaches MAC parsing (`ERROR: invalid MAC address`), and with a third argument it prints usage and
  does nothing. Reproduce, transmitting nothing, with an unparseable MAC:
  `PINEAPPLE_DEAUTH_CLIENT_CSA ZZ:ZZ:ZZ:ZZ:ZZ:ZZ 9` vs the same plus a third argument.
  The disassembly reading may well be right for whichever function was read; the step from "this
  function checks for 3" to "all three commands take 3" is the part that failed, and it is the same
  reading-then-wrong-inference shape this file warns about twice. `resp_fire` was already correct
  (`CSA` passes two, the others three) - by luck, since no test or measurement covered it until now.
  46 `PINEAPPLE_*` commands, zero added, zero removed, still stands.
- **All three deauth commands are symlinks to `/usr/bin/hak5cmd`** (`readlink -f`, 2026-11-05), so
  the GUI button and a payload's command are the same code path below `/tmp/api.sock`. Their own
  usage text describes the split: `DEAUTH` = "a Wi-Fi client" (deauth + disassoc), `_ALL` = "all
  Wi-Fi clients on an AP" (deauth + disassoc + **CSA**), `_CSA` = "all clients" (CSA only). That
  independently corroborates the `[A]` inference below that `_ALL` is untargeted - weakly, since
  this binary's help has been wrong three times, but it points the same way.
- **`hak5cmd` exits 0 on every path, including its error paths**, and writes errors to **stderr**
  (measured 2026-11-05: `2>/dev/null` swallows the message, `1>/dev/null` does not). So an exit
  status from any `PINEAPPLE_*` command is worthless as a success signal and the stderr capture is
  load-bearing. `resp_fire` checks both; anything new must check stderr, not `$?`.
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
closed without hardware — `dev/pager-prearrival.md`. The ones most worth knowing: whether Recon's
packet counters move the way `resp_verdict` assumes. **The count-byte experiment (day-one step 17a) has RUN — 2026-11-10, see "Fourth contact" and then "Fifth contact", which withdraws its headline.** **Both instruments were run too (`--clone` and `--count-dec`, 2026-11-10), and an adversarial pass then showed the OBSERVABLE was the weak half** — see "Fifth contact", which is the state of record. What survives: the five appended bytes are what disrupt this client. What does not: `--clone` is a near-tautological control on a mac80211 client (a verbatim clone hashes to the same `beacon_crc` and is dropped at `mlme.c:6929`), Channel Switch **Mode 1** freezes the client count-independently (`mlme.c:2610`), the real AP's own beacons abort a pending switch ~10/s (`mlme.c:2452`), and the `--count-dec` arm transmitted count 0 on 23 of 92 frames. **The count byte's effect is un-measured, not null.** **All three next-steps were then run — see "Sixth contact", which is the state of record.** `--elem=32:00` did nothing, so C1 holds in the strong form: it is the channel-switch element, not beacon churn. The mode arms gave a both-matter answer rather than either/or. **Those captures have been read — see "Seventh contact", and "Eighth contact", which reads the mode-0 capture frame by frame.** Only the mode-0 arm contains auth/assoc; all six mode-1 arms contain none, so mode 1 quiesces the client in place while mode 0 makes it re-associate — ~~mode 0 moves it~~ is **[A]** and was withdrawn as a reading 2026-11-10: that capture holds no frame showing the station change channel or saying where it went, only a station leaving and rejoining ch 8 three times, and no receiver was on ch 1. Fourth contact's "honoured a switch then fell back" is refuted. The count >= 1 denial prediction was tested at last and FAILED — the client re-associated successfully while count-3 CSAs were in the air — and the likely reason is structural: the target AP's own beacons keep refreshing the cached IEs, so **17a cannot test the denial path against an AP that is still on the air.** Whether a frame reaches the air on **5 GHz DFS or 6 GHz** still needs an external receiver.
(`inj_parse_channels` is **no longer** on this list — it ran against a live radio on 2026-11-02 and
was correct; see "First contact". Nor is *"the three `PINEAPPLE_DEAUTH_CLIENT*` commands are
documented only by `hak5cmd`'s help text"* — they are now read from pineapd's own handler, see
"Third contact". Nor is *"whether CSA moves a real client at all"*, which is not answerable through
these commands: every CSA they queue announces **channel 14 with count 0**, so a US client that
honoured it would be told to move immediately to a channel it may not use, and the question now
belongs entirely to `pagerinj`. Nor is *"whether `inject_csa`'s `unsigned char` is the count or the
channel"* — resolved in "Third contact": it is the **New Channel Number**, the literal 14 from
`0x473634`, landing in element 37 byte 3, with the Count byte separately `0` from `li s1,0` at
`0x4bee6c`.
*Corrected 2026-11-10, two stale claims removed from this parenthesis.* It previously said `_CSA`
"cannot build a valid request, so no CSA this firmware's commands emit has ever reached the air" —
that was the withdrawn missing-`sta` explanation. `_CSA` sends a well-formed opcode-402 request
whose `sta` is simply never read, so `inject_csa` **is** called and a CSA record **is** queued; what
is unknown is whether the beacon race then transmits it, which is a separate open question with its
own falsifier. And it listed the `unsigned char` question as the replacement open item when the same
day's work had already closed it.)

**⚠ FIXED 2026-11-04 for AP rows — read this as history plus a live remainder.** The block below
described the state before `bss_clients` existed. *And since 2026-11-10 the `NO_CLIENTS` refusal it
describes no longer exists for an AP row at all: operator-decided, *"I'll accept nuclear blast. Let the AP row fire broadcast frames."* A
zero-member AP row fires and loots `INCONCLUSIVE`; see the Response rung paragraph of the code map.* What it says about the *cause* still holds and is
measured: no shipped firmware supplies a client→AP association. What no longer holds is the
conclusion that nothing can fire: an AP row, and both Recon hooks, now recover the subject set from
a capture (`RESPONSE.md` §13a-i). ~~**Still true:** a user-payload **client** row aborts in
`resp_target`'s client branch, and client Watch, Stimulus, kit detection and the AP→client tree
remain inert, all for the same missing `AP_OF`. The inverse lookup that would fix those is the
recon side's and is worth more than the membership work.~~ **AMENDED 2026-11-10 — that lookup has
landed, laptop-verified only** (code map, "Association"). A client row no longer aborts: its card
offers `Watch (find AP first)` / `Disrupt (find AP first)`, and one lookup that hears the client
fills `AP_OF` for the rest of the run. **What is still true is narrower:** the firmware still
supplies no association, so a client that has not been looked up, and was not heard in a membership
capture, still reads `-` and still gates the same five features for that row; and none of the
lookup has run on a device, where its park (`EXAMINE_CHANNEL` alone) has never been issued.
The blocker is the **association column**, not the firmware version. On **1.1.3** `_pineap RECON
CLIENTS` does not exist; since 2026-11-03 client rows come from `RECON DEVICES` instead, but that
object carries no association either, so every client row has `AP_OF` `-` and `resp_target` refuses
it exactly as on 2.0.0 (below), while every AP row has `R_TARGET` broadcast, 0 subjects, and
`resp_fire` refuses with `NO_CLIENTS`. On **2.0.0** client
rows arrive but the device object has no association field, so `JQ_CLI`'s `(.ap_mac // .bssid //
"-")` gives `-` for every one; an AP row then finds 0 matching clients and refuses the same way,
while a client row never even reaches the sweep because `AP_OF` is `-` and `resp_target` returns 1
in its client branch. On both, the user payload transmitted nothing and logged the refusal — until
the membership capture landed, which is what changed the AP-row half.

**⚠ The Recon client hook is the exception, and it transmits on 1.1.3 today.** Everything above is
about the **user payload**, whose association comes from `recon_lines CLIENTS`. The two Recon hooks do
not use it: `hook_target` (`dev/CamHound/hook_main.sh:20-37`) builds its one row from the
`_RECON_SELECTED_*` variables the Recon UI exports, setting `AP_OF[$HOOK_MAC]` from
`_RECON_SELECTED_AP_BSSID` and the channel from `_RECON_SELECTED_{CLIENT,AP}_CHANNEL`, with **no
`_pineap RECON` call at all**. So a hook client row has a real association and a real channel,
`resp_target`'s client branch passes, and `resp_fire` transmits behind the usual picker and confirm —
on 1.1.3, on 2.0.0, regardless of what `RECON CLIENTS` returns. *Found by the recon-side session's
review; verified at `hook_main.sh`'s `hook_target` and `resp_target`.* So "the rung cannot
transmit" was true of the user payload only, and is now untrue of its AP rows as well.

*Corrected 2026-11-03: the first version of this warning said `RESPONSE=1` "buys nothing until the
device is flashed", which implied a flash would buy a working rung. It would not, and that was the
load-bearing half. The 1.1.3 half stands.* Note the determination plan's standing instruction —
`dev/pager-6ghz-determination-plan.md:155` "never flash it to this device" — therefore costs nothing
on this axis. **[A]** — the byte counts and object shape are `[V]`; the code paths were read; the
composition is the inference. ~~*Falsified by:* a Disrupt transmitting **from the user payload** on
either firmware.~~ **SPENT 2026-11-05 — that Disrupt happened.** See "Second contact" above for the
loot row and the log. What the block above still describes correctly is the CAUSE (no firmware
supplies an association) and, **for a client row that has not been resolved off the air**, the
remainder (it aborts in `resp_target`'s client branch, and client Watch, Stimulus, kit detection and
the AP-to-client tree are inert for it — since 2026-11-10 the card turns that row into a lookup
instead of a dead end; see the amendment above). The second falsifier is untouched and still live:
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
Verified in code: `AP_OF[mac] == "-"` disables Watch-on-a-client and Stimulus (`watchable()`), kit
detection (`kit_eval`), the AP→client tree (`write_report`) and, for client rows only, the response
rung (`resp_target`). **Cited by name on purpose** — these four line numbers were exact on
2026-11-04 and all four pointed into unrelated functions one commit later.
But the *attack* never needed it — `CSA` is `<bssid> <ch>` and `BOTH`'s target is discarded, and
`RECON APS` supplies both on 1.1.3, so the firmware can transmit today. What refused was CamHound's
own `NO_CLIENTS` measurement guard — **removed for AP rows 2026-11-10, operator-decided ("nuclear
blast")**: a zero-member AP row now fires the broadcast and loots `INCONCLUSIVE`. The fix was to read the association off the air with a
BSSID-filtered capture (the filter shape at `:1804`, the radiotap-aware frame walker in
`beacon_find`), which is firmware-independent and better evidence than Recon's cumulative counters.
Full working, ranked options and the resolved mechanics are in `dev/CamHound/RESPONSE.md` §13a
and §13a-i. **Implemented 2026-11-04** (`bss_clients`/`capture_bss`/`CLI_AWK`), **and the inverse — one
client's own frames, its BSSID read from them — on 2026-11-10** (`assoc_lookup`, same walker in
`mode=pairs`), which is what fills `AP_OF` and so reaches the other four. ⚠ Three mechanics stated in §13a's first draft are
**wrong** and are corrected in §13a-i, which is the build decision of record: `addr2` is the
client only on a **ToDS** frame, `-s 32` cannot reach `addr2` at all, and the bash
`pcap_bytes`/`hex_octet` walker beacon_find uses is **O(n²)** and cannot be reused at this
file size.

**The inverse lookup has four things only a device can answer** (`dev/pager-day-one.md` 8d has the
commands). All are `[A]` until then; the design degrades rather than fails on each, which is why it
shipped ahead of the measurement.
1. **Does `PINEAPPLE_EXAMINE_CHANNEL` alone park the radio?** Never issued without `EXAMINE_BSSID`
   on a Pager. If it does not, every lookup logs `lock=hop` and takes three windows; nothing breaks.
   *Falsified (as a park) by:* three differing channel samples after it.
2. **Is a camera's uplink heard inside `ASSOC_CAP_SECS` (6 s)?** A streaming camera sends tens of
   frames a second; a sleeping battery camera may send none. `NO_FRAMES` on the right channel for a
   device known to be streaming would mean the window or the filter is wrong, not the device.
3. **Does the OR filter arm on the device's tcpdump?** `capture_bss` uses the same shape — two
   `wlan addrN` terms joined by `or` inside `type data and (…)` — and its capture returned frames on
   the device (Second contact), but **which of its two filter forms armed there is not recorded
   here**, so this is likely, not known. The logs already taken can answer it for the membership
   capture: `grep -c 'OR filter did not arm' /root/loot/CamHound/events.log` — 0 means the OR form
   armed. The lookup's own uplink-only retry exists for the other answer.
4. **Is the client row's `freq` a usable guide to its AP's channel?** It is the device-level
   last-heard frequency. For a camera that is associated and streaming it should be the AP's; the
   fixtures already contain the counter-case (a client heard on 2437 MHz whose AP is on channel 36),
   and the lookup reports that as "not heard on ch 6" rather than as an absence.

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
`--allow-same-chan`, and emits a radiotap RATE field with `--phy-rate <Mbps>`. **Since 2026-11-10 it
carries 17a's control arm, `--clone`** (flood a captured beacon verbatim, no element appended — the
one thing that separates "the client honoured the switch" from "the client was upset by spoofed
beacons"), **and `--count-dec`** (decrement the count 3,2,1,0 and repeat, as a real AP does,
instead of the constant count every run before this sent).

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
