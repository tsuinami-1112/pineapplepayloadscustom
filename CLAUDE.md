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
| config block | top of file → `# ... end config block ---` | neither |
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
`disrupt_menu` call it). `inj_parse_channels` is its awk parser — **it has never seen live `iw`
output**; diffing it by hand against a real run is a day-one job.

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
| Bench running order once hardware arrives | `dev/pager-day-one.md` |
| Self-contained brief for the session that will walk the operator through the bench | `dev/pager-bench-handoff.md` |

Each of those cross-references the others; `pager-csa-primitives.md` is the reference the rest defer
to on mechanism.

## Established so far — a snapshot, not a verdict

**Read this to recognise a question that has already had work done on it, not as a reason to stop
asking it.** Everything below was derived from static analysis of firmware 1.1.3-stable and kernel
source, as of commit `07916df`, with **no hardware on the bench**. Full working and citations are in
the docs above.

Over one day these conclusions needed three independent reviews and were materially wrong twice, in
both directions. So: a session with the device in front of it outranks anything here; so does a
contradicting primary source. If you overturn something, change it here and say so in the commit
rather than leaving two answers in the repo. `dev/pager-csa-primitives.md` §"Re-deriving from
scratch, if you do not trust this file" exists for exactly that.

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
- **pineapd's CSA carries Channel Switch Count = 0** (built at `0x4bee8a`), and
  `ieee80211_mgd_csa_present()` discards a count-0 CSA before the auth/assoc refusal check. So CSA
  can kick a client but can never deny it a reconnection. Count 0 is also what makes the move
  immediate. A non-zero count would get both — needs our own injector, no setting exists. This is
  the single most load-bearing firmware fact for the response rung.
- **Beacon protection needs both ends.** The AP must enable it (hostapd advertises Ext Cap bit 84
  only with `beacon_prot=1` *and* driver support; it turns itself on once 11be is enabled with PMF)
  **and** the client must be able to install a BIGTK (`nl80211` refuses key idx 6–7 without
  `NL80211_EXT_FEATURE_BEACON_PROTECTION[_CLIENT]`). The AP's bit 84 is policy, not client
  behaviour.
- **Hardware, from FCC ID 2A52Y-MK1:** 6 GHz is certified across all four U-NII sub-bands, so the
  block is software. The Pager is a **one-transmitter** device — `WIFI-1`/`WIFI-2` do all TX on
  every band; `2.4G-1`/`2.4G-2` are annotated "Not used for transmitting", so `radio0` is
  receive-only and **`wlan0mon` cannot hear 5 GHz**. Board `Pager V2.2.0`.
- **Firmware under analysis is 1.1.3-stable** — OpenWrt 24.10.1, `ramips/mt76x8`, `mipsel_24kc`,
  mac80211 from backports-6.12. Every address above is pinned to it. `pineapd` is **MIPS16e** with
  no section headers: disassemble with `-m mips:16`, mask bit 0 off symbol values, and read symbols
  with `nm -D` / `objdump -T` / `readelf --use-dynamic -sW` — plain `readelf -s` and
  `readelf --dyn-syms` return nothing **and exit 0**.
- **`libwifi.so.0.0.10` exports 113 functions**, 92 unused by pineapd, including
  `libwifi_create_action`, `_action_no_ack`, `_add_action_detail`, `_create_probe_resp`,
  `_set_probe_resp_channel` and the `libwifi_*_tag` element API. Reach them with `dlopen`/`dlsym` —
  **linking `-lwifi` against the shipped file is refused** (no section headers). No headers or
  static lib ship, so write prototypes and struct layouts by hand against upstream `0.0.10`.

**Refuted hypotheses**, so they are not re-proposed — but note which rest on what:

- *Hard, from the FCC filing (primary source):* that the Pager has no 6 GHz radio; that it was
  6 GHz receive-capable but never certified to transmit; that `wlan0mon` could serve as the 5 GHz
  receiver (the antenna map plus `radio0`'s `band '2g'` settle it).
- *From source analysis, so re-openable by measurement:* that `cfg80211` is what blocks DFS
  injection (the block is pineapd's); that probe-response CSA is a fallback for beacon protection.

## Open, and needs the hardware

Listed in `dev/CamHound/RESPONSE.md` §13 and `dev/pager-day-one.md`. The ones most worth knowing:
`inj_parse_channels` has never parsed real `iw` output; the three `PINEAPPLE_DEAUTH_CLIENT*`
commands are documented only by `hak5cmd`'s help text; whether Recon's packet counters move the way
`resp_verdict` assumes; whether CSA moves a real client at all; and the count-byte experiment
(day-one step 17a).

## Re-obtaining the firmware

Extraction lives in a session scratchpad and **will not exist for a future session**. To rebuild it:
the image URL and its sha256 are in `dev/pager-6ghz-determination-plan.md` §0.4 (with the recovery
ladder); the version-identity gate is §P0.2. Put it in its own new empty directory and treat it as untrusted per the standing rules.
