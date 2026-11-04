# CamHound — state of play, 2026-11-03 (recon-side session)

Written so a fresh session can pick up without the conversation. Facts here are either in git or were
measured by the operator on the bare 1.1.3 unit today; nothing is from memory.

## Branches and PRs

- `master` 536de09: everything up to and including PR #16 (recon-side work, injector, bench docs).
- `claude/modest-babbage-2g7rmv` a2be257 = PR #18 (open): the response session's six commits —
  RESPONSE defaults to 1, attack_scope, scope-based measurement, the never-measured-is-INCONCLUSIVE
  fix, RESPONSE_CONFIRM fails closed, the narrowed "cannot transmit" claim.
- `claude/clever-wozniak-hn3xyn` fbfab6a (recon side, this session): #18's six commits, then
  7b5e8fc (five review follow-ups + the `firmwares/1.1.3-stable` URL fix), 4356936 (BAND6 band write,
  clients from `RECON DEVICES` on 1.1.3), and three CLAUDE.md commits with the operator's review rules.
  Merging this branch makes #18 empty rather than conflicting. No PR is open for it yet.

## Measured on the bare 1.1.3 unit today (operator, SSH as root)

- `_pineap RECON CLIENTS format=json` → `Unknown recon command`, rc 255.
- `_pineap RECON DEVICES format=json` / `RECON APS format=json` → the 2.0.0 object shape exactly
  (hash-keyed `beacon`/`response`/`probe`, device keys alphabetical, `hidden` a JSON boolean), no
  association key. The parsers written for 2.0.0 read it; clients on 1.1.3 now come from DEVICES.
- `PINEAPPLE_SET_BANDS` usage: `[interface] {2} {5} {6}` (token form; nosey-neighbor's `both` is wrong).
  `wlan1mon 2 5 6` with pineapd running: uci still `2,5`, pid unchanged, Recon rows kept, and 16 live
  channel samples over 8 s showed 2.4/5 GHz only — a no-op as issued. `bands_apply` verifies by the
  live channel and reports "band write not applied" in that case. Next checks are day-one 8c.
- `_pineap RECON CHANNELS` is a per-frequency observation histogram, not the hop set.
- `PINEAPPLE_RECON_NEW` with no argument printed nothing; name-vs-duration still open (day-one 8b).

## Capture-based subject path: decided 2026-11-04, not yet built

The operator greenlit it (see the division of labour below). The **build decision of record is
`dev/CamHound/RESPONSE.md` §13a-i** — read that, not §13a, whose option (1) is a
different and larger design, and three of whose stated mechanics are wrong. Adopted: the capture
supplies **membership**, Recon still supplies the **counters**; `resp_verdict`/`resp_aggregate`/
`resp_write` are untouched. The `ap_mac` test in `resp_snapshot` is **unioned**, never replaced
(replacement breaks 5 of 9 snapshot selftest cases; measured). Known before writing a line: no
harness scenario drives Disrupt on the real-firmware shape, and `harness/fix/cli.json` carries
`ap_mac` values no firmware emits — so a Disrupt-under-`HARNESS_NO_CLIENTS` arm is part of the
work, not a nicety. `resp_clamp_lock`'s floor is **not** moved: the extra lock seconds are additive
at the `lock_target` call site in `resp_fire`, and the `resp` line logs the computed figure and the
measured elapsed time — that is the dwell number this handoff promised you.

## Division of labour with the response-rung session (session_01HfHn2Fym5eRJnEQyvHVu7C)

Theirs: attack_scope, disrupt_menu, resp_target/fire/snapshot/verdict/aggregate/write, posture_*,
hook_header.sh/hook_main.sh, RESPONSE.md §§3–11 and 13–14, CLAUDE.md's response-rung bullets, and
(if the operator greenlights it) a capture-based subject path. Ours: everything recon-side, the
Settings menu, the parsers, inj_probe, the band write, resp_clamp_lock (they hand us a measured dwell
figure rather than moving the floor). Sequencing agreed: their selftest cases append after our
recon_stat fallback cases; they extend the harness dispatcher after s_bands/s_devices.

## Open on the bench (day-one 8b/8c)

Where a client's association lives (the Go UI daemon's recon API carries `ap_mac`; `_pineap` does
not); whether the band write applies after a fresh Recon session or a pineapd restart; the
`PINEAPPLE_RECON_NEW` parameter; the lock-floor timing (`resp` lines in events.log).

## Loading onto the Pager

Nothing of ours has run on the device yet. Everything is laptop-verified (selftest 236/0, harness 13
scenarios / 71 checks, 0 failures, on the commit after a17b583; `--selftest` is safe to run on the
Pager since that commit, every device-changing command being stubbed). Install per the user README;
first run: watch `events.log` for
`client verb: DEVICES`, `inj probe: tx phy phy1`, the Settings pages, and inventory persistence across
two runs. Known-inert on 1.1.3: client association (kit detection, client Watch, per-client Disrupt);
the response rung from the user payload (refused before transmit); BAND6 (no-op). The Recon client
hook can transmit from the Pager's Recon client menu, behind the picker and the confirm.

## Review of the band write and the DEVICES fallback — done, fixes landed

Workflow run `wf_f3640da9-dde` (tiered, per the CLAUDE.md rules) over `git diff 7b5e8fc 4356936`;
its template is in `dev/review/`. **Refuted 1 of 19** (11 full-tier, 8 light-tier); 18 confirmed and
fixed in the commit after 033a091. A refutation rate that low is a warning about the verifiers as
much as a verdict on the code — the one refuted finding (the README's needs line) was a doc claim,
and every code finding was confirmed; a second pass by a fresh reader is cheap and worth it before
the other session builds on `bands_*`. What the fixes changed, so the next reader does not re-derive:

- A band write that is issued but never trusted is restored anyway at exit (`BANDS_WROTE` beside
  `BANDS_ORIG`), by `settings_reset` when BAND6 goes back to 0, by the watchdog when the UI kills the
  run, and by `bands_recover` at the next start — the pre-write bands are kept on disk in
  `BANDS_STATE` (`$LOOT_DIR/.bands_orig`, so a reboot does not lose it). Harness arms `bands3-5`
  drive the no-op write measured on 1.1.3, the Settings toggle, and a state file left by a killed run.
- `parse_cli_fallback` now treats a device as an AP only when its `beacon`/`response` object is
  non-empty, matching `JQ_DEVCLI`'s `length == 0` test; its known limit (a probed SSID containing
  `{` or an escaped quote) is written beside the code. The `nojq` scenario compares both parsers
  over `RECON DEVICES` too, and `fix/devices.json` is stored with sorted keys, the measured order.
- The docs that still called the client rung "never run" and the DEVICES verb an "untested lead" are
  date-qualified (CLAUDE.md, RESPONSE.md §13's lead paragraph; its 1.1.3 row's `where` cell now names
  `resp_snapshot`'s sweep instead of a line number); the starred-key count is sixteen everywhere it is
  stated.
- Found while testing the fix, not by the review: the run_lock watchdog outlives its process by up to
  3 s, so the next run's band write could be undone (and its state file deleted) by the previous run's
  watchdog. It now acts on the bands only while the lock file still names its own pid; a run started
  since has already replayed the file. The harness showed it as three intermittent `bands` failures.

**Verification of that commit, after the usage limit reset (2026-11-03):** the full harness
(`run_harness.sh all`) passed on the committed source — 70 checks, 0 failures; the one `Killed` line
in its output is the `lock` scenario's deliberate SIGKILL. A second tiered review of the fix set
(`git diff 033a091 ec3b548`, four finder dimensions, three lenses for device code and one sceptic
for docs and tests) ran after it: **refuted 3 of 20** (29 raw, 20 after dedupe; 14 full-tier, 6
light-tier), confirmed 17, all fixed in the commit after a17b583. Two mattered. The watchdog's
lock-ownership guard assumed any run started since replays the band record, which a Recon hook does
not, so the record now names the pid that wrote it and only that run's watchdog replays it
(`bands_watchdog_restore`, lib), the next user-payload start replaying any record; both claim the
file by rename first. And the selftest's new `settings_reset` case reached the real
`PAYLOAD_DEL_CONFIG` on a Pager, so `st_stub_ui` now stubs every device-changing command whether or
not it is present. The rest: the undo record is a precondition of the write, `bands_recover`
validates the record and refreshes the status line, the pineapd-restart report fires on both
outcomes, reset follows BAND6 both ways, harness arm `bands6` kills a BAND6 run and watches its
watchdog, and six doc spots. Refuted, left alone: the once-per-run guard keyed on `BANDS_ORIG`, the
fixture's lack of an empty-object device (the selftest covers it), the config comment's wording.
