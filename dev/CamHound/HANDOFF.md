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

Nothing of ours has run on the device yet. Everything is laptop-verified (selftest 225/0, harness 13
scenarios 0 failures on fbfab6a). Install per the user README; first run: watch `events.log` for
`client verb: DEVICES`, `inj probe: tx phy phy1`, the Settings pages, and inventory persistence across
two runs. Known-inert on 1.1.3: client association (kit detection, client Watch, per-client Disrupt);
the response rung from the user payload (refused before transmit); BAND6 (no-op). The Recon client
hook can transmit from the Pager's Recon client menu, behind the picker and the confirm.

## Review in flight when this was written

Workflow run `wf_f3640da9-dde` (tiered, per the CLAUDE.md rules) over `git diff 7b5e8fc 4356936`;
its template is in `dev/review/`. Findings that survive get fixed on this branch before handover.
