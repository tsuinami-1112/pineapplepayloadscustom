# Review workflow template

`camhound-review.workflow.js` is the Workflow-tool script the recon-side session used on 2026-11-03
for the band-write commit, kept here because the operator's standing rules in `CLAUDE.md`
§"Review workflows" are easier to follow from a working example than from prose:

- a preamble (`COMMON`) that names the measured facts and what is already settled or owned by another
  session, read by every agent;
- at most four finder dimensions over `git diff <base> HEAD`;
- tiered verification: findings whose fix would change device code, contradict a measured fact or
  rest on a composed inference get three lenses (trace, intent, impact) in batches of nine; docs,
  comments, counts, wording and test gaps get one sceptical verifier that defaults to refuted;
- the first line of the result is the refutation count, with a warning when nothing was refuted.

To reuse: copy it, change `COMMON`'s base/head and settled-facts paragraph and the `DIMS` prompts,
pass it to the Workflow tool as `script` (or save it under the session's workflow directory and use
`scriptPath`). The `fullTier` predicate is where the consequence/likelihood judgement lives; adjust it
per review and say why in the summary. Big claims that deserve one agent per finding per lens are
allowed by rule 2 — add them as their own `agent()` calls with the reason in the label.
