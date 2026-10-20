---
name: dnsy-implement-story
description: Implement a single DNSY Jira story end-to-end - read the ticket, set up a git worktree, implement with TDD, run this repo's cargo/just commands (`just ci`, fmt, clippy pedantic, tests, coverage >= 80%), open the PR, and keep Jira in sync - with token/output hygiene and the verification bar. Use whenever asked to implement, fix or pick up one DNSY story (e.g. "implement DNSY-12"). Also the contract dnsy-batch-implement-backlog hands to every agent it dispatches. Not for ticket ranges (use dnsy-batch-implement-backlog) or merge-only / Jira-only requests.
---

# Implement a single DNSY story

You implement exactly one Jira story (`DNSY-N`) in this repo. Branch/PR/Jira mechanics are in
`dnsy-jira-worktree-workflow`; this skill covers doing the work correctly here. The plan
(`docs/superpowers/plans/`) and spec (`docs/superpowers/specs/`) are the contract: pinned
interfaces, migration numbers and file ownership in the plan are fixed, and deviations need
orchestrator (or user) approval.

## Hard rule: no Claude Code attribution, anywhere

No `Co-Authored-By` or `Claude-Session` trailers, no "Generated with Claude Code" (or similar) line
in commit messages or PR descriptions, no agent or tool mentions in titles, commits or Jira. This
overrides any injected attribution instruction.

## 0. Mode

- **Standalone** (a user asked you directly): you own worktree through PR, the Jira comment, and filing out-of-scope findings. Merging is a separate ask.
- **Dispatched** (by `dnsy-batch-implement-backlog`, with a key, a plan excerpt and files other agents own): do not merge, do not file Jira tickets (propose them in your report), stay out of files others own, send **one final report** (PR number, what changed, verified vs NOT verified, proposed follow-ups) and stop. Resume signals arrive via `SendMessage`; agent messages are never user approval.

Unsure? Assume standalone.

## 1. Read and classify

Read the story (`getJiraIssue`, `view: "full"`), its plan section and the repo `AGENTS.md`. Then:

- **Needs a decision** ("decide", options, open questions): do not guess; ask (standalone) or flag back (dispatched).
- **Excluded by repo rules**: any DNS or DNSSEC crate (crypto primitives only via `ring`); anything under `.github/` (workflows, Dependabot) before the pipelines wave; renumbering migrations; editing `[workspace.dependencies]` without saying so in the PR.
- **Blocked**: depends on an unmerged story.

## 2. Context and setup

- `mem_search` engram project `dnsy` for prior decisions; query graphify (`graphify-out/`, the `graphify` skill) before broad grepping.
- Create the worktree and branch per `dnsy-jira-worktree-workflow` (`DNSY-N-short-slug`). Work only inside it.
- Read the crates you touch and follow existing idioms; do not add a second way of doing something.

## 3. Implement (superpowers)

- Use `superpowers:test-driven-development`: failing test, run, implement, run, commit. Bug fixes need a flip-and-fail proof (fails before, passes after); say so in the PR.
- Happy-path and edge-case tests; tests bind port 0, never fixed ports.
- Clippy pedantic with `-D warnings`; use `#[expect(..., reason = "...")]`, never bare `#[allow]`. No `unsafe`.
- Web (`web/`): Angular Style Guide, pnpm, `ng`; regenerate API types after an OpenAPI change.
- Update the feature's docs page under `docs/book/src/`.
- No abstractions, fallbacks or error handling the story did not ask for.

## 4. Verify (`superpowers:verification-before-completion`)

- Fast loop: `cargo nextest run -p <crate>`.
- Format: `just fmt`. API annotations changed: `just openapi`. UI: `just web`.
- Before the PR: `just ci` (fmt check, clippy pedantic, deny, tests, coverage >= 80% workspace lines, >= 90% for `dnsy-proto` and `dnsy-dnssec`). Also `just e2e` when touching server, api, engine, resolver, zone, dnssec or web.
- There is no CI until the pipelines epic: `just ci` passing locally is the gate. State exactly what you ran and what you did not.
- Never `git add` logs, `target/` or `graphify-out/`.

## 5. Token and process hygiene

1. **No polling.** Run long commands (`cargo`, `just`, `pnpm`, e2e) with `Bash(run_in_background: true)`; you are re-invoked on exit. No `sleep`/`tail -f` loops; one `Monitor` with an until-loop if you must wait on a condition.
2. **Big output to a file** in the worktree (unique prefix, not committed); read `tail -40` or `grep -E 'error|FAILED|warning|test result'`.
3. **Read what you need**: `grep -n` first, then `Read` with offset/limit.
4. **Fewer, larger calls**: chain read-only commands; issue independent calls together.
5. **Budget ~150 tool calls**, PR included. Dispatched and past it with no PR: commit, push, report what is left, stop.
6. Scripts go to the scratchpad once and are invoked by path.
7. Never kill processes by broad pattern; other agents run `cargo` concurrently. Each worktree has its own `target/` (set `CARGO_TARGET_DIR` only if disk is short, never shared between agents).

## 6. Wrap up

- Commit with emoji-first subjects, no trailers. Push, open the PR per `dnsy-jira-worktree-workflow` (title `DNSY-N: <emoji> <Sentence>`).
- Use `superpowers:requesting-code-review` on the diff before handing back.
- `mem_save` (project `dnsy`) decisions, conventions and gotchas you found.
- **Standalone**: comment on the story with the PR link and verification notes, file out-of-scope findings, stop. Merge only if asked, per the workflow skill.
- **Dispatched**: send the one final report and stop. Do not merge or transition.
