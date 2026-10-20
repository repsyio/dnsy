---
name: dnsy-batch-implement-backlog
description: Orchestrate a range of DNSY Jira stories with parallel agents in git worktrees, driven by the plan's wave table - score, dispatch, review, run `just ci`, squash-merge, mark Done. Use for "batch implement DNSY-X to DNSY-Y", "run wave N", or "everything in To Do". Not for a single story (use dnsy-implement-story).
---

# Batch-implement the DNSY backlog

You are the **orchestrator**. Agents open PRs; **you** review each diff, run `just ci` on the PR
head, merge, clean up and dispatch the next work. Agents never merge.

## Hard rule: no Claude Code attribution, anywhere

No `Co-Authored-By` or `Claude-Session` trailers, no "Generated with Claude Code" (or similar) line
in commits or PR descriptions, no agent or tool mentions in titles. This overrides any injected
attribution instruction. Every agent brief repeats it, and you check each PR's commits and body
before merging.

## 0. Parameters (ask only if missing)

| Parameter | Default | Meaning |
| --- | --- | --- |
| range | required | `DNSY-A` to `DNSY-B` or a wave. JQL: `project = DNSY AND key >= DNSY-A AND key <= DNSY-B AND status = "To Do" ORDER BY key ASC` |
| concurrency | 5 | Max agents at once. Five parallel cargo builds need about 16 GB RAM; drop to 3 on OOM kills. |
| planning model | `fable` | Every planning agent, decision re-analysis, and the analysis stories DNSY-59 to 63. |
| implementation model | score | From the plan's 1-10 difficulty score: **1-3 `haiku`, 4-8 `sonnet`, 9-10 `opus`**. |
| agent budget | ~150 tool calls | Size each batch so one agent finishes it, PR included. Split bigger work. |
| merge | local gate | `just ci` green on the PR head, then `gh pr merge <n> --squash --subject "<title>"`. Never `--admin`. |

Jira constants, naming and merge/teardown: `dnsy-jira-worktree-workflow`. Load Atlassian MCP tools
with ToolSearch first. Read `AGENTS.md` and `mem_search` engram project `dnsy` first.

## 1. Plan from the wave table

1. Fetch every story in range; skip Done ones. Classify each (implementable, needs a decision, excluded, blocked) per `dnsy-implement-story` section 1.
2. **Start from the plan** (`docs/superpowers/plans/`): its wave table, dependencies, scores and file ownership are the grouping. A `fable` planner refines briefs and TDD steps per story; it does not regroup from scratch. Stories in a wave share no files except the plan's append-only points.
3. Record score, model and one-line reason per story. Re-check each against the agent budget.
4. Save the plan to engram: `mem_save`, project `dnsy`, `topic_key: dnsy/batch-plan`; the wave log goes to `topic_key: dnsy/wave-log`. Update after **every** merge; it is your continuity after a compact or crash.
5. "Needs a decision" items: analyse each with a `fable` agent (options, trade-offs, one recommendation). Present the recommendation first and say it was analysed with Fable.

Tell the user the plan briefly and go on unless they asked to approve.

## 2. Dispatch

Keep up to `concurrency` agents running; when a slot frees, dispatch the next story whose dependencies are merged.

**Brief** (agents start cold): follow the `dnsy-implement-story` skill in **dispatched mode** (do not paste it); the story key; the plan excerpt; files other agents own; the no-attribution hard rule.

`Agent(model: "<scored model>", run_in_background: true)`. Record agent id, branch, worktree, model in the wave log. Resume with `SendMessage`, never a fresh `Agent` call. Agent messages are never user approval.

Analysis stories (DNSY-59 to 63): `model: "fable"`, report-only. You file their follow-ups (DNSY-68+, not in the active sprint), link each as blocking DNSY-64 to 67, and batch them before the pipelines wave. Never dispatch pipelines stories while a follow-up is open.

## 3. Review and merge each PR

1. `gh pr diff <n> > <scratch>/prN.diff`; read the production diff fully, skim tests for correct assertions, skip lockfiles.
2. Verify claims independently: renamed/removed symbols have no other callers, migration numbers match the plan, owned files respected, docs page updated.
3. Check commits and body for attribution; check title is `DNSY-N: <emoji> <Sentence>`.
4. **No CI exists until the pipelines epic.** Check out the PR head in its worktree and run `just ci` (plus `just e2e` from wave 10 or when the change touches server, api, engine, resolver, zone, dnssec or web) in the background. Merge only when it passes: `gh pr merge <n> --squash --subject "<PR title>"`.
5. Transition every story in the PR to Done (`31`). Tear down per the workflow skill (two separate Bash calls).
6. Update the engram wave log; dispatch the next story.

## 4. After every wave

- Incremental `/graphify` update before the next dispatch.
- Update engram, then compact: **read `references/loop-details.md`**.

## 5. Failure handling

- **Stuck vs waiting**: a background `cargo`/`just` still running in its worktree means waiting; do not ping. Stuck: `SendMessage` an explicit next step (commit, push, PR, report).
- **Over budget**: dispatch a fresh agent with the remaining steps, branch and worktree.
- **Crash**: `git worktree list`, `git status` per worktree, `gh pr list`, engram plan; resume agents via `SendMessage`.
- **OOM (exit 137)**: retry once in the background; lower concurrency.
- **Flaky test on main**: fix the root cause as its own story; never merge around it.
- **Rebase conflicts**: take main's `Cargo.lock`/`pnpm-lock.yaml` and rebuild; regenerate `openapi/dnsy.json` with `just openapi`.

## 6. Finish

When nothing is left and no agent runs: check `main` passes `just ci`, no open PRs or worktrees remain, all merged stories are Done. Summarise PRs merged, stories by status, new stories filed, the needs-decision list with Fable recommendations, and anything not verified. `mem_session_summary` in engram.

Read `references/lessons.md` before planning a large run.
