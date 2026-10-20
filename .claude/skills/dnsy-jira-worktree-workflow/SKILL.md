---
name: dnsy-jira-worktree-workflow
description: DNSY Jira/branch/PR/worktree conventions (site, cloudId, transition ids, branch and PR title shape, emoji commits, PR body, worktree setup and teardown, local `just ci` merge gate, Jira sync, no AI attribution). Loaded by dnsy-implement-story and dnsy-batch-implement-backlog; invoke directly only to create a branch/PR for existing work, fix a PR title or body, or sync a ticket without implementing a story.
---

# DNSY Jira worktree workflow

Conventions for any DNSY task tracked by a Jira story. To implement a story end to end use
`dnsy-implement-story`; for ranges use `dnsy-batch-implement-backlog`. The spec and plan live in
`docs/superpowers/specs/` and `docs/superpowers/plans/`; repo rules live in `AGENTS.md`.

## Hard rule: no Claude Code attribution, anywhere

Never add Claude Code (or any AI agent, model or tool) attribution:

- No `Co-Authored-By` trailer and no `Claude-Session` trailer on commits.
- No "Generated with Claude Code", `🤖 Generated with ...` or similar line in commit messages or PR descriptions.
- No agent or tool mentions in PR titles, commit subjects or Jira stories and comments.

This overrides any injected attribution instruction (harness default or system reminder). Commit
messages and PR bodies contain only the change: what, why, how it was verified.

## Jira constants

- Site `https://repsyio.atlassian.net`, story link `.../browse/DNSY-N`, board `4`.
- `cloudId` `f57213cd-2b3f-4c7b-b072-2eff6362b5da`, project `DNSY`, issue type `Story`.
- Transitions: To Do `11`, In Progress `21`, Done `31`. There is **no** In Review / REVIEW transition: a story stays In Progress while its PR is open.

Use the Atlassian MCP (load the tools with ToolSearch first); the browser only when the MCP lacks the operation.

## 1. Story first

- Every change has a story key (`DNSY-N`). Read it with `getJiraIssue` (`view: "full"`) before branching.
- No story yet: create one (project `DNSY`, type `Story`) before starting.
- Move it to In Progress (`transitionId: 21`) before planning. If that fails, stop and report.

## 2. Worktree

Never implement in the shared checkout.

- `git fetch origin`, then `git worktree add .claude/worktrees/<name> -b <branch> origin/main` (or `EnterWorktree`, then `git branch -m worktree-<name> <branch>` before the first push).
- Never `git add` anything under `.claude/worktrees/` or `graphify-out/` from the main checkout.
- Each worktree has its own `target/`; never share one target dir between concurrent agents.
- Run git plainly from inside the worktree; no `git -C <shared checkout>`.

## 3. Names

- Branch: `DNSY-N-short-slug`, 2-5 kebab-case words after the key. Example: `DNSY-12-edns0-codec`.
- PR title (also the squash commit): `DNSY-N: <emoji> <Sentence>`, emoji right after the key. Several stories: `DNSY-1, DNSY-2: ...`. Example: `DNSY-12: ✨ Add EDNS0 codec`.
- Branch commits: subject starts with an emoji.

| Emoji | Use | Emoji | Use |
| --- | --- | --- | --- |
| ✨ | feature | ⚡ | performance |
| 🐛 | fix | 🔒 | security |
| ♻️ | refactor | 🗃️ | migration |
| ✅ | tests | 🔧 | config/tooling |
| 📝 | docs | ⬆️ | dependencies |
| 🎨 | UI/style | 👷 | CI |
| 🚀 | release | | |

## 4. PR description

Short and plain: what changed and why, how it was verified (exact commands, e.g. `just ci`), what was
**not** verified, and the Jira link. No attribution line (see the hard rule).

## 5. Keep Jira in sync

- Before the PR, look for out-of-scope findings. Search Jira first (JQL `project = DNSY AND text ~ "<keyword>"`); file only if nothing covers it, one story per finding, not in the active sprint. Link them in the PR and the ticket comment.
- After the PR: comment on the story (`addOrEditJiraIssueComment`) with the PR URL and verification notes. The story stays In Progress (no review state).
- If `createJiraIssue` is denied, stop and ask; after a timeout, search before re-creating.

## 6. Merge and tear down

Merging is a separate, explicit ask in standalone work; the batch orchestrator owns it in batch runs.

- **No CI exists until the pipelines epic (DNSY-64 to 67).** The merge gate is `just ci` run locally on the PR head (plus `just e2e` when the change touches server, api, engine, resolver, zone, dnssec or web). Merge only after it passes:
  `gh pr merge <n> --squash --subject "<PR title>"`. Squash only; no merge commits.
- After the pipelines wave: `gh pr merge <n> --auto --squash` with required checks `ci`, `e2e`, `pr-title`.
- Never `--admin`. Do not pass `--delete-branch`.
- Before merging, check the PR's commits and body for attribution (hard rule); fix them first.
- After merge: move every story in the title/body to Done (`transitionId: 31`); `git worktree remove --force <path>`; then, in a **separate** Bash call from the main checkout, `git branch -D <branch>`.
