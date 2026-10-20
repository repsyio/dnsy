# Batch lessons

## Review and merge

- Sequential merging of batches grouped so they share no files gave zero textual conflicts.
- Most real bugs caught in review were behaviour changes with other consumers (a new error breaking an e2e fixture or a UI default, a removed function's other callers). Grep every consumer: other crates, `tests/e2e`, `web/`, docs.
- After changing a shared contract (OpenAPI spec, a pinned cross-crate interface), regenerate and type-check every consumer before merging.
- Agents under-report "not verified": always ask what was not run. Full `just ci` before the PR and flip-and-fail proofs are worth requiring.
- Stories phrased "decide whether..." are not implementable; agents will implement a guess. Keep them out of the batch.
- Lockfile conflicts: take main's `Cargo.lock` / `pnpm-lock.yaml` and rebuild; never hand-merge.
- Regenerate `openapi/dnsy.json` (`just openapi`) on rebase instead of hand-merging it.
- e2e runs can leave root-owned files in worktrees so `git worktree remove` fails: tell the user to remove the directory, do not work around it.

## Token use

- Cost scales with calls x context; the levers are shorter runs and smaller contexts.
- Subagents were most of the tokens; agents above 300 calls used about half of agent tokens. Keep the ~150-call budget.
- Busy-wait polling was a large share of tokens: run builds in the background and wait for the exit notification.
- Tool results dominate an agent's context; large results (diffs, test dumps, screenshots) go to files and are read in slices.
- The fixed prefix (system prompt, AGENTS.md, skill list, MCP schemas) is paid on every call; keep AGENTS.md and skills short.
