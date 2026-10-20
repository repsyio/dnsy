# Compacting after every wave

Reviewing diffs and reports fills the orchestrator's context fast; compact at every wave boundary.

- **A wave** is a row of the plan's wave table. Treat it as closed when every PR is merged (or parked on the held list) and its worktrees are removed.
- **Also compact at about 200k context**, wave or not, once no hand-back is half-reviewed. Calls at 900k cost nine times calls at 100k.
- **Before compacting**, make engram the source of truth (`mem_save`, project `dnsy`): `dnsy/batch-plan` and `dnsy/wave-log` updated for every merge; running agents (id, branch, worktree, model); the held/needs-decision list; new stories filed; the next stories to dispatch; open review notes.
- **Compact** with `/compact` and a focus such as: "DNSY batch wave N: keep the engram topic keys, running agents, next stories and held list; drop merged diffs and reports." If you cannot run it, say a compact is due and continue.
- **After compacting**: `mem_search` `dnsy/batch-plan` and `dnsy/wave-log`, run `git worktree list` and check running agents, run the incremental `/graphify` update if not done, then dispatch. Never dispatch from the summary alone.
- Never compact while a review or merge is in flight.
