# Contributing

Read [AGENTS.md](AGENTS.md) first: layout, commands, rules and conventions apply to every contributor.

1. Pick a Jira story (`DNSY-{n}`) and branch `DNSY-{n}-{short-slug}` in a git worktree.
2. Write the failing test first, then the code.
3. Run `just ci` locally; it is the merge gate.
4. Open a PR titled `DNSY-{n}: {emoji} {Sentence}`; commit subjects start with an emoji.
