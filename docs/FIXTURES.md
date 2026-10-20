# Test fixtures

The binary fixtures the tests use (the former `games/` tree) are **not** in
this repository. They live in the **private** repository
`EdgeOfAssembly/dumpexe-fixtures` (same `games/...` paths, plus
`SHA256SUMS`). It must stay private.

`tests/fixtures.sh` finds them, in this order:

1. `DUMPEXE_FIXTURES=<dir>` (a dir holding `games/`, or the games dir itself);
2. `./games` in the checkout (a local, untracked copy; gitignored);
3. `tests/.fixtures/dumpexe-fixtures` (gitignored cache), cloned on first use
   when git can reach the private repo. `DUMPEXE_FIXTURES_NO_CLONE=1` turns
   the clone off.

Each fixture a test uses is checked against `tests/fixtures.sha256`. When a
fixture is unavailable, its checks are skipped and the suite exits 77 (skip)
once all other checks pass, like the missing-uasm skip.

Paths such as `games/cutemouse/` in other docs refer to that private tree.
