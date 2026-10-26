# Test fixtures

The binary fixtures the tests use (the former `games/` tree) are **not** in
this repository. They live in the **private** repository
`EdgeOfAssembly/dumpexe-fixtures` (a `games/` tree plus `SHA256SUMS`). It
must stay private.

`tests/fixtures.sh` finds them, in this order:

1. `DUMPEXE_FIXTURES=<dir>` (a dir holding `games/`, or the games dir itself);
2. `./games` in the checkout (a local, untracked copy; gitignored);
3. `tests/.fixtures/dumpexe-fixtures` (gitignored cache), cloned on first use
   when git can reach the private repo. `DUMPEXE_FIXTURES_NO_CLONE=1` turns
   the clone off.

Tests name fixtures by generic id (`fx01` ... `fx12`). `tests/fixtures.sha256`
maps each id to a SHA-256 only, and `fixture ID` finds the file in the tree by
that hash, so no private path or title is part of this repository. The id to
file map is kept in the private RetroCodeMess repository. When a
fixture is unavailable, its checks are skipped and the suite exits 77 (skip)
once all other checks pass, like the missing-uasm skip.

Packed samples that are not in the fixtures repo are looked up by generic id
(`s01.exe` ... `s06.exe`) in `DUMPEXE_SAMPLES` (default `tests/.samples`), and
the packer samples (`exepack-1.exe`, `lz91.exe`, ...) in
`DUMPEXE_PACKER_SAMPLES` (default `tests/.samples/packers`). Missing samples
are skipped.
