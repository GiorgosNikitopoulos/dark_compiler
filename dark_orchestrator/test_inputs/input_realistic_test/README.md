# input_realistic_test

5 **real bug-fix** commits from canonical upstream C/C++ projects, picked
from the same `accepted_patches.jsonl` schema that `uve_extractor` mines
and `uve_extractor_pp` consumes.

Unlike `test_inputs/accepted_patches.jsonl` (which is **release-tag pairs**,
useful only as a build smoke), every row here points at a single security
fix commit:

* `parents[0]` is the actual git parent of the fix commit (the **vulnerable**
  side).
* `sha` is the fix commit (the **non-vulnerable** side).
* `patch` is the localized unified diff (1 file, ~250-1000 chars).
* `cwe_id` / `target_cwe` come from the upstream triage and identify what
  class of vulnerability the fix addresses.

Run with:

```bash
python3 -m dark_orchestrator run \
  --input-results-dir test_inputs/input_realistic_test \
  --output-dir dark_realistic_run \
  --fresh
```

## Rows (sorted by diff size, smallest first so progress is visible early)

| # | Repo | CWE | File | Function | Fix message |
|---|------|-----|------|----------|-------------|
| 1 | `vstakhov/libucl` | CWE-122 | `src/ucl_parser.c` | `ucl_maybe_parse_number` | Fix heap-buffer-overflow in `ucl_maybe_parse_number` |
| 2 | `pupnp/pupnp` | CWE-122 | `ixml/src/ixmlparser.c` | `Parser_getChar` | Fixes heap-buffer-overflow analogous to the previous patch |
| 3 | `libass/libass` | CWE-125 | `libass/ass_shaper.c` | `ass_shaper_reorder` | bidi: fix buffer overread on soft-wrapped events |
| 4 | `tio/tio` | CWE-787 | `src/configfile.c` | `replace_substring` | Fix potential buffer overflow in `match_and_replace()` |
| 5 | `libssh2/libssh2` | CWE-125 | `src/agent.c` | `agent_transact_pageant` | agent: pageant backend, bound reply copy, handle missing reply |

## Why these five

* All canonical upstream repos (`owner/name` matches the project's official
  GitHub org), no AOSP/TWRP/winlibs forks where parent SHAs may not exist.
* Diverse build systems: autotools (`libucl`, `pupnp`, `libass`),
  CMake (`libssh2`), Meson (`tio`).
* Small enough that CXXCrafter should solve each in 1-3 attempts; large
  enough to actually exercise apt deps and `make`/`cmake` properly (so the
  parent_base patch fast-path matters).
* Single-file localized fixes, so `changed_functions_from_diff` returns
  exactly the one function the CVE fixed and the per-function records in
  `function_status.jsonl` are meaningful.
