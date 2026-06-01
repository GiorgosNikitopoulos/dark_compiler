# dark_orchestrator test inputs

Two ready-to-use `--input-results-dir` directories for smoke-testing the
orchestrator end to end. Both files are valid `accepted_patches.jsonl`
inputs (the same schema as `uve_extractor`'s miner output that
`uve_extractor_pp` consumes).

## Layouts

```
test_inputs/
  accepted_patches.jsonl     # 8 small, well-known C/C++ release pairs
  smoke_one/
    accepted_patches.jsonl   # 1 pair (cJSON v1.7.18) for fastest smoke
```

## What's inside `accepted_patches.jsonl` (the 8-pair set)

Each line pins a tagged release commit (`sha`) and its first parent
(`parents[0]`). Tags are immutable, so the SHAs will never drift. Build
systems are intentionally vanilla (Make / CMake / autotools) so
CXXCrafter's LLM rarely needs more than one Dockerfile attempt.

| Repo | Tag | Build system |
|------|-----|--------------|
| DaveGamble/cJSON | v1.7.18 | CMake |
| kr/beanstalkd | v1.13 | Makefile |
| lz4/lz4 | v1.10.0 | Makefile |
| madler/zlib | v1.3.1 | configure + Make |
| akheron/jansson | v2.14 | CMake |
| facebook/zstd | v1.5.6 | Makefile |
| fmtlib/fmt | 11.0.2 | CMake |
| json-c/json-c | json-c-0.18-20240915 | CMake |

Each row deliberately omits `patch` (the unified diff). The orchestrator
tolerates this — `function_status.jsonl` will simply have zero
changed-function rows for these items, while build/ELF tracing still
runs end-to-end. To exercise the diff path too, append a `"patch":
"<unified-diff>"` field on any row.

## Usage

Single-pair smoke (fastest):

```bash
python -m dark_orchestrator run \
  --input-results-dir /home/gnikitopoulos/sima_binpool/dark_compiler/dark_orchestrator/test_inputs/smoke_one \
  --output-dir /tmp/dark_smoke_one \
  --jobs 1
```

Eight-pair full smoke:

```bash
python -m dark_orchestrator run \
  --input-results-dir /home/gnikitopoulos/sima_binpool/dark_compiler/dark_orchestrator/test_inputs \
  --output-dir /tmp/dark_smoke_all \
  --jobs 2
```

## What "passes"

After a run, expect:

- `out/cxx_compile/<item_id>/<side>/trace/elf_manifest.json` — per-layer
  ELF list (the per-Dockerfile-step trace).
- `out/cxx_compile/<item_id>/<side>/trace/elfs/layer_NNN/...` — copied-out
  ELF binaries.
- `out/records/commit_summary.jsonl` — one line per pair with
  `side_success`, `side_elf_counts`, `side_image_tags`.
- `out/metrics/yield_summary.json` — totals incl. `extracted_elfs`,
  `images_cleaned`, `images_failed_cleanup`.
- `docker images --filter "reference=dark_cxx/*"` shows nothing after the
  run finishes.
- Ctrl+C mid-run still leaves `docker images --filter "reference=dark_cxx/*"`
  empty.

## Verifying the SHAs

```bash
git ls-remote https://github.com/DaveGamble/cJSON refs/tags/v1.7.18
# acc76239bee01d8e9c858ae2cab296704e52d916  refs/tags/v1.7.18
```
