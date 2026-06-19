# 1000_cwe125

CWE-125 (out-of-bounds **read**) commits from
`uve_extractor/125_commits/accepted_patches.jsonl`, interleaved by repo so
runs get variety (round-robin: at most one consecutive row per repo until
that repo's queue is exhausted).

Regenerate:

```bash
python3 test_inputs/build_1000_cwe125.py
```

## Selection

* `cwe_id` / `target_cwe` / triage `mapped_cwe` = **CWE-125**
* triage accepted, localized, confidence ≥ 0.85 (tier fill to 0.80 / wider
  patch bounds only if needed to grow the pool)
* single modified C/C++ file, patch 100–6000 chars (tier fill may widen)
* canonical `owner/repo`, excludes kernel/device forks (same blocklist as
  `100_realistic`)

**Note:** the upstream corpus currently yields **974** qualifying rows, not
1000. The generator takes everything available after tiered fill and
round-robin mixing. See `sampling_stats.json`.

## Run

```bash
cd dark_orchestrator
./test_run_1000_cwe125.sh
```

Or manually:

```bash
python3 -m dark_orchestrator run \
  --input-results-dir test_inputs/1000_cwe125 \
  --output-dir dark_1000_cwe125 \
  --jobs 10
```

Bridge:

```bash
python3 bulk_verify_dark_compile.py \
  --dark-output ../dark_compiler/dark_orchestrator/dark_1000_cwe125 \
  --accepted-patches ../dark_compiler/dark_orchestrator/test_inputs/1000_cwe125/accepted_patches.jsonl \
  -o output_dark_1000_cwe125
```
