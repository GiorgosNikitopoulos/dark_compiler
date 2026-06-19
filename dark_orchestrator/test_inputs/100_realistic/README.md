# 100_realistic

100 **real bug-fix** commits sampled from
`uve_extractor/125_commits/accepted_patches.jsonl`, with **one commit per
repository** (100 distinct repos).

Same schema as `input_realistic_test` and the miner output that
`dark_orchestrator` / `uve_extractor_loader` consume:

* `parents[0]` — vulnerable side (git parent of the fix)
* `sha` — fix commit (non-vulnerable side)
* `patch` — localized unified diff hunk(s)
* `cwe_id` / `target_cwe` — vulnerability class from triage

## Selection criteria

Each row must pass:

* triage `accepted`, `localized_enough`, confidence ≥ 0.85
* single modified C/C++ source file
* patch size 100–6000 chars
* canonical `owner/repo` GitHub slug (exactly one `/`)
* excludes mailing-list mirrors, AOSP/device-kernel forks, vuln dump repos,
  and the five repos already in `input_realistic_test`

When a repo has multiple qualifying commits, the best row is kept (highest
triage confidence, patch size near ~800 chars). Well-known upstream orgs are
prioritized, then the rest is filled with a seeded shuffle (`seed=42`).

Regenerate:

```bash
python3 test_inputs/build_100_realistic.py
```

See `manifest.tsv` for the full list (repo, SHA, CWE, file, message).

## Overnight run

```bash
cd /home/gnikitopoulos/sima_binpool/dark_compiler/dark_orchestrator

python3 -m dark_orchestrator run \
  --input-results-dir test_inputs/100_realistic \
  --output-dir dark_100_realistic \
  --jobs 5
```

Or use the helper script:

```bash
./test_run_100_realistic.sh
```

After the run, inspect:

* `dark_100_realistic/records/commit_summary.jsonl` — per-item build success
* `dark_100_realistic/records/function_status.jsonl` — changed-function ELF trace
* `dark_100_realistic/metrics/yield_summary.json` — aggregate totals

Bridge into the loader pipeline:

```bash
cd /home/gnikitopoulos/sima_binpool/uve_extractor_loader
python3 bulk_verify_dark_compile.py \
  --dark-output ../dark_compiler/dark_orchestrator/dark_100_realistic \
  --accepted-patches ../dark_compiler/dark_orchestrator/test_inputs/100_realistic/accepted_patches.jsonl \
  -o output_dark_100
```

## Expectations

This is a **breadth** test, not a guaranteed-all-green smoke. CXXCrafter is
LLM-driven and some repos (kernels, embedded forks, exotic build systems) may
fail to compile. Failures are useful signal for overnight triage.
