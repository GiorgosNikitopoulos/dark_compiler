# dark_compiler

Orchestrates [CXXCrafter](https://github.com/seclab-fudan/CXXCrafter-Community-Edition)
— an LLM agent that auto-generates Dockerfiles to build C/C++ projects — over
vulnerability **commit-pairs**. For each pair it compiles the vulnerable (parent)
and patched sides, traces the ELF binaries emitted at each Docker layer, and
handles image lifecycle, parallel jobs, checkpoint/resume, and Ctrl+C teardown to
produce a **labeled binary dataset**.

## How it works

Given a directory of commit-pair results (each with a parent/patch diff), the
pipeline:

1. Drives CXXCrafter to build the **parent** (labeled `vulnerable`) and **patch**
   (labeled `non_vulnerable`) side of each pair.
2. **Traces ELFs per Docker image layer** so the compiled binaries can be
   extracted and attributed to a specific build layer (`--elf-mode last_elf_layer`
   keeps the last layer that produced ELFs; `all` extracts from every layer).
3. Maps changed functions from the patch diff onto the produced binaries.
4. Manages Docker **image lifecycle** (tagging, `rmi`/prune cleanup) and tears
   down cleanly on `Ctrl+C`.
5. Writes per-item records (JSONL) plus **checkpoint state** so runs **auto-resume**
   where they left off.

## Layout

| Path | Description |
|------|-------------|
| `dark_orchestrator/dark_orchestrator/` | The orchestration package (pipeline, CXX adapter, ELF tracer, state, metrics). |
| `dark_orchestrator/test_inputs/` | Sample commit-pair inputs and dataset-build scripts. |
| `CXXCrafter-Community-Edition/` | Vendored, modified copy of CXXCrafter (MIT). See [`VENDORED.md`](CXXCrafter-Community-Edition/VENDORED.md). |

## Install

Requires Python ≥ 3.10, a running **Docker daemon**, and an LLM API configured for
CXXCrafter (see `CXXCrafter-Community-Edition/`).

```bash
python -m venv venv && source venv/bin/activate
pip install ./CXXCrafter-Community-Edition
pip install ./dark_orchestrator
```

## Usage

```bash
python -m dark_orchestrator run \
  --input-results-dir /path/to/commit_pair_results \
  --output-dir /path/to/out \
  --jobs 4
```

Useful flags:

- `--elf-mode {last_elf_layer,all}` — which Docker layers to extract ELFs from.
- `--jobs N` — parallel commit-pair workers.
- `--fresh` — force a clean run (wipe checkpoint/completed state).
- `--retry-failed` — on resume, also re-enqueue previously failed pairs.
- `--keep-images` — skip image cleanup (debugging).
- `--reset-cxx-cache` — wipe CXXCrafter's cached Dockerfile playground first.

Rebuild the metrics summary from the time series:

```bash
python -m dark_orchestrator metrics --output-dir /path/to/out
```

## License

MIT — see [`LICENSE`](LICENSE). This project vendors a modified copy of CXXCrafter,
also MIT licensed; see [`CXXCrafter-Community-Edition/VENDORED.md`](CXXCrafter-Community-Edition/VENDORED.md)
for attribution and the list of local modifications.
