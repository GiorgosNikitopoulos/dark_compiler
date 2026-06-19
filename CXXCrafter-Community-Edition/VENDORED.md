# Vendored: CXXCrafter (Community Edition)

This directory contains a **vendored copy** of CXXCrafter, modified for use by
`dark_orchestrator`. It is included directly (not as a git submodule) so that the
artifact clones and runs reproducibly without depending on the upstream repository
remaining available.

- **Upstream:** https://github.com/seclab-fudan/CXXCrafter-Community-Edition
- **Based on upstream commit:** `bac70e9` (merge of `pypi-251059`)
- **License:** MIT (see `LICENSE` in this directory — retained from upstream)
- **Reference:** CXXCrafter, FSE (ESEC) 2025.

## Local modifications

Two changes were applied on top of upstream `bac70e9` to make CXXCrafter usable
by the orchestrator (247 insertions / 81 deletions across 9 files):

```
93931ec Fix symlink bug - 1000 experiment
0d10148 Mend CXX crafter to work
```

Touched files: `cli.py`, `config.py`, `execution_module/{__init__,docker_manager,utils}.py`,
`generation_module/__init__.py`, `generation_module/template/{dockerfile_template,prompt_template}.py`,
`log_utils.py`.

The complete diff against upstream is preserved in
[`MODIFICATIONS.patch`](MODIFICATIONS.patch). To see exactly what we changed
relative to a clean upstream checkout:

```bash
git clone https://github.com/seclab-fudan/CXXCrafter-Community-Edition
cd CXXCrafter-Community-Edition && git checkout bac70e9
git apply --stat /path/to/MODIFICATIONS.patch
```
