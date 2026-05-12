# Contributing to TDDF

Issues, bug reports, and pull requests are welcome.

## Getting started

```bash
git clone https://github.com/faivlex/tddf.git
cd tddf
uv sync --group dev
uv run pytest
```

TDDF is a deterministic, local-first regression harness for AI agents — think `pytest` for agent safety behaviour. Contributions should preserve that shape: scenarios in YAML, evaluation without an LLM judge, no cloud dependency.

## What's useful

- **New scenarios** — behaviour patterns not yet covered
- **New delivery strategies** — encoding or obfuscation techniques that multiply existing trap families
- **New adapters** — framework-specific target integrations
- **Bug fixes** — with a test that reproduces the issue
- **Documentation** — typos, clarity, missing examples

## Before submitting a PR

- Run `uv run pytest` and make sure all tests pass
- Follow existing code patterns — Pydantic models, dataclasses, type hints
- Keep changes focused — one concern per PR
- New features should include tests

## Style

- Python 3.12+, type hints everywhere
- Pydantic for config models, dataclasses for runtime data
- No LLM-as-judge — evaluation must be deterministic

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
