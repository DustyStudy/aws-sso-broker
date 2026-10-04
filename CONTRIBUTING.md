# Contributing

Thanks for taking a look at `ssobroker`. This started as a personal tool, so
the process is intentionally lightweight.

## Setup

```bash
git clone https://github.com/DustyStudy/aws-sso-broker.git
cd aws-sso-broker
python3 -m pip install -e ".[dev]"
pre-commit install   # optional but recommended — see below
```

## Before opening a PR

```bash
ruff check src tests
ruff format src tests
mypy src
pytest -v --cov=ssobroker --cov-report=term-missing
```

All four also run in CI (`.github/workflows/ci.yml`) on every push/PR, so a
green run locally should mean a green run there too.

### pre-commit (optional)

`.pre-commit-config.yaml` runs ruff lint+format and a few basic hygiene
checks automatically before each commit:

```bash
pre-commit install
```

## Code style

- Python 3.11+, type hints on new public functions (see `py.typed` —
  this package ships typed).
- Prefer explicit, boring code over clever abstractions — this tool
  manages AWS credentials; readability matters more than cleverness.
- New CLI commands should follow the existing pattern in `cli.py`: thin
  wrapper around logic that lives in a dedicated module (`exec_cmd.py`,
  `sso.py`, `policy_check.py`, etc.), not business logic inline in the
  Click command itself.

## Security-sensitive areas

Changes to credential handling, caching, or guardrails deserve extra
scrutiny. See [SECURITY.md](.github/SECURITY.md) for the reporting process
and which files those cover.

## Commit messages

Once release-please (`.github/workflows/release-please.yml`) is active,
version bumps and CHANGELOG.md entries are generated from commit messages
following [Conventional Commits](https://www.conventionalcommits.org/):

- `feat: ...` — new feature (minor bump)
- `fix: ...` — bug fix (patch bump)
- `feat!: ...` or a `BREAKING CHANGE:` footer — breaking change (major bump,
  or minor pre-1.0)
- `chore:`, `docs:`, `ci:`, `test:`, `refactor:` — no version bump, but
  still show up in the changelog under their own section

This only matters for commits on `main` going forward — nothing needs to be
retrofixed on history.

## Dependency lockfiles

`requirements/*.txt` are hash-locked with uv. Regenerate after changing
`pyproject.toml` or `requirements/release.in`:

```bash
uv pip compile pyproject.toml --extra dev --universal --generate-hashes --python-version 3.11 -o requirements/dev.txt
uv pip compile pyproject.toml --extra keyring --extra windows --universal --generate-hashes --python-version 3.11 -o requirements/runtime.txt
uv pip compile requirements/release.in --universal --generate-hashes --python-version 3.11 -o requirements/release.txt
```

`runtime.txt` is attached to every release and is what the SBOM describes.

## Releases

Merging the release-please PR tags the release and creates it as a draft.
The same workflow then builds the wheel and sdist with the hash-pinned tools
in `requirements/release.txt`, generates a CycloneDX SBOM, attests build
provenance for all of it, uploads the files and the attestation bundle to
the draft, and publishes it. If the build fails, the release stays a draft:
re-run the `build` job.

Publishing to PyPI is off until trusted publishing is set up (no API token is
stored anywhere):

1. On PyPI, add a trusted publisher for project `aws-sso-broker`: owner
   `DustyStudy`, repository `aws-sso-broker`, workflow
   `release-please.yml`, environment `pypi`.
2. In the repository settings, create an environment named `pypi`
   (optionally with required reviewers).
3. Set the repository variable `PYPI_PUBLISH` to `true`.
