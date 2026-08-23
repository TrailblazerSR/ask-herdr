# Contributing

Ask-Herdr is an experimental source-only developer preview. Keep changes
bounded to the documented local `query.status` contract unless a proposal
explicitly introduces and justifies a new compatibility surface.

## Before contributing

- Use synthetic data only. Never commit Project roots, Authority UUIDs,
  request files, provider output, credentials, local logs, or review transcripts.
- Discover the current contract from `bin/ask-herdr machine describe --json`
  and retrieve exact advertised schemas before changing behavior.
- Treat direct Herdr commands as a separate capability governed by
  `skills/herdr-command-authority/SKILL.md`.

## Test locally

The supported development environment is macOS with Python 3.10 or later.

```text
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m unittest discover -v -s tests
```

Run `bin/ask-herdr machine describe --json` and retrieve every schema affected
by the change. Contract changes must update implementation, bundled schemas,
tests, documentation, and agent instructions together. Preserve path-free
outcomes and the no-provider/no-Herdr/no-network/no-mutation boundary.

## Pull requests

Explain the user-visible contract change, privacy implications, platform
assumptions, tests run, and remaining limitations. Do not include private
release receipts or internal review material. Dependency additions require a
specific runtime or verification benefit and a license review.

## Contribution license

Unless explicitly stated otherwise, contributions intentionally submitted for
inclusion in Ask-Herdr are provided under the Apache License, Version 2.0, as
described in Section 5 of [LICENSE](LICENSE).
