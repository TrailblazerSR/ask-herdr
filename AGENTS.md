# Ask-Herdr Agent Instructions

## Ask-Herdr machine interface

For Ask-Herdr contract discovery, request validation, or `query.status`, read
and follow `.agents/skills/ask-herdr/SKILL.md`.

Treat the repository-local `bin/ask-herdr` executable and the exact schema
documents advertised by `machine describe --json` as executable authority.
The current developer preview is source-only, supports macOS with Python 3.10
or later, and exposes no Project-binding or discovery workflow.

Keep a bound request's Project root, Authority UUID, and complete JSON outside
agent/model context. Operate on an owner-prepared request by canonical absolute
file path and interpret only the path-free Machine Run outcome. Launcher
profiles in discovery are disabled metadata, not provider authority.

Resolve the exact Python executable before invoking the env-shebang launcher
and verify that it is Python 3.10 or later. Follow any more specific host or
repository executable policy. If resolution is ambiguous, stop rather than
installing software or changing shell or global configuration.

## Herdr command authority

`query.status` does not invoke Herdr. Before designing, reviewing,
implementing, documenting, or executing any separate Herdr CLI or socket-API
command, read and follow `skills/herdr-command-authority/SKILL.md`.

Repository examples and prior evidence are not Herdr command authority. Use
the exact target host's installed release-matched skill and schema, then
reconcile new or unknown commands with the latest official Herdr documentation.
Direct live Herdr control remains separately approval- and environment-gated.
