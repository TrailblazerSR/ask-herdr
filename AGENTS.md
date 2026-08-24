# Ask-Herdr Agent Instructions

## Ask-Herdr machine interface

For Ask-Herdr contract discovery, request validation, or `query.status`, read
and follow `.agents/skills/ask-herdr/SKILL.md`.

Treat the repository-local `bin/ask-herdr` executable and the exact schema
documents advertised by `machine describe --json` as executable authority.
The current developer preview is Git-installable and requires Python 3.10 or
later. Repository tasks still use the source wrapper so behavior and schemas
are bound to the exact checkout under review. macOS and Linux provide the full
local `query.status` path, WSL follows the Linux profile, and native Windows is
limited to static contract discovery and schema retrieval. Read
`docs/platform-support.md` and the discovered `runtime_platform` object before
selecting a route. The preview exposes no Project-binding or discovery
workflow.

Keep a bound request's Project root, Authority UUID, and complete JSON outside
agent/model context. Operate on an owner-prepared request by canonical absolute
file path and interpret only the path-free Machine Run outcome. Launcher
profiles in discovery are disabled metadata, not provider authority.

Resolve and approve the exact Python executable, verify that it is Python 3.10
or later, and pass `bin/ask-herdr` to it as a script argument. Direct execution
through the env shebang is a POSIX convenience, not the cross-platform launch
contract. Follow any more specific host or repository executable policy. If
resolution is ambiguous, stop rather than installing software or changing
shell or global configuration. Do not attempt Machine Validation or Machine
Run when discovery reports that feature inactive.

## Herdr command authority

`query.status` does not invoke Herdr. Before designing, reviewing,
implementing, documenting, or executing any separate Herdr CLI or socket-API
command, read and follow `skills/herdr-command-authority/SKILL.md`.

Repository examples and prior evidence are not Herdr command authority. Use
the exact target host's installed release-matched skill and schema, then
reconcile new or unknown commands with the latest official Herdr documentation.
Direct live Herdr control remains separately approval- and environment-gated.
