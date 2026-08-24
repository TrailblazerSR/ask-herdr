# `query.status` developer-preview quick start

## Scope

Ask-Herdr exposes one local, provider-free Machine Run operation:
`query.status`. It reads authenticated metadata for an already-bound Project.
It does not create or discover a Project binding, invoke Herdr or a provider,
use the network, mutate the Project, or contact remote/HPC resources.

A real read requires two matching values supplied privately by the Project
owner:

- the canonical absolute Project root; and
- the bound Project Authority UUID.

Repository access alone is insufficient for a successful status observation.

## Install or prepare a checkout

This developer preview requires Python 3.10 or later. macOS and Linux provide
the full local route, WSL follows the Linux/POSIX profile, and native Windows
provides static contract discovery and schema retrieval only. Read the
[platform-support matrix](platform-support.md), resolve the exact approved
Python executable, and follow any more specific host policy. Do not install
software or change shell or global configuration merely to make an ambiguous
interpreter resolve.

Install the current public `main` branch as an isolated application with one of
these commands:

```text
pipx install https://github.com/TrailblazerSR/ask-herdr/archive/refs/heads/main.zip
```

```text
uv tool install "ask-herdr @ https://github.com/TrailblazerSR/ask-herdr/archive/refs/heads/main.zip"
```

Then inspect the active contract from any directory:

```text
ask-herdr machine describe --json
```

For a source-checkout fallback, run the repository wrapper with the approved
interpreter:

POSIX shell (replace the interpreter path):

```text
/absolute/path/to/python3 bin/ask-herdr machine describe --json
```

PowerShell (replace the interpreter path):

```text
& 'C:\Path\To\python.exe' 'bin/ask-herdr' machine describe --json
```

Read `runtime_platform`, `features`, `schema_documents`, and `exit_classes`.
Continue to validation or Machine Run only when discovery reports
`execution_tier=full` and the corresponding feature as active. Retrieve the
exact request and outcome schemas advertised by that same response:

```text
ask-herdr machine schema --id EXACT_ADVERTISED_ID
```

Do not copy stale schema IDs or selector fields from another checkout.

## Use from Codex or Claude Code

Codex-compatible agents load `.agents/skills/ask-herdr/SKILL.md`. Claude Code
loads `.claude/skills/ask-herdr/SKILL.md`, which points to the same canonical
workflow. Start the agent from the repository so project instructions and
skills are discoverable. The isolated CLI install does not write to global
agent configuration.

A three-command checkout setup provides both the installed CLI and the
repository-local skills:

```text
git clone https://github.com/TrailblazerSR/ask-herdr.git
cd ask-herdr
pipx install .
```

`uv tool install .` is an equivalent final command.

For an agent-mediated read, prepare and protect the bound request yourself.
Give the agent only its canonical absolute path. The agent must not read,
print, copy, log, hash, or embed the request JSON, Project root, Authority UUID,
or v1 validation output in model context.

## Create a request

Create a private file outside the repository. Replace the example root and
Authority UUID with the matching owner-supplied values, and use a fresh
lowercase UUIDv4 for every `operation_id`.

```json
{
  "schema": "ask_herdr.request.v1",
  "operation": "query.status",
  "operation_id": "123e4567-e89b-42d3-a456-426614174000",
  "project": {
    "schema": "ask_herdr.project_binding.v1",
    "binding": "bound",
    "root": "/absolute/path/to/already-bound-project",
    "authority_id": "123e4567-e89b-42d3-a456-426614174002"
  },
  "authority_ref": null,
  "reason": {
    "schema": "ask_herdr.reason.v1",
    "action": "inspect"
  },
  "payload": {
    "schema": "ask_herdr.query.status.payload.v1",
    "selector": {
      "schema": "ask_herdr.query.status.selector.v1",
      "kind": "project"
    },
    "advisory": "none",
    "limit": 20,
    "cursor": null
  },
  "observation": {
    "schema": "ask_herdr.observation.v1",
    "mode": "immediate",
    "timeout_ms": null
  }
}
```

On macOS, Linux, or WSL, protect the file with mode `0600`. This is a POSIX
control, not a native-Windows ACL recipe. Do not paste the request or the
output of `machine validate` into an issue, chat, or provider prompt;
validation output may contain the private Project root. Native Windows
validation and Machine Run are held in this release.

## Run the status read

Use the canonical absolute request path:

```text
ask-herdr machine run --request /canonical/absolute/private-request.json
```

Agent-mediated execution must use a file path, not stdin. After capture,
strict parsing, trusted-header validation, and route selection succeed, the
command emits exactly one JSON line. Interpret it with the advertised outcome
and result schemas even when the process exit is nonzero.

| Exit | Route meaning |
| ---: | --- |
| `0` | Status observed: active or authenticated absent |
| `20` | Capability unavailable or request not currently admissible |
| `40` | Busy, reconciliation required, or stale cursor |
| `50` | Quarantined or ownership failure |
| `64` | Invalid request or unsupported command shape |

An unavailable or reconciliation result is never evidence that the selected
Project, Lane, Consultant Key, or operation is absent. Do not retry
automatically.

## Limitations

- Only `query.status` executes through Machine Run.
- Only `observation.mode=immediate` with `advisory=none` performs a read.
- Project, Lane, Consultant Key, and operation UUID selectors are supported;
  retrieve their exact forms from the advertised request schema.
- Full local execution is supported on macOS and Linux; WSL uses its Linux
  profile. Native Windows is contract-only until a versioned Windows path,
  ACL, and Project-store contract exists.
- There is no Project-binding/bootstrap workflow, package-registry release,
  hosted service, human facade, provider-backed operation, deployment, or
  remote execution surface.
