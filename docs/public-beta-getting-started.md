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

## Prepare the checkout

This developer preview supports macOS and Python 3.10 or later. Resolve the
exact `python3` executable before using the env-shebang launcher and follow any
more specific host policy. Do not install software or change shell or global
configuration merely to make an ambiguous interpreter resolve.

From the repository root, inspect the active contract:

```text
bin/ask-herdr machine describe --json
```

Read `features`, `schema_documents`, and `exit_classes`. Retrieve the exact
request and outcome schemas advertised by that same response:

```text
bin/ask-herdr machine schema --id EXACT_ADVERTISED_ID
```

Do not copy stale schema IDs or selector fields from another checkout.

## Use from Codex or Claude Code

Codex-compatible agents load `.agents/skills/ask-herdr/SKILL.md`. Claude Code
loads `.claude/skills/ask-herdr/SKILL.md`, which points to the same canonical
workflow. Start the agent from the repository so project instructions and
skills are discoverable.

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

Protect the file with mode `0600`. Do not paste it or the output of
`machine validate` into an issue, chat, or provider prompt; validation output
may contain the private Project root.

## Run the status read

Use the canonical absolute request path:

```text
bin/ask-herdr machine run --request /canonical/absolute/private-request.json
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
- There is no Project-binding/bootstrap workflow, installed package, hosted
  service, human facade, provider-backed operation, deployment, or remote
  execution surface.
