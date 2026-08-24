---
name: ask-herdr
description: Use the repository-local Ask-Herdr machine interface for contract discovery, private-request validation, or provider-free query.status reads. Trigger when the user asks to use Ask-Herdr or inspect status through it; use the separate Herdr command-authority workflow for direct Herdr session control.
---

# Ask-Herdr

Use a runtime-first workflow. `bin/ask-herdr` and the schema documents it
advertises are the command and contract authority; prose explains boundaries
but does not replace discovery.

## Establish the local boundary

1. Work from the repository root containing `bin/ask-herdr`.
2. Read the [platform-support contract](../../../docs/platform-support.md),
   identify the exact host profile, and select an approved Python interpreter.
   Pass `bin/ask-herdr` to that interpreter explicitly; direct execution is a
   POSIX convenience, not the portable launch contract. Apply any host-local
   executable guard in `AGENTS.md`. If the interpreter cannot be resolved
   without guessing or changing host configuration, stop and report it.
3. Read the [source quick start](../../../docs/public-beta-getting-started.md)
   for access and privacy rules. Read the
   [full public contract](../../../docs/public-beta-query-status.md) when
   constructing or interpreting a request or outcome.
4. Use `bin/ask-herdr` for the Machine interface. The similarly named
   `bin/ask-herdr-pipeline` is a legacy, stub-only Herdr prototype and is not
   the `query.status` route.

The boundary is established only when the repository, approved interpreter,
host profile, and applicable public contract are identified.

## Discover the current contract

Run static discovery first. Substitute the exact approved interpreter path for
the metavariable below; do not execute `APPROVED_PYTHON` literally:

```text
APPROVED_PYTHON bin/ask-herdr machine describe --json
```

Read `runtime_platform`, `features`, `schema_documents`, and `exit_classes`
from that response. Continue to validation or Machine Run only when discovery
reports the full execution tier and the corresponding feature as active.
Native Windows is currently contract-only: discovery and schema retrieval are
available, while validation and Machine Run are held pending a versioned
Windows path, ACL, and store protocol.

Treat `features.machine_run=false` as an unavailable execution surface. Treat
launcher profiles as disabled registry metadata unless a separately
authorized implementation explicitly proves otherwise.

Retrieve every request or outcome schema needed for the task by using the
exact ID advertised in the same discovery response:

```text
APPROVED_PYTHON bin/ask-herdr machine schema --id EXACT_ADVERTISED_ID
```

Do not cache version numbers, schema IDs, selector fields, exit tables, or
provider capabilities in prompts. Discovery is complete only after the exact
advertised schema documents needed for the request and result have been
retrieved from the same checkout.

## Preserve private Project binding

A bound request contains private Project identity data. On a full POSIX host,
for an agent-mediated status read:

- Have the Project owner prepare the request file outside the repository and
  provide only its canonical absolute file path. The path must not contain a
  symlinked component. Protect it with mode `0600`; this is a POSIX control,
  not a native-Windows ACL recipe.
- Operate on that path without reading, printing, copying, logging, hashing, or
  embedding the request contents in agent/model context.
- Use a file path, not `--request -`; stdin would place private request content
  in the agent-visible command channel.
- Keep `machine validate` output out of agent/model context because the v1
  validation result may contain the private Project root. An owner may run
  validation locally, or an agent may validate only a sanitized placeholder
  request whose Project data is non-sensitive.
- Never infer or discover a binding. A matching Project root and Authority UUID
  come from the Project owner through a private channel.

The privacy step is complete only when neither the request JSON nor validation
output has entered the conversation or tool output visible to the model.

## Run and interpret `query.status`

After discovery reports an active Machine Run surface, invoke only the
owner-prepared private file:

```text
APPROVED_PYTHON bin/ask-herdr machine run --request /canonical/absolute/private-request.json
```

Interpret the process result as follows:

1. If stdout contains the one-line public JSON envelope, interpret it using
   the advertised outcome and result schemas even when the process exit is
   nonzero.
2. Use the current discovery response's `exit_classes`; do not reduce every
   nonzero exit to a shell failure.
3. Treat unavailable, busy, stale-cursor, quarantined, and reconciliation
   outcomes as their typed states. None proves that a Project, Lane, key, or
   operation is absent.
4. Treat bounded stderr without a JSON envelope as a capture, parse,
   trusted-header, unsupported-route, or usage failure. Report its public
   diagnostic code without exposing private request material.
5. Do not retry automatically. Preserve the returned operation and request
   correlation fields and report the action needed from the owner.

The status read is complete when one typed public outcome is reported with its
exit class and no private path, request content, provider call, Herdr call,
network action, Project mutation, or remote/HPC effect.

## Route wider requests correctly

Only the operations reported active by current discovery may execute. Report a
held capability rather than routing it through a listed provider profile.

For direct Herdr CLI or socket work, read and follow the
[Herdr command-authority skill](../../../skills/herdr-command-authority/SKILL.md)
and re-establish authority on the exact target host. Direct live Herdr control,
provider use, remote/HPC effects, installation, publication, and deployment
remain separately approval-gated.
