# `query.status` developer-preview contract

## Contract authority

`bin/ask-herdr machine describe --json` and the schema documents retrievable
by their advertised IDs are the executable contract authority. This document
summarizes behavior and privacy boundaries; when prose and the same checkout's
schemas differ, stop and treat the mismatch as a release defect.

Machine Run accepts only `query.status`. The v1 `machine validate` route is
separate and may expose private Project identity in its validation result.

## Availability

The executable route accepts a bound `ask_herdr.request.v1` request with one of
four closed selector forms: Project, Lane, Consultant Key, or operation UUID.
Only `observation.mode=immediate` and `advisory=none` execute a metadata read.
Wait observation and summary/full advisory requests return typed unavailable
outcomes without inspecting the Project.

## Public outcome envelope

Machine Run emits `ask_herdr.outcome.v2`. Its closed members are:

```text
schema
operation
operation_id
request_digest
project
status
outcome_kind
exit_class
retry
policy
result
diagnostics
evidence_refs
advisory
timestamps
```

`operation` is always `query.status`. Except for `request_invalid`, `project`
is a path-free reference containing only its schema and Authority UUID. For
`request_invalid`, `project` is null. `request_digest` is envelope correlation,
not operation authority, Evidence authority, or a Metadata Cursor.

| Outcome kind | Status | Exit | Result read status |
| --- | --- | ---: | --- |
| `status_observed` | `succeeded` | `0` | `active` or `absent` |
| `status_busy` | `in_progress` | `40` | `busy` |
| `status_reconciliation_required` | `reconciliation_required` | `40` | `reconciliation_required` |
| `cursor_stale` | `failed` | `40` | `cursor_stale` |
| `status_quarantined` | `quarantined` | `50` | `quarantined` |
| `status_capability_unavailable` | `failed` | `20` | `unavailable` |
| `request_invalid` | `failed` | `64` | null |
| `request_not_currently_admissible` | `failed` | `20` | null |
| `request_reconciliation_required` | `reconciliation_required` | `40` | null |
| `request_quarantined` | `quarantined` | `50` | null |

No unavailable capability is represented as absence or success.

## Status result

`ask_herdr.query.status.result.v1` has exactly these members:

```text
schema
selector
read_status
detail_code
normalized_read_contract_digest
project_read_epoch
entries
next_cursor
operation_metadata
```

`read_status` is `active`, `absent`, `busy`, `reconciliation_required`,
`quarantined`, `cursor_stale`, or `unavailable`.

- Active results carry a normalized read-contract digest and Project Read
  Epoch. Project, Lane, and Key pages may carry a cursor.
- Active operation results carry immutable operation metadata and never a
  cursor. They carry one Lane head only when their association is bound.
- Authenticated absence carries no entries, cursor, or operation metadata. An
  epoch is present only when the negative projection was authenticated inside
  an otherwise active epoch.
- Reconciliation may carry only complete authenticated epoch data. An
  incomplete store or clock observation claims neither absence nor data.
- Busy, quarantined, and stale-cursor results carry no epoch, entries, cursor,
  or operation metadata.
- Unavailable results carry no normalized digest, epoch, entries, cursor, or
  operation metadata.

Retrieve the exact selector, entry, epoch, operation-metadata, detail-code,
presence, and cardinality rules from the advertised request and result schemas.

## Privacy and effects

The request contains private Project identity data. A coding agent operates on
an owner-prepared canonical absolute request path and interprets only the
path-free outcome. Request JSON and v1 validation output remain outside model
context.

The route reads local Authority Store, Lane Index, and Topology Ledger metadata
through observation-only interfaces. It performs no Project mutation and
invokes no provider, Herdr command, network service, or remote/HPC resource.
The public envelope excludes canonical paths, filesystem identity, raw durable
records, private Authority record digests, Evidence/result bytes, provider
identifiers, credentials, prompts, provider output, private exceptions, and
Herdr session state.

## Platform and compatibility

This source preview supports macOS and Python 3.10 or later. Its durable-store
read closure contains Darwin-specific filesystem primitives. Other operating
systems are unsupported, even if static schema files can be read there.

Direct Herdr work is outside this route. For a new or unknown Herdr command,
follow `skills/herdr-command-authority/SKILL.md`, the installed release-matched
skill and schema, and the latest official documentation at
<https://herdr.dev/docs/>. A documentation/runtime mismatch stops before any
mutation.
