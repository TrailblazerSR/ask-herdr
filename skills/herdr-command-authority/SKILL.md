---
name: herdr-command-authority
description: Verify Herdr CLI and socket commands against the installed release-matched skill, installed protocol schema, and current official Herdr documentation. Use before designing, reviewing, implementing, documenting, or executing a Herdr command, especially when a command is new, unknown, copied from history, or differs across Herdr releases.
---

# Herdr Command Authority

Use this workflow to prevent stale, invented, or cross-version Herdr commands.
Do not treat repository examples or remembered syntax as executable authority.

## Establish the local runtime contract

Keep each host separate. On the exact host where a command would run, identify
the installed binary and collect only read-only authority evidence:

```bash
command -v herdr
herdr --version
herdr --skill
herdr --help
herdr api schema --json
```

The installed `herdr --skill` output is the release-matched operating guide.
The installed schema is the socket-contract authority. Do not replace either
with syntax copied from a different release.

For a known command, also inspect the relevant installed command group. Run the
group without a nested subcommand, for example `herdr pane` or `herdr agent`.
Do not run bare `herdr`, because it launches or attaches the TUI. Do not probe a
mutating nested command by omitting arguments; some create commands are valid
with defaults and will execute.

## Resolve an unknown or new command

When a required capability is absent, unfamiliar, or differs from repository
history, read `references/official-sources.md` completely and consult the
latest relevant page on the official Herdr site.

Then reconcile the web documentation with all of these local facts:

1. the installed `herdr --version`;
2. the installed release-matched `herdr --skill`;
3. the relevant installed command-group output; and
4. `herdr api schema --json` for socket methods and payloads.

If the official site documents a command that the installed release does not
expose, record a **docs/runtime mismatch**. Do not execute, encode, or teach that
command as locally available. Stop before mutation and report whether the safe
next step is a version-matched alternative, an explicitly approved Herdr
upgrade, or a design hold.

Preview documentation is capability discovery only unless the installed binary
is itself a preview build. Stable documentation does not override an older
installed release.

## Apply the Ask-Herdr boundary

The public `query.status` route does not invoke Herdr and must not acquire a
Herdr dependency merely because direct Herdr syntax has been verified. If a
future Ask-Herdr capability introduces a Herdr command, treat its installed
version, schema version, protocol, exact argv, and nonmutation or isolated-test
boundary as a reviewed contract. A version change requires corresponding fake,
schema, and focused regression updates before any live mutation.

Command verification never activates a Machine Run operation, provider call,
or external effect.

## Respect the live-control boundary

For an agent directly inspecting or controlling a Herdr-managed session, first
require:

```bash
test "${HERDR_ENV:-}" = 1
```

If `HERDR_ENV=1` is absent, do not inspect or control the focused live session.
Read-only binary/version/skill/schema discovery for source work is allowed, as
are repository fakes and isolated named test sessions explicitly authorized by
the task.

Prefer CLI wrappers over raw socket requests. Use the raw socket API only when
the official socket guide and installed schema show that the required behavior
has no suitable CLI wrapper.

## Retain verification evidence

For a new or changed command, record the host, binary path, installed version,
relevant official URL, installed skill/schema check, exact argv, and nonmutation
or isolated-test boundary. Clearly separate documentation evidence from an
actually executed local smoke.
