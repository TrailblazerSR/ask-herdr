---
name: herdr-command-authority
description: Verify Herdr CLI and socket commands against the installed release-matched skill, installed protocol schema, and current official Herdr documentation. Use before designing, reviewing, implementing, documenting, or executing a Herdr command, especially when a command is new, unknown, copied from history, or differs across Herdr releases.
---

# Herdr Command Authority

Use this workflow to prevent stale, invented, or cross-version Herdr commands.
Do not treat repository examples or remembered syntax as executable authority.

## Establish the local runtime contract

Keep each host separate. On the exact host where a command would run, identify
the installed binary with the host-native resolver:

```bash
command -v herdr
```

```powershell
(Get-Command herdr -ErrorAction Stop).Source
```

Retain the resolved absolute path, then use that exact executable to collect
only read-only authority evidence: `--version`, `--skill`, `--help`, and
`api schema --json`. Do not switch back to an unresolved command name after
resolution.

The installed `herdr --skill` output is the release-matched operating guide.
The installed schema is the socket-contract authority. Do not replace either
with syntax copied from a different release.

For a known command, also inspect the relevant installed command group through
the same resolved binary, for example the `pane` or `agent` group. Do not run
the binary without arguments, because it launches or attaches the TUI. Do not
probe a mutating nested command by omitting arguments; some create commands are
valid with defaults and will execute.

## Resolve an unknown or new command

When a required capability is absent, unfamiliar, or differs from repository
history, read `references/official-sources.md` completely and consult the
latest relevant page on the official Herdr site. For a Windows host, also read
the current [official Windows support page](https://herdr.dev/docs/windows-beta/)
before assuming a Unix-only session, handoff, remote-target, or clipboard
behavior exists.

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

## Apply the project runtime pin

The legacy `bin/ask-herdr-pipeline` runner owns an exact reviewed Herdr version,
schema version, and protocol in its preflight constants. Read those constants;
do not duplicate their current numeric values in this skill. A version change
is a contract change and requires, before any live mutation:

- an updated version pin;
- an updated fake and focused preflight regression;
- validation of every constructed Herdr command against the new installed
  release skill and schema; and
- a fresh provider-free smoke in an isolated named test session.

Do not activate a public Machine Run, provider call, or external effect merely
because command syntax has been verified.

## Respect the live-control boundary

For an agent directly inspecting or controlling a Herdr-managed session, first
require `HERDR_ENV=1` through the host-native environment:

```bash
test "${HERDR_ENV:-}" = 1
```

```powershell
if ($env:HERDR_ENV -ne '1') { throw 'HERDR_ENV is not active' }
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
