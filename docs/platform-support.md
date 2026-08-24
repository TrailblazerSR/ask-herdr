# Platform support

Ask-Herdr is a source-only Python developer preview. Its provider-free
`query.status` path is native on macOS and Linux; WSL uses the Linux contract.
Native Windows currently exposes contract discovery and bundled schemas only.

Current `machine describe --json` output is the executable authority for the
checkout being used. Read its `runtime_platform`, `features`,
`schema_documents`, and `exit_classes` before choosing a command. Do not carry
version numbers, schema IDs, or capability flags forward from this document or
from an earlier run.

## Support matrix

| Host environment | Describe and schema | Validate | `query.status` Machine Run | Contract |
| --- | --- | --- | --- | --- |
| macOS | Supported | Supported | Supported | Native POSIX |
| Linux | Supported | Supported | Supported | Native POSIX |
| WSL | Supported | Supported | Supported | Linux/POSIX; use paths visible inside the WSL distribution |
| Native Windows | Supported | Held | Held | Contract-only; Windows path, ACL, and project-store behavior is not part of request v1 |
| Other Python hosts | Supported | Held | Held | Discovery-only; no storage backend is claimed |

Discovery schema `ask_herdr.describe.v3` reports a closed
`runtime_platform` object with the detected OS and path family, execution tier,
storage profile, supported operations, and limitations. A full host reports
`execution_tier=full` and lists `query.status`. Native Windows reports
`execution_tier=contract_only` and
`native_windows_project_store_unavailable`. An unrecognized host reports
`platform_storage_backend_unavailable`. On a held host, `machine validate` and
`machine run` stop with public diagnostic `runtime.platform_unsupported` and
exit `20`; they do not inspect a Project.

The frozen `ask_herdr.request.v1` Project-binding and private-store contract is
POSIX. Native Windows execution will require a separately versioned contract
for canonical Windows paths, ACL ownership, and durable-store identity. It is
not emulated by silently translating Windows paths into POSIX fields.

The Linux profile requires libc/kernel/filesystem support for
`renameat2(RENAME_NOREPLACE)` plus regular-file and directory `fsync`. Ubuntu
is the continuous-integration reference. If a Linux runtime or backing
filesystem cannot provide those guarantees, the store adapter fails closed;
it does not fall back to a check-then-rename or overwriting commit.

## Source launch

Use an approved Python interpreter and pass `bin/ask-herdr` as its script
argument. In the examples below, replace the interpreter path with the exact
approved executable for the host.

POSIX shells:

```text
/absolute/path/to/python3 bin/ask-herdr machine describe --json
/absolute/path/to/python3 bin/ask-herdr machine schema --id EXACT_ADVERTISED_ID
```

PowerShell:

```text
& 'C:\Path\To\python.exe' 'bin/ask-herdr' machine describe --json
& 'C:\Path\To\python.exe' 'bin/ask-herdr' machine schema --id EXACT_ADVERTISED_ID
```

Executing `bin/ask-herdr` directly is a POSIX convenience provided by its env
shebang, not the cross-platform launch contract. An agent or automation should
use the explicit-interpreter form so executable selection is visible and
reviewable.

## Private request handling

The privacy invariant is the same on every host: Project root, Authority UUID,
complete request JSON, and validation output stay outside agent/model context.
Only the canonical private request-file path enters an agent-mediated Machine
Run, and only the path-free public outcome may be interpreted.

On macOS, Linux, and WSL, create the request in a private owner-controlled
location, resolve every symlinked path component, and set mode `0600` before
use. `chmod 600` is a POSIX control, not a Windows instruction. Because native
Windows Machine Validation and Machine Run are held, this release does not
prescribe an equivalent Windows ACL recipe.

## Herdr is a separate boundary

The active `query.status` route does not invoke Herdr. Herdr itself distributes
stable builds for Linux, macOS, and Windows, with Windows-specific limitations
documented separately. Any direct Herdr command must be reconciled against the
exact host's installed release and the current official references:

- [Installation](https://herdr.dev/docs/install/)
- [Windows support](https://herdr.dev/docs/windows-beta/)
- [CLI reference](https://herdr.dev/docs/cli-reference/)

Use the repository's
[Herdr command-authority workflow](../skills/herdr-command-authority/SKILL.md)
before designing, documenting, or executing direct Herdr control.
