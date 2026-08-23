# Official Herdr Sources

Consult only official Herdr sources for command and protocol discovery:

- Documentation home and agent-routing note:
  <https://herdr.dev/docs/>
- CLI reference:
  <https://herdr.dev/docs/cli-reference/>
- Socket API and installed-schema workflow:
  <https://herdr.dev/docs/socket-api/>
- Release-matched agent skill guidance:
  <https://herdr.dev/docs/agent-skill/>
- Agent lifecycle and detection reference:
  <https://herdr.dev/docs/agents/>
- Preview channel documentation:
  <https://herdr.dev/docs/preview/>
- Agent setup and troubleshooting guide:
  <https://herdr.dev/agent-guide.md>

## Authority order

Use the installed binary to decide what can execute locally. Use the current
official site to discover and understand capabilities. A newer web example is
not evidence that an older local binary supports that syntax.

For an unknown command:

1. refresh the relevant official page;
2. compare it with `herdr --version` and `herdr --skill` on the target host;
3. confirm the relevant local command group and, for socket work,
   `herdr api schema --json`;
4. stop before mutation if those sources disagree; and
5. retain the URL, installed version, exact argv, and observed output in the
   change evidence.

Do not cache an entire web page as permanent command authority. This reference
registry is intentionally small so the latest official documentation is read
when a new or unknown command is encountered.
