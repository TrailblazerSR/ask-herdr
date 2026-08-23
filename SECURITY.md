# Security policy

## Sensitive Project data

An Ask-Herdr request can contain a canonical Project root and Authority UUID.
Treat the complete request and `machine validate` output as private. Do not
attach them to a public issue, pull request, discussion, chat, or provider
prompt. Use synthetic placeholders when demonstrating a problem.

The public `query.status` outcome is designed to be path-free, but review it
before sharing when investigating a suspected privacy defect.

## Reporting a vulnerability

Use GitHub private vulnerability reporting when it is enabled for the public
repository. If it is unavailable, ask the repository owner for a private
reporting channel without including vulnerability details in the public
request. Do not open a public issue containing secrets, Project identity,
private paths, exploit details, or provider credentials.

Include the affected commit, macOS and Python versions, the public diagnostic
code or typed outcome, and a reproduction that uses synthetic data. Maintainers
will acknowledge and prioritize reports on a best-effort basis; this developer
preview has no response-time guarantee.

## Scope

The current supported surface is the local, provider-free `query.status`
interface. Provider execution, live Herdr control, Project bootstrap, hosted
services, deployment, and remote/HPC execution are not part of this preview.
