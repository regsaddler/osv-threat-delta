# Threat model

## Protected properties

1. A report is bound to the exact lockfile bytes that were scanned.
2. Findings can be regenerated from the retained raw OSV response.
3. A delta cannot silently omit a bound predecessor's finding.
4. Runtime evidence cannot be written into a Git worktree.
5. The scanner cannot authorize or perform remediation.

## Considered failure modes

- DNS answers containing loopback, private, link-local, reserved, or otherwise
  non-public addresses.
- Redirects, ambient proxy settings, compressed response expansion, oversized
  responses, malformed JSON, duplicate findings, and response cardinality
  mismatches.
- Symlink substitution, concurrent writers, corrupted predecessor state,
  altered normalized findings, altered report counts, and forged quiet deltas.

## Outside scope

- Compromise of the local operating system or Python interpreter.
- Compromise of OSV or a certificate authority.
- Runtime reachability and exploitability analysis.
- Ecosystems other than PyPI.
- Windows support; the current state-lock and directory-safety design requires
  POSIX file-descriptor and `fcntl` semantics.
