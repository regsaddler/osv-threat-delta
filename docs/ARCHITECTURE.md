# Architecture

OSV Threat Delta is intentionally small and one-directional:

```text
hash-pinned lockfile
        |
        v
 bounded parser -> exact PyPI package/version batch -> OSV.dev
        |                                            |
        |                                            v
        +-------------------------------------- raw response hash
                                                     |
                                                     v
                                      normalized findings + delta
                                                     |
                                                     v
                                content-bound report + verifier
```

The scanner has no remediation path. Its output is evidence for a later human
or policy decision, not permission to modify an environment.

## Trust boundaries

- **Lockfile:** must use the supported exact-pin and SHA-256 grammar.
- **Network:** the OSV hostname is fixed; proxies and redirects are disabled;
  every resolved address must be public; TLS still validates the hostname.
- **Response:** media type, encoding, size, result cardinality, identifiers,
  timestamps, and nested collection sizes are bounded.
- **State:** runtime evidence must live outside every Git worktree, uses private
  permissions, rejects symlink traversal, and is written atomically.
- **Verification:** normalized findings are regenerated from the retained raw
  response and compared with the current lock and bound predecessor.

## Supported lock grammar

The public release accepts a deliberately narrow subset commonly emitted by
`pip-compile --generate-hashes`:

```text
package-name==1.2.3 \
    --hash=sha256:<64 lowercase hex> \
    --hash=sha256:<64 lowercase hex>
```

Comments and blank lines are allowed. Editable requirements, URLs, ranges,
environment markers, includes, options, and unhashed pins are rejected rather
than interpreted loosely.
