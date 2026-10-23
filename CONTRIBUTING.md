# Contributing

Contributions are welcome. Keep changes narrow and preserve the scanner's
fail-closed boundaries.

1. Create a focused branch.
2. Add or update a deterministic test for every behavior change.
3. Run `python -m unittest discover -s tests -v`.
4. Run `python -m compileall -q src tests`.
5. Explain any change to the report schema or authority boundary in the pull
   request.

Network tests must use fixtures or fakes by default. Live OSV calls belong in
an explicitly requested smoke test, not the unit suite.
