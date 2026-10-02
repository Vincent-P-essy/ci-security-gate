# Execution record

Dockerfile checks executed on two included demonstration files. Exit 1 on the deliberately unsafe fixture is the expected rejection.

- `python scripts/check_dockerfile.py --dockerfile docs/examples/good.Dockerfile` — exit 0 (expected 0).
- `python scripts/check_dockerfile.py --dockerfile docs/examples/bad.Dockerfile` — exit 1 (expected 1).

The terminal image renders recorded command output. [Full transcript](screenshots/execution.txt).

External integrations and production deployment are not covered by these fixtures.
