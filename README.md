# ci-security-gate

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/)

> **Reusable security workflow for the entire portfolio.**  
> One definition, one badge, used by every repository.

---

<!-- execution-capture -->
## What it does

`ci-security-gate` is a **GitHub reusable workflow** that runs three independent security checks on any repository in the portfolio and produces a consolidated Markdown report in the GitHub Step Summary:

| Check | Tool | What it catches |
|-------|------|------------------|
| Secret Scanning | Custom Python script | Hardcoded API keys, passwords, tokens (entropy + regex) |
| Dependency Audit | `pip-audit` | Known CVEs in Python dependencies |
| Dockerfile Lint | Custom Python script | Root user, `:latest` tag, secrets in ENV, pipe-to-shell installs |

---

## Use it in 3 lines

Create `.github/workflows/security.yml` in **your** repo and paste:

```yaml
jobs:
  security:
    uses: vincent-p-essy/ci-security-gate/.github/workflows/gate.yml@main
    with:
      python_project: true
```

That's it. See [`examples/usage.yml`](examples/usage.yml) for the full file ready to copy.

---

## Available inputs

| Input | Type | Default | Description |
|-------|------|---------|-------------|
| `python_project` | boolean | `true` | Enable pip-audit (disable for non-Python repos) |
| `dockerfile_path` | string | `'Dockerfile'` | Path to the Dockerfile to lint |
| `fail_on_warn` | boolean | `false` | Treat warnings as failures (blocks merges) |

### Output

| Output | Description |
|--------|-------------|
| `security_score` | Overall result: `PASS`, `WARN` or `FAIL` |

---

## How each check works

### Secret Scanning (`scripts/check_secrets.py`)

- Recursively walks all text files, skipping `.git/`, `node_modules/`, `__pycache__/`, `.venv/`, and binary files.
- Detects secrets via:
  - **Shannon entropy** > 4.5 on tokens longer than 20 characters that match a high-entropy charset (base64-like).
  - **Regex patterns** for `api_key`, `secret`, `password`, `token`, `credential` assignments in source code.
  - **Dotenv variables** (`SECRET=`, `PASSWORD=`, …) in `.env` files.
  - **PEM private keys** (`-----BEGIN RSA/EC/OPENSSH PRIVATE KEY-----`).
- Outputs `secrets-report.json`; exits 1 on critical findings.

### Dependency Audit (`pip-audit`)

- Runs `pip-audit --format json -r requirements.txt` if `requirements.txt` exists.
- Uploads the JSON report as a build artifact (`pip-audit-report.json`).
- Skipped automatically when `python_project: false`.

### Dockerfile Lint (`scripts/check_dockerfile.py`)

| Rule | Severity | Condition |
|------|----------|-----------|
| `non_root_user` | WARN/FAIL | No `USER` instruction, or last `USER` is root |
| `no_latest_tag` | WARN | `FROM image:latest` (non-reproducible) |
| `no_secrets_in_env` | FAIL | `ENV SECRET=`, `ENV TOKEN=`, etc. |
| `no_pipe_install` | FAIL | `curl … | bash` or `wget … | sh` |

- Outputs `dockerfile-report.json`; exits 1 on any FAIL.

### Security Score (`scripts/score.py`)

Aggregates the three reports and writes a Markdown table to `$GITHUB_STEP_SUMMARY`:

```
## 🛡️ Security Gate Report

| Check             | Status      | Details                        |
|-------------------|-------------|--------------------------------|
| Secret Scanning   | ✅ PASS     | 0 findings (42 files scanned)  |
| Dependency Audit  | ⚠️ WARN     | 2 vulnerabilities (1 fixable)  |
| Dockerfile Lint   | ✅ PASS     | All checks passed              |

**Overall: ⚠️ WARN**
```

The overall score is the **worst** status across all checks.  
With `fail_on_warn: true`, a `WARN` is promoted to `FAIL`.

---

## Ecosystem integration

Every repository in the portfolio includes:

```yaml
# .github/workflows/security.yml
jobs:
  security:
    uses: vincent-p-essy/ci-security-gate/.github/workflows/gate.yml@main
```

The green badge on each repo links back here:

```markdown
```

This creates a single source of truth: update the gate here, all repos benefit immediately on their next push.

---

## Roadmap

- [ ] **SAST** — integrate [Bandit](https://bandit.readthedocs.io/) for Python static analysis
- [ ] **Licence scan** — detect GPL/AGPL dependencies incompatible with proprietary code
- [ ] **SBOM generation** — produce a Software Bill of Materials (CycloneDX format)
- [ ] **Container image scan** — Trivy / Grype integration for built images
- [ ] **IaC lint** — Checkov for Terraform / Kubernetes manifests

---

## Author

**Vincent Plessy** — [vincent.plessy12@gmail.com](mailto:vincent.plessy12@gmail.com)

Feel free to open issues or PRs to extend the gate to new check types.
