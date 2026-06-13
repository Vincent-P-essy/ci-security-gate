#!/usr/bin/env python3
"""Aggregate results from all security checks and write a GitHub Step Summary."""

import json
import os
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

STATUS_ICON = {
    'PASS': '✅ PASS',
    'WARN': '⚠️ WARN',
    'FAIL': '❌ FAIL',
    'SKIP': '⏭️ SKIP',
    'UNKNOWN': '❓ UNKNOWN',
}


def load_json(path: str) -> dict | None:
    p = Path(path)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            return None
    return None


def severity(status: str) -> int:
    """Return a numeric severity so we can compute the worst overall status."""
    return {'PASS': 0, 'SKIP': 0, 'WARN': 1, 'FAIL': 2, 'UNKNOWN': 1}.get(status, 1)


# ---------------------------------------------------------------------------
# Evaluate each check
# ---------------------------------------------------------------------------

def eval_secrets() -> tuple[str, str]:
    """Return (status, details) for secret scanning."""
    env_count = os.environ.get('SECRETS_FINDINGS', '')
    report = load_json('secrets-report.json')

    if report is not None:
        findings = report.get('findings', [])
        count = len(findings)
        critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        if critical > 0:
            return 'FAIL', f'{critical} critical finding(s), {count} total'
        if count > 0:
            return 'WARN', f'{count} finding(s) (non-critical)'
        return 'PASS', f'0 findings ({report.get("files_scanned", "?")} files scanned)'

    # Fallback to environment variable set by the workflow
    if env_count.isdigit():
        count = int(env_count)
        if count == 0:
            return 'PASS', '0 findings'
        return 'WARN', f'{count} finding(s)'

    return 'UNKNOWN', 'Report not available'


def eval_pip_audit() -> tuple[str, str]:
    """Return (status, details) for pip-audit."""
    env_count = os.environ.get('VULN_COUNT', '')
    report = load_json('pip-audit-report.json')

    if report is not None:
        if report.get('skipped'):
            return 'SKIP', 'No requirements.txt found'
        deps = report.get('dependencies', [])
        vulns = [(d['name'], v) for d in deps for v in d.get('vulns', [])]
        if not vulns:
            return 'PASS', f'0 vulnerabilities ({len(deps)} packages audited)'
        # Bucket by severity
        critical = sum(1 for _, v in vulns if v.get('fix_versions'))
        return 'WARN', f'{len(vulns)} vulnerabilities ({critical} fixable)'

    if env_count.isdigit():
        count = int(env_count)
        return ('PASS' if count == 0 else 'WARN'), f'{count} vulnerabilities'

    # python_project=false means pip-audit was skipped intentionally
    python_project = os.environ.get('INPUT_PYTHON_PROJECT', 'true').lower()
    if python_project == 'false':
        return 'SKIP', 'python_project=false'

    return 'UNKNOWN', 'Report not available'


def eval_dockerfile() -> tuple[str, str]:
    """Return (status, details) for Dockerfile linting."""
    env_result = os.environ.get('DOCKERFILE_RESULT', '')
    report = load_json('dockerfile-report.json')

    if report is not None:
        result = report.get('result', 'UNKNOWN')
        if result == 'SKIP':
            return 'SKIP', 'Dockerfile not found'
        checks = report.get('checks', [])
        failed = [c['name'] for c in checks if c['status'] == 'FAIL']
        warned = [c['name'] for c in checks if c['status'] == 'WARN']
        if failed:
            return 'FAIL', f'Failed checks: {", ".join(failed)}'
        if warned:
            return 'WARN', f'Warnings: {", ".join(warned)}'
        return 'PASS', 'All checks passed'

    if env_result in ('PASS', 'WARN', 'FAIL', 'SKIP'):
        return env_result, env_result.lower()

    return 'UNKNOWN', 'Report not available'


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    secrets_status, secrets_detail = eval_secrets()
    audit_status, audit_detail = eval_pip_audit()
    docker_status, docker_detail = eval_dockerfile()

    checks = [
        ('Secret Scanning', secrets_status, secrets_detail),
        ('Dependency Audit', audit_status, audit_detail),
        ('Dockerfile Lint', docker_status, docker_detail),
    ]

    worst = max(severity(s) for _, s, _ in checks)
    overall = {0: 'PASS', 1: 'WARN', 2: 'FAIL'}.get(worst, 'FAIL')

    fail_on_warn = os.environ.get('FAIL_ON_WARN', 'false').lower() == 'true'
    if fail_on_warn and overall == 'WARN':
        overall = 'FAIL'

    # ----- Build Markdown summary -----
    rows = '\n'.join(
        f'| {name} | {STATUS_ICON.get(status, status)} | {detail} |'
        for name, status, detail in checks
    )
    summary = f"""## \U0001f6e1️ Security Gate Report

| Check | Status | Details |
|-------|--------|----------|
{rows}

**Overall: {STATUS_ICON.get(overall, overall)}**

> Generated by [ci-security-gate](https://github.com/vincent-p-essy/ci-security-gate)
"""

    # Write to GitHub Step Summary
    step_summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if step_summary:
        with open(step_summary, 'a') as fh:
            fh.write(summary)

    print(summary)

    # Set output
    github_output = os.environ.get('GITHUB_OUTPUT')
    if github_output:
        with open(github_output, 'a') as fh:
            fh.write(f'result={overall}\n')

    print(f'\nSecurity gate result: {overall}', file=sys.stderr)
    return 1 if overall == 'FAIL' else 0


if __name__ == '__main__':
    sys.exit(main())
