#!/usr/bin/env python3
"""Dockerfile linter: checks security best practices."""

import argparse
import json
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

class Check:
    """Result of a single Dockerfile check."""

    def __init__(self, name: str, status: str, message: str):
        self.name = name
        self.status = status  # PASS | WARN | FAIL
        self.message = message

    def to_dict(self) -> dict:
        return {'name': self.name, 'status': self.status, 'message': self.message}


def check_non_root_user(lines: list[str]) -> Check:
    """Ensure the image runs as a non-root user."""
    user_instructions = [
        l.strip() for l in lines
        if re.match(r'^USER\s+', l, re.IGNORECASE)
    ]
    if not user_instructions:
        return Check(
            'non_root_user',
            'WARN',
            'No USER instruction found; container will run as root by default.',
        )
    last_user = re.split(r'\s+', user_instructions[-1], maxsplit=1)[1].strip()
    if last_user.lower() in ('root', '0'):
        return Check(
            'non_root_user',
            'FAIL',
            f'Last USER instruction sets user to "{last_user}" (root).',
        )
    return Check('non_root_user', 'PASS', f'Container runs as user "{last_user}".')


def check_no_latest_tag(lines: list[str]) -> Check:
    """Warn when FROM uses the :latest tag."""
    offenders = []
    for line in lines:
        m = re.match(r'^FROM\s+(\S+)', line, re.IGNORECASE)
        if m:
            image = m.group(1)
            # Split away possible alias (AS name) and digest
            image_part = image.split('@')[0]
            tag = image_part.split(':')[1] if ':' in image_part else 'latest'
            if tag == 'latest':
                offenders.append(image)
    if offenders:
        return Check(
            'no_latest_tag',
            'WARN',
            f'FROM uses :latest tag (non-reproducible): {", ".join(offenders)}',
        )
    return Check('no_latest_tag', 'PASS', 'All FROM instructions use explicit tags.')


def check_no_secrets_in_env(lines: list[str]) -> Check:
    """Fail when ENV instructions expose secret-like variable names."""
    pattern = re.compile(
        r'^ENV\s+.*(SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|CREDENTIAL)',
        re.IGNORECASE,
    )
    offenders = [l.strip() for l in lines if pattern.match(l)]
    if offenders:
        return Check(
            'no_secrets_in_env',
            'FAIL',
            f'Secret-like variable(s) set via ENV: {offenders}',
        )
    return Check('no_secrets_in_env', 'PASS', 'No secrets detected in ENV instructions.')


def check_no_pipe_install(lines: list[str]) -> Check:
    """Fail on curl/wget piped directly to a shell interpreter."""
    pattern = re.compile(
        r'(curl|wget)\s+.*(\|\s*)(ba)?sh',
        re.IGNORECASE,
    )
    offenders = [l.strip() for l in lines if pattern.search(l)]
    if offenders:
        return Check(
            'no_pipe_install',
            'FAIL',
            f'Dangerous pipe-to-shell pattern detected: {offenders}',
        )
    return Check('no_pipe_install', 'PASS', 'No curl/wget pipe-to-shell patterns found.')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

CHECKS = [
    check_non_root_user,
    check_no_latest_tag,
    check_no_secrets_in_env,
    check_no_pipe_install,
]


def overall_result(checks: list[Check]) -> str:
    statuses = {c.status for c in checks}
    if 'FAIL' in statuses:
        return 'FAIL'
    if 'WARN' in statuses:
        return 'WARN'
    return 'PASS'


def main() -> int:
    parser = argparse.ArgumentParser(description='Lint a Dockerfile for security issues.')
    parser.add_argument('--dockerfile', default='Dockerfile', help='Path to the Dockerfile')
    parser.add_argument('--output', default='dockerfile-report.json', help='Output JSON file')
    args = parser.parse_args()

    dockerfile = Path(args.dockerfile)
    if not dockerfile.exists():
        print(f'[ERROR] Dockerfile not found: {dockerfile}', file=sys.stderr)
        report = {'result': 'SKIP', 'checks': [], 'error': str(dockerfile) + ' not found'}
        with open(args.output, 'w') as fh:
            json.dump(report, fh, indent=2)
        return 0

    lines = dockerfile.read_text(errors='replace').splitlines()
    results = [chk(lines) for chk in CHECKS]
    result = overall_result(results)

    report = {
        'result': result,
        'dockerfile': str(dockerfile),
        'checks': [c.to_dict() for c in results],
    }

    with open(args.output, 'w') as fh:
        json.dump(report, fh, indent=2)

    # Human-readable output
    print(f'Dockerfile: {dockerfile}')
    print(f'Overall   : {result}')
    print()
    for c in results:
        icon = {'PASS': '✅', 'WARN': '⚠️', 'FAIL': '❌'}.get(c.status, '?')
        print(f'  {icon} [{c.status}] {c.name}: {c.message}')

    return 1 if result == 'FAIL' else 0


if __name__ == '__main__':
    sys.exit(main())
