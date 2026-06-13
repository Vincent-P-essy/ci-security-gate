#!/usr/bin/env python3
"""Secret scanner: detects hardcoded secrets via entropy and regex patterns."""

import argparse
import json
import math
import os
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', '.tox', 'dist', 'build'}
SKIP_EXTENSIONS = {
    '.pyc', '.pyo', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg',
    '.woff', '.woff2', '.ttf', '.eot', '.otf', '.mp3', '.mp4', '.zip',
    '.tar', '.gz', '.bz2', '.xz', '.exe', '.dll', '.so', '.bin',
}

SECRET_REGEXES = [
    (
        'hardcoded_secret',
        re.compile(
            r'(api[_-]?key|secret|password|passwd|pwd|token|credential|auth[_-]?token)'
            r'\s*[:=]\s*[\'"](\S{8,})[\'"']',
            re.IGNORECASE,
        ),
        'CRITICAL',
    ),
    (
        'dotenv_assignment',
        re.compile(
            r'^(API[_]?KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL|AUTH[_]?TOKEN)\s*=\s*(\S{8,})$',
            re.IGNORECASE | re.MULTILINE,
        ),
        'HIGH',
    ),
    (
        'pem_private_key',
        re.compile(
            r'-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----',
            re.IGNORECASE,
        ),
        'CRITICAL',
    ),
]

SHANNON_THRESHOLD = 4.5
MIN_TOKEN_LEN = 20
# Characters that look like base64 / API key charsets
HIGH_ENTROPY_CHARSET = re.compile(r'^[A-Za-z0-9+/=_\-\.]{20,}$')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def shannon_entropy(data: str) -> float:
    """Compute the Shannon entropy of a string."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def is_binary(path: Path, sample_size: int = 8192) -> bool:
    """Return True if the file looks like a binary file."""
    try:
        with open(path, 'rb') as fh:
            chunk = fh.read(sample_size)
        return b'\x00' in chunk
    except OSError:
        return True


def iter_files(root: Path):
    """Yield all text files under *root*, skipping ignored dirs/extensions."""
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune ignored directories in-place so os.walk skips them
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            fpath = Path(dirpath) / filename
            if fpath.suffix.lower() in SKIP_EXTENSIONS:
                continue
            if is_binary(fpath):
                continue
            yield fpath


def scan_file(fpath: Path, root: Path) -> list[dict]:
    """Return a list of findings for *fpath*."""
    findings = []
    try:
        content = fpath.read_text(errors='replace')
    except OSError as exc:
        print(f'[WARN] Cannot read {fpath}: {exc}', file=sys.stderr)
        return findings

    rel = str(fpath.relative_to(root))
    lines = content.splitlines()

    # --- Regex checks ---
    for rule_name, pattern, severity in SECRET_REGEXES:
        for match in pattern.finditer(content):
            # Find line number
            lineno = content[: match.start()].count('\n') + 1
            findings.append({
                'file': rel,
                'line': lineno,
                'rule': rule_name,
                'severity': severity,
                'snippet': lines[lineno - 1].strip()[:120] if lineno <= len(lines) else '',
            })

    # --- Entropy check ---
    for lineno, line in enumerate(lines, start=1):
        for token in re.split(r'[\s\'"=:,;{}\[\]()]', line):
            if len(token) >= MIN_TOKEN_LEN and HIGH_ENTROPY_CHARSET.match(token):
                entropy = shannon_entropy(token)
                if entropy > SHANNON_THRESHOLD:
                    # Avoid duplicate matches already caught by regex
                    already = any(
                        f['file'] == rel and f['line'] == lineno
                        for f in findings
                    )
                    if not already:
                        findings.append({
                            'file': rel,
                            'line': lineno,
                            'rule': 'high_entropy_token',
                            'severity': 'HIGH',
                            'snippet': line.strip()[:120],
                            'entropy': round(entropy, 3),
                            'token_preview': token[:8] + '...',
                        })

    return findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description='Scan repository for hardcoded secrets.')
    parser.add_argument('--root', default='.', help='Root directory to scan')
    parser.add_argument('--output', default='secrets-report.json', help='Output JSON file')
    args = parser.parse_args()

    root = Path(args.root).resolve()
    all_findings: list[dict] = []
    files_scanned = 0

    for fpath in iter_files(root):
        files_scanned += 1
        findings = scan_file(fpath, root)
        all_findings.extend(findings)

    report = {
        'files_scanned': files_scanned,
        'findings': all_findings,
    }

    with open(args.output, 'w') as fh:
        json.dump(report, fh, indent=2)

    critical = [f for f in all_findings if f.get('severity') == 'CRITICAL']

    print(f'Files scanned : {files_scanned}')
    print(f'Total findings: {len(all_findings)}')
    print(f'Critical      : {len(critical)}')

    if all_findings:
        for finding in all_findings:
            print(
                f"  [{finding['severity']}] {finding['file']}:{finding['line']} "
                f"- {finding['rule']}"
            )

    return 1 if critical else 0


if __name__ == '__main__':
    sys.exit(main())
