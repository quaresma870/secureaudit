"""
Pre-commit hook — block commits containing secrets before they reach git.

Detection after a commit always has to clean up history (see the
`git_history` plugin); prevention at commit time is much cheaper. This
module installs/removes a git hook and runs a fast, staged-files-only
secrets scan when invoked.
"""

from __future__ import annotations

import shutil
import stat
import subprocess
import sys
from pathlib import Path

from secureaudit.core.models import Severity

_HOOK_MARKER = "# Installed by: secureaudit pre-commit install"

_HOOK_TEMPLATE = """#!/usr/bin/env bash
{marker}
# To skip this check for a single commit (not recommended): git commit --no-verify
{command} pre-commit run
exit $?
"""


def _resolve_secureaudit_command() -> str:
    """Absolute path to the secureaudit executable installing this hook,
    not the bare command name. A git hook runs in whatever PATH git
    itself uses at commit time, which commonly does NOT include an
    unactivated virtualenv's bin/ directory — a GUI git client, an IDE's
    git integration, or just a fresh terminal tab that hasn't run
    `source venv/bin/activate` all hit exactly this. Resolving and
    baking in the absolute path at install time, when we know for
    certain which secureaudit this is (sys.executable's own sibling, the
    same bin/Scripts directory pip installed the console script into),
    avoids the hook silently failing with 'command not found' in exactly
    those common scenarios — confirmed by actually reproducing that
    failure (a real venv install, hook fires from a shell where that
    venv's bin/ isn't on PATH) before fixing it, not assumed as a risk."""
    interpreter_dir = Path(sys.executable).parent
    for name in ("secureaudit", "secureaudit.exe"):
        candidate = interpreter_dir / name
        if candidate.exists():
            return str(candidate)
    # Fall back to PATH resolution for unusual installs where the console
    # script doesn't live next to the interpreter (e.g. some pipx/Homebrew
    # layouts) — still better than a guaranteed-wrong absolute path.
    return shutil.which("secureaudit") or "secureaudit"


def get_git_root(start: Path | None = None) -> Path | None:
    """Return the root of the git repository containing `start` (default: cwd)."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=start or Path.cwd(),
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return None
        return Path(result.stdout.strip())
    except Exception:
        return None


def get_staged_files(repo_root: Path) -> list[Path]:
    """Return absolute paths of staged files (added/copied/modified)."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return []
        return [
            repo_root / line.strip()
            for line in result.stdout.splitlines()
            if line.strip()
        ]
    except Exception:
        return []


# ── Hook install/uninstall ────────────────────────────────────────────────────

def install_hook(repo_root: Path, force: bool = False) -> tuple[bool, str]:
    hooks_dir = repo_root / ".git" / "hooks"
    if not hooks_dir.parent.exists():
        return False, f"Not a git repository: {repo_root}"

    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    if hook_path.exists() and not force:
        existing = hook_path.read_text(errors="ignore")
        if _HOOK_MARKER not in existing:
            return False, (
                f"{hook_path} already exists and was not installed by secureaudit. "
                "Use --force to overwrite."
            )

    hook_path.write_text(_HOOK_TEMPLATE.format(marker=_HOOK_MARKER, command=_resolve_secureaudit_command()))
    mode = hook_path.stat().st_mode
    hook_path.chmod(mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return True, str(hook_path)


def uninstall_hook(repo_root: Path) -> tuple[bool, str]:
    hook_path = repo_root / ".git" / "hooks" / "pre-commit"
    if not hook_path.exists():
        return False, "No pre-commit hook installed."

    content = hook_path.read_text(errors="ignore")
    if _HOOK_MARKER not in content:
        return False, "Existing pre-commit hook was not installed by secureaudit — not removing."

    hook_path.unlink()
    return True, str(hook_path)


# ── Staged scan ───────────────────────────────────────────────────────────────

def run_staged_scan(repo_root: Path) -> int:
    """Scan staged files for secrets. Returns 0 (allow commit) or 1 (block)."""
    from secureaudit.core.config import load_config
    from secureaudit.plugins.secrets import SecretsPlugin

    staged = [f for f in get_staged_files(repo_root) if f.is_file()]
    if not staged:
        return 0

    cfg = load_config(repo_root / "secureaudit.yml")
    plugin = SecretsPlugin(cfg)
    findings = plugin.scan_files(staged, repo_root)

    blocking = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if not blocking:
        return 0

    print("\n🔐 SecureAudit — commit blocked: possible secret(s) detected\n")
    for f in blocking:
        loc = f"{f.file}:{f.line}" if f.line else (f.file or "")
        print(f"  [{f.severity.value}] {f.title} — {loc}")
    print(f"\n{len(blocking)} blocking finding(s). Remove the secret(s) before committing.")
    print("If this is a false positive, add a suppression comment on that line:")
    print('  # secureaudit-ignore: <rule-slug> reason="explanation"')
    print("To override for this commit only (not recommended): git commit --no-verify\n")
    return 1
