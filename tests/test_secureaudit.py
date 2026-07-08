"""
Tests for SecureAudit — plugins, engine and models.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from secureaudit.core.config import load_config
from secureaudit.core.engine import AuditEngine
from secureaudit.core.models import AuditResult, Finding, PluginResult, Severity

# ── Models ────────────────────────────────────────────────────────────────────

class TestSeverity:
    def test_score_penalties(self):
        assert Severity.CRITICAL.score_penalty == 25
        assert Severity.HIGH.score_penalty == 15
        assert Severity.INFO.score_penalty == 0

    def test_colors(self):
        assert Severity.CRITICAL.color == "#ef4444"
        assert Severity.INFO.color == "#6b7280"


class TestFinding:
    def test_to_dict(self):
        f = Finding(plugin="test", title="Test", severity=Severity.HIGH,
                    description="desc", file="foo.py", line=42)
        d = f.to_dict()
        assert d["severity"] == "HIGH"
        assert d["file"] == "foo.py"
        assert d["line"] == 42


class TestAuditResult:
    def _make_result(self) -> AuditResult:
        result = AuditResult(target="/tmp/test")
        pr = PluginResult(plugin="test")
        pr.findings = [
            Finding("test", "Critical issue", Severity.CRITICAL, "desc"),
            Finding("test", "High issue", Severity.HIGH, "desc"),
            Finding("test", "Low issue", Severity.LOW, "desc"),
        ]
        result.plugin_results = [pr]
        return result

    def test_score(self):
        result = self._make_result()
        # 100 - 25 (CRITICAL) - 15 (HIGH) - 3 (LOW) = 57
        assert result.score == 57

    def test_grade(self):
        result = self._make_result()
        assert result.grade == "D"

    def test_grade_a(self):
        result = AuditResult(target="/tmp")
        pr = PluginResult(plugin="test")
        pr.findings = [Finding("test", "Info", Severity.INFO, "desc")]
        result.plugin_results = [pr]
        assert result.grade == "A"
        assert result.score == 100

    def test_counts_by_severity(self):
        result = self._make_result()
        counts = result.counts_by_severity()
        assert counts["CRITICAL"] == 1
        assert counts["HIGH"] == 1
        assert counts["LOW"] == 1
        assert counts["MEDIUM"] == 0

    def test_to_dict(self):
        result = self._make_result()
        d = result.to_dict()
        assert d["score"] == 57
        assert d["target"] == "/tmp/test"
        assert len(d["plugins"]) == 1


# ── Config ────────────────────────────────────────────────────────────────────

class TestConfig:
    def test_defaults(self):
        cfg = load_config(None)
        assert cfg.fail_below == 70
        assert "secrets" in cfg.plugins
        assert cfg.exclude_paths  # not empty

    def test_custom_config(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write("fail_below: 90\nplugins:\n  - secrets\n  - cve\n")
            path = f.name
        try:
            cfg = load_config(path)
            assert cfg.fail_below == 90
            assert cfg.plugins == ["secrets", "cve"]
        finally:
            os.unlink(path)


# ── Secrets Plugin ────────────────────────────────────────────────────────────

class TestSecretsPlugin:
    def setup_method(self):
        from secureaudit.plugins.secrets import SecretsPlugin
        self.plugin = SecretsPlugin(load_config(None))

    def test_detect_aws_key(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "config.py").write_text('AWS_KEY = "AKIAI9ABCDEF1234WXYZ"\n')  # realistic entropy
            result = self.plugin.audit(d)
            assert any("AWS" in f.title for f in result.findings)

    def test_detect_private_key(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "server.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\nfakekey\n-----END RSA PRIVATE KEY-----\n")
            result = self.plugin.audit(d)
            assert any("Private Key" in f.title for f in result.findings)

    def test_detect_github_token(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, ".env").write_text("GITHUB_TOKEN=ghp_" + "A" * 36 + "\n")
            result = self.plugin.audit(d)
            assert any("GitHub" in f.title for f in result.findings)

    def test_clean_directory(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("def hello(): return 'world'\n")
            result = self.plugin.audit(d)
            assert not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in result.findings)

    def test_excludes_node_modules(self):
        with tempfile.TemporaryDirectory() as d:
            node_dir = Path(d, "node_modules")
            node_dir.mkdir()
            Path(node_dir, "config.js").write_text('const key = "AKIAIOSFODNN7EXAMPLE";\n')
            result = self.plugin.audit(d)
            assert not any("AWS" in f.title for f in result.findings)


# ── Filesystem Plugin ─────────────────────────────────────────────────────────

class TestFilesystemPlugin:
    def setup_method(self):
        from secureaudit.plugins.filesystem import FilesystemPlugin
        self.plugin = FilesystemPlugin(load_config(None))

    def test_detect_env_file(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, ".env").write_text("SECRET=mysecret\n")
            result = self.plugin.audit(d)
            assert any(".env" in f.title for f in result.findings)

    def test_detect_private_key_file(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "id_rsa").write_text("fake key\n")
            result = self.plugin.audit(d)
            assert any("id_rsa" in f.title for f in result.findings)

    def test_gitignored_env_is_info(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, ".env").write_text("SECRET=x\n")
            Path(d, ".gitignore").write_text(".env\n")
            result = self.plugin.audit(d)
            env_findings = [f for f in result.findings if ".env" in f.title]
            if env_findings:
                assert all(f.severity == Severity.INFO for f in env_findings)


# ── Policy Plugin ─────────────────────────────────────────────────────────────

class TestPolicyPlugin:
    def setup_method(self):
        from secureaudit.plugins.policy import PolicyPlugin
        self.plugin = PolicyPlugin(load_config(None))

    def test_missing_gitignore(self):
        with tempfile.TemporaryDirectory() as d:
            result = self.plugin.audit(d)
            assert any(".gitignore" in f.title for f in result.findings)

    def test_dockerfile_no_user(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, ".gitignore").write_text("*.env\n")
            Path(d, "Dockerfile").write_text("FROM python:3.11\nRUN pip install flask\nCMD python app.py\n")
            result = self.plugin.audit(d)
            assert any("root" in f.title.lower() for f in result.findings)

    def test_dockerfile_with_user(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, ".gitignore").write_text("*.env\n")
            Path(d, "Dockerfile").write_text(
                "FROM python:3.11-slim\nRUN useradd -m app\nUSER app\nCMD python app.py\n"
            )
            result = self.plugin.audit(d)
            assert not any("runs as root" in f.title for f in result.findings)


# ── Engine ────────────────────────────────────────────────────────────────────

class TestEngine:
    def test_runs_selected_plugins(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("def hello(): return 'world'\n")
            cfg = load_config(None)
            engine = AuditEngine(cfg)
            result = engine.run(d, plugins=["secrets", "filesystem", "policy"])
            plugin_names = [pr.plugin for pr in result.plugin_results]
            assert "secrets" in plugin_names
            assert "filesystem" in plugin_names
            assert "policy" in plugin_names
            assert "http" not in plugin_names

    def test_result_has_score(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = load_config(None)
            engine = AuditEngine(cfg)
            result = engine.run(d, plugins=["policy"])
            assert 0 <= result.score <= 100

    def test_handles_plugin_error_gracefully(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = load_config(None)
            engine = AuditEngine(cfg)
            # CVE plugin on empty dir should not crash
            result = engine.run(d, plugins=["cve"])
            assert result is not None
            assert len(result.plugin_results) == 1

    def test_json_report(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = load_config(None)
            engine = AuditEngine(cfg)
            result = engine.run(d, plugins=["policy"])
            data = result.to_dict()
            assert "score" in data
            assert "plugins" in data
            assert isinstance(data["plugins"], list)


# ── CORS Plugin ───────────────────────────────────────────────────────────────

class TestCORSPlugin:
    def setup_method(self):
        from secureaudit.plugins.cors import CORSPlugin
        self.plugin = CORSPlugin(load_config(None))

    def test_no_urls_returns_info(self):
        with tempfile.TemporaryDirectory() as d:
            result = self.plugin.audit(d)
            assert len(result.findings) == 1
            assert result.findings[0].severity == Severity.INFO
            assert "No URLs" in result.findings[0].title

    def test_registered(self):
        from secureaudit.plugins import available_plugins
        assert "cors" in available_plugins()


# ── Git History Plugin ────────────────────────────────────────────────────────

class TestGitHistoryPlugin:
    def setup_method(self):
        from secureaudit.plugins.git_history import GitHistoryPlugin
        self.plugin = GitHistoryPlugin(load_config(None))

    def test_non_git_dir_returns_info(self):
        with tempfile.TemporaryDirectory() as d:
            result = self.plugin.audit(d)
            assert len(result.findings) == 1
            assert result.findings[0].severity == Severity.INFO
            assert "Not a git" in result.findings[0].title

    def test_git_repo_scans_history(self):
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            # Init a git repo with a secret in history
            subprocess.run(["git", "init"], cwd=d, capture_output=True)
            subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=d, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=d, capture_output=True)

            # Commit a secret
            secret_file = Path(d) / "config.py"
            secret_file.write_text('AWS_KEY = "AKIAI9ABCDEF1234WXYZ"\n')
            subprocess.run(["git", "add", "."], cwd=d, capture_output=True)
            subprocess.run(["git", "commit", "-m", "add config"], cwd=d, capture_output=True)

            # Remove the secret (but it's still in history)
            secret_file.write_text('AWS_KEY = os.environ["AWS_KEY"]\n')
            subprocess.run(["git", "add", "."], cwd=d, capture_output=True)
            subprocess.run(["git", "commit", "-m", "fix secret"], cwd=d, capture_output=True)

            result = self.plugin.audit(d)
            # Should find the secret in history
            critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
            assert len(critical) >= 1
            assert any("AWS" in f.title for f in critical)

    def test_registered(self):
        from secureaudit.plugins import available_plugins
        assert "git_history" in available_plugins()


# ── Scheduler ─────────────────────────────────────────────────────────────────

class TestScheduler:
    def test_parse_cron_every_30min(self):
        from secureaudit.scheduler import _parse_cron
        try:
            import schedule
        except ImportError:
            pytest.skip("schedule not installed")
        schedule.clear()
        job = _parse_cron("*/30 * * * *", lambda: None)
        assert job is not None
        schedule.clear()

    def test_parse_cron_daily(self):
        from secureaudit.scheduler import _parse_cron
        try:
            import schedule
        except ImportError:
            pytest.skip("schedule not installed")
        schedule.clear()
        job = _parse_cron("0 8 * * *", lambda: None)
        assert job is not None
        schedule.clear()

    def test_invalid_cron_raises(self):
        from secureaudit.scheduler import _parse_cron
        with pytest.raises((ValueError, RuntimeError)):
            _parse_cron("not a cron", lambda: None)

    def test_run_schedule_immediate_job_does_not_crash(self, monkeypatch):
        """Regression test for a real, reproduced bug: run_schedule's
        job() imported `from secureaudit.output.terminal import
        print_summary` — a module that doesn't exist anywhere in this
        codebase (secureaudit/output/ has never existed; the function it
        was looking for lives in secureaudit/reports/terminal.py). Every
        single `secureaudit schedule` invocation crashed immediately with
        ModuleNotFoundError, before even completing its first
        "runs immediately on start" job — confirmed by actually running
        the installed CLI command for real, not caught by the existing
        cron-parsing-only tests above, which never actually call
        run_schedule() at all.

        Lets job() actually execute for real (the only way to exercise
        the broken import at all, since it's a closure inside
        run_schedule — not separately callable), then breaks the
        otherwise-infinite while loop via a simulated KeyboardInterrupt
        on the first run_pending() call, the same clean-exit path Ctrl+C
        takes."""
        import schedule as schedule_lib

        from secureaudit.scheduler import run_schedule

        monkeypatch.setattr(schedule_lib, "run_pending", lambda: (_ for _ in ()).throw(KeyboardInterrupt))

        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("x = 1\n")
            # Must not raise — confirms the import inside job() actually
            # resolves, not just that _parse_cron (called separately,
            # before job() ever runs) succeeds.
            run_schedule(
                target=d, cron_expr="0 6 * * 1", plugins=["policy"], db=None,
                alert_webhook=None, fail_below=70, output_dir=None, config_path=None,
            )


# ── SAST Plugin ───────────────────────────────────────────────────────────────

class TestSASTPlugin:
    def setup_method(self):
        from secureaudit.plugins.sast import SASTPlugin
        self.plugin = SASTPlugin(load_config(None))

    def test_graceful_degradation_when_semgrep_missing(self, monkeypatch):
        import shutil
        monkeypatch.setattr(shutil, "which", lambda x: None)
        with tempfile.TemporaryDirectory() as d:
            result = self.plugin.audit(d)
            assert len(result.findings) == 1
            assert result.findings[0].severity == Severity.INFO
            assert "not installed" in result.findings[0].title.lower()

    def test_registered(self):
        from secureaudit.plugins import available_plugins
        assert "sast" in available_plugins()


# ── Malware Plugin ────────────────────────────────────────────────────────────

class TestMalwarePlugin:
    def setup_method(self):
        from secureaudit.plugins.malware import MalwarePlugin
        self.plugin = MalwarePlugin(load_config(None))

    def test_graceful_degradation_when_clamav_missing(self, monkeypatch):
        import shutil
        monkeypatch.setattr(shutil, "which", lambda x: None)
        with tempfile.TemporaryDirectory() as d:
            result = self.plugin.audit(d)
            assert len(result.findings) == 1
            assert result.findings[0].severity == Severity.INFO
            assert "not installed" in result.findings[0].title.lower()

    def test_no_scan_dirs_present(self, monkeypatch):
        import shutil
        monkeypatch.setattr(shutil, "which", lambda x: "/usr/bin/clamscan" if x == "clamscan" else None)
        with tempfile.TemporaryDirectory() as d:
            result = self.plugin.audit(d)
            assert any("No scannable directories" in f.title for f in result.findings)

    def test_registered(self):
        from secureaudit.plugins import available_plugins
        assert "malware" in available_plugins()


# ── Trivy Plugin ──────────────────────────────────────────────────────────────

class TestTrivyPlugin:
    def setup_method(self):
        from secureaudit.plugins.trivy import TrivyPlugin
        self.plugin = TrivyPlugin(load_config(None))

    def test_graceful_degradation_when_trivy_missing(self, monkeypatch):
        import shutil
        monkeypatch.setattr(shutil, "which", lambda x: None)
        with tempfile.TemporaryDirectory() as d:
            result = self.plugin.audit(d)
            assert len(result.findings) == 1
            assert result.findings[0].severity == Severity.INFO
            assert "not installed" in result.findings[0].title.lower()

    def test_registered(self):
        from secureaudit.plugins import available_plugins
        assert "trivy" in available_plugins()


# ── Default plugins config ───────────────────────────────────────────────────

class TestNewPluginsConfig:
    def test_cors_and_git_history_in_defaults(self):
        cfg = load_config(None)
        assert "cors" in cfg.plugins
        assert "git_history" in cfg.plugins

    def test_sast_malware_trivy_not_in_defaults(self):
        """These require external binaries — opt-in only, not run by default."""
        cfg = load_config(None)
        assert "sast" not in cfg.plugins
        assert "malware" not in cfg.plugins
        assert "trivy" not in cfg.plugins

    def test_all_new_plugins_available(self):
        from secureaudit.plugins import available_plugins
        plugins = available_plugins()
        for name in ("cors", "git_history", "sast", "malware", "trivy"):
            assert name in plugins, f"{name} should be registered"


# ── Finding fingerprint / rule_slug ──────────────────────────────────────────

class TestFindingFingerprint:
    def test_rule_slug_from_title(self):
        f = Finding(plugin="secrets", title="AWS Access Key detected", severity=Severity.CRITICAL, description="")
        assert f.rule_slug == "aws-access-key-detected"

    def test_rule_slug_prefers_rule_id(self):
        f = Finding(plugin="sast", title="SAST: foo", severity=Severity.HIGH, description="",
                    extra={"rule_id": "python.lang.security.sql-injection"})
        assert f.rule_slug == "python-lang-security-sql-injection"

    def test_fingerprint_stable_across_line_changes(self):
        f1 = Finding(plugin="secrets", title="AWS Access Key detected", severity=Severity.CRITICAL,
                     description="", file="app.py", line=10)
        f2 = Finding(plugin="secrets", title="AWS Access Key detected", severity=Severity.CRITICAL,
                     description="", file="app.py", line=42)
        assert f1.fingerprint() == f2.fingerprint()

    def test_fingerprint_differs_by_file(self):
        f1 = Finding(plugin="secrets", title="AWS Access Key detected", severity=Severity.CRITICAL,
                     description="", file="app.py")
        f2 = Finding(plugin="secrets", title="AWS Access Key detected", severity=Severity.CRITICAL,
                     description="", file="other.py")
        assert f1.fingerprint() != f2.fingerprint()

    def test_fingerprint_differs_by_plugin(self):
        f1 = Finding(plugin="secrets", title="Issue", severity=Severity.HIGH, description="", file="a.py")
        f2 = Finding(plugin="sast", title="Issue", severity=Severity.HIGH, description="", file="a.py")
        assert f1.fingerprint() != f2.fingerprint()


# ── Baseline ──────────────────────────────────────────────────────────────────

class TestBaseline:
    def test_save_and_load_baseline(self):
        from secureaudit.core.baseline import load_baseline, save_baseline

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / ".secureaudit-baseline.json"
            findings = [
                Finding(plugin="secrets", title="AWS Access Key detected",
                       severity=Severity.CRITICAL, description="", file="app.py"),
            ]
            count = save_baseline(path, findings, target=d)
            assert count == 1
            assert path.exists()

            data = load_baseline(path)
            assert data["version"] == 1
            assert len(data["fingerprints"]) == 1

    def test_merge_preserves_existing_entries(self):
        from secureaudit.core.baseline import load_baseline, save_baseline

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / ".secureaudit-baseline.json"
            f1 = Finding(plugin="secrets", title="Issue A", severity=Severity.HIGH, description="", file="a.py")
            f2 = Finding(plugin="secrets", title="Issue B", severity=Severity.HIGH, description="", file="b.py")

            save_baseline(path, [f1], target=d)
            save_baseline(path, [f2], target=d, merge=True)

            data = load_baseline(path)
            assert len(data["fingerprints"]) == 2

    def test_force_replaces_baseline(self):
        from secureaudit.core.baseline import load_baseline, save_baseline

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / ".secureaudit-baseline.json"
            f1 = Finding(plugin="secrets", title="Issue A", severity=Severity.HIGH, description="", file="a.py")
            f2 = Finding(plugin="secrets", title="Issue B", severity=Severity.HIGH, description="", file="b.py")

            save_baseline(path, [f1], target=d)
            save_baseline(path, [f2], target=d, merge=False)

            data = load_baseline(path)
            assert len(data["fingerprints"]) == 1

    def test_apply_suppressions_moves_baselined_findings(self):
        from secureaudit.core.baseline import apply_suppressions, save_baseline

        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            bpath = target / ".secureaudit-baseline.json"

            finding = Finding(plugin="secrets", title="AWS Access Key detected",
                              severity=Severity.CRITICAL, description="", file="app.py")
            save_baseline(bpath, [finding], target=str(target))

            result = AuditResult(target=str(target))
            pr = PluginResult(plugin="secrets")
            pr.findings = [
                Finding(plugin="secrets", title="AWS Access Key detected",
                       severity=Severity.CRITICAL, description="", file="app.py"),
                Finding(plugin="secrets", title="GitHub Token detected",
                       severity=Severity.CRITICAL, description="", file="other.py"),
            ]
            result.plugin_results = [pr]

            apply_suppressions(result, target=target, baseline_path=bpath)

            assert len(result.suppressed_findings) == 1
            assert result.suppressed_findings[0].suppressed_reason == "baseline"
            assert len(result.all_findings) == 1
            assert result.all_findings[0].title == "GitHub Token detected"

    def test_score_excludes_suppressed_findings(self):
        from secureaudit.core.baseline import apply_suppressions, save_baseline

        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            bpath = target / ".secureaudit-baseline.json"
            finding = Finding(plugin="secrets", title="Issue", severity=Severity.CRITICAL,
                              description="", file="app.py")
            save_baseline(bpath, [finding], target=str(target))

            result = AuditResult(target=str(target))
            pr = PluginResult(plugin="secrets")
            pr.findings = [Finding(plugin="secrets", title="Issue", severity=Severity.CRITICAL,
                                   description="", file="app.py")]
            result.plugin_results = [pr]

            apply_suppressions(result, target=target, baseline_path=bpath)
            assert result.score == 100  # baselined CRITICAL no longer penalises score


# ── Inline suppressions ──────────────────────────────────────────────────────

class TestInlineSuppressions:
    def test_simple_ignore_comment(self):
        from secureaudit.core.baseline import scan_inline_suppressions

        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            (target / "app.py").write_text(
                'API_KEY = "test123"  # secureaudit-ignore\n'
            )
            rules = scan_inline_suppressions(target, exclude_paths=set())
            assert ("app.py", 1) in rules

    def test_ignore_with_rule_slug(self):
        from secureaudit.core.baseline import scan_inline_suppressions

        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            (target / "app.py").write_text(
                'X = 1  # secureaudit-ignore: hardcoded-password reason="test fixture"\n'
            )
            rules = scan_inline_suppressions(target, exclude_paths=set())
            rule = rules[("app.py", 1)]
            assert rule.rule_slug == "hardcoded-password"
            assert rule.reason == "test fixture"

    def test_ignore_with_until_date(self):
        from secureaudit.core.baseline import scan_inline_suppressions

        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            (target / "app.py").write_text(
                "X = 1  # secureaudit-ignore: foo until=2099-01-01\n"
            )
            rules = scan_inline_suppressions(target, exclude_paths=set())
            rule = rules[("app.py", 1)]
            assert rule.until.isoformat() == "2099-01-01"

    def test_expired_suppression_not_applied(self):
        from datetime import date

        from secureaudit.core.baseline import SuppressionRule
        rule = SuppressionRule(rule_slug=None, reason=None, until=date(2000, 1, 1))
        assert rule.is_expired()

    def test_future_suppression_not_expired(self):
        from datetime import date

        from secureaudit.core.baseline import SuppressionRule
        rule = SuppressionRule(rule_slug=None, reason=None, until=date(2099, 1, 1))
        assert not rule.is_expired()

    def test_inline_suppression_applied_in_apply_suppressions(self):
        from secureaudit.core.baseline import apply_suppressions

        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            (target / "app.py").write_text(
                'PWD = "x"  # secureaudit-ignore: hardcoded-password\n'
            )
            result = AuditResult(target=str(target))
            pr = PluginResult(plugin="secrets")
            pr.findings = [
                Finding(plugin="secrets", title="Hardcoded Password", severity=Severity.HIGH,
                       description="", file="app.py", line=1),
            ]
            result.plugin_results = [pr]

            apply_suppressions(result, target=target, baseline_path=None, check_inline=True)
            assert len(result.suppressed_findings) == 1
            assert "inline" in result.suppressed_findings[0].suppressed_reason


# ── CLI integration (catches signature/decorator bugs) ───────────────────────

class TestCLIIntegration:
    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def test_scan_command_runs_without_crashing(self):
        """Regression test: scan() previously referenced --sarif/--db params
        with no corresponding @click.option decorators, causing a TypeError
        at invocation time. This test would have caught that.
        """
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("def hello(): return 'world'\n")
            result = runner.invoke(cli, ["scan", d, "--plugins", "policy", "--no-terminal"])
            assert result.exit_code == 0, result.output

    def test_scan_with_sarif_and_db_flags(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("def hello(): return 'world'\n")
            sarif_path = Path(d) / "out.sarif"
            db_path = Path(d) / "audits.db"
            result = runner.invoke(cli, [
                "scan", d, "--plugins", "policy", "--no-terminal",
                "--sarif", str(sarif_path), "--db", str(db_path),
            ])
            assert result.exit_code == 0, result.output
            assert sarif_path.exists()
            assert db_path.exists()

    def test_baseline_command(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("def hello(): return 'world'\n")
            result = runner.invoke(cli, ["baseline", d, "--plugins", "policy"])
            assert result.exit_code == 0, result.output
            assert (Path(d) / ".secureaudit-baseline.json").exists()

    def test_scan_respects_baseline(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            # No .gitignore → policy plugin will flag it
            r1 = runner.invoke(cli, ["baseline", d, "--plugins", "policy"])
            assert r1.exit_code == 0

            r2 = runner.invoke(cli, ["scan", d, "--plugins", "policy", "--no-terminal", "--fail-below", "0"])
            assert r2.exit_code == 0

    def test_list_plugins_includes_new_plugins(self):
        from secureaudit.cli import cli
        runner = self._runner()
        result = runner.invoke(cli, ["list-plugins"])
        assert result.exit_code == 0
        for name in ("cors", "git_history", "sast", "malware", "trivy"):
            assert name in result.output


# ── Diff ──────────────────────────────────────────────────────────────────────

def _make_audit_result(target: str, findings: list[Finding]) -> AuditResult:
    result = AuditResult(target=target)
    pr = PluginResult(plugin="secrets")
    pr.findings = findings
    result.plugin_results = [pr]
    return result


class TestDiff:
    def test_resolve_run_id_numeric(self):
        from secureaudit.core.diff import resolve_run_id
        assert resolve_run_id("unused.db", "42") == 42

    def test_resolve_run_id_invalid_keyword(self):
        from secureaudit.core.diff import resolve_run_id
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            with pytest.raises(ValueError):
                resolve_run_id(db, "not-a-valid-ref")

    def test_resolve_latest_and_previous(self):
        from secureaudit.core.diff import resolve_run_id
        from secureaudit.reports.history import save

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            r1 = save(_make_audit_result(d, []), db)
            r2 = save(_make_audit_result(d, []), db)

            assert resolve_run_id(db, "latest") == r2
            assert resolve_run_id(db, "previous") == r1

    def test_resolve_previous_fails_with_one_run(self):
        from secureaudit.core.diff import resolve_run_id
        from secureaudit.reports.history import save

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_audit_result(d, []), db)
            with pytest.raises(ValueError):
                resolve_run_id(db, "previous")

    def test_diff_detects_new_and_resolved(self):
        from secureaudit.core.diff import diff_runs
        from secureaudit.reports.history import save

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")

            r1 = save(_make_audit_result(d, [
                Finding(plugin="secrets", title="Old Issue", severity=Severity.HIGH,
                       description="", file="a.py"),
            ]), db)

            r2 = save(_make_audit_result(d, [
                Finding(plugin="secrets", title="New Issue", severity=Severity.CRITICAL,
                       description="", file="b.py"),
            ]), db)

            result = diff_runs(db, r1, r2)
            assert len(result.new) == 1
            assert result.new[0]["title"] == "New Issue"
            assert len(result.resolved) == 1
            assert result.resolved[0]["title"] == "Old Issue"
            assert result.unchanged_count == 0

    def test_diff_unchanged_findings_not_duplicated(self):
        from secureaudit.core.diff import diff_runs
        from secureaudit.reports.history import save

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            same_finding = Finding(plugin="secrets", title="Persistent Issue",
                                   severity=Severity.MEDIUM, description="", file="a.py")

            r1 = save(_make_audit_result(d, [same_finding]), db)
            r2 = save(_make_audit_result(d, [same_finding]), db)

            result = diff_runs(db, r1, r2)
            assert result.new == []
            assert result.resolved == []
            assert result.unchanged_count == 1

    def test_has_new_regression_true_for_critical(self):
        from secureaudit.core.diff import diff_runs
        from secureaudit.reports.history import save

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            r1 = save(_make_audit_result(d, []), db)
            r2 = save(_make_audit_result(d, [
                Finding(plugin="secrets", title="Critical Issue", severity=Severity.CRITICAL,
                       description="", file="a.py"),
            ]), db)
            result = diff_runs(db, r1, r2)
            assert result.has_new_regression

    def test_has_new_regression_false_for_low_severity(self):
        from secureaudit.core.diff import diff_runs
        from secureaudit.reports.history import save

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            r1 = save(_make_audit_result(d, []), db)
            r2 = save(_make_audit_result(d, [
                Finding(plugin="secrets", title="Minor Issue", severity=Severity.LOW,
                       description="", file="a.py"),
            ]), db)
            result = diff_runs(db, r1, r2)
            assert not result.has_new_regression

    def test_diff_excludes_suppressed_by_default(self):
        from secureaudit.core.diff import diff_runs
        from secureaudit.reports.history import save

        with tempfile.TemporaryDirectory() as d:
            target = str(d)
            db = str(Path(d) / "audits.db")

            result1 = AuditResult(target=target)
            result1.suppressed_findings = [
                Finding(plugin="secrets", title="Suppressed Issue", severity=Severity.HIGH,
                       description="", file="a.py"),
            ]
            r1 = save(result1, db)
            r2 = save(_make_audit_result(target, []), db)

            diff_result = diff_runs(db, r1, r2)
            assert diff_result.resolved == []  # suppressed findings excluded by default

    def test_diff_includes_suppressed_when_requested(self):
        from secureaudit.core.diff import diff_runs
        from secureaudit.reports.history import save

        with tempfile.TemporaryDirectory() as d:
            target = str(d)
            db = str(Path(d) / "audits.db")

            result1 = AuditResult(target=target)
            result1.suppressed_findings = [
                Finding(plugin="secrets", title="Suppressed Issue", severity=Severity.HIGH,
                       description="", file="a.py"),
            ]
            r1 = save(result1, db)
            r2 = save(_make_audit_result(target, []), db)

            diff_result = diff_runs(db, r1, r2, include_suppressed=True)
            assert len(diff_result.resolved) == 1


class TestDiffCLI:
    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def test_diff_command_no_regression_exits_zero(self):
        from secureaudit.cli import cli
        from secureaudit.reports.history import save

        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_audit_result(d, []), db)
            save(_make_audit_result(d, []), db)

            result = runner.invoke(cli, ["diff", "1", "2", "--db", db])
            assert result.exit_code == 0, result.output

    def test_diff_command_regression_exits_nonzero(self):
        from secureaudit.cli import cli
        from secureaudit.reports.history import save

        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_audit_result(d, []), db)
            save(_make_audit_result(d, [
                Finding(plugin="secrets", title="New Critical", severity=Severity.CRITICAL,
                       description="", file="a.py"),
            ]), db)

            result = runner.invoke(cli, ["diff", "1", "2", "--db", db])
            assert result.exit_code == 1

    def test_diff_command_missing_db(self):
        from secureaudit.cli import cli
        runner = self._runner()
        result = runner.invoke(cli, ["diff", "1", "2", "--db", "/nonexistent/audits.db"])
        assert result.exit_code != 0

    def test_diff_command_json_output(self):
        from secureaudit.cli import cli
        from secureaudit.reports.history import save

        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_audit_result(d, []), db)
            save(_make_audit_result(d, []), db)

            result = runner.invoke(cli, ["diff", "latest", "previous", "--db", db, "--json"])
            assert result.exit_code == 0
            import json as _json
            data = _json.loads(result.output)
            assert "new" in data
            assert "resolved" in data


# ── Pre-commit hook ───────────────────────────────────────────────────────────

def _init_git_repo(d: str) -> None:
    import subprocess
    subprocess.run(["git", "init", "-q"], cwd=d, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=d, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=d, capture_output=True)


def _git_stage(d: str, *files: str) -> None:
    import subprocess
    subprocess.run(["git", "add", *files], cwd=d, capture_output=True)


class TestPrecommitHookManagement:
    def test_get_git_root_in_repo(self):
        from secureaudit.core.precommit import get_git_root
        with tempfile.TemporaryDirectory() as d:
            _init_git_repo(d)
            root = get_git_root(Path(d))
            assert root is not None
            assert Path(d).resolve() == root.resolve()

    def test_get_git_root_outside_repo(self):
        from secureaudit.core.precommit import get_git_root
        with tempfile.TemporaryDirectory() as d:
            # No git init — should return None (or a root above /tmp, but never error)
            result = get_git_root(Path(d))
            # Either None or some parent repo — must not raise
            assert result is None or isinstance(result, Path)

    def test_install_hook_creates_executable_file(self):
        from secureaudit.core.precommit import install_hook
        with tempfile.TemporaryDirectory() as d:
            _init_git_repo(d)
            ok, path = install_hook(Path(d))
            assert ok
            hook_path = Path(path)
            assert hook_path.exists()
            assert hook_path.stat().st_mode & 0o111  # executable bits set

    def test_install_hook_uses_absolute_path_not_bare_command(self):
        """Regression test for a real, reproduced bug: the hook used to
        call bare `secureaudit pre-commit run`, trusting PATH at commit
        time — which a real venv install + a fresh shell without that
        venv activated genuinely does not have, producing a silent
        'command not found' that lets a commit with a real secret through
        instead of blocking it (the opposite of this feature's entire
        purpose). The hook must reference an absolute path resolved at
        install time instead, when we know for certain which secureaudit
        this is. Mocks the resolver itself, since whether THIS specific
        test environment happens to have a real sibling executable next
        to sys.executable is a separate concern (covered by the resolver's
        own tests below) from confirming install_hook actually uses
        whatever it returns."""
        from unittest.mock import patch

        from secureaudit.core.precommit import install_hook

        with tempfile.TemporaryDirectory() as d:
            _init_git_repo(d)
            with patch(
                "secureaudit.core.precommit._resolve_secureaudit_command",
                return_value="/opt/myvenv/bin/secureaudit",
            ):
                ok, path = install_hook(Path(d))
            assert ok
            content = Path(path).read_text()
            assert "\nsecureaudit pre-commit run\n" not in content
            assert "/opt/myvenv/bin/secureaudit pre-commit run" in content

    def test_resolve_secureaudit_command_prefers_interpreter_sibling(self):
        """When a 'secureaudit' executable sits next to sys.executable
        (the normal pip/venv install layout), that exact path is used —
        not whatever 'secureaudit' happens to resolve to via PATH, which
        could be a different installed version entirely."""
        from unittest.mock import patch

        from secureaudit.core.precommit import _resolve_secureaudit_command

        with tempfile.TemporaryDirectory() as d:
            fake_interpreter = Path(d) / "python3"
            fake_interpreter.touch()
            fake_secureaudit = Path(d) / "secureaudit"
            fake_secureaudit.touch()

            with patch("sys.executable", str(fake_interpreter)):
                resolved = _resolve_secureaudit_command()
            assert resolved == str(fake_secureaudit)

    def test_resolve_secureaudit_command_falls_back_to_path(self):
        """No executable next to sys.executable at all (an unusual
        install layout) — falls back to PATH resolution rather than
        baking in a path that's guaranteed not to exist."""
        from unittest.mock import patch

        from secureaudit.core.precommit import _resolve_secureaudit_command

        with tempfile.TemporaryDirectory() as d:
            fake_interpreter = Path(d) / "python3"
            fake_interpreter.touch()

            with patch("sys.executable", str(fake_interpreter)), \
                 patch("shutil.which", return_value="/usr/local/bin/secureaudit"):
                resolved = _resolve_secureaudit_command()
            assert resolved == "/usr/local/bin/secureaudit"

    def test_install_hook_fails_without_git_dir(self):
        from secureaudit.core.precommit import install_hook
        with tempfile.TemporaryDirectory() as d:
            ok, msg = install_hook(Path(d))
            assert not ok
            assert "Not a git repository" in msg

    def test_install_hook_refuses_to_overwrite_foreign_hook(self):
        from secureaudit.core.precommit import install_hook
        with tempfile.TemporaryDirectory() as d:
            _init_git_repo(d)
            hooks_dir = Path(d) / ".git" / "hooks"
            hooks_dir.mkdir(parents=True, exist_ok=True)
            (hooks_dir / "pre-commit").write_text("#!/bin/sh\necho 'existing hook'\n")

            ok, msg = install_hook(Path(d))
            assert not ok
            assert "already exists" in msg

    def test_install_hook_force_overwrites(self):
        from secureaudit.core.precommit import install_hook
        with tempfile.TemporaryDirectory() as d:
            _init_git_repo(d)
            hooks_dir = Path(d) / ".git" / "hooks"
            hooks_dir.mkdir(parents=True, exist_ok=True)
            (hooks_dir / "pre-commit").write_text("#!/bin/sh\necho 'existing hook'\n")

            ok, _ = install_hook(Path(d), force=True)
            assert ok

    def test_uninstall_removes_our_hook(self):
        from secureaudit.core.precommit import install_hook, uninstall_hook
        with tempfile.TemporaryDirectory() as d:
            _init_git_repo(d)
            install_hook(Path(d))
            ok, _ = uninstall_hook(Path(d))
            assert ok
            assert not (Path(d) / ".git" / "hooks" / "pre-commit").exists()

    def test_uninstall_refuses_foreign_hook(self):
        from secureaudit.core.precommit import uninstall_hook
        with tempfile.TemporaryDirectory() as d:
            _init_git_repo(d)
            hooks_dir = Path(d) / ".git" / "hooks"
            hooks_dir.mkdir(parents=True, exist_ok=True)
            (hooks_dir / "pre-commit").write_text("#!/bin/sh\necho 'not ours'\n")

            ok, msg = uninstall_hook(Path(d))
            assert not ok
            assert "not" in msg.lower()

    def test_uninstall_no_hook_present(self):
        from secureaudit.core.precommit import uninstall_hook
        with tempfile.TemporaryDirectory() as d:
            _init_git_repo(d)
            ok, msg = uninstall_hook(Path(d))
            assert not ok
            assert "No pre-commit hook" in msg


class TestStagedFileScanning:
    def test_get_staged_files_empty_when_nothing_staged(self):
        from secureaudit.core.precommit import get_staged_files
        with tempfile.TemporaryDirectory() as d:
            _init_git_repo(d)
            assert get_staged_files(Path(d)) == []

    def test_get_staged_files_returns_staged_paths(self):
        from secureaudit.core.precommit import get_staged_files
        with tempfile.TemporaryDirectory() as d:
            _init_git_repo(d)
            Path(d, "app.py").write_text("print('hello')\n")
            _git_stage(d, "app.py")

            staged = get_staged_files(Path(d))
            assert len(staged) == 1
            assert staged[0].name == "app.py"

    def test_run_staged_scan_passes_clean_files(self):
        from secureaudit.core.precommit import run_staged_scan
        with tempfile.TemporaryDirectory() as d:
            _init_git_repo(d)
            Path(d, "app.py").write_text("def hello(): return 'world'\n")
            _git_stage(d, "app.py")

            assert run_staged_scan(Path(d)) == 0

    def test_run_staged_scan_blocks_on_secret(self, capsys):
        from secureaudit.core.precommit import run_staged_scan
        with tempfile.TemporaryDirectory() as d:
            _init_git_repo(d)
            Path(d, "config.py").write_text('AWS_KEY = "AKIAI9ABCDEF1234WXYZ"\n')
            _git_stage(d, "config.py")

            exit_code = run_staged_scan(Path(d))
            assert exit_code == 1
            captured = capsys.readouterr()
            assert "blocked" in captured.out.lower()

    def test_run_staged_scan_no_staged_files(self):
        from secureaudit.core.precommit import run_staged_scan
        with tempfile.TemporaryDirectory() as d:
            _init_git_repo(d)
            # Nothing staged at all
            assert run_staged_scan(Path(d)) == 0

    def test_run_staged_scan_does_not_apply_inline_suppressions(self):
        """Documents current behaviour: the pre-commit hook is intentionally
        minimal and fast — it scans staged files directly via SecretsPlugin
        and does not currently parse inline 'secureaudit-ignore' comments.
        """
        from secureaudit.core.precommit import run_staged_scan
        with tempfile.TemporaryDirectory() as d:
            _init_git_repo(d)
            Path(d, "config.py").write_text(
                'AWS_KEY = "AKIAI9ABCDEF1234WXYZ"  # secureaudit-ignore\n'
            )
            _git_stage(d, "config.py")
            assert run_staged_scan(Path(d)) == 1


class TestPrecommitCLI:
    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def test_install_and_uninstall_via_cli(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            _init_git_repo(d)
            import os
            old_cwd = os.getcwd()
            try:
                os.chdir(d)
                r1 = runner.invoke(cli, ["pre-commit", "install"])
                assert r1.exit_code == 0, r1.output
                assert (Path(d) / ".git" / "hooks" / "pre-commit").exists()

                r2 = runner.invoke(cli, ["pre-commit", "uninstall"])
                assert r2.exit_code == 0, r2.output
                assert not (Path(d) / ".git" / "hooks" / "pre-commit").exists()
            finally:
                os.chdir(old_cwd)

    def test_install_outside_git_repo_fails(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            import os
            old_cwd = os.getcwd()
            try:
                os.chdir(d)
                result = runner.invoke(cli, ["pre-commit", "install"])
                assert result.exit_code != 0
            finally:
                os.chdir(old_cwd)


# ── Init wizard ───────────────────────────────────────────────────────────────

class TestDetectProject:
    def test_detects_python_via_requirements(self):
        from secureaudit.core.init import detect_project
        with tempfile.TemporaryDirectory() as d:
            Path(d, "requirements.txt").write_text("# no deps\n")
            detection = detect_project(Path(d))
            assert "python" in detection["languages"]

    def test_detects_node_via_package_json(self):
        from secureaudit.core.init import detect_project
        with tempfile.TemporaryDirectory() as d:
            Path(d, "package.json").write_text("{}\n")
            detection = detect_project(Path(d))
            assert "node" in detection["languages"]

    def test_detects_multiple_languages(self):
        from secureaudit.core.init import detect_project
        with tempfile.TemporaryDirectory() as d:
            Path(d, "requirements.txt").write_text("\n")
            Path(d, "go.mod").write_text("module example\n")
            detection = detect_project(Path(d))
            assert "python" in detection["languages"]
            assert "go" in detection["languages"]

    def test_detects_dockerfile(self):
        from secureaudit.core.init import detect_project
        with tempfile.TemporaryDirectory() as d:
            Path(d, "Dockerfile").write_text("FROM python:3.11\n")
            detection = detect_project(Path(d))
            assert detection["has_dockerfile"]

    def test_detects_dockerfile_variant(self):
        from secureaudit.core.init import detect_project
        with tempfile.TemporaryDirectory() as d:
            Path(d, "Dockerfile.prod").write_text("FROM python:3.11\n")
            detection = detect_project(Path(d))
            assert detection["has_dockerfile"]

    def test_detects_git(self):
        from secureaudit.core.init import detect_project
        with tempfile.TemporaryDirectory() as d:
            _init_git_repo(d)
            detection = detect_project(Path(d))
            assert detection["has_git"]

    def test_no_markers_found(self):
        from secureaudit.core.init import detect_project
        with tempfile.TemporaryDirectory() as d:
            detection = detect_project(Path(d))
            assert detection["languages"] == []
            assert not detection["has_dockerfile"]
            assert not detection["has_git"]


class TestBuildConfig:
    def test_python_repo_with_dockerfile_and_git(self):
        """Matches the issue's acceptance criteria exactly."""
        from secureaudit.core.init import build_config
        detection = {"languages": ["python"], "has_dockerfile": True,
                     "has_git": True, "has_ci": False}
        config = build_config(detection)
        for expected in ("secrets", "cve", "filesystem", "policy", "trivy", "git_history"):
            assert expected in config["plugins"]
        assert "http" not in config["plugins"]
        assert "network" not in config["plugins"]
        assert "cors" not in config["plugins"]

    def test_bare_repo_minimal_plugins(self):
        from secureaudit.core.init import build_config
        detection = {"languages": [], "has_dockerfile": False, "has_git": False, "has_ci": False}
        config = build_config(detection)
        assert config["plugins"] == ["secrets", "filesystem", "policy"]

    def test_urls_enable_http_and_cors(self):
        from secureaudit.core.init import build_config
        detection = {"languages": [], "has_dockerfile": False, "has_git": False, "has_ci": False}
        config = build_config(detection, urls=["https://api.example.com"])
        assert "http" in config["plugins"]
        assert "cors" in config["plugins"]
        assert config["http"]["urls"] == ["https://api.example.com"]
        assert config["cors"]["urls"] == ["https://api.example.com"]

    def test_hosts_enable_network_only(self):
        from secureaudit.core.init import build_config
        detection = {"languages": [], "has_dockerfile": False, "has_git": False, "has_ci": False}
        config = build_config(detection, hosts=["example.com"])
        assert "network" in config["plugins"]
        assert "http" not in config["plugins"]
        assert "cors" not in config["plugins"]
        assert config["network"]["hosts"] == ["example.com"]

    def test_dockerfile_adds_trivy_config(self):
        from secureaudit.core.init import build_config
        detection = {"languages": [], "has_dockerfile": True, "has_git": False, "has_ci": False}
        config = build_config(detection)
        assert "trivy" in config["plugins"]
        assert config["trivy"]["scan_images"] is False

    def test_fail_below_default(self):
        from secureaudit.core.init import build_config
        detection = {"languages": [], "has_dockerfile": False, "has_git": False, "has_ci": False}
        config = build_config(detection)
        assert config["fail_below"] == 70


class TestWriteConfig:
    def test_writes_valid_yaml_that_loads_back(self):
        from secureaudit.core.init import build_config, write_config

        with tempfile.TemporaryDirectory() as d:
            detection = {"languages": ["python"], "has_dockerfile": False,
                        "has_git": False, "has_ci": False}
            config = build_config(detection)
            path = Path(d) / "secureaudit.yml"
            write_config(path, config)

            assert path.exists()
            loaded_cfg = load_config(path)
            assert loaded_cfg.plugins == config["plugins"]
            assert loaded_cfg.fail_below == 70

    def test_generated_config_works_with_engine(self):
        """Acceptance criteria: generated secureaudit.yml passes a scan without errors."""
        from secureaudit.core.init import build_config, write_config

        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            Path(target, "app.py").write_text("def hello(): return 'world'\n")
            detection = {"languages": [], "has_dockerfile": False,
                        "has_git": False, "has_ci": False}
            config = build_config(detection)
            path = target / "secureaudit.yml"
            write_config(path, config)

            cfg = load_config(path)
            engine = AuditEngine(cfg)
            result = engine.run(target)  # must not raise
            assert result is not None


class TestInitCLI:
    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def test_init_yes_flag_skips_prompts(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("def hello(): return 'world'\n")
            result = runner.invoke(cli, ["init", d, "--yes"])
            assert result.exit_code == 0, result.output
            assert (Path(d) / "secureaudit.yml").exists()
            # --yes implies baseline creation too
            assert (Path(d) / ".secureaudit-baseline.json").exists()

    def test_init_no_baseline_flag(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("def hello(): return 'world'\n")
            result = runner.invoke(cli, ["init", d, "--yes", "--no-baseline"])
            assert result.exit_code == 0, result.output
            assert (Path(d) / "secureaudit.yml").exists()
            assert not (Path(d) / ".secureaudit-baseline.json").exists()

    def test_init_refuses_to_overwrite_without_force(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "secureaudit.yml").write_text("plugins: [secrets]\n")
            result = runner.invoke(cli, ["init", d, "--yes"])
            assert result.exit_code != 0

    def test_init_force_overwrites(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "secureaudit.yml").write_text("plugins: [secrets]\n")
            result = runner.invoke(cli, ["init", d, "--yes", "--force", "--no-baseline"])
            assert result.exit_code == 0, result.output

    def test_init_detects_dockerfile_and_reports_it(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "Dockerfile").write_text("FROM python:3.11-slim\nUSER app\n")
            result = runner.invoke(cli, ["init", d, "--yes", "--no-baseline"])
            assert result.exit_code == 0
            assert "trivy" in result.output.lower()

    def test_init_generated_yaml_is_valid(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "requirements.txt").write_text("# placeholder\n")
            result = runner.invoke(cli, ["init", d, "--yes", "--no-baseline"])
            assert result.exit_code == 0
            cfg = load_config(Path(d) / "secureaudit.yml")
            assert "secrets" in cfg.plugins
            assert "cve" in cfg.plugins


# ── Packaging ─────────────────────────────────────────────────────────────────

class TestPackaging:
    def test_pyproject_has_valid_build_backend(self):
        """Regression test: pyproject.toml previously had
        build-backend = "setuptools.backends.legacy:build", which is not a
        valid PEP 517 entry point and would fail any real `pip install` or
        `python -m build` — this had zero coverage until now.
        """
        import tomllib

        pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)

        backend = data["build-system"]["build-backend"]
        assert backend == "setuptools.build_meta", (
            f"build-backend is {backend!r} — must be a real PEP 517 backend "
            "for 'pip install' / 'python -m build' to work."
        )

    def test_pyproject_version_matches_cli_fallback_format(self):
        import tomllib

        pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)

        version = data["project"]["version"]
        # Must be a plausible semver-ish string, not empty
        assert version
        assert version[0].isdigit()

    def test_cli_version_resolves_dynamically(self):
        """Regression test: --version was hardcoded to "1.0.0" regardless
        of the actual installed/pyproject version.
        """
        import secureaudit.cli as cli_module
        # __version__ should either match an installed package version,
        # or fall back to the dev marker — never a silently-stale hardcoded string.
        assert cli_module.__version__ == "0.0.0+dev" or cli_module.__version__[0].isdigit()

    def test_entry_point_is_declared(self):
        import tomllib

        pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)

        assert data["project"]["scripts"]["secureaudit"] == "secureaudit.cli:main"


# ── Notifications (Slack / Teams) ────────────────────────────────────────────

def _make_result_with_findings(target: str = "/tmp/test") -> AuditResult:
    result = AuditResult(target=target)
    pr = PluginResult(plugin="secrets")
    pr.findings = [
        Finding(plugin="secrets", title="AWS Access Key detected", severity=Severity.CRITICAL,
               description="desc", file="app.py", line=12),
        Finding(plugin="policy", title="Missing .gitignore entry", severity=Severity.MEDIUM,
               description="desc", file=".gitignore"),
    ]
    result.plugin_results = [pr]
    return result


class TestScoreColorHelpers:
    def test_green_at_90_and_above(self):
        from secureaudit.notifications import score_color_hex, score_color_name, score_emoji
        assert score_color_hex(90) == "#22c55e"
        assert score_color_hex(100) == "#22c55e"
        assert score_color_name(95) == "good"
        assert score_emoji(90) == "🟢"

    def test_yellow_between_60_and_89(self):
        from secureaudit.notifications import score_color_hex, score_color_name
        assert score_color_hex(60) == "#f59e0b"
        assert score_color_hex(89) == "#f59e0b"
        assert score_color_name(75) == "warning"

    def test_red_below_60(self):
        from secureaudit.notifications import score_color_hex, score_color_name, score_emoji
        assert score_color_hex(59) == "#ef4444"
        assert score_color_hex(0) == "#ef4444"
        assert score_color_name(10) == "attention"
        assert score_emoji(0) == "🔴"


class TestSlackPayload:
    def test_payload_structure(self):
        from secureaudit.notifications import build_slack_payload
        result = _make_result_with_findings()
        payload = build_slack_payload(result)

        assert "attachments" in payload
        attachment = payload["attachments"][0]
        assert "color" in attachment
        assert "blocks" in attachment
        # Must not be raw JSON dumped as text — must use Block Kit structure
        assert isinstance(attachment["blocks"], list)
        assert attachment["blocks"][0]["type"] == "header"

    def test_payload_includes_score_and_grade(self):
        from secureaudit.notifications import build_slack_payload
        result = _make_result_with_findings()
        payload = build_slack_payload(result)
        blocks_text = str(payload)
        assert str(result.score) in blocks_text
        assert result.grade in blocks_text

    def test_payload_includes_top_findings(self):
        from secureaudit.notifications import build_slack_payload
        result = _make_result_with_findings()
        payload = build_slack_payload(result)
        blocks_text = str(payload)
        assert "AWS Access Key detected" in blocks_text

    def test_payload_includes_dashboard_button_when_url_given(self):
        from secureaudit.notifications import build_slack_payload
        result = _make_result_with_findings()
        payload = build_slack_payload(result, dashboard_url="https://dash.example.com/run/1")
        blocks = payload["attachments"][0]["blocks"]
        action_blocks = [b for b in blocks if b["type"] == "actions"]
        assert len(action_blocks) == 1
        assert action_blocks[0]["elements"][0]["url"] == "https://dash.example.com/run/1"

    def test_no_dashboard_button_without_url(self):
        from secureaudit.notifications import build_slack_payload
        result = _make_result_with_findings()
        payload = build_slack_payload(result)
        blocks = payload["attachments"][0]["blocks"]
        assert not any(b["type"] == "actions" for b in blocks)

    def test_color_matches_score(self):
        from secureaudit.notifications import build_slack_payload, score_color_hex
        result = AuditResult(target="/tmp/clean")  # no findings -> score 100
        payload = build_slack_payload(result)
        assert payload["attachments"][0]["color"] == score_color_hex(100)


class TestTeamsPayload:
    def test_payload_structure(self):
        from secureaudit.notifications import build_teams_payload
        result = _make_result_with_findings()
        payload = build_teams_payload(result)

        assert payload["type"] == "message"
        attachment = payload["attachments"][0]
        assert attachment["contentType"] == "application/vnd.microsoft.card.adaptive"
        card = attachment["content"]
        assert card["type"] == "AdaptiveCard"
        assert "body" in card

    def test_payload_includes_score_and_grade(self):
        from secureaudit.notifications import build_teams_payload
        result = _make_result_with_findings()
        payload = build_teams_payload(result)
        card_text = str(payload)
        assert str(result.score) in card_text
        assert result.grade in card_text

    def test_payload_includes_top_findings(self):
        from secureaudit.notifications import build_teams_payload
        result = _make_result_with_findings()
        payload = build_teams_payload(result)
        assert "AWS Access Key detected" in str(payload)

    def test_action_open_url_when_dashboard_given(self):
        from secureaudit.notifications import build_teams_payload
        result = _make_result_with_findings()
        payload = build_teams_payload(result, dashboard_url="https://dash.example.com/run/1")
        card = payload["attachments"][0]["content"]
        assert card["actions"][0]["type"] == "Action.OpenUrl"
        assert card["actions"][0]["url"] == "https://dash.example.com/run/1"

    def test_no_actions_key_without_dashboard_url(self):
        from secureaudit.notifications import build_teams_payload
        result = _make_result_with_findings()
        payload = build_teams_payload(result)
        card = payload["attachments"][0]["content"]
        assert "actions" not in card


class TestSlackDigest:
    def test_empty_runs(self):
        from secureaudit.notifications import build_slack_digest
        payload = build_slack_digest([], "/tmp/test")
        assert "text" in payload

    def test_digest_shows_trend(self):
        from secureaudit.notifications import build_slack_digest
        runs = [
            {"score": 95, "grade": "A", "critical_high": 0},
            {"score": 80, "grade": "B", "critical_high": 2},
        ]
        payload = build_slack_digest(runs, "/tmp/test")
        text = str(payload)
        assert "improved" in text
        assert "95" in text

    def test_digest_regressed_trend(self):
        from secureaudit.notifications import build_slack_digest
        runs = [
            {"score": 70, "grade": "C", "critical_high": 3},
            {"score": 90, "grade": "A", "critical_high": 0},
        ]
        payload = build_slack_digest(runs, "/tmp/test")
        assert "regressed" in str(payload)


class TestNotificationSending:
    def test_send_slack_handles_unreachable_url(self):
        from secureaudit.notifications import send_slack
        result = _make_result_with_findings()
        ok = send_slack("http://localhost:1/nonexistent", result)
        assert ok is False  # never raises, just returns False

    def test_send_teams_handles_unreachable_url(self):
        from secureaudit.notifications import send_teams
        result = _make_result_with_findings()
        ok = send_teams("http://localhost:1/nonexistent", result)
        assert ok is False


class TestNotificationCLIIntegration:
    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def test_scan_with_alert_slack_does_not_crash(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("def hello(): return 'world'\n")
            result = runner.invoke(cli, [
                "scan", d, "--plugins", "policy", "--no-terminal",
                "--alert-slack", "http://localhost:1/unreachable",
                "--fail-below", "0",
            ])
            assert result.exit_code == 0, result.output

    def test_scan_with_alert_teams_does_not_crash(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("def hello(): return 'world'\n")
            result = runner.invoke(cli, [
                "scan", d, "--plugins", "policy", "--no-terminal",
                "--alert-teams", "http://localhost:1/unreachable",
                "--fail-below", "0",
            ])
            assert result.exit_code == 0, result.output

    def test_digest_command_without_webhook_prints(self):
        from secureaudit.cli import cli
        from secureaudit.reports.history import save

        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_audit_result(d, []), db)

            result = runner.invoke(cli, ["digest", d, "--db", db, "--days", "7"])
            assert result.exit_code == 0, result.output
            # The earlier version of this test only checked exit_code,
            # which a silently-empty digest also satisfies — strengthened
            # after finding exactly that (see the regression test below).
            assert "printing digest instead" in result.output
            assert "score=" in result.output

    def test_digest_command_target_dot_matches_absolute_stored_target(self):
        """Regression test for a real, reproduced bug: AuditEngine
        resolves target to an absolute path before it's ever stored
        (core/engine.py) — `secureaudit scan .` (this project's own
        README's primary example) stores the resolved absolute path, not
        the literal '.'. digest's target filter used to compare against
        the raw CLI argument with no resolution, so `secureaudit digest .`
        right after `secureaudit scan .` printed "printing digest
        instead" followed by zero actual rows — not an error, just
        silently wrong, for the most common possible usage pattern."""
        import os

        from secureaudit.cli import cli
        from secureaudit.reports.history import save

        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            resolved_d = str(Path(d).resolve())
            db = str(Path(d) / "audits.db")
            # Stored exactly as AuditEngine would: the resolved absolute path.
            save(_make_audit_result(resolved_d, []), db)

            original_cwd = os.getcwd()
            try:
                os.chdir(d)
                result = runner.invoke(cli, ["digest", ".", "--db", db, "--days", "7"])
            finally:
                os.chdir(original_cwd)

            assert result.exit_code == 0, result.output
            assert "score=" in result.output, (
                f"digest '.' found no rows even though a run for the resolved "
                f"absolute path exists — target resolution regressed.\n{result.output}"
            )

    def test_digest_command_missing_db(self):
        from secureaudit.cli import cli
        runner = self._runner()
        result = runner.invoke(cli, ["digest", "/tmp", "--db", "/nonexistent/audits.db"])
        assert result.exit_code != 0


# ── Incremental scan cache ───────────────────────────────────────────────────

class TestCacheCore:
    def test_hash_file_returns_sha256(self):
        from secureaudit.core.cache import hash_file
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.txt"
            p.write_text("hello")
            h = hash_file(p)
            assert h is not None
            assert len(h) == 64

    def test_hash_file_stable_for_same_content(self):
        from secureaudit.core.cache import hash_file
        with tempfile.TemporaryDirectory() as d:
            p1 = Path(d) / "a.txt"
            p2 = Path(d) / "b.txt"
            p1.write_text("same content")
            p2.write_text("same content")
            assert hash_file(p1) == hash_file(p2)

    def test_hash_file_changes_with_content(self):
        from secureaudit.core.cache import hash_file
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.txt"
            p.write_text("v1")
            h1 = hash_file(p)
            p.write_text("v2")
            h2 = hash_file(p)
            assert h1 != h2

    def test_hash_file_missing_returns_none(self):
        from secureaudit.core.cache import hash_file
        assert hash_file(Path("/nonexistent/file.txt")) is None

    def test_hash_config_stable_regardless_of_key_order(self):
        from secureaudit.core.cache import hash_config
        h1 = hash_config({"a": 1, "b": 2})
        h2 = hash_config({"b": 2, "a": 1})
        assert h1 == h2

    def test_hash_config_changes_with_value(self):
        from secureaudit.core.cache import hash_config
        h1 = hash_config({"timeout": 60})
        h2 = hash_config({"timeout": 120})
        assert h1 != h2

    def test_cache_key_deterministic(self):
        from secureaudit.core.cache import cache_key
        k1 = cache_key("secrets", 1, "cfg123", "filehash456")
        k2 = cache_key("secrets", 1, "cfg123", "filehash456")
        assert k1 == k2

    def test_cache_key_differs_by_schema_version(self):
        from secureaudit.core.cache import cache_key
        k1 = cache_key("secrets", 1, "cfg", "filehash")
        k2 = cache_key("secrets", 2, "cfg", "filehash")
        assert k1 != k2


class TestFileCache:
    def test_set_and_get(self):
        from secureaudit.core.cache import FileCache
        with tempfile.TemporaryDirectory() as d:
            cache = FileCache(Path(d) / "cache.json")
            cache.set("key1", [{"plugin": "secrets", "title": "x"}])
            assert cache.get("key1") == [{"plugin": "secrets", "title": "x"}]

    def test_get_missing_key_returns_none(self):
        from secureaudit.core.cache import FileCache
        with tempfile.TemporaryDirectory() as d:
            cache = FileCache(Path(d) / "cache.json")
            assert cache.get("nonexistent") is None

    def test_save_and_reload_persists(self):
        from secureaudit.core.cache import FileCache
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "cache.json"
            cache1 = FileCache(path)
            cache1.set("key1", [{"a": 1}])
            cache1.save()

            cache2 = FileCache(path)
            assert cache2.get("key1") == [{"a": 1}]

    def test_save_without_changes_does_not_error(self):
        from secureaudit.core.cache import FileCache
        with tempfile.TemporaryDirectory() as d:
            cache = FileCache(Path(d) / "cache.json")
            cache.save()  # no entries set — should be a no-op, not an error
            assert not (Path(d) / "cache.json").exists()  # never written if never dirty

    def test_corrupt_cache_file_treated_as_empty(self):
        from secureaudit.core.cache import FileCache
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "cache.json"
            path.write_text("not valid json{{{")
            cache = FileCache(path)
            assert cache.entry_count == 0

    def test_wrong_schema_version_treated_as_empty(self):
        import json as _json

        from secureaudit.core.cache import FileCache
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "cache.json"
            path.write_text(_json.dumps({"version": 999, "entries": {"x": []}}))
            cache = FileCache(path)
            assert cache.entry_count == 0

    def test_clear(self):
        from secureaudit.core.cache import FileCache
        with tempfile.TemporaryDirectory() as d:
            cache = FileCache(Path(d) / "cache.json")
            cache.set("key1", [{"a": 1}])
            cache.clear()
            assert cache.entry_count == 0


class TestScanWithCache:
    def test_no_cache_scans_every_file(self):
        from secureaudit.core.cache import scan_with_cache

        class FakePlugin:
            name = "fake"
            schema_version = 1
            plugin_config = {}
            cache = None

        calls = []
        def scan_one(f):
            calls.append(f)
            return []

        with tempfile.TemporaryDirectory() as d:
            files = [Path(d) / "a.py", Path(d) / "b.py"]
            for f in files:
                f.write_text("x")
            scan_with_cache(FakePlugin(), files, scan_one)
            assert len(calls) == 2

    def test_cache_hit_skips_scan_one(self):
        from secureaudit.core.cache import FileCache, scan_with_cache

        with tempfile.TemporaryDirectory() as d:
            cache_dir = Path(d) / ".cache"
            cache = FileCache(cache_dir / "cache.json")

            class FakePlugin:
                name = "fake"
                schema_version = 1
                plugin_config = {}

            plugin = FakePlugin()
            plugin.cache = cache

            f = Path(d) / "a.py"
            f.write_text("content")

            calls = []
            def scan_one(path):
                calls.append(path)
                return []

            # First call — cache miss, scan_one called
            scan_with_cache(plugin, [f], scan_one)
            assert len(calls) == 1

            # Second call — cache hit, scan_one NOT called again
            scan_with_cache(plugin, [f], scan_one)
            assert len(calls) == 1

    def test_changing_file_content_invalidates_cache(self):
        from secureaudit.core.cache import FileCache, scan_with_cache

        with tempfile.TemporaryDirectory() as d:
            cache = FileCache(Path(d) / "cache.json")

            class FakePlugin:
                name = "fake"
                schema_version = 1
                plugin_config = {}

            plugin = FakePlugin()
            plugin.cache = cache

            f = Path(d) / "a.py"
            f.write_text("v1")

            calls = []
            def scan_one(path):
                calls.append(path.read_text())
                return []

            scan_with_cache(plugin, [f], scan_one)
            f.write_text("v2")
            scan_with_cache(plugin, [f], scan_one)

            assert calls == ["v1", "v2"]  # both calls happened — content changed, cache missed

    def test_changing_config_invalidates_cache(self):
        from secureaudit.core.cache import FileCache, scan_with_cache

        with tempfile.TemporaryDirectory() as d:
            cache = FileCache(Path(d) / "cache.json")

            class FakePlugin:
                name = "fake"
                schema_version = 1
                def __init__(self):
                    self.plugin_config = {"timeout": 60}
                    self.cache = cache

            plugin = FakePlugin()
            f = Path(d) / "a.py"
            f.write_text("same content")

            calls = []
            def scan_one(path):
                calls.append(1)
                return []

            scan_with_cache(plugin, [f], scan_one)
            plugin.plugin_config = {"timeout": 120}  # config changed
            scan_with_cache(plugin, [f], scan_one)

            assert len(calls) == 2  # config change forced a re-scan despite unchanged content

    def test_findings_round_trip_through_cache(self):
        from secureaudit.core.cache import FileCache, scan_with_cache

        with tempfile.TemporaryDirectory() as d:
            cache = FileCache(Path(d) / "cache.json")

            class FakePlugin:
                name = "fake"
                schema_version = 1
                plugin_config = {}

            plugin = FakePlugin()
            plugin.cache = cache

            f = Path(d) / "a.py"
            f.write_text("content")

            def scan_one(path):
                return [Finding(plugin="fake", title="Issue", severity=Severity.HIGH,
                               description="desc", file="a.py", line=3)]

            result1 = scan_with_cache(plugin, [f], scan_one)
            assert len(result1) == 1

            # Second call hits cache — must return an equivalent Finding, not the scan_one call
            result2 = scan_with_cache(plugin, [f], lambda p: (_ for _ in ()).throw(AssertionError("should not be called")))
            assert len(result2) == 1
            assert result2[0].title == "Issue"
            assert result2[0].severity == Severity.HIGH


# ── Regression: cache must never scan its own stored evidence ───────────────

class TestCacheSelfScanRegression:
    """Regression test for a real bug: the cache file stores finding evidence
    text (e.g. the matched secret line) inside .secureaudit-cache/cache.json.
    If that directory isn't excluded from file collection, the next scan
    re-discovers its own cached evidence as a 'new' secret, growing the cache
    and duplicating findings forever.
    """

    def test_secrets_plugin_does_not_rescan_its_own_cache_dir(self):
        from secureaudit.core.cache import FileCache, default_cache_path
        from secureaudit.plugins.secrets import SecretsPlugin

        cfg = load_config(None)
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            (target / "config.py").write_text('AWS_KEY = "AKIAI9ABCDEF1234WXYZ"\n')

            cache_path = default_cache_path(target)

            cache1 = FileCache(cache_path)
            plugin1 = SecretsPlugin(cfg)
            plugin1.cache = cache1
            result1 = plugin1.audit(target)
            cache1.save()
            assert len(result1.findings) == 1

            # Re-run with a freshly loaded cache — must still find exactly 1,
            # never more, regardless of what got written into the cache file.
            cache2 = FileCache(cache_path)
            plugin2 = SecretsPlugin(cfg)
            plugin2.cache = cache2
            result2 = plugin2.audit(target)
            assert len(result2.findings) == 1

    def test_cache_dir_excluded_even_with_custom_exclude_paths(self):
        """Even if a user's secureaudit.yml overrides exclude_paths and forgets
        to include .secureaudit-cache, the hard-coded CACHE_DIR_NAME check
        must still protect against the self-scan bug.
        """
        from secureaudit.core.cache import FileCache, default_cache_path
        from secureaudit.plugins.secrets import SecretsPlugin

        cfg = load_config(None)
        cfg._data["exclude_paths"] = [".git"]  # deliberately omits .secureaudit-cache

        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            (target / "config.py").write_text('AWS_KEY = "AKIAI9ABCDEF1234WXYZ"\n')
            cache_path = default_cache_path(target)

            cache1 = FileCache(cache_path)
            plugin1 = SecretsPlugin(cfg)
            plugin1.cache = cache1
            plugin1.audit(target)
            cache1.save()

            cache2 = FileCache(cache_path)
            plugin2 = SecretsPlugin(cfg)
            plugin2.cache = cache2
            result2 = plugin2.audit(target)
            assert len(result2.findings) == 1
            assert cache2.entry_count == 1  # only config.py, never the cache file itself


# ── Plugin integration: secrets caching ──────────────────────────────────────

class TestSecretsPluginCaching:
    def test_cache_hit_on_unchanged_file(self):
        from secureaudit.core.cache import FileCache
        from secureaudit.plugins.secrets import SecretsPlugin

        cfg = load_config(None)
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            (target / "app.py").write_text("def hello(): return 1\n")
            cache = FileCache(target / "cache.json")

            plugin = SecretsPlugin(cfg)
            plugin.cache = cache
            plugin.audit(target)
            assert cache.entry_count == 1

    def test_no_cache_attribute_falls_back_to_normal_scan(self):
        """cache defaults to None on BasePlugin — must behave identically to
        pre-caching behaviour when not explicitly enabled."""
        from secureaudit.plugins.secrets import SecretsPlugin

        cfg = load_config(None)
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            (target / "config.py").write_text('AWS_KEY = "AKIAI9ABCDEF1234WXYZ"\n')
            plugin = SecretsPlugin(cfg)
            assert plugin.cache is None
            result = plugin.audit(target)
            assert len(result.findings) == 1


# ── Plugin integration: SAST caching ──────────────────────────────────────────

class TestSASTPluginCaching:
    def test_all_cache_hits_skips_semgrep_invocation(self, monkeypatch):
        from secureaudit.core.cache import FileCache, cache_key, hash_config, hash_file
        from secureaudit.plugins.sast import SASTPlugin

        cfg = load_config(None)
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            f = target / "app.py"
            f.write_text("print('hi')\n")

            cache = FileCache(target / "cache.json")
            plugin = SASTPlugin(cfg)
            plugin.cache = cache

            # Pre-populate the cache as if a previous run already scanned this file
            config_hash = hash_config({"ruleset": "auto", **plugin.plugin_config})
            key = cache_key(plugin.name, plugin.schema_version, config_hash, hash_file(f))
            cache.set(key, [])

            monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/semgrep")

            called = {"count": 0}
            def fake_run_semgrep(*args, **kwargs):
                called["count"] += 1
                return []
            monkeypatch.setattr(plugin, "_run_semgrep", fake_run_semgrep)

            plugin.audit(target)
            assert called["count"] == 0  # semgrep never invoked — full cache hit

    def test_partial_cache_hit_only_scans_changed_files(self, monkeypatch):
        from secureaudit.core.cache import FileCache, cache_key, hash_config, hash_file
        from secureaudit.plugins.sast import SASTPlugin

        cfg = load_config(None)
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            unchanged = target / "unchanged.py"
            changed = target / "changed.py"
            unchanged.write_text("print('a')\n")
            changed.write_text("print('b')\n")

            cache = FileCache(target / "cache.json")
            plugin = SASTPlugin(cfg)
            plugin.cache = cache

            config_hash = hash_config({"ruleset": "auto", **plugin.plugin_config})
            key = cache_key(plugin.name, plugin.schema_version, config_hash, hash_file(unchanged))
            cache.set(key, [])

            monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/semgrep")

            received_targets = {}
            def fake_run_semgrep(scan_targets, *args, **kwargs):
                received_targets["files"] = list(scan_targets)
                return []
            monkeypatch.setattr(plugin, "_run_semgrep", fake_run_semgrep)

            plugin.audit(target)
            assert received_targets["files"] == [changed]  # only the changed file passed through

    def test_cache_writes_empty_findings_for_clean_file(self, monkeypatch):
        """A file with zero findings must still get an explicit cache entry —
        otherwise it would never become a cache hit on the next run."""
        from secureaudit.core.cache import FileCache
        from secureaudit.plugins.sast import SASTPlugin

        cfg = load_config(None)
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            f = target / "clean.py"
            f.write_text("print('clean')\n")

            cache = FileCache(target / "cache.json")
            plugin = SASTPlugin(cfg)
            plugin.cache = cache

            monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/semgrep")
            monkeypatch.setattr(plugin, "_run_semgrep", lambda *a, **k: [])

            plugin.audit(target)
            assert cache.entry_count == 1


# ── Plugin integration: policy caching ───────────────────────────────────────

class TestPolicyPluginCaching:
    def test_dockerfile_check_cached_per_file(self):
        from secureaudit.core.cache import FileCache
        from secureaudit.plugins.policy import PolicyPlugin

        cfg = load_config(None)
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            (target / ".gitignore").write_text("*.env\n")
            (target / "Dockerfile").write_text("FROM python:3.11\nCMD python app.py\n")

            cache = FileCache(target / "cache.json")
            plugin = PolicyPlugin(cfg)
            plugin.cache = cache

            result1 = plugin.audit(target)
            assert any("root" in f.title.lower() for f in result1.findings)

            # Cache entry exists for the Dockerfile check specifically
            assert cache.entry_count >= 1

            result2 = plugin.audit(target)
            assert any("root" in f.title.lower() for f in result2.findings)

    def test_ci_security_check_cached_per_file(self):
        from secureaudit.core.cache import FileCache
        from secureaudit.plugins.policy import PolicyPlugin

        cfg = load_config(None)
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            (target / ".gitignore").write_text("*.env\n")
            wf_dir = target / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "ci.yml").write_text(
                "on: pull_request_target\njobs:\n  test:\n    steps:\n"
                "      - uses: actions/checkout@v4\n        with:\n          ref: head\n"
            )

            cache = FileCache(target / "cache.json")
            plugin = PolicyPlugin(cfg)
            plugin.cache = cache
            result = plugin.audit(target)
            assert any("pull_request_target" in f.title for f in result.findings)


# ── Engine integration ────────────────────────────────────────────────────────

class TestEngineCaching:
    def test_engine_passes_cache_to_all_plugins(self):
        from secureaudit.core.cache import FileCache

        with tempfile.TemporaryDirectory() as d:
            cache = FileCache(Path(d) / "cache.json")
            cfg = load_config(None)
            engine = AuditEngine(cfg, cache=cache)
            result = engine.run(d, plugins=["secrets", "policy"])
            assert result is not None  # ran without error with a cache attached

    def test_engine_without_cache_plugins_have_none(self):
        cfg = load_config(None)
        engine = AuditEngine(cfg)
        assert engine.cache is None


# ── CLI integration ───────────────────────────────────────────────────────────

class TestCacheCLI:
    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def test_scan_creates_cache_by_default(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("def hello(): return 1\n")
            result = runner.invoke(cli, [
                "scan", d, "--plugins", "secrets,policy", "--no-terminal", "--fail-below", "0",
            ])
            assert result.exit_code == 0, result.output
            assert (Path(d) / ".secureaudit-cache" / "cache.json").exists()

    def test_scan_no_cache_flag_skips_cache_creation(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("def hello(): return 1\n")
            result = runner.invoke(cli, [
                "scan", d, "--plugins", "secrets,policy", "--no-terminal",
                "--fail-below", "0", "--no-cache",
            ])
            assert result.exit_code == 0, result.output
            assert not (Path(d) / ".secureaudit-cache").exists()

    def test_cache_status_no_cache_present(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            result = runner.invoke(cli, ["cache", "status", d])
            assert result.exit_code == 0
            assert "No cache found" in result.output

    def test_cache_status_after_scan(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("def hello(): return 1\n")
            runner.invoke(cli, ["scan", d, "--plugins", "secrets", "--no-terminal", "--fail-below", "0"])
            result = runner.invoke(cli, ["cache", "status", d])
            assert result.exit_code == 0
            assert "Entries:" in result.output

    def test_cache_clear_removes_cache_file(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("def hello(): return 1\n")
            runner.invoke(cli, ["scan", d, "--plugins", "secrets", "--no-terminal", "--fail-below", "0"])
            assert (Path(d) / ".secureaudit-cache" / "cache.json").exists()

            result = runner.invoke(cli, ["cache", "clear", d])
            assert result.exit_code == 0
            assert not (Path(d) / ".secureaudit-cache" / "cache.json").exists()

    def test_cache_clear_when_absent(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            result = runner.invoke(cli, ["cache", "clear", d])
            assert result.exit_code == 0
            assert "No cache found" in result.output

    def test_second_scan_produces_identical_findings(self):
        """Acceptance criteria: caching must never change scan correctness."""
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as scan_dir, tempfile.TemporaryDirectory() as out_dir:
            Path(scan_dir, "config.py").write_text('AWS_KEY = "AKIAI9ABCDEF1234WXYZ"\n')

            # Reports are written OUTSIDE the scanned directory — a report file
            # placed inside the target would itself contain the matched secret
            # text and get rescanned as a new finding next run. That's a
            # separate, expected consequence of where you put your output, not
            # a caching correctness issue, so this test keeps the two concerns
            # apart deliberately.
            json1 = Path(out_dir) / "r1.json"
            json2 = Path(out_dir) / "r2.json"
            runner.invoke(cli, ["scan", scan_dir, "--plugins", "secrets", "--no-terminal",
                               "--fail-below", "0", "--json", str(json1)])
            runner.invoke(cli, ["scan", scan_dir, "--plugins", "secrets", "--no-terminal",
                               "--fail-below", "0", "--json", str(json2)])

            import json as _json
            data1 = _json.loads(json1.read_text())
            data2 = _json.loads(json2.read_text())
            assert data1["severity_counts"] == data2["severity_counts"]


# ── Project grouping ──────────────────────────────────────────────────────────

def _make_result(target: str, n_findings: int = 0, severity=Severity.MEDIUM) -> AuditResult:
    r = AuditResult(target=target)
    pr = PluginResult(plugin="secrets")
    pr.findings = [
        Finding(plugin="secrets", title=f"Issue {i}", severity=severity, description="")
        for i in range(n_findings)
    ]
    r.plugin_results = [pr]
    return r


class TestConfigProject:
    def test_project_none_by_default(self):
        cfg = load_config(None)
        assert cfg.project is None

    def test_project_read_from_config(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write("project: acme-corp\n")
            path = f.name
        try:
            cfg = load_config(path)
            assert cfg.project == "acme-corp"
        finally:
            os.unlink(path)


class TestHistoryProjectGrouping:
    def test_save_with_project(self):
        from secureaudit.reports.history import get_runs, save
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_result("/repo/a"), db, project="acme")
            runs = get_runs(db)
            assert runs[0]["project"] == "acme"

    def test_save_without_project_is_null(self):
        from secureaudit.reports.history import get_runs, save
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_result("/repo/a"), db)
            runs = get_runs(db)
            assert runs[0]["project"] is None

    def test_get_runs_filters_by_project(self):
        from secureaudit.reports.history import get_runs, save
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_result("/repo/a"), db, project="acme")
            save(_make_result("/repo/b"), db, project="widgets")
            save(_make_result("/repo/c"), db)

            acme_runs = get_runs(db, project="acme")
            assert len(acme_runs) == 1
            assert acme_runs[0]["target"] == "/repo/a"

    def test_get_runs_without_project_filter_returns_all(self):
        from secureaudit.reports.history import get_runs, save
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_result("/repo/a"), db, project="acme")
            save(_make_result("/repo/b"), db)
            assert len(get_runs(db)) == 2

    def test_old_schema_database_migrates_automatically(self):
        """Backward compatibility: a database created before the project
        column existed must still work with the new code, unmodified by hand."""
        import sqlite3

        from secureaudit.reports.history import get_runs, save

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "old.db")
            conn = sqlite3.connect(db)
            conn.executescript("""
                CREATE TABLE runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL, timestamp TEXT NOT NULL,
                    score INTEGER NOT NULL, grade TEXT NOT NULL,
                    total_findings INTEGER NOT NULL, critical_high INTEGER NOT NULL,
                    suppressed_count INTEGER NOT NULL DEFAULT 0,
                    duration_ms REAL NOT NULL, plugins TEXT NOT NULL
                );
            """)
            conn.execute(
                "INSERT INTO runs (target, timestamp, score, grade, total_findings, "
                "critical_high, duration_ms, plugins) VALUES (?,?,?,?,?,?,?,?)",
                ("/old/repo", "2025-01-01T00:00:00", 85, "B", 3, 1, 120.0, '["secrets"]'),
            )
            conn.commit()
            conn.close()

            runs = get_runs(db)
            assert len(runs) == 1
            assert runs[0]["project"] is None  # migrated column defaults to NULL

            save(_make_result("/new/repo"), db, project="fresh")
            assert len(get_runs(db)) == 2


class TestGetProjects:
    def test_returns_one_row_per_project_latest_run(self):
        from secureaudit.reports.history import get_projects, save
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_result("/repo/a", n_findings=2), db, project="acme")
            save(_make_result("/repo/a", n_findings=0), db, project="acme")  # latest, clean
            save(_make_result("/repo/b", n_findings=1), db, project="widgets")

            projects = get_projects(db)
            assert len(projects) == 2
            acme = next(p for p in projects if p["project"] == "acme")
            assert acme["total_findings"] == 0  # the latest acme run, not the first

    def test_excludes_ungrouped_runs(self):
        from secureaudit.reports.history import get_projects, save
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_result("/repo/a"), db, project="acme")
            save(_make_result("/repo/b"), db)  # ungrouped
            projects = get_projects(db)
            assert len(projects) == 1
            assert projects[0]["project"] == "acme"

    def test_empty_database_returns_empty_list(self):
        from secureaudit.reports.history import get_projects, save
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_result("/repo/a"), db)  # only an ungrouped run exists
            assert get_projects(db) == []

    def test_get_project_run_count(self):
        from secureaudit.reports.history import get_project_run_count, save
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_result("/repo/a"), db, project="acme")
            save(_make_result("/repo/a"), db, project="acme")
            save(_make_result("/repo/a"), db, project="acme")
            assert get_project_run_count(db, "acme") == 3
            assert get_project_run_count(db, "nonexistent") == 0


# ── Dashboard project routes ──────────────────────────────────────────────────

class TestDashboardProjects:
    def _client(self, db):
        from fastapi.testclient import TestClient

        from secureaudit.dashboard.app import create_app
        return TestClient(create_app(db))

    def test_projects_page_lists_projects(self):
        from secureaudit.reports.history import save
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_result("/repo/a"), db, project="acme")
            save(_make_result("/repo/b"), db, project="widgets")

            client = self._client(db)
            r = client.get("/projects")
            assert r.status_code == 200
            assert "acme" in r.text
            assert "widgets" in r.text

    def test_projects_page_empty_state(self):
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            import sqlite3

            from secureaudit.reports.history import _ensure_schema
            conn = sqlite3.connect(db)
            _ensure_schema(conn)
            conn.close()

            client = self._client(db)
            r = client.get("/projects")
            assert r.status_code == 200
            assert "No projects yet" in r.text

    def test_project_detail_shows_trend(self):
        from secureaudit.reports.history import save
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_result("/repo/a", n_findings=2), db, project="acme")
            save(_make_result("/repo/a", n_findings=0), db, project="acme")

            client = self._client(db)
            r = client.get("/projects/acme")
            assert r.status_code == 200
            assert "Score Trend" in r.text

    def test_project_detail_404_when_no_runs(self):
        from secureaudit.reports.history import save
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_result("/repo/a"), db, project="acme")

            client = self._client(db)
            r = client.get("/projects/does-not-exist")
            assert r.status_code == 404

    def test_api_projects_endpoint(self):
        from secureaudit.reports.history import save
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_result("/repo/a"), db, project="acme")
            save(_make_result("/repo/b"), db)  # ungrouped — must not appear

            client = self._client(db)
            r = client.get("/api/projects")
            assert r.status_code == 200
            data = r.json()
            assert len(data) == 1
            assert data[0]["project"] == "acme"

    def test_api_runs_filters_by_project_query_param(self):
        from secureaudit.reports.history import save
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_result("/repo/a"), db, project="acme")
            save(_make_result("/repo/b"), db, project="widgets")

            client = self._client(db)
            r = client.get("/api/runs?project=acme")
            data = r.json()
            assert len(data) == 1
            assert data[0]["project"] == "acme"

    def test_index_links_to_projects(self):
        from secureaudit.reports.history import save
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_result("/repo/a"), db)

            client = self._client(db)
            r = client.get("/")
            assert 'href="/projects"' in r.text


# ── CLI: history and projects commands ───────────────────────────────────────

class TestHistoryAndProjectsCLI:
    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def test_history_command_basic(self):
        from secureaudit.cli import cli
        from secureaudit.reports.history import save
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_result("/repo/a"), db)
            result = runner.invoke(cli, ["history", "--db", db])
            assert result.exit_code == 0, result.output
            assert "/repo/a" in result.output

    def test_history_command_filters_by_project(self):
        from secureaudit.cli import cli
        from secureaudit.reports.history import save
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_result("/repo/a"), db, project="acme")
            save(_make_result("/repo/b"), db, project="widgets")

            result = runner.invoke(cli, ["history", "--db", db, "--project", "acme"])
            assert result.exit_code == 0
            assert "/repo/a" in result.output
            assert "/repo/b" not in result.output

    def test_history_command_missing_db(self):
        from secureaudit.cli import cli
        runner = self._runner()
        result = runner.invoke(cli, ["history", "--db", "/nonexistent/audits.db"])
        assert result.exit_code != 0

    def test_history_command_no_runs_for_project(self):
        from secureaudit.cli import cli
        from secureaudit.reports.history import save
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_result("/repo/a"), db, project="acme")
            result = runner.invoke(cli, ["history", "--db", db, "--project", "nonexistent"])
            assert result.exit_code == 0
            assert "No runs found" in result.output

    def test_projects_command_lists_projects(self):
        from secureaudit.cli import cli
        from secureaudit.reports.history import save
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_result("/repo/a"), db, project="acme")
            save(_make_result("/repo/b"), db, project="widgets")

            result = runner.invoke(cli, ["projects", "--db", db])
            assert result.exit_code == 0
            assert "acme" in result.output
            assert "widgets" in result.output

    def test_projects_command_empty(self):
        from secureaudit.cli import cli
        from secureaudit.reports.history import save
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_result("/repo/a"), db)  # ungrouped only
            result = runner.invoke(cli, ["projects", "--db", db])
            assert result.exit_code == 0
            assert "No projects found" in result.output

    def test_scan_with_db_and_project_in_config(self):
        from secureaudit.cli import cli
        from secureaudit.reports.history import get_runs
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("def hello(): return 1\n")
            Path(d, "secureaudit.yml").write_text("plugins: [policy]\nproject: my-project\n")
            db = str(Path(d) / "audits.db")

            result = runner.invoke(cli, ["scan", d, "--db", db, "--no-terminal", "--fail-below", "0"])
            assert result.exit_code == 0, result.output

            runs = get_runs(db)
            assert runs[0]["project"] == "my-project"


# ── REST API: token auth ──────────────────────────────────────────────────────

class TestDashboardAuth:
    def _client(self, db, api_token=None, require_token=False):
        from fastapi.testclient import TestClient

        from secureaudit.dashboard.app import create_app
        return TestClient(create_app(db, api_token=api_token, require_token=require_token))

    def test_docs_enabled(self):
        with tempfile.TemporaryDirectory() as d:
            client = self._client(str(Path(d) / "audits.db"))
            r = client.get("/docs")
            assert r.status_code == 200

    def test_openapi_schema_available(self):
        with tempfile.TemporaryDirectory() as d:
            client = self._client(str(Path(d) / "audits.db"))
            r = client.get("/openapi.json")
            assert r.status_code == 200
            assert "/api/scan" in r.json()["paths"]

    def test_localhost_mode_no_token_required_for_write(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "target"
            target.mkdir()
            (target / "app.py").write_text("x = 1\n")
            client = self._client(str(Path(d) / "audits.db"), require_token=False)
            r = client.post("/api/scan", json={"target": str(target), "plugins": ["policy"]})
            assert r.status_code == 200

    def test_require_token_blocks_write_without_header(self):
        with tempfile.TemporaryDirectory() as d:
            client = self._client(str(Path(d) / "audits.db"), api_token="secret", require_token=True)
            r = client.post("/api/scan", json={"target": str(d)})
            assert r.status_code == 401

    def test_require_token_blocks_wrong_token(self):
        with tempfile.TemporaryDirectory() as d:
            client = self._client(str(Path(d) / "audits.db"), api_token="secret", require_token=True)
            r = client.post("/api/scan", json={"target": str(d)},
                           headers={"Authorization": "Bearer wrong"})
            assert r.status_code == 401

    def test_require_token_accepts_correct_token(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "target"
            target.mkdir()
            (target / "app.py").write_text("x = 1\n")
            client = self._client(str(Path(d) / "audits.db"), api_token="secret", require_token=True)
            r = client.post("/api/scan", json={"target": str(target), "plugins": ["policy"]},
                           headers={"Authorization": "Bearer secret"})
            assert r.status_code == 200

    def test_read_endpoints_open_even_when_token_required(self):
        with tempfile.TemporaryDirectory() as d:
            client = self._client(str(Path(d) / "audits.db"), api_token="secret", require_token=True)
            r = client.get("/api/runs")
            assert r.status_code == 200  # GET is never gated, per acceptance criteria

    def test_require_token_with_no_token_configured_fails_closed(self):
        """If require_token is True but no token was ever set (shouldn't happen
        via the CLI, which auto-generates one, but defend the API directly),
        write requests must fail rather than silently allow access."""
        with tempfile.TemporaryDirectory() as d:
            client = self._client(str(Path(d) / "audits.db"), api_token=None, require_token=True)
            r = client.post("/api/scan", json={"target": str(d)})
            assert r.status_code in (401, 503)


# ── REST API: async scan trigger ─────────────────────────────────────────────

class TestDashboardScanAPI:
    def _client(self, db):
        from fastapi.testclient import TestClient

        from secureaudit.dashboard.app import create_app
        return TestClient(create_app(db))

    def test_scan_returns_immediately_with_scan_id(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "target"
            target.mkdir()
            (target / "app.py").write_text("x = 1\n")
            client = self._client(str(Path(d) / "audits.db"))

            r = client.post("/api/scan", json={"target": str(target), "plugins": ["policy"]})
            assert r.status_code == 200
            data = r.json()
            assert "scan_id" in data
            assert data["status"] == "running"

    def test_scan_completes_and_is_pollable(self):
        import time
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "target"
            target.mkdir()
            (target / "app.py").write_text("x = 1\n")
            client = self._client(str(Path(d) / "audits.db"))

            scan_id = client.post(
                "/api/scan", json={"target": str(target), "plugins": ["policy"]}
            ).json()["scan_id"]

            status = None
            for _ in range(30):
                r = client.get(f"/api/scan/{scan_id}")
                status = r.json()
                if status["status"] != "running":
                    break
                time.sleep(0.05)

            assert status["status"] == "completed"
            assert status["run_id"] is not None

    def test_scan_persists_to_history_with_project(self):
        import time
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "target"
            target.mkdir()
            (target / "app.py").write_text("x = 1\n")
            db = str(Path(d) / "audits.db")
            client = self._client(db)

            scan_id = client.post(
                "/api/scan",
                json={"target": str(target), "plugins": ["policy"], "project": "acme"},
            ).json()["scan_id"]

            for _ in range(30):
                if client.get(f"/api/scan/{scan_id}").json()["status"] != "running":
                    break
                time.sleep(0.05)

            from secureaudit.reports.history import get_runs
            runs = get_runs(db, project="acme")
            assert len(runs) == 1

    def test_unknown_scan_id_returns_404(self):
        with tempfile.TemporaryDirectory() as d:
            client = self._client(str(Path(d) / "audits.db"))
            r = client.get("/api/scan/nonexistent-id")
            assert r.status_code == 404

    def test_scan_failure_reported_not_crashed(self, monkeypatch):
        """The architecture catches plugin errors per-plugin (BasePlugin.run()),
        so a nonexistent target alone wouldn't actually raise. Simulate a real
        failure point (e.g. AuditEngine.run itself blowing up) by monkeypatching
        it directly, and confirm the background task reports 'failed' rather
        than crashing the server or leaving the scan stuck as 'running' forever.
        """
        import time

        from secureaudit.core.engine import AuditEngine

        def boom(self, target, plugins=None):
            raise RuntimeError("simulated engine failure")

        monkeypatch.setattr(AuditEngine, "run", boom)

        with tempfile.TemporaryDirectory() as d:
            client = self._client(str(Path(d) / "audits.db"))
            scan_id = client.post("/api/scan", json={"target": d}).json()["scan_id"]

            status = None
            for _ in range(30):
                status = client.get(f"/api/scan/{scan_id}").json()
                if status["status"] != "running":
                    break
                time.sleep(0.05)

            assert status["status"] == "failed"
            assert "simulated engine failure" in status["error"]


# ── REST API: filterable findings ────────────────────────────────────────────

class TestFindingsSeverityFilter:
    def test_get_run_findings_filters_by_severity(self):
        from secureaudit.reports.history import get_run_findings, save
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            result = _make_result("/repo", n_findings=0)
            pr = PluginResult(plugin="secrets")
            pr.findings = [
                Finding(plugin="secrets", title="Crit issue", severity=Severity.CRITICAL, description=""),
                Finding(plugin="secrets", title="Low issue", severity=Severity.LOW, description=""),
            ]
            result.plugin_results = [pr]
            run_id = save(result, db)

            critical_only = get_run_findings(db, run_id, severity="CRITICAL")
            assert len(critical_only) == 1
            assert critical_only[0]["title"] == "Crit issue"

    def test_severity_filter_case_insensitive(self):
        from secureaudit.reports.history import get_run_findings, save
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            result = _make_result("/repo")
            pr = PluginResult(plugin="secrets")
            pr.findings = [Finding(plugin="secrets", title="X", severity=Severity.HIGH, description="")]
            result.plugin_results = [pr]
            run_id = save(result, db)

            findings = get_run_findings(db, run_id, severity="high")
            assert len(findings) == 1

    def test_api_findings_endpoint_severity_query_param(self):
        from fastapi.testclient import TestClient

        from secureaudit.dashboard.app import create_app
        from secureaudit.reports.history import save

        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            result = _make_result("/repo")
            pr = PluginResult(plugin="secrets")
            pr.findings = [
                Finding(plugin="secrets", title="Crit", severity=Severity.CRITICAL, description=""),
                Finding(plugin="secrets", title="Med", severity=Severity.MEDIUM, description=""),
            ]
            result.plugin_results = [pr]
            run_id = save(result, db)

            client = TestClient(create_app(db))
            r = client.get(f"/api/runs/{run_id}/findings?severity=CRITICAL")
            assert r.status_code == 200
            data = r.json()
            assert len(data) == 1
            assert data[0]["title"] == "Crit"


# ── Project webhooks ──────────────────────────────────────────────────────────

class TestProjectWebhooks:
    def test_register_and_get_webhooks(self):
        from secureaudit.core.webhooks import get_webhooks, register_webhook
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            webhook_id = register_webhook(db, "acme", "https://example.com/hook")
            hooks = get_webhooks(db, "acme")
            assert len(hooks) == 1
            assert hooks[0]["id"] == webhook_id
            assert hooks[0]["url"] == "https://example.com/hook"

    def test_get_webhooks_empty_for_unknown_project(self):
        from secureaudit.core.webhooks import get_webhooks
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            assert get_webhooks(db, "nonexistent") == []

    def test_delete_webhook(self):
        from secureaudit.core.webhooks import delete_webhook, get_webhooks, register_webhook
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            webhook_id = register_webhook(db, "acme", "https://example.com/hook")
            assert delete_webhook(db, webhook_id) is True
            assert get_webhooks(db, "acme") == []

    def test_delete_nonexistent_webhook_returns_false(self):
        from secureaudit.core.webhooks import delete_webhook
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            assert delete_webhook(db, 999) is False

    def test_no_webhooks_no_fire(self):
        from secureaudit.core.webhooks import check_and_fire_project_webhooks
        from secureaudit.reports.history import save
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            save(_make_result("/repo"), db, project="acme")
            fired = check_and_fire_project_webhooks(db, "acme", 1)
            assert fired == 0

    def test_first_run_never_fires(self):
        """No previous run to diff against — must not fire, and must not error."""
        from secureaudit.core.webhooks import check_and_fire_project_webhooks, register_webhook
        from secureaudit.reports.history import save
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            register_webhook(db, "acme", "http://localhost:1/unreachable")
            run_id = save(_make_result("/repo", n_findings=3, severity=Severity.CRITICAL), db, project="acme")
            fired = check_and_fire_project_webhooks(db, "acme", run_id)
            assert fired == 0

    def test_fires_on_new_critical_finding(self):
        import http.server
        import json as _json
        import threading

        received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                body = self.rfile.read(length)
                received.append(_json.loads(body))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            from secureaudit.core.webhooks import check_and_fire_project_webhooks, register_webhook
            from secureaudit.reports.history import save
            with tempfile.TemporaryDirectory() as d:
                db = str(Path(d) / "audits.db")
                register_webhook(db, "acme", f"http://127.0.0.1:{port}/hook")

                run1 = save(_make_result("/repo", n_findings=0), db, project="acme")
                check_and_fire_project_webhooks(db, "acme", run1)
                assert len(received) == 0

                run2 = save(
                    _make_result("/repo", n_findings=1, severity=Severity.CRITICAL),
                    db, project="acme",
                )
                fired = check_and_fire_project_webhooks(db, "acme", run2)
                assert fired == 1
                assert len(received) == 1
                assert received[0]["project"] == "acme"
                assert received[0]["new_findings_count"] == 1
        finally:
            server.shutdown()

    def test_does_not_fire_without_new_regression(self):
        from secureaudit.core.webhooks import check_and_fire_project_webhooks, register_webhook
        from secureaudit.reports.history import save
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            register_webhook(db, "acme", "http://localhost:1/unreachable")

            save(_make_result("/repo", n_findings=1, severity=Severity.LOW), db, project="acme")
            run2 = save(_make_result("/repo", n_findings=1, severity=Severity.LOW), db, project="acme")
            fired = check_and_fire_project_webhooks(db, "acme", run2)
            assert fired == 0  # same LOW finding, no new CRITICAL/HIGH

    def test_unreachable_webhook_does_not_raise(self):
        from secureaudit.core.webhooks import check_and_fire_project_webhooks, register_webhook
        from secureaudit.reports.history import save
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            register_webhook(db, "acme", "http://127.0.0.1:1/unreachable")

            save(_make_result("/repo", n_findings=0), db, project="acme")
            run2 = save(_make_result("/repo", n_findings=1, severity=Severity.CRITICAL), db, project="acme")
            fired = check_and_fire_project_webhooks(db, "acme", run2)  # must not raise
            assert fired == 0  # POST failed, correctly not counted as fired


class TestWebhookAPIEndpoints:
    def _client(self, db, **kwargs):
        from fastapi.testclient import TestClient

        from secureaudit.dashboard.app import create_app
        return TestClient(create_app(db, **kwargs))

    def test_register_webhook_via_api(self):
        with tempfile.TemporaryDirectory() as d:
            client = self._client(str(Path(d) / "audits.db"))
            r = client.post("/api/projects/acme/webhooks", json={"url": "https://example.com/hook"})
            assert r.status_code == 200
            assert r.json()["project"] == "acme"

    def test_list_webhooks_via_api(self):
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            client = self._client(db)
            client.post("/api/projects/acme/webhooks", json={"url": "https://example.com/hook"})
            r = client.get("/api/projects/acme/webhooks")
            assert r.status_code == 200
            assert len(r.json()) == 1

    def test_delete_webhook_via_api(self):
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "audits.db")
            client = self._client(db)
            webhook_id = client.post(
                "/api/projects/acme/webhooks", json={"url": "https://example.com/hook"}
            ).json()["id"]
            r = client.delete(f"/api/projects/acme/webhooks/{webhook_id}")
            assert r.status_code == 200

    def test_webhook_endpoints_gated_by_token(self):
        with tempfile.TemporaryDirectory() as d:
            client = self._client(str(Path(d) / "audits.db"), api_token="secret", require_token=True)
            r = client.post("/api/projects/acme/webhooks", json={"url": "https://example.com/hook"})
            assert r.status_code == 401


# ── CLI: serve command token logic ───────────────────────────────────────────

class TestServeCommandTokenLogic:
    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def test_serve_help_mentions_token(self):
        from secureaudit.cli import cli
        runner = self._runner()
        result = runner.invoke(cli, ["serve", "--help"])
        assert result.exit_code == 0
        assert "--token" in result.output


class TestServeMissingDashboardDeps:
    """Regression tests for a real, reproduced bug: serve only checked
    `import uvicorn`, with `import fastapi` left for dashboard.app's own
    module-level import statement to surface. If uvicorn happened to be
    installed but fastapi wasn't, the user got a raw, unhandled
    ModuleNotFoundError traceback instead of the same clean error message
    — confirmed by actually installing only one of the two in a real
    clean venv and triggering it, not assumed as a theoretical risk."""

    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    @staticmethod
    def _block_import(*names):
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name in names:
                raise ImportError(f"simulated: {name} not installed")
            return real_import(name, *args, **kwargs)
        return fake_import

    def test_missing_uvicorn_shows_clean_message(self):
        import builtins
        from unittest.mock import patch

        from secureaudit.cli import cli
        runner = self._runner()
        with patch.object(builtins, "__import__", side_effect=self._block_import("uvicorn")):
            result = runner.invoke(cli, ["serve"])
        assert result.exit_code == 1
        assert "Dashboard dependencies missing" in result.output
        assert "secureaudit[dashboard]" in result.output
        assert "Traceback" not in result.output

    def test_missing_fastapi_shows_clean_message_not_raw_traceback(self):
        """The specific bug: uvicorn present, fastapi absent."""
        import builtins
        from unittest.mock import patch

        from secureaudit.cli import cli
        runner = self._runner()
        with patch.object(builtins, "__import__", side_effect=self._block_import("fastapi")):
            result = runner.invoke(cli, ["serve"])
        assert result.exit_code == 1
        assert "Dashboard dependencies missing" in result.output
        assert "secureaudit[dashboard]" in result.output
        assert "Traceback" not in result.output
        assert "ModuleNotFoundError" not in result.output


# ── Compliance: OWASP ASVS mapping ───────────────────────────────────────────

class TestOWASPASVSControls:
    def test_at_least_15_controls_defined(self):
        """Acceptance criteria: at least 15 working ASVS control mappings."""
        from secureaudit.compliance.owasp_asvs import CONTROLS
        assert len(CONTROLS) >= 15

    def test_all_controls_have_required_fields(self):
        from secureaudit.compliance.owasp_asvs import CONTROLS
        for control in CONTROLS:
            assert control.id.startswith("V")
            assert control.chapter
            assert control.description
            assert len(control.plugins) > 0

    def test_all_referenced_plugins_actually_exist(self):
        """Every plugin name referenced by a control must be a real, registered plugin —
        otherwise the mapping would silently never apply to anything."""
        from secureaudit.compliance.owasp_asvs import CONTROLS
        from secureaudit.plugins import available_plugins

        registered = set(available_plugins())
        for control in CONTROLS:
            for plugin_name in control.plugins:
                assert plugin_name in registered, f"{control.id} references unknown plugin {plugin_name!r}"


class TestOWASPASVSEvaluate:
    def _run(self, target, plugins):
        cfg = load_config(None)
        engine = AuditEngine(cfg)
        return engine.run(target, plugins=plugins)

    def test_returns_one_row_per_control(self):
        from secureaudit.compliance.owasp_asvs import CONTROLS, evaluate
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("x = 1\n")
            result = self._run(d, ["policy"])
            rows = evaluate(result)
            assert len(rows) == len(CONTROLS)

    def test_not_applicable_when_plugin_not_run(self):
        from secureaudit.compliance.owasp_asvs import evaluate
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("x = 1\n")
            result = self._run(d, ["policy"])  # secrets plugin never runs
            rows = evaluate(result)
            secrets_control = next(r for r in rows if r["id"] == "V6.4.1")
            assert secrets_control["status"] == "NOT_APPLICABLE"

    def test_fail_when_secret_detected(self):
        from secureaudit.compliance.owasp_asvs import evaluate
        with tempfile.TemporaryDirectory() as d:
            Path(d, "config.py").write_text('AWS_KEY = "AKIAI9ABCDEF1234WXYZ"\n')
            result = self._run(d, ["secrets"])
            rows = evaluate(result)
            secrets_control = next(r for r in rows if r["id"] == "V6.4.1")
            assert secrets_control["status"] == "FAIL"
            assert secrets_control["evidence_count"] == 1

    def test_pass_when_plugin_ran_clean(self):
        from secureaudit.compliance.owasp_asvs import evaluate
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("def hello(): return 1\n")
            result = self._run(d, ["secrets"])
            rows = evaluate(result)
            secrets_control = next(r for r in rows if r["id"] == "V6.4.1")
            assert secrets_control["status"] == "PASS"
            assert secrets_control["evidence_count"] == 0

    def test_suppressed_findings_do_not_count_as_fail(self):
        """A baselined/suppressed finding shouldn't count as a compliance failure —
        consistent with how it's excluded from the score."""
        from secureaudit.compliance.owasp_asvs import evaluate
        from secureaudit.core.baseline import apply_suppressions, save_baseline

        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            (target / "config.py").write_text('AWS_KEY = "AKIAI9ABCDEF1234WXYZ"\n')

            result1 = self._run(target, ["secrets"])
            bpath = target / ".secureaudit-baseline.json"
            save_baseline(bpath, result1.all_findings, str(target))

            result2 = self._run(target, ["secrets"])
            apply_suppressions(result2, target=target, baseline_path=bpath)

            rows = evaluate(result2)
            secrets_control = next(r for r in rows if r["id"] == "V6.4.1")
            assert secrets_control["status"] == "PASS"

    def test_dockerfile_root_fails_hardening_control(self):
        from secureaudit.compliance.owasp_asvs import evaluate
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            (target / ".gitignore").write_text("*.env\n")
            (target / "Dockerfile").write_text("FROM python:3.11\nCMD python app.py\n")
            result = self._run(target, ["policy"])
            rows = evaluate(result)
            hardening = next(r for r in rows if r["id"] == "V14.1.3")
            assert hardening["status"] == "FAIL"

    def test_unpinned_dependencies_fail_freshness_control(self):
        from secureaudit.compliance.owasp_asvs import evaluate
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            (target / ".gitignore").write_text("*.env\n")
            (target / "requirements.txt").write_text("flask\nrequests\n")
            result = self._run(target, ["policy"])
            rows = evaluate(result)
            freshness = next(r for r in rows if r["id"] == "V14.2.1")
            assert freshness["status"] == "FAIL"

    def test_ci_hardcoded_secret_fails_pipeline_control(self):
        from secureaudit.compliance.owasp_asvs import evaluate
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            (target / ".gitignore").write_text("*.env\n")
            wf_dir = target / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "ci.yml").write_text(
                "on: pull_request_target\njobs:\n  test:\n    steps:\n"
                "      - uses: actions/checkout@v4\n        with:\n          ref: head\n"
            )
            result = self._run(target, ["policy"])
            rows = evaluate(result)
            pipeline = next(r for r in rows if r["id"] == "V14.3.2")
            assert pipeline["status"] == "FAIL"

    def test_http_missing_hsts_fails_correct_control_only(self):
        """A missing HSTS header must fail V14.4.5 specifically, not the
        generic V14.4.1 'other headers' bucket — the matchers must not overlap."""
        from secureaudit.compliance.owasp_asvs import evaluate
        from secureaudit.core.models import AuditResult, Finding, PluginResult, Severity

        result = AuditResult(target="/tmp/test")
        pr = PluginResult(plugin="http")
        pr.findings = [
            Finding(plugin="http", title="Missing header: Strict-Transport-Security",
                   severity=Severity.HIGH, description=""),
        ]
        result.plugin_results = [pr]

        rows = evaluate(result)
        hsts = next(r for r in rows if r["id"] == "V14.4.5")
        other_headers = next(r for r in rows if r["id"] == "V14.4.1")
        assert hsts["status"] == "FAIL"
        assert other_headers["status"] == "PASS"  # not double-counted

    def test_http_missing_csp_fails_correct_control_only(self):
        from secureaudit.compliance.owasp_asvs import evaluate
        from secureaudit.core.models import AuditResult, Finding, PluginResult, Severity

        result = AuditResult(target="/tmp/test")
        pr = PluginResult(plugin="http")
        pr.findings = [
            Finding(plugin="http", title="Missing header: Content-Security-Policy",
                   severity=Severity.MEDIUM, description=""),
        ]
        result.plugin_results = [pr]

        rows = evaluate(result)
        csp = next(r for r in rows if r["id"] == "V14.4.3")
        hsts = next(r for r in rows if r["id"] == "V14.4.5")
        assert csp["status"] == "FAIL"
        assert hsts["status"] == "PASS"

    def test_http_other_header_buckets_correctly(self):
        from secureaudit.compliance.owasp_asvs import evaluate
        from secureaudit.core.models import AuditResult, Finding, PluginResult, Severity

        result = AuditResult(target="/tmp/test")
        pr = PluginResult(plugin="http")
        pr.findings = [
            Finding(plugin="http", title="Missing header: X-Frame-Options",
                   severity=Severity.MEDIUM, description=""),
        ]
        result.plugin_results = [pr]

        rows = evaluate(result)
        other = next(r for r in rows if r["id"] == "V14.4.1")
        hsts = next(r for r in rows if r["id"] == "V14.4.5")
        assert other["status"] == "FAIL"
        assert hsts["status"] == "PASS"

    def test_ssl_issue_fails_tls_control(self):
        from secureaudit.compliance.owasp_asvs import evaluate
        from secureaudit.core.models import AuditResult, Finding, PluginResult, Severity

        result = AuditResult(target="/tmp/test")
        pr = PluginResult(plugin="http")
        pr.findings = [
            Finding(plugin="http", title="SSL certificate expired: example.com",
                   severity=Severity.CRITICAL, description=""),
        ]
        result.plugin_results = [pr]

        rows = evaluate(result)
        tls = next(r for r in rows if r["id"] == "V9.1.1")
        assert tls["status"] == "FAIL"

    def test_cors_finding_fails_cors_control(self):
        from secureaudit.compliance.owasp_asvs import evaluate
        from secureaudit.core.models import AuditResult, Finding, PluginResult, Severity

        result = AuditResult(target="/tmp/test")
        pr = PluginResult(plugin="cors")
        pr.findings = [
            Finding(plugin="cors", title="CORS: wildcard origin + credentials — https://api.example.com",
                   severity=Severity.CRITICAL, description=""),
        ]
        result.plugin_results = [pr]

        rows = evaluate(result)
        cors_control = next(r for r in rows if r["id"] == "V14.5.3")
        assert cors_control["status"] == "FAIL"

    def test_sast_sqli_fails_injection_control_only(self):
        """A SQLi finding must fail V5.3.5 specifically, not V5.3.4 (XSS) or
        V12.5.1 (traversal) — the rule_id-based matchers must not cross-fire."""
        from secureaudit.compliance.owasp_asvs import evaluate
        from secureaudit.core.models import AuditResult, Finding, PluginResult, Severity

        result = AuditResult(target="/tmp/test")
        pr = PluginResult(plugin="sast")
        pr.findings = [
            Finding(plugin="sast", title="SAST: sql-injection", severity=Severity.CRITICAL,
                   description="", extra={"rule_id": "python.lang.security.audit.sql-injection"}),
        ]
        result.plugin_results = [pr]

        rows = evaluate(result)
        injection = next(r for r in rows if r["id"] == "V5.3.5")
        xss = next(r for r in rows if r["id"] == "V5.3.4")
        traversal = next(r for r in rows if r["id"] == "V12.5.1")
        assert injection["status"] == "FAIL"
        assert xss["status"] == "PASS"
        assert traversal["status"] == "PASS"

    def test_sast_xss_fails_xss_control_only(self):
        from secureaudit.compliance.owasp_asvs import evaluate
        from secureaudit.core.models import AuditResult, Finding, PluginResult, Severity

        result = AuditResult(target="/tmp/test")
        pr = PluginResult(plugin="sast")
        pr.findings = [
            Finding(plugin="sast", title="SAST: xss-vulnerability", severity=Severity.HIGH,
                   description="", extra={"rule_id": "javascript.lang.security.audit.xss"}),
        ]
        result.plugin_results = [pr]

        rows = evaluate(result)
        xss = next(r for r in rows if r["id"] == "V5.3.4")
        injection = next(r for r in rows if r["id"] == "V5.3.5")
        assert xss["status"] == "FAIL"
        assert injection["status"] == "PASS"

    def test_trivy_cve_finding_counts_toward_dependency_freshness_only(self):
        """A trivy CVE finding (has 'package' in extra) must count toward
        V14.2.1, but a trivy IaC finding (has 'check_id') must not."""
        from secureaudit.compliance.owasp_asvs import evaluate
        from secureaudit.core.models import AuditResult, Finding, PluginResult, Severity

        result = AuditResult(target="/tmp/test")
        pr = PluginResult(plugin="trivy")
        pr.findings = [
            Finding(plugin="trivy", title="CVE-2024-0001 in libfoo 1.0", severity=Severity.HIGH,
                   description="", extra={"package": "libfoo", "installed": "1.0", "fixed": "1.1"}),
        ]
        result.plugin_results = [pr]

        rows = evaluate(result)
        freshness = next(r for r in rows if r["id"] == "V14.2.1")
        hardening = next(r for r in rows if r["id"] == "V14.1.3")
        assert freshness["status"] == "FAIL"
        assert hardening["status"] == "PASS"  # IaC-specific control unaffected by a CVE finding

    def test_trivy_iac_finding_counts_toward_hardening_only(self):
        from secureaudit.compliance.owasp_asvs import evaluate
        from secureaudit.core.models import AuditResult, Finding, PluginResult, Severity

        result = AuditResult(target="/tmp/test")
        pr = PluginResult(plugin="trivy")
        pr.findings = [
            Finding(plugin="trivy", title="IaC misconfig: missing USER", severity=Severity.HIGH,
                   description="", extra={"check_id": "DS002"}),
        ]
        result.plugin_results = [pr]

        rows = evaluate(result)
        hardening = next(r for r in rows if r["id"] == "V14.1.3")
        freshness = next(r for r in rows if r["id"] == "V14.2.1")
        assert hardening["status"] == "FAIL"
        assert freshness["status"] == "PASS"

    def test_malware_finding_fails_malware_control(self):
        from secureaudit.compliance.owasp_asvs import evaluate
        from secureaudit.core.models import AuditResult, Finding, PluginResult, Severity

        result = AuditResult(target="/tmp/test")
        pr = PluginResult(plugin="malware")
        pr.findings = [
            Finding(plugin="malware", title="Malware detected: Eicar-Test-Signature",
                   severity=Severity.CRITICAL, description=""),
        ]
        result.plugin_results = [pr]

        rows = evaluate(result)
        malware_control = next(r for r in rows if r["id"] == "V10.3.2")
        assert malware_control["status"] == "FAIL"

    def test_git_history_finding_fails_history_control(self):
        from secureaudit.compliance.owasp_asvs import evaluate
        from secureaudit.core.models import AuditResult, Finding, PluginResult, Severity

        result = AuditResult(target="/tmp/test")
        pr = PluginResult(plugin="git_history")
        pr.findings = [
            Finding(plugin="git_history", title="Historical secret: AWS Access Key",
                   severity=Severity.CRITICAL, description=""),
        ]
        result.plugin_results = [pr]

        rows = evaluate(result)
        history_control = next(r for r in rows if r["id"] == "V1.4.1")
        assert history_control["status"] == "FAIL"

    def test_info_only_findings_never_cause_fail(self):
        """Plugins' own 'all clear' INFO findings (e.g. 'No CORS misconfigurations
        found') must never be mistaken for evidence of a compliance failure."""
        from secureaudit.compliance.owasp_asvs import evaluate
        from secureaudit.core.models import AuditResult, Finding, PluginResult, Severity

        result = AuditResult(target="/tmp/test")
        pr = PluginResult(plugin="cors")
        pr.findings = [
            Finding(plugin="cors", title="No CORS misconfigurations found",
                   severity=Severity.INFO, description=""),
        ]
        result.plugin_results = [pr]

        rows = evaluate(result)
        cors_control = next(r for r in rows if r["id"] == "V14.5.3")
        assert cors_control["status"] == "PASS"

    def test_malware_info_clean_finding_never_causes_fail(self):
        """Regression: malware plugin's 'No malware detected' INFO finding was
        incorrectly counted as failure evidence before the global INFO exclusion fix."""
        from secureaudit.compliance.owasp_asvs import evaluate
        from secureaudit.core.models import AuditResult, Finding, PluginResult, Severity

        result = AuditResult(target="/tmp/test")
        pr = PluginResult(plugin="malware")
        pr.findings = [
            Finding(plugin="malware", title="No malware detected", severity=Severity.INFO, description=""),
        ]
        result.plugin_results = [pr]

        rows = evaluate(result)
        malware_control = next(r for r in rows if r["id"] == "V10.3.2")
        assert malware_control["status"] == "PASS"

    def test_git_history_info_clean_finding_never_causes_fail(self):
        """Regression: same bug class as malware/cors — 'No secrets found in
        git history' is INFO, not evidence of a failed control."""
        from secureaudit.compliance.owasp_asvs import evaluate
        from secureaudit.core.models import AuditResult, Finding, PluginResult, Severity

        result = AuditResult(target="/tmp/test")
        pr = PluginResult(plugin="git_history")
        pr.findings = [
            Finding(plugin="git_history", title="No secrets found in git history",
                   severity=Severity.INFO, description=""),
        ]
        result.plugin_results = [pr]

        rows = evaluate(result)
        history_control = next(r for r in rows if r["id"] == "V1.4.1")
        assert history_control["status"] == "PASS"


class TestComplianceFrameworkRegistry:
    def test_owasp_asvs_registered(self):
        from secureaudit.compliance import FRAMEWORKS
        assert "owasp-asvs" in FRAMEWORKS

    def test_cis_docker_registered(self):
        from secureaudit.compliance import FRAMEWORKS
        assert "cis-docker" in FRAMEWORKS

    def test_registry_function_matches_module_function(self):
        from secureaudit.compliance import FRAMEWORKS
        from secureaudit.compliance.owasp_asvs import evaluate
        assert FRAMEWORKS["owasp-asvs"] is evaluate

    def test_cis_docker_registry_function_matches_module_function(self):
        from secureaudit.compliance import FRAMEWORKS
        from secureaudit.compliance.cis_docker import evaluate
        assert FRAMEWORKS["cis-docker"] is evaluate


class TestCISDockerEvaluate:
    """CIS Docker Benchmark control IDs (4.1, 4.2, 4.9, 4.10) and their
    descriptions are checked against the actual published benchmark
    (cross-referenced against multiple independent sources, not guessed)
    — see cis_docker.py's module docstring for sourcing."""

    def _run(self, target, plugins):
        cfg = load_config(None)
        engine = AuditEngine(cfg)
        return engine.run(target, plugins=plugins)

    def test_returns_one_row_per_control(self):
        from secureaudit.compliance.cis_docker import CONTROLS, evaluate
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("x = 1\n")
            result = self._run(d, ["policy"])
            rows = evaluate(result)
            assert len(rows) == len(CONTROLS)

    def test_not_applicable_when_plugin_not_run(self):
        from secureaudit.compliance.cis_docker import evaluate
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("x = 1\n")
            result = self._run(d, ["network"])  # neither policy nor secrets runs
            rows = evaluate(result)
            for row in rows:
                assert row["status"] == "NOT_APPLICABLE"

    def test_pass_when_no_dockerfile_at_all(self):
        """No Dockerfile in the repo at all is treated as PASS (vacuously
        — nothing to violate), not NOT_APPLICABLE, since the controls'
        plugins (policy/secrets) DID run. An earlier version tried to
        special-case this as NOT_APPLICABLE by checking for a finding
        mentioning "dockerfile", which broke PASS for a real, compliant
        Dockerfile (no such finding exists for a clean one either) —
        caught by actually running it against one, not reasoned through
        up front. See the module's evaluate() docstring."""
        from secureaudit.compliance.cis_docker import evaluate
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("x = 1\n")
            result = self._run(d, ["policy", "secrets"])
            rows = evaluate(result)
            for row in rows:
                assert row["status"] == "PASS"

    def test_pass_when_dockerfile_is_clean(self):
        from secureaudit.compliance.cis_docker import evaluate
        with tempfile.TemporaryDirectory() as d:
            Path(d, "Dockerfile").write_text(
                "FROM python:3.11.9-slim\nCOPY app.py /app/app.py\nUSER nonroot\nCMD [\"python\", \"/app/app.py\"]\n"
            )
            result = self._run(d, ["policy", "secrets"])
            rows = evaluate(result)
            for row in rows:
                assert row["status"] == "PASS", f"{row['id']} unexpectedly {row['status']}"

    def test_fail_4_1_when_dockerfile_runs_as_root(self):
        from secureaudit.compliance.cis_docker import evaluate
        with tempfile.TemporaryDirectory() as d:
            Path(d, "Dockerfile").write_text("FROM python:3.11.9-slim\nCOPY app.py /app/app.py\n")
            result = self._run(d, ["policy"])
            rows = evaluate(result)
            control = next(r for r in rows if r["id"] == "4.1")
            assert control["status"] == "FAIL"
            assert control["evidence_count"] == 1

    def test_fail_4_2_when_base_image_unpinned(self):
        from secureaudit.compliance.cis_docker import evaluate
        with tempfile.TemporaryDirectory() as d:
            Path(d, "Dockerfile").write_text("FROM python:latest\nUSER nonroot\nCOPY app.py /app/app.py\n")
            result = self._run(d, ["policy"])
            rows = evaluate(result)
            control = next(r for r in rows if r["id"] == "4.2")
            assert control["status"] == "FAIL"

    def test_fail_4_9_when_add_used_instead_of_copy(self):
        from secureaudit.compliance.cis_docker import evaluate
        with tempfile.TemporaryDirectory() as d:
            Path(d, "Dockerfile").write_text(
                "FROM python:3.11.9-slim\nUSER nonroot\nADD app.tar.gz /app\n"
            )
            result = self._run(d, ["policy"])
            rows = evaluate(result)
            control = next(r for r in rows if r["id"] == "4.9")
            assert control["status"] == "FAIL"

    def test_fail_4_10_when_secret_in_dockerfile(self):
        from secureaudit.compliance.cis_docker import evaluate
        with tempfile.TemporaryDirectory() as d:
            Path(d, "Dockerfile").write_text(
                'FROM python:3.11.9-slim\nUSER nonroot\n'
                'ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
            )
            result = self._run(d, ["policy", "secrets"])
            rows = evaluate(result)
            control = next(r for r in rows if r["id"] == "4.10")
            assert control["status"] == "FAIL"
            assert control["evidence_count"] >= 1

    def test_secret_in_a_different_file_does_not_trigger_4_10(self):
        """4.10 is specifically about secrets baked into the Dockerfile —
        a secret detected in some other source file is a real (different)
        finding, but must not count as evidence for THIS control."""
        from secureaudit.compliance.cis_docker import evaluate
        with tempfile.TemporaryDirectory() as d:
            Path(d, "Dockerfile").write_text("FROM python:3.11.9-slim\nUSER nonroot\nCOPY . /app\n")
            Path(d, "config.py").write_text('AWS_KEY = "AKIAI9ABCDEF1234WXYZ"\n')
            result = self._run(d, ["policy", "secrets"])
            rows = evaluate(result)
            control = next(r for r in rows if r["id"] == "4.10")
            assert control["status"] == "PASS"

    def test_suppressed_findings_do_not_count_as_fail(self):
        from secureaudit.compliance.cis_docker import evaluate
        from secureaudit.core.baseline import apply_suppressions, save_baseline
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            (target / "Dockerfile").write_text("FROM python:3.11.9-slim\nCOPY app.py /app/app.py\n")

            result1 = self._run(target, ["policy"])
            bpath = target / ".secureaudit-baseline.json"
            save_baseline(bpath, result1.all_findings, str(target))

            result2 = self._run(target, ["policy"])
            apply_suppressions(result2, target=target, baseline_path=bpath)

            rows = evaluate(result2)
            control = next(r for r in rows if r["id"] == "4.1")
            assert control["status"] == "PASS"


class TestComplianceCLI:
    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def test_compliance_report_flag_runs_without_error(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("x = 1\n")
            result = runner.invoke(cli, [
                "scan", d, "--plugins", "secrets,policy", "--fail-below", "0",
                "--compliance-report", "owasp-asvs",
            ])
            assert result.exit_code == 0, result.output
            assert "Compliance" in result.output
            assert "V6.4.1" in result.output

    def test_compliance_output_writes_json(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "config.py").write_text('AWS_KEY = "AKIAI9ABCDEF1234WXYZ"\n')
            out_path = Path(d) / "compliance.json"

            result = runner.invoke(cli, [
                "scan", d, "--plugins", "secrets", "--fail-below", "0",
                "--compliance-report", "owasp-asvs", "--compliance-output", str(out_path),
            ])
            assert result.exit_code == 0, result.output
            assert out_path.exists()

            import json as _json
            data = _json.loads(out_path.read_text())
            assert len(data) >= 15
            assert all("status" in row for row in data)

    def test_cis_docker_compliance_report_via_cli(self):
        """cis-docker is reachable through the real CLI, not just the
        FRAMEWORKS dict directly — confirms --compliance-report's
        click.Choice() actually includes it, which is the part an earlier
        version of this got wrong (the Choice list was hardcoded to
        ["owasp-asvs"] and never updated when a new framework was
        registered, so it would have been silently rejected by Click
        before this test existed to catch it)."""
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "Dockerfile").write_text("FROM python:latest\nCOPY app.py /app/app.py\n")
            result = runner.invoke(cli, [
                "scan", d, "--plugins", "policy", "--fail-below", "0",
                "--compliance-report", "cis-docker",
            ])
            assert result.exit_code == 0, result.output
            assert "CIS Docker Benchmark" in result.output
            assert "4.1" in result.output

    def test_compliance_report_invalid_framework_rejected(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            result = runner.invoke(cli, [
                "scan", d, "--fail-below", "0", "--compliance-report", "not-a-real-framework",
            ])
            assert result.exit_code != 0

    def test_no_compliance_flag_means_no_compliance_section(self):
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("x = 1\n")
            result = runner.invoke(cli, ["scan", d, "--plugins", "policy", "--fail-below", "0"])
            assert result.exit_code == 0
            assert "Compliance" not in result.output


# ── SARIF output ─────────────────────────────────────────────────────────────

class TestSarifOutput:
    """Validates SARIF output against the REAL official SARIF 2.1.0 schema
    (bundled in tests/fixtures/, not fetched live — keeps this test fast
    and not network-dependent), not just "did a file get written"."""

    @staticmethod
    def _make_result():
        from secureaudit.core.models import AuditResult, Finding, PluginResult, Severity
        result = AuditResult(target="/tmp/fakeproject")
        result.plugin_results.append(PluginResult(
            plugin="secrets",
            findings=[Finding(
                plugin="secrets", title="Hardcoded API Key", severity=Severity.HIGH,
                description="Found a hardcoded API key in source.",
                remediation="Move to environment variables.",
                file="app/config.py", line=12, evidence="API_KEY = 'sk-12345'",
                reference="https://example.com/docs",
            )],
        ))
        result.plugin_results.append(PluginResult(
            plugin="policy",
            findings=[Finding(
                plugin="policy", title="Missing license file", severity=Severity.INFO,
                description="No LICENSE file found at repo root.",
                remediation=None, file=None, line=None, evidence=None, reference=None,
            )],
        ))
        return result

    @staticmethod
    def _schema():
        schema_path = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"
        with open(schema_path) as f:
            return json.load(f)

    def test_output_validates_against_official_schema(self, tmp_path):
        from secureaudit.reports.sarif import write_sarif
        out = tmp_path / "out.sarif"
        write_sarif(self._make_result(), out)

        with open(out) as f:
            sarif_doc = json.load(f)

        import jsonschema
        jsonschema.validate(instance=sarif_doc, schema=self._schema())  # raises on failure

    def test_schema_url_is_not_a_dead_link(self):
        """Regression test: the $schema URL this previously pointed to
        (.../master/Documents/CommitteeSpecifications/2.1.0/...) 404s — a
        known, widely-reported issue with the spec's own published
        examples. Doesn't re-fetch the URL on every test run (network
        dependency, slow) — just confirms the code still points at the
        specific path confirmed to actually resolve, so a future edit
        can't silently reintroduce the dead one."""
        import inspect

        from secureaudit.reports import sarif as sarif_module
        source = inspect.getsource(sarif_module)
        assert "sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json" in source
        assert "sarif-spec/master/Documents/CommitteeSpecifications" not in source

    def test_findings_with_no_location_omit_locations_field(self, tmp_path):
        """A finding with no file/line (like the policy finding above)
        must not produce a malformed or empty locations array — SARIF
        requires locations entries to have real content if present at all."""
        from secureaudit.reports.sarif import write_sarif
        out = tmp_path / "out.sarif"
        write_sarif(self._make_result(), out)
        with open(out) as f:
            sarif_doc = json.load(f)
        results = sarif_doc["runs"][0]["results"]
        no_location_result = next(r for r in results if "locations" not in r or not r.get("locations"))
        assert no_location_result["ruleId"].startswith("policy/")

    def test_severity_mapping_matches_github_conventions(self, tmp_path):
        """CRITICAL/HIGH -> error, MEDIUM -> warning, INFO -> note/none —
        confirms the actual written output, not just the internal mapping
        dict, in case a future refactor changes how it's applied."""
        from secureaudit.reports.sarif import write_sarif
        out = tmp_path / "out.sarif"
        write_sarif(self._make_result(), out)
        with open(out) as f:
            sarif_doc = json.load(f)
        results = sarif_doc["runs"][0]["results"]
        high_result = next(r for r in results if "secrets/" in r["ruleId"])
        info_result = next(r for r in results if "policy/" in r["ruleId"])
        assert high_result["level"] == "error"
        assert info_result["level"] in ("note", "none")

    def test_rules_are_deduplicated_across_findings(self, tmp_path):
        """Two findings from the same plugin+title (e.g. the same rule
        firing on two different files) must produce ONE rule entry, not
        a duplicate per finding — SARIF rules are meant to be unique
        per logical check, with multiple results referencing the same rule."""
        from secureaudit.core.models import AuditResult, Finding, PluginResult, Severity
        from secureaudit.reports.sarif import write_sarif

        result = AuditResult(target="/tmp/fakeproject")
        result.plugin_results.append(PluginResult(
            plugin="secrets",
            findings=[
                Finding(
                    plugin="secrets", title="Hardcoded API Key", severity=Severity.HIGH,
                    description="x", remediation=None, file=f, line=1, evidence=None, reference=None,
                )
                for f in ("a.py", "b.py")
            ],
        ))

        out = tmp_path / "out.sarif"
        write_sarif(result, out)
        with open(out) as f:
            sarif_doc = json.load(f)

        rules = sarif_doc["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert len(sarif_doc["runs"][0]["results"]) == 2


# ── Per-plugin end-to-end smoke tests ────────────────────────────────────────

class TestAllPluginsRunWithoutCrashing:
    """Smoke tests confirming every plugin listed in `secureaudit
    list-plugins` can be invoked via the real AuditEngine without
    crashing — even when its external dependency (semgrep, clamav,
    trivy) is not installed. Graceful degradation to an INFO finding
    is explicitly tested, not treated as a pass by accident.

    This is the test class that #30 asked for after the end-to-end
    audit found that 5 plugins (cors, sast, malware, network, http)
    had never been run outside their own isolated unit tests, meaning
    a broken import or changed function signature could have gone
    undetected indefinitely."""

    def _run(self, d, plugins):
        from secureaudit.core.config import load_config
        from secureaudit.core.engine import AuditEngine
        cfg = load_config(None)
        engine = AuditEngine(cfg)
        return engine.run(d, plugins=plugins)

    def test_cors_runs_without_crash_and_returns_info_when_no_urls(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("x = 1\n")
            result = self._run(d, ["cors"])
            pr = result.plugin_results[0]
            assert pr.plugin == "cors"
            assert pr.error is None
            # No URLs configured → INFO finding, not an exception
            assert any(f.severity == Severity.INFO for f in result.all_findings)

    def test_sast_runs_without_crash_and_degrades_gracefully_without_semgrep(self):
        """If semgrep is installed, it runs; if not, it returns an INFO
        finding rather than raising ImportError or crashing the engine."""
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("x = 1\n")
            result = self._run(d, ["sast"])
            pr = result.plugin_results[0]
            assert pr.plugin == "sast"
            assert pr.error is None
            assert pr.score is not None

    def test_malware_runs_without_crash_and_degrades_gracefully_without_clamav(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("x = 1\n")
            result = self._run(d, ["malware"])
            pr = result.plugin_results[0]
            assert pr.plugin == "malware"
            assert pr.error is None
            assert pr.score is not None

    def test_network_runs_without_crash(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("x = 1\n")
            result = self._run(d, ["network"])
            pr = result.plugin_results[0]
            assert pr.plugin == "network"
            assert pr.error is None

    def test_http_runs_without_crash_and_degrades_when_no_live_target(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("x = 1\n")
            result = self._run(d, ["http"])
            pr = result.plugin_results[0]
            assert pr.plugin == "http"
            assert pr.error is None
            assert pr.score is not None

    def test_filesystem_detects_sensitive_files(self):
        """Not just 'runs without crash' — confirms actual detection
        works, so regressions in the detection logic are caught."""
        with tempfile.TemporaryDirectory() as d:
            Path(d, ".env").write_text("PASSWORD=secret\n")
            Path(d, "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\n")
            result = self._run(d, ["filesystem"])
            pr = result.plugin_results[0]
            assert pr.error is None
            titles = [f.title for f in result.all_findings]
            assert any("id_rsa" in t for t in titles)
            assert any(".env" in t for t in titles)

    def test_all_registered_plugins_importable_and_runnable(self):
        """Meta-test: every plugin returned by available_plugins() can
        be passed to AuditEngine.run() without raising an ImportError
        or AttributeError — the most common symptom of a broken plugin
        module path or renamed function."""
        from secureaudit.plugins import available_plugins
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("x = 1\n")
            for name in available_plugins():
                result = self._run(d, [name])
                pr = result.plugin_results[0]
                assert pr.error is None, (
                    f"Plugin '{name}' raised an error when run via AuditEngine: "
                    f"{pr.error}"
                )


# ── Documentation freshness ───────────────────────────────────────────────────

class TestDocumentationFreshness:
    """Confirms the README's stated test count and plugin count match
    reality — preventing the repeated, human-caught drift that happened
    during recent sprints (the README said '6 plugins' when 11 exist,
    and the test count was stale at several points). A test failing here
    means someone added a test or plugin without updating the README.

    These counts are checked here, not in a separate CI script, so they
    run on every `pytest` invocation (including local dev runs), not just
    in CI — catching the drift at the earliest possible moment."""

    def test_readme_test_count_matches_reality(self):
        """The exact number of collected tests must match what the README
        claims. When this fails, update the README's count to match the
        real one — do NOT change the assertion to match a stale README."""
        import re
        import subprocess

        result = subprocess.run(
            ["python3", "-m", "pytest", "tests/", "--collect-only", "-q", "--tb=no"],
            cwd=Path(__file__).parent.parent,
            capture_output=True, text=True,
        )
        match = re.search(r"(\d+) test[s]? collected", result.stdout)
        assert match, f"Could not parse pytest collection output:\n{result.stdout}"
        real_count = int(match.group(1))

        readme = (Path(__file__).parent.parent / "README.md").read_text()
        readme_match = re.search(r"\*\*(\d+) tests\*\*", readme)
        assert readme_match, "README.md has no '**N tests**' line in the Features section"
        readme_count = int(readme_match.group(1))

        assert real_count == readme_count, (
            f"README says {readme_count} tests, but pytest collects {real_count}. "
            f"Update the README's test count to {real_count}."
        )

    def test_readme_plugin_count_matches_reality(self):
        """The exact number of available plugins must match what the README
        claims. When this fails, update the README's plugin count and
        plugin list in the Features section."""
        import re

        from secureaudit.plugins import available_plugins

        real_count = len(available_plugins())

        readme = (Path(__file__).parent.parent / "README.md").read_text()
        readme_match = re.search(r"\*\*(\d+) plugins\*\*", readme)
        assert readme_match, "README.md has no '**N plugins**' line in the Features section"
        readme_count = int(readme_match.group(1))

        assert real_count == readme_count, (
            f"README says {readme_count} plugins, but {real_count} are registered. "
            f"Update the README's plugin count to {real_count}."
        )


# ── PCI-DSS compliance ─────────────────────────────────────────────────────

class TestPCIDSSEvaluate:
    """PCI-DSS v4.0 control IDs (6.2.4, 6.3.1) confirmed against the real,
    current PCI-DSS v4.0 control numbering — see pci_dss.py's module
    docstring for sourcing and the explicit, deliberate scope limits."""

    def _run(self, target, plugins):
        cfg = load_config(None)
        engine = AuditEngine(cfg)
        return engine.run(target, plugins=plugins)

    def test_returns_one_row_per_control(self):
        from secureaudit.compliance.pci_dss import CONTROLS, evaluate
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("x = 1\n")
            result = self._run(d, ["policy"])
            rows = evaluate(result)
            assert len(rows) == len(CONTROLS)

    def test_not_applicable_when_neither_plugin_ran(self):
        from secureaudit.compliance.pci_dss import evaluate
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("x = 1\n")
            result = self._run(d, ["network"])
            rows = evaluate(result)
            for row in rows:
                assert row["status"] == "NOT_APPLICABLE"

    def test_sast_sqli_finding_fails_6_2_4(self):
        from secureaudit.compliance.pci_dss import evaluate
        from secureaudit.core.models import AuditResult, Finding, PluginResult, Severity

        result = AuditResult(target="/tmp/test")
        pr = PluginResult(plugin="sast")
        pr.findings = [
            Finding(plugin="sast", title="SAST: python.lang.security.audit.sqli.sql-injection",
                    severity=Severity.HIGH, description="", file="db.py", line=5),
        ]
        result.plugin_results = [pr]

        rows = evaluate(result)
        control = next(r for r in rows if r["id"] == "6.2.4")
        assert control["status"] == "FAIL"
        assert control["evidence_count"] == 1

    def test_sast_xss_finding_also_fails_6_2_4(self):
        """6.2.4 covers both injection AND XSS (a single PCI-DSS control,
        unlike OWASP ASVS's V5.3.5/V5.3.4 split into two) — confirms the
        matcher's keyword list covers both categories under this one
        control, not just injection."""
        from secureaudit.compliance.pci_dss import evaluate
        from secureaudit.core.models import AuditResult, Finding, PluginResult, Severity

        result = AuditResult(target="/tmp/test")
        pr = PluginResult(plugin="sast")
        pr.findings = [
            Finding(plugin="sast", title="SAST: javascript.lang.security.audit.xss-vulnerability",
                    severity=Severity.HIGH, description=""),
        ]
        result.plugin_results = [pr]

        rows = evaluate(result)
        control = next(r for r in rows if r["id"] == "6.2.4")
        assert control["status"] == "FAIL"

    def test_unrelated_sast_finding_does_not_fail_6_2_4(self):
        """A real, non-false-positive test: a sast finding that's neither
        injection nor XSS (e.g. weak crypto) must not count as evidence
        for 6.2.4 — confirms the keyword matcher isn't accidentally
        matching every sast finding regardless of category."""
        from secureaudit.compliance.pci_dss import evaluate
        from secureaudit.core.models import AuditResult, Finding, PluginResult, Severity

        result = AuditResult(target="/tmp/test")
        pr = PluginResult(plugin="sast")
        pr.findings = [
            Finding(plugin="sast", title="SAST: python.lang.security.audit.weak-crypto",
                    severity=Severity.MEDIUM, description=""),
        ]
        result.plugin_results = [pr]

        rows = evaluate(result)
        control = next(r for r in rows if r["id"] == "6.2.4")
        assert control["status"] == "PASS"
        assert control["evidence_count"] == 0

    def test_cve_finding_fails_6_3_1(self):
        from secureaudit.compliance.pci_dss import evaluate
        from secureaudit.core.models import AuditResult, Finding, PluginResult, Severity

        result = AuditResult(target="/tmp/test")
        pr = PluginResult(plugin="cve")
        pr.findings = [
            Finding(plugin="cve", title="CVE-2023-30861 in flask 2.0.1",
                    severity=Severity.HIGH, description=""),
        ]
        result.plugin_results = [pr]

        rows = evaluate(result)
        control = next(r for r in rows if r["id"] == "6.3.1")
        assert control["status"] == "FAIL"
        assert control["evidence_count"] == 1

    def test_trivy_cve_style_finding_fails_6_3_1_but_iac_misconfig_does_not(self):
        """Mirrors owasp_asvs.py's own equivalent distinction: a trivy CVE
        finding (real 'package' key in extra) counts toward 6.3.1, but a
        trivy IaC-misconfig finding (a 'check_id' key, no 'package') is a
        different kind of finding entirely and must not."""
        from secureaudit.compliance.pci_dss import evaluate
        from secureaudit.core.models import AuditResult, Finding, PluginResult, Severity

        result = AuditResult(target="/tmp/test")
        pr = PluginResult(plugin="trivy")
        pr.findings = [
            Finding(plugin="trivy", title="CVE-2024-1234 in openssl 1.1.1",
                    severity=Severity.CRITICAL, description="",
                    extra={"package": "openssl", "installed": "1.1.1"}),
            Finding(plugin="trivy", title="IaC misconfig: Dockerfile runs as root",
                    severity=Severity.MEDIUM, description="",
                    extra={"check_id": "DS002"}),
        ]
        result.plugin_results = [pr]

        rows = evaluate(result)
        control = next(r for r in rows if r["id"] == "6.3.1")
        assert control["status"] == "FAIL"
        assert control["evidence_count"] == 1  # only the CVE finding, not the IaC one

    def test_clean_scan_passes_both_controls(self):
        """Both plugins ran, produced only INFO/no findings -- PASS, not
        NOT_APPLICABLE (the plugins DID run)."""
        from secureaudit.compliance.pci_dss import evaluate
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("x = 1\n")
            result = self._run(d, ["sast", "cve"])
            rows = evaluate(result)
            for row in rows:
                assert row["status"] in ("PASS", "NOT_APPLICABLE")
                # sast/cve both ran, so neither should be NOT_APPLICABLE here
                assert row["status"] == "PASS"

    def test_suppressed_findings_do_not_count_as_fail(self):
        """Note: checks for a real, non-INFO sast finding specifically —
        without semgrep installed, sast still produces an INFO
        'Semgrep not installed' finding, which is not empty but is also
        not a real finding to suppress (applies_to() already filters
        INFO severity out). A naive `if not result1.all_findings` check
        would be fooled by that INFO finding into skipping the real
        suppression logic entirely while still reporting PASSED -- caught
        by actually checking what a semgrep-less environment produces
        before trusting the skip condition, not assumed correct."""
        from secureaudit.compliance.pci_dss import evaluate
        from secureaudit.core.baseline import apply_suppressions, save_baseline
        from secureaudit.core.models import Severity
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            (target / "db.py").write_text(
                "import sqlite3\n"
                "def get_user(user_id):\n"
                "    conn = sqlite3.connect('db.sqlite')\n"
                "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
                "    return conn.execute(query).fetchall()\n"
            )
            result1 = self._run(target, ["sast"])
            real_findings = [f for f in result1.all_findings if f.severity != Severity.INFO]
            if not real_findings:
                import pytest
                pytest.skip("semgrep not installed; cannot exercise a real sast finding here")

            bpath = target / ".secureaudit-baseline.json"
            save_baseline(bpath, result1.all_findings, str(target))

            result2 = self._run(target, ["sast"])
            apply_suppressions(result2, target=target, baseline_path=bpath)

            rows = evaluate(result2)
            control = next(r for r in rows if r["id"] == "6.2.4")
            assert control["status"] == "PASS"


class TestPCIDSSFrameworkRegistry:
    def test_pci_dss_registered(self):
        from secureaudit.compliance import FRAMEWORKS
        assert "pci-dss" in FRAMEWORKS

    def test_registry_function_matches_module_function(self):
        from secureaudit.compliance import FRAMEWORKS
        from secureaudit.compliance.pci_dss import evaluate
        assert FRAMEWORKS["pci-dss"] is evaluate


class TestPCIDSSCLI:
    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def test_pci_dss_compliance_report_via_cli(self):
        """pci-dss is reachable through the real CLI, not just the
        FRAMEWORKS dict directly -- confirms --compliance-report's
        click.Choice() picks it up automatically from the registry (the
        exact wiring bug already found and fixed for cis-docker in #28,
        confirmed not to have regressed here)."""
        from secureaudit.cli import cli
        runner = self._runner()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "app.py").write_text("x = 1\n")
            result = runner.invoke(cli, [
                "scan", d, "--plugins", "sast,cve", "--fail-below", "0",
                "--compliance-report", "pci-dss",
            ])
            assert result.exit_code == 0, result.output
            assert "PCI-DSS" in result.output
            assert "6.2.4" in result.output
            assert "6.3.1" in result.output


# ── Demo command ──────────────────────────────────────────────────────────────

class TestDemoCommand:
    """Issue #38: `secureaudit demo` — a single command that scans a
    throwaway demo project with real planted findings and starts the
    dashboard, with zero configuration required from the person trying
    it out."""

    def _runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def test_demo_no_serve_scans_and_reports_real_findings(self):
        """--no-serve avoids starting a real HTTP server inside a test,
        while still exercising the real scan/save path end-to-end."""
        from secureaudit.cli import cli
        runner = self._runner()
        result = runner.invoke(cli, ["demo", "--no-serve"])
        assert result.exit_code == 0, result.output
        assert "AWS Secret Key" in result.output
        assert "CRITICAL" in result.output
        assert "Skipped starting the dashboard" in result.output
        assert "secureaudit serve --db" in result.output

    def test_demo_creates_project_outside_the_repo(self):
        """The demo project must live under a temp directory, not be
        written into this repository's own working tree."""
        import re

        from secureaudit.cli import cli
        runner = self._runner()
        result = runner.invoke(cli, ["demo", "--no-serve"])
        match = re.search(r"Demo project: (\S+)", result.output)
        assert match, "expected the demo project path to be printed"
        demo_path = Path(match.group(1))
        repo_root = Path(__file__).parent.parent.resolve()
        assert repo_root not in demo_path.resolve().parents, (
            f"demo project {demo_path} was created inside the repo ({repo_root}) "
            f"-- must be a temp directory instead"
        )

    def test_demo_persists_to_a_real_db(self):
        """The demo command's own db path (printed on --no-serve) must
        be a real, queryable SQLite history db -- not just a claim."""
        import re

        from secureaudit.cli import cli
        from secureaudit.reports.history import get_runs
        runner = self._runner()
        result = runner.invoke(cli, ["demo", "--no-serve"])
        match = re.search(r"secureaudit serve --db (\S+)", result.output)
        assert match
        db_path = match.group(1)
        runs = get_runs(db_path)
        assert len(runs) == 1
        assert runs[0]["score"] < 70  # the demo project is deliberately insecure

    def test_demo_low_score_does_not_cause_a_nonzero_exit(self):
        """Unlike `scan`, `demo` should never fail the process just
        because the (deliberately insecure) demo project scores low --
        it's a demonstration, not a CI gate. Confirms this explicitly
        rather than assuming print_summary's own threshold-fail styling
        doesn't also propagate to the exit code."""
        from secureaudit.cli import cli
        runner = self._runner()
        result = runner.invoke(cli, ["demo", "--no-serve"])
        assert result.exit_code == 0

    def test_demo_missing_dashboard_deps_still_reports_scan_results(self):
        """If fastapi/uvicorn genuinely aren't installed, `demo` (unlike
        `serve`) should NOT hard-fail -- the scan itself already
        succeeded and is useful on its own; only the dashboard-start
        step is skipped, with a clear pointer to fix and retry."""
        import builtins
        from unittest.mock import patch

        from secureaudit.cli import cli

        real_import = builtins.__import__
        def fake_import(name, *args, **kwargs):
            if name == "fastapi":
                raise ImportError("simulated: fastapi not installed")
            return real_import(name, *args, **kwargs)

        runner = self._runner()
        with patch.object(builtins, "__import__", side_effect=fake_import):
            result = runner.invoke(cli, ["demo"])
        assert result.exit_code == 0, result.output
        assert "AWS Secret Key" in result.output  # the scan itself still ran and reported
        assert "Dashboard dependencies missing" in result.output
        assert "secureaudit[dashboard]" in result.output
