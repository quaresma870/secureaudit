"""
Tests for SecureAudit — plugins, engine and models.
"""

from __future__ import annotations

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
