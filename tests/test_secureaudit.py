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
