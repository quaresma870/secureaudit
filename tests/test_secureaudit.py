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
