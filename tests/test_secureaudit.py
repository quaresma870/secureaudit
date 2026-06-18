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
