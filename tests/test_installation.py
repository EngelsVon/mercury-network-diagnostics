from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import venv
import zipfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run_process(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )


class InstalledEntryPointTests(unittest.TestCase):
    def test_clean_wheel_console_and_module_entry_points_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            shutil.copytree(
                PROJECT_ROOT,
                source,
                ignore=shutil.ignore_patterns(
                    ".git",
                    ".planning",
                    "__pycache__",
                    "*.pyc",
                    "*.egg-info",
                    "build",
                    "dist",
                ),
            )
            wheelhouse = root / "wheelhouse"
            wheelhouse.mkdir()
            build = run_process(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "wheel",
                    ".",
                    "--no-deps",
                    "--wheel-dir",
                    str(wheelhouse),
                ],
                cwd=source,
                environment=os.environ.copy(),
            )
            self.assertEqual(
                build.returncode,
                0,
                msg=f"wheel build failed:\n{build.stdout}\n{build.stderr}",
            )
            wheels = tuple(wheelhouse.glob("*.whl"))
            self.assertEqual(len(wheels), 1)
            with zipfile.ZipFile(wheels[0]) as archive:
                contents = set(archive.namelist())
            self.assertTrue({
                "mercury/web/__init__.py",
                "mercury/web/static/index.html",
                "mercury/web/static/app.js",
                "mercury/web/static/style.css",
            }.issubset(contents))

            environment_path = root / "venv"
            venv.EnvBuilder(with_pip=True, system_site_packages=True).create(environment_path)
            if os.name == "nt":
                python = environment_path / "Scripts" / "python.exe"
                console = environment_path / "Scripts" / "mercury.exe"
            else:
                python = environment_path / "bin" / "python"
                console = environment_path / "bin" / "mercury"
            install = run_process(
                [
                    str(python),
                    "-m",
                    "pip",
                    "install",
                    "--no-index",
                    "--no-deps",
                    "--force-reinstall",
                    str(wheels[0]),
                ],
                cwd=root,
                environment=os.environ.copy(),
            )
            self.assertEqual(
                install.returncode,
                0,
                msg=f"wheel install failed:\n{install.stdout}\n{install.stderr}",
            )

            clean_cwd = root / "empty"
            clean_cwd.mkdir()
            clean_environment = os.environ.copy()
            clean_environment.pop("PYTHONHOME", None)
            clean_environment.pop("PYTHONPATH", None)
            clean_environment["PYTHONNOUSERSITE"] = "1"
            clean_environment["PYTHONUTF8"] = "1"
            imported = run_process(
                [
                    str(python),
                    "-c",
                    (
                        "from pathlib import Path; import mercury; "
                        "print(Path(mercury.__file__).resolve())"
                    ),
                ],
                cwd=clean_cwd,
                environment=clean_environment,
            )
            self.assertEqual(imported.returncode, 0, msg=imported.stderr)
            self.assertTrue(
                Path(imported.stdout.strip()).is_relative_to(
                    environment_path.resolve()
                )
            )

            stable_cases = (
                ("version", "--json"),
                ("model", "--json"),
                ("status", "--help"),
                ("diagnose", "--help"),
                ("mapping", "--help"),
                ("coverage", "--help"),
                ("agent", "--help"),
                ("web", "--help"),
                ("--json", "plan"),
                ("--json", "plan", "192.0.2.10", "--ports", "443"),
            )
            for arguments in stable_cases:
                with self.subTest(arguments=arguments):
                    module = run_process(
                        [str(python), "-m", "mercury", *arguments],
                        cwd=clean_cwd,
                        environment=clean_environment,
                    )
                    script = run_process(
                        [str(console), *arguments],
                        cwd=clean_cwd,
                        environment=clean_environment,
                    )
                    self.assertEqual(
                        (script.returncode, script.stdout, script.stderr),
                        (module.returncode, module.stdout, module.stderr),
                    )

            arguments = (
                "plan",
                "127.0.0.1",
                "--ports",
                "443",
                "--json",
            )
            module = run_process(
                [str(python), "-m", "mercury", *arguments],
                cwd=clean_cwd,
                environment=clean_environment,
            )
            script = run_process(
                [str(console), *arguments],
                cwd=clean_cwd,
                environment=clean_environment,
            )
            self.assertEqual(
                (script.returncode, script.stderr),
                (module.returncode, module.stderr),
            )
            self.assertEqual(module.returncode, 0)
            module_payload = json.loads(module.stdout)
            script_payload = json.loads(script.stdout)
            for payload in (module_payload, script_payload):
                payload.pop("created_at")
                payload.pop("digest")
                payload["scope"].pop("expires_at")
            self.assertEqual(script_payload, module_payload)


class DocumentationTests(unittest.TestCase):
    def test_readme_documents_supported_platforms_and_safe_uv_paths(self) -> None:
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
        for text in (
            "uv run --no-sync python -m mercury web",
            "Windows and Ubuntu",
            "macOS and other platforms",
            "--authorized",
            "--token-file",
            "--retain-sensitive",
            "Operator release smoke",
            "does not scan unowned",
            "Internal mapping and two-endpoint coverage",
            "Coverage receiver configuration",
            "coverage_profiles",
            "nmap_sctp_init",
            "not_applicable",
        ):
            with self.subTest(text=text):
                self.assertIn(text, readme)


if __name__ == "__main__":
    unittest.main()
