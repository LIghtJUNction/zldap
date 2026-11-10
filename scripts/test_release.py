from contextlib import chdir, contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
import tomllib
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import release


ROOT_MANIFEST = '[package]\nname = "zldap"\nversion = "1.12.9"\n'
ROOT_LOCK = 'version = 3\n\n[[package]]\nname = "zldap"\nversion = "1.12.9"\n'
OTHER_PACKAGE = '[[package]]\nname = "devother"\nversion = "1.12.9"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "' + 'a' * 64 + '"\n'
COMPARISON_LOCK = 'version = 4\n\n' + OTHER_PACKAGE + '\n[[package]]\nname = "zldap"\nversion = "1.12.9"\n\n[[package]]\nname = "zldap-comparison"\nversion = "0.0.0"\ndependencies = ["devother", "zldap"]\n'


@contextmanager
def temporary_project(comparison=COMPARISON_LOCK):
    originals = {
        "Cargo.toml": ROOT_MANIFEST,
        "Cargo.lock": ROOT_LOCK,
        "comparison/Cargo.lock": comparison,
    }
    with TemporaryDirectory() as directory, chdir(directory):
        Path("comparison").mkdir()
        for filename, contents in originals.items():
            Path(filename).write_text(contents)
        with patch("release.output"):
            yield originals


class ReleaseTests(unittest.TestCase):
    def test_bumps_reset_components(self):
        self.assertEqual(release.next_version("1.12.9", "patch"), "1.12.10")
        self.assertEqual(release.next_version("1.12.9", "minor"), "1.13.0")
        self.assertEqual(release.next_version("1.12.9", "major"), "2.0.0")
        self.assertEqual(release.next_version("0.1.0", "current"), "0.1.0")

    def test_invalid_release_versions(self):
        for version in ["01.2.3", "1.02.3", "1.2", "1.2.3-rc.1", "1.2.3\n", "-1.2.3"]:
            with self.subTest(version=version), self.assertRaises(ValueError):
                release.next_version(version, "patch")

    def test_manifest_update_is_scoped(self):
        old = '[package]\nname = "zldap"\nversion = "0.1.0" # retained\n\n[dependencies.other]\nversion = "0.1.0"\n'
        updated = release.replace_manifest_version(old, "0.1.0", "0.2.0")
        self.assertIn('version = "0.2.0" # retained', updated)
        self.assertIn('[dependencies.other]\nversion = "0.1.0"', updated)

    def test_lockfile_dependency_is_rejected(self):
        lock = 'version = 3\n\n[[package]]\nname = "zldap"\nversion = "0.1.0"\n'
        self.assertIn('version = "0.2.0"', release.replace_lock_version(lock, "zldap", "0.1.0", "0.2.0"))
        for invalid in [lock.replace("version = 3", "version = 4"), lock + '\n[[package]]\nname = "thirdparty"\nversion = "1.0.0"\n']:
            with self.assertRaises(ValueError):
                release.replace_lock_version(invalid, "zldap", "0.1.0", "0.2.0")

    def test_all_bumps_synchronize_both_lockfiles_without_changing_other_pins(self):
        for kind, expected in [("patch", "1.12.10"), ("minor", "1.13.0"), ("major", "2.0.0")]:
            with self.subTest(kind=kind), temporary_project():
                release.bump(kind)
                manifest = tomllib.loads(Path("Cargo.toml").read_text())
                root = tomllib.loads(Path("Cargo.lock").read_text())
                comparison_text = Path("comparison/Cargo.lock").read_text()
                comparison = tomllib.loads(comparison_text)
                packages = {item["name"]: item for item in comparison["package"]}
                self.assertEqual(manifest["package"]["version"], expected)
                self.assertEqual(root["package"][0]["version"], expected)
                self.assertEqual(packages["zldap"]["version"], expected)
                self.assertEqual(root["version"], 3)
                self.assertEqual(comparison["version"], 4)
                self.assertEqual(packages["devother"]["version"], "1.12.9")
                self.assertEqual(packages["zldap-comparison"]["version"], "0.0.0")
                self.assertIn(OTHER_PACKAGE, comparison_text)

    def test_current_validates_all_files_without_writing(self):
        with temporary_project() as originals:
            with patch.object(Path, "write_text", side_effect=AssertionError("current must not write")):
                release.bump("current")
            self.assertEqual({name: Path(name).read_text() for name in originals}, originals)

    def test_invalid_comparison_lock_prevents_any_partial_bump(self):
        invalid_locks = [
            COMPARISON_LOCK.replace('name = "zldap"\nversion = "1.12.9"', 'name = "zldap"\nversion = "1.12.8"'),
            COMPARISON_LOCK.replace('name = "zldap"\n', 'name = "zldap"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'),
            COMPARISON_LOCK.replace("version = 4", "version = 2"),
            COMPARISON_LOCK + '\n[[package]]\nname = "zldap"\nversion = "9.0.0"\n',
        ]
        for comparison in invalid_locks:
            with self.subTest(comparison=comparison), temporary_project(comparison) as originals:
                with self.assertRaises(ValueError):
                    release.bump("patch")
                self.assertEqual({name: Path(name).read_text() for name in originals}, originals)

    def test_write_failure_rolls_back_preceding_bump_changes(self):
        write_text = Path.write_text
        failed = False

        def fail_once(path, contents):
            nonlocal failed
            if str(path) == "comparison/Cargo.lock" and not failed:
                failed = True
                raise OSError("synthetic write failure")
            return write_text(path, contents)

        with temporary_project() as originals:
            with patch.object(Path, "write_text", fail_once), self.assertRaises(OSError):
                release.bump("minor")
            self.assertTrue(failed)
            self.assertEqual({name: Path(name).read_text() for name in originals}, originals)

    def test_only_registry_404_means_available(self):
        with patch("release.urlopen", side_effect=HTTPError("", 404, "", {}, None)):
            self.assertIsNone(release.registry_version("zldap", "0.1.0"))
        for error in [HTTPError("", 403, "", {}, None), HTTPError("", 429, "", {}, None), HTTPError("", 500, "", {}, None), URLError("offline")]:
            with self.subTest(error=error), patch("release.urlopen", side_effect=error), self.assertRaises(RuntimeError):
                release.registry_version("zldap", "0.1.0")

    def test_recovery_requires_identical_archive(self):
        with patch("release.package_info", return_value=("zldap", "0.1.0")), patch("release.artifact_checksum", return_value="a" * 64), patch("release.registry_version", return_value="b" * 64):
            with self.assertRaisesRegex(RuntimeError, "different archive"):
                release.check_registry("zldap-0.1.0.crate", True)
            with self.assertRaisesRegex(RuntimeError, "already occupied"):
                release.check_registry("zldap-0.1.0.crate", False)


if __name__ == "__main__":
    unittest.main()
