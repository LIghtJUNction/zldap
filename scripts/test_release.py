import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import release


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
