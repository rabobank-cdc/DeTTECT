import os
import tempfile
import unittest
from pathlib import Path

from health import _is_file_modified, _update_health_state_cache


class HealthCacheFilenameTest(unittest.TestCase):
    def test_modified_cache_file_uses_yaml_stem(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                Path('cache').mkdir()
                Path('my.yaml').write_text('content')

                self.assertTrue(_is_file_modified('my.yaml'))

                self.assertTrue(Path('cache/last-modified_my').exists())
                self.assertFalse(Path('cache/last-modified_').exists())
            finally:
                os.chdir(cwd)

    def test_error_state_cache_file_uses_yaml_stem(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                Path('cache').mkdir()
                Path('normal.yaml').write_text('content')

                _update_health_state_cache('normal.yaml', True)

                self.assertTrue(Path('cache/last-error-state_normal').exists())
                self.assertFalse(Path('cache/last-error-state_nor').exists())
            finally:
                os.chdir(cwd)


if __name__ == '__main__':
    unittest.main()
