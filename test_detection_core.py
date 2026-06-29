import tempfile
import unittest
from pathlib import Path

from detection_core import ZeekReader


class DetectionCoreTests(unittest.TestCase):
    def test_zeek_reader(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "ssl.log"
            path.write_text(
                "#separator \\x09\n"
                "#fields\tts\tuid\tid.orig_h\tid.resp_h\tserver_name\n"
                "1.0\tC1\t10.0.0.1\t1.1.1.1\texample.test\n",
                encoding="utf-8",
            )
            self.assertEqual(list(ZeekReader(path))[0]["uid"], "C1")


if __name__ == "__main__":
    unittest.main()
