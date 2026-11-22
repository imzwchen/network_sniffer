import ctypes
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from network_sniffer.capture import _PcapReader, _load_libpcap, open_capture, save_capture


_SAMPLE = Path(__file__).resolve().parents[1] / "sample.pcap"


class SaveCaptureTests(unittest.TestCase):
    def test_save_replaces_existing_pcap_without_leaving_old_packets(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcap"
            previous = _SAMPLE.read_bytes()
            path.write_bytes(previous)

            library = _load_libpcap()
            errors = ctypes.create_string_buffer(256)
            handle = library.pcap_open_offline(os.fsencode(_SAMPLE), errors)
            self.assertTrue(handle, errors.value)
            try:
                reader = _PcapReader(library, handle)
                with path.open("rb") as old_capture, save_capture(reader, path) as writer:
                    expected = reader.read(writer)
                    self.assertIsNotNone(expected)
                    self.assertEqual(old_capture.read(), previous)
            finally:
                library.pcap_close(handle)

            with open_capture(path) as packets:
                self.assertEqual(list(packets), [expected])
            self.assertEqual(list(Path(directory).iterdir()), [path])
