import struct
import unittest

from medidx.dicom import parse, parse_json_bytes
from medidx.security import ApiError


def _tag(g, e):
    return struct.pack("<HH", g, e)


def _evr(vr, payload: bytes) -> bytes:
    if vr in ("OB", "OW", "SQ", "UN", "UT"):
        return vr.encode() + b"\x00\x00" + struct.pack("<I", len(payload)) + payload
    return vr.encode() + struct.pack("<H", len(payload)) + payload


def _lo(v: str) -> bytes:
    return v.encode("latin-1")


class TestDicomParser(unittest.TestCase):
    def _build(self, with_preamble=True):
        item_inner = _tag(0x0020, 0x000e) + _evr("UI", _lo("1.2.3.4.5\x00"))
        item_inner += _tag(0x0008, 0x1155) + _evr("UI", _lo("1.2.3.4.6\x00"))
        item = _tag(0xFFFE, 0xE000) + struct.pack("<I", len(item_inner)) + item_inner
        seq = item + _tag(0xFFFE, 0xE0DD) + struct.pack("<I", 0)

        buf = (b"\x00" * 128 + b"DICM") if with_preamble else b""
        buf += _tag(0x0008, 0x0060) + _evr("CS", _lo("MR"))
        buf += _tag(0x0010, 0x0020) + _evr("LO", _lo("MRN-TEST-001"))
        buf += _tag(0x0008, 0x1115) + _evr("SQ", seq)
        buf += _tag(0x0028, 0x0010) + _evr("US", struct.pack("<H", 256))
        buf += _tag(0x7FE0, 0x0010) + _evr("OW", b"\x00" * 64)
        return buf

    def test_explicit_le_with_sequence_and_pixels(self):
        ds = parse(self._build(), filename="x.dcm")
        self.assertEqual(ds.media_type, "dicom_explicit_le")
        self.assertEqual(ds.elements["(0008,0060)"], "MR")
        self.assertEqual(ds.elements["(0010,0020)"], "MRN-TEST-001")
        self.assertEqual(ds.elements["(0028,0010)"], 256)
        self.assertEqual(ds.elements["(0008,1115)"][0]["(0020,000e)"], "1.2.3.4.5")
        self.assertNotIn("(7fe0,0010)", ds.elements)

    def test_no_preamble_dataset(self):
        ds = parse(self._build(with_preamble=False), media_type="dcm")
        self.assertEqual(ds.elements["(0008,0060)"], "MR")

    def test_dicom_json(self):
        raw = b'{"elements":{"(0010,0020)":"X"},"pixel_sheet":{"width":1,"height":1,"regions":[]}}'
        ds = parse_json_bytes(raw)
        self.assertEqual(ds.get("(0010,0020)"), "X")

    def test_bad_json_rejected(self):
        with self.assertRaises(ApiError):
            parse_json_bytes(b"{not json")
        with self.assertRaises(ApiError):
            parse_json_bytes(b'{"elements":{"bad":"x"}}')


if __name__ == "__main__":
    unittest.main()
