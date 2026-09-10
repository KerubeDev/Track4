import os
import tempfile
import unittest
from datetime import datetime

from app.emulator import parser
from app.emulator.parser import ParseError, iter_file, parse_line, parse_timestamp

_FIXTURE = os.path.join(
    os.path.dirname(__file__), "fixtures", "queries.sample"
)


class ParserTest(unittest.TestCase):
    def test_parses_standard_line(self):
        rec = parse_line(
            "09-Sep-2026 08:04:59.901 queries: info: client @0x7fa2c438edf0 "
            "190.102.59.241#35082 (www.apple.com): query: www.apple.com IN A + "
            "(172.19.1.2)",
            "queries.0",
        )
        self.assertEqual(rec.timestamp, datetime(2026, 9, 9, 8, 4, 59, 901000))
        self.assertEqual(rec.client_ip, "190.102.59.241")
        self.assertEqual(rec.client_port, 35082)
        self.assertEqual(rec.qname, "www.apple.com")
        self.assertEqual(rec.qtype, "A")
        self.assertEqual(rec.resolver_ip, "172.19.1.2")
        self.assertEqual(rec.source_file, "queries.0")

    def test_parses_type65_and_flags(self):
        rec = parse_line(
            "09-Sep-2026 08:05:01.024 queries: info: client @0x7fa2c424c580 "
            "190.102.59.209#52839 (time.google.com): query: time.google.com "
            "IN AAAA +E(0)DV (172.19.1.2)",
            "queries.0",
        )
        self.assertEqual(rec.qtype, "AAAA")

    def test_lowercases_qname(self):
        rec = parse_line(
            "09-Sep-2026 08:04:59.912 queries: info: client @0x7fa2c438edf0 "
            "190.102.56.90#56836 (Census1.Shodan.IO): query: Census1.Shodan.IO "
            "IN A + (172.19.1.2)",
            "queries.0",
        )
        self.assertEqual(rec.qname, "census1.shodan.io")

    def test_parses_chaos_class_query(self):
        rec = parse_line(
            "09-Sep-2026 08:10:48.300 queries: info: client @0x7fa2d516fcf0 "
            "190.102.57.82#18999 (version.server): query: version.server "
            "CH TXT - (172.19.1.2)",
            "queries.0",
        )
        self.assertEqual(rec.qname, "version.server")
        self.assertEqual(rec.qtype, "TXT")

    def test_parses_escaped_paren_qname(self):
        rec = parse_line(
            "09-Sep-2026 08:01:38.619 queries: info: client @0x7fa2d4985400 "
            "200.12.213.198#50508 (\\(none\\)): query: \\(none\\) IN AAAA + "
            "(172.19.1.2)",
            "queries.0",
        )
        self.assertEqual(rec.qname, "(none)")
        self.assertEqual(rec.qtype, "AAAA")

    def test_rejects_garbage(self):
        with self.assertRaises(ParseError):
            parse_line("not a query line", "queries.0")

    def test_parse_timestamp_millis(self):
        self.assertEqual(
            parse_timestamp("09-Sep-2026 08:04:59.901"),
            datetime(2026, 9, 9, 8, 4, 59, 901000),
        )

    def test_iter_file_parses_fixture(self):
        records = list(iter_file(_FIXTURE, "queries.sample"))
        self.assertEqual(len(records), 6)
        for i in range(len(records) - 1):
            self.assertLessEqual(records[i].timestamp, records[i + 1].timestamp)

    def test_iter_file_counts_decode_errors(self):
        parser.bad_decodes = 0
        line = (
            b"09-Sep-2026 08:04:59.901 queries: info: client @0x7fa2c438edf0 "
            b"190.102.59.241#35082 (www\xffapple.com): query: www\xffapple.com "
            b"IN A + (172.19.1.2)\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.bin")
            with open(path, "wb") as handle:
                handle.write(line)
            records = list(iter_file(path, "bad.bin"))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].qname, "www\ufffdapple.com")
        self.assertEqual(parser.bad_decodes, 1)


if __name__ == "__main__":
    unittest.main()
