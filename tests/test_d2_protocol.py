import json
import tempfile
import unittest
from pathlib import Path

from defi_lsa.adapters.protocol import ProtocolAnnouncementAdapter


class Response:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self):
        return self.payload


class ProtocolAdapterTests(unittest.TestCase):
    def test_feed_persists_metadata_without_body(self):
        def opener(request, timeout=30):
            return Response(
                {
                    "items": [
                        {
                            "title": "Incident update",
                            "link": "https://protocol.example/update",
                            "published": "2023-03-13T08:00:00Z",
                            "content": "body must not be retained",
                        }
                    ]
                }
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = ProtocolAnnouncementAdapter(opener=opener).fetch_protocol_feed(
                "https://protocol.example/feed.json",
                "evt",
                raw_dir=root,
                output_dir=root,
            )
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].source, "protocol")
            normalized = next(
                (root / "data" / "raw" / "normalized" / "protocol" / "evt.jsonl").open(
                    encoding="utf-8"
                )
            )
            self.assertNotIn("body must not be retained", normalized)


if __name__ == "__main__":
    unittest.main()
