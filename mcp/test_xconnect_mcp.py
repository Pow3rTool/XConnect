from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))

import xconnect_mcp


class RemoteWriteMetadataTests(unittest.TestCase):
    def test_metadata_is_optional_and_omitted_by_default(self) -> None:
        ctx = object()
        with patch.object(xconnect_mcp, "_forward", return_value="ok") as forward:
            result = xconnect_mcp.remote_write(
                node="node-id",
                path="/etc/example.conf",
                content="enabled=true\n",
                ctx=ctx,
            )

        self.assertEqual(result, "ok")
        forward.assert_called_once_with(
            ctx,
            "POST",
            "/v1/write",
            {
                "node": "node-id",
                "path": "/etc/example.conf",
                "content": "enabled=true\n",
            },
        )

    def test_metadata_is_forwarded_unchanged(self) -> None:
        ctx = object()
        with patch.object(xconnect_mcp, "_forward", return_value="ok") as forward:
            result = xconnect_mcp.remote_write(
                node="node-id",
                path="/etc/example.conf",
                content="enabled=true\n",
                ctx=ctx,
                expected_hash="abc123",
                force=True,
                make_dirs=True,
                owner="service-user",
                group="service-group",
                mode="0640",
            )

        self.assertEqual(result, "ok")
        forward.assert_called_once_with(
            ctx,
            "POST",
            "/v1/write",
            {
                "node": "node-id",
                "path": "/etc/example.conf",
                "content": "enabled=true\n",
                "expected_hash": "abc123",
                "force": True,
                "make_dirs": True,
                "owner": "service-user",
                "group": "service-group",
                "mode": "0640",
            },
        )


if __name__ == "__main__":
    unittest.main()
