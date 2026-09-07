from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

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


class StructuredResultTests(unittest.TestCase):
    def test_nested_rcon_json_is_native_structured_content(self) -> None:
        response = httpx.Response(
            200,
            json={
                "principal": "operator@example.test",
                "node": "spiffe://tenant/node/one",
                "result": (
                    'HTTP 200 {"rc":0,"stdout":"hello\\n","stderr":"",'
                    '"timed_out":false}'
                ),
                "dur_ms": 12,
            },
        )

        result = xconnect_mcp._response_result(response)

        self.assertFalse(result.isError)
        self.assertEqual(result.structuredContent["http_status"], 200)
        self.assertEqual(result.structuredContent["remote_http_status"], 200)
        self.assertEqual(result.structuredContent["result"]["stdout"], "hello\n")
        self.assertEqual(json.loads(result.content[0].text), result.structuredContent)

    def test_nonzero_shell_exit_is_not_an_mcp_transport_error(self) -> None:
        response = httpx.Response(
            200,
            json={"result": 'HTTP 200 {"rc":7,"stdout":"","stderr":"nope\\n"}'},
        )

        result = xconnect_mcp._response_result(response)

        self.assertFalse(result.isError)
        self.assertTrue(result.structuredContent["ok"])
        self.assertEqual(result.structuredContent["result"]["rc"], 7)

    def test_remote_http_failure_is_an_mcp_error(self) -> None:
        response = httpx.Response(
            200,
            json={"result": 'HTTP 429 {"error":"node busy"}'},
        )

        result = xconnect_mcp._response_result(response)

        self.assertTrue(result.isError)
        self.assertFalse(result.structuredContent["ok"])
        self.assertEqual(result.structuredContent["remote_http_status"], 429)
        self.assertEqual(result.structuredContent["result"]["error"], "node busy")

    def test_caller_http_failure_preserves_actionable_fields(self) -> None:
        response = httpx.Response(
            409,
            json={"error": "ambiguous node", "candidates": [{"node_id": "one"}]},
        )

        result = xconnect_mcp._response_result(response)

        self.assertTrue(result.isError)
        self.assertEqual(result.structuredContent["http_status"], 409)
        self.assertEqual(result.structuredContent["candidates"][0]["node_id"], "one")

    def test_non_json_caller_response_is_explicit_error(self) -> None:
        response = httpx.Response(502, text="bad gateway")

        result = xconnect_mcp._response_result(response)

        self.assertTrue(result.isError)
        self.assertEqual(result.structuredContent["response"], "bad gateway")
        self.assertIn("non-JSON", result.structuredContent["error"])

    def test_local_validation_error_is_structured(self) -> None:
        result = xconnect_mcp._err("missing command", example={"command": "uname -a"})

        self.assertTrue(result.isError)
        self.assertEqual(result.structuredContent["ok"], False)
        self.assertEqual(result.structuredContent["example"]["command"], "uname -a")

    def test_fastmcp_advertises_output_schema(self) -> None:
        tool = xconnect_mcp.mcp._tool_manager.get_tool("remote_run")

        self.assertIsNotNone(tool)
        self.assertIn("ok", tool.output_schema["required"])
        self.assertTrue(tool.output_schema["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
