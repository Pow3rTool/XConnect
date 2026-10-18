import asyncio
import base64
import json
import unittest
from unittest.mock import patch

from mcp import types
import xconnect_mcp as bridge
from desktop_mcp import DesktopStep, register


class DesktopMCPTests(unittest.TestCase):
    def test_session_tools_have_no_identity_or_credentials_arguments(self):
        tools = {t.name: t for t in asyncio.run(bridge.mcp.list_tools())}
        for name in ("desktop_status", "desktop_login"):
            self.assertEqual(set(tools[name].inputSchema["properties"]), {"node"})
            self.assertEqual(tools[name].inputSchema["required"], ["node"])

    def test_catalog_exposes_both_paths(self):
        tools = {t.name: t for t in asyncio.run(bridge.mcp.list_tools())}
        self.assertTrue({"desktop_observe", "desktop_frame", "desktop_find", "desktop_act", "desktop_task", "desktop_recover", "desktop_lock"} <= tools.keys())
        self.assertIn("node", tools["desktop_observe"].inputSchema["required"])
        self.assertEqual(set(tools["desktop_recover"].inputSchema["properties"]), {"node"})
        self.assertIn("session_id", tools["desktop_observe"].inputSchema["properties"])
        self.assertIn("middle", json.dumps(tools["desktop_act"].inputSchema))
        self.assertEqual(tools["desktop_task"].inputSchema["properties"]["steps"]["maxItems"], 8)

    def test_lock_body_and_receipt(self):
        functions = {}
        class Registrar:
            def tool(self):
                def add(fn): functions[fn.__name__] = fn; return fn
                return add
        def forward(ctx, method, path, body):
            self.assertEqual((method,path,body),("POST","/v1/desktop/lock",{"node":"test-host","session_id":1}))
            return types.CallToolResult(content=[], structuredContent={"ok":True,"locked":True,"verified":True})
        register(Registrar(),forward,bridge._err)
        result=functions["desktop_lock"](None,node="test-host",session_id=1)
        self.assertTrue(result.structuredContent["verified"])

    def test_image_is_native_not_duplicated_in_metadata(self):
        functions = {}
        class Registrar:
            def tool(self):
                def add(fn):
                    functions[fn.__name__] = fn
                    return fn
                return add
        image = base64.b64encode(b"\xff\xd8\xff" + b"test").decode()
        def forward(ctx, method, path, body):
            self.assertEqual(path, "/v1/desktop/observe")
            return types.CallToolResult(content=[], structuredContent={"ok": True, "image": {"mimeType": "image/jpeg", "data": image}}, isError=False)
        register(Registrar(), forward, bridge._err)
        result = functions["desktop_observe"](None, node="test-host")
        self.assertNotIn("image", result.structuredContent)
        self.assertEqual(result.content[1].type, "image")
        self.assertNotIn(image, result.content[0].text)


    def test_interaction_images_are_ordered_and_no_pixels_in_metadata(self):
        functions = {}
        class Registrar:
            def tool(self):
                def add(fn):
                    functions[fn.__name__] = fn
                    return fn
                return add
        encoded = base64.b64encode(b"\xff\xd8\xff" + b"frame").decode()
        picture = {"mimeType": "image/jpeg", "data": encoded}
        def forward(ctx, method, path, body):
            self.assertEqual(path, "/v1/desktop/interact")
            return types.CallToolResult(content=[], structuredContent={"ok": True,
                "frames": [{"observation": {"elapsed_ms": 100, "phase": "during_move"}, "image": picture}],
                "observation": {"elapsed_ms": 300, "phase": "checkpoint"}, "image": picture})
        register(Registrar(), forward, bridge._err)
        result = functions["desktop_interact"](None, node="test-host", operation="begin", frame_id="f"*32)
        self.assertEqual([p.type for p in result.content], ["text", "text", "image", "text", "image"])
        self.assertNotIn(encoded, json.dumps(result.structuredContent))
        self.assertIn('"elapsed_ms":100', result.content[1].text)
        self.assertIn('"elapsed_ms":300', result.content[3].text)

    def test_focus_guard_is_nested_and_only_sent_when_set(self):
        functions = {}
        class Registrar:
            def tool(self):
                def add(fn):
                    functions[fn.__name__] = fn
                    return fn
                return add
        bodies = []
        def forward(ctx, method, path, body):
            bodies.append(body)
            return types.CallToolResult(content=[], structuredContent={"ok": True}, isError=False)
        register(Registrar(), forward, bridge._err)
        functions["desktop_act"](None, frame_id="f"*32, action="type", label="run box", node="test-host", text="notepad", expect_foreground_class="#32770", expect_foreground_title="Run")
        functions["desktop_act"](None, frame_id="f"*32, action="key", label="enter", node="test-host", key="ENTER")
        steps = [DesktopStep(action="key", key="WIN+R"), DesktopStep(action="type", text="x", expect_foreground_title="Run")]
        functions["desktop_task"](None, steps=steps, node="test-host")
        self.assertEqual(bodies[0]["action"]["expect_foreground"], {"class": "#32770", "title": "Run"})
        self.assertNotIn("expect_foreground_class", json.dumps(bodies[0]))
        self.assertNotIn("expect_foreground", bodies[1]["action"])
        self.assertNotIn("expect_foreground", bodies[2]["steps"][0])
        self.assertEqual(bodies[2]["steps"][1]["expect_foreground"], {"title": "Run"})

    def test_wait_and_launch_bodies(self):
        functions = {}
        class Registrar:
            def tool(self):
                def add(fn):
                    functions[fn.__name__] = fn
                    return fn
                return add
        calls = []
        def forward(ctx, method, path, body):
            calls.append((path, body))
            return types.CallToolResult(content=[], structuredContent={"ok": True}, isError=False)
        register(Registrar(), forward, bridge._err)
        functions["desktop_wait"](None, node="test-host", until="foreground", window_class="#32770", window_title="Run", timeout_ms=4000)
        functions["desktop_wait"](None, node="test-host", until="cursor_idle")
        functions["desktop_launch"](None, node="test-host", command="omp models", wait=True)
        functions["desktop_launch"](None, node="test-host", command="notepad")
        steps = [DesktopStep(action="key", key="WIN+R"), DesktopStep(action="wait", until="foreground", window_class="#32770", timeout_ms=3000)]
        functions["desktop_task"](None, steps=steps, node="test-host")
        self.assertEqual(calls[0], ("/v1/desktop/wait", {"node": "test-host", "session_id": 0, "include_image": True,
            "action": {"action": "wait", "until": "foreground", "duration_ms": 4000, "window": {"class": "#32770", "title": "Run"}}}))
        self.assertNotIn("window", calls[1][1]["action"])
        self.assertEqual(calls[2][1]["launch"], {"command": "omp models", "wait": True, "timeout_ms": 20000})
        self.assertEqual(calls[3][1]["launch"], {"command": "notepad", "wait": False})
        key, wait = calls[4][1]["steps"]
        self.assertNotIn("until", key)
        self.assertNotIn("timeout_ms", key)
        self.assertEqual((wait["until"], wait["duration_ms"], wait["window"]), ("foreground", 3000, {"class": "#32770"}))

    def test_attach_console_tool(self):
        tools = {t.name: t for t in asyncio.run(bridge.mcp.list_tools())}
        schema = tools["desktop_attach_console"].inputSchema
        self.assertEqual(set(schema["required"]), {"node", "session_id"})
        self.assertFalse(schema["properties"]["force"]["default"])
        functions = {}
        class Registrar:
            def tool(self):
                def add(fn):
                    functions[fn.__name__] = fn
                    return fn
                return add
        calls = []
        def forward(ctx, method, path, body):
            calls.append((path, body))
            return types.CallToolResult(content=[], structuredContent={"ok": False, "desktop_state": "session_disconnected"}, isError=True)
        register(Registrar(), forward, bridge._err)
        result = functions["desktop_attach_console"](None, node="test-host", session_id=2, force=True)
        self.assertEqual(calls, [("/v1/desktop/attach_console", {"node": "test-host", "session_id": 2, "force": True})])
        self.assertTrue(result.isError)

    def test_interaction_schema_has_bounded_events(self):
        tools = {t.name: t for t in asyncio.run(bridge.mcp.list_tools())}
        schema = tools["desktop_interact"].inputSchema
        self.assertIn("operation", schema["required"])
        self.assertIn("60000", json.dumps(schema))
        self.assertIn("key_down", json.dumps(schema))


if __name__ == "__main__":
    unittest.main()
