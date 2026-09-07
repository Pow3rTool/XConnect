"""XConnect MCP bridge — the streamable-http MCP server turnstone connects to.

Why a bridge: turnstone's MCP client speaks the MCP protocol over streamable-http
with per-user OAuth (token as a Bearer header). XConnect's data-plane API is plain
REST (/v1/run, /v1/jobs). This thin server speaks MCP and forwards the caller's
Bearer straight to XConnect's REST API, which does the real work (validate token →
Orthanc authZ → inject to the RCON tunnel). No creds live here; it's a pass-through.

Tools mirror the CLI worker primitives on purpose (same premise, same safeguards):
  remote_run · remote_jobs · list_remote_hosts
"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
from typing import Annotated, Any, Literal

import httpx
from mcp import types as mcp_types
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel, ConfigDict, Field

XCONNECT_API = os.environ.get("XCONNECT_API", "http://127.0.0.1:8780")
# Public host nginx proxies under (DNS-rebinding allow-list). Set MCP_PUBLIC_HOST
# in the systemd unit to the real FQDN; the default stays neutral on purpose.
PUBLIC_HOST = os.environ.get("MCP_PUBLIC_HOST", "localhost")

mcp = FastMCP(
    "xconnect",
    instructions=(
        "Run shell commands on remote managed nodes through the Pow3rtool fabric — "
        "the remote equivalent of your local shell.\n\n"
        "WORKFLOW (do this in order):\n"
        "1. `whoami` — confirm who you are and what you're allowed to do (verb class + tenant).\n"
        "2. `list_remote_hosts` — discover nodes by their human NAME (e.g. 'database', "
        "'web-1'). Target a node by that name. At scale (hundreds/thousands of nodes) "
        "pass a `filter` (e.g. 'database') instead of listing everything — or, if the "
        "user already named the machine, skip listing and target it by name directly.\n"
        "3. `search_node_knowledge` — BEFORE you change anything on a node, read its shared "
        "knowledge (operator warnings, prior-agent notes, runbooks). After a material change, "
        "record what you learned with `append_node_knowledge` so the next agent inherits it.\n"
        "4. `remote_run` for quick one-shot commands. Large output returns a secure, "
        "short-lived capture handle plus previews; use `read_command_output` to page, "
        "tail, or search it. "
        "Use `remote_jobs` instead for anything long-running — it survives tunnel blips and "
        "is reattachable.\n\n"
        "ARGUMENTS: every run takes `node` (the target) and `command` (the shell line to run, "
        "exactly as you'd type in bash, e.g. `hostname && uname -a`). Commands execute via "
        "`bash -lc` on the node.\n\n"
        "AUTH: calls run under YOUR identity (per-user OAuth) and are authorized centrally per "
        "node+verb; an unauthorized call returns a 403 with the reason — that is policy, not a "
        "bug to route around."
    ),
    host=os.environ.get("MCP_HOST", "127.0.0.1"),
    port=int(os.environ.get("MCP_PORT", "8781")),
    # Stateful streamable-http: issue Mcp-Session-Id + hold the server->client SSE
    # stream so the client reaches a durable "connected" state (not just one-shot).
    stateless_http=False,
    json_response=False,
    # Allow the nginx-proxied public host through the SDK's DNS-rebinding guard.
    transport_security=TransportSecuritySettings(
        allowed_hosts=[PUBLIC_HOST, f"{PUBLIC_HOST}:443", "127.0.0.1:8781", "localhost:8781"],
        allowed_origins=[f"https://{PUBLIC_HOST}", "http://127.0.0.1:8781"],
    ),
)


def _bearer(ctx: Context) -> str:
    """Pull the caller's OAuth Bearer off the incoming HTTP request to forward it."""
    try:
        req = ctx.request_context.request
        if req is not None:
            return req.headers.get("authorization", "")
    except Exception:
        pass
    return ""


class AgentToolResponse(BaseModel):
    """Stable top-level schema shared by every XConnect tool result."""

    model_config = ConfigDict(extra="allow")

    ok: bool
    http_status: int | None = None
    remote_http_status: int | None = None
    error: str | None = None


ToolCallResult = Annotated[mcp_types.CallToolResult, AgentToolResponse]
_LEGACY_REMOTE_RESULT = re.compile(r"^HTTP[ ]+([0-9]{3})(?:[ ](.*))?$", re.DOTALL)


def _tool_result(payload: dict[str, Any], *, is_error: bool) -> ToolCallResult:
    """Return native structuredContent plus the same JSON as a text fallback."""
    fallback = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return mcp_types.CallToolResult(
        content=[mcp_types.TextContent(type="text", text=fallback)],
        structuredContent=payload,
        isError=is_error,
    )


def _decode_remote_result(value: Any) -> tuple[int | None, Any]:
    """Decode Caller's legacy 'HTTP <status> <json>' RCON response."""
    if not isinstance(value, str):
        return None, value
    match = _LEGACY_REMOTE_RESULT.fullmatch(value)
    if match is None:
        return None, value
    status = int(match.group(1))
    body = match.group(2) or ""
    try:
        decoded: Any = json.loads(body)
    except json.JSONDecodeError:
        decoded = {"text": body}
    return status, decoded


def _response_result(response: httpx.Response) -> ToolCallResult:
    try:
        parsed: Any = response.json()
    except (json.JSONDecodeError, ValueError):
        return _tool_result(
            {
                "ok": False,
                "http_status": response.status_code,
                "error": "xconnect returned a non-JSON response",
                "response": response.text,
            },
            is_error=True,
        )

    if not isinstance(parsed, dict):
        return _tool_result(
            {
                "ok": False,
                "http_status": response.status_code,
                "error": "xconnect returned JSON that was not an object",
                "response": parsed,
            },
            is_error=True,
        )

    payload: dict[str, Any] = dict(parsed)
    payload["http_status"] = response.status_code
    remote_status, remote_result = _decode_remote_result(payload.get("result"))
    if remote_status is not None:
        payload["remote_http_status"] = remote_status
        payload["result"] = remote_result
        if isinstance(remote_result, dict) and isinstance(
            remote_result.get("output_capture"), dict
        ):
            # Make the handle easy for an agent to find without discarding the
            # complete decoded RCON result shape.
            payload["output_capture"] = remote_result["output_capture"]

    failed = not 200 <= response.status_code < 300
    if remote_status is not None:
        failed = failed or not 200 <= remote_status < 300
    failed = failed or bool(payload.get("error"))
    payload["ok"] = not failed
    if failed and not payload.get("error"):
        failed_status = remote_status if remote_status is not None else response.status_code
        payload["error"] = f"xconnect request failed with HTTP {failed_status}"
    return _tool_result(payload, is_error=failed)


def _forward(ctx: Context, method: str, path: str, body: dict | None) -> ToolCallResult:
    headers = {"Content-Type": "application/json"}
    auth = _bearer(ctx)
    if auth:
        headers["Authorization"] = auth
    try:
        response = httpx.request(
            method,
            f"{XCONNECT_API}{path}",
            json=body,
            headers=headers,
            timeout=120,
        )
        return _response_result(response)
    except httpx.HTTPError as exc:
        return _err(f"xconnect unreachable: {exc}")


def _err(message: str, **extra: object) -> ToolCallResult:
    """A structured, self-correcting error the calling model can act on."""
    return _tool_result({"ok": False, "error": message, **extra}, is_error=True)


# A node may be given as its full SPIFFE id or any unique fragment.
_NODE = Annotated[
    str,
    Field(
        description=(
            "Target node, as the EXACT `node_id` or `name` from list_remote_hosts. "
            "Node names are often opaque hostnames (e.g. 'host-7q2x') — the user's "
            "term for a machine ('the database') maps to a node via its `description`, "
            "not its name. So: call list_remote_hosts(filter='database') to find the "
            "node, then target it by its exact `node_id`. Passing an ambiguous value "
            "returns a 409 with candidate nodes — re-issue with one exact node_id."
        ),
        examples=["bb087e37-88b9-4df4-8b4c-f8ba4608666d", "host-7q2x"],
    ),
]
_COMMAND = Annotated[
    str,
    Field(
        default="",
        description=(
            "The shell command line to run on the node, exactly as typed in a terminal "
            "(executed via `bash -lc`). Example: 'hostname && uname -a'."
        ),
        examples=["hostname && uname -a", "df -h /", "systemctl is-active nginx"],
    ),
]


def _resolve_command(command: str, cmd: str) -> str:
    """Accept the command under either `command` (preferred) or `cmd` (alias) —
    LLMs reach for both. Returns the non-empty one, or '' if neither was given."""
    return (command or cmd or "").strip()


@mcp.tool()
def remote_run(
    node: _NODE,
    ctx: Context,
    command: _COMMAND = "",
    cmd: Annotated[
        str,
        Field(default="", description="Alias for `command`; either name works."),
    ] = "",
    capture_output: Annotated[
        bool,
        Field(
            default=False,
            description=(
                "Force stdout/stderr into a secure 10-minute server-side capture and "
                "return previews plus a capture_id. Output above 32 KiB is captured "
                "automatically even when this is false."
            ),
        ),
    ] = False,
) -> ToolCallResult:
    """Run a ONE-SHOT shell command on a managed node and return its output.

    The remote equivalent of running a command in a terminal: the line runs via
    `bash -lc` on the target node and you get back stdout/stderr + exit code
    (output is size-bounded). Use this for quick commands that finish in seconds;
    for anything long-running use `remote_jobs` instead (it survives tunnel blips).

    Args:
        node: the target node (full SPIFFE id or a unique fragment — see
            list_remote_hosts).
        command: the shell command line, e.g. "hostname && uname -a".

    Example:
        remote_run(node="bb087e37", command="df -h /")
    """
    shell = _resolve_command(command, cmd)
    if not shell:
        return _err(
            "Missing the command to run. Pass it in `command` (the shell line, "
            "e.g. 'uname -a').",
            example={"node": node or "<node-id-or-fragment>", "command": "hostname && uname -a"},
        )
    body = {"node": node, "cmd": shell}
    if capture_output:
        body["capture"] = True
    return _forward(ctx, "POST", "/v1/run", body)


@mcp.tool()
def remote_jobs(node: _NODE, ctx: Context, command: _COMMAND = "",
    cmd: Annotated[str, Field(default="", description="Alias for `command`; either name works.")] = "") -> ToolCallResult:
    """Start a LONG-RUNNING job on a node (use instead of remote_run for anything
    not near-instant).

    Returns a job_id. The job keeps running and buffering output even across a
    tunnel blip, and is reattachable by cursor — so it won't be lost if the
    connection drops. Same arguments as remote_run.

    Args:
        node: the target node (full SPIFFE id or a unique fragment).
        command: the shell command line to start.

    Example:
        remote_jobs(node="bb087e37", command="apt-get update && apt-get -y upgrade")
    """
    shell = _resolve_command(command, cmd)
    if not shell:
        return _err(
            "Missing the command to run. Pass it in `command` (the shell line).",
            example={"node": node or "<node-id-or-fragment>", "command": "long-running-cmd …"},
        )
    return _forward(ctx, "POST", "/v1/jobs", {"node": node, "cmd": shell})


@mcp.tool()
def read_command_output(
    capture_id: Annotated[
        str,
        Field(
            min_length=36,
            max_length=36,
            description="The capture_id returned by remote_run.",
            examples=["cap_0123456789abcdef0123456789abcdef"],
        ),
    ],
    ctx: Context,
    stream: Annotated[
        Literal["stdout", "stderr"],
        Field(default="stdout", description="Which captured stream to inspect."),
    ] = "stdout",
    mode: Annotated[
        Literal["page", "tail", "search"],
        Field(
            default="page",
            description=(
                "page reads from a character offset; tail reads the final limit "
                "characters; search applies a bounded RE2 regex line by line. "
                "To tail output, set mode='tail' and limit to the number of "
                "characters; do not pass a negative offset."
            ),
        ),
    ] = "page",
    offset: Annotated[
        int,
        Field(
            default=0,
            ge=0,
            description=(
                "Zero-based character offset for page mode. For final output, use "
                "mode='tail' and limit=N; negative offsets are invalid."
            ),
        ),
    ] = 0,
    limit: Annotated[
        int,
        Field(
            default=12000,
            ge=1,
            le=64000,
            description="Maximum characters returned (default 12,000; hard max 64,000).",
        ),
    ] = 12000,
    pattern: Annotated[
        str,
        Field(
            default="",
            max_length=256,
            description="RE2 regular expression required by search mode.",
        ),
    ] = "",
    start_line: Annotated[
        int,
        Field(
            default=0,
            ge=0,
            description="Zero-based line at which search mode begins or resumes.",
        ),
    ] = 0,
    context: Annotated[
        int,
        Field(default=0, ge=0, le=10, description="Context lines around search matches."),
    ] = 0,
    max_matches: Annotated[
        int,
        Field(default=20, ge=1, le=100, description="Maximum search matches returned."),
    ] = 20,
) -> ToolCallResult:
    """Inspect a large remote_run result without loading all of it into context.

    Captures are ephemeral (10 minutes), RAM-only, and scoped to the same tenant,
    human identity, and agent application that created them. The server re-checks
    current authorization on every read. Use next_offset for page mode or
    next_start_line for search mode to continue.

    To read the final N characters, set mode="tail" and limit=N. Do not use a
    negative offset; offset is only a forward cursor for page mode.
    """
    return _forward(
        ctx,
        "POST",
        "/v1/output/read",
        {
            "capture_id": capture_id,
            "stream": stream,
            "mode": mode,
            "offset": offset,
            "limit": limit,
            "pattern": pattern,
            "start_line": start_line,
            "context": context,
            "max_matches": max_matches,
        },
    )


@mcp.tool()
def list_remote_hosts(
    ctx: Context,
    filter: Annotated[
        str,
        Field(
            default="",
            description=(
                "Substring to narrow the list by node name or id (case-insensitive), "
                "e.g. 'database', 'web', 'us-east'. STRONGLY recommended when the fleet "
                "is large — without it you only get the first page."
            ),
            examples=["database", "web", "prod"],
        ),
    ] = "",
    limit: Annotated[
        int,
        Field(default=50, description="Max hosts to return (default 50)."),
    ] = 50,
) -> ToolCallResult:
    """Discover the nodes you can reach, BY HUMAN NAME. Start here to find a target.

    Returns each host as {name, description, svid, node_id, online}, plus
    `total_matched` and `total_online`. `name` is often an opaque hostname
    (e.g. "host-7q2x"); `description` is the human role ("primary database")
    that maps a user's term to the node. Pass the exact `node_id` (or exact name)
    as `node` to remote_run / remote_jobs.

    AT SCALE (hundreds/thousands of nodes): do NOT enumerate everything. When the
    user names a machine ("the database box"), call this with `filter="database"`
    (matches name AND description), pick the node, then target its exact `node_id`.
    The result is paged (see `truncated`/`total_matched`) — narrow the filter
    rather than raising the limit. If a target is ambiguous, remote_run returns a
    409 with candidates; re-issue with one exact node_id.
    """
    qs = []
    if filter:
        qs.append("filter=" + urllib.parse.quote(filter))
    if limit:
        qs.append("limit=" + str(int(limit)))
    path = "/v1/hosts" + ("?" + "&".join(qs) if qs else "")
    return _forward(ctx, "GET", path, None)


@mcp.tool()
def remote_read(
    node: _NODE,
    path: Annotated[str, Field(description="Absolute path of the file to read on the node.")],
    ctx: Context,
    offset: Annotated[int, Field(default=0, description="1-based start line (default: from the top).")] = 0,
    limit: Annotated[int, Field(default=0, description="Max lines to return (default: a large window).")] = 0,
) -> ToolCallResult:
    """Read a file on a managed node. Returns line-numbered content PLUS a `hash`
    — keep that hash: remote_edit/remote_write take it as `expected_hash` so your
    change is rejected (409 stale) if the file moved under you. Always read before
    you edit. Output is bounded; page large files with offset/limit."""
    body = {"node": node, "path": path}
    if offset:
        body["offset"] = offset
    if limit:
        body["limit"] = limit
    return _forward(ctx, "POST", "/v1/read", body)


@mcp.tool()
def remote_edit(
    node: _NODE,
    path: Annotated[str, Field(description="Absolute path of the file to edit.")],
    old_string: Annotated[str, Field(description="Exact text to replace (include surrounding context so it's unique).")],
    new_string: Annotated[str, Field(description="Replacement text.")],
    ctx: Context,
    replace_all: Annotated[bool, Field(default=False, description="Replace every occurrence (else exactly one; ambiguous match → 409).")] = False,
    expected_hash: Annotated[str, Field(default="", description="The `hash` from your remote_read — the read-before-write guard.")] = "",
) -> ToolCallResult:
    """Make an in-place string replacement in a file on a node. `old_string` must
    match exactly and be unique unless replace_all=true (a multi-match without it
    is a 409 — add context). Pass `expected_hash` from a prior remote_read; if the
    file changed since, the edit is refused (409 stale) so you never clobber a
    concurrent change. Requires 'full' access. Binary files are refused."""
    body = {"node": node, "path": path, "old_string": old_string, "new_string": new_string}
    if replace_all:
        body["replace_all"] = True
    if expected_hash:
        body["expected_hash"] = expected_hash
    return _forward(ctx, "POST", "/v1/edit", body)


@mcp.tool()
def remote_write(
    node: _NODE,
    path: Annotated[str, Field(description="Absolute path of the file to write.")],
    content: Annotated[str, Field(description="Full new file content.")],
    ctx: Context,
    expected_hash: Annotated[str, Field(default="", description="`hash` from remote_read when overwriting an existing file (the guard).")] = "",
    force: Annotated[bool, Field(default=False, description="Overwrite an existing file blindly (no expected_hash). Use sparingly.")] = False,
    make_dirs: Annotated[bool, Field(default=False, description="Create parent directories if missing.")] = False,
    owner: Annotated[
        str,
        Field(default="", description="Set the file owner after writing, as a local user name or decimal UID."),
    ] = "",
    group: Annotated[
        str,
        Field(default="", description="Set the file group after writing, as a local group name or decimal GID."),
    ] = "",
    mode: Annotated[
        str,
        Field(
            default="",
            pattern=r"^(?:0o)?0?[0-7]{3}$",
            description=(
                "Set exact file permission bits after writing, as an octal string "
                "such as '0640'. Special setuid/setgid/sticky bits are refused."
            ),
            examples=["0600", "0640", "0755"],
        ),
    ] = "",
) -> ToolCallResult:
    """Create or overwrite a file on a node with `content`. Creating a new file
    just works. Overwriting an EXISTING file is refused (409) unless you pass
    `expected_hash` from a remote_read (preferred — proves you saw the current
    contents) or force=true (blind overwrite). Optional `owner`, `group`, and
    `mode` metadata are validated by RCON before it writes the content. When
    omitted, existing ownership/mode behavior is preserved. Requires 'full' access."""
    body = {"node": node, "path": path, "content": content}
    if expected_hash:
        body["expected_hash"] = expected_hash
    if force:
        body["force"] = True
    if make_dirs:
        body["make_dirs"] = True
    if owner:
        body["owner"] = owner
    if group:
        body["group"] = group
    if mode:
        body["mode"] = mode
    return _forward(ctx, "POST", "/v1/write", body)


@mcp.tool()
def search_node_knowledge(
    node: _NODE,
    ctx: Context,
    query: Annotated[
        str,
        Field(
            default="",
            description="Optional focus term (e.g. 'nginx', 'reboot', 'backups') to "
            "filter this node's recorded knowledge. Leave empty to get everything.",
        ),
    ] = "",
) -> ToolCallResult:
    """Read the shared, persistent KNOWLEDGE about a node — ALWAYS do this BEFORE you
    touch a box. This is the fabric's "wiki for agents": what previous operators and
    agents learned about this exact machine, so you inherit hard-won context instead
    of rediscovering it (or breaking something a predecessor already warned about).

    Returns three layers:
      • critical_core  — operator-curated must-heed warnings/runbooks (e.g. "PROD DB,
        do not restart without a change ticket"). Treat these as standing orders.
      • node_knowledge — what prior agents recorded about THIS node (newest first).
      • similar_nodes  — knowledge inferred from like-named/same-role siblings; it
        MAY NOT apply here (each entry says so) — corroborate before acting on it.

    Also returns `over_budget`: when true, this node's knowledge has grown past the
    curation threshold — still usable, but a platform engineer should prune it.

    Provenance (who wrote it, when, operator vs agent) is stamped by the fabric and
    returned with each entry — weigh agent-written notes accordingly. Reading needs
    only read-only access. After you make a material change, record what you learned
    with append_node_knowledge so the next agent inherits it.
    """
    return _forward(ctx, "POST", "/v1/knowledge/search", {"node": node, "query": query})


@mcp.tool()
def append_node_knowledge(
    node: _NODE,
    content: Annotated[
        str,
        Field(
            description="The durable fact to record about this node, in plain prose. "
            "Write it for the NEXT agent/operator: what's true about this box, what "
            "broke and why, the gotcha, the runbook step. Be specific and concise "
            "(e.g. 'Postgres data dir is /srv/pg on a separate ZFS dataset; never "
            "`systemctl restart` during business hours — failover takes ~90s'). "
            "Do NOT include who you are — your identity is recorded automatically.",
            examples=[
                "nginx vhosts live in /etc/nginx/sites-enabled; reload (don't restart) after edits.",
                "This box backs the billing DB — snapshot before any kernel/package upgrade.",
            ],
        ),
    ],
    ctx: Context,
) -> ToolCallResult:
    """Record durable KNOWLEDGE about a node so the NEXT agent or operator inherits it
    — the write side of the shared "wiki for agents". Use this after you learn
    something material about a box: its layout, a hazard, a runbook, why a change was
    made, what NOT to do.

    Your identity (who) and the time (when) are stamped by the fabric automatically —
    never put that in `content`, and don't bother trying to flag something as
    "critical": only operators can curate the always-surfaced critical core (via the
    console). This requires 'full' access (writing a box's memory is a mutation);
    read-only callers get a 403. The entry is added (append-only) and immediately
    visible to search_node_knowledge.
    """
    return _forward(ctx, "POST", "/v1/knowledge/append", {"node": node, "content": content})


@mcp.tool()
def whoami(ctx: Context) -> ToolCallResult:
    """Show YOUR identity and permissions as the fabric sees them (no arguments).

    Returns your principal (UPN, object id, tenant, scopes) and the authorization
    you've been granted (tenant, verb-class grants, effective access). Call this
    first to confirm who you are and what you're allowed to do before running
    commands — it never changes anything."""
    return _forward(ctx, "GET", "/v1/whoami", None)


# Advertise TOOLS-ONLY. FastMCP wires up resource/prompt request handlers by
# default, so it advertises `resources`+`prompts` capabilities even though we
# expose none. Dropping those handlers makes get_capabilities() omit them — which
# is both correct (we have no resources/prompts) and avoids MCP clients that tear
# the connection down inside their resource/prompt discovery step.
for _rt in (
    mcp_types.ListResourcesRequest, mcp_types.ReadResourceRequest,
    mcp_types.ListResourceTemplatesRequest, mcp_types.ListPromptsRequest,
    mcp_types.GetPromptRequest, mcp_types.SubscribeRequest, mcp_types.UnsubscribeRequest,
):
    mcp._mcp_server.request_handlers.pop(_rt, None)


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
