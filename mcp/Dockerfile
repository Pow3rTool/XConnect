# XConnect MCP bridge — self-contained image (same pattern as the other pow3rtool MCP
# servers). Build from the mcp/ subdir:  podman build -t xconnect-mcp mcp/
# Pure pass-through: forwards the caller's Bearer to the broker's REST API on loopback.
# No secrets, no state. Runs as non-root; config via env at runtime.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

# deps installed globally (as root) so any runtime UID can import them
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY xconnect_mcp.py .
RUN useradd --system --uid 10001 mcp
USER mcp

EXPOSE 8781
# Binds MCP_HOST:MCP_PORT (default 127.0.0.1:8781, fronted by host nginx under
# --network=host). XCONNECT_API points at the broker on loopback; MCP_PUBLIC_HOST is
# the FQDN nginx proxies under (DNS-rebinding allow-list). All via EnvironmentFile.
CMD ["python", "xconnect_mcp.py"]
