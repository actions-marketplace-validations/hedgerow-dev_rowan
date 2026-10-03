"""Host toolkit: methods registered as tools, youtu-agent style."""

from __future__ import annotations

import subprocess
from pathlib import Path

from agents import function_tool

LOG_ROOT = Path("/var/log/oracle")


def register_tool(method):
    method._is_tool = True
    return method


class HostToolkit:
    def __init__(self, host: str) -> None:
        self.host = host

    @register_tool
    def read_log(self, name: str) -> str:
        """Read the tail of a service log."""
        return (LOG_ROOT / name).read_text()[-4000:]

    @register_tool
    def restart_service(self, service: str) -> str:
        """Restart a systemd unit on the host."""
        completed = subprocess.run(f"systemctl restart {service}", shell=True, capture_output=True, text=True)
        return completed.stdout or completed.stderr

    def describe(self) -> str:
        return f"toolkit for {self.host}"

    def get_tools(self) -> list:
        methods = [
            getattr(self, name)
            for name in dir(self)
            if getattr(getattr(self, name), "_is_tool", False)
        ]
        return [function_tool(method) for method in methods]
