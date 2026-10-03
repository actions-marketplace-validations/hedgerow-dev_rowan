"""NetworkManager helpers."""

import subprocess


def rename_connection(interface, hostname):
    """Point `interface` at `hostname` in NetworkManager."""
    subprocess.run(
        f"nmcli con mod {interface} connection.id {hostname}",
        shell=True,
        check=True,
    )
