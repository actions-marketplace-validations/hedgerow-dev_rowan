import os
import subprocess


def disk_usage(directory: str) -> str:
    return subprocess.run(f"du -sh {directory}", shell=True, capture_output=True, text=True).stdout


def disk_usage_safe(directory: str) -> str:
    return subprocess.run(["du", "-sh", "--", directory], capture_output=True, text=True).stdout


def workspace_listing(directory: str) -> list[str]:
    return os.listdir(os.path.join("/srv", os.path.basename(directory)))
