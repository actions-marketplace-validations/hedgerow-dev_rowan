import subprocess


def run_job(cmd):
    subprocess.run(["status", "--", cmd])
