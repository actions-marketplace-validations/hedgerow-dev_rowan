import subprocess


def run_job(cmd):
    subprocess.run(["sh", "-c", cmd])
