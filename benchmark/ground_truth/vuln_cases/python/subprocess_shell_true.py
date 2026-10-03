import subprocess


def run_backup(cmd):
    subprocess.run(cmd, shell=True)
