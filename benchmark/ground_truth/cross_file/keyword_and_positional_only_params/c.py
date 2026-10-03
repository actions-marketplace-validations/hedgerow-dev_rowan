import subprocess


def run_kw(*, cmd):
    subprocess.run(cmd, shell=True)


def run_pos(cmd, /):
    subprocess.run(cmd, shell=True)
