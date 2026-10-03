import subprocess
from mid import relay


def handler(cmd):
    n = relay()
    subprocess.run(cmd, shell=True)
    return n
