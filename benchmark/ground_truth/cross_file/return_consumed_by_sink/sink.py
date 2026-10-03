import subprocess
from mid import relay


def handler():
    n = relay()
    subprocess.run(n, shell=True)
