import subprocess


class Request:
    def __init__(self, cmd):
        subprocess.run(cmd, shell=True)
