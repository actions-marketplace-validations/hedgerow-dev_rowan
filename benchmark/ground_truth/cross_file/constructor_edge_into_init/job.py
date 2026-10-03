import subprocess


class Job:
    def __init__(self, cmd):
        subprocess.run(cmd, shell=True)
