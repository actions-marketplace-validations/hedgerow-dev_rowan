import subprocess


class Job:
    def __init__(self, cmd):
        self.cmd = cmd

    def run(self):
        subprocess.run("uptime", shell=True)
