import subprocess


class Runner:
    def run(self, cmd):
        subprocess.run(cmd, shell=True)
