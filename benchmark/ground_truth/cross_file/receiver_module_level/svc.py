import subprocess


class Svc:
    def go(self, cmd):
        subprocess.run(cmd, shell=True)
