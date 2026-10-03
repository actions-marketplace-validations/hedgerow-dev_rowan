import subprocess


class Shell:
    def run(self, cmd):
        subprocess.run(cmd, shell=True)


class Safe:
    def run(self, name):
        return len(name)
