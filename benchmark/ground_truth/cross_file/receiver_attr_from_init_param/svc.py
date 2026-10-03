from runner import Runner


class Svc:
    def __init__(self, runner: Runner):
        self.runner = runner

    def go(self, cmd):
        self.runner.run(cmd)
