from safe_runner import SafeRunner


class Svc:
    def __init__(self, runner: SafeRunner):
        self.runner = runner

    def go(self, cmd):
        self.runner.run(cmd)
