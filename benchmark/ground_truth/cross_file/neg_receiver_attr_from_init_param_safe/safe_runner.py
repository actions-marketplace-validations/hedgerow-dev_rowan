import logging

logger = logging.getLogger(__name__)


class SafeRunner:
    def run(self, cmd):
        logger.info("requested %s", cmd)
