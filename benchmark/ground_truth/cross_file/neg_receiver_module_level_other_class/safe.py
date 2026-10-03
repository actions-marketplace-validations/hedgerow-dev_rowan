import logging

logger = logging.getLogger(__name__)


class Safe:
    def go(self, cmd):
        logger.info("requested %s", cmd)
