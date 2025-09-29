import logging
import os

# ANSI color codes
RESET = "\033[0m"
GRAY = "\033[90m"
YELLOW = "\033[33m"
RED = "\033[31m"


class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: GRAY,
        logging.INFO: "",
        logging.WARNING: YELLOW,
        logging.ERROR: RED,
        logging.CRITICAL: RED,
    }

    def format(self, record):
        color = self.COLORS.get(record.levelno, "")
        message = super().format(record)
        return f"{color}{message}{RESET}"


# Create logger
logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

handler = logging.StreamHandler()
formatter = ColorFormatter("%(asctime)s [%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
