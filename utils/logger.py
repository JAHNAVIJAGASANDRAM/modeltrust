"""Structured logging configuration for ModelTrust."""
import logging
from logging.handlers import RotatingFileHandler
from config import Config


def get_logger(name: str = "modeltrust") -> logging.Logger:
    """Return a configured logger writing to console and rotating log file."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    try:
        Config.LOGS_DIR.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            Config.LOGS_DIR / "modeltrust.log",
            maxBytes=2 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError:
        # Fallback to console logging only if file cannot be opened
        pass

    logger.propagate = False
    return logger
