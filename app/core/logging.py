from pathlib import Path
from loguru import logger


BASE_DIR = Path(__file__).resolve().parents[2]
LOG_DIR = BASE_DIR / "logs"

LOG_DIR.mkdir(parents=True, exist_ok=True)


def setup_logging():
    logger.remove()

    logger.add(
        LOG_DIR / "system.log",
        rotation="10 MB",
        retention="7 days",
        level="INFO",
        encoding="utf-8"
    )

    logger.add(
        LOG_DIR / "events.log",
        rotation="10 MB",
        retention="7 days",
        level="INFO",
        encoding="utf-8"
    )

    logger.add(
        LOG_DIR / "alerts.log",
        rotation="10 MB",
        retention="7 days",
        level="WARNING",
        encoding="utf-8"
    )

    logger.add(
        LOG_DIR / "errors.log",
        rotation="10 MB",
        retention="7 days",
        level="ERROR",
        encoding="utf-8"
    )

    logger.add(
        LOG_DIR / "audit.log",
        rotation="10 MB",
        retention="7 days",
        level="INFO",
        encoding="utf-8"
    )

    logger.info("RDRS logging system initialized")


setup_logging()