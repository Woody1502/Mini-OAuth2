import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_FORMAT = "%(asctime)s - [%(levelname)s] - %(name)s - %(message)s"
DT_FORMAT = "%d.%m.%Y %H:%M:%S"


def configure_logging(log_file: str = "logs/server.log") -> None:
    Path(log_file).parent.mkdir(exist_ok=True)
    rotating_handler = RotatingFileHandler(
        log_file, maxBytes=10 ** 6, backupCount=5
    )
    logging.basicConfig(
        datefmt=DT_FORMAT,
        format=LOG_FORMAT,
        level=logging.INFO,
        handlers=(rotating_handler,),
    )
    logging.getLogger("uvicorn").propagate = False
    logging.getLogger("uvicorn.access").propagate = False
    logging.getLogger("uvicorn.error").propagate = False


def configure_cli_logging() -> None:
    logging.basicConfig(
        datefmt=DT_FORMAT,
        format=LOG_FORMAT,
        level=logging.INFO,
        handlers=(logging.StreamHandler(),),
    )
