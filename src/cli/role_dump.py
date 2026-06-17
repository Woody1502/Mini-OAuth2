import logging
import json

from src.core.logging_config import configure_cli_logging

configure_cli_logging()
logger = logging.getLogger(__name__)


def main() -> None:
    with open('data/roles.json') as f:
        data = json.load(f)
    for role in data:
        logger.info("%s: %s", role, data[role]['scopes'])


if __name__ == "__main__":
    main()
