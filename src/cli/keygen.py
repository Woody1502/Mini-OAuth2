import json
import logging
import os
import secrets

from src.core.logging_config import configure_cli_logging

configure_cli_logging()
logger = logging.getLogger(__name__)


def main() -> None:
    secret = secrets.token_urlsafe(32)
    for config in ('config/auth.json', 'config/rs.json'):
        with open(config) as f:
            data = json.load(f)
        data['auth_secret'] = secret
        with open(config, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(config, 0o600)
    logger.info("новый секрет: %s", secret)


if __name__ == "__main__":
    main()
