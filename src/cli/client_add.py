import argparse
import json
import logging

from src.constants import ALL_GRANTS
from src.core.logging_config import configure_cli_logging

configure_cli_logging()
logger = logging.getLogger(__name__)


def configure_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Добавить клиента в data/clients.json')
    parser.add_argument(
        'client_id',
        help='Идентификатор клиента'
    )
    parser.add_argument(
        'client_secret',
        help='Секрет клиента'
    )
    parser.add_argument(
        '--grants',
        nargs='+',
        choices=ALL_GRANTS,
        default=['client_credentials'],
        help=f'Разрешённые grant-типы: {", ".join(ALL_GRANTS)}'
    )
    parser.add_argument(
        '--scopes',
        nargs='+',
        default=['payments:read'],
        help='Разрешённые скоупы: payments:read, payments:write, users:read, ...'
    )
    parser.add_argument(
        '--aud',
        default='payments-api',
        help='Целевая аудитория токена (по умолчанию: payments-api)'
    )
    return parser


def main() -> None:
    parser = configure_argument_parser()
    args = parser.parse_args()

    client = {
        "client_id": args.client_id,
        "client_secret": args.client_secret,
        "allowed_grants": args.grants,
        "allowed_scopes": args.scopes,
        "aud": args.aud,
    }

    with open("data/clients.json") as f:
        clients = json.load(f)
    clients.append(client)
    with open("data/clients.json", "w") as f:
        json.dump(clients, f, indent=2)

    logger.info("клиент %s добавлен", args.client_id)


if __name__ == "__main__":
    main()
