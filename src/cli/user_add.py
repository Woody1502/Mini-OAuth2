import argparse
import json
import logging
import uuid

from src.core.logging_config import configure_cli_logging
from src.core.password_hasher import PasswordHasher

configure_cli_logging()
logger = logging.getLogger(__name__)


def configure_argument_parser(available_roles: list[str]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Добавить пользователя в data/users.json')
    parser.add_argument(
        'username',
        help='Имя пользователя'
    )
    parser.add_argument(
        'password',
        help='Пароль (будет захеширован)'
    )
    parser.add_argument(
        '--roles',
        nargs='+',
        choices=available_roles,
        default=['viewer'],
        help=f'Роли: {", ".join(available_roles)}'
    )
    return parser


def main() -> None:
    with open("data/roles.json") as f:
        available_roles = list(json.load(f).keys())

    parser = configure_argument_parser(available_roles)
    args = parser.parse_args()

    user = {
        "user_id": f"u-{uuid.uuid4().hex[:8]}",
        "username": args.username,
        "password_hash": PasswordHasher().hash(args.password),
        "roles": args.roles,
        "status": "active",
    }

    with open("data/users.json") as f:
        users = json.load(f)
    users.append(user)
    with open("data/users.json", "w") as f:
        json.dump(users, f, indent=2)

    logger.info("пользователь %s добавлен с id %s", args.username, user['user_id'])


if __name__ == "__main__":
    main()
