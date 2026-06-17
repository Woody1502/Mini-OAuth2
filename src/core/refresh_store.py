import secrets
import json
import time
from src.core.exceptions import (
    RefreshTokenNotFoundError,
    RefreshTokenAlreadyRotatedError,
    RefreshTokenExpiredError,
)


class RefreshStore:
    def __init__(self, path: str):
        self.path = path

    def create(self, user_id: str, client_id: str, exp: int) -> str:
        refresh_id = secrets.token_urlsafe(32)
        refresh_index = {"refresh_id": refresh_id, "user_id": user_id, "client_id": client_id, "exp": exp, "rotated": False}
        with open(self.path, 'a') as f:
            f.write(json.dumps(refresh_index) + '\n')
        return refresh_id

    def get(self, refresh_id: str) -> dict | None:
        tmp = None
        for record in self._read_records():
            if record["refresh_id"] == refresh_id:
                tmp = record
        return tmp

    def rotate(self, old_refresh_id: str, user_id: str, client_id: str, exp: int) -> str:
        old_record = self.get(old_refresh_id)
        if old_record is None:
            raise RefreshTokenNotFoundError('нет old refresh id')
        if old_record['rotated'] == True:
            raise RefreshTokenAlreadyRotatedError('Токен уже был использован для ротации раньше!')
        if old_record['exp'] < time.time():
            raise RefreshTokenExpiredError('Токен истёк!')

        with open(self.path, 'a') as f:
            f.write(json.dumps({**old_record, "rotated": True}) + '\n')
        
        return self.create(user_id, client_id, exp)

    def _read_records(self) -> list[dict]:
        records = []
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records