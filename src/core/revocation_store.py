import json


class RevocationStore:
    def __init__(self, path: str):
        self.path = path

    def revoke_access(self, jti: str, exp: int) -> None:
        if self.is_access_revoked(jti):
            return
        with open(self.path, 'a') as f:
            f.write(json.dumps({"type": "access", "jti": jti, "exp": exp}) + '\n')

    def revoke_refresh(self, refresh_id: str, exp: int) -> None:
        if self.is_refresh_revoked(refresh_id):
            return
        with open(self.path, 'a') as f:
            f.write(json.dumps({"type": "refresh", "refresh_id": refresh_id, "exp": exp}) + '\n')


    def is_refresh_revoked(self, refresh_id: str) -> bool:
        for record in self._read_records():
            if record["type"] == "refresh" and record["refresh_id"] == refresh_id:
                return True
        return False


    def _read_records(self) -> list[dict]:
        records = []
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    def is_access_revoked(self, jti: str) -> bool:
        for record in self._read_records():
            if record["type"] == "access" and record["jti"] == jti:
                return True
        return False
