import json


class UserRepoFile:
    def __init__(self, path: str):
        self.path = path

    def find_by_username(self, username: str) -> dict | None:
        with open(self.path) as f:
            data = json.load(f)
        for record in data:
            if record['username'] == username:
                return record

    def find_by_user_id(self, user_id: str) -> dict | None:
        with open(self.path) as f:
            data = json.load(f)
        for record in data:
            if record['user_id'] == user_id:
                return record


class ClientRepoFile:
    def __init__(self, path: str):
        self.path = path

    def find_by_id(self, client_id: str) -> dict | None:
        with open(self.path) as f:
            data = json.load(f)
        for record in data:
            if record['client_id'] == client_id:
                return record


class RoleRepoFile:
    def __init__(self, path: str):
        self.path = path

    def load(self) -> dict:
        with open(self.path) as f:
            return json.load(f)
