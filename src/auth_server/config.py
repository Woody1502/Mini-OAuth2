import json

from pydantic import BaseModel


class AuthConfig(BaseModel):
    issuer: str
    aud: str
    access_ttl_sec: int
    refresh_ttl_days: int
    clock_skew_sec: int
    token_alg: str
    auth_secret: str
    data_dir: str

    @classmethod
    def load(cls, path: str = "config/auth.json") -> "AuthConfig":
        with open(path) as f:
            data = json.load(f)
        return cls(**data)
