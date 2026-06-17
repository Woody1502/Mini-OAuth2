import json
from pydantic import BaseModel


class RSConfig(BaseModel):
    issuer: str
    aud: str
    clock_skew_sec: int
    auth_secret: str
    data_dir: str

    @classmethod
    def load(cls, path: str = "config/rs.json") -> "RSConfig":
        with open(path) as f:
            data = json.load(f)
        return cls(**data)
