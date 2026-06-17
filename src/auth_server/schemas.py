from pydantic import BaseModel


class TokenRequest(BaseModel):
    grant_type: str
    client_id: str
    client_secret: str
    scopes: list[str] = []
    username: str | None = None
    password: str | None = None


class RefreshRequest(BaseModel):
    grant_type: str = "refresh_token"
    refresh_token: str
    client_id: str
    client_secret: str


class RevokeRequest(BaseModel):
    token: str
    token_type_hint: str | None = None


class IntrospectRequest(BaseModel):
    token: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    scope: str
    refresh_token: str | None = None


class IntrospectActiveResponse(BaseModel):
    active: bool
    typ: str
    alg: str
    iss: str
    aud: str
    sub: str
    client_id: str
    scopes: list[str]
    roles: list[str]
    jti: str
    iat: int
    exp: int


class IntrospectInactiveResponse(BaseModel):
    active: bool


class WellKnownResponse(BaseModel):
    issuer: str
    aud: str
    access_ttl_sec: int
    refresh_ttl_days: int
    token_alg: str
