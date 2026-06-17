import uuid


def build_payload(config, sub: str, scopes: list[str], client_id: str, roles: list[str], now: int) -> dict:
    return {
        "typ": "AT",
        "alg": "HS256",
        "iss": config.issuer,
        "aud": config.aud,
        "sub": sub,
        "client_id": client_id,
        "scopes": scopes,
        "roles": roles,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + config.access_ttl_sec,
    }


def token_response(access_token: str, expires_in: int, scope: str,
                   refresh_token: str | None = None) -> dict:
    resp = {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": expires_in,
        "scope": scope,
    }
    if refresh_token:
        resp["refresh_token"] = refresh_token
    return resp
