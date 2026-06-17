from src.core.exceptions import InvalidSignatureError


class AuthError(Exception):
    pass


class AuthMiddleware:
    def __init__(self, token_codec, config, revocation_store, clock):
        self.token_codec = token_codec
        self.config = config
        self.revocation_store = revocation_store
        self.clock = clock

    def authenticate(self, token: str) -> dict:
        try:
            payload = self.token_codec.decode(token)
            if self.clock.is_not_yet_valid(payload["iat"]):
                raise AuthError('Token is not valid yet')
            if self.clock.is_expired(payload['exp']):
                raise AuthError('Token is expired')
            if payload.get('aud') != self.config.aud:
                raise AuthError('invalid aud')
            if self.revocation_store.is_access_revoked(payload['jti']):
                raise AuthError("Token revoked")
            return payload
        except InvalidSignatureError:
            raise AuthError('invalid token')
