class InvalidClientError(Exception):
    pass


class InvalidGrantError(Exception):
    pass


class UnauthorizedClientError(Exception):
    pass


class UnsupportedGrantTypeError(Exception):
    pass


class AccessDeniedError(Exception):
    pass


class TokenReuseError(Exception):
    pass
