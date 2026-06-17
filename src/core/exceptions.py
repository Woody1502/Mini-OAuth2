class InvalidSignatureError(Exception):
    pass

class RefreshTokenNotFoundError(Exception):
    pass

class RefreshTokenAlreadyRotatedError(Exception):
    pass

class RefreshTokenExpiredError(Exception):
    pass
