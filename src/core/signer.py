import base64
import hashlib
import hmac


class SignerHS256:
    def __init__(self, secret: str):
        self.secret = secret

    def sign(self, payload_bytes: bytes) -> str:
        digest = hmac.new(self.secret.encode(), payload_bytes, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).decode()

    def verify(self, payload_bytes: bytes, signature: str) -> bool:
        expected = self.sign(payload_bytes)
        return hmac.compare_digest(expected, signature)
