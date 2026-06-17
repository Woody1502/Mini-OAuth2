import os
import hashlib
import base64
import hmac
from src.constants import PBKDF2_DEFAULT_ITERATIONS

class PasswordHasher:
    def __init__(self, iterations: int = PBKDF2_DEFAULT_ITERATIONS):
        self.iterations = iterations

    def hash(self, password: str) -> str:
        salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, self.iterations)
        salt_b64 = base64.urlsafe_b64encode(salt).decode()
        hash_b64 = base64.urlsafe_b64encode(dk).decode()
        return f"pbkdf2_sha256${self.iterations}${salt_b64}${hash_b64}"

    def verify(self, password: str, encoded: str) -> bool:
        parsed = encoded.split("$")
        salt_b64 = parsed[2]
        iters = int(parsed[1])
        hashed_b64 = parsed[3]
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        hashed = base64.urlsafe_b64decode(hashed_b64.encode())
        pass_str = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters)
        return hmac.compare_digest(hashed, pass_str)
