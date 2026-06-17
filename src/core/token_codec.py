import json
import base64
import hmac
from src.core.signer import SignerHS256
from src.core.exceptions import InvalidSignatureError

class TokenCodec:
    def __init__(self, signer):
        self.signer: SignerHS256 = signer

    def encode(self, payload: dict) -> str:
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        payload_b64_str = base64.urlsafe_b64encode(payload_json.encode()).decode()
        signature_str = self.signer.sign(payload_b64_str.encode())
        return f"{payload_b64_str}.{signature_str}"


    def decode(self, token: str) -> dict:
        try:
            payload_b64_str, signature_str = token.split(".")
        except ValueError:
            raise InvalidSignatureError('broken token')
        sign_to_check_str = self.signer.sign(payload_b64_str.encode())
        compare = hmac.compare_digest(sign_to_check_str, signature_str)
        if compare:
            decoded_bytes = base64.urlsafe_b64decode(payload_b64_str.encode())
            return json.loads(decoded_bytes.decode())
        raise InvalidSignatureError('invalid signature')