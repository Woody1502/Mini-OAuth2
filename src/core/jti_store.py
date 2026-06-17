class JtiStore:

    def __init__(self):
        self._issued: set[str] = set()

    def seen(self, jti: str) -> bool:
        return jti in self._issued

    def record(self, jti: str) -> None:
        self._issued.add(jti)

    def remove(self, jti: str) -> None:
        self._issued.discard(jti)
