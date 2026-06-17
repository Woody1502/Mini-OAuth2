import time

class Clock:

    def __init__(self, skew_sec: int = 0):
        self.skew_sec = skew_sec

    def now(self) -> int:
        return int(time.time())

    def is_expired(self, exp: int) -> bool:
        return self.now() > exp + self.skew_sec

    def is_not_yet_valid(self, issued_at: int) -> bool:
        return self.now() < issued_at - self.skew_sec
