import json
import time


class MetricsStore:
    def __init__(self, path: str):
        self.path = path

    def record(self, event: str, **kwargs) -> None:
        entry = {"ts": int(time.time()), "event": event, **kwargs}
        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")
