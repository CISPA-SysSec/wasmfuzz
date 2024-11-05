from dataclasses import dataclass
from io import TextIOWrapper
from typing import Dict, Optional
from contextlib import contextmanager
from pathlib import Path
import json

@dataclass
class Stats:
    ts_secs: float
    total_execs: int
    cov_metrics: Dict[str, float] = {}
    crashes: Optional[int] = None
    hangs: Optional[int] = None
    finds: Optional[int] = None
    recent_speed: Optional[float] = None
    corpus_entries: Optional[int]


class JsonlStream:
    def __init__(self, f: TextIOWrapper):
        self.f = f

    def add(self, obj):
        self.f.write(json.dumps(obj) + "\n")
        self.f.flush()

@contextmanager
def jsonl_stream(path: Path):
    with open(path, "w") as f:
        try:
            yield JsonlStream(f)
        finally:
            pass