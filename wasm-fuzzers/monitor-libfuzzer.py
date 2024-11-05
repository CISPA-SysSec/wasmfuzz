import argparse
import fileinput
from pathlib import Path
import time
import re

from monitor import Stats, jsonl_stream


def parse_status_line(s, ts_secs):
    m = re.search(r'#([0-9]+)[ \t]+\w+[ \t]+cov: ([0-9]+)[ \t]+ft: ([0-9]+)[ \t]+corp: ([0-9]+)/', s)
    if m is None: return

    execs = int(m.group(1))
    cov = int(m.group(2))
    ft = int(m.group(3))
    corp = int(m.group(4))
    speed = float(m.group(5))

    return Stats(
        ts_secs=ts_secs,
        cov_metrics={"pcguard": cov, "libfuzzer-ft": ft},
        corpus_size=corp,
        total_execs=execs,
        speed=speed,
    )

def run(output_path: Path):
    with jsonl_stream(output_path) as out:
        start = time.time()
        for line in fileinput.input():
            stat = parse_status_line(line, time.time() - start)
            if stat is None: continue
            out.add(stat)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output-path", default="/monitor.jsonl")
    args = parser.parse_args()
    run(Path(args.output_path))