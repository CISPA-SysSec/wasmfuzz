import argparse
from pathlib import Path
import time

from monitor import Stats, jsonl_stream

def parse_stats_file(path: Path):
    with open(path) as f:
        data = f.read()
    if data.count("command_line      :") != 1:
        return None
    for line in data.splitlines():
        assert line[18] == ":"
    p = {line[:18].strip(): line[19:].strip() for line in data.splitlines()}
    return Stats(
        ts_secs=float(p["run_time"]),
        cov_metrics={
            "bitmap_cvg": float(p["bitmap_cvg"][:-1]) / 100,
            "edges_found": int(p["edges_found"]),
            "total_edges": int(p["total_edges"]),
        },
        total_execs=int(p["execs_done"]),
        recent_speed=float(p["execs_ps_last_min"]),
        corpus_entries=int(p["corpus_count"]),
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("sync-dir", default="/sync/default/")
    parser.add_argument("poll-secs", default=5)
    parser.add_argument("output-path", default="/monitor.jsonl")
    args = parser.parse_args()
    with jsonl_stream(args.output_path) as out:
        start = time.time()
        prev_ts = None
        while True:
            stat = parse_stats_file(Path(args.syncdir) / "fuzzer_stats")
            if stat and prev_ts != stat.ts_secs:
                out.add(stat)
                prev_ts = stat.ts_secs
            time.sleep(float(args.poll_secs))