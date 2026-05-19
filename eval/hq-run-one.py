#!/usr/bin/env python3
import os
import json
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

_terminate_signal = 0


def count_cores_from_hq_cpus(hq_cpus: str | None) -> int:
    if not hq_cpus:
        return 1
    return max(1, sum(1 for cpu in hq_cpus.split(",") if cpu.strip()))


def parse_timeout_seconds(timeout: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)([smh])", timeout)
    if not match:
        raise ValueError(
            "timeout must match '<n>s', '<n>m', or '<n>h' (e.g. 1s/1m/1h)"
        )
    value = int(match.group(1))
    unit = match.group(2)
    scale = {"s": 1, "m": 60, "h": 3600}[unit]
    return value * scale


def apply_env_assignments(env_assigns: str) -> None:
    if not env_assigns:
        return
    for assignment in env_assigns.split():
        if "=" not in assignment:
            print(f"Skipping malformed env assignment: {assignment}", file=sys.stderr)
            continue
        key, value = assignment.split("=", 1)
        os.environ[key] = value


def signal_handler(sig: int, _frame: object) -> None:
    global _terminate_signal
    _terminate_signal = sig


def terminate_process(proc: subprocess.Popen[bytes] | None, label: str) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        return
    try:
        os.killpg(pgid, signal.SIGINT)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=2)
        return
    except subprocess.TimeoutExpired:
        pass

    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        print(f"[hq-run] warning: failed to kill {label} pid={proc.pid}", file=sys.stderr)


def main() -> int:
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    task = json.loads(os.environ["HQ_ENTRY"])

    target = str(task["target"])
    bucket = str(task["bucket"])
    wasmfuzz = str(task["fuzzer"])
    monitor_bin = str(task["monitor"])
    runs_dir_raw = str(task["runs_dir"])
    timeout = str(task["timeout"])
    timeout_seconds = parse_timeout_seconds(timeout)
    monitor_interval = str(task.get("monitor_interval") or "60s")
    corpora_dir = str(task.get("corpora_dir") or "")
    exp_arg = str(task.get("experiment_arg") or "")
    env_assigns = str(task.get("env_assignments") or "")

    runs_dir = Path(runs_dir_raw)
    apply_env_assignments(env_assigns)

    cores = count_cores_from_hq_cpus(os.environ.get("HQ_CPUS"))

    runs_dir.mkdir(parents=True, exist_ok=True)
    target_stem = Path(target).stem
    job_id = (
        f"{target_stem}-{bucket}-{int(time.time())}-"
        f"{os.environ.get('HQ_JOB_ID', 'x')}.{os.environ.get('HQ_TASK_ID', '0')}"
    )
    out_file = runs_dir / f"{job_id}.jsonl"
    corpus_dir = Path(tempfile.mkdtemp(prefix="wasmfuzz-hq-"))

    monitor_proc: subprocess.Popen[bytes] | None = None
    fuzzer_proc: subprocess.Popen[bytes] | None = None

    print(f"[hq-run] job={job_id} cores={cores} target={target} bucket={bucket}")
    print(f"[hq-run] exp_arg='{exp_arg}' env='{env_assigns}'")

    try:
        monitor_cmd = [
            monitor_bin,
            "monitor-cov",
            target,
            "--dir",
            str(corpus_dir),
            "--out-file",
            str(out_file),
            "--bucket",
            bucket,
            f"--interval={monitor_interval}",
            "--continuous",
        ]
        monitor_proc = subprocess.Popen(monitor_cmd, start_new_session=True)

        fuzz_cmd = [
            wasmfuzz,
            "fuzz",
            target,
            "--dir",
            str(corpus_dir),
            "--timeout",
            timeout,
            "--cores",
            str(cores),
        ]
        if exp_arg:
            fuzz_cmd.append(exp_arg)
        fuzzer_proc = subprocess.Popen(fuzz_cmd, start_new_session=True)

        first_rc: int | None = None
        deadline = time.monotonic() + timeout_seconds
        while first_rc is None:
            if _terminate_signal:
                print(f"[hq-run] received signal {_terminate_signal}; cleaning up")
                first_rc = 128 + _terminate_signal
                break
            fuzzer_rc = fuzzer_proc.poll()
            if fuzzer_rc is not None:
                first_rc = fuzzer_rc
                break
            monitor_rc = monitor_proc.poll()
            if monitor_rc is not None:
                first_rc = monitor_rc
                break
            if time.monotonic() >= deadline:
                print(f"[hq-run] timeout {timeout} reached; cleaning up")
                first_rc = 124
                break
            time.sleep(1)

        print(f"[hq-run] first child exited rc={first_rc}; cleaning up")
        return int(first_rc or 0)
    finally:
        terminate_process(monitor_proc, "monitor")
        terminate_process(fuzzer_proc, "fuzzer")

        if corpora_dir:
            dest = Path(corpora_dir) / f"{target_stem}-{bucket}"
            dest.mkdir(parents=True, exist_ok=True)
            try:
                for item in corpus_dir.iterdir():
                    dst = dest / item.name
                    if item.is_dir():
                        shutil.copytree(item, dst, dirs_exist_ok=True)
                    else:
                        shutil.copy2(item, dst)
            except FileNotFoundError:
                pass

        shutil.rmtree(corpus_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
