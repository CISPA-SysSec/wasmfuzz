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
import secrets
from pathlib import Path

_terminate_signal = 0
_children: list["Child"] = []


def count_cores_from_hq_cpus(hq_cpus: str | None) -> int:
    if not hq_cpus:
        return 1
    return max(1, sum(1 for cpu in hq_cpus.split(",") if cpu.strip()))


def parse_duration_seconds(value: str) -> float:
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([smh])", value.strip())
    if not match:
        raise ValueError(
            f"duration must match '<n>s', '<n>m', or '<n>h': got {value!r}"
        )
    return float(match.group(1)) * {"s": 1, "m": 60, "h": 3600}[match.group(2)]


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
    for child in _children:
        child.signal(signal.SIGINT)


class Child:
    """A subprocess in its own session, killable as a group."""

    def __init__(self, label: str, cmd: list[str], env: dict[str, str] = {}) -> None:
        env_ = os.environ.copy()
        env_.update(env)
        self.label = label
        self.proc = subprocess.Popen(cmd, start_new_session=True, env=env_)
        # start_new_session=True makes the child its own session leader,
        # so pgid == pid.
        self.pgid = self.proc.pid
        _children.append(self)

    def poll(self) -> int | None:
        return self.proc.poll()

    def signal(self, sig: int) -> None:
        try:
            os.killpg(self.pgid, sig)
        except (ProcessLookupError, PermissionError):
            pass

    def wait_for_exit(self, grace_seconds: float) -> None:
        if self.proc.poll() is not None:
            return
        try:
            self.proc.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            pass

    def terminate(self) -> None:
        if self.proc.poll() is not None:
            return
        self.signal(signal.SIGINT)
        try:
            self.proc.wait(timeout=0.2)
            return
        except subprocess.TimeoutExpired:
            pass
        self.signal(signal.SIGKILL)
        try:
            self.proc.wait(timeout=0.2)
        except subprocess.TimeoutExpired:
            print(
                f"[hq-run] warning: failed to kill {self.label} pid={self.proc.pid}",
                file=sys.stderr,
            )


def supervise(fuzzer: Child, monitor: Child, deadline: float) -> tuple[str, int]:
    """Block until something interesting happens. Returns (reason, rc)."""
    while True:
        if _terminate_signal:
            return ("signal", 128 + _terminate_signal)
        rc = fuzzer.poll()
        if rc is not None:
            return ("fuzzer_exited", rc)
        rc = monitor.poll()
        if rc is not None:
            return ("monitor_exited", rc)
        if time.monotonic() >= deadline:
            return ("timeout", 124)
        try:
            fuzzer.proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass


def save_corpus(corpus_dir: Path, corpora_dir: str, dest_name: str) -> None:
    if not corpora_dir:
        return
    dest = Path(corpora_dir) / dest_name
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
    timeout_seconds = parse_duration_seconds(timeout)
    monitor_interval = str(task.get("monitor_interval") or "60s")
    monitor_grace_seconds = parse_duration_seconds(monitor_interval) * 1.5
    corpora_dir = str(task.get("corpora_dir") or "")
    exp_arg = str(task.get("experiment_arg") or "")
    env_assigns = str(task.get("env_assignments") or "")

    runs_dir = Path(runs_dir_raw)
    apply_env_assignments(env_assigns)

    cores = count_cores_from_hq_cpus(os.environ.get("HQ_CPUS"))

    runs_dir.mkdir(parents=True, exist_ok=True)
    target_stem = Path(target).stem
    job_id = (
        f"{target_stem}-{bucket}-{int(time.time())}-{secrets.token_hex(4)}-"
        f"{os.environ.get('HQ_JOB_ID', 'x')}.{os.environ.get('HQ_TASK_ID', '0')}"
    )
    out_file = runs_dir / f"{job_id}.jsonl"
    if os.environ.get("HQ_TASK_DIR"):
        task_dir = Path(os.environ["HQ_TASK_DIR"])
    else:
        task_dir = Path(tempfile.mkdtemp(prefix="wasmfuzz-hq-"))
    corpus_dir = task_dir / "corpus"
    corpus_dir.mkdir()

    monitor: Child | None = None
    fuzzer: Child | None = None

    print(f"[hq-run] job={job_id} cores={cores} target={target} bucket={bucket}")
    print(f"[hq-run] exp_arg='{exp_arg}' env='{env_assigns}'")

    try:
        monitor = Child(
            "monitor",
            [
                monitor_bin, "monitor-cov", target,
                "--dir", str(corpus_dir),
                "--out-file", str(out_file),
                "--bucket", bucket,
                f"--interval={monitor_interval}",
                "--continuous",
                f"--stats-in={task_dir / 'metrics.json'}"
            ],
        )

        fuzz_cmd = [
            wasmfuzz, "fuzz", target,
            "--dir", str(corpus_dir),
            "--timeout", timeout,
            "--cores", str(cores),
        ]
        if exp_arg:
            fuzz_cmd.append(exp_arg)
        fuzzer = Child("fuzzer", fuzz_cmd, env={"WASMFUZZ_METRICS_JSON": task_dir / 'metrics.json'})

        reason, rc = supervise(fuzzer, monitor, time.monotonic() + timeout_seconds)
        print(f"[hq-run] {reason} rc={rc}; cleaning up")

        if reason in ("fuzzer_exited", "timeout"):
            fuzzer.terminate()
            print(
                f"[hq-run] waiting up to {monitor_grace_seconds:.1f}s "
                f"for monitor to catch up"
            )
            monitor.wait_for_exit(monitor_grace_seconds)

        return rc
    finally:
        if monitor is not None:
            monitor.terminate()
        if fuzzer is not None:
            fuzzer.terminate()

        save_corpus(corpus_dir, corpora_dir, f"{target_stem}-{bucket}")
        shutil.rmtree(corpus_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
