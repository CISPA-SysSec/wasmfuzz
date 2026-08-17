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

CGROUP_MOUNT = Path("/sys/fs/cgroup")


def read_self_cgroup_v2() -> Path:
    with open("/proc/self/cgroup") as f:
        for line in f:
            hid, _controllers, path = line.rstrip("\n").split(":", 2)
            if hid == "0":
                return CGROUP_MOUNT / path.lstrip("/")
    raise RuntimeError("no cgroup v2 unified hierarchy in /proc/self/cgroup")


def try_rmdir(path: Path, attempts: int = 20) -> None:
    """Best-effort removal of an (empty) cgroup directory, retrying briefly
    after SIGKILL to let the kernel drain cgroup.procs."""
    for i in range(attempts):
        try:
            path.rmdir()
            return
        except FileNotFoundError:
            return
        except OSError:
            if i + 1 == attempts:
                return
            time.sleep(0.05)


class Cgroup:
    """Memory-limited cgroup subtree for the fuzzer and monitor.

    Instead of enabling the memory controller in the HQ worker's own cgroup
    (which requires evacuating the worker process and reversing that on
    cleanup), we walk *up* the hierarchy to find the nearest ancestor that
    already has +memory in its subtree_control and allows us to mkdir there.
    We create a fresh wasmfuzz-task.<token> cgroup at that level with no
    other processes in it, so cleanup is always a plain rmdir — no state is
    left behind for subsequent tasks.
    """

    def __init__(self) -> None:
        self.task_cg: Path | None = None
        self.memory_enabled = False
        try:
            self._setup()
        except (OSError, RuntimeError, ValueError) as e:
            print(
                f"[hq-run] warning: cgroup setup failed ({e}); "
                "running without memory limits",
                file=sys.stderr,
            )

    def _setup(self) -> None:
        self_cg = read_self_cgroup_v2()
        parent = _find_memory_parent(self_cg)
        if parent is None:
            print(
                "[hq-run] warning: no writable ancestor cgroup with memory "
                "controller found; running without memory limits",
                file=sys.stderr,
            )
            return
        task_cg = parent / f"wasmfuzz-task.{secrets.token_hex(4)}"
        task_cg.mkdir()
        self.task_cg = task_cg
        (task_cg / "cgroup.subtree_control").write_text("+memory")
        self.memory_enabled = True

    def leaf(self, label: str, memory_limit_gb: int | None) -> Path | None:
        if self.task_cg is None:
            return None
        leaf = self.task_cg / f"{label}.{secrets.token_hex(4)}"
        try:
            leaf.mkdir()
            if self.memory_enabled and memory_limit_gb is not None:
                (leaf / "memory.max").write_text(str(memory_limit_gb * 1024**3))
                (leaf / "memory.swap.max").write_text("0")
            return leaf
        except OSError as e:
            print(
                f"[hq-run] warning: could not set up cgroup for {label} ({e})",
                file=sys.stderr,
            )
            return None

    def cleanup(self) -> None:
        if self.task_cg is None:
            return
        try:
            children = sorted(self.task_cg.iterdir(), reverse=True)
        except OSError:
            children = []
        for child in children:
            if child.is_dir():
                try_rmdir(child)
        try_rmdir(self.task_cg)


def _find_memory_parent(start: Path) -> Path | None:
    """Walk up the cgroup tree to find the nearest ancestor that has +memory
    in its subtree_control and allows mkdir (i.e. is within our delegation)."""
    cg = start
    while cg != cg.parent:
        try:
            if "memory" in (cg / "cgroup.subtree_control").read_text().split():
                probe = cg / f"wasmfuzz-probe.{secrets.token_hex(2)}"
                probe.mkdir()
                probe.rmdir()
                return cg
        except OSError:
            pass
        cg = cg.parent
    return None


def _make_preexec(cgroup: Path | None):
    """Return a preexec_fn that marks the process as OOM-preferred and
    optionally moves it into a cgroup leaf before exec."""
    def preexec() -> None:
        try:
            Path("/proc/self/oom_score_adj").write_text("1000")
        except OSError:
            pass
        if cgroup is not None:
            try:
                (cgroup / "cgroup.procs").write_text(str(os.getpid()))
            except OSError:
                pass
    return preexec


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

    def __init__(
        self,
        label: str,
        cmd: list[str],
        env: dict[str, str] = {},
        cgroup: Path | None = None,
    ) -> None:
        env_ = os.environ.copy()
        env_.update(env)
        self.label = label
        self.proc = subprocess.Popen(
            cmd, start_new_session=True, env=env_,
            preexec_fn=_make_preexec(cgroup),
        )
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
    cgroup = Cgroup()

    print(f"[hq-run] job={job_id} cores={cores} target={target} bucket={bucket}")
    print(f"[hq-run] exp_arg='{exp_arg}' env='{env_assigns}'")

    # Note: monitor and fuzzer have generous memory limits. Average use has to
    # be at <3GB/run to properly work on high-core-count cluster machines.
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
            cgroup=cgroup.leaf("monitor", memory_limit_gb=5),
        )

        fuzz_cmd = [
            wasmfuzz, "fuzz", target,
            "--dir", str(corpus_dir),
            "--timeout", timeout,
            "--cores", str(cores),
        ]
        if exp_arg:
            fuzz_cmd.append(exp_arg)
        fuzzer = Child(
            "fuzzer",
            fuzz_cmd,
            env={"WASMFUZZ_METRICS_JSON": str(task_dir / 'metrics.json')},
            cgroup=cgroup.leaf("fuzzer", memory_limit_gb=10),
        )

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

        cgroup.cleanup()
        save_corpus(corpus_dir, corpora_dir, f"{target_stem}-{bucket}")
        shutil.rmtree(corpus_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
