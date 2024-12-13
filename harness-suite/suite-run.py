#!/usr/bin/env python3

import argparse
import asyncio
import contextlib
import os
import sys
import math
from pathlib import Path

import pandas as pd


parser = argparse.ArgumentParser()
parser.add_argument('--no-parallel', action='store_true')
parser.add_argument('--quiet', action='store_true')
parser.add_argument('--target', default=None)
parser.add_argument('--wasmfuzz', default="wasmfuzz")
DEFAULT_TIMEOUTS = ["8m", "22m", "1h30m", "2h"]
parser.add_argument('--timeout', default=DEFAULT_TIMEOUTS[:], action='append')
parser.add_argument('--cores-per-harness', default=8)
parser.add_argument('--harness-dir', default="./out")
parser.add_argument('--corpus-dir', default="./corpus")

args = parser.parse_args()
assert Path(args.harness_dir).exists()
# cut of default arguments if user specified their own timeout schedule
args.timeout = DEFAULT_TIMEOUTS if args.timeout == DEFAULT_TIMEOUTS else args.timeout[len(DEFAULT_TIMEOUTS):]
timeouts = [int(pd.Timedelta(x).total_seconds()) for x in args.timeout]

available_parallelism = math.ceil((os.cpu_count() or 1) * 0.98)
cores_available = available_parallelism
cores_cond = asyncio.Condition()
@contextlib.asynccontextmanager
async def cores(n):
    global cores_available
    n = min(n, available_parallelism)
    async with cores_cond:
        await cores_cond.wait_for(lambda: cores_available >= n)
        cores_available -= n
    try:
        yield
    finally:
        async with cores_cond:
            cores_available += n
            cores_cond.notify_all()

async def run(cmd, pipe_stdout=None, stdout_prefix=None, mix_stderr=False):
    print(cmd)

    async def _stream_tee(source, f1, f2):
        while line := await source.readline():
            line = line.decode("utf-8")
            if not args.quiet:
                print(f"[{stdout_prefix}]", line, file=f1, end='')
            print(line, file=f2, end='')
    if not pipe_stdout:
        proc = await asyncio.create_subprocess_exec(*cmd)
        await proc.wait()
    elif mix_stderr:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        with open(pipe_stdout, "w") as f:
            await asyncio.wait([
                asyncio.create_task(_stream_tee(proc.stdout, sys.stdout, f)),
                asyncio.create_task(_stream_tee(proc.stderr, sys.stderr, f))
            ])
        await proc.wait()
    else:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE)
        with open(pipe_stdout, "w") as f:
            await _stream_tee(proc.stdout, sys.stdout, f)
        await proc.wait()

async def run_target(target):
    corpus = Path(args.corpus_dir) / target.stem
    corpus.mkdir(exist_ok=True, parents=True)
    Path("/tmp/wasmfuzz-logs").mkdir(exist_ok=True)

    seed_dir = None
    assert timeouts

    total_timeout = 0
    for timeout in timeouts:
        total_timeout += timeout
        t = pd.Timedelta(total_timeout, unit="s").components
        snapshot = f"snapshot-{t.days}d-{t.hours}h-{t.minutes}m"
        snapshot_dir = corpus / snapshot
        snapshot_dir.mkdir(exist_ok=True)
        async with cores(int(args.cores_per_harness)):
            await run([
                    args.wasmfuzz,
                    "fuzz", str(target),
                    f"--timeout={timeout}s",
                    f"--cores={args.cores_per_harness}",
                    f"--out-dir={snapshot_dir}",
                ] + ([
                    f"--seed-dir={seed_dir}",
                ] if seed_dir is not None else []),
                pipe_stdout=f"/tmp/wasmfuzz-logs/{target.stem}-{snapshot}.log",
                stdout_prefix=target.stem,
                mix_stderr=True
            )

        corpus_info_csv = corpus / f"{snapshot}.csv"
        async with cores(int(args.cores_per_harness)):
            await run([
                    args.wasmfuzz,
                    "corpus-info", str(target),
                    f"--dir={snapshot_dir}",
                    f"--csv-out={corpus_info_csv}",
                ],
                pipe_stdout=f"/tmp/wasmfuzz-logs/{target.stem}-{snapshot}.log",
                stdout_prefix=target.stem,
                mix_stderr=True
            )
        seed_dir = snapshot_dir

async def main():
    jobs = []
    for target in Path(args.harness_dir).glob("*.wasm"):
        if args.target and args.target not in target.stem: continue
        if args.no_parallel:
            await run_target(target)
        else:
            jobs.append(asyncio.create_task(run_target(target)))
    await asyncio.wait(jobs)

asyncio.run(main())
