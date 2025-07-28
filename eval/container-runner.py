#!/usr/bin/env python3

import argparse
import asyncio
import contextlib
import csv
import json
import math
import os
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
import time
import random

from collections import defaultdict
from socket import gethostname
from pathlib import Path


available_parallelism = math.ceil((os.cpu_count() or 1) * 0.98)
if available_parallelism > 1: available_parallelism -= 1
cores_available = list(range(available_parallelism))
cores_cond = None  # created inside of loop
@contextlib.asynccontextmanager
async def cores(n):
    global cores_available, cores_cond
    if not cores_cond:
        cores_cond = asyncio.Condition()
    if n > available_parallelism:
        print(f"[WARN] single job requires {n} cores but we only have {available_parallelism}! queueing anyways...")
        n = available_parallelism
    async with cores_cond:
        await cores_cond.wait_for(lambda: len(cores_available) >= n)
        random.shuffle(cores_available)
        core_ids = cores_available[:n]
        cores_available = cores_available[n:]
    try:
        yield core_ids
    finally:
        async with cores_cond:
            cores_available += core_ids
            cores_cond.notify_all()

def time_as_seconds(v: str):
    units = [
        ("d", 24*60*60),
        ("h", 60*60),
        ("m", 60),
        ("s", 1),
        ("", 1)
    ]
    try:
        for (suffix, scale) in units:
            if v.endswith(suffix):
                return int(v.removesuffix(suffix)) * scale
    except ValueError:
            raise argparse.ArgumentTypeError(f"can't parse {v!r} to seconds")


PODMAN = os.environ.get("PODMAN", "podman" if shutil.which("podman") else "docker")
if PODMAN == "podman":
    with open("/proc/sys/kernel/keys/maxkeys") as f:
        maxkeys = int(f.read().strip())
    if maxkeys < os.cpu_count():
        print(f"[WARN] spawning {os.cpu_count()} containers with podman would run into a kernel limit:")
        print(f"       kernel.keys.maxkeys={maxkeys}")
        print(f"Increase the limit accordingly to continue:")
        print(f"sudo sysctl -w kernel.keys.maxkeys={os.cpu_count()*2}")
        os.exit(1)


parser = argparse.ArgumentParser()
parser.add_argument('--no-parallel', action='store_true', help="Only run one job at a time")
parser.add_argument('--repeat', default=1, type=int, help="Repeat experiment N times")
parser.add_argument('--cores-per-fuzzer', default=1, type=int, help="Run multi-core fuzzing experiments")
parser.add_argument('--pin-cores', action='store_true', help="Pin each container to specific cores")
parser.add_argument('--core-limit', default=None, type=int, help="Limit the total cores used in this experiment")
parser.add_argument('--timeout', default=10*60, type=time_as_seconds, help="Campaign length. Default: 10m")
parser.add_argument('--harness-suite', default="./harness-suite/out", help="Path to WASM harnesses")
parser.add_argument('--runs-dir', default="/tmp/eval-runs/", help="Output directory for job eval results (jsonl logs)")
parser.add_argument('--tags-csv', default="./harness-suite/tags.csv")

# TODO: remove this? re-use the container binary?
parser.add_argument('--wasmfuzz', default="wasmfuzz", help="Path to wasmfuzz binary for coverage collection")

parser.add_argument('--native-cov', action='store_true')

parser.add_argument('--target', action='append', help="Only run harnesses that contain this string")
parser.add_argument('--tag', action='append', help="Only run targets with this tag")
parser.add_argument('--skip-tag', action='append', help="Don't run targets with this tag")
parser.add_argument('--fuzzer', action='append', help="Run with this fuzzer")
parser.add_argument('--keep-corpora', default=None, help="Copy resulting corpora to this path")

args = parser.parse_args()
fuzzers: list[str] = args.fuzzer or [
    "wasmfuzz",
    "wasmfuzz-rel",
    "wafl",
    "fuzzm",
    "libfuzzer-wasm2c",
    "libfuzzer-w2c2",
    "aflpp-wasm2c",
    "aflpp-w2c2",
    "libafl-libfuzzer-wasm2c",
]

class LibfuzzerMonitor:
    def __init__(self, bin_path: Path, bucket:str, target_name: str, interval_secs=30, only_new=False):
        self.bin_path = bin_path
        self.bucket = bucket
        self.only_new = only_new
        self.interval_secs = interval_secs
        self.meta = dict(
            target=target_name,
            bucket=bucket,
            start_timestamp=int(time.time()),
            interval_secs=interval_secs,
            collector="libfuzzer",
        )

    async def collect(self, stable_corp_dir):
        fuzzer_cmd = [PODMAN, "run", "--rm", "-it"]
        fuzzer_cmd += ["--mount", f"type=bind,source={self.bin_path.absolute()},destination=/{self.bin_path.name},ro=true,relabel=shared"]
        fuzzer_cmd += ["--mount", f"type=bind,source={stable_corp_dir.absolute()},destination=/corpus,ro=true,relabel=shared"]
        fuzzer_cmd += ["--network", "none"]
        fuzzer_cmd += ["docker.io/ubuntu:24.04"]
        fuzzer_cmd += [
            f"/{self.bin_path.name}",
            "-runs=0",
            "/corpus"
        ]
        if PODMAN == "docker":
            # HACK: if we're using docker as a backend: don't add relable=shared to mount arguments
            fuzzer_cmd = [x.replace(",relabel=shared", "").replace(",rw=true", "") for x in fuzzer_cmd]
        p = await asyncio.create_subprocess_exec(
            *fuzzer_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_data, stderr_data = await p.communicate()
        if p.returncode != 0:
            print("libfuzzer coverage monitor crashed!")
            print("=== STDOUT ===")
            print(stdout_data.decode())
            print("=== STDERR ===")
            print(stderr_data.decode())
            return dict(crashing=True)

        # INFO: Loaded 1 modules   (2279 inline 8-bit counters): 2279 [0x567b6664, 0x567b6f4b),
        # #56	DONE   cov: 92 ft: 113 corp: 37/2317b lim: 221 exec/s: 0 rss: 25Mb
        m = re.search(r'#[0-9]+[ \t]+DONE[ \t]+cov: ([0-9]+)[ \t]+ft: ([0-9]+)[ \t]+corp: ([0-9]+)/', stdout_data.decode())
        if m is not None:
            cov = int(m.group(1))
            ft = int(m.group(2))
            corp = int(m.group(3))
            # print(cov, ft, corp)
            return dict(cov_libfuzzer=cov, cov_libfuzzer_ft=ft, finds=corp, crashing=False)
        else:
            print("libfuzzer output didn't match!")
            print("=== STDOUT ===")
            print(stdout_data.decode())
            print("=== STDERR ===")
            print(stderr_data.decode())
            return dict(crashing=True)

    async def run(self, corpus_path: Path, out_path: Path):
        seen = set()
        i = 0
        start = time.time()
        try:
            with tempfile.TemporaryDirectory("wasmfuzz-libfuzzer-cov") as stable_corp_dir:
                stable_corp_dir = Path(stable_corp_dir)
                with open(out_path, "w") as out_f:
                    while True:
                        i += 1
                        target = start + self.interval_secs*i
                        delay = target - time.time()
                        if delay < 0:
                            print(f"[WARN] skipping libfuzzer cov run {delay = }")
                            continue
                        await asyncio.sleep(delay if delay > 0 else 0)

                        # copy all files from corpus to stable_corp_dir
                        new = False
                        for el in corpus_path.iterdir():
                            if el.stem in seen: continue
                            try:
                                shutil.copyfile(el, stable_corp_dir / f"{i:04}_{el.stem}")
                            except FileNotFoundError:
                                # this can happen when fuzzers run cmin concurrently
                                continue
                            seen.add(el.stem)
                            new = True

                        record = dict(
                            i=i,
                            seconds=self.interval_secs*i,
                            seconds_rt=time.time() - start,
                            entries=len(seen),
                        )
                        # run libfuzzer for total coverage
                        if new or not self.only_new:
                            res = await self.collect(stable_corp_dir)
                            record = {**record, **res}
                        if i == 1:
                            record = {**record, **self.meta}
                        out_f.write(json.dumps(record) + "\n")
                        out_f.flush()

        except asyncio.CancelledError:
            pass

class FuzzJob:
    def __init__(self, target_wasm: Path, bucket, corpus_dir: Path, runs_dir: Path, job_name=None, timeout=None, idle_timeout=None, core_ids=None):
        self.runs_dir = runs_dir
        self.runs_dir.mkdir(exist_ok=True)
        self.run_corpus_dir = corpus_dir
        self.target_wasm = target_wasm
        self.job_name = job_name or f"{self.target_wasm.stem}-{bucket}"
        self.timeout = timeout
        self.bucket = bucket
        self.idle_timeout = idle_timeout
        self.job_uuid = secrets.token_hex(6)
        self.job_id = f"{self.job_name}-{int(time.time())}-{self.job_uuid}"
        self.run_path = self.runs_dir / f"{self.job_id}.jsonl"
        self.core_ids = core_ids
    async def watchdog_task(self):
        start = time.time()
        while True:
            await asyncio.sleep(1)
            if self.timeout and time.time() - start > self.timeout:
                print(f"[{self.job_name}] watchdog timeout hit")
                return
            if self.idle_timeout:
                raise RuntimeError("not implemented")

    async def spawn(self, cmd, **kwargs):
        cmd = [str(x) for x in cmd]
        if PODMAN == "docker":
            # HACK: if we're using docker as a backend: don't add relable=shared to mount arguments
            cmd = [x.replace(",relabel=shared", "").replace(",rw=true", "") for x in cmd]
        print(' '.join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            # stdout=asyncio.subprocess.DEVNULL,
            # stderr=asyncio.subprocess.DEVNULL,
            start_new_session=True,
            **kwargs
        )
        return_code = None
        try:
            return_code = await proc.wait()
        except asyncio.CancelledError as e:
            print("got cancellederror, killing pg", cmd)
            pgrp = os.getpgid(proc.pid)
            try:
                os.killpg(pgrp, signal.SIGINT)
                await asyncio.sleep(5)
                if PODMAN in cmd and self.job_uuid in cmd:
                    subprocess.run([PODMAN, "kill", self.job_uuid])
                await asyncio.sleep(5)
                os.killpg(pgrp, signal.SIGKILL)
                await asyncio.sleep(1)
            except ProcessLookupError:
                pass
            await proc.wait()
            raise e
        if return_code is not None:
            print(f"[{self.job_name}] process exited with {return_code}")
        else:
            print(f"[{self.job_name}] process exited")

    async def run(self, fuzzer, env=None):
        await asyncio.sleep(1)
        interval_secs = 60*3 #120 if args.native_cov else 60

        self.monitor_native = None
        if args.native_cov: # TRACK LIBFUZZER COV
            native_bin = self.target_wasm.with_suffix(".exe")
            if not native_bin.exists():
                print(f"[-] missing native_bin for {self.target_wasm.stem}: {native_bin}")
                return
            out_path = self.runs_dir / f"{self.job_id}-libfuzzer.jsonl"
            task = LibfuzzerMonitor(native_bin, self.bucket, target_name=self.target_wasm.name, interval_secs=interval_secs)
            self.monitor_native = asyncio.create_task(task.run(self.run_corpus_dir, out_path))

        self.monitor = asyncio.create_task(self.spawn([
            args.wasmfuzz,
            "monitor-cov",
            self.target_wasm,
            "--dir", self.run_corpus_dir,
            "--out-file", self.run_path,
            "--bucket", self.bucket,
            f"--interval={interval_secs}s", "--continuous"
        ]))

        fuzzer_cmd = [PODMAN, "run", "--rm", "-it"]
        for k, v in env.items():
            fuzzer_cmd += ["--env", f"{k}={v}"]
        fuzzer_cmd += ["--mount", f"type=bind,source={self.target_wasm.absolute()},destination=/{self.target_wasm.stem},ro=true,relabel=shared"]
        fuzzer_cmd += ["--mount", f"type=bind,source={self.run_corpus_dir.absolute()},destination=/corpus,rw=true,relabel=shared"]
        fuzzer_cmd += ["--security-opt=seccomp=unconfined"] # reduce performance hit of running fuzzers in a container
        # fuzzer_cmd += ["--privileged"] # for /dev/restore-dirty
        #    nix2 has ~10gb per 8 cores ( 64GB,  48 cores)
        # aarch64 has ~16gb per 8 cores ( 16GB,   8 cores)
        #    tuna has ~32gb per 8 cores ( 32GB,   8 cores)
        #  alfred has 128gb per 8 cores (  2TB, 128 cores)
        # srv-23- has ~32gb per 8 cores (768GB, 192 cores)
        fuzzer_cmd += ["--memory", "16g"]
        fuzzer_cmd += ["--network", "none"]
        fuzzer_cmd += ["--log-driver", "none"] # afl++ people say that docker's log infra causes performance issues?
        if self.core_ids:
            fuzzer_cmd += ["--cpuset-cpus", ",".join(map(str, self.core_ids))]
        fuzzer_cmd += ["--name", self.job_uuid]
        if fuzzer.endswith("-native"):
            assert fuzzer in ["libfuzzer-native", "libafl-libfuzzer-native"]
            # image = "docker.io/i386/ubuntu:focal" if fuzzer == "libfuzzer-native" else "docker.io/ubuntu:24.04"
            image = "docker.io/ubuntu:24.04"
            source = self.target_wasm.with_suffix(".exe")
            fuzzer_cmd += ["--mount", f"type=bind,source={source.absolute()},destination=/{self.target_wasm.stem}-{fuzzer},ro=true,relabel=shared"]
            fuzzer_cmd += [image]
            num_cores = int(env["FUZZER_CORES"])
            if num_cores > 1:
                fuzzer_cmd += [f"/{self.target_wasm.stem}-{fuzzer}", f"-fork={num_cores}", "/corpus"]
            else:
                fuzzer_cmd += [f"/{self.target_wasm.stem}-{fuzzer}", "/corpus"]
        else:
            fuzzer_cmd += [f"wasm-fuzzers-{fuzzer}"]
            fuzzer_cmd += [f"/{self.target_wasm.stem}"]
        self.fuzzer = asyncio.create_task(self.spawn(fuzzer_cmd))
        self.watchdog = asyncio.create_task(self.watchdog_task())
        print(f"[{self.job_name}] spawned tasks")
        _done, _pending = await asyncio.wait(
            [self.monitor, self.fuzzer, self.watchdog],
            return_when=asyncio.FIRST_COMPLETED
        )
        print(f"[{self.job_name}] got one exit")

        await asyncio.sleep(1)
        self.fuzzer.cancel()
        self.watchdog.cancel()
        # we might've found a crasher. let's make sure monitor-cov picks it up.
        await asyncio.sleep(interval_secs*1.1)
        self.monitor.cancel()
        if self.monitor_native:
            self.monitor_native.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.monitor_native

        for task in (self.monitor, self.fuzzer, self.watchdog):
            with contextlib.suppress(asyncio.CancelledError):
                await task
        print(f"[{self.job_name}] cancelled all")



async def run_target(target, fuzzer, config=None, num_cores=1):
    async with cores(num_cores) as core_ids:
        config_str = None
        config_env = {"FUZZER_CONFIG": None, "FUZZER_CORES": str(num_cores)}
        if config is not None:
            if isinstance(config, str) and fuzzer == "wasmfuzz":
                config = dict(name=config, config=config, args=f"--experiment={config}")
            if isinstance(config, str):
                config = dict(name=config, config=config)
            config_str = config["name"]
            config_env.update({f"FUZZER_{k.upper()}": v for k, v in config.items()})
        bucket = f"{fuzzer}-{config_str}" if config_str is not None else fuzzer
        bucket += f"-{gethostname()}"
        slug = f"{target.stem}-{bucket}"

        try:
            with tempfile.TemporaryDirectory(prefix="wasmfuzz-eval", suffix=slug) as corpus_dir:
                wasm_job = FuzzJob(
                    target, bucket=bucket, timeout=args.timeout,
                    corpus_dir=Path(corpus_dir), runs_dir=Path(args.runs_dir),
                    core_ids=core_ids if args.pin_cores else None
                )
                await wasm_job.run(fuzzer=fuzzer, env=config_env)
                if args.keep_corpora:
                    t_dir = Path(args.keep_corpora) / slug
                    t_dir.mkdir(parents=True, exist_ok=True)
                    shutil.copytree(corpus_dir, t_dir, dirs_exist_ok=True)
        except Exception as e:
            print(f"exception in run_target for {target=} {e=}")
            raise e



async def main():
    all_tags = defaultdict(set)
    tags_path = Path(args.tags_csv)
    if tags_path.exists():
        with open(tags_path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                harness = Path(row["harness"]).stem
                for k, v in row.items():
                    if v in {"1", "true"}:
                        all_tags[harness].add(k)
    else:
        print(f"[WARN] couldn't find harness tags ({args.tags_csv!r})")
    jobs = []
    for _ in range(args.repeat):
        for target in Path(args.harness_suite).glob("*.wasm"):
            # if we specify a target filter: make sure our harness contains this string
            if args.target and not any(t in target.stem for t in args.target):
                continue

            tags = all_tags[target.stem]
            # if we specify tags: make sure our target contains all of them
            if args.tag and not all(t in tags for t in args.tag):
                continue

            # if we specify tags to skip
            if any(t in tags for t in args.skip_tag or []):
                continue

            print(target.stem)
            for fuzzer in fuzzers:
                config = None
                if "|" in fuzzer:
                    fuzzer, config = fuzzer.split("|", 1)
                task = run_target(target, fuzzer, config=config, num_cores=args.cores_per_fuzzer)
                if args.no_parallel:
                    await task
                else:
                    jobs.append(asyncio.create_task(task))
    if jobs:
        await asyncio.gather(*jobs)

if __name__ == "__main__":
    assert Path(args.harness_suite).is_dir(), f"--bins={args.harness_suite!r} not found"
    if args.core_limit:
        assert args.core_limit <= os.cpu_count()
        cores_available = list(range(args.core_limit))

    asyncio.run(main(), debug=True)
