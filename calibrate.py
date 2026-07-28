#!/usr/bin/env python3
"""
calibrate.py - runs 5 workloads on this machine and derives classifier
thresholds from actual measured distributions instead of guessing.

CPU   - sysbench prime computation, max ipc no memory pressure
MEM   - pointer chasing over a buffer >= 2x llc size, cant be prefetched
        so basically guaranteed cache misses. falls back to stress-ng
IO    - dd from /dev/urandom + fsync loop, forces real block io
IDLE  - just sleeps, gives the zero baseline
CONTENTION - forks cores+2 busy loops so cores are oversubscribed, needed
        because none of the other 4 ever create real runqueue contention,
        can skip with --skip-contention

derives 7 thresholds total (ipc_cpu, ipc_mem, llc_mem, ctx_io, ipc_idle,
io_wait_bound, rq_wait_starved) using midpoints between the workload
distributions plus an adaptive guard band (10-30%, wider when the
distributions are noisy relative to the gap between them).

usage: sudo python3 calibrate.py [--duration 20] [--skip-idle] [--skip-contention]
"""


import os
import sys
import time
import signal
import argparse
import subprocess
import statistics
import csv
import pwd
import struct
import tempfile
import textwrap
from pathlib import Path

import hw_profile

SCRIPT_DIR  = Path(__file__).parent.resolve()
MONITOR_BIN = SCRIPT_DIR / "schedmon"
BPF_OBJ     = SCRIPT_DIR / "bpf" / "ctx_switch.bpf.o"

SUDO_USER = os.environ.get("SUDO_USER")
if SUDO_USER:
    REAL_HOME = Path(pwd.getpwnam(SUDO_USER).pw_dir)
else:
    REAL_HOME = Path.home()

CONF_PATH = REAL_HOME / ".config" / "schedmon" / "thresholds.conf"

def get_hardware():
    """cores, llc bytes, ram gb"""
    cores = os.cpu_count() or 2

    llc_bytes = 0
    try:
        cache_root = Path("/sys/devices/system/cpu/cpu0/cache")
        for index_dir in sorted(cache_root.iterdir()):
            try:
                ctype = (index_dir / "type").read_text().strip()
                if ctype in ("Unified", "Data"):
                    level = int((index_dir / "level").read_text().strip())
                    size_str = (index_dir / "size").read_text().strip()
                    mult = 1024 if size_str.endswith("K") else (
                           1024*1024 if size_str.endswith("M") else 1)
                    size_b = int(size_str.rstrip("KMG")) * mult
                    if level >= 3 or (level == 2 and size_b > llc_bytes):
                        llc_bytes = size_b
            except Exception:
                continue
    except Exception:
        pass
    if llc_bytes == 0:
        llc_bytes = 4 * 1024 * 1024  # just guess 4mb

    ram_gb = 8
    try:
        for line in open("/proc/meminfo"):
            if line.startswith("MemTotal:"):
                ram_gb = max(1, round(int(line.split()[1]) / (1024**2)))
                break
    except Exception:
        pass

    return cores, llc_bytes, ram_gb


def get_cpu_model():
    model = hw_profile.read_cpu_model()
    return model if model else "unknown"


def wrap_cmd(cmd_list):
    """Drop privileges if running under sudo so workloads run as the real user."""
    if SUDO_USER:
        return ["sudo", "-u", SUDO_USER] + cmd_list
    return cmd_list


def launch_cpu_workload():
    """compiled busy loop run as root so perf_event_open works fine
    regardless of perf_event_paranoid. falls back to sysbench if no gcc"""
    cpu_src = textwrap.dedent("""\
        #include <stdint.h>
        int main(void) {
            /* 4 independent lcg chains to keep the alu busy, no memory access */
            volatile uint64_t a = 1, b = 2, c = 3, d = 4;
            while (1) {
                a = a * 6364136223846793005ULL + 1442695040888963407ULL;
                b = b * 6364136223846793005ULL + 2305843009213693951ULL;
                c = c * 6364136223846793005ULL + 4611686018427387903ULL;
                d = d * 6364136223846793005ULL + 9223372036854775807ULL;
            }
        }
    """)
    src_path = Path(tempfile.mktemp(suffix=".c", prefix="calib_cpu_"))
    bin_path = Path(tempfile.mktemp(prefix="calib_cpu_"))
    src_path.write_text(cpu_src)
    try:
        subprocess.run(["gcc", "-O2", "-o", str(bin_path), str(src_path)],
                       check=True, capture_output=True)
        src_path.unlink(missing_ok=True)
        p = subprocess.Popen([str(bin_path)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return p, "cpu-spin (root)"
    except Exception:
        src_path.unlink(missing_ok=True)

    # sysbench runs as SUDO_USER, less accurate since cross-uid perf
    # monitoring can get blocked by the kernel
    try:
        p = subprocess.Popen(
            wrap_cmd(["sysbench", "cpu", "--cpu-max-prime=20000",
                      "--time=300", "--threads=1", "run"]),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.3)
        if p.poll() is not None:
            raise FileNotFoundError("sysbench exited immediately")
        return p, "sysbench-cpu (fallback)"
    except FileNotFoundError:
        pass

    raise RuntimeError("Cannot launch CPU workload: gcc and sysbench both unavailable")

def launch_mem_workload(llc_bytes):
    """pointer chasing over a buffer way bigger than llc, guaranteed
    miss on every deref since the prefetcher cant predict a random walk"""
    buf_mb = max(64, (llc_bytes * 8) // (1024 * 1024))

    src = textwrap.dedent(f"""\
        #include <stdlib.h>
        #include <stdint.h>
        #include <string.h>
        #include <stdio.h>

        /* random permutation of pointers, one per cache line, walk it forever */
        int main(void) {{
            size_t buf_bytes = {buf_mb}ULL * 1024 * 1024;
            size_t n = buf_bytes / 64;
            uintptr_t *buf = malloc(buf_bytes);
            if (!buf) {{ perror("malloc"); return 1; }}

            /* fisher-yates shuffle to build the random cycle */
            for (size_t i = 0; i < n; i++) buf[i] = (uintptr_t)&buf[i];
            for (size_t i = n - 1; i > 0; i--) {{
                size_t j = (size_t)rand() % (i + 1);
                uintptr_t tmp = buf[i]; buf[i] = buf[j]; buf[j] = tmp;
            }}

            volatile uintptr_t *p = &buf[0];
            while (1) p = (volatile uintptr_t *)*p;

            free(buf);
            return 0;
        }}
    """)
    src_path = Path(tempfile.mktemp(suffix=".c", prefix="calib_mem_"))
    bin_path = Path(tempfile.mktemp(prefix="calib_mem_"))
    src_path.write_text(src)
    try:
        subprocess.run(["gcc", "-O2", "-o", str(bin_path), str(src_path)],
                       check=True, capture_output=True)
        src_path.unlink(missing_ok=True)
        p = subprocess.Popen([str(bin_path)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return p, f"pointer-chase ({buf_mb}MB > LLC)"
    except Exception as e:
        src_path.unlink(missing_ok=True)

    try:
        p = subprocess.Popen(
            wrap_cmd(["stress-ng", "--cache", "1",
                      f"--cache-size={buf_mb}m", "--timeout", "300s"]),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.3)
        if p.poll() is not None:
            raise FileNotFoundError()
        return p, f"stress-ng --cache {buf_mb}m"
    except FileNotFoundError:
        pass

    raise RuntimeError("Cannot launch MEM workload: gcc and stress-ng both unavailable")


def launch_io_workload():
    """writes+fdatasyncs in a loop to force real block io"""
    tmp = Path(tempfile.mktemp(prefix="calib_io_"))

    src = textwrap.dedent(f"""\
        #include <stdio.h>
        #include <stdlib.h>
        #include <fcntl.h>
        #include <unistd.h>
        #include <string.h>

        /* 32x 64kb writes then fdatasync, seek back so we dont fill the disk */
        int main(void) {{
            char path[] = "{tmp}";
            int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd < 0) {{ perror("open"); return 1; }}
            static char buf[65536];
            memset(buf, 0xAB, sizeof(buf));
            while (1) {{
                for (int i = 0; i < 32; i++) {{
                    if (write(fd, buf, sizeof(buf)) < 0) break;
                }}
                fdatasync(fd);
                lseek(fd, 0, SEEK_SET);
            }}
            close(fd);
            return 0;
        }}
    """)
    src_path = Path(tempfile.mktemp(suffix=".c", prefix="calib_io_"))
    bin_path = Path(tempfile.mktemp(prefix="calib_io_"))
    src_path.write_text(src)
    try:
        subprocess.run(["gcc", "-O2", "-o", str(bin_path), str(src_path)],
                       check=True, capture_output=True)
        src_path.unlink(missing_ok=True)
        p = subprocess.Popen([str(bin_path)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return p, f"fdatasync-loop ({tmp.name})", [bin_path, tmp]
    except Exception:
        src_path.unlink(missing_ok=True)

    try:
        p = subprocess.Popen(
            wrap_cmd(["stress-ng", "--io", "2", "--timeout", "300s"]),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.3)
        if p.poll() is not None:
            raise FileNotFoundError()
        return p, "stress-ng --io 2", []
    except FileNotFoundError:
        pass

    raise RuntimeError("Cannot launch IO workload: gcc and stress-ng both unavailable")


def launch_idle_workload():
    """just sleeps, gives us the zero baseline"""
    src = textwrap.dedent("""\
        #include <unistd.h>
        int main(void) { while(1) sleep(10); return 0; }
    """)
    src_path = Path(tempfile.mktemp(suffix=".c", prefix="calib_idle_"))
    bin_path = Path(tempfile.mktemp(prefix="calib_idle_"))
    src_path.write_text(src)
    try:
        subprocess.run(["gcc", "-O2", "-o", str(bin_path), str(src_path)],
                       check=True, capture_output=True)
        src_path.unlink(missing_ok=True)
        p = subprocess.Popen([str(bin_path)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return p, "sleep-loop"
    except Exception:
        src_path.unlink(missing_ok=True)

    # Fallback: use sleep
    p = subprocess.Popen(wrap_cmd(["sleep", "300"]),
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return p, "sleep 300"


def launch_contention_workload(cores):
    """forks cores+2 busy loops so cpu is oversubscribed. none of the
    other 4 workloads ever have more work than cores so cant produce real
    runqueue wait, this is the only one that can.

    using one forking parent instead of N separate Popen calls means
    get_all_pids()'s existing pgrep -P recursion just finds all the
    children automatically, nothing else needs to change"""
    n_procs = cores + 2
    src = textwrap.dedent(f"""\
        #include <stdint.h>
        #include <unistd.h>
        #include <sys/wait.h>

        static void burn(void) {{
            volatile uint64_t a = 1, b = 2, c = 3, d = 4;
            while (1) {{
                a = a * 6364136223846793005ULL + 1442695040888963407ULL;
                b = b * 6364136223846793005ULL + 2305843009213693951ULL;
                c = c * 6364136223846793005ULL + 4611686018427387903ULL;
                d = d * 6364136223846793005ULL + 9223372036854775807ULL;
            }}
        }}

        int main(void) {{
            for (int i = 0; i < {n_procs}; i++) {{
                pid_t pid = fork();
                if (pid == 0) {{
                    burn();
                    _exit(0);
                }}
            }}
            /* parent just waits, gets sigterm'd + children reaped same
             * as every other workload */
            while (1) pause();
            return 0;
        }}
    """)
    src_path = Path(tempfile.mktemp(suffix=".c", prefix="calib_contention_"))
    bin_path = Path(tempfile.mktemp(prefix="calib_contention_"))
    src_path.write_text(src)
    try:
        subprocess.run(["gcc", "-O2", "-o", str(bin_path), str(src_path)],
                       check=True, capture_output=True)
        src_path.unlink(missing_ok=True)
        p = subprocess.Popen([str(bin_path)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return p, f"{n_procs} contending procs (cores={cores})"
    except Exception:
        src_path.unlink(missing_ok=True)

    raise RuntimeError("Cannot launch CONTENTION workload: gcc unavailable")


def get_all_pids(base_pid):
    """Collect PID + all threads (TIDs) + all child processes recursively."""
    targets = {base_pid}
    try:
        for t in os.listdir(f"/proc/{base_pid}/task"):
            targets.add(int(t))
    except (FileNotFoundError, ValueError):
        pass
    try:
        out = subprocess.check_output(
            ["pgrep", "-P", str(base_pid)], stderr=subprocess.DEVNULL)
        for c in out.decode().split():
            targets.update(get_all_pids(int(c)))
    except subprocess.CalledProcessError:
        pass
    return targets


def collect_samples(pids, duration_s, label, warmup_s=2.0, filter_zeros=False):
    """runs schedmon against the pids, collects csv, drops the first
    warmup_s seconds since the sliding window (500ms) isnt full yet"""
    pids_str = ",".join(map(str, pids))
    csv_path = SCRIPT_DIR / f"_calib_{label}.csv"

    cmd = [
        str(MONITOR_BIN), str(BPF_OBJ),
        "--pids", pids_str,
        "--csv",  str(csv_path),
        "--interval", "50",
        "--label", label,
    ]

    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(warmup_s + duration_s)
    p.terminate()
    try:
        p.wait(timeout=3)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()

    rows = {"ipc": [], "llc": [], "ctx": [], "io_freq": [], "io_wait": [], "rq_wait": []}
    if not csv_path.exists():
        return rows

    cutoff_ns = None
    try:
        with open(csv_path) as f:
            reader = csv.DictReader(f)
            all_rows = list(reader)

        if not all_rows:
            return rows

        first_ts = int(all_rows[0]["timestamp_ns"])
        cutoff_ns = first_ts + int(warmup_s * 1e9)

        n_filtered = 0
        for row in all_rows:
            if int(row["timestamp_ns"]) < cutoff_ns:
                continue
            ipc_val = float(row["ipc"])
            # ipc==0 usually just means the process didnt get scheduled that
            # interval, noise for cpu/mem workloads but keep it for io/idle
            if filter_zeros and ipc_val == 0.0:
                n_filtered += 1
                continue
            rows["ipc"].append(ipc_val)
            rows["llc"].append(float(row["llc_miss"]))
            rows["ctx"].append(float(row["ctx_freq"]))
            rows["io_freq"].append(float(row.get("io_freq", 0)))
            rows["io_wait"].append(float(row.get("io_wait_ms", 0)))
            rows["rq_wait"].append(float(row.get("rq_wait_ms", 0)))

    except Exception as e:
        print(f"  WARNING: CSV parse error: {e}")
    finally:
        csv_path.unlink(missing_ok=True)

    if filter_zeros and n_filtered:
        print(f"  Filtered : {n_filtered} zero-IPC samples"
              " (process descheduled — not representative of workload)")

    return rows


def remove_outliers(values, k=2.0):
    """drop values more than k stdev from the mean, needs >= 4 values"""
    if len(values) < 4:
        return values
    mean = statistics.mean(values)
    stdev = statistics.stdev(values)
    if stdev == 0:
        return values
    return [v for v in values if abs(v - mean) <= k * stdev]


def summarise(label, rows):
    """Print and return cleaned statistics for a workload."""
    result = {}
    print(f"  {'Metric':<12} {'raw_n':>6} {'clean_n':>7} "
          f"{'mean':>8} {'stdev':>8} {'p10':>8} {'p90':>8}")
    print(f"  {'-'*60}")

    for metric, values in rows.items():
        if not values:
            result[metric] = {"mean": 0.0, "stdev": 0.0, "p10": 0.0,
                              "p90": 0.0, "n": 0}
            continue
        raw_n = len(values)
        clean = remove_outliers(values)
        if not clean:
            clean = values
        s = sorted(clean)
        n = len(s)
        mean  = statistics.mean(clean)
        stdev = statistics.stdev(clean) if n > 1 else 0.0
        p10   = s[max(0, int(n * 0.10))]
        p90   = s[min(n-1, int(n * 0.90))]
        result[metric] = {"mean": mean, "stdev": stdev,
                          "p10": p10, "p90": p90, "n": n}
        print(f"  {metric:<12} {raw_n:>6} {n:>7} "
              f"{mean:>8.4f} {stdev:>8.4f} {p10:>8.4f} {p90:>8.4f}")
    return result


def run_workload(name, launcher_fn, duration_s, llc_bytes=None, cores=None):
    print(f"\n── {name} workload {'─'*(40-len(name))}")

    cleanup_files = []
    try:
        if name == "MEM":
            p_work, desc = launcher_fn(llc_bytes)
        elif name == "IO":
            result = launcher_fn()
            p_work, desc = result[0], result[1]
            cleanup_files = result[2]
        elif name == "CONTENTION":
            p_work, desc = launcher_fn(cores)
        else:
            p_work, desc = launcher_fn()
    except RuntimeError as e:
        print(f"  SKIP: {e}")
        return None

    print(f"  Workload : {desc}  (PID {p_work.pid})")

    # Give the workload time to start fully before collecting PIDs
    time.sleep(1.5)

    if p_work.poll() is not None:
        print(f"  ERROR: workload exited immediately (returncode={p_work.returncode})")
        return None

    pids = get_all_pids(p_work.pid)
    print(f"  Tracing  : {sorted(pids)} ({len(pids)} thread(s))")
    print(f"  Duration : {duration_s}s + 2s warmup")

    # stop the production daemon while we measure so we dont fight over
    # perf_event_open on the same pids, restart right after
    daemon_was_running = daemon_stop()
    if daemon_was_running:
        print(f"  Daemon   : stopped for measurement window")

    filter_z = name in ("CPU", "MEM")
    try:
        rows = collect_samples(pids, duration_s, name.lower(), filter_zeros=filter_z)
    finally:
        if daemon_was_running:
            daemon_start()
            print(f"  Daemon   : restarted")

    try:
        p_work.terminate()
        p_work.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p_work.kill()
        p_work.wait()

    for f in cleanup_files:
        try:
            Path(f).unlink(missing_ok=True)
        except Exception:
            pass

    n = len(rows["ipc"])
    if n == 0:
        print("  WARNING: No samples collected after warmup — "
              "check that schedmon is built and BPF object exists.")
        return None

    print(f"  Samples  : {n} (after warmup discard)")
    stats = summarise(name, rows)
    return stats


def adaptive_guard_frac(gap, lo_stdev, hi_stdev, base=0.10, min_frac=0.10, max_frac=0.30):
    """widens the guard band when noise is large relative to the gap
    between distributions. matters on narrow-issue cpus where the whole
    ipc range gets compressed (~0.15-0.6 instead of 0.3-3.0), same noise
    is a much bigger deal there so a flat 10% isnt enough margin"""
    if gap <= 0:
        return base
    avg_stdev = (lo_stdev + hi_stdev) / 2.0
    if avg_stdev <= 0:
        return base
    noise_ratio = avg_stdev / gap
    frac = base + min(noise_ratio, 1.0) * (max_frac - base)
    return max(min_frac, min(frac, max_frac))


def midpoint_with_guard(lo_val, hi_val, guard_frac=0.10):
    """midpoint between lo/hi shifted guard_frac toward hi, biases the
    threshold a bit to reduce false positives on borderline cases"""
    mid = (lo_val + hi_val) / 2.0
    shift = (hi_val - lo_val) * guard_frac
    return mid + shift


def derive_thresholds(cpu_stats, mem_stats, io_stats, idle_stats, contention_stats,
                       cores, llc_bytes, ram_gb):
    """derives all 7 thresholds from the measured distributions, falls
    back to hardware guesses if a workload got skipped or didnt produce
    enough samples"""
    print(f"\n{'─'*50}")
    print(f"[calibrate] Hardware: {cores} cores, "
          f"{llc_bytes//1024//1024}MB LLC, {ram_gb}GB RAM")
    cpu_model = get_cpu_model()
    print(f"[calibrate] CPU model: {cpu_model}")

    # ipc_cpu: p10 of cpu ipc vs p90 of mem ipc
    if cpu_stats and mem_stats:
        cpu_ipc_low = cpu_stats["ipc"]["p10"]
        mem_ipc_high = mem_stats["ipc"]["p90"]
        if cpu_ipc_low > mem_ipc_high:
            gf = adaptive_guard_frac(cpu_ipc_low - mem_ipc_high,
                                      mem_stats["ipc"]["stdev"], cpu_stats["ipc"]["stdev"])
            ipc_cpu_thresh = midpoint_with_guard(mem_ipc_high, cpu_ipc_low, gf)
        else:
            print("  [WARN] CPU and MEM IPC distributions overlap. "
                  "Using mean-based fallback.")
            ipc_cpu_thresh = (cpu_stats["ipc"]["mean"] + mem_stats["ipc"]["mean"]) / 2.0
    else:
        # narrow-issue cpus dont get faster ipc ceilings just from more cores,
        # hw_profile checks the model string for known low power families
        ipc_cpu_thresh = hw_profile.hw_ipc_cpu_fallback(cores, cpu_model)
        print(f"  [WARN] Using hardware fallback for ipc_cpu_threshold: {ipc_cpu_thresh:.4f}"
              + (" (narrow-issue CPU detected)"
                 if hw_profile.is_narrow_issue_cpu(cpu_model) else ""))

    # ipc_mem: p10 of mem ipc vs p90 of idle ipc
    if mem_stats and idle_stats:
        mem_ipc_low  = mem_stats["ipc"]["p10"]
        idle_ipc_high = idle_stats["ipc"]["p90"]
        if mem_ipc_low > idle_ipc_high:
            gf = adaptive_guard_frac(mem_ipc_low - idle_ipc_high,
                                      idle_stats["ipc"]["stdev"], mem_stats["ipc"]["stdev"])
            ipc_mem_thresh = midpoint_with_guard(idle_ipc_high, mem_ipc_low, gf)
        else:
            ipc_mem_thresh = mem_stats["ipc"]["mean"] * 0.7
    elif mem_stats:
        ipc_mem_thresh = mem_stats["ipc"]["mean"] * 0.7
    else:
        ipc_mem_thresh = 0.4
        print(f"  [WARN] Using fallback for ipc_mem_threshold: {ipc_mem_thresh:.4f}")

    # llc_mem: p10 of mem llc vs p90 of cpu llc
    if mem_stats and cpu_stats:
        mem_llc_low = mem_stats["llc"]["p10"]
        cpu_llc_high = cpu_stats["llc"]["p90"]
        if mem_llc_low > cpu_llc_high:
            gf = adaptive_guard_frac(mem_llc_low - cpu_llc_high,
                                      cpu_stats["llc"]["stdev"], mem_stats["llc"]["stdev"])
            llc_mem_thresh = midpoint_with_guard(cpu_llc_high, mem_llc_low, gf)
        else:
            print("  [WARN] CPU and MEM LLC distributions overlap. "
                  "Using mean-based fallback.")
            llc_mem_thresh = (mem_stats["llc"]["mean"] + cpu_stats["llc"]["mean"]) / 2.0
    else:
        llc_mem_thresh = 0.02 * (8.0 / ram_gb)
        print(f"  [WARN] Using hardware fallback for llc_mem_threshold: {llc_mem_thresh:.6f}")

    # ctx_io: p10 of io ctx_freq vs p90 of idle ctx_freq
    if io_stats and idle_stats:
        io_ctx_low   = io_stats["ctx"]["p10"]
        idle_ctx_high = idle_stats["ctx"]["p90"]
        if io_ctx_low > idle_ctx_high:
            gf = adaptive_guard_frac(io_ctx_low - idle_ctx_high,
                                      idle_stats["ctx"]["stdev"], io_stats["ctx"]["stdev"])
            ctx_io_thresh = midpoint_with_guard(idle_ctx_high, io_ctx_low, gf)
        else:
            ctx_io_thresh = io_stats["ctx"]["mean"] * 0.5
            print(f"  [WARN] IO and IDLE ctx distributions overlap. "
                  f"Using 50% of IO mean: {ctx_io_thresh:.1f}")
    elif io_stats:
        ctx_io_thresh = io_stats["ctx"]["mean"] * 0.5
    else:
        ctx_io_thresh = 500.0
        print(f"  [WARN] Using fallback for ctx_io_threshold: {ctx_io_thresh:.1f}")

    # ipc_idle: p90 of idle ipc + 2 stdev, capped below ipc_mem so idle
    # doesnt eat into real (if quiet) mem-bound activity
    if idle_stats:
        idle_ipc_p90 = idle_stats["ipc"]["p90"]
        idle_ipc_stdev = idle_stats["ipc"]["stdev"]
        ipc_idle_thresh = idle_ipc_p90 + 2.0 * idle_ipc_stdev
        ipc_idle_thresh = min(ipc_idle_thresh, ipc_mem_thresh * 0.5)
    else:
        ipc_idle_thresh = 0.05
        print(f"  [WARN] Using fallback for ipc_idle_threshold: {ipc_idle_thresh:.4f}")

    # io_wait_bound: p10 of io io_wait vs p90 of idle io_wait
    if io_stats and idle_stats:
        io_wait_low   = io_stats["io_wait"]["p10"]
        idle_wait_high = idle_stats["io_wait"]["p90"]
        if io_wait_low > idle_wait_high:
            gf = adaptive_guard_frac(io_wait_low - idle_wait_high,
                                      idle_stats["io_wait"]["stdev"], io_stats["io_wait"]["stdev"])
            io_wait_bound_thresh = midpoint_with_guard(idle_wait_high, io_wait_low, gf)
        else:
            io_wait_bound_thresh = io_stats["io_wait"]["mean"] * 0.5
            print("  [WARN] IO and IDLE io_wait distributions overlap. "
                  f"Using 50% of IO mean: {io_wait_bound_thresh:.2f}")
    elif io_stats:
        io_wait_bound_thresh = io_stats["io_wait"]["mean"] * 0.5
    else:
        io_wait_bound_thresh = 5.0
        print(f"  [WARN] Using fallback for io_wait_bound_threshold: {io_wait_bound_thresh:.2f}")

    # rq_wait_starved: p10 of contention rq_wait vs p90 of idle rq_wait.
    # needs the CONTENTION workload specifically since none of the other
    # 4 ever oversubscribe cores
    if contention_stats and idle_stats:
        cont_wait_low = contention_stats["rq_wait"]["p10"]
        idle_wait_high = idle_stats["rq_wait"]["p90"]
        if cont_wait_low > idle_wait_high:
            gf = adaptive_guard_frac(cont_wait_low - idle_wait_high,
                                      idle_stats["rq_wait"]["stdev"],
                                      contention_stats["rq_wait"]["stdev"])
            rq_wait_starved_thresh = midpoint_with_guard(idle_wait_high, cont_wait_low, gf)
        else:
            rq_wait_starved_thresh = contention_stats["rq_wait"]["mean"] * 0.5
            print("  [WARN] CONTENTION and IDLE rq_wait distributions overlap. "
                  f"Using 50% of CONTENTION mean: {rq_wait_starved_thresh:.2f}")
    elif contention_stats:
        rq_wait_starved_thresh = contention_stats["rq_wait"]["mean"] * 0.5
    else:
        rq_wait_starved_thresh = 2.0
        print(f"  [WARN] Using fallback for rq_wait_starved_threshold: {rq_wait_starved_thresh:.2f} "
              "(CONTENTION workload skipped or unavailable)")

    # no floor on ipc_cpu_thresh on purpose -- in-order cpus genuinely
    # have ipc < 0.5 even compute bound, a floor would just be wrong here

    if ipc_mem_thresh >= ipc_cpu_thresh:
        print(f"  [WARN] ipc_mem_threshold ({ipc_mem_thresh:.4f}) >= "
              f"ipc_cpu_threshold ({ipc_cpu_thresh:.4f}). "
              f"Clamping ipc_mem to 70% of ipc_cpu.")
        ipc_mem_thresh = ipc_cpu_thresh * 0.70

    llc_mem_thresh = max(llc_mem_thresh, 0.005)
    ctx_io_thresh = max(ctx_io_thresh, 50.0)
    ipc_idle_thresh        = max(ipc_idle_thresh, 0.0)
    io_wait_bound_thresh   = max(io_wait_bound_thresh, 0.1)
    rq_wait_starved_thresh = max(rq_wait_starved_thresh, 0.1)

    return {
        "ipc_cpu_threshold": round(ipc_cpu_thresh, 4),
        "ipc_mem_threshold": round(ipc_mem_thresh, 4),
        "llc_mem_threshold": round(llc_mem_thresh, 6),
        "ctx_io_threshold":  round(ctx_io_thresh,  1),
        "ipc_idle_threshold":        round(ipc_idle_thresh, 4),
        "io_wait_bound_threshold":   round(io_wait_bound_thresh, 2),
        "rq_wait_starved_threshold": round(rq_wait_starved_thresh, 2),
    }


def write_thresholds(thresholds, cores, llc_bytes, ram_gb, durations):
    CONF_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONF_PATH, "w") as f:
        f.write("# Auto-generated by calibrate.py\n")
        f.write(f"# Generated  : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Hardware   : {cores} cores, "
                f"{llc_bytes//1024//1024}MB LLC, {ram_gb}GB RAM\n")
        f.write(f"# CPU model  : {get_cpu_model()}\n")
        f.write(f"# Collection : {durations}s per workload "
                f"(+ 2s warmup each)\n")
        f.write(f"# Method     : midpoint between workload distributions "
                f"with adaptive guard band (10%-30%, widened when "
                f"distributions are noisy relative to their gap)\n\n")
        for k, v in thresholds.items():
            f.write(f"{k} = {v}\n")

    if SUDO_USER:
        uid = pwd.getpwnam(SUDO_USER).pw_uid
        gid = pwd.getpwnam(SUDO_USER).pw_gid
        os.chown(CONF_PATH, uid, gid)
        os.chown(CONF_PATH.parent, uid, gid)

    print(f"\n[calibrate] Thresholds written to {CONF_PATH}")


def check_prerequisites():
    """checks schedmon binary + bpf object exist and were running as root"""
    ok = True
    if not MONITOR_BIN.exists():
        print(f"[calibrate] ERROR: {MONITOR_BIN} not found. Run 'make' first.",
              file=sys.stderr)
        ok = False
    if not BPF_OBJ.exists():
        print(f"[calibrate] ERROR: {BPF_OBJ} not found. Run 'make bpf' first.",
              file=sys.stderr)
        ok = False
    if os.geteuid() != 0:
        print("[calibrate] ERROR: must run as root (sudo python3 calibrate.py).",
              file=sys.stderr)
        ok = False
    return ok


def daemon_is_active():
    r = subprocess.run(["systemctl", "is-active", "--quiet", "schedmon"])
    return r.returncode == 0

def daemon_stop():
    """stops the systemd unit, returns True if it was actually running
    (so caller knows whether to restart it after)"""
    if not daemon_is_active():
        return False
    subprocess.run(["systemctl", "stop", "schedmon"],
                   stderr=subprocess.DEVNULL)
    for _ in range(50):
        if not daemon_is_active():
            break
        time.sleep(0.1)
    time.sleep(0.3)   # let shm unlink propagate
    return True

def daemon_start():
    """starts the daemon and waits until its actually ready (unit active
    AND the shm ring buffer exists) -- otherwise dashboard stays blank
    while systemd already says active but bpf is still loading"""
    subprocess.run(["systemctl", "start", "schedmon"],
                   stderr=subprocess.DEVNULL)
    for _ in range(50):
        if daemon_is_active():
            break
        time.sleep(0.1)
    for _ in range(100):
        if os.path.exists("/dev/shm/monitor_rb_dash"):
            break
        time.sleep(0.1)
    time.sleep(0.3)


def main():
    parser = argparse.ArgumentParser(
        description="Calibrate schedmon workload thresholds.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Workloads run one at a time, no overlap.

            Min recommended duration: 15s (~260 samples after warmup).
            20-30s is more stable.

            Daemon only stops during each measurement window, not for
            the whole run.
        """))
    parser.add_argument("--duration", type=float, default=20.0,
                        help="Collection seconds per workload (default: 20)")
    parser.add_argument("--skip-idle", action="store_true",
                        help="Skip idle baseline (use if calibration takes too long)")
    parser.add_argument("--skip-contention", action="store_true",
                        help="Skip CPU-contention workload used for the "
                             "CPU-STARVED (rq_wait) threshold "
                             "(use if calibration takes too long)")
    args = parser.parse_args()

    if not check_prerequisites():
        sys.exit(1)

    cores, llc_bytes, ram_gb = get_hardware()
    print(f"[calibrate] Hardware detected: {cores} cores, "
          f"{llc_bytes//1024//1024}MB LLC, {ram_gb}GB RAM")
    print(f"[calibrate] CPU: {get_cpu_model()}")
    print(f"[calibrate] Duration: {args.duration}s per workload + 2s warmup each")
    n_workloads = 3 + (0 if args.skip_idle else 1) + (0 if args.skip_contention else 1)
    print(f"[calibrate] Total time: ~{int(n_workloads * (args.duration + 4))}s\n")

    results = {}

    results["CPU"]  = run_workload("CPU",  launch_cpu_workload,  args.duration)
    results["MEM"]  = run_workload("MEM",  launch_mem_workload,  args.duration,
                                   llc_bytes=llc_bytes)
    results["IO"]   = run_workload("IO",   launch_io_workload,   args.duration)
    if not args.skip_idle:
        results["IDLE"] = run_workload("IDLE", launch_idle_workload, args.duration)
    else:
        results["IDLE"] = None

    if not args.skip_contention:
        results["CONTENTION"] = run_workload("CONTENTION", launch_contention_workload,
                                              args.duration, cores=cores)
    else:
        results["CONTENTION"] = None

    thresholds = derive_thresholds(
        results["CPU"], results["MEM"], results["IO"], results["IDLE"],
        results["CONTENTION"], cores, llc_bytes, ram_gb)

    print(f"\n{'─'*50}")
    print("Derived thresholds:")
    for k, v in thresholds.items():
        print(f"  {k:<30} = {v}")

    write_thresholds(thresholds, cores, llc_bytes, ram_gb, args.duration)

    print("\n[calibrate] Done.")
    print("[calibrate] Daemon was restarted between each workload.")
    print("[calibrate] Dashboard was blank only during each measurement window.")

if __name__ == "__main__":
    main()