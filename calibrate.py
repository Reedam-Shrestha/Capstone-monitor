#!/usr/bin/env python3
"""
calibrate.py — Hardware-adaptive threshold calibration for schedmon.

Runs four controlled workloads on this specific machine and derives classifier
thresholds from the actual measured metric distributions.  Each workload is
chosen to produce a clean, unambiguous signal for one metric dimension.

Workloads:
  CPU   — sysbench prime number computation: purely arithmetic, no memory
           pressure, no I/O.  Produces maximum IPC for this CPU.

  MEM   — pointer-chasing across a large buffer (>= 2x LLC size).  Pointer
           chasing cannot be prefetched, so every access misses the cache and
           goes to DRAM.  Produces minimum IPC and maximum LLC miss rate.
           Falls back to stress-ng --cache if the custom binary is unavailable.

  IO    — dd reading from /dev/urandom and writing to a temp file in a tight
           loop, combined with fsync() to force actual block I/O completions.
           Uses only standard tools (dd, sync) — no stress-ng required.
           Also runs in parallel to generate both io_freq and ctx_freq signal.

  IDLE  — process sleeps for the collection window.  Establishes the true zero
           baseline: what IPC/LLC does a doing-nothing process report?

Threshold derivation:
  ipc_cpu_threshold  — midpoint between CPU and MEM IPC distributions
  ipc_mem_threshold  — midpoint between MEM and IDLE IPC distributions
  llc_mem_threshold  — midpoint between MEM and CPU LLC miss distributions
  ctx_io_threshold   — midpoint between IO and IDLE ctx_freq distributions

  The midpoint approach is better than scaling heuristics because it finds
  the actual decision boundary on this machine rather than guessing from
  hardware specs.  All thresholds include a 10% guard band toward the MEM/IO
  side to reduce false positives on mixed workloads.

Usage:
  sudo python3 calibrate.py [--duration 20] [--no-restart]
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

# ── paths ────────────────────────────────────────────────────────────────────

SCRIPT_DIR  = Path(__file__).parent.resolve()
MONITOR_BIN = SCRIPT_DIR / "schedmon"
BPF_OBJ     = SCRIPT_DIR / "bpf" / "ctx_switch.bpf.o"

SUDO_USER = os.environ.get("SUDO_USER")
if SUDO_USER:
    REAL_HOME = Path(pwd.getpwnam(SUDO_USER).pw_dir)
else:
    REAL_HOME = Path.home()

CONF_PATH = REAL_HOME / ".config" / "schedmon" / "thresholds.conf"

# ── hardware detection ────────────────────────────────────────────────────────

def get_hardware():
    """Read CPU count, LLC size (bytes), and total RAM from procfs/sysfs."""
    cores = os.cpu_count() or 2

    # LLC size: walk sysfs cache hierarchy, take the largest unified cache
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
        llc_bytes = 4 * 1024 * 1024  # safe fallback: 4MB

    # Total RAM in GB
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
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return "unknown"


# ── workload launchers ────────────────────────────────────────────────────────

def wrap_cmd(cmd_list):
    """Drop privileges if running under sudo so workloads run as the real user."""
    if SUDO_USER:
        return ["sudo", "-u", SUDO_USER] + cmd_list
    return cmd_list


def launch_cpu_workload():
    """
    Pure arithmetic: compiled C busy-loop running as root.
    Compiled binary is tried first (runs as root, no wrap_cmd) so
    perf_event_open works regardless of kernel.perf_event_paranoid.
    Sysbench is only used if gcc is unavailable.
    """
    # Primary: compile and run a minimal LCG busy-loop as root
    cpu_src = textwrap.dedent("""\
        #include <stdint.h>
        int main(void) {
            /* Four independent LCG chains — fills all ALU slots on an
             * in-order Celeron N4020, maximising IPC without any memory
             * pressure.  Each chain is a Lehmer LCG (multiply + add). */
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
        # Run as root — no wrap_cmd
        p = subprocess.Popen([str(bin_path)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return p, "cpu-spin (root)"
    except Exception:
        src_path.unlink(missing_ok=True)

    # Fallback: sysbench (runs as SUDO_USER via wrap_cmd — less accurate
    # because cross-uid perf monitoring may be restricted by the kernel)
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
    """
    Pointer-chasing across a buffer 4x the LLC size.
    Each pointer dereference is a guaranteed LLC miss → DRAM access.
    Cannot be prefetched by hardware prefetchers.
    Produces: minimum IPC, maximum LLC miss rate.
    """
    buf_mb = max(64, (llc_bytes * 8) // (1024 * 1024))  # 8x LLC → deeper DRAM pressure

    src = textwrap.dedent(f"""\
        #include <stdlib.h>
        #include <stdint.h>
        #include <string.h>
        #include <stdio.h>

        /* Pointer-chasing: follow a random permutation of pointers across
         * a {buf_mb}MB buffer.  Each pointer is 64 bytes apart (one cache line).
         * The random permutation prevents the hardware prefetcher from
         * predicting the access pattern. */
        int main(void) {{
            size_t buf_bytes = {buf_mb}ULL * 1024 * 1024;
            size_t n = buf_bytes / 64;          /* number of 64-byte slots */
            uintptr_t *buf = malloc(buf_bytes);
            if (!buf) {{ perror("malloc"); return 1; }}

            /* Build a random cyclic permutation using Fisher-Yates */
            for (size_t i = 0; i < n; i++) buf[i] = (uintptr_t)&buf[i];
            for (size_t i = n - 1; i > 0; i--) {{
                size_t j = (size_t)rand() % (i + 1);
                uintptr_t tmp = buf[i]; buf[i] = buf[j]; buf[j] = tmp;
            }}

            /* Chase pointers forever — one LLC miss per iteration */
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

    # Fallback: stress-ng --cache
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
    """
    Real block I/O: dd reads random data, writes to a temp file, fsync forces
    block completions.  Runs multiple dd processes in parallel to saturate
    ctx_freq with genuine I/O waits.

    This produces:
      io_freq     > 0   (bytes/sec to /proc/PID/io)
      io_wait_ms  > 0   (BPF block_rq_complete latency)
      ctx_freq    high  (process blocks on write, wakes on completion)
    """
    tmp = Path(tempfile.mktemp(prefix="calib_io_"))

    src = textwrap.dedent(f"""\
        #include <stdio.h>
        #include <stdlib.h>
        #include <fcntl.h>
        #include <unistd.h>
        #include <string.h>

        /* Write 64KB blocks in batches of 32, then fdatasync.
         * 32 * 64KB = 2MB per sync cycle — ~8x more data per fsync than
         * the original 16 * 4KB = 64KB.  Drives much higher io_freq and
         * more context switches per second on this Celeron N4020. */
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
                /* Seek back to start to avoid filling the disk */
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

    # Fallback: stress-ng --io
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
    """Sleep — establishes true zero baseline for all metrics."""
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


# ── PID collection ────────────────────────────────────────────────────────────

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


# ── tracing ───────────────────────────────────────────────────────────────────

def collect_samples(pids, duration_s, label, warmup_s=2.0, filter_zeros=False):
    """
    Run schedmon targeting the given PIDs, collect CSV samples,
    discard the first warmup_s seconds (sliding window not yet full),
    return per-metric lists.

    The sliding window needs SWAG_CAPACITY=10 samples × 50ms = 500ms to fill.
    We use warmup_s=2.0 to be safe and let the workload stabilise.
    """
    pids_str = ",".join(map(str, pids))
    csv_path = SCRIPT_DIR / f"_calib_{label}.csv"

    cmd = [
        str(MONITOR_BIN), str(BPF_OBJ),
        "--pids", pids_str,
        "--csv",  str(csv_path),
        "--interval", "50",
        "--no-per-core",      # calibration needs aggregate only
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

    rows = {"ipc": [], "llc": [], "ctx": [], "io_freq": [], "io_wait": []}
    if not csv_path.exists():
        return rows

    cutoff_ns = None
    try:
        with open(csv_path) as f:
            reader = csv.DictReader(f)
            all_rows = list(reader)

        if not all_rows:
            return rows

        # Discard warmup: skip rows within warmup_s of the first timestamp
        first_ts = int(all_rows[0]["timestamp_ns"])
        cutoff_ns = first_ts + int(warmup_s * 1e9)

        n_filtered = 0
        for row in all_rows:
            if int(row["timestamp_ns"]) < cutoff_ns:
                continue
            ipc_val = float(row["ipc"])
            # filter_zeros: drop intervals where the process was descheduled
            # (ipc==0 when d_cycles==0, i.e. the process did not run at all
            # during that 200ms slow-path interval). These zeros are noise for
            # CPU/MEM workload characterisation; include them for IO/IDLE.
            if filter_zeros and ipc_val == 0.0:
                n_filtered += 1
                continue
            rows["ipc"].append(ipc_val)
            rows["llc"].append(float(row["llc_miss"]))
            rows["ctx"].append(float(row["ctx_freq"]))
            rows["io_freq"].append(float(row.get("io_freq", 0)))
            rows["io_wait"].append(float(row.get("io_wait_ms", 0)))

    except Exception as e:
        print(f"  WARNING: CSV parse error: {e}")
    finally:
        csv_path.unlink(missing_ok=True)

    if filter_zeros and n_filtered:
        print(f"  Filtered : {n_filtered} zero-IPC samples"
              " (process descheduled — not representative of workload)")

    return rows


def remove_outliers(values, k=2.0):
    """
    Remove values more than k standard deviations from the mean.
    Returns the cleaned list.  Requires at least 4 values.
    """
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


# ── workload runner ───────────────────────────────────────────────────────────

def run_workload(name, launcher_fn, duration_s, llc_bytes=None):
    print(f"\n── {name} workload {'─'*(40-len(name))}")

    cleanup_files = []
    try:
        if name == "MEM":
            p_work, desc = launcher_fn(llc_bytes)
        elif name == "IO":
            result = launcher_fn()
            p_work, desc = result[0], result[1]
            cleanup_files = result[2]
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

    # Stop the production daemon for the measurement window only.
    # This gives calibrate's schedmon exclusive BPF attachment and
    # prevents the two instances fighting over perf_event_open for the same PID.
    # The daemon is restarted immediately after collect_samples returns,
    # so the dashboard is only blank for ~(warmup + duration) seconds per workload.
    daemon_was_running = daemon_stop()
    if daemon_was_running:
        print(f"  Daemon   : stopped for measurement window")

    # CPU and MEM: filter out zero-IPC samples (process descheduled intervals)
    # IO and IDLE: keep zeros — they are meaningful for those workloads
    filter_z = name in ("CPU", "MEM")
    try:
        rows = collect_samples(pids, duration_s, name.lower(), filter_zeros=filter_z)
    finally:
        # Always restart the daemon, even if collect_samples raised
        if daemon_was_running:
            daemon_start()
            print(f"  Daemon   : restarted")

    # Stop workload
    try:
        p_work.terminate()
        p_work.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p_work.kill()
        p_work.wait()

    # Cleanup temp files
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


# ── threshold derivation ──────────────────────────────────────────────────────

def midpoint_with_guard(lo_val, hi_val, guard_frac=0.10):
    """
    Return the midpoint between lo_val and hi_val, shifted guard_frac toward
    hi_val.  This biases the threshold slightly toward the high-signal side
    to reduce false positives on borderline workloads.

    Example: lo=0.5, hi=1.5 → midpoint=1.0, guard shifts to 1.05.
    """
    mid = (lo_val + hi_val) / 2.0
    shift = (hi_val - lo_val) * guard_frac
    return mid + shift


def derive_thresholds(cpu_stats, mem_stats, io_stats, idle_stats, cores, llc_bytes, ram_gb):
    """
    Derive four thresholds from measured distributions using midpoint separation.

    Each threshold is the decision boundary between two workload classes,
    with a small guard band toward the high-signal side.

    Falls back to hardware-based estimates when a workload was skipped or
    produced too few samples.
    """
    print(f"\n{'─'*50}")
    print(f"[calibrate] Hardware: {cores} cores, "
          f"{llc_bytes//1024//1024}MB LLC, {ram_gb}GB RAM")
    print(f"[calibrate] CPU model: {get_cpu_model()}")

    # ── ipc_cpu_threshold ────────────────────────────────────────────────────
    # Boundary between CPU-bound (high IPC) and everything else.
    # Use p10 of CPU distribution (conservative lower bound of CPU IPC)
    # vs p90 of MEM distribution (conservative upper bound of MEM IPC).
    # Midpoint sits cleanly in the gap between the two distributions.
    if cpu_stats and mem_stats:
        cpu_ipc_low = cpu_stats["ipc"]["p10"]   # worst CPU-bound IPC
        mem_ipc_high = mem_stats["ipc"]["p90"]  # best MEM-bound IPC
        if cpu_ipc_low > mem_ipc_high:
            ipc_cpu_thresh = midpoint_with_guard(mem_ipc_high, cpu_ipc_low)
        else:
            # Distributions overlap — use mean as fallback
            print("  [WARN] CPU and MEM IPC distributions overlap. "
                  "Using mean-based fallback.")
            ipc_cpu_thresh = (cpu_stats["ipc"]["mean"] + mem_stats["ipc"]["mean"]) / 2.0
    else:
        # Hardware fallback: 2-core→1.2, 8-core→2.0, linear interpolation
        ipc_cpu_thresh = 1.2 + max(0, (cores - 2)) * 0.1333
        ipc_cpu_thresh = min(ipc_cpu_thresh, 3.0)
        print(f"  [WARN] Using hardware fallback for ipc_cpu_threshold: {ipc_cpu_thresh:.4f}")

    # ── ipc_mem_threshold ────────────────────────────────────────────────────
    # Boundary between MEM-bound (low IPC) and IDLE (near-zero IPC).
    # MEM-bound processes have measurable IPC (doing something);
    # idle processes have near-zero IPC.
    if mem_stats and idle_stats:
        mem_ipc_low  = mem_stats["ipc"]["p10"]
        idle_ipc_high = idle_stats["ipc"]["p90"]
        if mem_ipc_low > idle_ipc_high:
            ipc_mem_thresh = midpoint_with_guard(idle_ipc_high, mem_ipc_low)
        else:
            ipc_mem_thresh = mem_stats["ipc"]["mean"] * 0.7
    elif mem_stats:
        ipc_mem_thresh = mem_stats["ipc"]["mean"] * 0.7
    else:
        ipc_mem_thresh = 0.4
        print(f"  [WARN] Using fallback for ipc_mem_threshold: {ipc_mem_thresh:.4f}")

    # ── llc_mem_threshold ────────────────────────────────────────────────────
    # Boundary between MEM-bound (high LLC miss rate) and CPU-bound (low).
    # Use p10 of MEM LLC vs p90 of CPU LLC.
    if mem_stats and cpu_stats:
        mem_llc_low = mem_stats["llc"]["p10"]
        cpu_llc_high = cpu_stats["llc"]["p90"]
        if mem_llc_low > cpu_llc_high:
            llc_mem_thresh = midpoint_with_guard(cpu_llc_high, mem_llc_low)
        else:
            print("  [WARN] CPU and MEM LLC distributions overlap. "
                  "Using mean-based fallback.")
            llc_mem_thresh = (mem_stats["llc"]["mean"] + cpu_stats["llc"]["mean"]) / 2.0
    else:
        # Hardware fallback: 8GB→0.02, scales inversely with RAM
        llc_mem_thresh = 0.02 * (8.0 / ram_gb)
        print(f"  [WARN] Using hardware fallback for llc_mem_threshold: {llc_mem_thresh:.6f}")

    # ── ctx_io_threshold ─────────────────────────────────────────────────────
    # Boundary between IO-bound (high ctx/s) and non-IO-bound.
    # Use p10 of IO ctx_freq vs p90 of IDLE ctx_freq.
    if io_stats and idle_stats:
        io_ctx_low   = io_stats["ctx"]["p10"]
        idle_ctx_high = idle_stats["ctx"]["p90"]
        if io_ctx_low > idle_ctx_high:
            ctx_io_thresh = midpoint_with_guard(idle_ctx_high, io_ctx_low)
        else:
            # IO and IDLE ctx distributions overlap — use 50% of IO mean
            ctx_io_thresh = io_stats["ctx"]["mean"] * 0.5
            print(f"  [WARN] IO and IDLE ctx distributions overlap. "
                  f"Using 50% of IO mean: {ctx_io_thresh:.1f}")
    elif io_stats:
        ctx_io_thresh = io_stats["ctx"]["mean"] * 0.5
    else:
        ctx_io_thresh = 500.0
        print(f"  [WARN] Using fallback for ctx_io_threshold: {ctx_io_thresh:.1f}")

    # ── sanity checks ────────────────────────────────────────────────────────
    # NOTE: do NOT add a floor on ipc_cpu_thresh here.
    # In-order CPUs (Intel Tremont / Celeron N-series, ARM Cortex-A5x) have
    # genuine IPC < 0.5 even on compute-bound workloads because they cannot
    # issue more than 1 instruction per cycle.  A floor would override the
    # real measurement and produce thresholds that misclassify everything.
    # If perf counters were truly unavailable, ipc would be 0.0 (not 0.4),
    # which is caught by the ipc_mem >= ipc_cpu check below.

    # Enforce monotonicity: ipc_mem < ipc_cpu
    if ipc_mem_thresh >= ipc_cpu_thresh:
        print(f"  [WARN] ipc_mem_threshold ({ipc_mem_thresh:.4f}) >= "
              f"ipc_cpu_threshold ({ipc_cpu_thresh:.4f}). "
              f"Clamping ipc_mem to 70% of ipc_cpu.")
        ipc_mem_thresh = ipc_cpu_thresh * 0.70

    # LLC threshold must be positive
    llc_mem_thresh = max(llc_mem_thresh, 0.005)

    # ctx threshold must be positive
    ctx_io_thresh = max(ctx_io_thresh, 50.0)

    return {
        "ipc_cpu_threshold": round(ipc_cpu_thresh, 4),
        "ipc_mem_threshold": round(ipc_mem_thresh, 4),
        "llc_mem_threshold": round(llc_mem_thresh, 6),
        "ctx_io_threshold":  round(ctx_io_thresh,  1),
    }


# ── output ────────────────────────────────────────────────────────────────────

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
                f"with 10% guard band\n\n")
        for k, v in thresholds.items():
            f.write(f"{k} = {v}\n")

    if SUDO_USER:
        uid = pwd.getpwnam(SUDO_USER).pw_uid
        gid = pwd.getpwnam(SUDO_USER).pw_gid
        os.chown(CONF_PATH, uid, gid)
        os.chown(CONF_PATH.parent, uid, gid)

    print(f"\n[calibrate] Thresholds written to {CONF_PATH}")


def check_prerequisites():
    """Check that schedmon and BPF object exist before starting."""
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


# ── daemon lifecycle helpers ──────────────────────────────────────────────────

def daemon_is_active():
    """Return True if schedmon systemd unit is currently running."""
    r = subprocess.run(["systemctl", "is-active", "--quiet", "schedmon"])
    return r.returncode == 0

def daemon_stop():
    """
    Stop the systemd daemon and wait until it is gone.
    Returns True if the daemon was running (so the caller knows to restart it).
    Returns False if it was already stopped (no restart needed).
    """
    if not daemon_is_active():
        return False
    subprocess.run(["systemctl", "stop", "schedmon"],
                   stderr=subprocess.DEVNULL)
    # Wait up to 5 s for the unit to stop and release shm/BPF resources
    for _ in range(50):
        if not daemon_is_active():
            break
        time.sleep(0.1)
    time.sleep(0.3)   # let shm unlink propagate
    return True

def daemon_start():
    """
    Start the systemd daemon and wait until truly ready:
    unit active AND /dev/shm/monitor_rb_dash exists.
    Without the shm check the dashboard stays blank even though systemd
    reports the unit as active — the binary is still loading BPF.
    """
    subprocess.run(["systemctl", "start", "schedmon"],
                   stderr=subprocess.DEVNULL)
    # Step 1: wait up to 5s for systemd unit to become active
    for _ in range(50):
        if daemon_is_active():
            break
        time.sleep(0.1)
    # Step 2: wait up to 10s for the daemon to create the shm ring buffer
    # (BPF load + tracepoint attach can take 2-4s on slow hardware)
    for _ in range(100):
        if os.path.exists("/dev/shm/monitor_rb_dash"):
            break
        time.sleep(0.1)
    time.sleep(0.3)   # let first samples be written into the buffer


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Calibrate schedmon workload thresholds.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Workloads run sequentially. Each is isolated: one workload at a time,
            no background interference from other calibration processes.

            Minimum recommended duration: 15s (gives ~260 samples after 2s warmup).
            Recommended for stable results:   20-30s.

            The systemd daemon is stopped only during each measurement window
            (~warmup + duration seconds) and restarted between workloads.
            The dashboard is briefly blank per workload, not for the full run.
        """))
    parser.add_argument("--duration", type=float, default=20.0,
                        help="Collection seconds per workload (default: 20)")
    parser.add_argument("--skip-idle", action="store_true",
                        help="Skip idle baseline (use if calibration takes too long)")
    args = parser.parse_args()

    if not check_prerequisites():
        sys.exit(1)

    cores, llc_bytes, ram_gb = get_hardware()
    print(f"[calibrate] Hardware detected: {cores} cores, "
          f"{llc_bytes//1024//1024}MB LLC, {ram_gb}GB RAM")
    print(f"[calibrate] CPU: {get_cpu_model()}")
    print(f"[calibrate] Duration: {args.duration}s per workload + 2s warmup each")
    print(f"[calibrate] Total time: ~{int((4 if not args.skip_idle else 3) * (args.duration + 4))}s\n")

    # The daemon is stopped per-workload (inside run_workload) for the minimum
    # time needed to collect clean samples, then restarted before the next
    # workload begins.  The dashboard is only blank during each measurement
    # window (~warmup + duration seconds), not for the whole calibration run.
    results = {}

    # Run each workload sequentially so they don't interfere with each other
    results["CPU"]  = run_workload("CPU",  launch_cpu_workload,  args.duration)
    results["MEM"]  = run_workload("MEM",  launch_mem_workload,  args.duration,
                                   llc_bytes=llc_bytes)
    results["IO"]   = run_workload("IO",   launch_io_workload,   args.duration)
    if not args.skip_idle:
        results["IDLE"] = run_workload("IDLE", launch_idle_workload, args.duration)
    else:
        results["IDLE"] = None

    thresholds = derive_thresholds(
        results["CPU"], results["MEM"], results["IO"], results["IDLE"],
        cores, llc_bytes, ram_gb)

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
