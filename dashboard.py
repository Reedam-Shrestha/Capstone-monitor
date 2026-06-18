"""
Real-Time Performance Monitor Dashboard
Reads from shared-memory ring buffer written by schedmon.
Usage: python3 dashboard.py [--top 20] [--sort cpu|mem|ipc] [--interval 2]
"""

import os, sys, time, mmap, struct, ctypes, argparse
from dataclasses import dataclass, field
from typing import Dict

from rich.console import Console
from rich.table   import Table
from rich.live    import Live
from rich.panel   import Panel
from rich         import box

# ── Ring buffer constants — must match ring_buffer.h + smoothed_metrics.h ──
#
# SmoothedMetrics v4 layout (sizeof == 72):
#   offset  0  int      pid
#   offset  4  int      cpu_id
#   offset  8  uint64   timestamp_ns
#   offset 16  double   smoothed_ipc
#   offset 24  double   smoothed_llc_miss
#   offset 32  double   smoothed_ctx_freq
#   offset 40  double   smoothed_io_freq
#   offset 48  double   smoothed_io_wait_ms
#   offset 56  double   smoothed_rq_wait_ms
#   offset 64  double   smoothed_migration_freq
#
MONITOR_ABI_VERSION = 4   # must match smoothed_metrics.h
SLOT                = 72  # sizeof(SmoothedMetrics)
CAP                 = 32768  # RB_CAPACITY

SHM_PATH = "/dev/shm/monitor_rb_dash"

class SmoothedMetrics(ctypes.Structure):
    _fields_ = [
        ("pid",                    ctypes.c_int),
        ("cpu_id",                 ctypes.c_int),
        ("timestamp_ns",           ctypes.c_uint64),
        ("smoothed_ipc",           ctypes.c_double),
        ("smoothed_llc_miss",      ctypes.c_double),
        ("smoothed_ctx_freq",      ctypes.c_double),
        ("smoothed_io_freq",       ctypes.c_double),
        ("smoothed_io_wait_ms",    ctypes.c_double),
        ("smoothed_rq_wait_ms",    ctypes.c_double),
        ("smoothed_migration_freq",ctypes.c_double),
    ]

assert ctypes.sizeof(SmoothedMetrics) == SLOT, \
    f"SmoothedMetrics C size mismatch: expected {SLOT}, got {ctypes.sizeof(SmoothedMetrics)}"

# ── Threshold loader ─────────────────────────────────────────────────────────
_CONF_PATH = os.path.expanduser("~/.config/schedmon/thresholds.conf")
_DEFAULTS  = {
    "ipc_cpu_threshold": 1.2,
    "ipc_mem_threshold": 0.8,
    "llc_mem_threshold": 0.02,
    "ctx_io_threshold":  500.0,
}

def load_thresholds() -> dict:
    t = dict(_DEFAULTS)
    if not os.path.exists(_CONF_PATH):
        return t
    try:
        for line in open(_CONF_PATH):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            if key in t:
                t[key] = float(val.strip())
    except Exception:
        pass
    return t

_thresholds   = load_thresholds()
_thresh_mtime = 0.0


# ── Workload classifier (display-only — Bigyan's is authoritative) ───────────
def classify(ipc: float, llc_miss: float, ctx_freq: float,
             io_wait_ms: float, rq_wait_ms: float):
    """
    Rule-based classifier for the dashboard display.
    Labelled 'Est.Workload' to distinguish from Bigyan's authoritative classifier.
    Re-reads thresholds.conf on disk change (live recalibration).
    """
    global _thresholds, _thresh_mtime
    try:
        mt = os.path.getmtime(_CONF_PATH)
        if mt != _thresh_mtime:
            _thresholds   = load_thresholds()
            _thresh_mtime = mt
    except Exception:
        pass

    t = _thresholds

    # I/O-bound: prioritise io_wait_ms (latency) over ctx_freq (throughput)
    # A process blocked on slow I/O has high wait even with moderate ctx rate.
    if io_wait_ms > 5.0 or ctx_freq > t["ctx_io_threshold"]:
        return "IO-BOUND",  "red"

    # CPU-starved: process wants CPU (high IPC when it runs) but is waiting
    # for cores (high rq_wait_ms).  Distinct from CPU-BOUND which has low wait.
    # Signal for Prabhakar: this process should migrate to a less loaded core.
    if ipc > t["ipc_cpu_threshold"] and rq_wait_ms > 2.0:
        return "CPU-STARVED", "bright_red"

    if ipc > t["ipc_cpu_threshold"] and ctx_freq < t["ctx_io_threshold"]:
        return "CPU-BOUND", "green"
    if llc_miss > t["llc_mem_threshold"] and ipc < t["ipc_mem_threshold"]:
        return "MEM-BOUND", "yellow"
    if ipc < 0.05:
        return "IDLE",      "dim"
    return "MIXED",         "blue"


# ── Ring buffer drain ────────────────────────────────────────────────────────
def drain_ring_buffer() -> Dict[int, SmoothedMetrics]:
    result: Dict[int, SmoothedMetrics] = {}
    if not os.path.exists(SHM_PATH):
        return result

    slots_sz = SLOT * CAP
    try:
        actual = os.path.getsize(SHM_PATH)
        fd     = os.open(SHM_PATH, os.O_RDWR)
        mm     = mmap.mmap(fd, actual, access=mmap.ACCESS_WRITE)
        os.close(fd)
    except Exception:
        return result

    try:
        head_off = slots_sz
        tail_off = slots_sz + 4
        head = int.from_bytes(mm[head_off:head_off+4], 'little')
        tail = int.from_bytes(mm[tail_off:tail_off+4], 'little')

        drained = 0
        while tail != head and drained < CAP:
            idx    = tail % CAP
            offset = idx * SLOT
            chunk  = bytes(mm[offset:offset+SLOT])

            pid = int.from_bytes(chunk[0:4],  'little', signed=True)
            ts  = int.from_bytes(chunk[8:16], 'little')

            if 0 < pid < 4194304 and ts > 0:
                ipc = struct.unpack_from('d', chunk, 16)[0]
                if 0.0 <= ipc <= 20.0:
                    m = SmoothedMetrics.from_buffer_copy(chunk)
                    if pid not in result or ts > result[pid].timestamp_ns:
                        result[pid] = m

            new_tail = (tail + 1) % CAP
            mm[tail_off:tail_off+4] = new_tail.to_bytes(4, 'little')
            tail    = new_tail
            drained += 1

    except Exception:
        pass
    finally:
        mm.close()

    return result


# ── /proc helpers ────────────────────────────────────────────────────────────
def read_proc_stat(pid: int):
    try:
        with open(f"/proc/{pid}/stat") as f:
            line = f.read()
        comm_s = line.index('(') + 1
        comm_e = line.rindex(')')
        comm   = line[comm_s:comm_e]
        rest   = line[comm_e+2:].split()
        return comm, int(rest[11]) + int(rest[12])
    except Exception:
        return None

def read_proc_status(pid: int):
    rss_kb, threads = 0, 0
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss_kb  = int(line.split()[1])
                elif line.startswith("Threads:"):
                    threads = int(line.split()[1])
    except Exception:
        pass
    return rss_kb, threads


# ── Per-PID display state ────────────────────────────────────────────────────
@dataclass
class PidInfo:
    pid:            int   = 0
    comm:           str   = ""
    cpu_pct:        float = 0.0
    rss_mb:         float = 0.0
    threads:        int   = 0
    cpu_id:         int   = -1
    ipc:            float = 0.0
    llc_miss:       float = 0.0
    ctx_freq:       float = 0.0
    io_freq:        float = 0.0
    io_wait_ms:     float = 0.0
    rq_wait_ms:     float = 0.0
    migration_freq: float = 0.0
    prev_ticks:     int   = 0
    seen:           bool  = False
    last_seen:      float = field(default_factory=time.time)


# ── Dashboard ────────────────────────────────────────────────────────────────
class Dashboard:
    def __init__(self, top_n: int, interval: float, sort_by: str = "cpu",
                 show_zero: bool = False):
        self.top_n     = top_n
        self.interval  = interval
        self.sort_by   = sort_by
        self.show_zero = show_zero
        self.state:    Dict[int, PidInfo] = {}
        self.hz        = os.sysconf("SC_CLK_TCK")
        self.ncores    = os.cpu_count() or 1

    def update(self):
        rb_data = drain_ring_buffer()
        now     = time.time()

        for info in self.state.values():
            info.seen = False

        for pid, m in rb_data.items():
            stat = read_proc_stat(pid)
            if not stat:
                continue
            comm, total_ticks = stat
            rss_kb, threads   = read_proc_status(pid)

            if pid not in self.state:
                self.state[pid] = PidInfo(pid=pid, prev_ticks=total_ticks)

            info             = self.state[pid]
            info.comm        = comm
            info.rss_mb      = rss_kb / 1024
            info.threads     = threads
            info.seen        = True
            info.last_seen   = now
            info.cpu_id      = m.cpu_id

            delta            = total_ticks - info.prev_ticks
            info.cpu_pct     = (delta / (self.interval * self.hz)) * 100 / self.ncores
            info.prev_ticks  = total_ticks

            info.ipc            = m.smoothed_ipc
            info.llc_miss       = m.smoothed_llc_miss
            info.ctx_freq       = m.smoothed_ctx_freq
            info.io_freq        = m.smoothed_io_freq
            info.io_wait_ms     = m.smoothed_io_wait_ms
            info.rq_wait_ms     = m.smoothed_rq_wait_ms
            info.migration_freq = m.smoothed_migration_freq

        for pid in list(self.state.keys()):
            if not self.state[pid].seen:
                if now - self.state[pid].last_seen > 10.0:
                    del self.state[pid]

    def make_table(self):
        sort_key = {
            "cpu": lambda x: x.cpu_pct,
            "mem": lambda x: x.rss_mb,
            "ipc": lambda x: x.ipc,
        }.get(self.sort_by, lambda x: x.cpu_pct)

        rows = sorted(self.state.values(), key=sort_key, reverse=True)

        # Filter all-zero entries unless --zero/-z was passed.
        # "Active" means at least one perf metric is non-zero.
        if not self.show_zero:
            rows = [r for r in rows if
                    r.ipc > 0.0 or r.llc_miss > 0.0 or r.ctx_freq > 0.0
                    or r.io_freq > 0.0 or r.io_wait_ms > 0.0
                    or r.rq_wait_ms > 0.0 or r.migration_freq > 0.0]

        if self.top_n > 0:
            rows = rows[:self.top_n]

        conf_exists = os.path.exists(_CONF_PATH)
        shm_ok      = os.path.exists(SHM_PATH)
        src_str = "[green]shm live[/]" if shm_ok else "[red]shm missing — start schedmon[/]"
        cal_str = "[green]calibrated[/]" if conf_exists else "[yellow]defaults[/]"

        table = Table(
            box=box.SIMPLE_HEAVY,
            title=(f"[bold cyan]Performance Monitor[/]  "
                   f"[dim]{time.strftime('%H:%M:%S')}[/]  "
                   f"{src_str}  thresholds:{cal_str}  "
                   f"[dim]ABI v{MONITOR_ABI_VERSION}[/]"),
            title_justify="left",
            show_header=True,
            header_style="bold white",
            border_style="bright_black",
            pad_edge=False,
        )
        table.add_column("PID",          style="cyan bold", width=7,  no_wrap=True)
        table.add_column("Process",      style="white",     width=18, no_wrap=True)
        table.add_column("CPU%",         style="green",     width=7,  justify="right")
        table.add_column("RSS(MB)",      style="blue",      width=8,  justify="right")
        table.add_column("Thds",         style="dim",       width=5,  justify="right")
        table.add_column("IPC",          style="yellow",    width=6,  justify="right")
        table.add_column("LLC%",         style="magenta",   width=8,  justify="right")
        table.add_column("ctx/s",        style="red",       width=8,  justify="right")
        table.add_column("io B/s",       style="cyan",      width=9,  justify="right")
        table.add_column("io_wait",      style="magenta",   width=9,  justify="right")
        table.add_column("rq_wait",      style="yellow",    width=9,  justify="right")
        table.add_column("mig/s",        style="cyan",      width=7,  justify="right")
        table.add_column("Est.Workload", width=12)

        has_per_core = any(i.cpu_id >= 0 for i in rows)
        if has_per_core:
            table.add_column("Core", style="dim", width=5, justify="right")

        for info in rows:
            label, color = classify(info.ipc, info.llc_miss, info.ctx_freq,
                                    info.io_wait_ms, info.rq_wait_ms)

            if info.cpu_pct > 80:
                cpu_str = f"[bold red]{info.cpu_pct:5.1f}[/]"
            elif info.cpu_pct > 40:
                cpu_str = f"[yellow]{info.cpu_pct:5.1f}[/]"
            else:
                cpu_str = f"{info.cpu_pct:5.1f}"

            # Highlight high I/O wait in red, high rq_wait in yellow
            io_wait_str = (f"[red]{info.io_wait_ms:6.1f}ms[/]"
                           if info.io_wait_ms > 5.0
                           else f"{info.io_wait_ms:6.1f}ms")
            rq_wait_str = (f"[yellow]{info.rq_wait_ms:6.1f}ms[/]"
                           if info.rq_wait_ms > 2.0
                           else f"{info.rq_wait_ms:6.1f}ms")

            # Format io_freq as bytes/sec with K/M suffix for readability
            io_b = info.io_freq
            if io_b >= 1048576:
                io_str = f"{io_b/1048576:5.1f}M"
            elif io_b >= 1024:
                io_str = f"{io_b/1024:5.1f}K"
            else:
                io_str = f"{io_b:5.0f}B"

            # Highlight high migration rate in cyan — indicates scheduler bouncing
            mig_str = (f"[bold cyan]{info.migration_freq:5.1f}[/]"
                       if info.migration_freq > 10.0
                       else f"{info.migration_freq:5.1f}")

            _row = [
                str(info.pid),
                info.comm[:18],
                cpu_str,
                f"{info.rss_mb:6.1f}",
                str(info.threads),
                f"{info.ipc:.2f}",
                f"{info.llc_miss*100:.3f}",
                f"{info.ctx_freq:,.0f}",
                io_str,
                io_wait_str,
                rq_wait_str,
                mig_str,
                f"[{color}]{label}[/]",
            ]
            if has_per_core:
                _row.append(str(info.cpu_id) if info.cpu_id >= 0 else "agg")
            table.add_row(*_row)

        total = len(self.state)
        active = len(rows)
        zero_note = "" if self.show_zero else f"  [dim]({total - active} idle hidden, -z to show)[/]"
        return Panel(
            table,
            title="[bold]Workload-Aware Linux Resource Monitor[/]",
            subtitle=f"[dim]{active} active / {total} total{zero_note}  |  sort:{self.sort_by}  |  Ctrl+C to exit[/]",
            border_style="cyan",
        )


# ── Entry point ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--top",      type=int,   default=20)
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--sort",     default="cpu",
                        choices=["cpu", "mem", "ipc"])
    parser.add_argument("--zero", "-z", action="store_true",
                        help="Show idle/zero-value processes (hidden by default)")
    args = parser.parse_args()

    console = Console()

    if not os.path.exists(SHM_PATH):
        console.print(f"[yellow]Waiting for {SHM_PATH} ...[/]")
        console.print("[dim]Check: sudo systemctl status schedmon[/]")

    if not os.path.exists(_CONF_PATH):
        console.print("[yellow]No calibration file. Using default thresholds.[/]")
        console.print("[dim]Run: sudo python3 calibrate.py  to calibrate[/]")
        time.sleep(2)

    dash = Dashboard(args.top, args.interval, args.sort, show_zero=args.zero)

    with Live(console=console, refresh_per_second=1, screen=True) as live:
        try:
            while True:
                dash.update()
                live.update(dash.make_table())
                time.sleep(args.interval)
        except KeyboardInterrupt:
            pass

    console.print("[cyan]Dashboard stopped.[/]")


if __name__ == "__main__":
    main()
