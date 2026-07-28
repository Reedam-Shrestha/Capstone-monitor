# schedmon — Real-Time Performance Monitoring Daemon

A low-overhead Linux performance monitoring daemon that collects hardware
performance counters and kernel-traced software events per process, smooths
them over a 500ms sliding window, and exports metrics via two lock-free
shared-memory ring buffers for workload classification.

Part of the **"Workload-Aware Linux Resource Management Framework"** capstone project.

---

## Architecture

```
┌─────────────┐  perf_event_open  ┌─────────────────────────────────┐
│  Linux PMU  │◄──────────────────│           schedmon              │
│  eBPF progs │◄── bpf() syscall ─│          (C daemon)             │
└─────────────┘                   │                                 │
                                  │  perf counters → SlidingWindow  │
                                  │  eBPF maps     → SlidingWindow  │
                                  │  /proc/PID/io  → SlidingWindow  │
                                  │                                 │
                                  │  ┌──────────────────────────┐   │
                                  │  │     2 Ring Buffers       │   │
                                  │  │  /monitor_rb        (agg)│   │
                                  │  │  /monitor_rb_dash   (agg)│   │
                                  │  └────────────┬─────────────┘   │
                                  └───────────────┼─────────────────┘
                                                  │
                        ┌─────────────────────────┴───────────────────┐
                        │                                              │
             ┌──────────▼──────┐                              ┌───────▼──────────┐
             │   Classifier    │                              │    Dashboard     │
             │  (reads /agg)   │                              │  (reads /agg)    │
             └────────┬────────┘                              └──────────────────┘
                      │ writes BPF map (e.g. scx_mem_class)
             ┌────────▼────────┐
             │  sched_ext (scx)│
             │  scheduler      │
             │  (scx_rr/mem/   │
             │   io/fair/cpu)  │
             └─────────────────┘
```

The scx scheduler agent is **not** a direct consumer of schedmon's ring
buffers — it reads a BPF map (e.g. `scx_mem_class`, keyed by task pid/tid)
that the classifier writes after reading schedmon's aggregate buffer.
schedmon → classifier → scx scheduler is a pipeline, not a fan-out.

Per-core monitoring and its dedicated ring buffer were removed: none of the
five sched_ext schedulers this project targets (`scx_rr`, `scx_mem`,
`scx_io`, `scx_fair`, `scx_cpu`) read per-core data — every one dispatches
from a single shared (or, for `scx_mem`, two-class) DSQ using
`scx_bpf_dsq_move_to_local()`. The `cpu_id` field remains in the wire
format (always `-1`, i.e. aggregate) so per-core collection could be
reintroduced without another ABI bump if a future scheduler needs it.

---

## Metrics Collected (ABI v5)

Each ring buffer slot is a `SmoothedMetrics` struct (88 bytes, 8-byte aligned):

| Field | Source | Description |
|---|---|---|
| `hw_pmu_available` | perf_event_open() result | 1=hardware PMU counters, 0=software-clock fallback |
| `smoothed_ipc` | perf PMU | Instructions per cycle (500ms window); **only valid when `hw_pmu_available == 1`** |
| `smoothed_llc_miss` | perf PMU | LLC miss rate as fraction of instructions; **only valid when `hw_pmu_available == 1`** |
| `smoothed_ctx_freq` | eBPF sched_switch | Voluntary context switches/sec |
| `smoothed_io_freq` | /proc/PID/io (`read_bytes`+`write_bytes`) | Physical disk bytes/sec; excludes page-cache hits |
| `smoothed_io_syscall_freq` | /proc/PID/io (`rchar`+`wchar`) | Total read()/write() syscall bytes/sec; **includes** page-cache hits |
| `smoothed_io_wait_ms` | eBPF block_rq | Avg block I/O latency ms (direct I/O) |
| `smoothed_rq_wait_ms` | eBPF sched_wakeup | Avg runqueue wait ms per wakeup |
| `smoothed_migration_freq` | eBPF pid_last_cpu | Core migrations/sec |

`smoothed_migration_freq` is the primary signal for scheduler instability —
high values mean the process is being bounced across cores, destroying cache
locality. Sourced purely from eBPF (pid_last_cpu map), not tied to per-core perf fds.

`hw_pmu_available` exists because a software-clock fallback process reports
`smoothed_ipc`/`smoothed_llc_miss` as `0.0` — the same value a genuinely
idle process reports. Without this field the two cases are indistinguishable
to any consumer. Always check `hw_pmu_available` before using those two
fields; treat them as unknown, not "low", when it is 0.

`smoothed_io_syscall_freq` is deliberately a **separate** field from
`smoothed_io_freq`, not a replacement — they measure different things. A
process reading the same cached file in a tight loop shows high
`smoothed_io_syscall_freq` but near-zero `smoothed_io_freq`; that's expected
and useful, since it distinguishes "moving bytes through syscalls" from
"actually contending for the physical disk". Do not derive one from the
other.

---

## Ring Buffers

| Path | Consumers | Contents |
|---|---|---|
| `/dev/shm/monitor_rb` | Classifier | Aggregate only (`cpu_id == -1`) |
| `/dev/shm/monitor_rb_dash` | Dashboard | Aggregate only (`cpu_id == -1`) |

Capacity: 32768 slots each. Lock-free SPSC. Slots are 88 bytes. Both
buffers carry identical aggregate content on independent tails — the
dashboard's slower, human-visible drain rate never starves the classifier.
There is no per-core buffer (see Architecture above for why).

---

## Quick Install

```bash
git clone https://github.com/Reedam-Shrestha/schedmon.git
cd schedmon
sudo ./install.sh
```

> Builds, installs, calibrates thresholds, and starts the daemon in one command.

---

## Manual Install

### 1. Dependencies

```bash
sudo apt update
sudo apt install -y gcc clang make python3 libbpf-dev libelf-dev zlib1g-dev \
                    linux-headers-$(uname -r) sysbench stress-ng
pip3 install rich
```

### 2. Build

```bash
make clean && make
```

### 3. Install

```bash
sudo make install
sudo cp schedmon.service /etc/systemd/system/
sudo systemctl daemon-reload
```

### 4. Calibrate *(required — derives classifier thresholds for this hardware)*

```bash
sudo python3 /opt/schedmon/calibrate.py --duration 30
```

### 5. Start

```bash
sudo systemctl enable --now schedmon
```

---

## Usage

```bash
# Live dashboard
python3 /opt/schedmon/dashboard.py

# Daemon logs
journalctl -u schedmon -f

# Run manually (stop service first)
sudo systemctl stop schedmon
sudo /opt/schedmon/schedmon /opt/schedmon/bpf/ctx_switch.bpf.o \
    --top 20 --terminal

# Recalibrate after hardware changes
sudo python3 /opt/schedmon/calibrate.py --duration 30
```

---

## CLI Options

| Flag | Description |
|---|---|
| `--top N` | Monitor top N processes by CPU (default: 256 = all) |
| `--pids P1,P2` | Monitor specific PIDs explicitly |
| `--interval MS` | Sample interval ms (default: 50) |
| `--csv FILE` | Write samples to CSV (calibration use) |
| `--label STR` | Workload label written to CSV (for classifier training) |
| `--min-uid UID` | Only monitor processes with uid >= UID (default: 0) |
| `--terminal` | Print live table to stdout |
| `--zero, -z` | Show idle/zero-value processes (hidden by default) |

---

## File Structure

```
schedmon/
├── Makefile
├── schedmon.service          # systemd unit file
├── README.md
├── dashboard.py              # Rich terminal dashboard
├── calibrate.py              # Hardware-adaptive threshold calibration
├── hw_profile.py             # Shared narrow-issue CPU detection (calibrate.py + dashboard.py)
├── src/
│   ├── schedmon.c            # Main daemon
│   ├── schedmon.h            # PidState, DaemonConfig, constants
│   ├── smoothed_metrics.h    # SmoothedMetrics struct (ABI v5, 88 bytes)
│   ├── perf_counter.c/h      # perf_event_open wrapper
│   ├── ebpf_tracer.c/h       # libbpf wrapper + BPF map readers
│   ├── proc_scanner.c/h      # /proc PID scanner and CPU ranker
│   ├── ring_buffer.c/h       # Lock-free SPSC ring buffer (3 instances)
│   └── sliding_window.c/h    # N=10 sample sliding window (SWAG, 500ms)
└── bpf/
    └── ctx_switch.bpf.c      # eBPF: sched, block I/O, fork/exit tracepoints
```

---

## For Classifier Consumers

Include `smoothed_metrics.h` and check ABI at compile time:

```c
#include "smoothed_metrics.h"
_Static_assert(MONITOR_ABI_VERSION == 5, "recompile against updated smoothed_metrics.h");
```

Attach to the ring buffer:

```c
RingBuffer *rb = rb_attach();   // /monitor_rb — aggregate only
SmoothedMetrics m;
while (rb_pop(rb, &m)) {
    // m.smoothed_ipc, m.smoothed_llc_miss, m.smoothed_migration_freq ...
}
rb_detach(rb);
```

`cpu_id` is always `-1` (aggregate) — the field is retained in the wire
format for possible future per-core reintroduction, but no producer
currently emits `cpu_id >= 0`. The scx scheduler agent (see
`scx_rr`/`scx_mem`/`scx_io`/`scx_fair`/`scx_cpu`) is not a ring buffer
consumer at all; it reads a BPF map the classifier writes after classifying
schedmon's output (e.g. `scx_mem_class`), not schedmon's shared memory
directly.

---

## Uninstall

```bash
sudo systemctl disable --now schedmon
sudo rm -rf /opt/schedmon
sudo rm /etc/systemd/system/schedmon.service
sudo systemctl daemon-reload
```