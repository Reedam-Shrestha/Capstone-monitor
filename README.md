# schedmon — Real-Time Performance Monitoring Daemon

A low-overhead Linux performance monitoring daemon that collects hardware
performance counters and kernel-traced software events per process, smooths
them over a 500ms sliding window, and exports metrics via three lock-free
shared-memory ring buffers for workload classification and scheduler selection.

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
                                  │  │     3 Ring Buffers       │   │
                                  │  │  /monitor_rb        (agg)│   │
                                  │  │  /monitor_rb_dash   (all)│   │
                                  │  │  /monitor_rb_sched  (pc) │   │
                                  │  └────────────┬─────────────┘   │
                                  └───────────────┼─────────────────┘
                                                  │
             ┌────────────────────────────────────┼──────────────────────┐
             │                                    │                      │
  ┌──────────▼──────┐                  ┌──────────▼───────┐    ┌────────▼──────┐
  │   Classifier    │                  │    Dashboard     │    │  ghOSt Agent  │
  │  (reads /agg)   │                  │  (reads /all)    │    │ (reads /pc)   │
  └─────────────────┘                  └──────────────────┘    └───────────────┘
```

---

## Metrics Collected (ABI v4)

Each ring buffer slot is a `SmoothedMetrics` struct (72 bytes, 8-byte aligned):

| Field | Source | Description |
|---|---|---|
| `smoothed_ipc` | perf PMU | Instructions per cycle (500ms window) |
| `smoothed_llc_miss` | perf PMU | LLC miss rate as fraction of instructions |
| `smoothed_ctx_freq` | eBPF sched_switch | Voluntary context switches/sec |
| `smoothed_io_freq` | /proc/PID/io | Disk bytes/sec (read + write − cancelled) |
| `smoothed_io_wait_ms` | eBPF block_rq | Avg block I/O latency ms (direct I/O) |
| `smoothed_rq_wait_ms` | eBPF sched_wakeup | Avg runqueue wait ms per wakeup |
| `smoothed_migration_freq` | eBPF pid_last_cpu | Core migrations/sec |

`smoothed_migration_freq` is the primary signal for scheduler instability —
high values mean the process is being bounced across cores, destroying cache
locality. Does not require per-core perf fds; works with `--no-per-core`.

---

## Ring Buffers

| Path | Consumers | Contents |
|---|---|---|
| `/dev/shm/monitor_rb` | Classifier | Aggregate only (`cpu_id == -1`) |
| `/dev/shm/monitor_rb_dash` | Dashboard | Aggregate + per-core |
| `/dev/shm/monitor_rb_sched` | ghOSt agent | Per-core only (`cpu_id >= 0`) |

Capacity: 32768 slots each. Lock-free SPSC. Slots are 72 bytes.
Classifier should only read `/monitor_rb`.

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
| `--no-per-core` | Disable per-core counters (use on VMs without hardware PMU) |
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
├── src/
│   ├── schedmon.c            # Main daemon
│   ├── schedmon.h            # PidState, DaemonConfig, constants
│   ├── smoothed_metrics.h    # SmoothedMetrics struct (ABI v4, 72 bytes)
│   ├── perf_counter.c/h      # perf_event_open wrapper
│   ├── ebpf_tracer.c/h       # libbpf wrapper + BPF map readers
│   ├── proc_scanner.c/h      # /proc PID scanner and CPU ranker
│   ├── ring_buffer.c/h       # Lock-free SPSC ring buffer (3 instances)
│   └── sliding_window.c/h    # N=10 sample sliding window (SWAG, 500ms)
└── bpf/
    └── ctx_switch.bpf.c      # eBPF: sched, block I/O, fork/exit tracepoints
```

---

## For Classifier / ghOSt Consumers

Include `smoothed_metrics.h` and check ABI at compile time:

```c
#include "smoothed_metrics.h"
_Static_assert(MONITOR_ABI_VERSION == 4, "recompile against updated smoothed_metrics.h");
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

`cpu_id == -1` means aggregate entry (what the classifier should use).
`cpu_id >= 0` means per-core entry (for ghOSt agent via `/monitor_rb_sched`).

---

## Uninstall

```bash
sudo systemctl disable --now schedmon
sudo rm -rf /opt/schedmon
sudo rm /etc/systemd/system/schedmon.service
sudo systemctl daemon-reload
```
