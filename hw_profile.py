"""
hw_profile.py 
Both calibrate.py (hardware-fallback threshold formula, used only when a
workload was skipped or produced too few samples) and dashboard.py (default
thresholds shown before calibrate.py has ever been run) need to guess a
reasonable ipc_cpu_threshold from hardware alone.
"""

import re

# Regex patterns matched against the raw `model name` string from
# /proc/cpuinfo. Real strings include trademark symbols between the brand
# and model number — e.g. "Intel(R) Celeron(R) N4020 CPU @ 1.10GHz" — so
# plain substring checks like "Celeron N" miss the actual target hardware
# for this project. Patterns tolerate that.
_NARROW_ISSUE_PATTERNS = (
    r"(Celeron|Pentium)\b.{0,20}\bN\d{3,4}\b",  # Celeron/Pentium N-series, either brand/model order
    r"Pentium.{0,10}Silver",           # Pentium Silver branding
    r"\bAtom\b",                       # bare Atom-branded parts
    r"\bN(95|100|150|200|250|305)\b",  # Intel Processor N-series SKUs sold without a brand prefix
    r"Snapdragon",                     # ARM in-order/little-core mobile SoCs
    r"Cortex-A5\d",                    # ARM Cortex-A53/A55-class little cores
    r"Cortex-A7\b",
)
_NARROW_ISSUE_RE = re.compile("|".join(_NARROW_ISSUE_PATTERNS), re.IGNORECASE)

# Conservative IPC ceiling to use as a threshold when no calibration data exists
# not a substitute for calibration.
NARROW_ISSUE_IPC_CEILING = 0.5


def read_cpu_model() -> str:
    """Read `model name` from /proc/cpuinfo. Returns '' if unavailable."""
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return ""


def is_narrow_issue_cpu(model_str: str) -> bool:
    """
    Return True if model_str matches a known narrow-issue / low-power core
    family (Atom-derived Intel N/J-series, ARM little cores, etc.) where a
    core-count-scaled IPC threshold would be wrong.
    """
    if not model_str:
        return False
    return bool(_NARROW_ISSUE_RE.search(model_str))


def hw_ipc_cpu_fallback(cores: int, cpu_model: str) -> float:
    """
    Hardware-only fallback for ipc_cpu_threshold, used by calibrate.py when
    the CPU or MEM calibration workload was skipped or produced too few
    samples. Prefer real calibration data over this whenever available —
    this exists only to avoid an unreachable threshold in its absence.
    """
    if is_narrow_issue_cpu(cpu_model):
        return NARROW_ISSUE_IPC_CEILING

    # linear interpolation

    thresh = 1.2 + max(0, (cores - 2)) * 0.1333
    return min(thresh, 3.0)
