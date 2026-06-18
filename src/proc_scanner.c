#define _POSIX_C_SOURCE 200809L

#include "proc_scanner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <stdint.h>

/* ── Fast String Parser ────────────────────────────────────────────────── */
/* Replaces sscanf by quickly jumping over space-separated fields */
static inline const char* skip_fields(const char* p, int count) {
    for (int i = 0; i < count; i++) {
        while (*p && *p != ' ') p++; /* Skip word */
        while (*p && *p == ' ') p++; /* Skip spaces */
    }
    return p;
}

/* ── Read /proc/PID/stat ───────────────────────────────────────────────── */
/* Optimization: only fetch comm if the process is newly discovered */
static int read_proc_stat(int pid, ProcEntry *out, int fetch_comm) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[512];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    fclose(f);

    char *comm_start = strchr(line, '(');
    char *comm_end   = strrchr(line, ')');
    if (!comm_start || !comm_end) return -1;

    if (fetch_comm) {
        int comm_len = (int)(comm_end - comm_start - 1);
        if (comm_len > 15) comm_len = 15;
        snprintf(out->comm, sizeof(out->comm), "%.*s", comm_len, comm_start + 1);
        out->comm[comm_len] = '\0';
    }

    /* Jump 11 fields past the 'state' field to reach utime (field 14) */
    const char *rest = comm_end + 2; 
    rest = skip_fields(rest, 11);

    /* Fast parse utime and stime */
    char *next = NULL;
    out->utime = strtoul(rest, &next, 10);
    if (next) {
        out->stime = strtoul(next, NULL, 10);
    } else {
        out->stime = 0;
    }

    out->pid = pid;
    out->total_ticks = out->utime + out->stime;
    return 0;
}

static int read_proc_uid(int pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[128];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            /* Fast parse UID */
            const char *p = line + 4;
            while (*p && isspace(*p)) p++;
            int uid = atoi(p);
            fclose(f);
            return uid;
        }
    }
    fclose(f);
    return -1;
}

static ProcEntry *find_or_alloc(ProcScanner *ps, int pid, int *is_new) {
    for (int i = 0; i < ps->n_entries; i++) {
        if (ps->entries[i].pid == pid) {
            *is_new = 0;
            return &ps->entries[i];
        }
    }

    if (ps->n_entries >= PROC_MAX_TRACKED) return NULL;
    ProcEntry *e = &ps->entries[ps->n_entries++];
    memset(e, 0, sizeof(*e));
    e->pid = pid;
    e->uid = -1;   /* sentinel: not yet read; 0 is valid (root) */
    *is_new = 1;
    return e;
}

void proc_scanner_init(ProcScanner *ps) {
    memset(ps, 0, sizeof(*ps));
}

/* ── proc_scanner_scan_pids (NEW: eBPF optimized) ──────────────────────── */
void proc_scanner_scan_pids(ProcScanner *ps, const uint32_t *pids, int num_pids) {
    for (int i = 0; i < ps->n_entries; i++)
        ps->entries[i].active = 0;

    for (int i = 0; i < num_pids; i++) {
        int pid = (int)pids[i];
        if (pid <= 1) continue;

        int is_new = 0;
        ProcEntry *e = find_or_alloc(ps, pid, &is_new);
        if (!e) continue;

        ProcEntry tmp;
        if (read_proc_stat(pid, &tmp, is_new) != 0) continue;

        if (is_new) {
            snprintf(e->comm, sizeof(e->comm), "%s", tmp.comm);
            e->prev_ticks = tmp.total_ticks;
        } else {
            e->prev_ticks = e->total_ticks;
        }

        e->utime        = tmp.utime;
        e->stime        = tmp.stime;
        e->total_ticks  = tmp.total_ticks;
        e->delta_ticks  = (tmp.total_ticks > e->prev_ticks) ? tmp.total_ticks - e->prev_ticks : 0;
        e->active       = 1;

        if (e->uid == -1 && pid > 1)
            e->uid = read_proc_uid(pid);
    }

    int w = 0;
    for (int i = 0; i < ps->n_entries; i++) {
        if (ps->entries[i].active)
            ps->entries[w++] = ps->entries[i];
    }
    ps->n_entries = w;
    ps->scan_count++;
}

/* ── proc_scanner_scan (Fallback directory scan) ───────────────────────── */
void proc_scanner_scan(ProcScanner *ps) {
    for (int i = 0; i < ps->n_entries; i++)
        ps->entries[i].active = 0;

    DIR *dir = opendir("/proc");
    if (!dir) return;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (!isdigit(ent->d_name[0])) continue;
        int pid = atoi(ent->d_name);
        if (pid <= 1) continue;

        int is_new = 0;
        ProcEntry *e = find_or_alloc(ps, pid, &is_new);
        if (!e) continue;

        ProcEntry tmp;
        if (read_proc_stat(pid, &tmp, is_new) != 0) continue;

        if (is_new) {
            snprintf(e->comm, sizeof(e->comm), "%s", tmp.comm);
            e->prev_ticks = tmp.total_ticks;
        } else {
            e->prev_ticks = e->total_ticks;
        }

        e->utime        = tmp.utime;
        e->stime        = tmp.stime;
        e->total_ticks  = tmp.total_ticks;
        e->delta_ticks  = (tmp.total_ticks > e->prev_ticks) ? tmp.total_ticks - e->prev_ticks : 0;
        e->active       = 1;

        if (e->uid == -1 && pid > 1)
            e->uid = read_proc_uid(pid);
    }
    closedir(dir);

    int w = 0;
    for (int i = 0; i < ps->n_entries; i++) {
        if (ps->entries[i].active)
            ps->entries[w++] = ps->entries[i];
    }
    ps->n_entries = w;
    ps->scan_count++;
}

static int cmp_delta_desc(const void *a, const void *b) {
    const ProcEntry *pa = (const ProcEntry *)a;
    const ProcEntry *pb = (const ProcEntry *)b;
    if (pb->delta_ticks > pa->delta_ticks) return  1;
    if (pb->delta_ticks < pa->delta_ticks) return -1;
    return 0;
}

int proc_scanner_top_n(const ProcScanner *ps, int *pids, int n, int min_uid) {
    if (ps->n_entries == 0) return 0;

    ProcEntry sorted[PROC_MAX_TRACKED];
    int count = 0;
    for (int i = 0; i < ps->n_entries; i++) {
        if (!ps->entries[i].active) continue;
        if (ps->entries[i].uid >= 0 && ps->entries[i].uid < min_uid) continue;
        sorted[count++] = ps->entries[i];
    }

    qsort(sorted, count, sizeof(ProcEntry), cmp_delta_desc);

    int written = 0;
    for (int i = 0; i < count && written < n; i++)
        pids[written++] = sorted[i].pid;

    return written;
}

void proc_scanner_print(const ProcScanner *ps, int n) {
    ProcEntry sorted[PROC_MAX_TRACKED];
    int count = 0;
    for (int i = 0; i < ps->n_entries && i < PROC_MAX_TRACKED; i++)
        sorted[count++] = ps->entries[i];
    qsort(sorted, count, sizeof(ProcEntry), cmp_delta_desc);

    printf("  %-8s  %-16s  %-10s  %-6s\n", "PID", "COMM", "CPU_TICKS", "UID");
    for (int i = 0; i < count && i < n; i++)
        printf("  %-8d  %-16s  %-10lu  %-6d\n",
               sorted[i].pid, sorted[i].comm,
               (unsigned long)sorted[i].delta_ticks,
               sorted[i].uid);
}
