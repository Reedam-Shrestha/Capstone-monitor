CC     = gcc
CLANG  = clang
CFLAGS = -Wall -Wextra -O2 -std=c11 -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -Isrc
LDFLAGS = -lbpf -lelf -lz -lrt

# Arch-independent BPF include path — works on x86_64 and aarch64
BPF_CFLAGS = -O2 -g -target bpf \
             -I/usr/include/$(shell uname -m)-linux-gnu

SRCS = src/schedmon.c \
       src/proc_scanner.c \
       src/perf_counter.c \
       src/ebpf_tracer.c \
       src/sliding_window.c \
       src/ring_buffer.c

HDRS = src/schedmon.h \
       src/proc_scanner.h \
       src/perf_counter.h \
       src/ebpf_tracer.h \
       src/sliding_window.h \
       src/ring_buffer.h \
       src/smoothed_metrics.h

.PHONY: all clean bpf install

all: bpf schedmon

bpf:
	$(CLANG) $(BPF_CFLAGS) -c bpf/ctx_switch.bpf.c -o bpf/ctx_switch.bpf.o

# Headers listed as dependency so 'make' rebuilds on any header change
schedmon: $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

# Install to /opt/schedmon for systemd service
install: all
	install -d /opt/schedmon/bpf
	install -m 755 schedmon          /opt/schedmon/
	install -m 644 bpf/ctx_switch.bpf.o /opt/schedmon/bpf/
	install -m 755 dashboard.py      /opt/schedmon/
	install -m 755 calibrate.py      /opt/schedmon/

clean:
	rm -f schedmon bpf/ctx_switch.bpf.o
