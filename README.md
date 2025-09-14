# CPU Time Monitor using eBPF

This is a CPU time monitoring tool that uses eBPF (extended Berkeley Packet Filter) to track CPU usage by processes in real-time. The monitor attaches to the kernel's scheduler tracepoint to collect CPU time statistics for all running processes and displays the top CPU consumers.

## TLDR

- Tracks CPU time usage per process using eBPF and sorts by delta time and total time
- Monitors both active process time and processors' idle time
- Can adjust the periods of sampling by changing code (default 10-second intervals)
- Uses kernel tracepoints for efficient, low-overhead monitoring

## Prerequisites

- Linux system with eBPF support (this was built on a Debian Linux server)
- `bpftool` utility installed
- `libbpf` development libraries
- `clang` compiler
- Root/sudo privileges (required to load eBPF programs into the kernel)

## Usage

1. **Generate the kernel headers file:**
   ```bash
   make vmlinux.h
   ```
   This creates `vmlinux.h` containing kernel data structure definitions needed for eBPF compilation.

2. **Compile the eBPF program and userspace application:**
   ```bash
   make
   ```
   This compiles both the eBPF kernel program (`cpu_monitor.bpf.c`) and the userspace loader (`cpu_monitor.c`).

3. **Run the CPU monitor:**
   ```bash
   sudo ./cpu_monitor.out
   ```
   The program requires root privileges to load eBPF programs into the kernel.

## Output

The monitor displays:
- Process ID (PID)
- Delta processor time (CPU time used since last measurement)
- Total processor time (cumulative CPU time since monitoring started)
- System idle time

Example output:
```
--------------------- START ---------------------
--- Top N processes that take CPU time ---
-------------------------------------------------
Pid: 1234, delta processor time 150 ms, total processor time 2500 ms
Pid: 5678, delta processor time 80 ms, total processor time 1200 ms
...
-------------------------------------------------
-------- Total idle time 8500 ms --------
-------------------------------------------------
```

The repo includes two example output files (`heavy-load.out` and `light-load.out`) showing sample monitoring results under heavy and light loads on my own Debian Linux server. You can simulate CPU load using the `stress-ng` tool, e.g.:
```bash
stress-ng --cpu 4 --timeout 60s  # 4 CPU cores for 60 seconds
```

You can see the number of CPU cores your machine has with:
```bash
nproc
```

## How It Works

The eBPF program attaches to the `sched:sched_switch` tracepoint, which triggers whenever the kernel scheduler switches between processes. The userspace program periodically reads the collected data from eBPF maps and displays the results sorted by CPU usage.

## Cleanup

To remove generated files:
```bash
make clean      # Remove binaries
make cleanall   # Remove binaries and vmlinux.h
```

## Acknowledgments

I took the Makefile and some eBPF boilerplate from Columbia University's [EECS6891E Extensible Operating Systems course tutorial](https://github.com/tengjiang/eBPF-Tutorial).