#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <linux/bpf_common.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// global map per thread because threads can execute on different cores
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);   // thread id
  __type(value, u64); // last start in ns
  __uint(max_entries, 4096);
} thread_last_start SEC(".maps");

// per cpu map because there might exist > 1 thread per process
// each tgid (thread group id) == process id
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, u32);   // thread group id (process id)
  __type(value, u64); // total nanoseconds of tgid on that cpu
  __uint(max_entries, 4096);
} process_total_time SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, u64); // last idle start
} idle_last_start SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, u64); // total idle time
} idle_total_time SEC(".maps");

// tgid = process id
// pid = thread id
SEC("tracepoint/cpu_monitor")
int cpu_monitor(struct trace_event_raw_sched_switch *ctx) {
  u64 now = bpf_ktime_get_ns();
  u32 next_pid = (u32)ctx->next_pid;
  u32 prev_pid = (u32)ctx->prev_pid;

  // Extra code for accounting for idle time
  u32 idx = 0;

  // If we're ABOUT TO GO IDLE on this CPU, remember the start time
  if (next_pid == 0) {
    bpf_map_update_elem(&idle_last_start, &idx, &now, BPF_ANY);
  }

  // If we're LEAVING IDLE on this CPU add delta time to idle_time
  if (prev_pid == 0) {
    u64 *start = bpf_map_lookup_elem(&idle_last_start, &idx);
    if (start) {
      u64 delta = now - *start;
      u64 *tot = bpf_map_lookup_elem(&idle_total_time, &idx);
      if (tot)
        *tot += delta;
    }
  }

  // 1) Always record next start if not idle
  if (next_pid != 0) {
    bpf_map_update_elem(&thread_last_start, &next_pid, &now, BPF_ANY);
  }

  // 2) Skip accounting if previously idle
  if (prev_pid == 0) {
    return 0;
  }

  // Here this should correspond to prev_pid
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = (u32)id;
  u32 tgid = (u32)(id >> 32);

  // Sanity check
  if (pid != ctx->prev_pid) {
    bpf_printk("this mustn't have happened! pid doesnt match context pid. "
               "pid=%d, ctx->prev_pid=%d\n",
               pid, ctx->prev_pid);
    return 0;
  }

  u64 *start = bpf_map_lookup_elem(&thread_last_start, &pid);
  // Only process if start exists in map, meaning start was actually recorded
  // For example it might not exist if cpu_monitor started running after
  // the process it's recording started running
  if (start) {
    u64 delta = now - (*start);

    // If first write, then create the entry in the hash map
    u64 zero = 0;
    bpf_map_update_elem(&process_total_time, &tgid, &zero, BPF_NOEXIST);

    // Update time
    u64 *time = bpf_map_lookup_elem(&process_total_time, &tgid);

    // extra cautious
    if (time) {
      (*time) += delta;
    }
  }

  return 0;
}
