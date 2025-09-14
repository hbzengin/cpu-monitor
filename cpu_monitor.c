#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_legacy.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#define NUM_MAP_ENTRIES (4096)
#define NANOSECONDS_IN_S (1000000000)
#define NANOSECONDS_IN_MS (1000000)

typedef struct process_usage {
  __u32 id;
  __u64 total_time;
  __u64 delta_time;
} process_usage;

int cmp_process_usage(const void *a, const void *b) {
  const process_usage *x = a;
  const process_usage *y = b;

  if (x->delta_time > y->delta_time)
    return -1;
  if (x->delta_time < y->delta_time)
    return 1;
  if (x->total_time > y->total_time) {
    return -1;
  }
  if (x->total_time < y->total_time) {
    return 1;
  }
  return 0;
}

// Might be a better way to get cpus instead of nprocs?
int get_cpu_count() { return libbpf_num_possible_cpus(); }

__u64 roundup(__u64 num_to_round, __u64 multiple) { return ((num_to_round + multiple - 1) / multiple) * multiple; }

// todo: in the next version use skeletons and learn how they work
int main() {
  struct bpf_object *obj;
  struct bpf_program *prog;
  struct bpf_link *link;

  fprintf(stderr, "Loading BPF code in memory\n");
  obj = bpf_object__open_file("cpu_monitor.bpf.o", NULL);

  if (libbpf_get_error(obj)) {
    fprintf(stderr, "ERROR: opening BPF object file failed\n");
    return 1;
  }

  fprintf(stderr, "Loading and verifying the code in the kernel\n");
  if (bpf_object__load(obj)) {
    fprintf(stderr, "ERROR: loading BPF object file failed\n");
    return 1;
  }

  fprintf(stderr, "Attaching BPF program to tracepoint\n");
  prog = bpf_object__find_program_by_name(obj, "cpu_monitor");
  if (libbpf_get_error(prog)) {
    fprintf(stderr, "ERROR: finding BPF program failed\n");
    return 1;
  }

  link = bpf_program__attach_tracepoint(prog, "sched", "sched_switch");

  if (libbpf_get_error(link)) {
    fprintf(stderr, "ERROR: Attaching BPF program to tracepoint failed\n");
    return 1;
  }

  struct bpf_map *process_time_map;
  struct bpf_map *idle_time_map;

  process_time_map = bpf_object__find_map_by_name(obj, "process_total_time");
  idle_time_map = bpf_object__find_map_by_name(obj, "idle_total_time");

  if (libbpf_get_error(process_time_map) || libbpf_get_error(idle_time_map)) {
    fprintf(stderr, "ERROR: finding BPF map failed\n");
    return 1;
  }

  int process_time_map_fd = bpf_map__fd(process_time_map);
  int idle_time_map_fd = bpf_map__fd(idle_time_map);

  int num_cpus = get_cpu_count();
  __u64 *process_vals = (__u64 *)malloc(roundup(sizeof(__u64), 8) * num_cpus);
  __u64 *idle_vals = (__u64 *)malloc(roundup(sizeof(__u64), 8) * num_cpus);

  process_usage *results = malloc(NUM_MAP_ENTRIES * sizeof(process_usage));
  process_usage *prev_results = calloc(NUM_MAP_ENTRIES, sizeof(process_usage));

  int prev_count = 0;

  while (1) {
    sleep(10);

    __u32 *curr_key = NULL;
    __u32 next_key;
    int count = 0;

    __u32 key0 = 0;
    __u64 idle_total = 0;
    if (bpf_map_lookup_elem(idle_time_map_fd, &key0, idle_vals) == 0) {
      for (int i = 0; i < num_cpus; i++) {
        idle_total += idle_vals[i];
      }
    }

    while (bpf_map_get_next_key(process_time_map_fd, curr_key, &next_key) == 0) {
      bpf_map_lookup_elem(process_time_map_fd, &next_key, process_vals);

      // this is total time taken in ns by this pid
      __u64 total = 0;
      for (int i = 0; i < num_cpus; i++) {
        total += process_vals[i];
      }

      results[count].id = next_key;
      results[count].total_time = total;

      bool found = false;
      // find delta time
      for (int i = 0; i < prev_count; i++) {
        if (prev_results[i].id == next_key) {
          results[count].delta_time = total - prev_results[i].total_time;
          found = true;
          break;
        }
      }

      if (!found) {
        results[count].delta_time = total - 0;
      }

      count++;
      curr_key = &next_key;
    }
    prev_count = count;

    qsort(results, count, sizeof(process_usage), cmp_process_usage);
    memcpy(prev_results, results, count * sizeof(process_usage));

    int num_to_render = count;
    printf("--------------------- START ---------------------\n");
    printf("--- Top %d processes that take CPU time ---\n", num_to_render);
    printf("-------------------------------------------------\n");
    for (int i = 0; i < count; i++) {
      printf("Pid: %u, delta processor time %llu ms, total processor time %llu ms\n", results[i].id, results[i].delta_time / NANOSECONDS_IN_MS,
             results[i].total_time / NANOSECONDS_IN_MS);
    }
    printf("-------------------------------------------------\n");
    printf("-------- Total idle time %llu ms --------\n", idle_total / NANOSECONDS_IN_MS);
    printf("-------------------------------------------------\n");
  }

  free(process_vals);
  free(idle_vals);
  bpf_link__destroy(link);
  bpf_object__close(obj);

  return 0;
}