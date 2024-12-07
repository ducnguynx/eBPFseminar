#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "data_t.h"

char message_default[30] = "Other user";
char message_root[30] = "Root user (UID = 0)";
char message_duc[30] = "Default user (UID = 1000)";
char message_one[30] = "Daemon user (UID = 1)";
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output SEC(".maps");

struct user_msg_t {
   char message[30];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct user_msg_t);
} my_config SEC(".maps");

SEC("ksyscall/execve")
int BPF_KPROBE_SYSCALL(hello, const char *pathname)
{
   u32 pid_root = 0;
   bpf_map_update_elem(&my_config, &pid_root, &message_root, BPF_ANY);
   u32 pid_duc = 1000;
   bpf_map_update_elem(&my_config, &pid_duc, &message_duc, BPF_ANY);
   u32 pid_one = 1;
   bpf_map_update_elem(&my_config, &pid_one, &message_one, BPF_ANY);
   struct data_t data = {}; 
   struct user_msg_t *p;

   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   bpf_get_current_comm(&data.command, sizeof(data.command));
   bpf_probe_read_user_str(&data.path, sizeof(data.path), pathname);

   p = bpf_map_lookup_elem(&my_config, &data.uid);
   if (p != 0) {
      bpf_probe_read_kernel_str(&data.message, sizeof(data.message), p->message);
   } else {
      bpf_probe_read_kernel_str(&data.message, sizeof(data.message), message_default); 
   }

   bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));   
   return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
