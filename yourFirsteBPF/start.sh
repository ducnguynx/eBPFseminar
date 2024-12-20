bpftool prog load yourFirsteBPF.bpf.o /sys/fs/bpf/yourFirsteBPF
bpftool net attach xdp pinned /sys/fs/bpf/yourFirsteBPF dev ens33
sudo cat /sys/kernel/debug/tracing/trace_pipe
