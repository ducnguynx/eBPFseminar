bpftool prog load hello.bpf.o /sys/fs/bpf/hello
bpftool net attach xdp pinned /sys/fs/bpf/hello dev wlx347de44144f6

sleep 10

bpftool net detach xdp dev wlx347de44144f6
rm -f /sys/fs/bpf/hello

