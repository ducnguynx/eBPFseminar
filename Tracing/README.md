# Tracing
An eBPF program that shows information every time execve() system call is made
## Dependencies
Working with 5.15 & upstream mainline kernel
### My setup
[Ubuntu 22.04 LTS Desktop Image](https://releases.ubuntu.com/jammy/)  
[VMware Workstation 17 pro](https://blogs.vmware.com/workstation/2024/05/vmware-workstation-pro-now-available-free-for-personal-use.html)  
### Needed packages
Build dependencies  
```
sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
  libllvm14 llvm-14-dev libclang-14-dev python3 zlib1g-dev libelf-dev libfl-dev python3-setuptools \
  liblzma-dev libdebuginfod-dev arping netperf iperf
```
[libbpf](https://github.com/libbpf/libbpf) & [bpftool](https://github.com/libbpf/bpftool)  
[BCC framework](https://github.com/iovisor/bcc/blob/master/INSTALL.md). BUILD IT FROM SOURCE TO AVOID BUGS. Actually there are many ways to get the system up and running, but I prefer to install BCC framework for simplicity

## Usage
Build the project
```
sudo make
```
Run
```python
sudo ./execveTracing
```
## Contributing
This project is adapted from Liz Rice's example in chapter 5 of [learning eBPF](https://github.com/lizrice/learning-ebpf)
## License
This work is dual-licensed under BSD 2-clause license and GNU LGPL v2.1 license.
You can choose between one of them if you use this work.
`SPDX-License-Identifier: BSD-2-Clause OR LGPL-2.1`
