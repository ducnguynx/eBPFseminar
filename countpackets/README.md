# countpackets
An XDP eBPF program to count how many Wi-Fi packets have arrived in 10 seconds
## Dependencies
Working with 5.15 & upstream mainline kernel
### My setup
[Ubuntu 22.04 LTS Desktop Image](https://releases.ubuntu.com/jammy/)  
[VMware Workstation 17 pro](https://blogs.vmware.com/workstation/2024/05/vmware-workstation-pro-now-available-free-for-personal-use.html)  
### Needed packages
[airmon-ng](https://github.com/aircrack-ng/aircrack-ng) for getting your Wi-Fi NIC to Monitor Mode  
Build dependencies  
```
sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
  libllvm14 llvm-14-dev libclang-14-dev python3 zlib1g-dev libelf-dev libfl-dev python3-setuptools \
  liblzma-dev libdebuginfod-dev arping netperf iperf
```
[libbpf](https://github.com/libbpf/libbpf) & [bpftool](https://github.com/libbpf/bpftool)  
[BCC framework](https://github.com/iovisor/bcc/blob/master/INSTALL.md). BUILD IT FROM SOURCE TO AVOID BUGS. Actually there are many ways to get the system up and running, but I prefer install BCC framework for simplicity

## Usage
Every machine have different radio tap header length, make sure to change what fit yours in hello.bpf.c file  
Different NIC have different name, use iwconfig and change to yours in start.sh files  
Remember to bring your NIC to monitor mode by
```
sudo airmon-ng start "your NIC name"
```
In your terminal
```python

# build the project
sudo make
# start capturing
sudo ./start.sh
# in a new terminal, execute this command to see how many packets have arrived
sudo ./see.sh
```
## Contributing
This project is maintained by me & @PhamDuong1311, checking out his [github](https://github.com/PhamDuong1311)  
Please make sure to update tests as appropriate.

## License
This work is dual-licensed under BSD 2-clause license and GNU LGPL v2.1 license.
You can choose between one of them if you use this work.
`SPDX-License-Identifier: BSD-2-Clause OR LGPL-2.1`
