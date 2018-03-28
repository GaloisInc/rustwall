#!/bin/bash
# To view/change MTU settings of a device:
#  ip link show | grep mtu
#  sudo ip link set tap1 mtu 1500
sudo ip tuntap add dev tap1 mode tap
sudo ip addr add 192.168.69.2/24 broadcast 192.168.69.255 dev tap1
sudo ip link set tap1 up
