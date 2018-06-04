# Rustwall

Network firewall for seL4, written in Rust.

The firewall itself is meant to replace [this Camkes firewall component](https://github.com/seL4/camkes-vm/blob/master/components/Firewall/src/firewall.c). 

Rustwall uses (currenlt a modified version of) [smoltcp](https://github.com/GaloisInc/smoltcp/tree/firewall) as its network stack. 
