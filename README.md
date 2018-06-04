# Rustwall

Network firewall for seL4, written in Rust.

The firewall itself is meant to replace [this Camkes firewall component](https://github.com/seL4/camkes-vm/blob/master/components/Firewall/src/firewall.c). 

Rustwall uses (currenlt a modified version of) [smoltcp](https://github.com/podhrmic/smoltcp/tree/sel4) as its network stack. The hope is to eventually merge the changes into the upstream.

## Architecture
![Architecture](https://www.lucidchart.com/publicSegments/view/0e227a9e-cf7c-463b-bdc2-9c20ee692e59/image.png)

## Deployment
To be used in a true seL4 environment, Rustwall has to be compiled using [rust-camkes](https://github.com/aisamanra/rust-camkes-samples). This is currently work in progress, more info will follow.
