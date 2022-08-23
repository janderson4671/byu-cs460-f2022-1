# Hands-On with Cougarnet

The objective of this assignment is to familiarize you with the Cougarnet
framework, which will be used for completing your lab assignments for this
class.


# Installation

Use the following commands to install the build and run-time dependencies for
Cougarnet:

```bash
$ sudo apt install git python3-setuptools
$ sudo apt install openvswitch-switch tmux lxterminal python3-pygraphviz libgraph-easy-perl tcpdump wireshark socat
```

Clone the Cougarnet repository, then build and install it:

```bash
$ git clone https://github.com/cdeccio/cougarnet/
$ cd cougarnet
$ python3 setup.py build
$ sudo python3 setup.py install
```


# Exercises

1. Complete the four
   [Working Examples](https://github.com/cdeccio/cougarnet/blob/main/README.md#working-examples)

2. Look through the
   [Cougarnet documentation](https://github.com/cdeccio/cougarnet/blob/main/README.md).
   While much of it might not make sense just yet, you will be referring back
   to this as you do the labs.
