.. _kernel-interface:

****************
Kernel Interface
****************

There are several different methods for reading kernel routing table
information, updating kernel routing tables, and for looking up interfaces.
FRR relies heavily on the Netlink (``man 7 netlink``) interface to
communicate with the Kernel. However, other interfaces are still used
in some parts of the code.

- ioctl
     This method is a very traditional way for reading or writing kernel
     information. `ioctl` can be used for looking up interfaces and for
     modifying interface addresses, flags, mtu settings and other types of
     information. Also, `ioctl` can insert and delete kernel routing table
     entries. It will soon be available on almost any platform which zebra
     supports, but it is a little bit ugly thus far, so if a better method is
     supported by the kernel, zebra will use that.

- sysctl
     This is a program that can lookup kernel information using MIB (Management
     Information Base) syntax. Normally, it only provides a way of getting
     information from the kernel. So one would usually want to change kernel
     information using another method such as `ioctl`.

- proc filesystem
     This is a special filesystem mount that provides an easy way of getting
     kernel information.

- routing socket / Netlink
     Netlink first appeard in Linux kernel 2.0. It makes asynchronous
     communication between the kernel and FRR possible, similar to a routing
     socket on BSD systems. Netlink communication is done by reading/writing
     over Netlink socket.
