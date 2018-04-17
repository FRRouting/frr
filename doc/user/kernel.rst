.. _kernel-interface:

****************
Kernel Interface
****************

There are several different methods for reading kernel routing table
information, updating kernel routing tables, and for looking up interfaces.

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
     On recent Linux kernels (2.0.x and 2.2.x), there is a kernel/user
     communication support called `Netlink`. It makes asynchronous communication
     between kernel and FRR possible, similar to a routing socket on BSD systems.

     Before you use this feature, be sure to select (in kernel configuration) the
     kernel/Netlink support option 'Kernel/User network link driver' and 'Routing
     messages'.

     Today, the :file:`/dev/route` special device file is obsolete.  Netlink
     communication is done by reading/writing over Netlink socket.

     After the kernel configuration, please reconfigure and rebuild FRR.  You can
     use Netlink as a dynamic routing update channel between FRR and the kernel.
