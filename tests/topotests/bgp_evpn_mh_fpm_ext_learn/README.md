# EVPN MAC-over-FPM topotest

From `tests/topotests`, run the suite with a SONiC `dplane_fpm_sonic.so` built
against the Zebra under test. Each router runs the module, and its test
socket plays the `fpmsyncd` side of the MAC protocol. The gate test starts
Zebra with the default kernel mode. The other tests enable
`--kernel-mac-ext-learn`. A SONiC kernel with EVPN-MH peer-sync FDB support is
required for the pin case. The case first checks the kernel acknowledgments
for an ordinary FDB write and a peer-sync write.

```sh
FRR_TEST_FPM_SONIC_MODULE=/path/to/dplane_fpm_sonic.so \
    pytest bgp_evpn_mh_fpm_ext_learn
```

| Starting state and event order | Kernel | Zebra and BGP | FPM |
| --- | --- | --- | --- |
| Kernel mode with the FPM module loaded. Receive an ASIC MAC learn, then reconnect. | Host MAC stays absent. | Host MAC stays absent. | The module consumes the frame without applying the learn. |
| Remote IMET route, then delete its all-zero VXLAN FDB entry | Restore the flood entry | Remote VTEP remains known | |
| FPM learn, duplicate learn, move, kernel delete, FPM age-out | Program the new port, then accept the kernel delete | Keep the MAC after the kernel delete. Withdraw it after the FPM age-out. | Local MAC is absent from the outbound stream through the subsequent remote marker. |
| BGP Type-2 install, then withdraw | Add and remove the remote VTEP entry | Install and withdraw the remote MAC | Add and delete carry the VTEP without a protocol tag. |
| Port down, sticky and dynamic FPM learns, port up, bridge detach | Program only the sticky MAC on port-up and remove it on detach | Withhold both learns while down. Advertise the sticky MAC on port-up. The live port's MAC stays advertised on detach. | |
| VNI removed, FPM learn, VNI restored | Record the MAC while the VNI is absent | Advertise after the VNI returns without a second FPM learn | |
| FRR restarts, FPM reconnects, ASIC state is replayed and BGP comes back up | Rebuild local and remote forwarding entries | Relearn the local MAC from FPM and the remote MAC from BGP | Replay a local MAC from the socket peer and send a fresh remote add |
| ASIC learn or ES advertisement arrives first. Once both hold the MAC, age the ASIC source first or withdraw the peer first | Clear the entry after the last source goes away | Preserve the surviving source. The peer-only entry may be local-inactive. | |
| ES peer holds a pin, reconnect FPM, delete the kernel entry, then withdraw the peer | Install the pin. Its final kernel delete finds it already absent. | Withdraw the MAC | Install and replay the static pin on the local ES port. Send the delete after the kernel reports the entry absent. |

The race cases also need an FRR build configured with `--enable-dev-build`.
They hold work before the dataplane providers, drive each ordering to an
observed Zebra or BGP state, and then release the queue. The old FDB entry
may stay in place while the queue is held. If both sources are absent between
events, Zebra and BGP may temporarily withdraw the MAC. FPM output from a
later queued update or a later kernel FDB write orders the final FDB checks
after execution. Tests that remove an existing kernel entry use the resulting
FDB state or a later link notification to check recovery from that loss.

| Starting state and event order with writes held | Kernel after release | Zebra and BGP | FPM |
| --- | --- | --- | --- |
| The remote MAC is installed or its install is queued. ASIC learn before BGP withdrawal, or BGP withdrawal before ASIC learn | Local `extern_learn` entry on the new port. Both remote bridge and VXLAN entries are absent. | Advertise the ASIC MAC, then withdraw it on ASIC aging. | Send the remote add and delete in order. |
| The remote MAC was installed and its VXLAN `self` entry is already absent. Run the same two orders. | Same local entry and cleanup as when the full remote entry was present. | The remote withdrawal leaves the ASIC source in place. | Still send the remote delete after the prior add. |
| The ASIC MAC is installed. BGP mobility update before ASIC age-out, ASIC age-out before the BGP update, or an existing lower-sequence BGP path at age-out. Send a duplicate ASIC delete. | Remote bridge and VXLAN entries survive. The old access-port entry is absent. | Select the remote VTEP, including fallback to the already-present path without a fresh update. Withdraw the local advertisement. | Send the selected remote add, then the delete on BGP withdrawal. |
| Only the ASIC or only the ES peer owns the MAC. Add the other source before deleting the first, or delete the first before adding the other. | Keep the surviving ES port entry and clear it after the last source leaves. | Advertise the final owner. The peer-only MAC is local-inactive and the ASIC-only MAC is active. | |
| The ASIC and two ES peers own the MAC. Age the ASIC source, then withdraw either peer while the pin is queued. Withdraw the last peer after the pin is installed. | Keep the ES port entry through the first peer withdrawal and remove it after the last. | Keep advertising the peer-backed MAC until the last peer withdraws. | Install the static ES port pin. |

The test uses link notifications, kernel acknowledgments, socket frames, and
BGP advertisements as ordering points. A zero MAC hold time lets the test
drive peer removal by withdrawing BGP. The suite exercises FRR with a
simulated FPM peer. It exercises queue delays and verifies their completed
effects. The kernel determines the relative delivery order of netlink
multicast notifications and command replies. Full SONiC container restart
and ASIC programming require a SONiC system test.
