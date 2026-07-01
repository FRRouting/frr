# util_pcap.py
import re, time, shlex
from pathlib import Path

OSPFV2_FILTER = "ip proto 89"

class PerInterfacePcapManager:
    def __init__(self, outdir="pcaps", tag="ospf4"):
        self.outdir = Path(outdir)
        self.tag = tag
        self.pids = {}   # (router, ifname) -> pid

    def _list_ifaces(self, router):
        txt = router.cmd("ip -o link show")
        # Lines like: "3: r1-eth0@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> ..."
        ifaces = []
        seen = set()
        for ln in txt.splitlines():
            m = re.match(r"\d+:\s+([^:]+):\s+<([^>]*)>", ln)
            if not m:
                continue
            ifn = m.group(1).split("@")[0]
            flags = m.group(2).split(",")
            up = "UP" in flags
            if ifn not in seen:
                seen.add(ifn)
                ifaces.append((ifn, up))
        return ifaces

    def start_all(self, tgen):
        if tgen is None or not tgen.routers():
            raise RuntimeError("Call start_all() only after tgen.start_router()")

        self.outdir = self.outdir.resolve()
        self.outdir.mkdir(parents=True, exist_ok=True)
        # Clean previous captures for a fresh run
        for old in self.outdir.glob("*.pcap*"):
            try:
                old.unlink()
            except OSError:
                pass
        for old in self.outdir.glob("*.csv*"):
            try:
                old.unlink()
            except OSError:
                pass

        for rname, router in tgen.routers().items():
            for ifn, up in self._list_ifaces(router):
                if ifn == "lo":
                    continue
                # If you only want 'UP' links, uncomment:
                # if not up: continue

                pcap_path = self.outdir / f"{rname}-{ifn}-{self.tag}.pcap"
                cmd = (
                    f"nohup tcpdump -i {shlex.quote(ifn)} -U -s 0 "
                    #f"-w {shlex.quote(str(pcap_path))} {OSPFV2_FILTER} "
                    f"-w {shlex.quote(str(pcap_path))}"
                    f">/dev/null 2>&1 & echo $!"
                )
                pid = router.cmd(cmd).strip()
                # Basic sanity: numeric PID?
                try:
                    self.pids[(rname, ifn)] = int(pid)
                except ValueError:
                    # tcpdump might be missing; surface the router's error
                    out = router.cmd("which tcpdump || true")
                    raise RuntimeError(
                        f"Failed to start tcpdump on {rname}:{ifn} "
                        f"(got PID '{pid}'). tcpdump path: {out}"
                    )

        # Small settle to ensure files are created
        time.sleep(0.3)

    def stop_all(self, tgen=None):
        # Best-effort terminate inside each router
        if not self.pids:
            return
        # If tgen wasn't passed, try to get it (optional)
        routers = {}
        if tgen is not None and tgen.routers():
            routers = tgen.routers()

        for (rname, ifn), pid in list(self.pids.items()):
            router = routers.get(rname)
            if router:
                router.cmd(f"kill -TERM {pid} >/dev/null 2>&1 || true")
        time.sleep(0.3)
        for (rname, ifn), pid in list(self.pids.items()):
            router = routers.get(rname)
            if router:
                router.cmd(f"kill -KILL {pid} >/dev/null 2>&1 || true")
        self.pids.clear()
# util_pcap.py
