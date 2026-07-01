import re
import shlex
import time
from pathlib import Path

OSPFV2_FILTER = "ip proto 89"


class PerInterfacePcapManager:
    def __init__(self, outdir="pcaps", tag="ospf4"):
        self.outdir = Path(outdir)
        self.tag = tag
        self.pids = {}

    def _list_ifaces(self, router):
        txt = router.cmd("ip -o link show")
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

                pcap_path = self.outdir / f"{rname}-{ifn}-{self.tag}.pcap"
                cmd = (
                    f"nohup tcpdump -i {shlex.quote(ifn)} -U -s 0 "
                    f"-w {shlex.quote(str(pcap_path))}"
                    f">/dev/null 2>&1 & echo $!"
                )
                pid = router.cmd(cmd).strip()
                try:
                    self.pids[(rname, ifn)] = int(pid)
                except ValueError:
                    out = router.cmd("which tcpdump || true")
                    raise RuntimeError(
                        f"Failed to start tcpdump on {rname}:{ifn} "
                        f"(got PID '{pid}'). tcpdump path: {out}"
                    )

        time.sleep(0.3)

    def stop_all(self, tgen=None):
        if not self.pids:
            return
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
