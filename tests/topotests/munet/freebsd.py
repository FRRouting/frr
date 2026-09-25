# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
"""FreeBSD VNET jail backend for munet.

Each munet and each host is a persistent VNET jail. The munet jail owns the
bridges. Router jails are children of that jail: their names are
``parent.child``, and the kernel uses the text before the last dot as the
parent. epair(4) endpoints then move into those children by jail id.
The jail root is a private directory with read-only nullfs of the base
system, so cleanup can unmount before removing the directory. ``/usr/local/etc/frr``
is a symlink to ``/etc/frr`` so a FreeBSD build that uses ``--sysconfdir=/usr/local/etc``
still reads the configs the tests write.

Jail ids are not stored in ``Commander.pid``. That field stays the pytest
process id so namespace teardown does not signal an unrelated process.
"""

import atexit
import contextlib
import ctypes
import ctypes.util
import fcntl
import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

_libc = None


def _libc_handle():
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    return _libc


def set_process_name(name):
    """Set the name shown by ps via setproctitle."""
    libc = _libc_handle()
    # A leading "-" keeps ps from prefixing the name with the executable.
    libc.setproctitle.restype = None
    libc.setproctitle.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
    libc.setproctitle(b"-%s", name.encode("ascii"))


def set_parent_death_signal(signum):
    """Deliver signum when the parent exits, using procctl."""
    libc = _libc_handle()
    # P_PID is 0. PROC_PDEATHSIG_CTL is 11.
    sig = ctypes.c_int(signum)
    libc.procctl.argtypes = (
        ctypes.c_int,
        ctypes.c_int64,
        ctypes.c_int,
        ctypes.c_void_p,
    )
    libc.procctl.restype = ctypes.c_int
    libc.procctl(0, 0, 11, ctypes.byref(sig))


JAIL_ROOT = Path("/tmp/frr-topotest-jails")
LOCK_PATH = Path("/tmp/frr-topotest.lock")
IP_IN_JAIL = "/topotest/bin/ip"
FREEBSD_PATH = (
    "/topotest/bin:/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin"
)

_NULLFS_RO = (
    "/bin",
    "/sbin",
    "/lib",
    "/libexec",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/libexec",
    "/usr/libdata",
    "/usr/share",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/usr/local/lib",
    "/usr/local/libexec",
    "/usr/local/libdata",
    "/usr/local/share",
)

_ETC_FILES = (
    "passwd",
    "master.passwd",
    "pwd.db",
    "spwd.db",
    "group",
    "services",
    "protocols",
    "resolv.conf",
    "nsswitch.conf",
    "login.conf",
    "localtime",
    "hosts",
    "libmap.conf",
)

_seq = 0
_atexit_done = False
_modules_ready = False


@contextlib.contextmanager
def _lock():
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    handle = open(LOCK_PATH, "a", encoding="ascii")
    fcntl.flock(handle, fcntl.LOCK_EX)
    try:
        yield
    finally:
        fcntl.flock(handle, fcntl.LOCK_UN)
        handle.close()


def _our_pid():
    from .base import our_pid

    return our_pid


def _state_path(pid=None):
    if pid is None:
        pid = _our_pid()
    return Path(f"/tmp/frr-topotest-{pid}.json")


def _pid_alive(pid):
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _host_run(args, check=True):
    proc = subprocess.run(args, capture_output=True, text=True)
    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"{args!r} failed ({proc.returncode}): {detail}")
    return proc


def _read_state(path):
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


def _write_state(path, entries):
    if entries:
        path.write_text(json.dumps(entries), encoding="utf-8")
    elif path.exists():
        path.unlink()


def _record(entry):
    path = _state_path()
    with _lock():
        entries = [
            item for item in _read_state(path) if item.get("name") != entry["name"]
        ]
        entries.append(entry)
        _write_state(path, entries)
    _register_atexit()


def _forget(name):
    path = _state_path()
    with _lock():
        entries = [item for item in _read_state(path) if item.get("name") != name]
        _write_state(path, entries)


def _register_atexit():
    global _atexit_done
    if _atexit_done:
        return
    atexit.register(cleanup_our_jails)
    _atexit_done = True


def ensure_modules():
    """Load if_epair and if_bridge. Jails cannot kldload."""
    global _modules_ready
    if _modules_ready:
        return
    for mod in ("if_epair", "if_bridge"):
        _host_run(["/sbin/kldload", "-n", mod], check=False)
        proc = _host_run(["/sbin/kldstat", "-q", "-m", mod], check=False)
        if proc.returncode != 0:
            raise RuntimeError(f"kernel module {mod} is not loaded")
    _modules_ready = True


def _mountpoints_under(root):
    root = str(Path(root).resolve())
    proc = _host_run(["/sbin/mount", "-p"], check=False)
    points = []
    for line in (proc.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        mountpoint = parts[1].replace("\\040", " ")
        if mountpoint == root or mountpoint.startswith(root + os.sep):
            points.append(mountpoint)
    points.sort(key=len, reverse=True)
    return points


def _umount_tree(root):
    for mountpoint in _mountpoints_under(root):
        _host_run(["/sbin/umount", mountpoint], check=False)
    left = _mountpoints_under(root)
    for mountpoint in left:
        _host_run(["/sbin/umount", "-f", mountpoint], check=False)
    return _mountpoints_under(root)


def _child_jails(parent):
    """Return host-visible names of jails whose parent jid is ``parent``."""
    looked = _host_run(["/usr/sbin/jls", "-j", parent, "jid"], check=False)
    parent_jid = (looked.stdout or "").strip() if looked.returncode == 0 else ""
    if not parent_jid.isdigit():
        return []
    proc = _host_run(["/usr/sbin/jls", "-n"], check=False)
    kids = []
    for line in (proc.stdout or "").splitlines():
        fields = {}
        for tok in line.split():
            if "=" in tok:
                key, val = tok.split("=", 1)
                fields[key] = val
        if fields.get("parent") == parent_jid and fields.get("name"):
            kids.append(fields["name"])
    return kids


def _jail_remove(name, seen=None):
    if seen is None:
        seen = set()
    if name in seen:
        return
    seen.add(name)
    for child in _child_jails(name):
        _jail_remove(child, seen)
    _host_run(["/usr/sbin/jail", "-r", name], check=False)


def _nullfs(src, jail_root, mounts, readonly):
    src = Path(src)
    if not src.exists():
        return
    try:
        Path(jail_root).resolve().relative_to(src.resolve())
    except ValueError:
        pass
    else:
        raise RuntimeError(
            f"refusing to mount {src} over a jail rooted inside it ({jail_root})"
        )
    dest = Path(jail_root) / str(src).lstrip("/")
    dest.mkdir(parents=True, exist_ok=True)
    opt = "ro" if readonly else "rw"
    _host_run(["/sbin/mount", "-t", "nullfs", "-o", opt, str(src), str(dest)])
    mounts.append(str(dest))


def _expose(host_path, jail_root, mounts):
    host_path = Path(host_path)
    if not host_path.exists() and not host_path.is_symlink():
        return
    dest = Path(jail_root) / str(host_path).lstrip("/")
    if host_path.is_symlink():
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists() and not dest.is_symlink():
            dest.symlink_to(os.readlink(host_path))
        return
    if host_path.is_dir():
        _nullfs(host_path, jail_root, mounts, readonly=True)


def _copy_etc(jail_root):
    etc = Path(jail_root) / "etc"
    etc.mkdir(parents=True, exist_ok=True)
    for name in _ETC_FILES:
        src = Path("/etc") / name
        if src.is_file() or src.is_symlink():
            shutil.copy2(src, etc / name, follow_symlinks=True)


def _install_shim(jail_root):
    dest_dir = Path(jail_root) / "topotest" / "bin"
    dest_dir.mkdir(parents=True, exist_ok=True)
    src = Path(__file__).with_name("freebsd_ip.py")
    dest = dest_dir / "ip"
    shutil.copy2(src, dest)
    dest.chmod(0o755)


def _pre_argv(ns):
    pre = [
        "/usr/sbin/jexec",
        ns.jail_name,
        "/usr/bin/env",
        f"PATH={FREEBSD_PATH}",
        "LD_LIBRARY_PATH=/usr/local/lib",
    ]
    cwd = getattr(ns, "freebsd_cwd", None)
    if cwd:
        quoted = _shell_quote(str(cwd))
        pre += ["/bin/sh", "-c", f'cd {quoted} && exec "$@"', "sh"]
    return pre


def _shell_quote(text):
    import shlex

    return shlex.quote(text)


def _install_pre(ns, pre):
    from .base import LinuxNamespace

    pre = list(pre)
    if isinstance(ns, LinuxNamespace):
        ns._LinuxNamespace__base_pre_cmd = list(pre)
        ns._LinuxNamespace__pre_cmd = list(pre)
        ns._LinuxNamespace__root_base_pre_cmd = list(pre)
        ns._LinuxNamespace__root_pre_cmd = list(pre)
    else:
        ns._SharedNamespace__base_pre_cmd = list(pre)
        ns._SharedNamespace__pre_cmd = list(pre)


def _paths_to_mount(ns):
    paths = []
    repo_real = Path(os.path.realpath(__file__)).parents[3]
    repo_abs = Path(os.path.abspath(__file__)).parents[3]
    paths.append(repo_real)
    if repo_abs != repo_real:
        paths.append(repo_abs)
    if ns.unet is not None and getattr(ns.unet, "rundir", None):
        rundir = Path(ns.unet.rundir)
    else:
        rundir = Path(ns.rundir)
    rundir.mkdir(parents=True, exist_ok=True)
    real = Path(os.path.realpath(rundir))
    plain = Path(os.path.abspath(rundir))
    for candidate in (real, plain):
        if candidate not in paths:
            paths.append(candidate)
    return paths


def _build_root(ns, private_mounts):
    jail_path = Path(ns.jail_path)
    jail_path.mkdir(parents=True, exist_ok=True)
    os.chmod(JAIL_ROOT, 0o755)
    os.chmod(jail_path.parent, 0o755)
    os.chown(jail_path, 0, 0)
    os.chmod(jail_path, 0o755)
    mounts = []
    for host_path in _NULLFS_RO:
        _expose(host_path, jail_path, mounts)
    _copy_etc(jail_path)
    for rel in (
        "etc/frr",
        "etc/snmp",
        "var/run/frr",
        "var/lib/frr",
        "var/log",
        "var/tmp",
        "tmp",
        "root",
        "dev",
        "topotest/bin",
        "usr/local/etc",
    ):
        path = jail_path / rel
        path.mkdir(parents=True, exist_ok=True)
    os.chmod(jail_path / "tmp", 0o1777)
    os.chmod(jail_path / "var/tmp", 0o1777)
    os.chmod(jail_path / "root", 0o700)
    run_link = jail_path / "run"
    if not run_link.exists() and not run_link.is_symlink():
        run_link.symlink_to("var/run")
    frr_link = jail_path / "usr/local/etc/frr"
    if not frr_link.exists() and not frr_link.is_symlink():
        frr_link.symlink_to("/etc/frr")
    specs = private_mounts or []
    if isinstance(specs, str):
        specs = [specs]
    for spec in specs:
        parts = spec.split(":", 1)
        inner = parts[-1]
        dest = jail_path / inner.lstrip("/")
        if len(parts) == 1:
            # Linux mounts these paths as tmpfs, mode 1777. FRR binds
            # /var/run/frr sockets after it drops to the frr user.
            dest.mkdir(parents=True, exist_ok=True)
            os.chmod(dest, 0o1777)
            continue
        outer = Path(parts[0])
        if outer.is_file() or (outer.exists() and not outer.is_dir()):
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(outer, dest, follow_symlinks=True)
            continue
        if not outer.exists():
            outer.mkdir(parents=True, exist_ok=True)
        dest.mkdir(parents=True, exist_ok=True)
        _host_run(["/sbin/mount", "-t", "nullfs", "-o", "rw", str(outer), str(dest)])
        mounts.append(str(dest))
    for name in ("ld-elf.so.hints", "ld-elf32.so.hints"):
        src = Path("/var/run") / name
        if src.is_file():
            shutil.copy2(src, jail_path / "var/run" / name)
    _install_shim(jail_path)
    for src in _paths_to_mount(ns):
        _nullfs(src, jail_path, mounts, readonly=False)
    dev = jail_path / "dev"
    _host_run(["/sbin/mount", "-t", "devfs", "devfs", str(dev)])
    mounts.append(str(dev))
    ns.freebsd_mounts = mounts
    return mounts


def _jail_create(ns, nested):
    """Create the jail and store its jid.

    ``parent`` is a read-only jid. Passing ``parent=<name>`` is rejected.
    A name ``parent.child`` created from the host makes ``parent`` the
    parent jail, which is required before ``ifconfig IF vnet <jid>`` can
    move an epair out of the munet jail.
    """
    cmd = [
        "/usr/sbin/jail",
        "-i",
        "-c",
        f"name={ns.jail_name}",
        f"path={ns.jail_path}",
        f"host.hostname={ns.jail_hostname}",
        "persist=true",
        "vnet=new",
        "allow.raw_sockets=true",
        "allow.reserved_ports=true",
        "allow.chflags=true",
        "allow.mount=true",
        "allow.mount.tmpfs=true",
        "allow.mount.nullfs=true",
        "allow.mount.devfs=true",
        "enforce_statfs=1",
        "children.max=8" if nested else "children.max=128",
    ]
    proc = _host_run(cmd)
    jid_text = (proc.stdout or "").strip().split()
    if not jid_text or not jid_text[0].isdigit():
        looked = _host_run(["/usr/sbin/jls", "-j", ns.jail_name, "jid"])
        jid_text = [(looked.stdout or "").strip()]
    if not jid_text[0].isdigit() or int(jid_text[0]) <= 0:
        raise RuntimeError(f"could not read jid for {ns.jail_name}: {proc.stdout!r}")
    ns.jail_jid = int(jid_text[0])


def _jail_sysctl(name):
    for assignment in (
        "net.inet.ip.forwarding=1",
        "net.inet6.ip6.forwarding=1",
        "net.inet6.ip6.dad_count=0",
        "net.inet6.ip6.auto_linklocal=1",
    ):
        _host_run(["/usr/sbin/jexec", name, "/sbin/sysctl", assignment], check=False)
    _host_run(["/usr/sbin/jexec", name, "/sbin/ifconfig", "lo0", "up"], check=False)
    _host_run(
        ["/usr/sbin/jexec", name, "/sbin/ifconfig", "lo0", "inet", "127.0.0.1/8"],
        check=False,
    )
    _host_run(
        [
            "/usr/sbin/jexec",
            name,
            "/sbin/ifconfig",
            "lo0",
            "inet6",
            "::1",
            "prefixlen",
            "128",
        ],
        check=False,
    )
    _host_run(
        ["/usr/sbin/jexec", name, "/sbin/ifconfig", "lo0", "inet6", "-ifdisabled"],
        check=False,
    )


def _next_name(node_name):
    global _seq
    from .base import fsafe_name

    _seq += 1
    return f"ft{_our_pid()}x{_seq}_{fsafe_name(node_name)}"


def _hostname_for(name):
    if re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$", name):
        return name
    from .base import fsafe_name

    return fsafe_name(name)[:63] or "frr"


def init_namespace(ns, private_mounts=None, set_hostname=True):
    """Create the VNET jail backing this namespace and point commands at it."""
    del set_hostname  # host.hostname is always set; jails require one
    if os.geteuid() != 0:
        raise RuntimeError("FreeBSD topotests must run as root")
    ensure_modules()
    parent = ns.unet if getattr(ns, "unet", None) is not None else None
    parent_name = None
    if parent is not None and getattr(parent, "freebsd_jail", False):
        parent_name = parent.jail_name

    ns.freebsd_jail = True
    short = _next_name(ns.name)
    ns.jail_name = f"{parent_name}.{short}" if parent_name else short
    ns.jail_jid = None
    ns.jail_hostname = _hostname_for(ns.name)
    ns.jail_path = str(JAIL_ROOT / str(_our_pid()) / short)
    ns.freebsd_mounts = []
    ns.freebsd_cwd = None
    ns.nsflags = []
    ns.ifnetns = {}
    ns.uflags = 0
    ns.p_ns_fds = None
    ns.p_ns_fnames = None
    ns.pid_ns = False
    ns.init_pid = None
    ns.unshare_inline = False
    ns.nsenter_fork = False
    ns.p = None
    ns.ppid = os.getppid()
    ns.ppid_fd = None
    ns.pid = _our_pid()
    ns.pids = [_our_pid()]
    ns.ip_path = IP_IN_JAIL
    ns.cwd = os.path.abspath(os.getcwd())

    try:
        _build_root(ns, private_mounts)
        _record(
            {
                "name": ns.jail_name,
                "path": ns.jail_path,
                "parent": parent_name or "",
            }
        )
        _jail_create(ns, parent_name is not None)
        _jail_sysctl(ns.jail_name)
        _install_pre(ns, _pre_argv(ns))
    except Exception:
        logger.error("FreeBSD jail setup failed for %s", ns.jail_name, exc_info=True)
        try:
            _destroy_path(ns.jail_name, ns.jail_path)
            _forget(ns.jail_name)
        except Exception:
            logger.error(
                "cleanup after failed jail setup failed for %s",
                ns.jail_name,
                exc_info=True,
            )
        raise
    ns.logger.info("%s: created VNET jail %s jid %s", ns, ns.jail_name, ns.jail_jid)


def set_namespace_cwd(ns, cwd):
    """Remember cwd and rebuild the jexec prefix. jexec has no --wd flag."""
    ns.freebsd_cwd = str(cwd)
    _install_pre(ns, _pre_argv(ns))


def jail_mkdir(ns, inner):
    """Create a directory inside the jail root.

    The root is already private, so this stands in for a tmpfs mount.
    Mode 1777 matches a Linux tmpfs.
    """
    path = Path(ns.jail_path) / str(inner).lstrip("/")
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o1777)


def jail_bind_mount(ns, outer, inner):
    """Expose outer at inner inside the jail. Files are copied; dirs are nullfs."""
    outer = Path(outer)
    dest = Path(ns.jail_path) / str(inner).lstrip("/")
    if outer.is_file() or (outer.exists() and not outer.is_dir()):
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(outer, dest, follow_symlinks=True)
        return
    if not outer.exists():
        outer.mkdir(parents=True, exist_ok=True)
    dest.mkdir(parents=True, exist_ok=True)
    _host_run(["/sbin/mount", "-t", "nullfs", "-o", "rw", str(outer), str(dest)])
    ns.freebsd_mounts.append(str(dest))


def _destroy_path(name, path):
    if name:
        _jail_remove(name)
    if not path:
        return
    raw = Path(path)
    if not raw.exists() and not raw.is_symlink():
        return
    jail_path = raw.resolve()
    root = JAIL_ROOT.resolve()
    if root != jail_path and root not in jail_path.parents:
        raise RuntimeError(f"refusing to remove {jail_path}")
    left = _umount_tree(jail_path)
    if left:
        raise RuntimeError(f"mounts remain under {jail_path}: {left}")
    if jail_path.exists():
        shutil.rmtree(jail_path)


def destroy_namespace(ns):
    """Remove this jail, unmount its nullfs/devfs tree, then delete the root."""
    name = getattr(ns, "jail_name", None)
    path = getattr(ns, "jail_path", None)
    try:
        _destroy_path(name, path)
        if name:
            _forget(name)
        pid_dir = JAIL_ROOT / str(_our_pid())
        if pid_dir.exists() and not any(pid_dir.iterdir()):
            pid_dir.rmdir()
    except Exception:
        ns.logger.error("%s: FreeBSD jail cleanup failed", ns, exc_info=True)
        raise


def _reap_entry(entry):
    name = entry.get("name")
    path = entry.get("path")
    try:
        _destroy_path(name, path)
    except Exception:
        logger.error("stale jail cleanup failed for %s", name or path, exc_info=True)


def _reap_file(path, force):
    pid_text = path.stem.split("-")[-1]
    if not force and pid_text.isdigit() and _pid_alive(pid_text):
        return
    entries = _read_state(path)
    # Children carry a parent name. Remove those first.
    entries.sort(key=lambda item: 0 if item.get("parent") else 1)
    for entry in entries:
        _reap_entry(entry)
    if path.exists() and (force or not _pid_alive(pid_text)):
        left = _read_state(path)
        # Drop entries whose jail path is gone.
        remain = []
        for entry in left:
            jail_path = entry.get("path")
            if jail_path and Path(jail_path).exists():
                remain.append(entry)
        _write_state(path, remain)


def _reap_pid_dir(pid, force):
    pid_dir = JAIL_ROOT / str(pid)
    if not pid_dir.exists():
        return
    if not force and _pid_alive(pid):
        return
    for child in sorted(
        pid_dir.iterdir(), key=lambda item: len(str(item)), reverse=True
    ):
        try:
            _destroy_path(child.name, child)
        except Exception:
            logger.error(
                "stale jail directory cleanup failed for %s", child, exc_info=True
            )
    if pid_dir.exists() and not any(pid_dir.iterdir()):
        pid_dir.rmdir()


def reap_stale():
    """Remove jails left by pytest processes that are no longer running."""
    with _lock():
        for path in Path("/tmp").glob("frr-topotest-*.json"):
            _reap_file(path, force=False)
        if JAIL_ROOT.exists():
            for pid_dir in JAIL_ROOT.iterdir():
                if pid_dir.name.isdigit():
                    _reap_pid_dir(pid_dir.name, force=False)


def cleanup_our_jails():
    """Drop jails created by this process. Used from atexit and session end."""
    with _lock():
        path = _state_path()
        if path.exists():
            _reap_file(path, force=True)
        _reap_pid_dir(_our_pid(), force=True)


def finish_bridge(bridge, name, mtu):
    """Create an if_bridge in the parent VNET jail."""
    parent = bridge.unet
    if not getattr(parent, "jail_name", None):
        raise RuntimeError("FreeBSD bridge requires the parent VNET jail")
    bridge.freebsd_jail = False
    bridge.jail_name = parent.jail_name
    bridge.jail_path = parent.jail_path
    bridge.freebsd_cwd = None
    bridge.ip_path = IP_IN_JAIL
    _install_pre(bridge, _pre_argv(bridge))
    bridge.cmd_status(["/sbin/ifconfig", name, "destroy"], warn=False)
    text = _cmd_text(bridge, ["/sbin/ifconfig", "bridge", "create"])
    created = text.split()[-1]
    if created != name:
        _cmd_text(bridge, ["/sbin/ifconfig", created, "name", name])
    if mtu:
        _cmd_text(bridge, ["/sbin/ifconfig", name, "mtu", str(mtu)])
    _cmd_text(bridge, ["/sbin/ifconfig", name, "up"])
    bridge.logger.debug("%s: created if_bridge in %s", bridge, bridge.jail_name)


async def delete_bridge(bridge):
    """Destroy the if_bridge interface."""
    import subprocess

    rc, out, err = await bridge.async_cmd_status(
        ["/sbin/ifconfig", bridge.name, "destroy"],
        stdin=subprocess.DEVNULL,
        start_new_session=True,
        warn=False,
    )
    if rc:
        bridge.logger.error(
            "%s: error deleting bridge %s: %s", bridge, bridge.name, err or out
        )


def _cmd_text(ns, args):
    rc, out, err = ns.cmd_status_nsonly(args, warn=False)
    if rc:
        detail = ((out or "") + (err or "")).strip()
        raise RuntimeError(f"{args!r} failed ({rc}): {detail}")
    text = (out or "").strip()
    if not text:
        text = (err or "").strip()
    return text


def _rename_up(ns, current, wanted, mtu):
    if current != wanted:
        _cmd_text(ns, ["/sbin/ifconfig", current, "name", wanted])
    if mtu:
        _cmd_text(ns, ["/sbin/ifconfig", wanted, "mtu", str(mtu)])
    _cmd_text(ns, ["/sbin/ifconfig", wanted, "up"])
    rc, _, err = ns.cmd_status_nsonly(
        ["/sbin/ifconfig", wanted, "inet6", "-ifdisabled"], warn=False
    )
    if rc:
        ns.logger.warning("%s: inet6 -ifdisabled %s: %s", ns, wanted, err)


def _vnet_arg(ns):
    """Jail id for ``ifconfig IF vnet``. The move only sees child jails."""
    jid = getattr(ns, "jail_jid", None)
    if not jid:
        raise RuntimeError(f"{getattr(ns, 'jail_name', ns)} has no jail id")
    return str(jid)


def _create_epair(munet):
    text = _cmd_text(munet, ["/sbin/ifconfig", "epair", "create"])
    end_a = text.split()[-1]
    if not end_a.endswith("a"):
        raise RuntimeError(f"unexpected epair name {text!r}")
    return end_a, end_a[:-1] + "b"


def add_link(munet, name1, if1, name2, if2, mtu, isp2p):
    """Create an epair between two hosts, or between a bridge and a host."""
    if isp2p:
        lhost, rhost = munet.hosts[name1], munet.hosts[name2]
        nsif1 = lhost.get_ns_ifname(if1)
        nsif2 = rhost.get_ns_ifname(if2)
        if len(nsif1) >= 16 or len(nsif2) >= 16:
            raise RuntimeError(f"interface name exceeds 15 characters: {nsif1} {nsif2}")
        end_a, end_b = _create_epair(munet)
        _cmd_text(munet, ["/sbin/ifconfig", end_a, "vnet", _vnet_arg(lhost)])
        _cmd_text(munet, ["/sbin/ifconfig", end_b, "vnet", _vnet_arg(rhost)])
        _rename_up(lhost, end_a, nsif1, mtu)
        _rename_up(rhost, end_b, nsif2, mtu)
        lhost.register_interface(if1)
        rhost.register_interface(if2)
    else:
        switch = munet.switches[name1]
        rhost = munet.hosts[name2]
        nsif1 = switch.get_ns_ifname(if1)
        nsif2 = rhost.get_ns_ifname(if2)
        if mtu is None:
            mtu = switch.mtu
        if len(nsif1) >= 16 or len(nsif2) >= 16:
            raise RuntimeError(f"interface name exceeds 15 characters: {nsif1} {nsif2}")
        end_a, end_b = _create_epair(munet)
        _cmd_text(munet, ["/sbin/ifconfig", end_b, "vnet", _vnet_arg(rhost)])
        _rename_up(munet, end_a, nsif1, mtu)
        _cmd_text(munet, ["/sbin/ifconfig", switch.name, "addm", nsif1])
        _cmd_text(munet, ["/sbin/ifconfig", switch.name, "up"])
        _rename_up(rhost, end_b, nsif2, mtu)
        switch.register_interface(if1)
        rhost.register_interface(if2)
        rhost.register_network(switch.name, if2)
    munet.get_mac(name1, nsif1)
    munet.get_mac(name2, nsif2)


def add_dummy(host, ifname, nsif, mtu):
    """Create a cloned lo interface and rename it. FreeBSD has no dummy(4)."""
    text = _cmd_text(host, ["/sbin/ifconfig", "lo", "create"])
    created = text.split()[-1] if text else ""
    if not created:
        raise RuntimeError("ifconfig lo create returned no name")
    _rename_up(host, created, nsif, mtu)
    host.register_interface(ifname)


def interface_mac(dev, nsifname):
    """Return the Ethernet address from ifconfig."""
    text = _cmd_text(dev, ["/sbin/ifconfig", nsifname])
    match = re.search(r"ether ([0-9a-fA-F:]+)", text)
    if not match:
        raise RuntimeError(f"no ether address on {nsifname}: {text}")
    return match.group(1)


async def delete_link(host, nsrif, lname, log):
    """Destroy one epair end. The kernel removes the pair."""
    rc, out, err = await host.async_cmd_status_nsonly(
        ["/sbin/ifconfig", nsrif, "destroy"],
        stdin=subprocess.DEVNULL,
        start_new_session=True,
        warn=False,
    )
    if rc:
        log.error("Err del epair %s: %s", lname, err or out)
