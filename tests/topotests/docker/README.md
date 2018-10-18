# Topotests in Docker

## Quickstart

If you have Docker installed, you can run the topotests in Docker.
The easiest way to do this, is to use the `frr-topotests.sh` script
from this repository:

```console
wget -O /usr/local/bin/frr-topotests \
    https://raw.githubusercontent.com/frrouting/topotests/master/docker/frr-topotests.sh
chmod +x /usr/local/bin/frr-topotests
```

Once this script is in place, simply run it while you are inside your FRR repository:

```console
frr-topotests
```

## Advanced Usage

There are several environtment variables which can be used to modify the behavior of
the image. Those can be listed using `frr-topotests -h`.

For example, a volume is used to cache build artifacts between multiple runs
of the image. If you need to force a complete recompile, you can set `TOPOTEST_CLEAN`:

```console
TOPOTEST_CLEAN=1 frr-topotests
```

By default, `frr-topotests` will execute pytest without any arguments. If you append an
arguments with the first one starting with `/` or `./`, they will replace the call to
pytest. If the appended arguments do not match this patttern, they will be provided to
pytest as arguments.

So, to run a specific test with more verbose logging:

```console
frr-topotests -vv -s all-protocol-startup/test_all_protocol_startup.py
```

And to compile FRR but drop into a shell instead of running pytest:

```console
frr-topotests /bin/bash
```
