# Topotests in Docker

## Quickstart

If you have Docker installed, you can run the topotests in Docker.
The easiest way to do this, is to use the make targets from this
repository.

Your current user needs to have access to the Docker daemon. Alternatively
you can run these commands as root.

```console
make topotests-build
make topotests
```

The first command will build a docker image with all the dependencies needed
to run the topotests.

The second command will spawn an instance of this image, compile FRR inside
of it, and run the topotests.

## Advanced Usage

Internally, the topotests make target uses a shell script to spawn the docker
container.

There are several environment variables which can be used to modify the behavior
of the script, these can be listed by calling it with `-h`:

```console
./tests/topotests/docker/frr-topotests.sh -h
```

For example, a volume is used to cache build artifacts between multiple runs
of the image. If you need to force a complete recompile, you can set `TOPOTEST_CLEAN`:

```console
TOPOTEST_CLEAN=1 ./tests/topotests/docker/frr-topotests.sh
```

By default, `frr-topotests.sh` will build frr and run pytest. If you append
arguments and the first one starts with `/` or `./`, they will replace the call to
pytest. If the appended arguments do not match this patttern, they will be provided to
pytest as arguments.

So, to run a specific test with more verbose logging:

```console
./tests/topotests/docker/frr-topotests.sh -vv -s all-protocol-startup/test_all_protocol_startup.py
```

And to compile FRR but drop into a shell instead of running pytest:

```console
./tests/topotests/docker/frr-topotests.sh /bin/bash
```
